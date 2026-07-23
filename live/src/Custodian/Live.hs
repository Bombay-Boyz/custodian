{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE LinearTypes #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies #-}

-- | @Custodian.Live@ — the idiomatic layer's real backend, implementing
-- the capability classes from "Custodian.Core" and "Custodian.Map" on
-- top of the unrestricted "Custodian.Raw" FFI transcript. This is the
-- Dependency-Inversion boundary (§2.2) exercised for real: the mock
-- ("Custodian.Mock") and this module are two instances of the same
-- classes, so the phantom-typed, linear, bracket-scoped API runs
-- unchanged against either.
--
-- Requires @libbpf@ to link and a @CAP_BPF@-capable kernel to run.
module Custodian.Live
  ( LiveObj
  , LiveLink
  , LiveSys
  ) where

import Data.Word (Word32, Word8)
import Foreign.C.Error (Errno (..), eNOENT, getErrno)
import Foreign.C.String (withCString)
import Foreign.C.Types (CInt)
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Marshal.Array (peekArray, pokeArray)
import Foreign.Marshal.Utils (fillBytes, with)
import Foreign.Ptr (Ptr, nullPtr)
import System.Posix.Types (Fd (..))

import Control.Monad (void)
import Data.Proxy (Proxy)
import Prelude.Linear qualified as L
import System.IO.Linear qualified as Linear
import Unsafe.Linear qualified as Unsafe

import Custodian.Core (AttachDetach (..), ObjectLifecycle (..))
import Custodian.Errors (CustodianError (..))
import Custodian.Map (MapLookup (..), MapShape (..), MapSyscalls (..))
import Custodian.Raw
import Custodian.Raw.MapInfo
  ( mapInfoKeySize
  , mapInfoValueSize
  , peekMapInfo
  , sizeOfMapInfo
  )

--------------------------------------------------------------------------------
-- Owned handles
--------------------------------------------------------------------------------

-- | Owned @struct bpf_object *@.
newtype LiveObj = LiveObj (Ptr Bpf_object)

-- | The links produced by attaching /all/ of an object's programs. Held
-- as a list so a multi-program object is a single linear resource that
-- 'Custodian.Core.teardown' releases in one step (matching the accounting
-- backend's @AcctLinks@ in the test suite).
newtype LiveLink = LiveLink [Ptr Bpf_link]

-- | Phantom naming the real element-syscall backend.
data LiveSys

-- A raw pointer is an opaque token: consuming or duplicating one is a
-- no-op on the Haskell side. Linearity (in "Custodian.Core"), not a
-- runtime copy count, forbids using a handle after it is closed.
instance L.Consumable LiveObj where
  consume = Unsafe.toLinear (\(LiveObj p) -> p `seq` ())
instance L.Dupable LiveObj where
  dup2 = Unsafe.toLinear (\(LiveObj p) -> (LiveObj p, LiveObj p))
instance L.Consumable LiveLink where
  consume = Unsafe.toLinear (\(LiveLink ls) -> ls `seq` ())
instance L.Dupable LiveLink where
  dup2 = Unsafe.toLinear (\(LiveLink ls) -> (LiveLink ls, LiveLink ls))

--------------------------------------------------------------------------------
-- Lifecycle
--------------------------------------------------------------------------------

instance ObjectLifecycle LiveObj where
  rawOpen path = Linear.fromSystemIO (openImpl path)
  rawLoad = Unsafe.toLinear (\(LiveObj p) -> Linear.fromSystemIO (loadImpl p))
  rawClose = Unsafe.toLinear (\(LiveObj p) -> Linear.fromSystemIO (c_bpf_object__close p))

openImpl :: FilePath -> IO (Either CustodianError LiveObj)
openImpl path =
  withCString path $ \cpath -> do
    p <- c_bpf_object__open cpath
    pure $
      if p == nullPtr
        then Left (LibbpfFailure (path ++ ": bpf_object__open returned NULL"))
        else Right (LiveObj p)

loadImpl :: Ptr Bpf_object -> IO (Either CustodianError LiveObj)
loadImpl p = do
  rc <- c_bpf_object__load p
  pure $
    if rc == 0
      then Right (LiveObj p)
      else Left (LibbpfFailure ("bpf_object__load failed with rc=" ++ show rc))

instance AttachDetach LiveObj LiveLink where
  rawAttach = Unsafe.toLinear (\(LiveObj p) -> Linear.fromSystemIO (attachImpl p))
  rawDetach = Unsafe.toLinear (\(LiveLink ls) -> Linear.fromSystemIO (detachImpl ls))

-- | Attach /every/ program in the object, collecting one link each. If
-- any single attach fails, the links already created are rolled back
-- (detached) before returning, so a partial attach never leaks — and the
-- object is handed back so the caller can still close it.
attachImpl
  :: Ptr Bpf_object -> IO (Either (LiveObj, CustodianError) (LiveObj, LiveLink))
attachImpl p = go nullPtr []
  where
    go prev acc = do
      prog <- c_bpf_object__next_program p prev
      if prog == nullPtr
        then case acc of
          [] -> pure (Left (LiveObj p, LibbpfFailure "no programs to attach"))
          _ -> pure (Right (LiveObj p, LiveLink (reverse acc)))
        else do
          link <- c_bpf_program__attach prog
          if link == nullPtr
            then do
              mapM_ destroy acc -- roll back everything attached so far
              pure (Left (LiveObj p, LibbpfFailure "bpf_program__attach returned NULL"))
            else go prog (link : acc)

-- | Destroy every link in the bundle, newest first.
detachImpl :: [Ptr Bpf_link] -> IO ()
detachImpl = mapM_ destroy . reverse

destroy :: Ptr Bpf_link -> IO ()
destroy l = void (c_bpf_link__destroy l)

--------------------------------------------------------------------------------
-- Map lookup: fd + kernel-declared shape, read via the hsc2hs struct
--------------------------------------------------------------------------------

instance MapLookup LiveObj where
  type Sys LiveObj = LiveSys
  rawFindMap (LiveObj p) name =
    withCString name $ \cname -> do
      mapPtr <- c_bpf_object__find_map_by_name p cname
      if mapPtr == nullPtr
        then pure (Left (LibbpfFailure (name ++ ": find_map_by_name returned NULL")))
        else do
          fd <- c_bpf_map__fd mapPtr
          if fd < 0
            then pure (Left (LibbpfFailure "bpf_map__fd returned a negative fd"))
            else shapeByInfo fd

-- | Read a map's declared shape from the kernel via
-- @bpf_map_get_info_by_fd@, using the header-derived offsets in
-- "Custodian.Raw.MapInfo" — the canonical source, not a userspace guess.
shapeByInfo :: CInt -> IO (Either CustodianError (Fd, MapShape))
shapeByInfo fd =
  allocaBytes sizeOfMapInfo $ \infoPtr -> do
    fillBytes infoPtr 0 sizeOfMapInfo
    with (fromIntegral sizeOfMapInfo :: Word32) $ \lenPtr -> do
      rc <- c_bpf_map_get_info_by_fd fd infoPtr lenPtr
      if rc /= 0
        then Left . syscallError "bpf_map_get_info_by_fd" <$> getErrno
        else do
          info <- peekMapInfo infoPtr
          pure
            ( Right
                ( Fd fd
                , MapShape
                    (fromIntegral (mapInfoKeySize info))
                    (fromIntegral (mapInfoValueSize info))
                )
            )

--------------------------------------------------------------------------------
-- Element syscalls (errno-preserving; ENOENT folded into the result)
--------------------------------------------------------------------------------

instance MapSyscalls LiveSys where
  sysLookup
    :: Proxy LiveSys -> Fd -> Int -> [Word8] -> IO (Either Errno (Maybe [Word8]))
  sysLookup _ (Fd fd) valueSize key =
    withBytes key $ \kp ->
      allocaBytes valueSize $ \vp -> do
        rc <- c_bpf_map_lookup_elem fd kp vp
        if rc == 0
          then Right . Just <$> peekArray valueSize vp
          else do
            e <- getErrno
            pure (if e == eNOENT then Right Nothing else Left e)

  sysUpdate :: Proxy LiveSys -> Fd -> [Word8] -> [Word8] -> IO (Either Errno ())
  sysUpdate _ (Fd fd) key val =
    withBytes key $ \kp ->
      withBytes val $ \vp -> do
        rc <- c_bpf_map_update_elem fd kp vp 0 -- 0 = BPF_ANY
        if rc == 0 then pure (Right ()) else Left <$> getErrno

  sysDelete :: Proxy LiveSys -> Fd -> [Word8] -> IO (Either Errno Bool)
  sysDelete _ (Fd fd) key =
    withBytes key $ \kp -> do
      rc <- c_bpf_map_delete_elem fd kp
      if rc == 0
        then pure (Right True)
        else do
          e <- getErrno
          pure (if e == eNOENT then Right False else Left e)

  sysKeys :: Proxy LiveSys -> Fd -> Int -> IO (Either Errno [[Word8]])
  sysKeys _ (Fd fd) keySize =
    allocaBytes keySize $ \nxt -> do
      rc0 <- c_bpf_map_get_next_key fd nullPtr nxt
      if rc0 /= 0
        then endOrError
        else do
          first <- peekArray keySize nxt
          go first [first]
    where
      endOrError :: IO (Either Errno [[Word8]])
      endOrError = do
        e <- getErrno
        pure (if e == eNOENT then Right [] else Left e)

      go :: [Word8] -> [[Word8]] -> IO (Either Errno [[Word8]])
      go lastKey acc =
        allocaBytes keySize $ \cur ->
          allocaBytes keySize $ \nxt -> do
            pokeArray cur lastKey
            rc <- c_bpf_map_get_next_key fd cur nxt
            if rc /= 0
              then do
                e <- getErrno
                pure (if e == eNOENT then Right (reverse acc) else Left e)
              else do
                k <- peekArray keySize nxt
                go k (k : acc)

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

withBytes :: [Word8] -> (Ptr Word8 -> IO a) -> IO a
withBytes bs f =
  allocaBytes (length bs) $ \p -> do
    fillBytes p 0 (length bs)
    pokeArray p bs
    f p

-- | Package a preserved 'Errno' into a 'CustodianError'. 'Errno' is a
-- @newtype@ over 'CInt', matched here via its exported constructor.
syscallError :: String -> Errno -> CustodianError
syscallError op (Errno n) = SyscallFailure op n
