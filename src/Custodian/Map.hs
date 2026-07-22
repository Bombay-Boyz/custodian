{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleContexts #-}

-- | The typed map API (vision doc §2.5\/§3.5, Phase 4). Deliberately
-- NOT linear-typed, unlike "Custodian"'s 'BpfObject': a map is a
-- /borrowed/ resource -- read and written many times over its parent
-- object's lifetime -- not a consumed-once one. 'LiveMap' is scoped via
-- rank-2 branding instead (the same @forall s. ... -> r@ trick
-- @runST@\/@STRef@ use), which is what 'withMap' below enforces: the
-- brand @br@ can never unify with anything outside the callback that
-- introduced it, so a 'LiveMap' cannot escape the scope in which its
-- parent object is guaranteed live.
--
-- Scope note (v1, per the vision doc): 'HashMap' and 'ArrayMap' only;
-- keys\/values are anything with an existing 'Storable' instance
-- (@Word32@, @Word64@, @CInt@, etc.) -- no custom @hsc2hs@-derived
-- struct support yet. This is a deliberate, documented scope choice,
-- not an oversight -- see project history for the reasoning.
module Custodian.Map
  ( MapType (..)
  , LiveMap
  , mapFd
  , MapLookup (..)
  , withMap
  , readMap
  , writeMap
  , deleteMap
  , mapKeys
  ) where

import Prelude
import Data.Word (Word64)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Storable (Storable (..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.C.Error (Errno (..), getErrno, eNOENT)
import System.Posix.Types (Fd (..))
import Custodian.Errors (CustodianError (..))
import Custodian.Raw
  ( c_bpf_map_lookup_elem
  , c_bpf_map_update_elem
  , c_bpf_map_delete_elem
  , c_bpf_map_get_next_key
  )

-- | Map-type witness, paralleling the program-type witness pattern
-- used elsewhere in the design. v1 supports only these two.
data MapType = HashMap | ArrayMap

-- | A scoped, typed handle onto a declared map. Backed by nothing more
-- than the map's raw file descriptor: @libbpf@ has no
-- @bpf_map__destroy@ for callers to invoke at all -- a map's lifetime
-- is entirely owned by the @bpf_object@ that declared it, released
-- when that object is closed. There is nothing for 'withMap' to clean
-- up on its own, which is why (unlike 'Custodian.withLoadedBpfObject'\/
-- 'Custodian.withAttachedBpfObject') it needs no exception-safety
-- machinery at all.
--
-- The @br@ (brand) parameter is rank-2, introduced fresh by 'withMap'
-- for each call and never unifiable with any other scope's brand --
-- this is what stops a 'LiveMap' value from escaping the callback that
-- produced it. @t@ is the 'MapType' witness; @k@\/@v@ are the key and
-- value types.
newtype LiveMap br (t :: MapType) key value = LiveMap {mapFd :: Fd}

-- | Capability: find a declared map's file descriptor by name, given
-- the backend's own object resource. Deliberately takes a plain,
-- already-borrowed @objRes@ (not the whole linear 'Custodian.BpfObject')
-- -- callers obtain that via the same borrowing techniques
-- 'Custodian.withLoadedBpfObject'\/'Custodian.withAttachedBpfObject'
-- already use internally (see 'Custodian.splitLoaded' and friends).
class MapLookup objRes where
  rawFindMapFd :: objRes -> String -> IO (Either CustodianError Fd)

-- | Run a callback against a named map, scoped so the resulting
-- 'LiveMap' cannot escape. No exception-safety wrapping needed here --
-- see 'LiveMap''s own docs for why.
withMap
  :: MapLookup objRes
  => objRes
  -> String
  -> (forall br. LiveMap br t k v -> IO a)
  -> IO (Either CustodianError a)
withMap objRes name callback = do
  fdResult <- rawFindMapFd objRes name
  case fdResult of
    Left err -> pure (Left err)
    Right fd -> Right <$> callback (LiveMap fd)

-- | Look up a key. A missing key is a normal, expected outcome
-- (@Right Nothing@), distinguished from a genuine failure by checking
-- @errno@ for @ENOENT@ specifically after the underlying
-- @bpf_map_lookup_elem@ call -- not by treating every non-zero return
-- the same way.
readMap :: forall br t k v. (Storable k, Storable v) => LiveMap br t k v -> k -> IO (Either CustodianError (Maybe v))
readMap (LiveMap fd) key =
  alloca $ \(keyPtr :: Ptr k) ->
    alloca $ \(valPtr :: Ptr v) -> do
      poke keyPtr key
      rc <- c_bpf_map_lookup_elem (fromIntegral fd) (castPtr keyPtr) (castPtr valPtr)
      if rc >= 0
        then Right . Just <$> peek valPtr
        else do
          errno <- getErrno
          if errno == eNOENT
            then pure (Right Nothing)
            else pure (Left (LibbpfFailure ("bpf_map_lookup_elem failed, errno=" ++ (case errno of Errno n -> show n))))

-- | Insert or update a key\/value pair.
writeMap :: forall br t k v. (Storable k, Storable v) => LiveMap br t k v -> k -> v -> IO (Either CustodianError ())
writeMap (LiveMap fd) key value =
  alloca $ \(keyPtr :: Ptr k) ->
    alloca $ \(valPtr :: Ptr v) -> do
      poke keyPtr key
      poke valPtr value
      rc <- c_bpf_map_update_elem (fromIntegral fd) (castPtr keyPtr) (castPtr valPtr) (0 :: Word64)
      if rc >= 0
        then pure (Right ())
        else do
          errno <- getErrno
          pure (Left (LibbpfFailure ("bpf_map_update_elem failed, errno=" ++ (case errno of Errno n -> show n))))

-- | Delete a key. Unlike 'readMap', a missing key here is treated as a
-- genuine failure (matching real @bpf_map_delete_elem@ semantics) --
-- deleting something that was never there usually indicates a caller
-- logic error worth surfacing, not a silently-fine outcome.
deleteMap :: forall br t k v. Storable k => LiveMap br t k v -> k -> IO (Either CustodianError ())
deleteMap (LiveMap fd) key =
  alloca $ \(keyPtr :: Ptr k) -> do
    poke keyPtr key
    rc <- c_bpf_map_delete_elem (fromIntegral fd) (castPtr keyPtr)
    if rc >= 0
      then pure (Right ())
      else do
        errno <- getErrno
        pure (Left (LibbpfFailure ("bpf_map_delete_elem failed, errno=" ++ (case errno of Errno n -> show n))))

-- | All keys currently in the map, via repeated @bpf_map_get_next_key@
-- (null key -> first key; each returned key fed back in as the next
-- call's key, until @ENOENT@ signals no more keys).
mapKeys :: forall br t k v. Storable k => LiveMap br t k v -> IO (Either CustodianError [k])
mapKeys (LiveMap fd) =
  alloca $ \(curKeyPtr :: Ptr k) ->
    alloca $ \(nextKeyPtr :: Ptr k) -> do
      let loop isFirst acc = do
            rc <-
              c_bpf_map_get_next_key
                (fromIntegral fd)
                (if isFirst then nullPtr else castPtr curKeyPtr)
                (castPtr nextKeyPtr)
            if rc >= 0
              then do
                k <- peek nextKeyPtr
                poke curKeyPtr k
                loop False (k : acc)
              else do
                errno <- getErrno
                if errno == eNOENT
                  then pure (Right (reverse acc))
                  else pure (Left (LibbpfFailure ("bpf_map_get_next_key failed, errno=" ++ (case errno of Errno n -> show n))))
      loop True []
