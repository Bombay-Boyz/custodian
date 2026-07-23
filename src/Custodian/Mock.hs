{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE LinearTypes #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE QualifiedDo #-}
{-# LANGUAGE TypeFamilies #-}

-- | An in-memory backend used to prove the abstraction is real (a second
-- instantiation of the same capability classes) and to give the property
-- tests something to run against without a kernel.
--
-- The lifecycle side ('MockHandle') carries no real resource — the
-- "can't tear down twice" guarantee is linearity's, not the mock's. The
-- map side ('MockSys') is a genuine in-process hash table keyed by file
-- descriptor, mirroring how the real kernel keys maps by a global fd, so
-- the element operations ('readMap' etc.) exercise real branching and
-- 'Storable' marshalling.
module Custodian.Mock
  ( MockHandle
  , mockHandle
  , MockSys
  , installMockMap
  , clearMockMaps
  ) where

import Control.Functor.Linear qualified as Control
import Custodian.Core (AttachDetach (..), ObjectLifecycle (..))
import Custodian.Errors (CustodianError (..))
import Custodian.Map (MapLookup (..), MapShape, MapSyscalls (..))
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import Data.Map.Strict qualified as Map
import Data.Proxy (Proxy)
import Data.Word (Word8)
import Foreign.C.Error (Errno)
import Prelude.Linear qualified as L
import System.IO.Unsafe (unsafePerformIO)
import System.Posix.Types (Fd)
import Unsafe.Linear qualified as Unsafe
import Prelude

--------------------------------------------------------------------------------
-- Lifecycle mock
--------------------------------------------------------------------------------

-- | Opaque stand-in for a live @bpf_object@ pointer: an identifying tag,
-- no kernel resource behind it.
newtype MockHandle = MockHandle Int

-- | A ready-made mock object handle. Map lookups ignore the handle's
-- contents (a mock has no real object behind it), so a single value
-- suffices for driving 'Custodian.Map.withMap' in tests.
mockHandle :: MockHandle
mockHandle = MockHandle 0

instance L.Consumable MockHandle where
  consume = Unsafe.toLinear (\(MockHandle t) -> L.consume t)

instance L.Dupable MockHandle where
  dup2 = Unsafe.toLinear (\(MockHandle t) -> (MockHandle t, MockHandle t))

instance ObjectLifecycle MockHandle where
  rawOpen _ = Control.pure (Right (MockHandle 0))
  rawLoad (MockHandle t) = Control.pure (Right (MockHandle t))
  rawClose (MockHandle t) = L.consume t `L.lseq` Control.pure ()

instance AttachDetach MockHandle MockHandle where
  rawAttach h = case L.dup2 h of
    (hObj, hLink) -> Control.pure (Right (hObj, hLink))
  rawDetach (MockHandle t) = L.consume t `L.lseq` Control.pure ()

--------------------------------------------------------------------------------
-- Map mock: a real in-process table keyed by fd
--------------------------------------------------------------------------------

-- | Phantom naming the mock element-syscall backend.
data MockSys

-- | @name -> (fd, shape)@, populated by 'installMockMap'.
{-# NOINLINE mockMapTable #-}
mockMapTable :: IORef (Map.Map String (Fd, MapShape))
mockMapTable = unsafePerformIO (newIORef Map.empty)

-- | @fd -> (key bytes -> value bytes)@, the actual element store.
{-# NOINLINE mockElemTable #-}
mockElemTable :: IORef (Map.Map Fd (Map.Map [Word8] [Word8]))
mockElemTable = unsafePerformIO (newIORef Map.empty)

-- | Declare a mock map: a name a lookup will resolve, its fd, and the
-- kernel-declared shape 'withMap' will validate against.
installMockMap :: String -> Fd -> MapShape -> IO ()
installMockMap name fd shape = do
  atomicModifyIORef' mockMapTable (\m -> (Map.insert name (fd, shape) m, ()))
  atomicModifyIORef'
    mockElemTable
    (\m -> (Map.insertWith (\_ old -> old) fd Map.empty m, ()))

-- | Reset all mock map state (call between tests).
clearMockMaps :: IO ()
clearMockMaps = do
  atomicModifyIORef' mockMapTable (const (Map.empty, ()))
  atomicModifyIORef' mockElemTable (const (Map.empty, ()))

instance MapLookup MockHandle where
  type Sys MockHandle = MockSys
  rawFindMap _ name = do
    table <- readIORef mockMapTable
    pure $ case Map.lookup name table of
      Nothing -> Left (MockFailure ("no such mock map: " ++ name))
      Just (fd, sh) -> Right (fd, sh)

withFdTable
  :: Fd -> (Map.Map [Word8] [Word8] -> (Map.Map [Word8] [Word8], r)) -> IO r
withFdTable fd f =
  atomicModifyIORef' mockElemTable $ \outer ->
    let inner = Map.findWithDefault Map.empty fd outer
        (inner', r) = f inner
     in (Map.insert fd inner' outer, r)

instance MapSyscalls MockSys where
  sysLookup
    :: Proxy MockSys -> Fd -> Int -> [Word8] -> IO (Either Errno (Maybe [Word8]))
  sysLookup _ fd _valueSize key = do
    outer <- readIORef mockElemTable
    pure (Right (Map.lookup fd outer >>= Map.lookup key))

  sysUpdate :: Proxy MockSys -> Fd -> [Word8] -> [Word8] -> IO (Either Errno ())
  sysUpdate _ fd key val = withFdTable fd (\inner -> (Map.insert key val inner, Right ()))

  sysDelete :: Proxy MockSys -> Fd -> [Word8] -> IO (Either Errno Bool)
  sysDelete _ fd key =
    withFdTable fd $ \inner ->
      case Map.lookup key inner of
        Nothing -> (inner, Right False) -- ENOENT: absent, not a failure
        Just _ -> (Map.delete key inner, Right True)

  sysKeys :: Proxy MockSys -> Fd -> Int -> IO (Either Errno [[Word8]])
  sysKeys _ fd _keySize = do
    outer <- readIORef mockElemTable
    pure (Right (maybe [] Map.keys (Map.lookup fd outer)))
