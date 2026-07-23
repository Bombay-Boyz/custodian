{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}

-- | The typed map API (vision doc §2.5\/§3.5).
--
-- Two guarantees this module adds over a naive @Ptr@-and-@fd@ binding,
-- both of them the point of the redesign:
--
--   1. __Shape safety.__ A 'LiveMap' is only ever constructed by
--      'withMap', and only after 'checkMapShape' has confirmed that the
--      caller's key\/value Haskell types have /exactly/ the byte sizes
--      the kernel map declares. A mismatch is reported as a
--      'MapShapeMismatch' before any 'readMap'\/'writeMap' can 'poke' or
--      'peek' a buffer, closing the stack over-\/under-run that an
--      unchecked cast would open. This is pure, total, and property-
--      tested independently of any backend ('checkMapShape').
--
--   2. __Scope safety.__ 'LiveMap' carries a rank-2 brand @br@ that
--      'withMap' introduces and that unifies with nothing outside the
--      callback, so a 'LiveMap' cannot escape the scope in which its
--      parent object is guaranteed live (the same @runST@ trick). It is
--      deliberately /not/ linear: reads and writes are repeatable, not
--      one-shot, so @%1@ would force pointless token-threading.
--
-- 'MapType' is a promoted ADT, and 'ValidKey' turns an illegal
-- key\/map-type pairing (an array map keyed by anything but 'Word32')
-- into a compile error rather than a runtime surprise.
module Custodian.Map
  ( -- * Map classification
    MapType (..)
  , SMapType (..)
  , ValidKey
  , Deletable

    -- * Kernel-declared shape and its validation
  , MapShape (..)
  , checkMapShape

    -- * Handles
  , LiveMap
  , liveMapFd

    -- * Capabilities
  , MapLookup (..)
  , MapSyscalls (..)

    -- * Scoped access and element operations
  , withMap
  , readMap
  , writeMap
  , deleteMap
  , mapKeys
  ) where

import Custodian.Errors (CustodianError (..), MapMismatch (..))
import Data.Kind (Type)
import Data.Proxy (Proxy (..))
import Data.Word (Word32, Word8)
import Foreign.C.Error (Errno (..))
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Marshal.Array (peekArray, pokeArray)
import Foreign.Marshal.Utils (with)
import Foreign.Ptr (castPtr)
import Foreign.Storable (Storable (..))
import System.Posix.Types (Fd)
import Prelude

-- | Map-type witness at the /kind/ level (promoted via @DataKinds@). v1
-- supports only these two.
data MapType = HashMap | ArrayMap
  deriving (Show, Eq)

-- | Singleton witness, so a 'MapType' can be matched on at the term
-- level without a partial mapping from some untyped tag.
data SMapType (t :: MapType) where
  SHashMap :: SMapType 'HashMap
  SArrayMap :: SMapType 'ArrayMap

-- | Which Haskell key types are legal for which map type. A
-- @BPF_MAP_TYPE_ARRAY@ is indexed by a 32-bit slot number, so its key is
-- always 'Word32'; a hash map may be keyed by any 'Storable'. Making
-- this a class (rather than a runtime check) means an array map keyed by
-- the wrong type fails to /compile/.
class (Storable k) => ValidKey (t :: MapType) k

instance (Storable k) => ValidKey 'HashMap k
instance ValidKey 'ArrayMap Word32

-- | Which map types support element /deletion/. A @BPF_MAP_TYPE_ARRAY@
-- is a fixed, densely-allocated table: @bpf_map_delete_elem@ on one
-- returns @EINVAL@, because a slot cannot cease to exist. Encoding that
-- as a missing instance (rather than a runtime @EINVAL@) makes
-- 'deleteMap' on an array map a /compile error/ — the same
-- illegal-states-unrepresentable discipline as 'ValidKey'.
class Deletable (t :: MapType)

instance Deletable 'HashMap

-- (no instance for 'ArrayMap — deletion is not a representable operation)

-- | The map's kernel-declared byte geometry, as reported by
-- @bpf_map__key_size@\/@bpf_map__value_size@ (or injected by the mock).
data MapShape = MapShape
  { shapeKeySize :: !Int
  , shapeValueSize :: !Int
  }
  deriving (Show, Eq)

-- | The whole safety argument in one total function: the caller's chosen
-- types fit the kernel map iff their 'sizeOf's match the declared sizes,
-- exactly. Anything else is a 'MapMismatch' carrying all four numbers.
--
-- Pre-condition:  none.
-- Post-condition: @Right ()@ iff @expK == 'shapeKeySize' s@ and
--                 @expV == 'shapeValueSize' s@; otherwise @Left@ with the
--                 four sizes, and never a partial result.
checkMapShape :: Int -> Int -> MapShape -> Either MapMismatch ()
checkMapShape expK expV (MapShape actK actV)
  | expK == actK && expV == actV = Right ()
  | otherwise =
      Left
        MapMismatch
          { mismatchExpectedKeySize = expK
          , mismatchActualKeySize = actK
          , mismatchExpectedValueSize = expV
          , mismatchActualValueSize = actV
          }

-- | A scoped, typed handle onto a declared map. @sys@ names the backend
-- that services element operations, @br@ is the escape-preventing brand,
-- @t@ the 'MapType', and @k@\/@v@ the key\/value types. Backed only by
-- the map's file descriptor: @libbpf@ has no @bpf_map__destroy@, so a
-- map's lifetime is owned entirely by its parent object and there is
-- nothing for 'withMap' to release.
newtype LiveMap sys br (t :: MapType) k v = LiveMap {liveMapFd :: Fd}

-- | Capability: resolve a declared map by name to its file descriptor
-- /and/ its kernel-declared shape. Returning the shape (not just the fd)
-- is what lets 'withMap' validate before handing out a 'LiveMap'.
class MapLookup objRes where
  -- | The element-syscall backend that services maps found through this
  -- object resource. Ties an object backend to exactly one 'MapSyscalls'
  -- instance, so 'withMap' cannot mix a real object with a mock syscall
  -- table or vice versa.
  type Sys objRes :: Type

  rawFindMap :: objRes -> String -> IO (Either CustodianError (Fd, MapShape))

-- | Capability: the element-level operations, one instance per backend.
-- Modelled at the byte level (exactly what the kernel exchanges) so the
-- 'Storable' marshalling in 'readMap' et al. is genuinely exercised.
--
-- Every method surfaces failures as @'Left' 'Errno'@, preserving the
-- kernel's @errno@ (vision doc §5). @ENOENT@ is folded into the /result/
-- rather than the error, because for lookup and iteration it is the
-- normal "absent"\/"no more keys" signal, not a failure: 'sysLookup'
-- reports it as @Right Nothing@ and 'sysDelete' as @Right False@.
class MapSyscalls sys where
  -- | @sysLookup p fd valueSize key@: read the value for @key@.
  -- @Right (Just v)@ found; @Right Nothing@ = @ENOENT@; @Left e@ = other
  -- failure. @valueSize@ (the map's declared @value_size@) sizes the
  -- receive buffer.
  sysLookup
    :: Proxy sys -> Fd -> Int -> [Word8] -> IO (Either Errno (Maybe [Word8]))

  -- | Insert or update. @Right ()@ on success.
  sysUpdate :: Proxy sys -> Fd -> [Word8] -> [Word8] -> IO (Either Errno ())

  -- | Delete. @Right True@ removed; @Right False@ = @ENOENT@ (absent);
  -- @Left e@ = other failure.
  sysDelete :: Proxy sys -> Fd -> [Word8] -> IO (Either Errno Bool)

  -- | @sysKeys p fd keySize@: all keys. @keySize@ sizes the iteration
  -- buffer. Normal @ENOENT@ termination is /not/ an error here.
  sysKeys :: Proxy sys -> Fd -> Int -> IO (Either Errno [[Word8]])

-- | Serialise a 'Storable' to its raw bytes (total: 'sizeOf' bytes,
-- exactly).
toBytes :: (Storable a) => a -> IO [Word8]
toBytes x = with x (\p -> peekArray (sizeOf x) (castPtr p))

-- | Deserialise raw bytes back to a 'Storable'. Only ever called on byte
-- lists produced against the same, shape-validated type, so the length
-- always matches 'sizeOf'.
fromBytes :: forall a. (Storable a) => [Word8] -> IO a
fromBytes bs =
  allocaBytes (sizeOf (undefined :: a)) $ \p -> do
    pokeArray (castPtr p) bs
    peek p

-- | Run a callback against a named map, validating the map's shape
-- against @k@\/@v@ first and scoping the resulting 'LiveMap' so it
-- cannot escape.
--
-- Pre-condition:  @objRes@ borrows a still-live 'Custodian.Core.Loaded'
--                 (or 'Custodian.Core.Attached') object — guaranteed by
--                 obtaining it from a 'Custodian.Core.Scope'.
-- Post-condition: the callback runs, and its result is returned, iff the
--                 map exists and its declared shape matches @k@\/@v@;
--                 otherwise a 'Left' is returned and the callback never
--                 runs (so no read\/write on a mis-sized buffer is
--                 possible).
withMap
  :: forall objRes t k v a
   . (MapLookup objRes, ValidKey t k, Storable v)
  => objRes
  -> String
  -> (forall br. LiveMap (Sys objRes) br t k v -> IO a)
  -> IO (Either CustodianError a)
withMap objRes name callback = do
  found <- rawFindMap objRes name
  case found of
    Left err -> pure (Left err)
    Right (fd, shape) ->
      case checkMapShape (sizeOf (undefined :: k)) (sizeOf (undefined :: v)) shape of
        Left mism -> pure (Left (MapShapeMismatch name mism))
        Right () -> Right <$> callback (LiveMap fd)

-- | Look up a key.
--
-- Post-condition: @Right (Just v)@ if present; @Right Nothing@ if absent
--                 (@ENOENT@); @Left ('SyscallFailure' ..)@ preserving
--                 @errno@ on any other failure.
readMap
  :: forall sys br t k v
   . (MapSyscalls sys, Storable k, Storable v)
  => LiveMap sys br t k v
  -> k
  -> IO (Either CustodianError (Maybe v))
readMap (LiveMap fd) key = do
  kb <- toBytes key
  result <- sysLookup (Proxy :: Proxy sys) fd (sizeOf (undefined :: v)) kb
  case result of
    Left e -> pure (Left (syscallError "bpf_map_lookup_elem" e))
    Right Nothing -> pure (Right Nothing)
    Right (Just vb) -> (Right . Just) <$> fromBytes vb

-- | Insert or update a key\/value pair.
--
-- Post-condition: @Right ()@ on success; @Left ('SyscallFailure' ..)@
--                 preserving @errno@ on failure.
writeMap
  :: forall sys br t k v
   . (MapSyscalls sys, Storable k, Storable v)
  => LiveMap sys br t k v
  -> k
  -> v
  -> IO (Either CustodianError ())
writeMap (LiveMap fd) key value = do
  kb <- toBytes key
  vb <- toBytes value
  result <- sysUpdate (Proxy :: Proxy sys) fd kb vb
  pure (either (Left . syscallError "bpf_map_update_elem") Right result)

-- | Delete a key. Unlike 'readMap', a missing key is a genuine failure
-- (matching @bpf_map_delete_elem@): deleting something never present
-- usually signals a caller logic error worth surfacing.
--
-- Post-condition: @Right ()@ if the key was present and removed;
--                 @Left ('LibbpfFailure' ..)@ if it was absent;
--                 @Left ('SyscallFailure' ..)@ preserving @errno@ on any
--                 other failure.
deleteMap
  :: forall sys br t k v
   . (MapSyscalls sys, Deletable t, Storable k)
  => LiveMap sys br t k v
  -> k
  -> IO (Either CustodianError ())
deleteMap (LiveMap fd) key = do
  kb <- toBytes key
  result <- sysDelete (Proxy :: Proxy sys) fd kb
  pure $ case result of
    Left e -> Left (syscallError "bpf_map_delete_elem" e)
    Right True -> Right ()
    Right False -> Left (LibbpfFailure "deleteMap: key not present")

-- | All keys currently in the map. Order is unspecified (the kernel's
-- iteration order is not guaranteed), so callers must not depend on it.
--
-- Post-condition: @Right ks@ on success (@Right []@ for an empty map,
--                 never a failure); @Left ('SyscallFailure' ..)@
--                 preserving @errno@ on failure.
mapKeys
  :: forall sys br t k v
   . (MapSyscalls sys, Storable k)
  => LiveMap sys br t k v
  -> IO (Either CustodianError [k])
mapKeys (LiveMap fd) = do
  result <- sysKeys (Proxy :: Proxy sys) fd (sizeOf (undefined :: k))
  case result of
    Left e -> pure (Left (syscallError "bpf_map_get_next_key" e))
    Right kbs -> Right <$> traverse fromBytes kbs

-- | Package a preserved 'Errno' into a 'CustodianError', naming the
-- failing syscall.
syscallError :: String -> Errno -> CustodianError
syscallError op (Errno n) = SyscallFailure op n
