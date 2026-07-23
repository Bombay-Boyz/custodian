{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE EmptyDataDecls #-}

-- | @Custodian.Raw@ — the near-verbatim, /unrestricted/ transcript of the
-- @libbpf@ C API (vision doc §3.1, §2.5).
--
-- This module deliberately contains no linear types, no phantom
-- lifecycle index, and no 'Custodian.Errors.CustodianError': it is meant
-- to be auditable line-by-line against the C headers, nothing more. The
-- linear discipline, the state machine, and the single error hierarchy
-- are all properties of the idiomatic layer ('Custodian.Live',
-- 'Custodian.Core') built /on top/ of this, never smuggled into the FFI
-- declarations themselves.
--
-- Every declaration below corresponds to exactly one @libbpf@ entry
-- point, named identically with a @c_@ prefix. Struct /fields/ are never
-- hand-transcribed here — where a struct must be read, its offsets are
-- derived from the headers by @hsc2hs@ in "Custodian.Raw.MapInfo"
-- (§2.6, Risk #1a).
module Custodian.Raw
  ( -- * Opaque handles (pointers into @libbpf@-owned memory)
    Bpf_object
  , Bpf_map
  , Bpf_program
  , Bpf_link
  , Bpf_map_info

    -- * Object lifecycle
  , c_bpf_object__open
  , c_bpf_object__load
  , c_bpf_object__close

    -- * Programs and links
  , c_bpf_object__next_program
  , c_bpf_program__attach
  , c_bpf_link__destroy

    -- * Maps
  , c_bpf_object__find_map_by_name
  , c_bpf_map__fd
  , c_bpf_map_get_info_by_fd
  , c_bpf_map_lookup_elem
  , c_bpf_map_update_elem
  , c_bpf_map_delete_elem
  , c_bpf_map_get_next_key
  ) where

import Data.Word (Word32, Word64, Word8)
import Foreign.C.String (CString)
import Foreign.C.Types (CInt (..))
import Foreign.Ptr (Ptr)

-- | @struct bpf_object@ — an opened\/loaded ELF object.
data Bpf_object

-- | @struct bpf_map@ — a map declared within an object.
data Bpf_map

-- | @struct bpf_program@ — a program declared within an object.
data Bpf_program

-- | @struct bpf_link@ — the handle returned by attaching a program.
data Bpf_link

-- | @struct bpf_map_info@ — the kernel's own description of a map,
-- filled in by 'c_bpf_map_get_info_by_fd' and decoded via the
-- header-derived offsets in "Custodian.Raw.MapInfo".
data Bpf_map_info

-- | @struct bpf_object *bpf_object__open(const char *path);@
foreign import capi unsafe "bpf/libbpf.h bpf_object__open"
  c_bpf_object__open :: CString -> IO (Ptr Bpf_object)

-- | @int bpf_object__load(struct bpf_object *obj);@
foreign import capi unsafe "bpf/libbpf.h bpf_object__load"
  c_bpf_object__load :: Ptr Bpf_object -> IO CInt

-- | @void bpf_object__close(struct bpf_object *obj);@
foreign import capi unsafe "bpf/libbpf.h bpf_object__close"
  c_bpf_object__close :: Ptr Bpf_object -> IO ()

-- | @struct bpf_program *bpf_object__next_program(const struct bpf_object *obj, struct bpf_program *prog);@
foreign import capi unsafe "bpf/libbpf.h bpf_object__next_program"
  c_bpf_object__next_program
    :: Ptr Bpf_object -> Ptr Bpf_program -> IO (Ptr Bpf_program)

-- | @struct bpf_link *bpf_program__attach(const struct bpf_program *prog);@
foreign import capi unsafe "bpf/libbpf.h bpf_program__attach"
  c_bpf_program__attach :: Ptr Bpf_program -> IO (Ptr Bpf_link)

-- | @int bpf_link__destroy(struct bpf_link *link);@
foreign import capi unsafe "bpf/libbpf.h bpf_link__destroy"
  c_bpf_link__destroy :: Ptr Bpf_link -> IO CInt

-- | @struct bpf_map *bpf_object__find_map_by_name(const struct bpf_object *obj, const char *name);@
foreign import capi unsafe "bpf/libbpf.h bpf_object__find_map_by_name"
  c_bpf_object__find_map_by_name :: Ptr Bpf_object -> CString -> IO (Ptr Bpf_map)

-- | @int bpf_map__fd(const struct bpf_map *map);@
foreign import capi unsafe "bpf/libbpf.h bpf_map__fd"
  c_bpf_map__fd :: Ptr Bpf_map -> IO CInt

-- | @int bpf_map_get_info_by_fd(int map_fd, struct bpf_map_info *info, __u32 *info_len);@
-- The @info@ buffer is read via header-derived offsets in
-- "Custodian.Raw.MapInfo"; here it is just an opaque byte buffer.
foreign import capi unsafe "bpf/bpf.h bpf_map_get_info_by_fd"
  c_bpf_map_get_info_by_fd :: CInt -> Ptr Bpf_map_info -> Ptr Word32 -> IO CInt

-- | @int bpf_map_lookup_elem(int fd, const void *key, void *value);@
foreign import capi unsafe "bpf/bpf.h bpf_map_lookup_elem"
  c_bpf_map_lookup_elem :: CInt -> Ptr Word8 -> Ptr Word8 -> IO CInt

-- | @int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags);@
foreign import capi unsafe "bpf/bpf.h bpf_map_update_elem"
  c_bpf_map_update_elem :: CInt -> Ptr Word8 -> Ptr Word8 -> Word64 -> IO CInt

-- | @int bpf_map_delete_elem(int fd, const void *key);@
foreign import capi unsafe "bpf/bpf.h bpf_map_delete_elem"
  c_bpf_map_delete_elem :: CInt -> Ptr Word8 -> IO CInt

-- | @int bpf_map_get_next_key(int fd, const void *key, void *next_key);@
foreign import capi unsafe "bpf/bpf.h bpf_map_get_next_key"
  c_bpf_map_get_next_key :: CInt -> Ptr Word8 -> Ptr Word8 -> IO CInt
