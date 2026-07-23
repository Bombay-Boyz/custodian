{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ForeignFunctionInterface #-}

-- | Near-verbatim FFI declarations against @libbpf@'s public C API
-- (headers under @\/usr\/include\/bpf@, package @libbpf-dev@, version
-- 1.5.0 at the time these declarations were transcribed -- see
-- 'libbpfVersion' below).
--
-- Deliberately unopinionated and near-1:1 with the C headers (vision
-- doc §3.1): every function here corresponds to exactly one @libbpf@
-- function, with no error classification, no linear types, and no
-- Haskell-idiomatic wrapping. That belongs in the 'Custodian' module,
-- instantiated against these declarations.
--
-- Uses @capi@ imports throughout, not @ccall@: GHC compiles a small C
-- stub that @#include@s the real header and checks each declared
-- signature against it, so a mismatched type is caught by the C
-- compiler at build time rather than trusted from a hand-transcribed
-- guess (Risk #1a: zero hand-transcribed FFI surface).
--
-- Scope note (Phase 2, first slice): assumes a single-program BPF
-- object -- 'bpfObjectFirstProgram' always fetches the first program
-- via @bpf_object__next_program(obj, NULL)@, matching the vision doc's
-- v1 scope (no per-program lookup by name yet). 'bpf_object__open' is
-- used (not the @_file@/@_opts@ variant), so no options struct -- and
-- therefore no 'hsc2hs'-derived 'Storable' instance -- is needed for
-- this slice. @bpf_object@, @bpf_program@, @bpf_map@, and @bpf_link@
-- are all genuinely opaque in the real header (forward-declared, no
-- body) -- confirmed by inspection, not assumed -- so they are
-- represented here as empty phantom types tagging a 'Ptr', never as
-- 'Storable' records.
module Custodian.Raw
  ( -- * Opaque handle tags
    CBpfObject
  , CBpfProgram
  , CBpfLink
  , CBpfMap

    -- * Version (for cross-checking against the Nix-pinned libbpf later)
  , libbpfVersion

    -- * Object lifecycle
  , c_bpf_object__open
  , c_bpf_object__load
  , c_bpf_object__close

    -- * Program lookup and attach
  , c_bpf_object__next_program
  , c_bpf_program__attach
  , c_bpf_link__destroy

    -- * Maps
  , c_bpf_object__find_map_by_name
  , c_bpf_map__fd
  , c_bpf_map_lookup_elem
  , c_bpf_map_update_elem
  , c_bpf_map_delete_elem
  , c_bpf_map_get_next_key
  ) where

import Data.Word (Word64)
import Foreign.C.String (CString)
import Foreign.C.Types (CInt (..))
import Foreign.Ptr (Ptr)
import Prelude

-- | @libbpf@ version this module's declarations were transcribed
-- against (from @bpf\/libbpf_version.h@: @LIBBPF_MAJOR_VERSION 1@,
-- @LIBBPF_MINOR_VERSION 5@). Not read from the header programmatically
-- (that would need its own tiny 'capi' accessor) -- recorded here as a
-- plain value so a version drift is at least visible in one place
-- pending the Phase 2 Nix flake pin.
libbpfVersion :: (Int, Int)
libbpfVersion = (1, 5)

-- | Opaque tag for @struct bpf_object@. The real struct is forward-
-- declared only (@struct bpf_object;@, no body) in @libbpf.h@ -- this
-- type is never constructed or inspected in Haskell, only used to tag
-- 'Ptr' for type safety across the FFI boundary.
data CBpfObject

-- | Opaque tag for @struct bpf_program@ (forward-declared only).
data CBpfProgram

-- | Opaque tag for @struct bpf_link@ (forward-declared only).
data CBpfLink

-- | Opaque tag for @struct bpf_map@ (forward-declared only).
data CBpfMap

-- | @struct bpf_object *bpf_object__open(const char *path);@
foreign import capi unsafe "bpf/libbpf.h bpf_object__open"
  c_bpf_object__open :: CString -> IO (Ptr CBpfObject)

-- | @int bpf_object__load(struct bpf_object *obj);@
foreign import capi unsafe "bpf/libbpf.h bpf_object__load"
  c_bpf_object__load :: Ptr CBpfObject -> IO CInt

-- | @void bpf_object__close(struct bpf_object *obj);@
foreign import capi unsafe "bpf/libbpf.h bpf_object__close"
  c_bpf_object__close :: Ptr CBpfObject -> IO ()

-- | @struct bpf_program *bpf_object__next_program(const struct bpf_object *obj, struct bpf_program *prog);@
--
-- Passing a null 'Ptr' for @prog@ returns the /first/ program in the
-- object (matches the @bpf_object__for_each_program@ macro's own use of
-- this function) -- this is how the single-program-object scope note
-- above is implemented: always call with a null second argument.
foreign import capi unsafe "bpf/libbpf.h bpf_object__next_program"
  c_bpf_object__next_program
    :: Ptr CBpfObject -> Ptr CBpfProgram -> IO (Ptr CBpfProgram)

-- | @struct bpf_link *bpf_program__attach(const struct bpf_program *prog);@
--
-- Auto-detects program type, attach type, and target based on the
-- program's ELF section (per @libbpf.h@'s own doc comment on this
-- function) -- this is the "no special attach-target plumbing" property
-- the vision doc relies on for 'tracepoint'\/'kprobe' scope.
foreign import capi unsafe "bpf/libbpf.h bpf_program__attach"
  c_bpf_program__attach :: Ptr CBpfProgram -> IO (Ptr CBpfLink)

-- | @int bpf_link__destroy(struct bpf_link *link);@
foreign import capi unsafe "bpf/libbpf.h bpf_link__destroy"
  c_bpf_link__destroy :: Ptr CBpfLink -> IO CInt

-- | @struct bpf_map *bpf_object__find_map_by_name(const struct bpf_object *obj, const char *name);@
foreign import capi unsafe "bpf/libbpf.h bpf_object__find_map_by_name"
  c_bpf_object__find_map_by_name :: Ptr CBpfObject -> CString -> IO (Ptr CBpfMap)

-- | @int bpf_map__fd(const struct bpf_map *map);@
foreign import capi unsafe "bpf/libbpf.h bpf_map__fd"
  c_bpf_map__fd :: Ptr CBpfMap -> IO CInt

-- | @int bpf_map_lookup_elem(int fd, const void *key, void *value);@
--
-- Declared in @bpf\/bpf.h@, not @libbpf.h@ -- confirmed by grep against
-- the real installed header; verified again the hard way when a first
-- attempt at pointing this at the wrong header failed to compile.
--
-- @key@\/@value@ are untyped @void*@ byte buffers in the real API --
-- deliberately left as 'Ptr' () here rather than any Haskell record;
-- giving them real types is Phase 4's typed-map-API job, not Raw's.
foreign import capi unsafe "bpf/bpf.h bpf_map_lookup_elem"
  c_bpf_map_lookup_elem :: CInt -> Ptr () -> Ptr () -> IO CInt

-- | @int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags);@
--
-- Declared in @bpf\/bpf.h@, not @libbpf.h@ -- see note above.
foreign import capi unsafe "bpf/bpf.h bpf_map_update_elem"
  c_bpf_map_update_elem :: CInt -> Ptr () -> Ptr () -> Word64 -> IO CInt

-- | @int bpf_map_delete_elem(int fd, const void *key);@
foreign import capi unsafe "bpf/bpf.h bpf_map_delete_elem"
  c_bpf_map_delete_elem :: CInt -> Ptr () -> IO CInt

-- | @int bpf_map_get_next_key(int fd, const void *key, void *next_key);@
--
-- @key@ may be a null 'Ptr' to fetch the /first/ key (per libbpf's own
-- convention, mirroring @bpf_object__next_program@'s null-for-first
-- idiom used elsewhere in this module) -- iteration support (Phase 4)
-- calls this repeatedly, feeding each returned key back in as the next
-- call's @key@, until it returns non-zero (no more keys).
foreign import capi unsafe "bpf/bpf.h bpf_map_get_next_key"
  c_bpf_map_get_next_key :: CInt -> Ptr () -> Ptr () -> IO CInt
