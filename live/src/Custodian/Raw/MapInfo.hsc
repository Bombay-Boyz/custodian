{-# LANGUAGE ScopedTypeVariables #-}

-- | Header-derived layout of @struct bpf_map_info@ (vision doc §2.6,
-- Risk #1a). Every offset and the total size below is computed by
-- @hsc2hs@ from @<linux/bpf.h>@ at build time — /not/ hand-transcribed —
-- so a kernel-header change that moves a field cannot silently corrupt a
-- read. This is DRY (§2.3) applied to the single highest-risk fact in a
-- binding: a struct field offset.
module Custodian.Raw.MapInfo
  ( MapInfo (..)
  , sizeOfMapInfo
  , peekMapInfo
  ) where

import Data.Word (Word32)
import Foreign.Ptr (Ptr)
import Foreign.Storable (peekByteOff)

#include <linux/bpf.h>

-- | The subset of @struct bpf_map_info@ Custodian needs: enough to
-- validate a caller's key\/value types against the kernel's own view of
-- the map (fix #1), sourced canonically from the kernel rather than from
-- a userspace guess.
data MapInfo = MapInfo
  { mapInfoType       :: !Word32
  , mapInfoKeySize    :: !Word32
  , mapInfoValueSize  :: !Word32
  , mapInfoMaxEntries :: !Word32
  }
  deriving (Show, Eq)

-- | @sizeof(struct bpf_map_info)@, from the header. Callers allocate a
-- buffer of exactly this size before 'Custodian.Raw.c_bpf_map_get_info_by_fd'.
sizeOfMapInfo :: Int
sizeOfMapInfo = #{size struct bpf_map_info}

-- | Read the four fields Custodian uses out of a filled-in
-- @struct bpf_map_info@ buffer, each at its header-derived offset.
peekMapInfo :: Ptr a -> IO MapInfo
peekMapInfo p =
  MapInfo
    <$> #{peek struct bpf_map_info, type}        p
    <*> #{peek struct bpf_map_info, key_size}    p
    <*> #{peek struct bpf_map_info, value_size}  p
    <*> #{peek struct bpf_map_info, max_entries} p
