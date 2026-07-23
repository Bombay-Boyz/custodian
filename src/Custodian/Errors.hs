{-# LANGUAGE LinearTypes #-}

-- | The single, closed classification of everything that can go wrong
-- across every backend. Extended by adding constructors, never worked
-- around at a call site (vision doc §2.3). Every value here is pure
-- diagnostic data — no resource ownership — which is why it is safely
-- 'Movable'.
module Custodian.Errors
  ( CustodianError (..)
  , MapMismatch (..)
  ) where

import Data.Unrestricted.Linear
  ( Consumable (..)
  , Dupable (..)
  , Movable (..)
  , Ur (..)
  )
import Foreign.C.Types (CInt)
import Unsafe.Linear qualified as Unsafe
import Prelude

-- | Describes exactly how a caller's chosen key\/value Haskell types
-- disagreed with the kernel map's declared byte sizes. Carrying the
-- four numbers (rather than a pre-rendered string) keeps the failure
-- inspectable and testable: a property can assert the precise mismatch,
-- not merely that /some/ error occurred.
data MapMismatch = MapMismatch
  { mismatchExpectedKeySize :: !Int
  , mismatchActualKeySize :: !Int
  , mismatchExpectedValueSize :: !Int
  , mismatchActualValueSize :: !Int
  }
  deriving (Show, Eq)

-- | Closed classification of every failure mode.
data CustodianError
  = -- | Mock backend only ('Custodian.Mock').
    MockFailure String
  | -- | A real @libbpf@\/kernel call failed. Kept distinct from
    -- 'MockFailure' so a real failure is never mislabelled as a mock one.
    LibbpfFailure String
  | -- | A map element syscall failed with a preserved @errno@ (vision
    -- doc §5: "errno preserved"). The 'String' names the failing
    -- operation (e.g. @"bpf_map_lookup_elem"@) and the 'CInt' is the raw
    -- @errno@ value, kept as a number so a caller can match on @EPERM@,
    -- @E2BIG@, etc. rather than parse a rendered message. @ENOENT@ is
    -- deliberately /not/ reported here: for lookup and iteration it is
    -- the normal "absent"\/"end" signal, handled in 'Custodian.Map'
    -- before it can reach this constructor.
    SyscallFailure String CInt
  | -- | A 'Custodian.Map.withMap' call was asked to view a map with
    -- key\/value Haskell types whose 'Foreign.Storable.sizeOf' does not
    -- match the kernel map's declared @key_size@\/@value_size@. Reported
    -- /before/ any read or write can touch memory, closing the buffer
    -- over-\/under-run hole that an unchecked cast would open.
    MapShapeMismatch String MapMismatch
  deriving (Show, Eq)

-- | A 'CustodianError' owns no resource, so discarding one releases
-- nothing; 'consume' is therefore a total no-op, asserted through the
-- sanctioned escape hatch exactly as 'Dupable'\/'Movable' below are.
instance Consumable CustodianError where
  consume = Unsafe.toLinear (\_ -> ())

-- | Total, resource-free duplication of pure diagnostic data. The
-- 'Unsafe.toLinear' is the sanctioned escape for a reconstruction GHC's
-- (documented-experimental) case-multiplicity inference cannot verify
-- through a lambda; there is no aliasing or leak hazard because the
-- value owns no resource.
instance Dupable CustodianError where
  dup2 = Unsafe.toLinear (\e -> (e, e))

-- | Pull a plain, freely-reusable copy of the error out of linear land
-- (via 'Ur') so it can be shown\/logged, not merely discarded.
instance Movable CustodianError where
  move = Unsafe.toLinear Ur
