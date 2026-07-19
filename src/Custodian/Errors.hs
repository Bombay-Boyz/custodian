module Custodian.Errors (CustodianError (..)) where

import Relude
import Data.Unrestricted.Linear (Consumable (..), Dupable (..), Movable (..), Ur (..))
import qualified Unsafe.Linear as Unsafe

-- | Closed classification of everything that can go wrong across the
-- mock and real backends. Extended, never worked around, per §2.3.
data CustodianError
  = MockFailure String
    -- ^ Mock backend only ('Custodian.Mock').
  | LibbpfFailure String
    -- ^ Real backend only ('Custodian.Live'/'Custodian.Raw') -- a genuine
    -- @libbpf@ call failed. Deliberately a separate constructor from
    -- 'MockFailure' rather than reusing it: labelling a real kernel-level
    -- failure as a "mock" failure would be actively misleading. Still
    -- just a descriptive string for now (Phase 2 first slice); capturing
    -- structured @errno@ values is a reasonable future extension, not
    -- done here.
  deriving (Show, Eq)

instance Consumable CustodianError where
  consume err = case err of
    MockFailure s -> consume s
    LibbpfFailure s -> consume s

-- | Required superclass of 'Movable' below. Same justification as
-- 'Movable''s instance: a total, resource-free duplication of a
-- String-only value, safely assertable via 'Unsafe.toLinear'.
instance Dupable CustodianError where
  dup2 =
    Unsafe.toLinear
      ( \err -> case err of
          MockFailure s -> (MockFailure s, MockFailure s)
          LibbpfFailure s -> (LibbpfFailure s, LibbpfFailure s)
      )

-- | Errors are diagnostic data, not a resource with an ownership
-- discipline to protect -- there is no reason a 'CustodianError' should
-- ever need to be discarded unread. 'Movable' is linear-base's sanctioned
-- way to get a plain, freely-reusable value out of a linear context
-- (via 'Ur'), which is what real logging/diagnostics needs -- 'consume'
-- alone (above) can only throw the error away, never inspect it.
--
-- Uses 'Unsafe.toLinear' rather than a direct equation: this is a total,
-- non-resource-holding reconstruction of a String-only value (no
-- aliasing or leak hazard whatsoever), but GHC's case/pattern
-- multiplicity inference for linear equations is documented as
-- experimental and can over-eagerly reject things like this that are
-- genuinely safe -- this is exactly the well-scoped case that escape
-- hatch exists for, not a way to paper over an actual linearity bug.
instance Movable CustodianError where
  move =
    Unsafe.toLinear
      ( \err -> case err of
          MockFailure s -> Ur (MockFailure s)
          LibbpfFailure s -> Ur (LibbpfFailure s)
      )
