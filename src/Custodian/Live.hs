{-# LANGUAGE LinearTypes #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE QualifiedDo #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}

-- | The real backend: 'ObjectLifecycle'/'AttachDetach' instances wired
-- against actual @libbpf@ calls ('Custodian.Raw'). This is the second
-- instantiation of the capability classes 'Custodian.Mock' also
-- provides -- proof that the Dependency Inversion in "Custodian" is
-- real, not a type that only ever had one instance.
--
-- Scope note: matches 'Custodian.Raw''s own scope note -- single-program
-- objects, plain @bpf_object__open@ (no options struct).
--
-- Plain (non-linear) marshalling logic here is written against an
-- explicitly @qualified Prelude as P@ rather than importing 'Prelude'
-- unqualified alongside 'Prelude.Linear': linear-base's own source
-- hides 'Prelude.Linear''s @IO@ when combining it with
-- "System.IO.Linear", implying real name clashes between the two
-- unqualified -- qualifying one side entirely sidesteps that rather
-- than risk it.
-- Orphan instances are unavoidable and deliberate here, not an
-- oversight: 'ObjectLifecycle'/'AttachDetach' are defined in
-- "Custodian" (kept backend-agnostic on purpose), and 'Ptr' 'CBpfObject'
-- is defined in base + "Custodian.Raw" -- neither lives in this module,
-- by design, since the whole point of this module is to be the SECOND
-- instantiation of those classes (alongside "Custodian.Mock", which
-- avoids the warning only because it happens to define its own
-- 'MockHandle' locally). Suppressed here, scoped to this file only, not
-- project-wide.
{-# OPTIONS_GHC -Wno-orphans #-}
module Custodian.Live () where

import Prelude.Linear
import qualified Prelude as P
import qualified System.IO.Linear as Linear
import qualified Unsafe.Linear as Unsafe
import Foreign.Ptr (Ptr, nullPtr)
import Foreign.C.String (withCString)
import Custodian (ObjectLifecycle (..), AttachDetach (..))
import Custodian.Errors (CustodianError (..))
import Custodian.Raw
  ( CBpfObject
  , CBpfLink
  , c_bpf_object__open
  , c_bpf_object__load
  , c_bpf_object__close
  , c_bpf_object__next_program
  , c_bpf_program__attach
  , c_bpf_link__destroy
  )

instance ObjectLifecycle (Ptr CBpfObject) where
  rawOpen path = Linear.fromSystemIO $
    withCString path $ \cpath ->
      c_bpf_object__open cpath P.>>= \ptr ->
        P.pure $
          if ptr P.== nullPtr
            then Left (LibbpfFailure (path P.++ ": bpf_object__open returned NULL"))
            else Right ptr

  -- 'Ptr' values are ordinary, freely-copyable machine words at the
  -- Haskell level -- the actual resource being protected is the kernel
  -- object the pointer merely names, not the pointer's bit pattern.
  -- 'Unsafe.toLinear' here asserts exactly that: this function uses its
  -- linear argument in a genuinely single-threaded way (pass to one FFI
  -- call, return the same value onward), which GHC's case/pattern
  -- inference for linear function bodies can't verify through a lambda,
  -- per the same documented-experimental limitation noted throughout
  -- "Custodian" and "Custodian.Mock".
  rawLoad = Unsafe.toLinear $ \ptr ->
    Linear.fromSystemIO $
      c_bpf_object__load ptr P.>>= \rc ->
        P.pure $
          if rc P.< 0
            then Left (LibbpfFailure ("bpf_object__load failed, rc=" P.++ P.show rc))
            else Right ptr

  rawClose = Unsafe.toLinear $ \ptr ->
    Linear.fromSystemIO (c_bpf_object__close ptr)

instance AttachDetach (Ptr CBpfObject) (Ptr CBpfLink) where
  -- Scope note (matches Custodian.Raw): always fetches the /first/
  -- program via @bpf_object__next_program(obj, NULL)@ -- single-program
  -- objects only, per Phase 2's first-slice scope.
  --
  -- Returns 'objPtr' alongside the error on EVERY failure path, not
  -- just on success: neither 'bpf_object__next_program' nor
  -- 'bpf_program__attach' failing invalidates the underlying object --
  -- it stays open and must still be closed. An earlier version of this
  -- function discarded 'objPtr' on failure, silently leaking the real
  -- kernel object every time attach failed.
  rawAttach = Unsafe.toLinear $ \objPtr ->
    Linear.fromSystemIO $
      c_bpf_object__next_program objPtr nullPtr P.>>= \progPtr ->
        if progPtr P.== nullPtr
          then P.pure (Left (objPtr, LibbpfFailure "bpf_object__next_program: no program found in object"))
          else
            c_bpf_program__attach progPtr P.>>= \linkPtr ->
              P.pure $
                if linkPtr P.== nullPtr
                  then Left (objPtr, LibbpfFailure "bpf_program__attach failed")
                  else Right (objPtr, linkPtr)

  rawDetach = Unsafe.toLinear $ \linkPtr ->
    Linear.fromSystemIO $
      c_bpf_link__destroy linkPtr P.>>= \_rc -> P.pure ()
