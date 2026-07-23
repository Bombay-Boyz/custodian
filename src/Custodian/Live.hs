{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE LinearTypes #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE QualifiedDo #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -Wno-orphans #-}

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
module Custodian.Live () where

import Custodian (AttachDetach (..), ObjectLifecycle (..))
import Custodian.Errors (CustodianError (..))
import Custodian.Map (MapLookup (..))
import Custodian.Raw
  ( CBpfLink
  , CBpfObject
  , c_bpf_link__destroy
  , c_bpf_map__fd
  , c_bpf_object__close
  , c_bpf_object__find_map_by_name
  , c_bpf_object__load
  , c_bpf_object__next_program
  , c_bpf_object__open
  , c_bpf_program__attach
  )
import Foreign.C.String (withCString)
import Foreign.Ptr (Ptr, nullPtr)
import Prelude.Linear
import qualified System.IO.Linear as Linear
import System.Posix.Types (Fd (..))
import qualified Unsafe.Linear as Unsafe
import qualified Prelude as P

-- | 'Ptr' values are ordinary, freely-copyable machine addresses at the
-- Haskell level -- duplicating or discarding the pointer VALUE never
-- touches the underlying kernel resource it merely names, so these are
-- safe in the same sense 'MockHandle''s instances are. Needed for
-- 'Custodian.borrowObjRes'\/'Custodian.withLoadedBpfObject'\/
-- 'Custodian.withAttachedBpfObject' to work against this backend.
instance Consumable (Ptr CBpfObject) where
  consume = Unsafe.toLinear (\_ -> ())

instance Dupable (Ptr CBpfObject) where
  dup2 = Unsafe.toLinear (\p -> (p, p))

instance Consumable (Ptr CBpfLink) where
  consume = Unsafe.toLinear (\_ -> ())

instance Dupable (Ptr CBpfLink) where
  dup2 = Unsafe.toLinear (\p -> (p, p))

instance ObjectLifecycle (Ptr CBpfObject) where
  rawOpen path = Linear.fromSystemIO
    $ withCString path
    $ \cpath ->
      c_bpf_object__open cpath P.>>= \ptr ->
        P.pure
          $ if ptr P.== nullPtr
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
    Linear.fromSystemIO
      $ c_bpf_object__load ptr
      P.>>= \rc ->
        P.pure
          $ if rc P.< 0
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
    Linear.fromSystemIO
      $ c_bpf_object__next_program objPtr nullPtr
      P.>>= \progPtr ->
        if progPtr P.== nullPtr
          then
            P.pure
              ( Left
                  (objPtr, LibbpfFailure "bpf_object__next_program: no program found in object")
              )
          else
            c_bpf_program__attach progPtr P.>>= \linkPtr ->
              P.pure
                $ if linkPtr P.== nullPtr
                  then Left (objPtr, LibbpfFailure "bpf_program__attach failed")
                  else Right (objPtr, linkPtr)

  rawDetach = Unsafe.toLinear $ \linkPtr ->
    Linear.fromSystemIO
      $ c_bpf_link__destroy linkPtr
      P.>>= \_rc -> P.pure ()

instance MapLookup (Ptr CBpfObject) where
  rawFindMapFd objPtr name =
    withCString name $ \cname ->
      c_bpf_object__find_map_by_name objPtr cname P.>>= \mapPtr ->
        if mapPtr P.== nullPtr
          then
            P.pure
              (Left (LibbpfFailure (name P.++ ": bpf_object__find_map_by_name returned NULL")))
          else
            c_bpf_map__fd mapPtr P.>>= \fd ->
              P.pure
                $ if fd P.< 0
                  then Left (LibbpfFailure "bpf_map__fd returned a negative fd")
                  else Right (Fd fd)
