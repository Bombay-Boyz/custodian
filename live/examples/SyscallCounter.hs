{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeApplications #-}

-- | The canonical eBPF "hello world" (vision doc §9), written against
-- Custodian's phantom-typed /and/ linear-typed API. It opens a compiled
-- object, attaches its tracepoint program, and exercises the typed map
-- API against the genuine kernel-created @counters@ map — all inside the
-- 'withAttachedBpfObject' bracket, so teardown (detach then close) runs
-- exactly once no matter how the body exits.
--
-- Requires @libbpf@ to link and a @CAP_BPF@-capable kernel plus the
-- compiled @hello.bpf.o@ to run. It builds\/links without either.
module Main (main) where

import Data.Word (Word32, Word64)

import Custodian.Core (scopeResource, withAttachedBpfObject)
import Custodian.Errors (CustodianError)
import Custodian.Live (LiveObj)
import Custodian.Map (MapType (HashMap), mapKeys, readMap, withMap, writeMap)

objectPath :: FilePath
objectPath = "hello.bpf.o"

main :: IO ()
main = do
  outcome <-
    withAttachedBpfObject @LiveObj objectPath $ \scope -> do
      -- The object is guaranteed live for this whole scope; the borrowed
      -- resource drives the typed map API and cannot escape or be freed.
      inner <-
        withMap @LiveObj @'HashMap @Word32 @Word64 (scopeResource scope) "counters" $ \m -> do
          w1 <- writeMap m 42 100
          w2 <- writeMap m 7 200
          readback <- readMap m 42
          keys <- mapKeys m
          -- Combine element-op results in the Either monad: any Left
          -- short-circuits, otherwise pair the readback with the keys.
          pure (w1 *> w2 *> ((,) <$> readback <*> keys))
      pure (flatten inner)
  report outcome

-- | Collapse the two Either layers ('withMap' wraps the element-op
-- Either) into one.
flatten
  :: Either CustodianError (Either CustodianError a)
  -> Either CustodianError a
flatten = either Left id

-- | 'withAttachedBpfObject' and the map callback each return an
-- 'Either', so the result is doubly wrapped; report each failure layer
-- distinctly.
report
  :: Either CustodianError (Either CustodianError (Maybe Word64, [Word32]))
  -> IO ()
report (Left err) = putStrLn ("lifecycle failed: " ++ show err)
report (Right (Left err)) = putStrLn ("map operation failed: " ++ show err)
report (Right (Right (readback, keys))) = do
  putStrLn ("counters[42] = " ++ show readback)
  putStrLn ("counters keys = " ++ show keys)
