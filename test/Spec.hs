{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE LinearTypes #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE QualifiedDo #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | Property and example tests for the custodian redesign.
--
-- The accounting backend ('Acct') below records every open\/close\/
-- attach\/detach against global counters, so a property can assert that
-- a resource was released /exactly once/ — not merely "at least once",
-- which is all the original @IORef Bool@ emergency tests could check
-- (review finding #5). A double free shows up as @closes == 2@ /and/ an
-- anomaly; a leak shows up as a non-empty live set.
module Main (main) where

import Control.Exception (ErrorCall (..), throwIO, try)
import Control.Monad (join)
import Data.IORef
import Data.List (nub, sort)
import Data.Set qualified as Set
import Data.Word (Word32, Word64)
import Foreign.C.Error (Errno (..))
import Foreign.C.Types (CInt)
import System.IO.Unsafe (unsafePerformIO)
import System.Posix.Types (Fd (..))
import Prelude

import Control.Functor.Linear qualified as Control
import Data.Unrestricted.Linear (Ur (..))
import Prelude.Linear qualified as L
import System.IO.Linear qualified as Linear
import Unsafe.Linear qualified as Unsafe

import Hedgehog
import Hedgehog.Gen qualified as Gen
import Hedgehog.Range qualified as Range
import Test.Tasty (TestTree, defaultMain, testGroup)
import Test.Tasty.Hedgehog (testProperty)

import Custodian.Core
import Custodian.Errors
import Custodian.Map
import Custodian.Mock
  ( MockHandle
  , MockSys
  , clearMockMaps
  , installMockMap
  , mockHandle
  )

--------------------------------------------------------------------------------
-- Accounting backend: counts resource operations in global IORefs.
--------------------------------------------------------------------------------

newtype Acct = Acct Int

data Ledger = Ledger
  { lNextId :: IORef Int
  , lOpens :: IORef Int
  , lCloses :: IORef Int
  , lAttaches :: IORef Int
  , lDetaches :: IORef Int
  , lLiveObj :: IORef (Set.Set Int)
  , lLiveLink :: IORef (Set.Set Int)
  , lAnomaly :: IORef [String]
  , lOrder :: IORef [String] -- teardown order, newest last
  , lAttachFails :: IORef Bool
  , lOpenFails :: IORef Bool
  , lProgramCount :: IORef Int -- how many programs an attach should bind
  }

{-# NOINLINE ledger #-}
ledger :: Ledger
ledger =
  unsafePerformIO $
    Ledger
      <$> newIORef 0
      <*> newIORef 0
      <*> newIORef 0
      <*> newIORef 0
      <*> newIORef 0
      <*> newIORef Set.empty
      <*> newIORef Set.empty
      <*> newIORef []
      <*> newIORef []
      <*> newIORef False
      <*> newIORef False
      <*> newIORef 1

resetLedger :: IO ()
resetLedger = do
  writeIORef (lNextId ledger) 0
  writeIORef (lOpens ledger) 0
  writeIORef (lCloses ledger) 0
  writeIORef (lAttaches ledger) 0
  writeIORef (lDetaches ledger) 0
  writeIORef (lLiveObj ledger) Set.empty
  writeIORef (lLiveLink ledger) Set.empty
  writeIORef (lAnomaly ledger) []
  writeIORef (lOrder ledger) []
  writeIORef (lAttachFails ledger) False
  writeIORef (lOpenFails ledger) False
  writeIORef (lProgramCount ledger) 1

freshId :: IO Int
freshId = atomicModifyIORef' (lNextId ledger) (\n -> (n + 1, n))

bump :: (Ledger -> IORef Int) -> IO ()
bump sel = atomicModifyIORef' (sel ledger) (\n -> (n + 1, ()))

noteAnomaly :: String -> IO ()
noteAnomaly s = atomicModifyIORef' (lAnomaly ledger) (\xs -> (xs ++ [s], ()))

noteOrder :: String -> IO ()
noteOrder s = atomicModifyIORef' (lOrder ledger) (\xs -> (xs ++ [s], ()))

recordOpen :: IO (Either CustodianError Acct)
recordOpen = do
  fails <- readIORef (lOpenFails ledger)
  if fails
    then pure (Left (LibbpfFailure "open failed"))
    else do
      i <- freshId
      bump lOpens
      atomicModifyIORef' (lLiveObj ledger) (\s -> (Set.insert i s, ()))
      pure (Right (Acct i))

recordClose :: Int -> IO ()
recordClose i = do
  bump lCloses
  noteOrder "close"
  live <- readIORef (lLiveObj ledger)
  if Set.member i live
    then atomicModifyIORef' (lLiveObj ledger) (\s -> (Set.delete i s, ()))
    else noteAnomaly ("double-close object " ++ show i)

-- | A bundle of the links produced by attaching an object's programs.
-- Modelling the link resource as a /list/ (rather than a single link) is
-- how a backend supports multi-program objects without changing the core
-- lifecycle: 'Custodian.Core.teardown' detaches the whole bundle in one
-- linear step. The real backend does the same (see @Custodian.Live@,
-- whose @LiveLink@ carries @[Ptr Bpf_link]@).
newtype AcctLinks = AcctLinks [Int]

recordAttach :: Int -> IO (Either (Acct, CustodianError) (Acct, AcctLinks))
recordAttach i = do
  fails <- readIORef (lAttachFails ledger)
  n <- readIORef (lProgramCount ledger)
  if fails
    then pure (Left (Acct i, LibbpfFailure "attach failed"))
    else do
      lids <- mapM (const attachOne) [1 .. n]
      pure (Right (Acct i, AcctLinks lids))
  where
    attachOne = do
      lid <- freshId
      bump lAttaches
      atomicModifyIORef' (lLiveLink ledger) (\s -> (Set.insert lid s, ()))
      pure lid

-- | Detach every link in the bundle, newest first (mirroring a real
-- backend tearing down links in reverse attach order), each exactly once.
recordDetach :: [Int] -> IO ()
recordDetach lids = mapM_ detachOne (reverse lids)
  where
    detachOne i = do
      bump lDetaches
      noteOrder "detach"
      live <- readIORef (lLiveLink ledger)
      if Set.member i live
        then atomicModifyIORef' (lLiveLink ledger) (\s -> (Set.delete i s, ()))
        else noteAnomaly ("double-detach link " ++ show i)

instance L.Consumable Acct where
  consume = Unsafe.toLinear (\(Acct i) -> L.consume i)

instance L.Dupable Acct where
  dup2 = Unsafe.toLinear (\(Acct i) -> (Acct i, Acct i))

instance L.Consumable AcctLinks where
  consume = Unsafe.toLinear (\(AcctLinks is) -> L.consume is)

instance L.Dupable AcctLinks where
  dup2 = Unsafe.toLinear (\(AcctLinks is) -> (AcctLinks is, AcctLinks is))

instance ObjectLifecycle Acct where
  rawOpen _ = Linear.fromSystemIO recordOpen
  rawLoad = Unsafe.toLinear (\(Acct i) -> Control.pure (Right (Acct i)))
  rawClose = Unsafe.toLinear (\(Acct i) -> Linear.fromSystemIO (recordClose i))

instance AttachDetach Acct AcctLinks where
  rawAttach = Unsafe.toLinear (\(Acct i) -> Linear.fromSystemIO (recordAttach i))
  rawDetach = Unsafe.toLinear (\(AcctLinks is) -> Linear.fromSystemIO (recordDetach is))

--------------------------------------------------------------------------------
-- checkMapShape: pure, total shape validation (fix #1, unit core)
--------------------------------------------------------------------------------

prop_shapeMatchesIffSizesEqual :: Property
prop_shapeMatchesIffSizesEqual = property $ do
  expK <- forAll (Gen.int (Range.linear 0 4096))
  expV <- forAll (Gen.int (Range.linear 0 4096))
  actK <- forAll (Gen.int (Range.linear 0 4096))
  actV <- forAll (Gen.int (Range.linear 0 4096))
  let result = checkMapShape expK expV (MapShape actK actV)
  case result of
    Right () -> do
      expK === actK
      expV === actV
    Left m -> do
      -- the reported numbers are exactly the inputs, and at least one differs
      mismatchExpectedKeySize m === expK
      mismatchActualKeySize m === actK
      mismatchExpectedValueSize m === expV
      mismatchActualValueSize m === actV
      assert (expK /= actK || expV /= actV)

prop_shapeExactMatchAccepts :: Property
prop_shapeExactMatchAccepts = property $ do
  k <- forAll (Gen.int (Range.linear 0 4096))
  v <- forAll (Gen.int (Range.linear 0 4096))
  checkMapShape k v (MapShape k v) === Right ()

-- Off-by-one in either dimension is always rejected (the classic
-- buffer-overrun trigger).
prop_shapeOffByOneRejected :: Property
prop_shapeOffByOneRejected = property $ do
  k <- forAll (Gen.int (Range.linear 1 4096))
  v <- forAll (Gen.int (Range.linear 1 4096))
  d <- forAll (Gen.element [(-1), 1])
  assert (isLeft (checkMapShape k v (MapShape (k + d) v)))
  assert (isLeft (checkMapShape k v (MapShape k (v + d))))
  where
    isLeft = either (const True) (const False)

--------------------------------------------------------------------------------
-- withMap: accept iff shape matches; callback runs iff accepted (fix #1)
--------------------------------------------------------------------------------

-- word32 key (4 bytes), word64 value (8 bytes)
sizeK, sizeV :: Int
sizeK = 4
sizeV = 8

prop_withMapAcceptsMatchingShape :: Property
prop_withMapAcceptsMatchingShape = withTests 50 . property $ do
  fd <- forAll (Fd . fromIntegral <$> Gen.int (Range.linear 1 1000))
  (ran, res) <- evalIO $ do
    resetLedger
    clearMockMaps
    installMockMap "m" fd (MapShape sizeK sizeV)
    ranRef <- newIORef False
    r <- withMap @MockHandle @'HashMap @Word32 @Word64 mockHandle "m" $ \_lm -> do
      writeIORef ranRef True
      pure (42 :: Int)
    ran <- readIORef ranRef
    pure (ran, r)
  ran === True
  res === Right 42

prop_withMapRejectsMismatch :: Property
prop_withMapRejectsMismatch = withTests 50 . property $ do
  -- declare a wrong key size so validation must reject
  badK <- forAll (Gen.filter (/= sizeK) (Gen.int (Range.linear 0 64)))
  (ran, res) <- evalIO $ do
    resetLedger
    clearMockMaps
    installMockMap "m" (Fd 7) (MapShape badK sizeV)
    ranRef <- newIORef False
    r <- withMap @MockHandle @'HashMap @Word32 @Word64 mockHandle "m" $ \_lm -> do
      writeIORef ranRef True
      pure (42 :: Int)
    ran <- readIORef ranRef
    pure (ran, r)
  ran === False -- callback must NOT have run
  case res of
    Left (MapShapeMismatch _ m) -> do
      mismatchExpectedKeySize m === sizeK
      mismatchActualKeySize m === badK
    other -> annotateShow other >> failure

--------------------------------------------------------------------------------
-- Map element round-trips against the in-memory mock (edge cases)
--------------------------------------------------------------------------------

-- Run a callback with a fresh mock hash map "m" of the given shape.
onMap
  :: ( forall br
        . LiveMap MockSys br 'HashMap Word32 Word64 -> IO (Either CustodianError a)
     )
  -> IO (Either CustodianError a)
onMap k = do
  clearMockMaps
  installMockMap "m" (Fd 1) (MapShape sizeK sizeV)
  outcome <- withMap @MockHandle @'HashMap @Word32 @Word64 mockHandle "m" k
  -- withMap yields Either (shape/lookup failure) (callback result), and the
  -- callback itself yields Either (element-op failure) a; flatten to one.
  pure (join outcome)

prop_writeThenReadReturnsValue :: Property
prop_writeThenReadReturnsValue = property $ do
  key <- forAll (Gen.word32 (Range.linearBounded))
  val <- forAll (Gen.word64 (Range.linearBounded))
  got <- evalIO $ onMap $ \lm -> do
    _ <- writeMap lm key val
    readMap lm key
  got === Right (Just val)

prop_readMissingIsNothing :: Property
prop_readMissingIsNothing = property $ do
  key <- forAll (Gen.word32 Range.linearBounded)
  got <- evalIO $ onMap $ \lm -> readMap lm key
  got === Right Nothing

prop_overwriteKeepsLatest :: Property
prop_overwriteKeepsLatest = property $ do
  key <- forAll (Gen.word32 Range.linearBounded)
  v1 <- forAll (Gen.word64 Range.linearBounded)
  v2 <- forAll (Gen.word64 Range.linearBounded)
  got <- evalIO $ onMap $ \lm -> do
    _ <- writeMap lm key v1
    _ <- writeMap lm key v2
    readMap lm key
  got === Right (Just v2)

prop_deletePresentThenGone :: Property
prop_deletePresentThenGone = property $ do
  key <- forAll (Gen.word32 Range.linearBounded)
  val <- forAll (Gen.word64 Range.linearBounded)
  after <- evalIO $ onMap $ \lm -> do
    _ <- writeMap lm key val
    d <- deleteMap lm key
    case d of
      Left e -> pure (Left e) -- delete of a present key must succeed
      Right () -> readMap lm key -- ... and the key must then be gone
  after === Right Nothing

prop_deleteAbsentIsError :: Property
prop_deleteAbsentIsError = property $ do
  key <- forAll (Gen.word32 Range.linearBounded)
  del <- evalIO $ onMap $ \lm -> deleteMap lm key
  -- deleting a never-present key surfaces as Left (not silently ok)
  assert (either (const True) (const False) del)

prop_mapKeysRoundTrip :: Property
prop_mapKeysRoundTrip = property $ do
  keys <- forAll (Gen.list (Range.linear 0 50) (Gen.word32 (Range.linear 0 1000)))
  let uniq = nub keys
  got <- evalIO $ onMap $ \lm -> do
    mapM_ (\k -> writeMap lm k (fromIntegral k)) uniq
    mapKeys lm
  case got of
    Right ks -> sort ks === sort uniq
    Left e -> annotateShow e >> failure

prop_emptyMapHasNoKeys :: Property
prop_emptyMapHasNoKeys = withTests 1 . property $ do
  got <- evalIO $ onMap mapKeys
  got === Right ([] :: [Word32])

--------------------------------------------------------------------------------
-- errno preservation (vision doc §5): a backend that fails with a fixed
-- errno, so we can assert readMap/deleteMap surface it verbatim, and that
-- ENOENT is NOT mistaken for a hard failure.
--------------------------------------------------------------------------------

data FailObj = FailObj
data FailSys

eACCES :: CInt
eACCES = 13

instance MapLookup FailObj where
  type Sys FailObj = FailSys
  rawFindMap _ _ = pure (Right (Fd 1, MapShape 4 8)) -- matches Word32/Word64

instance MapSyscalls FailSys where
  sysLookup _ _ _ _ = pure (Left (Errno eACCES))
  sysUpdate _ _ _ _ = pure (Left (Errno eACCES))
  sysDelete _ _ _ = pure (Left (Errno eACCES))
  sysKeys _ _ _ = pure (Left (Errno eACCES))

onFailMap
  :: ( forall br
        . LiveMap FailSys br 'HashMap Word32 Word64 -> IO (Either CustodianError a)
     )
  -> IO (Either CustodianError a)
onFailMap k = do
  outcome <- withMap @FailObj @'HashMap @Word32 @Word64 FailObj "m" k
  pure (join outcome)

prop_lookupPreservesErrno :: Property
prop_lookupPreservesErrno = withTests 1 . property $ do
  got <- evalIO $ onFailMap $ \lm -> readMap lm (0 :: Word32)
  case got of
    Left (SyscallFailure op n) -> do op === "bpf_map_lookup_elem"; n === eACCES
    other -> annotateShow other >> failure

prop_deleteHardFailureIsNotAbsent :: Property
prop_deleteHardFailureIsNotAbsent = withTests 1 . property $ do
  -- A real errno (EACCES) must surface as SyscallFailure, NOT be mistaken
  -- for the "key not present" (ENOENT) case.
  got <- evalIO $ onFailMap $ \lm -> deleteMap lm (0 :: Word32)
  case got of
    Left (SyscallFailure op n) -> do op === "bpf_map_delete_elem"; n === eACCES
    other -> annotateShow other >> failure

--------------------------------------------------------------------------------
-- Array maps: Word32-keyed, read/write/enumerate. (Deletion is a COMPILE
-- error for array maps — see negative-tests/cases/Case5_ArrayDelete.hs.)
--------------------------------------------------------------------------------

onArrayMap
  :: ( forall br
        . LiveMap MockSys br 'ArrayMap Word32 Word64 -> IO (Either CustodianError a)
     )
  -> IO (Either CustodianError a)
onArrayMap k = do
  clearMockMaps
  installMockMap "arr" (Fd 2) (MapShape sizeK sizeV) -- Word32 key (4), Word64 value (8)
  outcome <- withMap @MockHandle @'ArrayMap @Word32 @Word64 mockHandle "arr" k
  pure (join outcome)

prop_arrayWriteReadRoundTrip :: Property
prop_arrayWriteReadRoundTrip = property $ do
  idx <- forAll (Gen.word32 (Range.linear 0 127))
  val <- forAll (Gen.word64 Range.linearBounded)
  got <- evalIO $ onArrayMap $ \m -> do
    _ <- writeMap m idx val
    readMap m idx
  got === Right (Just val)

prop_arrayKeysRoundTrip :: Property
prop_arrayKeysRoundTrip = property $ do
  idxs <- forAll (Gen.list (Range.linear 0 20) (Gen.word32 (Range.linear 0 127)))
  let uniq = nub idxs
  got <- evalIO $ onArrayMap $ \m -> do
    mapM_ (\i -> writeMap m i (fromIntegral i)) uniq
    mapKeys m
  case got of
    Right ks -> sort ks === sort uniq
    Left e -> annotateShow e >> failure

--------------------------------------------------------------------------------
-- Bracket wrappers: exactly-once teardown, leak-freedom, ordering (fixes #2/#3/#4/#5)
--------------------------------------------------------------------------------

liveObjCount, liveLinkCount, closes, detaches, opens, attaches :: IO Int
liveObjCount = Set.size <$> readIORef (lLiveObj ledger)
liveLinkCount = Set.size <$> readIORef (lLiveLink ledger)
closes = readIORef (lCloses ledger)
detaches = readIORef (lDetaches ledger)
opens = readIORef (lOpens ledger)
attaches = readIORef (lAttaches ledger)

anomalies :: IO [String]
anomalies = readIORef (lAnomaly ledger)

prop_loadedClosesExactlyOnce :: Property
prop_loadedClosesExactlyOnce = withTests 1 . property $ do
  (res, o, c, live, anom) <- evalIO $ do
    resetLedger
    r <-
      withLoadedBpfObject @Acct "p" (\_scope -> pure (7 :: Int))
        :: IO (Either CustodianError Int)
    (,,,,) r <$> opens <*> closes <*> liveObjCount <*> anomalies
  res === Right 7
  o === 1
  c === 1 -- closed exactly once (not zero, not twice)
  live === 0 -- nothing leaked
  anom === []

prop_loadedClosesOnceOnException :: Property
prop_loadedClosesOnceOnException = withTests 1 . property $ do
  (threw, c, live, anom) <- evalIO $ do
    resetLedger
    outcome <-
      try
        (withLoadedBpfObject @Acct "p" (\_scope -> throwIO (ErrorCall "boom") :: IO Int))
        :: IO (Either ErrorCall (Either CustodianError Int))
    let threw = case outcome of Left (ErrorCall _) -> True; _ -> False
    (,,,) threw <$> closes <*> liveObjCount <*> anomalies
  threw === True -- the callback's exception propagates
  c === 1 -- but the object is still closed exactly once
  live === 0
  anom === []

prop_openFailureNoClose :: Property
prop_openFailureNoClose = withTests 1 . property $ do
  (res, o, c) <- evalIO $ do
    resetLedger
    writeIORef (lOpenFails ledger) True
    r <-
      withLoadedBpfObject @Acct "p" (\_scope -> pure (1 :: Int))
        :: IO (Either CustodianError Int)
    (,,) r <$> opens <*> closes
  assert (either (const True) (const False) res)
  o === 0
  c === 0 -- nothing opened, so nothing to close

prop_attachedTeardownOrderAndOnce :: Property
prop_attachedTeardownOrderAndOnce = withTests 1 . property $ do
  (res, a, d, c, lo, ll, order, anom) <- evalIO $ do
    resetLedger
    r <-
      withAttachedBpfObject @Acct "p" (\_scope -> pure (5 :: Int))
        :: IO (Either CustodianError Int)
    (,,,,,,,) r
      <$> attaches
      <*> detaches
      <*> closes
      <*> liveObjCount
      <*> liveLinkCount
      <*> readIORef (lOrder ledger)
      <*> anomalies
  res === Right 5
  a === 1
  d === 1 -- link detached exactly once
  c === 1 -- object closed exactly once
  lo === 0
  ll === 0
  order === ["detach", "close"] -- link torn down before object
  anom === []

prop_attachFailureClosesObjectNoCallback :: Property
prop_attachFailureClosesObjectNoCallback = withTests 1 . property $ do
  (res, ran, o, c, d, lo, ll, anom) <- evalIO $ do
    resetLedger
    writeIORef (lAttachFails ledger) True
    ranRef <- newIORef False
    r <-
      withAttachedBpfObject @Acct
        "p"
        (\_scope -> writeIORef ranRef True >> pure (0 :: Int))
        :: IO (Either CustodianError Int)
    ran <- readIORef ranRef
    (,,,,,,,) r ran
      <$> opens
      <*> closes
      <*> detaches
      <*> liveObjCount
      <*> liveLinkCount
      <*> anomalies
  assert (either (const True) (const False) res) -- surfaced as Left
  ran === False -- callback never ran on attach failure
  o === 1 -- object was opened+loaded
  c === 1 -- and closed exactly once (no leak on attach failure)
  d === 0 -- no link ever existed to detach
  lo === 0
  ll === 0
  anom === []

-- A multi-program object attaches N links; teardown must detach every one
-- of them, exactly once, before closing the object — no link leaked.
prop_multiProgramDetachesAllLinks :: Property
prop_multiProgramDetachesAllLinks = property $ do
  n <- forAll (Gen.int (Range.linear 1 8))
  (res, a, d, ll, order, anom) <- evalIO $ do
    resetLedger
    writeIORef (lProgramCount ledger) n
    r <-
      withAttachedBpfObject @Acct "p" (\_scope -> pure ())
        :: IO (Either CustodianError ())
    (,,,,,) r
      <$> attaches
      <*> detaches
      <*> liveLinkCount
      <*> readIORef (lOrder ledger)
      <*> anomalies
  res === Right ()
  a === n -- all N programs attached
  d === n -- all N links detached
  ll === 0 -- none leaked
  anom === [] -- and none detached twice
  -- teardown order: every detach precedes the single close
  order === replicate n "detach" ++ ["close"]

-- The exception path for an ATTACHED object (vision doc §3.4/§9): if the
-- callback throws, every link is still detached and the object still
-- closed, each exactly once, with nothing leaked. This is the guarantee
-- linearity alone cannot make — bracket's, spot-checked here.
prop_attachedClosesOnceOnException :: Property
prop_attachedClosesOnceOnException = withTests 1 . property $ do
  (threw, a, d, c, lo, ll, anom) <- evalIO $ do
    resetLedger
    writeIORef (lProgramCount ledger) 2
    outcome <-
      try
        ( withAttachedBpfObject @Acct
            "p"
            (\_scope -> throwIO (ErrorCall "boom") :: IO Int)
        )
        :: IO (Either ErrorCall (Either CustodianError Int))
    let threw = case outcome of Left (ErrorCall _) -> True; _ -> False
    (,,,,,,) threw
      <$> attaches
      <*> detaches
      <*> closes
      <*> liveObjCount
      <*> liveLinkCount
      <*> anomalies
  threw === True -- the callback's exception propagates
  a === 2
  d === 2 -- both links detached despite the exception
  c === 1 -- object closed exactly once
  lo === 0
  ll === 0 -- no link leaked on the exception path
  anom === []

--------------------------------------------------------------------------------
-- Manual linear lifecycle: open -> load -> attach -> teardown, balanced.
--------------------------------------------------------------------------------

runManagedLifecycle :: IO ()
runManagedLifecycle =
  Linear.withLinearIO $ Control.do
    opened <- openObject @Acct @AcctLinks "p"
    L.either
      consumeErr
      ( \obj -> Control.do
          loaded <- loadObject obj
          L.either
            consumeErr
            ( \lobj -> Control.do
                attached <- attachObject lobj
                L.either
                  (Unsafe.toLinear (\(e, lo) -> Control.do teardown lo; consumeErr e))
                  (\ao -> Control.do teardown ao; Control.pure (Ur ()))
                  attached
            )
            loaded
      )
      opened
  where
    consumeErr :: CustodianError %1 -> Linear.IO (Ur ())
    consumeErr e = L.consume e `L.lseq` Control.pure (Ur ())

prop_manualLifecycleBalanced :: Property
prop_manualLifecycleBalanced = withTests 1 . property $ do
  (o, c, a, d, lo, ll, anom) <- evalIO $ do
    resetLedger
    runManagedLifecycle
    (,,,,,,)
      <$> opens
      <*> closes
      <*> attaches
      <*> detaches
      <*> liveObjCount
      <*> liveLinkCount
      <*> anomalies
  o === 1
  a === 1
  d === 1
  c === 1
  lo === 0
  ll === 0
  anom === []

--------------------------------------------------------------------------------

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests =
  testGroup
    "custodian-verified"
    [ testGroup
        "checkMapShape (fix #1: map size validation)"
        [ testProperty "match iff sizes equal" prop_shapeMatchesIffSizesEqual
        , testProperty "exact match accepts" prop_shapeExactMatchAccepts
        , testProperty "off-by-one rejected" prop_shapeOffByOneRejected
        ]
    , testGroup
        "withMap gate (fix #1: no read/write on mis-sized buffer)"
        [ testProperty
            "accepts matching shape, runs callback"
            prop_withMapAcceptsMatchingShape
        , testProperty "rejects mismatch, callback never runs" prop_withMapRejectsMismatch
        ]
    , testGroup
        "map element semantics (edge cases)"
        [ testProperty "write then read returns value" prop_writeThenReadReturnsValue
        , testProperty "read missing key is Nothing" prop_readMissingIsNothing
        , testProperty "overwrite keeps latest" prop_overwriteKeepsLatest
        , testProperty "delete present then gone" prop_deletePresentThenGone
        , testProperty "delete absent is error" prop_deleteAbsentIsError
        , testProperty "mapKeys round-trip" prop_mapKeysRoundTrip
        , testProperty "empty map has no keys" prop_emptyMapHasNoKeys
        ]
    , testGroup
        "errno preservation (fix: vision doc §5)"
        [ testProperty "lookup surfaces the errno verbatim" prop_lookupPreservesErrno
        , testProperty
            "hard failure is not mistaken for absent"
            prop_deleteHardFailureIsNotAbsent
        ]
    , testGroup
        "array maps (Word32-keyed; delete is a compile error)"
        [ testProperty "write then read round-trip" prop_arrayWriteReadRoundTrip
        , testProperty "mapKeys round-trip" prop_arrayKeysRoundTrip
        ]
    , testGroup
        "bracket wrappers (fixes #2/#3/#4/#5: exactly-once, no leak)"
        [ testProperty "loaded closes exactly once" prop_loadedClosesExactlyOnce
        , testProperty
            "loaded closes once even on exception"
            prop_loadedClosesOnceOnException
        , testProperty "open failure closes nothing" prop_openFailureNoClose
        , testProperty
            "attached: detach-before-close, each once"
            prop_attachedTeardownOrderAndOnce
        , testProperty
            "attach failure closes object, no callback"
            prop_attachFailureClosesObjectNoCallback
        , testProperty
            "multi-program object detaches all links"
            prop_multiProgramDetachesAllLinks
        , testProperty
            "attached: exception still detaches all + closes once"
            prop_attachedClosesOnceOnException
        ]
    , testGroup
        "manual linear lifecycle"
        [ testProperty "open/load/attach/teardown balanced" prop_manualLifecycleBalanced
        ]
    ]
