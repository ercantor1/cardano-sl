{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}

module Test.Pos.Wallet.Web.AddressSpec
       ( spec
       ) where

import           Universum

import           Data.Default (def)
import           Formatting (sformat, (%))
import           Serokell.Data.Memory.Units (memory)
import           Test.Hspec (Spec, beforeAll_, describe)
import           Test.Hspec.QuickCheck (modifyMaxSuccess, prop)
import           Test.QuickCheck (Discard (..), arbitrary)
import           Test.QuickCheck.Monadic (pick, stop)

import           Pos.Binary (biSize)
import           Pos.Chain.Genesis as Genesis (Config (..))
import           Pos.Client.Txp.Addresses (getFakeChangeAddress, getNewAddress)
import           Pos.Configuration ()
import           Pos.Core.Common (Address)
import           Pos.Core.NetworkMagic (NetworkMagic (..), makeNetworkMagic)
import           Pos.Crypto (PassPhrase)

import           Pos.Util.Wlog (setupTestLogging)
import           Pos.Wallet.Web.Account (GenSeed (..), genUniqueAddress)
import           Pos.Wallet.Web.ClientTypes (AccountId, CAccountInit (..), caId)
import           Pos.Wallet.Web.Error (WalletError (..))
import           Pos.Wallet.Web.Methods.Logic (newAccount)
import           Pos.Wallet.Web.State (askWalletSnapshot, getWalletAddresses,
                     wamAddress)
import           Pos.Wallet.Web.Util (decodeCTypeOrFail)
import           Test.Pos.Chain.Genesis.Dummy (dummyEpochSlots)
import           Test.Pos.Configuration (withDefConfigurations,
                     withProvidedMagicConfig)
import           Test.Pos.Util.QuickCheck.Property (assertProperty, expectedOne)
import           Test.Pos.Wallet.Web.Mode (WalletProperty)
import           Test.Pos.Wallet.Web.Util (importSingleWallet,
                     mostlyEmptyPassphrases)

spec :: Spec
spec = beforeAll_ setupTestLogging $
    withDefConfigurations $ \_ _ _ -> do
        describe "Fake address has maximal possible size" $
            modifyMaxSuccess (const 10) $ do
                prop "getNewAddress" $ \pm ->
                    withProvidedMagicConfig pm $ \genesisConfig _ _ ->
                        fakeAddressHasMaxSizeTest changeAddressGenerator genesisConfig
                prop "genUniqueAddress" $ \pm ->
                    withProvidedMagicConfig pm $ \genesisConfig _ _ ->
                        fakeAddressHasMaxSizeTest commonAddressGenerator genesisConfig

type AddressGenerator = NetworkMagic -> AccountId -> PassPhrase -> WalletProperty Address

fakeAddressHasMaxSizeTest :: AddressGenerator -> Genesis.Config -> Word32 -> WalletProperty ()
fakeAddressHasMaxSizeTest generator genesisConfig accSeed = do
    let nm = makeNetworkMagic $ configProtocolMagic genesisConfig
    passphrase <- importSingleWallet genesisConfig mostlyEmptyPassphrases
    ws <- askWalletSnapshot
    wid <- expectedOne "wallet addresses" $ getWalletAddresses ws
    accId <- lift $ decodeCTypeOrFail . caId
         =<< newAccount nm (DeterminedSeed accSeed) passphrase (CAccountInit def wid)
    address <- generator nm accId passphrase

    largeAddress <- lift (getFakeChangeAddress nm dummyEpochSlots)

    assertProperty
        (biSize largeAddress >= biSize address)
        (sformat (memory%" < "%memory) (biSize largeAddress) (biSize address))

-- | Addresses generator used in 'MonadAddresses' to create change addresses.
-- Unfortunatelly, its randomness doesn't depend on QuickCheck seed,
-- so another proper generator is helpful.
changeAddressGenerator :: AddressGenerator
changeAddressGenerator nm accId passphrase =
    lift $ getNewAddress nm dummyEpochSlots (accId, passphrase)

-- | Generator which is directly used in endpoints.
commonAddressGenerator :: AddressGenerator
commonAddressGenerator nm accId passphrase = do
    ws <- askWalletSnapshot
    addrSeed <- pick arbitrary
    let genAddress = genUniqueAddress nm ws (DeterminedSeed addrSeed) passphrase accId
    -- can't catch under 'PropertyM', workarounding
    maddr <- lift $ (Just <$> genAddress) `catch` seedBusyHandler
    addr <- maybe (stop Discard) pure maddr
    return $ addr ^. wamAddress
  where
    seedBusyHandler (InternalError "address generation: this index is already taken")
                      = pure Nothing
    seedBusyHandler e = throwM e
