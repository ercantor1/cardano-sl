{-# LANGUAGE TypeFamilies #-}

-- | Wallet redemption

module Pos.Wallet.Web.Methods.Redeem
       ( redeemAda
       , redeemAdaPaperVend
       ) where

import           Universum

import           Data.ByteString.Base58 (bitcoinAlphabet, decodeBase58)
import qualified Serokell.Util.Base64 as B64

import           Pos.Chain.Genesis as Genesis (Config (..))
import           Pos.Chain.Txp (TxAux (..), TxOut (..), TxpConfiguration)
import           Pos.Client.Txp.History (TxHistoryEntry (..))
import           Pos.Client.Txp.Network (prepareRedemptionTx)
import           Pos.Core (getCurrentTimestamp)
import           Pos.Core.NetworkMagic (makeNetworkMagic)
import           Pos.Crypto (PassPhrase, aesDecrypt, hash,
                     redeemDeterministicKeyGen)
import           Pos.Util (maybeThrow)
import           Pos.Util.Mnemonic (mnemonicToAesKey)
import           Pos.Wallet.Web.Account (GenSeed (..))
import           Pos.Wallet.Web.ClientTypes (AccountId (..), CAccountId (..),
                     CAddress (..), CBackupPhrase (..),
                     CPaperVendWalletRedeem (..), CTx (..), CWalletRedeem (..))
import           Pos.Wallet.Web.Error (WalletError (..))
import           Pos.Wallet.Web.Methods.History (addHistoryTxMeta, constructCTx,
                     getCurChainDifficulty)
import qualified Pos.Wallet.Web.Methods.Logic as L
import           Pos.Wallet.Web.Methods.Txp (MonadWalletTxFull, rewrapTxError,
                     submitAndSaveNewPtx)
import           Pos.Wallet.Web.Pending (mkPendingTx)
import           Pos.Wallet.Web.State (AddressLookupMode (Ever), askWalletDB,
                     getWalletSnapshot)
import           Pos.Wallet.Web.Util (decodeCTypeOrFail, getWalletAddrsDetector)

redeemAda
    :: MonadWalletTxFull ctx m
    => Genesis.Config
    -> TxpConfiguration
    -> (TxAux -> m Bool)
    -> PassPhrase
    -> CWalletRedeem
    -> m CTx
redeemAda genesisConfig txpConfig submitTx passphrase CWalletRedeem {..} = do
    seedBs <- maybe invalidBase64 pure
        -- NOTE: this is just safety measure
        $ rightToMaybe (B64.decode crSeed) <|> rightToMaybe (B64.decodeUrl crSeed)
    redeemAdaInternal genesisConfig txpConfig submitTx passphrase crWalletId seedBs
  where
    invalidBase64 =
        throwM . RequestError $ "Seed is invalid base64(url) string: " <> crSeed

-- Decrypts certificate based on:
--  * https://github.com/input-output-hk/postvend-app/blob/master/src/CertGen.hs#L205
--  * https://github.com/input-output-hk/postvend-app/blob/master/src/CertGen.hs#L160
redeemAdaPaperVend
    :: MonadWalletTxFull ctx m
    => Genesis.Config
    -> TxpConfiguration
    -> (TxAux -> m Bool)
    -> PassPhrase
    -> CPaperVendWalletRedeem
    -> m CTx
redeemAdaPaperVend genesisConfig txpConfig submitTx passphrase CPaperVendWalletRedeem {..} = do
    seedEncBs <- maybe invalidBase58 pure
        $ decodeBase58 bitcoinAlphabet $ encodeUtf8 pvSeed
    let aesKey = mnemonicToAesKey (bpToList pvBackupPhrase)
    seedDecBs <- either decryptionFailed pure
        $ aesDecrypt seedEncBs aesKey
    redeemAdaInternal genesisConfig txpConfig submitTx passphrase pvWalletId seedDecBs
  where
    invalidBase58 =
        throwM . RequestError $ "Seed is invalid base58 string: " <> pvSeed
    decryptionFailed e =
        throwM . RequestError $ "Decryption failed: " <> show e


redeemAdaInternal
    :: MonadWalletTxFull ctx m
    => Genesis.Config
    -> TxpConfiguration
    -> (TxAux -> m Bool)
    -> PassPhrase
    -> CAccountId
    -> ByteString
    -> m CTx
redeemAdaInternal genesisConfig txpConfig submitTx passphrase cAccId seedBs = do
    (_, redeemSK) <- maybeThrow (RequestError "Seed is not 32-byte long") $
                     redeemDeterministicKeyGen seedBs
    accId <- decodeCTypeOrFail cAccId
    db <- askWalletDB

    let nm = makeNetworkMagic $ configProtocolMagic genesisConfig
    -- new redemption wallet
    _ <- L.getAccount nm accId

    dstAddr <- decodeCTypeOrFail . cadId =<< L.newAddress nm RandomSeed passphrase accId
    ws <- getWalletSnapshot db
    th <- rewrapTxError "Cannot send redemption transaction" $ do
        (txAux, redeemAddress, redeemBalance) <- prepareRedemptionTx
            genesisConfig
            redeemSK
            dstAddr

        ts <- Just <$> getCurrentTimestamp
        let tx = taTx txAux
            txHash = hash tx
            txInputs = [TxOut redeemAddress redeemBalance]
            th = THEntry txHash tx Nothing txInputs [dstAddr] ts
            dstWallet = aiWId accId
        ptx <- mkPendingTx (configProtocolConstants genesisConfig)
                           ws
                           dstWallet
                           txHash
                           txAux
                           th

        th <$ submitAndSaveNewPtx genesisConfig txpConfig db submitTx ptx

    -- add redemption transaction to the history of new wallet
    let cWalId = aiWId accId
    -- We add TxHistoryEntry's meta created by us in advance
    -- to make TxHistoryEntry in CTx consistent with entry in history.
    _ <- addHistoryTxMeta db cWalId th
    ws' <- getWalletSnapshot db
    let cWalAddrsDetector = getWalletAddrsDetector ws' Ever cWalId
    diff <- getCurChainDifficulty
    fst <$> constructCTx ws' cWalId cWalAddrsDetector diff th
