module Cardano.Wallet.API.WIP.Handlers (handlers)
where

import           Universum

import           Servant

import           Pos.Client.Txp.Util (defaultInputSelectionPolicy)

import           Cardano.Wallet.API.Response
import           Cardano.Wallet.API.V1.Handlers.Transactions (txFromMeta)
import           Cardano.Wallet.API.V1.Types as V1
import qualified Cardano.Wallet.API.WIP as WIP (API)
import           Cardano.Wallet.Kernel.CoinSelection.FromGeneric
                     (ExpenseRegulation (..))
import           Cardano.Wallet.WalletLayer (ActiveWalletLayer (..),
                     PassiveWalletLayer)
import qualified Cardano.Wallet.WalletLayer as WalletLayer
import           Cardano.Wallet.WalletLayer.Kernel.Conv (toInputGrouping)

-- | WIP @Servant@ handlers the are not part of the offical api yet.
handlers :: ActiveWalletLayer IO -> ServerT WIP.API Handler
handlers awl = checkExternalWallet pwl
           :<|> newExternalWallet pwl
           :<|> deleteExternalWallet pwl
           :<|> newUnsignedTransaction awl
           :<|> submitSignedTransaction awl
  where
    pwl = walletPassiveLayer awl

checkExternalWallet :: PassiveWalletLayer IO
                    -> PublicKeyAsBase58
                    -> Handler (WalletResponse WalletAndTxHistory)
checkExternalWallet _pwl _encodedRootPK =
    error "[CHW-54], Cardano Hardware Wallet feature, check external wallet, unimplemented yet."

{-
checkExternalWallet
    :: ( V0.MonadWalletLogic ctx m
       , V0.MonadWalletHistory ctx m
       , MonadUnliftIO m
       , HasLens SyncQueue ctx SyncQueue
       )
    => Genesis.Config
    -> PublicKeyAsBase58
    -> m (WalletResponse WalletAndTxHistory)
checkExternalWallet genesisConfig encodedRootPK = do
    rootPK <- mkPublicKeyOrFail encodedRootPK

    ws <- V0.askWalletSnapshot
    let walletId = encodeCType . Core.makePubKeyAddressBoot $ rootPK
    walletExists <- V0.doesWalletExist walletId
    (v0wallet, transactions, isWalletReady) <- if walletExists
        then do
            -- Wallet is here, it means that user already used this wallet (for example,
            -- hardware device) on this computer, so we have to return stored information
            -- about this wallet and history of transactions (if any transactions was made).
            --
            -- By default we have to specify account and address for getting transactions
            -- history. But currently all we have is root PK, so we return complete history
            -- of transactions, for all accounts and addresses.
            let allAccounts = getWalletAccountIds ws walletId
                -- We want to get a complete history, so we shouldn't specify an address.
                address = Nothing
            (V0.WalletHistory history, _) <- V0.getHistory walletId
                                                           (const allAccounts)
                                                           address
            v1Transactions <- mapM (\(_, (v0Tx, _)) -> migrate v0Tx) $ Map.toList history
            (,,) <$> V0.getWallet walletId
                 <*> pure v1Transactions
                 <*> pure True
        else do
            -- No such wallet in db, it means that this wallet (for example, hardware
            -- device) was not used on this computer. But since this wallet _could_ be
            -- used on another computer, we have to (try to) restore this wallet.
            -- Since there's no wallet meta-data, we use default one.
            let largeCurrencyUnit = 0
                defaultMeta = V0.CWalletMeta "External wallet"
                                             V0.CWAStrict
                                             largeCurrencyUnit
                -- This is a new wallet, currently un-synchronized, so there's no
                -- history of transactions yet.
                transactions = []
            (,,) <$> restoreExternalWallet genesisConfig defaultMeta encodedRootPK
                 <*> pure transactions
                 <*> pure False -- We restore wallet, so it's unready yet.

    v1wallet <- migrateWallet ws v0wallet isWalletReady
    let walletAndTxs = WalletAndTxHistory v1wallet transactions
    single <$> pure walletAndTxs
-}

newExternalWallet :: PassiveWalletLayer IO
                  -> NewExternalWallet
                  -> Handler (WalletResponse Wallet)
newExternalWallet pwl newExternalWalletRequest = do
    res <- liftIO $ WalletLayer.createWallet pwl (WalletLayer.CreateExternalWallet newExternalWalletRequest)
    case res of
        Left err     -> throwM err
        Right wallet -> return $ single wallet

deleteExternalWallet :: PassiveWalletLayer IO
                     -> PublicKeyAsBase58
                     -> Handler NoContent
deleteExternalWallet pwl encodedRootPK = do
    res <- liftIO $ WalletLayer.deleteExternalWallet pwl encodedRootPK
    case res of
        Left err -> throwM err
        Right () -> return NoContent

-- | Creates new unsigned transaction.
--
-- NOTE: This function does /not/ perform a payment, it just prepares raw
-- transaction which will be signed and submitted to the blockchain later.
newUnsignedTransaction :: ActiveWalletLayer IO
                       -> Payment
                       -> Handler (WalletResponse UnsignedTransaction)
newUnsignedTransaction aw payment@Payment{..} = do
    let inputGrouping = toInputGrouping $ fromMaybe (V1 defaultInputSelectionPolicy)
                                                    pmtGroupingPolicy
    res <- liftIO $ (WalletLayer.createUnsignedTx aw) inputGrouping
                                                      SenderPaysFee
                                                      payment
    case res of
        Left err         -> throwM err
        Right unsignedTx -> return $ single unsignedTx

-- | Submits externally-signed transaction to the blockchain.
submitSignedTransaction :: ActiveWalletLayer IO
                        -> SignedTransaction
                        -> Handler (WalletResponse Transaction)
submitSignedTransaction aw signedTx = liftIO $ do
    res <- liftIO $ (WalletLayer.submitSignedTx aw) signedTx
    case res of
        Left err -> throwM err
        Right (_, meta) -> txFromMeta aw WalletLayer.NewPaymentUnknownAccountId meta
