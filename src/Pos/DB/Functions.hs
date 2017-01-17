{-# LANGUAGE AllowAmbiguousTypes       #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE ScopedTypeVariables       #-}
{-# LANGUAGE TypeFamilies              #-}

-- | Basically wrappers over RocksDB library.

module Pos.DB.Functions
       ( openDB

       -- * Key/Value helpers
       , encodeWithKeyPrefix
       , rocksDelete
       , rocksGetBi
       , rocksGetBytes
       , rocksPutBi
       , rocksPutBytes
       , rocksDecodeWP
       , rocksDecodeMaybe
       , rocksDecodeMaybeWP
       , rocksDecodeKeyValMaybe

       -- * Batch
       , RocksBatchOp (..)
       , SomeBatchOp (..)
       , SomePrettyBatchOp (..)
       , rocksWriteBatch
       ) where

import qualified Data.ByteString       as BS (drop, isPrefixOf)
import qualified Data.ByteString.Lazy  as BSL
import           Data.Default          (def)
import           Data.List.NonEmpty    (NonEmpty)
import qualified Data.Text.Buildable
import qualified Database.RocksDB      as Rocks
import           Formatting            (bprint, sformat, shown, string, (%))
import           Serokell.Util.Text    (listJson)
import           Universum

import           Pos.Binary.Class      (Bi, decodeFull, encodeStrict)
import           Pos.DB.Error          (DBError (DBMalformed))
import           Pos.DB.Iterator.Class (MonadDBIterator (..))
import           Pos.DB.Types          (DB (..))

openDB :: MonadIO m => FilePath -> m (DB ssc)
openDB fp = DB def def def
                   <$> Rocks.open fp def
                        { Rocks.createIfMissing = True
                        , Rocks.compression     = Rocks.NoCompression
                        }

encodeWithKeyPrefix
    :: forall i . (MonadDBIterator i, Bi (IterKey i))
    => IterKey i -> ByteString
encodeWithKeyPrefix = (iterKeyPrefix @i Proxy <>) . encodeStrict

-- | Read ByteString from RocksDb using given key.
rocksGetBytes :: (MonadIO m) => ByteString -> DB ssc -> m (Maybe ByteString)
rocksGetBytes key DB {..} = Rocks.get rocksDB rocksReadOpts key

-- | Read serialized value from RocksDB using given key.
rocksGetBi
    :: forall v m ssc.
       (Bi v, MonadIO m, MonadThrow m)
    => ByteString -> DB ssc -> m (Maybe v)
rocksGetBi key db = do
    bytes <- rocksGetBytes key db
    traverse (rocksDecode . (ToDecodeValue key)) bytes

data ToDecode
    = ToDecodeKey !ByteString
    | ToDecodeValue !ByteString
                    !ByteString

rocksDecode :: (Bi v, MonadThrow m) => ToDecode -> m v
rocksDecode (ToDecodeKey key) =
    either (onParseError key) pure . decodeFull . BSL.fromStrict $ key
rocksDecode (ToDecodeValue key val) =
    either (onParseError key) pure . decodeFull . BSL.fromStrict $ val

onParseError :: (MonadThrow m) => ByteString -> [Char] -> m a
onParseError rawKey errMsg = throwM $ DBMalformed $ sformat fmt rawKey errMsg
  where
    fmt = "rocksGetBi: stored value is malformed, key = "%shown%", err: "%string

-- with prefix
rocksDecodeWP
    :: forall i m . (MonadThrow m, MonadDBIterator i, Bi (IterKey i))
    => ByteString -> m (IterKey i)
rocksDecodeWP key
    | BS.isPrefixOf (iterKeyPrefix @i Proxy) key =
        either (onParseError key) pure .
        decodeFull .
        BSL.fromStrict .
        BS.drop (length $ iterKeyPrefix @i Proxy) $
        key
    | otherwise = onParseError key "unexpected prefix"

-- rocksDecodeKeyValWP :: forall i m . (MonadThrow m, MonadDBIterator i,
--                         Bi (IterKey i), Bi (IterValue i))
--                     => (ByteString, ByteString) -> m (IterKey i, IterValue i)
-- rocksDecodeKeyValWP (k, v) =
--     (,) <$> rocksDecodeWP @i k <*> rocksDecode (ToDecodeValue k v)

-- Parse maybe
rocksDecodeMaybeWP
    :: forall i . (MonadDBIterator i, Bi (IterKey i))
    => ByteString -> Maybe (IterKey i)
rocksDecodeMaybeWP s
    | BS.isPrefixOf (iterKeyPrefix @i Proxy) s =
          rightToMaybe .
          decodeFull .
          BSL.fromStrict .
          BS.drop (length $ iterKeyPrefix @i Proxy) $ s
    | otherwise = Nothing

rocksDecodeMaybe :: (Bi v) => ByteString -> Maybe v
rocksDecodeMaybe = rightToMaybe . decodeFull . BSL.fromStrict

rocksDecodeKeyValMaybe
    :: (Bi k, Bi v)
    => (ByteString, ByteString) -> Maybe (k, v)
rocksDecodeKeyValMaybe (k, v) = (,) <$> rocksDecodeMaybe k <*> rocksDecodeMaybe v

-- | Write ByteString to RocksDB for given key.
rocksPutBytes :: (MonadIO m) => ByteString -> ByteString -> DB ssc -> m ()
rocksPutBytes k v DB {..} = Rocks.put rocksDB rocksWriteOpts k v

-- | Write serializable value to RocksDb for given key.
rocksPutBi :: (Bi v, MonadIO m) => ByteString -> v -> DB ssc -> m ()
rocksPutBi k v = rocksPutBytes k (encodeStrict v)

rocksDelete :: (MonadIO m) => ByteString -> DB ssc -> m ()
rocksDelete k DB {..} = Rocks.delete rocksDB rocksWriteOpts k

----------------------------------------------------------------------------
-- Batch
----------------------------------------------------------------------------

class RocksBatchOp a where
    toBatchOp :: a -> [Rocks.BatchOp]

instance RocksBatchOp Rocks.BatchOp where
    toBatchOp = pure

data EmptyBatchOp

instance RocksBatchOp EmptyBatchOp where
    toBatchOp _ = []

instance Buildable EmptyBatchOp where
    build _ = ""

data SomeBatchOp =
    forall a. RocksBatchOp a =>
              SomeBatchOp a

instance Monoid SomeBatchOp where
    mempty = SomeBatchOp ([]::[EmptyBatchOp])
    mappend a b = SomeBatchOp [a, b]

instance RocksBatchOp SomeBatchOp where
    toBatchOp (SomeBatchOp a) = toBatchOp a

data SomePrettyBatchOp =
    forall a. (RocksBatchOp a, Buildable a) =>
              SomePrettyBatchOp a

instance Monoid SomePrettyBatchOp where
    mempty = SomePrettyBatchOp ([]::[SomePrettyBatchOp])
    mappend a b = SomePrettyBatchOp [a, b]

instance RocksBatchOp SomePrettyBatchOp where
    toBatchOp (SomePrettyBatchOp a) = toBatchOp a

instance Buildable SomePrettyBatchOp where
    build (SomePrettyBatchOp x) = Data.Text.Buildable.build x

-- instance (Foldable t, RocksBatchOp a) => RocksBatchOp (t a) where
--     toBatchOp = concatMap toBatchOp -- overlapping instances, wtf ?????

instance RocksBatchOp a => RocksBatchOp [a] where
    toBatchOp = concatMap toBatchOp

instance RocksBatchOp a => RocksBatchOp (NonEmpty a) where
    toBatchOp = concatMap toBatchOp

instance Buildable [SomePrettyBatchOp] where
    build = bprint listJson

-- | Write Batch encapsulation
rocksWriteBatch :: (RocksBatchOp a, MonadIO m) => [a] -> DB ssc -> m ()
rocksWriteBatch batch DB {..} =
    Rocks.write rocksDB rocksWriteOpts (concatMap toBatchOp batch)
