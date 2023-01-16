package fr.acinq.bitcoin

import kotlin.test.Test
import kotlin.test.assertEquals

class BIP86TestsCommon {
    @Test
    fun `BIP86 reference tests`() {
        val seed = MnemonicCode.toSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(" "), "")
        val master = DeterministicWallet.generate(seed)
        assertEquals(DeterministicWallet.encode(master, DeterministicWallet.xprv), "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu")
        assertEquals(DeterministicWallet.encode(DeterministicWallet.publicKey(master), DeterministicWallet.xpub), "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8")

        val accountKey = DeterministicWallet.derivePrivateKey(master, KeyPath("m/86'/22'/0'"))
        assertEquals(DeterministicWallet.encode(accountKey, DeterministicWallet.xprv), "xprv9yAiuawQkke1uNSdsVtVPEVrUsk3Ndu22hJQH5vnTSWEp4NqA5vvtYMNiraAsdR9eLBg2rF5wfaWSfYaYupe3CJdQuMPhY8kPZ81YCyv53N")
        assertEquals(DeterministicWallet.encode(DeterministicWallet.publicKey(accountKey), DeterministicWallet.xpub), "xpub6CA5K6UJb8CK7rX6yXRVkNSb2uaXn6csPvE15ULQ1n3DgrhyhdFBSLfra8rMTAXbout2FCRvgnj26Ff4iUAcFDquukx6txcsPbRxN5FZiJR")

        val key = DeterministicWallet.derivePrivateKey(accountKey, listOf(0L, 0L))
        assertEquals(key.secretkeybytes, DeterministicWallet.derivePrivateKey(master, KeyPath("m/86'/22'/0'/0/0")).secretkeybytes)
        val internalKey = XonlyPublicKey(key.publicKey)
        assertEquals(internalKey.value, ByteVector32("31ac3f7df9589d2037b255fc6c0d028274189287f9d461afc65b946c8b1a5fc1"))
        val outputKey = internalKey.outputKey(Crypto.SchnorrTweak.NoScriptTweak).first
        assertEquals(outputKey.value, ByteVector32("ff2138daad188067451d42932700b0075f1bf19918b5d99ba77abb50b5a79f3c"))
        val script = listOf(OP_1, OP_PUSHDATA(outputKey.value))
        assertEquals(Script.write(script).byteVector(), ByteVector("5120ff2138daad188067451d42932700b0075f1bf19918b5d99ba77abb50b5a79f3c"))
        assertEquals(Bitcoin.addressFromPublicKeyScript(Block.LivenetGenesisBlock.hash, script), "mona1plusn3k4drzqxw3gag2fjwq9sqa03huverz6anxa802a4pdd8nu7q3k9fgm")

        val key1 = DeterministicWallet.derivePrivateKey(accountKey, listOf(0L, 1L))
        assertEquals(key1.secretkeybytes, DeterministicWallet.derivePrivateKey(master, KeyPath("m/86'/22'/0'/0/1")).secretkeybytes)
        val internalKey1 = XonlyPublicKey(key1.publicKey)
        assertEquals(internalKey1.value, ByteVector32("237f0803a7db6281698c24efe1afaeee2d463a6a9bd8feea5f5d4958c92bbdf4"))
        val outputKey1 = internalKey1.outputKey(Crypto.SchnorrTweak.NoScriptTweak).first
        assertEquals(outputKey1.value, ByteVector32("6aeb7ad0db59bdd68affc92fcb8ae645d0aab26f25836d74d0500b788f87f459"))
        val script1 = listOf(OP_1, OP_PUSHDATA(outputKey1.value))
        assertEquals(Script.write(script1).byteVector(), ByteVector("51206aeb7ad0db59bdd68affc92fcb8ae645d0aab26f25836d74d0500b788f87f459"))
        assertEquals(Bitcoin.addressFromPublicKeyScript(Block.LivenetGenesisBlock.hash, script1), "mona1pdt4h45xmtx7adzhleyhuhzhxghg24vn0ykpk6axs2q9h3ru873vsgh4nt4")

        val key2 = DeterministicWallet.derivePrivateKey(accountKey, listOf(1L, 0L))
        assertEquals(key2.secretkeybytes, DeterministicWallet.derivePrivateKey(master, KeyPath("m/86'/22'/0'/1/0")).secretkeybytes)
        val internalKey2 = XonlyPublicKey(key2.publicKey)
        assertEquals(internalKey2.value, ByteVector32("95636415481b00a133b8e2721bbab0e2960e8dba847461f017e490ae93068dc9"))
        val outputKey2 = internalKey2.outputKey(Crypto.SchnorrTweak.NoScriptTweak).first
        assertEquals(outputKey2.value, ByteVector32("566bdb0a120db9c4b2bd4d64d7fd6bd00129ab14d7571d6be45ac6dff7ca8e7d"))
        val script2 = listOf(OP_1, OP_PUSHDATA(outputKey2.value))
        assertEquals(Script.write(script2).byteVector(), ByteVector("5120566bdb0a120db9c4b2bd4d64d7fd6bd00129ab14d7571d6be45ac6dff7ca8e7d"))
        assertEquals(Bitcoin.addressFromPublicKeyScript(Block.LivenetGenesisBlock.hash, script2), "mona1p2e4akzsjpkuufv4af4jd0ltt6qqjn2c56at366lyttrdla723e7sqya0we")
    }

    @Test
    fun `compute taproot addresses`() {
        val (_, master) = DeterministicWallet.ExtendedPrivateKey.decode("tprv8ZgxMBicQKsPeQQADibg4WF7mEasy3piWZUHyThAzJCPNgMHDVYhTCVfev3jFbDhcYm4GimeFMbbi9z1d9rfY1aL5wfJ9mNebQ4thJ62EJb")
        val key = DeterministicWallet.derivePrivateKey(master, "86'/1'/0'/0/1")
        val internalKey = XonlyPublicKey(key.publicKey)
        val outputKey = internalKey.outputKey(Crypto.SchnorrTweak.NoScriptTweak).first
        assertEquals("tmona1phlhs7afhqzkgv0n537xs939s687826vn8l24ldkrckvwsnlj3d7qn48d85", Bech32.encodeWitnessAddress("tmona", 1, outputKey.value.toByteArray()))
    }

    @Test
    fun `compute more taproot addresses`() {
        // addresses created by bitcoin core with a wallet imported with descriptor "tr(tprv8ZgxMBicQKsPdyyuveRPhVYogdPXBDqRiUXDo5TcLKe3f9YfonipqbgJD7pCXdovZTfTyj6SjZ928SkPunnDTiXV7Y2HSsG9XAGki6n8dRF/86h/1h/0h/0/*)"
        val expected = listOf(
            "tmona1pufpxa6zyvkdrz52qhtt9r5hl7pts7r3a5anndeupt0yqys8s8s6qm43u7j",
            "tmona1pa978mqd3rfj0k33ef4u7nrc7qh3s08wy9fd3sfl770c9fqc5mh5qr86az9",
            "tmona1pm3xkwh3av3mlsr25mvk320lq94xpjzkv9l3u8x5w8ppwz5nfpqgqqaxqw5",
            "tmona1pdyzhpg5yletzl07yks0eqwgxkddf23cy6vj64wd42tpc0xnglsvslfkkmp",
            "tmona1pks4qar2hlhvpzcuw6tj77x3xunt9jcgnm4lk6eu5d765vxv94sfsnpuecx",
            "tmona1pdtjstl80rtl7lwuhktfw86sv0g65079sh6gsaa9qg6lcrph6xmsq2hg8kg",
            "tmona1p6tlajumgdvlhfm6m8h3v5zche4dvfk3ey60vpux5wqeaysm6apuq62u8tf",
            "tmona1pn0w8e85ml8chl2vda83euynvrxtelpww8m2mnzf3ugpc7w6zl3lqvz9yss",
            "tmona1px03j0r6kru2nrwtq04m8v54q8t3shkfk7vgh704as5kfd0fanalq988dg5",
            "tmona1ps0qzx37ckd0cx209qa65q4kxha7kcr8vx63hgv6wk2y7jwqxq6lsjdwh94"

        )
        val (_, master) = DeterministicWallet.ExtendedPrivateKey.decode("tprv8ZgxMBicQKsPdyyuveRPhVYogdPXBDqRiUXDo5TcLKe3f9YfonipqbgJD7pCXdovZTfTyj6SjZ928SkPunnDTiXV7Y2HSsG9XAGki6n8dRF")
        for (i in 0 until  10) {
            val key = DeterministicWallet.derivePrivateKey(master, "86'/1'/0'/0/$i")
            val internalKey = XonlyPublicKey(key.publicKey)
            val outputKey = internalKey.outputKey(Crypto.SchnorrTweak.NoScriptTweak).first
            assertEquals(expected[i], Bech32.encodeWitnessAddress("tmona", 1, outputKey.value.toByteArray()))
        }
    }
}
