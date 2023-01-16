/*
 * Copyright 2020 ACINQ SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.acinq.bitcoin

import fr.acinq.bitcoin.Bitcoin.computeBIP84Address
import kotlin.test.Test
import kotlin.test.assertEquals

class BIP84TestsCommon {
    /**
     * BIP 84 (Derivation scheme for P2WPKH based accounts) reference tests
     * see https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
     */
    @Test
    fun `BIP49 reference tests`() {
        val seed = MnemonicCode.toSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(" "), "")
        val master = DeterministicWallet.generate(seed)
        assertEquals(DeterministicWallet.encode(master, DeterministicWallet.zprv), "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5")
        assertEquals(DeterministicWallet.encode(DeterministicWallet.publicKey(master), DeterministicWallet.zpub), "zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF")

        val accountKey = DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/22'/0'"))
        assertEquals(DeterministicWallet.encode(accountKey, DeterministicWallet.zprv), "zprvAcZ5F4WJkcPfLQbTgjhcNt4sxGSXFxHWyLZsxd8fENCMFKRhc32Xjdwo4WMje5zhNzy2WeqoHYWFhNittqCHD96Bj1mM7eFVdf5oNhahGtx")
        assertEquals(DeterministicWallet.encode(DeterministicWallet.publicKey(accountKey), DeterministicWallet.zpub), "zpub6qYRea3CaywxYtfvnmEck21cWJH1fR1NLZVUm1YGnhjL87kr9aLnHSGGumibCJWR9SswtGCuK15Z57WC18oJzkAhZXCTcWTcdHJMfbydrok")

        val key = DeterministicWallet.derivePrivateKey(accountKey, listOf(0L, 0L))
        assertEquals(key.secretkeybytes, DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/22'/0'/0/0")).secretkeybytes)
        assertEquals(key.privateKey.toBase58(Base58.Prefix.SecretKey), "TAWKTY1ch7Zay7DggupUoHCbkJY4HxXp5oGU6DXVofVq68f5i8t4")
        assertEquals(
            key.publicKey,
            PublicKey.fromHex("02501db0fe8b6003439eb434a818f4fe24865b9eae20461070f50601dc9bc68426")
        )
        assertEquals(computeBIP84Address(key.publicKey, Block.LivenetGenesisBlock.hash), "mona1qpgmk2vdx5ve6xm93rplw9d6uszpe4am5my7x72")

        val key1 = DeterministicWallet.derivePrivateKey(accountKey, listOf(0L, 1L))
        assertEquals(key1.secretkeybytes, DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/22'/0'/0/1")).secretkeybytes)
        assertEquals(key1.privateKey.toBase58(Base58.Prefix.SecretKey), "T49phmvFNh5bzDpvzE1iUgdtuq7JiruVo2R34nGcYSU7CbJYoSoB")
        assertEquals(
            key1.publicKey,
            PublicKey.fromHex("0292505225edc87cc6017ee4ca6d6dccc891b16b23fec9a7f161b87e7c3fbf1475")
        )
        assertEquals(computeBIP84Address(key1.publicKey, Block.LivenetGenesisBlock.hash), "mona1qrxn93s4m5wlg029z4mzwlwyc7r7efml9ku0ama")

        val key2 = DeterministicWallet.derivePrivateKey(accountKey, listOf(1L, 0L))
        assertEquals(key2.secretkeybytes, DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/22'/0'/1/0")).secretkeybytes)
        assertEquals(key2.privateKey.toBase58(Base58.Prefix.SecretKey), "T46eKCC5ngZk6zQL2rpewxBMRgN8HEJfTrPeaNW1DuwJVfkzCZf8")
        assertEquals(
            key2.publicKey,
            PublicKey.fromHex("02389c16bfd721115c6f1e9fbb66f88e437da724cef7015f027a5732389dcd4c7e")
        )
        assertEquals(computeBIP84Address(key2.publicKey, Block.LivenetGenesisBlock.hash), "mona1q7t5p3u22skphsflmxnta7tjw8kspf7s35q793e")
    }
}
