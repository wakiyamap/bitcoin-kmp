package fr.acinq.bitcoin

import fr.acinq.bitcoin.crypto.Pack

class UInt256() : Comparable<UInt256> {
    private val pn = IntArray(WIDTH)

    constructor(rhs: UInt256) : this() {
        rhs.pn.copyInto(pn, 0)
    }

    constructor(value: Long) : this() {
        setUInt64(value)
    }

    constructor(value: ByteArray) : this() {
        require(value.size <= 32)
        val reversed = value.reversedArray() + ByteArray(32 - value.size)
        for (i in 0 until WIDTH) {
            pn[i] = Pack.uint32LE(reversed, 4 * i)
        }
    }

    override fun compareTo(other: UInt256): Int {
        for(i in 0 until WIDTH) {
            if (pn[i] < other.pn[i]) return -1
            if (pn[i] > other.pn[i]) return 1
        }
        return 0
    }

    fun setUInt64(value: Long) {
        pn[0] = (value and 0xffffffff).toInt()
        pn[1] = (value.ushr(32) and 0xffffffff).toInt()
        for (i in 2 until WIDTH) {
            pn[i] = 0
        }
    }

    infix fun shl(bitCount: Int): UInt256 {
        val a = UInt256()
        val k = bitCount / 32
        val shift = bitCount % 32
        for (i in 0 until WIDTH) {
            if (i + k + 1 < WIDTH && shift != 0)
                a.pn[i + k + 1] = a.pn[i + k + 1] or (pn[i].ushr(32 - shift))
            if (i + k < WIDTH)
                a.pn[i + k] = a.pn[i + k] or (pn[i].shl(shift))
        }
        return a
    }

    infix fun shr(bitCount: Int): UInt256 {
        val a = UInt256()
        val k = bitCount / 32
        val shift = bitCount % 32
        for (i in 0 until WIDTH) {
            if (i - k - 1 >= 0 && shift != 0)
                a.pn[i - k - 1] = a.pn[i - k - 1] or (pn[i] shl (32 - shift));
            if (i - k >= 0)
                a.pn[i - k] = a.pn[i - k] or (pn[i] ushr shift)
        }
        return a
    }

    fun bits(): Int {
        for (pos in WIDTH - 1 downTo 0) {
            if (pn[pos] != 0) {
                for (nbits in 31 downTo 0) {
                    if ((pn[pos] and 1.shl(nbits)) != 0)
                        return 32 * pos + nbits + 1;
                }
                return 32 * pos + 1;
            }
        }
        return 0;
    }

    fun getLow64() : Long = pn[0].toLong() or (pn[1].toLong().shl(32))

    fun endodeCompact(fNegative: Boolean): Long {
        var nSize = (bits() + 7) / 8;
        var nCompact = 0L;
        if (nSize <= 3) {
            nCompact = getLow64() shl 8 * (3 - nSize);
        } else {
            val bn = UInt256(this) shr 8 * (nSize - 3);
            nCompact = bn.getLow64();
        }
        // The 0x00800000 bit denotes the sign.
        // Thus, if it is already set, divide the mantissa by 256 and increase the exponent.
        if ((nCompact and 0x00800000L) != 0L) {
            nCompact  = nCompact ushr 8;
            nSize++;
        }
        require((nCompact and 0x007fffffL.inv()) == 0L);
        require(nSize < 256);
        nCompact  = nCompact or (nSize.toLong() shl 24);
        if (fNegative && (nCompact and 0x007fffffL.inv() != 0L)) {
            nCompact = nCompact or 0x00800000
        }
        return nCompact;

    }

    override fun toString(): String {
        val bytes = ByteArray(32)
        for (i in 0 until WIDTH) {
            Pack.writeUint32LE(pn[i], bytes, 4 * i)
        }
        return Hex.encode(bytes.reversedArray())
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as UInt256

        if (!pn.contentEquals(other.pn)) return false

        return true
    }

    override fun hashCode(): Int {
        return pn.contentHashCode()
    }

    companion object {
        private const val WIDTH = 8

        val Zero = UInt256()

        fun decodeCompact(nCompact: Long): Triple<UInt256, Boolean, Boolean> {
            val nSize = (nCompact ushr 24).toInt();
            var nWord = nCompact and 0x007fffff;
            var result = UInt256()
            if (nSize <= 3) {
                nWord = nWord ushr (8 * (3 - nSize));
                result.setUInt64(nWord);
            } else {
                result.setUInt64(nWord);
                result = result.shl(8 * (nSize - 3));
            }
            val pfNegative = nWord != 0L && (nCompact and 0x00800000L) != 0L;
            val pfOverflow = nWord != 0L && ((nSize > 34) ||
                    (nWord > 0xff && nSize > 33) ||
                    (nWord > 0xffff && nSize > 32));
            return Triple(result, pfNegative, pfOverflow);
        }
    }
}