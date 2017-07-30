/*
 * Copyright (c) 2017 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

using System;

namespace Crypto {

/*
 * Helper methods for handling big integers.
 */

static class BigInt {

	/* 
	 * Normalize a big integer to its minimal size encoding
	 * (unsigned big-endian). This function always returns
	 * a new, fresh array.
	 */
	internal static byte[] NormalizeBE(byte[] val)
	{
		return NormalizeBE(val, false);
	}

	/*
	 * Normalize a big integer to its minimal size encoding
	 * (big-endian). If 'signed' is true, then room for a sign
	 * bit (of value 0) is kept. Note that even if 'signed' is
	 * true, the source array is assumed positive (i.e. unsigned).
	 * This function always returns a new, fresh array.
	 */
	internal static byte[] NormalizeBE(byte[] val, bool signed)
	{
		int n = val.Length;
		int i = 0;
		while (i < n && val[i] == 0) {
			i ++;
		}
		if (signed && (i == n || val[i] >= 0x80)) {
			i --;
		}
		byte[] nval = new byte[n - i];
		if (i < 0) {
			Array.Copy(val, 0, nval, 1, n);
		} else {
			Array.Copy(val, i, nval, 0, n - i);
		}
		return nval;
	}

	/*
	 * Compute the exact bit length of an integer (unsigned big-endian
	 * encoding).
	 */
	internal static int BitLength(byte[] val)
	{
		return BitLength(val, 0, val.Length);
	}

	/*
	 * Compute the exact bit length of an integer (unsigned big-endian
	 * encoding).
	 */
	internal static int BitLength(byte[] val, int off, int len)
	{
		int tlen = 0;
		uint hb = 0;
		uint nf = ~(uint)0;
		for (int i = 0; i < len; i ++) {
			int b = (int)(val[off + i] & nf);
			uint bnz = nf & (uint)((b | -b) >> 31);
			tlen |= (int)bnz & (len - i);
			hb |= bnz & (uint)b;
			nf &= ~bnz;
		}
		return (tlen << 3) - 8 + BitLength(hb);
	}

	/*
	 * Compute the exact bit length of an integer (in a 32-bit word).
	 */
	internal static int BitLength(uint w)
	{
		int bitLen = 0;
		for (int f = 16; f > 0; f >>= 1) {
			uint nw = w >> f;
			int x = (int)nw;
			uint ctl = (uint)((x | -x) >> 31);
			w = (w & ~ctl) | (nw & ctl);
			bitLen += f & (int)ctl;
		}
		return bitLen + (int)w;
	}

	/*
	 * Compute a simple hashcode on an integer. The returned value
	 * depends on the numerical value (assuming that the array is
	 * in unsigned big-endian representation) but not on the presence
	 * of leading zeros. The memory access pattern of this method
	 * depends only on the length of the array x.
	 */
	public static uint HashInt(byte[] x)
	{
		/*
		 * We simply compute x modulo 4294967291 (0xFFFFFFFB),
		 * which is a prime number. The value is injected byte
		 * by byte, and we keep the running state on two words
		 * (16 bits per word, but we allow a few extra bits of
		 * carry).
		 *
		 * For all iterations, "hi" contains at most 16 bits,
		 * and "lo" is less than 16*2^16 (i.e. it fits on 20 bits).
		 */
		uint hi = 0, lo = 0;
		for (int i = 0; i < x.Length; i ++) {
			hi = (hi << 8) + (lo >> 8);
			lo = (lo & 0xFF) << 8;
			lo += (uint)5 * (hi >> 16) + (uint)x[i];
			hi &= 0xFFFF;
		}

		/*
		 * Final reduction. We first propagate the extra bits
		 * from the low word, which may induce one extra bit
		 * on the high word, which we propagate back.
		 */
		hi += (lo >> 16);
		lo &= 0xFFFF;
		lo += (uint)5 * (hi >> 16);
		hi &= 0xFFFF;

		/*
		 * If we have extra bits at that point, then this means
		 * that adding a 4-bits-or-less value to "hi" implied
		 * a carry, so now "hi" is small and the addition below
		 * won't imply a carry.
		 */
		hi += (lo >> 16);
		lo &= 0xFFFF;

		/*
		 * At that point, value is on 32 bits. We want to do a
		 * final reduction for 0xFFFFFFFB..0xFFFFFFFF. Value is
		 * in this range if and only if 'hi' is 0xFFFF and 'lo'
		 * is at least 0xFFFB.
		 */
		int z = (int)(((hi + 1) >> 16) | ((lo + 5) >> 16));
		return (hi << 16) + lo + ((uint)5 & (uint)((z | -z) >> 31));
	}

	/*
	 * Add two integers together. The two operands a[] and b[]
	 * use big-endian encoding. The returned product array is newly
	 * allocated and normalized. The operands are not modified. The
	 * operands need not be normalized and may be the same array.
	 */
	public static byte[] Add(byte[] a, byte[] b)
	{
		int aLen = a.Length;
		int bLen = b.Length;
		int xLen = Math.Max(aLen, bLen) + 1;
		byte[] x = new byte[xLen];
		int cc = 0;
		for (int i = 0; i < xLen; i ++) {
			int wa = (i < aLen) ? (int)a[aLen - 1 - i] : 0;
			int wb = (i < bLen) ? (int)b[bLen - 1 - i] : 0;
			int wx = wa + wb + cc;
			x[xLen - 1 - i] = (byte)wx;
			cc = wx >> 8;
		}
		return NormalizeBE(x);
	}

	/*
	 * Subtract integer b[] from integer a[]. Both operands use
	 * big-endian encoding. If b[] turns out to be greater than a[],
	 * then this method returns null.
	 */
	public static byte[] Sub(byte[] a, byte[] b)
	{
		int aLen = a.Length;
		int bLen = b.Length;
		int xLen = Math.Max(aLen, bLen);
		byte[] x = new byte[aLen];
		int cc = 0;
		for (int i = 0; i < xLen; i ++) {
			int wa = (i < aLen) ? (int)a[aLen - 1 - i] : 0;
			int wb = (i < bLen) ? (int)b[bLen - 1 - i] : 0;
			int wx = wa - wb - cc;
			x[xLen - 1 - i] = (byte)wx;
			cc = (wx >> 8) & 1;
		}
		if (cc != 0) {
			return null;
		}
		return NormalizeBE(x);
	}

	/*
	 * Multiply two integers together. The two operands a[] and b[]
	 * use big-endian encoding. The returned product array is newly
	 * allocated and normalized. The operands are not modified. The
	 * operands need not be normalized and may be the same array.
	 *
	 * The two source operands MUST NOT have length larger than
	 * 32767 bytes.
	 */
	public static byte[] Mul(byte[] a, byte[] b)
	{
		a = NormalizeBE(a);
		b = NormalizeBE(b);
		if (a.Length > 32767 || b.Length > 32767) {
			throw new CryptoException(
				"Operands too large for multiplication");
		}
		int aLen = a.Length;
		int bLen = b.Length;
		int xLen = aLen + bLen;
		uint[] x = new uint[xLen];
		for (int i = 0; i < aLen; i ++) {
			uint u = (uint)a[aLen - 1 - i];
			for (int j = 0; j < bLen; j ++) {
				x[i + j] += u * (uint)b[bLen - 1 - j];
			}
		}
		byte[] y = new byte[xLen];
		uint cc = 0;
		for (int i = 0; i < xLen; i ++) {
			uint w = x[i] + cc;
			y[xLen - 1 - i] = (byte)w;
			cc = w >> 8;
		}
		if (cc != 0) {
			throw new CryptoException(
				"Multiplication: internal error");
		}
		return NormalizeBE(y);
	}

	/*
	 * Compare two integers (unsigned, big-endian). Returned value
	 * is -1, 0 or 1, depending on whether a[] is lower than, equal
	 * to, or greater then b[]. a[] and b[] may have distinct sizes.
	 *
	 * Memory access pattern depends on the most significant index
	 * (i.e. lowest index, since we use big-endian convention) for
	 * which the two values differ.
	 */
	public static int Compare(byte[] a, byte[] b)
	{
		int na = a.Length;
		int nb = b.Length;
		for (int i = Math.Max(a.Length, b.Length); i > 0; i --) {
			byte xa = (i > na) ? (byte)0x00 : a[na - i];
			byte xb = (i > nb) ? (byte)0x00 : b[nb - i];
			if (xa != xb) {
				return xa < xb ? -1 : 1;
			}
		}
		return 0;
	}

	/*
	 * Compare two integers (unsigned, big-endian). Returned value
	 * is -1, 0 or 1, depending on whether a[] is lower than, equal
	 * to, or greater then b[]. a[] and b[] may have distinct sizes.
	 *
	 * This method's memory access pattern is independent of the
	 * contents of the a[] and b[] arrays.
	 */
	public static int CompareCT(byte[] a, byte[] b)
	{
		int na = a.Length;
		int nb = b.Length;
		uint lt = 0;
		uint gt = 0;
		for (int i = Math.Max(a.Length, b.Length); i > 0; i --) {
			int xa = (i > na) ? 0 : a[na - i];
			int xb = (i > nb) ? 0 : b[nb - i];
			lt |= (uint)((xa - xb) >> 31) & ~(lt | gt);
			gt |= (uint)((xb - xa) >> 31) & ~(lt | gt);
		}
		return (int)lt | -(int)gt;
	}

	/*
	 * Check whether an integer (unsigned, big-endian) is zero.
	 */
	public static bool IsZero(byte[] x)
	{
		return IsZeroCT(x) != 0;
	}

	/*
	 * Check whether an integer (unsigned, big-endian) is zero.
	 * Memory access pattern depends only on the length of x[].
	 * Returned value is 0xFFFFFFFF is the value is zero, 0x00000000
	 * otherwise.
	 */
	public static uint IsZeroCT(byte[] x)
	{
		int z = 0;
		for (int i = 0; i < x.Length; i ++) {
			z |= x[i];
		}
		return ~(uint)((z | -z) >> 31);
	}

	/*
	 * Check whether an integer (unsigned, big-endian) is one.
	 */
	public static bool IsOne(byte[] x)
	{
		return IsOneCT(x) != 0;
	}

	/*
	 * Check whether an integer (unsigned, big-endian) is one.
	 * Memory access pattern depends only on the length of x[].
	 * Returned value is 0xFFFFFFFF is the value is one, 0x00000000
	 * otherwise.
	 */
	public static uint IsOneCT(byte[] x)
	{
		int n = x.Length;
		if (n == 0) {
			return 0x00000000;
		}
		int z = 0;
		for (int i = 0; i < n - 1; i ++) {
			z |= x[i];
		}
		z |= x[n - 1] - 1;
		return ~(uint)((z | -z) >> 31);
	}

	/*
	 * Check whether the provided integer is odd (the source integer
	 * is in unsigned big-endian notation).
	 */
	public static bool IsOdd(byte[] x)
	{
		return x.Length > 0 && (x[x.Length - 1] & 0x01) != 0;
	}

	/*
	 * Compute a modular exponentiation (x^e mod n). Conditions:
	 * -- x[], e[] and n[] use big-endian encoding.
	 * -- x[] must be numerically smaller than n[].
	 * -- n[] must be odd.
	 * Result is returned as a newly allocated array of bytes of
	 * the same length as n[].
	 */
	public static byte[] ModPow(byte[] x, byte[] e, byte[] n)
	{
		ModInt mx = new ModInt(n);
		mx.Decode(x);
		mx.Pow(e);
		return mx.Encode();
	}

	/*
	 * Create a new random integer, chosen uniformly among integers
	 * modulo the provided max[].
	 */
	public static byte[] RandInt(byte[] max)
	{
		return RandInt(max, false);
	}

	/*
	 * Create a new random integer, chosen uniformly among non-zero
	 * integers modulo the provided max[].
	 */
	public static byte[] RandIntNZ(byte[] max)
	{
		return RandInt(max, true);
	}

	static byte[] RandInt(byte[] max, bool notZero)
	{
		int mlen = BitLength(max);
		if (mlen == 0 || (notZero && mlen == 1)) {
			throw new CryptoException(
				"Null maximum for random generation");
		}
		byte[] x = new byte[(mlen + 7) >> 3];
		byte hm = (byte)(0xFF >> ((8 - mlen) & 7));
		for (;;) {
			RNG.GetBytes(x);
			x[0] &= hm;
			if (notZero && IsZero(x)) {
				continue;
			}
			if (CompareCT(x, max) >= 0) {
				continue;
			}
			return x;
		}
	}

	/*
	 * Create a new random prime with a specific length (in bits). The
	 * returned prime will have its two top bits set, _and_ its two
	 * least significant bits set as well. The size parameter must be
	 * greater than or equal to 9 (that is, the unsigned encoding of
	 * the prime will need at least two bytes).
	 */
	public static byte[] RandPrime(int size)
	{
		if (size < 9) {
			throw new CryptoException(
				"Invalid size for prime generation");
		}
		int len = (size + 7) >> 3;
		byte[] buf = new byte[len];
		int hm1 = 0xFFFF >> ((len << 3) - size);
		int hm2 = 0xC000 >> ((len << 3) - size);
		for (;;) {
			RNG.GetBytes(buf);
			buf[len - 1] |= (byte)0x03;
			int x = (buf[0] << 8) | buf[1];
			x &= hm1;
			x |= hm2;
			buf[0] = (byte)(x >> 8);
			buf[1] = (byte)x;
			if (IsPrime(buf)) {
				return buf;
			}
		}
	}

	/*
	 * A bit-field for primes in the 0..255 range.
	 */
	static uint[] SMALL_PRIMES_BF = {
		0xA08A28AC, 0x28208A20, 0x02088288, 0x800228A2,
		0x20A00A08, 0x80282088, 0x800800A2, 0x08028228
	};

	static bool IsSmallPrime(int x)
	{
		if (x < 2 || x >= 256) {
			return false;
		}
		return ((SMALL_PRIMES_BF[x >> 5] >> (x & 31)) & (uint)1) != 0;
	}

	/*
	 * Test an integer for primality. This function runs up to 50
	 * Miller-Rabin rounds, which is a lot of overkill but ensures
	 * that non-primes will be reliably detected (with overwhelming
	 * probability) even with maliciously crafted inputs. "Normal"
	 * non-primes will be detected most of the time at the first
	 * iteration.
	 *
	 * This function is not constant-time.
	 */
	public static bool IsPrime(byte[] x)
	{
		x = NormalizeBE(x);

		/*
		 * Handle easy cases:
		 *   0 is not prime
		 *   small primes (one byte) are known in a constant bit-field
		 *   even numbers (larger than one byte) are non-primes
		 */
		if (x.Length == 0) {
			return false;
		}
		if (x.Length == 1) {
			return IsSmallPrime(x[0]);
		}
		if ((x[x.Length - 1] & 0x01) == 0) {
			return false;
		}

		/*
		 * Perform some trial divisions by small primes.
		 */
		for (int sp = 3; sp < 256; sp += 2) {
			if (!IsSmallPrime(sp)) {
				continue;
			}
			int z = 0;
			foreach (byte b in x) {
				z = ((z << 8) + b) % sp;
			}
			if (z == 0) {
				return false;
			}
		}

		/*
		 * Run some Miller-Rabin rounds. We use as basis random
		 * integers that are one byte smaller than the modulus.
		 */
		ModInt xm1 = new ModInt(x);
		ModInt y = xm1.Dup();
		y.Set(1);
		xm1.Sub(y);
		byte[] e = xm1.Encode();
		ModInt a = new ModInt(x);
		byte[] buf = new byte[x.Length - 1];
		for (int i = 0; i < 50; i ++) {
			RNG.GetBytes(buf);
			a.Decode(buf);
			a.Pow(e);
			if (!a.IsOne) {
				return false;
			}
		}
		return true;
	}

	/*
	 * Right-shift an array of bytes by some bits. The bit count MUST
	 * be positive or zero. Extra bits are dropped on the right, and
	 * left positions are filled with zeros.
	 */
	public static void RShift(byte[] buf, int numBits)
	{
		RShift(buf, 0, buf.Length, numBits);
	}

	/*
	 * Right-shift an array of bytes by some bits. The bit count MUST
	 * be positive or zero. Extra bits are dropped on the right, and
	 * left positions are filled with zeros.
	 */
	public static void RShift(byte[] buf, int off, int len, int numBits)
	{
		if (numBits >= 8) {
			int zlen = numBits >> 3;
			if (zlen >= len) {
				for (int i = 0; i < len; i ++) {
					buf[off + i] = 0;
				}
				return;
			}
			Array.Copy(buf, off, buf, off + zlen, len - zlen);
			for (int i = 0; i < zlen; i ++) {
				buf[off + i] = 0;
			}
			off += zlen;
			len -= zlen;
			numBits &= 7;
		}

		int cc = 0;
		for (int i = 0; i < len; i ++) {
			int x = buf[off + i];
			buf[off + i] = (byte)((x >> numBits) + cc);
			cc = x << (8 - numBits);
		}
	}
}

}
