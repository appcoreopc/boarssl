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
using System.Security.Cryptography;
using System.Text;

/*
 * A custom "big integer" implementation. It internally uses an array
 * of 32-bit integers, that encode the integer in little-endian convention,
 * using two's complement for negative integers.
 *
 * Apart from the array, a single 32-bit field is also present, which
 * encodes the sign. When the value is small (it fits on 32 bits), then
 * the array pointer is null, and the value is in the 32-bit field.
 * Since ZInt is a struct, this means that computations using ZInt do
 * not entail any dynamic (GC-based) memory allocation as long as the
 * value fits on 32 bits. This makes it substantially faster than usual
 * "big integer" implementations (including .NET's implementation, since
 * version 4.0) when values are small.
 *
 * Instances are immutable, and thus can be used as if they were
 * "plain integers".
 *
 * None of this code is "constant-time". As such, ZInt should be
 * considered unsuitable to implementations of cryptographic algorithms.
 */

public struct ZInt : IComparable, IComparable<ZInt>, IEquatable<ZInt> {

	/*
	 * CONVENTIONS:
	 *
	 * If varray == null, then "small" contains the integer value.
	 *
	 * If varray != null, then it contains the value, in little-endian
	 * convention (least significant word comes first) and of
	 * minimal encoded length (i.e. "trimmed"). Two's complement is
	 * used for negative values. "small" is then -1 or 0, depending
	 * on whether the value is negative or not.
	 *
	 * Note that the trimmed value does not always include the sign
	 * bit.
	 *
	 * If the integer value is in the range of values which can be
	 * represented in an "int", then magn is null. There is no allowed
	 * overlap between the two kinds of encodings.
	 *
	 * Default value thus encodes the integer zero.
	 */

	readonly int small;
	readonly uint[] varray;

	/*
	 * The value -1.
	 */
	public static ZInt MinusOne {
		get { return new ZInt(-1, null); }
	}

	/*
	 * The value 0.
	 */
	public static ZInt Zero {
		get { return new ZInt(0, null); }
	}

	/*
	 * The value 1.
	 */
	public static ZInt One {
		get { return new ZInt(1, null); }
	}

	/*
	 * The value 2.
	 */
	public static ZInt Two {
		get { return new ZInt(2, null); }
	}

	/*
	 * Internal constructor which assumes that the provided values are
	 * correct and normalized.
	 */
	private ZInt(int small, uint[] varray)
	{
		this.small = small;
		this.varray = varray;
#if DEBUG
		if (varray != null) {
			if (small != -1 && small != 0) {
				throw new Exception(
					"Bad sign encoding: " + small);
			}
			if (varray.Length == 0) {
				throw new Exception("Empty varray");
			}
			if (Length(small, varray) != varray.Length) {
				throw new Exception("Untrimmed varray");
			}
			if (varray.Length == 1) {
				/*
				 * If there was room for a sign bit, then
				 * the "small" encoding should have been used.
				 */
				if (((varray[0] ^ (uint)small) >> 31) == 0) {
					throw new Exception(
						"suboptimal encoding");
				}
			}
		}
#endif
	}

	/*
	 * Main internal build method. This method normalizes the encoding
	 * ("small" encoding is used when possible; otherwise, the varray
	 * is trimmed and the sign is normalized to -1 or 0).
	 *
	 * If "varray" is null, then the small value is used. Otherwise,
	 * only the sign bit (most significant bit) of "small" is used,
	 * and that value is normalized; the array is trimmed. If the
	 * small encoding then becomes applicable, then it is used.
	 */
	private static ZInt Make(int small, uint[] varray)
	{
		if (varray == null) {
			return new ZInt(small, null);
		}
		small >>= 31;
		int n = Length(small, varray);
		if (n == 1 && (((varray[0] ^ (uint)small) >> 31) == 0)) {
			small = (int)varray[0];
			varray = null;
		} else {
			/*
			 * Note: if n == 0 then the value is -1 or 0, and
			 * "small" already contains the correct value;
			 * Trim() will then return null, which is appropriate.
			 */
			varray = Trim(small, varray, n);
		}
		return new ZInt(small, varray);
	}

	/*
	 * Create an instance from a signed 32-bit integer.
	 */
	public ZInt(int val)
	{
		small = val;
		varray = null;
	}

	/*
	 * Create an instance from an unsigned 32-bit integer.
	 */
	public ZInt(uint val)
	{
		small = (int)val;
		if (small < 0) {
			small = 0;
			varray = new uint[1] { val };
		} else {
			varray = null;
		}
	}

	/*
	 * Create an instance from a signed 64-bit integer.
	 */
	public ZInt(long val)
	{
		small = (int)val;
		if ((long)small == val) {
			varray = null;
		} else {
			ulong uval = (ulong)val;
			uint w0 = (uint)uval;
			uint w1 = (uint)(uval >> 32);
			if (w1 == 0) {
				small = 0;
				varray = new uint[1] { w0 };
			} else if (w1 == 0xFFFFFFFF) {
				small = -1;
				varray = new uint[1] { w0 };
			} else {
				small = (int)w1 >> 31;
				varray = new uint[2] { w0, w1 };
			}
		}
	}

	/*
	 * Create an instance from an unsigned 64-bit integer.
	 */
	public ZInt(ulong val)
	{
		if (val <= 0x7FFFFFFF) {
			small = (int)val;
			varray = null;
		} else {
			small = 0;
			uint w0 = (uint)val;
			uint w1 = (uint)(val >> 32);
			if (w1 == 0) {
				varray = new uint[1] { w0 };
			} else {
				varray = new uint[2] { w0, w1 };
			}
		}
	}

	/*
	 * Create a ZInt instance for an integer expressed as an array
	 * of 32-bit integers (unsigned little-endian convention), with
	 * a specific number of value bits.
	 */
	public static ZInt Make(uint[] words, int numBits)
	{
		if (numBits == 0) {
			return Zero;
		}
		int n = (numBits + 31) >> 5;
		int kb = numBits & 31;
		uint[] m = new uint[n];
		Array.Copy(words, 0, m, 0, n);
		if (kb > 0) {
			m[n - 1] &= ~((uint)0xFFFFFFFF << kb);
		}
		return Make(0, m);
	}

	/*
	 * Create a ZInt instance for an integer expressed as an array
	 * of 64-bit integers (unsigned little-endian convention), with
	 * a specific number of value bits.
	 */
	public static ZInt Make(ulong[] words, int numBits)
	{
		if (numBits == 0) {
			return Zero;
		}
		int kw = (numBits + 63) >> 6;
		int kb = numBits & 63;
		int n = kw * 2;
		uint[] m = new uint[n];
		if (kb != 0) {
			ulong z = words[kw - 1]
				& ~((ulong)0xFFFFFFFFFFFFFFFF << kb);
			m[n - 1] = (uint)(z >> 32);
			m[n - 2] = (uint)z;
			kw --;
			n -= 2;
		}
		for (int i = kw - 1, j = n - 2; i >= 0; i --, j -= 2) {
			ulong z = words[i];
			m[j + 0] = (uint)z;
			m[j + 1] = (uint)(z >> 32);
		}
		return Make(0, m);
	}

	/*
	 * Test whether this value is 0.
	 */
	public bool IsZero {
		get {
			return small == 0 && varray == null;
		}
	}

	/*
	 * Test whether this value is 1.
	 */
	public bool IsOne {
		get {
			return small == 1;
		}
	}

	/*
	 * Test whether this value is even.
	 */
	public bool IsEven {
		get {
			uint w = (varray == null) ? (uint)small : varray[0];
			return (w & 1) == 0;
		}
	}

	/*
	 * Test whether this value is a power of 2. Note that 1 is a power
	 * of 2 (but 0 is not). For negative values, false is returned.
	 */
	public bool IsPowerOfTwo {
		get {
			if (small < 0) {
				return false;
			}
			if (varray == null) {
				return small != 0 && (small & -small) == small;
			}
			int n = varray.Length;
			int z = (int)varray[n - 1];
			if ((z & -z) != z) {
				return false;
			}
			for (int i = n - 2; i >= 0; i --) {
				if (varray[i] != 0) {
					return false;
				}
			}
			return true;
		}
	}

	/*
	 * Get the sign of this value as an integer (-1 for negative
	 * values, 1 for positive, 0 for zero).
	 */
	public int Sign {
		get {
			if (varray == null) {
				if (small < 0) {
					return -1;
				} else if (small == 0) {
					return 0;
				} else {
					return 1;
				}
			} else {
				return small | 1;
			}
		}
	}

	/*
	 * Test whether this value would fit in an 'int'.
	 */
	public bool IsInt {
		get {
			return varray == null;
		}
	}

	/*
	 * Test whether this value would fit in a "long".
	 */
	public bool IsLong {
		get {
			if (varray == null) {
				return true;
			}
			int n = varray.Length;
			if (n == 1) {
				return true;
			} else if (n == 2) {
				return ((int)varray[1] >> 31) == small;
			} else {
				return false;
			}
		}
	}

	/*
	 * Get the length of the value in bits. This is the minimal number
	 * of bits of the two's complement representation of the value,
	 * excluding the sign bit; thus, both 0 and -1 have bit length 0.
	 */
	public int BitLength {
		get {
			if (varray == null) {
				if (small < 0) {
					return 32 - LeadingZeros(~(uint)small);
				} else {
					return 32 - LeadingZeros((uint)small);
				}
			} else {
				int n = varray.Length;
				int bl = n << 5;
				uint w = varray[n - 1];
				if (small < 0) {
					return bl - LeadingZeros(~w);
				} else {
					return bl - LeadingZeros(w);
				}
			}
		}
	}

	/*
	 * Test whether the specified bit has value 1 or 0 ("true" is
	 * returned if the bit has value 1). Note that for negative values,
	 * two's complement representation is assumed.
	 */
	public bool TestBit(int n)
	{
		if (n < 0) {
			throw new ArgumentOutOfRangeException();
		}
		if (varray == null) {
			if (n >= 32) {
				return small < 0;
			} else {
				return (((uint)small >> n) & (uint)1) != 0;
			}
		} else {
			int nw = n >> 5;
			if (nw >= varray.Length) {
				return small != 0;
			}
			int nb = n & 31;
			return ((varray[nw] >> nb) & (uint)1) != 0;
		}
	}

	/*
	 * Copy some bits from this instance to the provided array. Bits
	 * are copied in little-endian order. First bit to be copied is
	 * bit at index "off", and exactly "num" bits are copied. This
	 * method modifies only the minimum number of destination words
	 * (i.e. the first "(num+31)/32" words, exactly). Remaining bits
	 * in the last touched word are set to 0.
	 */
	public void CopyBits(int off, int num, uint[] dest)
	{
		CopyBits(off, num, dest, 0);
	}

	public void CopyBits(int off, int num, uint[] dest, int destOff)
	{
		if (off < 0 || num < 0) {
			throw new ArgumentOutOfRangeException();
		}
		if (num == 0) {
			return;
		}
		ZInt x = this;
		if (off > 0) {
			x >>= off;
		}
		int kw = num >> 5;
		int kb = num & 31;
		uint hmask = ~((uint)0xFFFFFFFF << kb);
		if (x.varray == null) {
			if (kw == 0) {
				dest[destOff] = (uint)x.small & hmask;
			} else {
				uint iw = (uint)(x.small >> 31);
				dest[destOff] = (uint)x.small;
				for (int i = 1; i < kw; i ++) {
					dest[destOff + i] = iw;
				}
				if (kb > 0) {
					dest[destOff + kw] = iw & hmask;
				}
			}
		} else {
			int n = x.varray.Length;
			if (kw <= n) {
				Array.Copy(x.varray, 0, dest, destOff, kw);
			} else {
				Array.Copy(x.varray, 0, dest, destOff, n);
				for (int i = n; i < kw; i ++) {
					dest[destOff + i] = (uint)x.small;
				}
			}
			if (kb > 0) {
				uint last;
				if (kw < n) {
					last = x.varray[kw] & hmask;
				} else {
					last = (uint)x.small & hmask;
				}
				dest[destOff + kw] = last;
			}
		}
	}

	/*
	 * Copy some bits from this instance to the provided array. Bits
	 * are copied in little-endian order. First bit to be copied is
	 * bit at index "off", and exactly "num" bits are copied. This
	 * method modifies only the minimum number of destination words
	 * (i.e. the first "(num+63)/64" words, exactly). Remaining bits
	 * in the last touched word are set to 0.
	 */
	public void CopyBits(int off, int num, ulong[] dest)
	{
		CopyBits(off, num, dest, 0);
	}

	public void CopyBits(int off, int num, ulong[] dest, int destOff)
	{
		if (off < 0 || num < 0) {
			throw new ArgumentOutOfRangeException();
		}
		if (num == 0) {
			return;
		}
		ZInt x = this;
		if (off > 0) {
			x >>= off;
		}
		int kw = num >> 6;
		int kb = num & 63;
		ulong hmask = ~((ulong)0xFFFFFFFFFFFFFFFF << kb);
		long xs = (long)x.small;
		if (x.varray == null) {
			if (kw == 0) {
				dest[destOff] = (ulong)xs & hmask;
			} else {
				ulong iw = (ulong)(xs >> 31);
				dest[destOff] = (ulong)xs;
				for (int i = 1; i < kw; i ++) {
					dest[destOff + i] = iw;
				}
				if (kb > 0) {
					dest[destOff + kw] = iw & hmask;
				}
			}
		} else {
			int n = x.varray.Length;
			uint iw = (uint)x.small;
			int j = 0;
			for (int i = 0; i < kw; i ++, j += 2) {
				uint w0 = (j < n) ? x.varray[j] : iw;
				uint w1 = ((j + 1) < n) ? x.varray[j + 1] : iw;
				dest[destOff + i] =
					(ulong)w0 | ((ulong)w1 << 32);
			}
			if (kb > 0) {
				uint w0 = (j < n) ? x.varray[j] : iw;
				uint w1 = ((j + 1) < n) ? x.varray[j + 1] : iw;
				ulong last = (ulong)w0 | ((ulong)w1 << 32);
				dest[destOff + kw] = last & hmask;
			}
		}
	}

	/*
	 * Extract a 32-bit word at a given offset (counted in bits).
	 * This function is equivalent to right-shifting the value by
	 * "off" bits, then returning the low 32 bits (however, this
	 * function may be more efficient).
	 */
	public uint GetWord(int off)
	{
		if (off < 0) {
			throw new ArgumentOutOfRangeException();
		}
		if (varray == null) {
			int x = small;
			if (off >= 32) {
				off = 31;
			}
			return (uint)(x >> off);
		}
		int n = varray.Length;
		int kw = off >> 5;
		if (kw >= n) {
			return (uint)small;
		}
		int kb = off & 31;
		if (kb == 0) {
			return varray[kw];
		} else {
			uint hi;
			if (kw == n - 1) {
				hi = (uint)small;
			} else {
				hi = varray[kw + 1];
			}
			uint lo = varray[kw];
			return (lo >> kb) | (hi << (32 - kb));
		}
	}

	/*
	 * Extract a 64-bit word at a given offset (counted in bits).
	 * This function is equivalent to right-shifting the value by
	 * "off" bits, then returning the low 64 bits (however, this
	 * function may be more efficient).
	 */
	public ulong GetWord64(int off)
	{
		if (off < 0) {
			throw new ArgumentOutOfRangeException();
		}
		if (varray == null) {
			int x = small;
			if (off >= 32) {
				off = 31;
			}
			return (ulong)(x >> off);
		}
		int n = varray.Length;
		int kw = off >> 5;
		if (kw >= n) {
			return (ulong)small;
		}
		int kb = off & 31;
		if (kb == 0) {
			if (kw == (n - 1)) {
				return (ulong)varray[kw]
					| ((ulong)small << 32);
			} else {
				return (ulong)varray[kw]
					| ((ulong)varray[kw + 1] << 32);
			}
		} else {
			uint v0, v1, v2;
			if (kw == (n - 1)) {
				v0 = varray[kw];
				v1 = (uint)small;
				v2 = (uint)small;
			} else if (kw == (n - 2)) {
				v0 = varray[kw];
				v1 = varray[kw + 1];
				v2 = (uint)small;
			} else {
				v0 = varray[kw];
				v1 = varray[kw + 1];
				v2 = varray[kw + 2];
			}
			uint lo = (v0 >> kb) | (v1 << (32 - kb));
			uint hi = (v1 >> kb) | (v2 << (32 - kb));
			return (ulong)lo | ((ulong)hi << 32);
		}
	}

	/*
	 * Convert this value to an 'int', using silent truncation if
	 * the value does not fit.
	 */
	public int ToInt {
		get {
			return (varray == null) ? small : (int)varray[0];
		}
	}

	/*
	 * Convert this value to an 'uint', using silent truncation if
	 * the value does not fit.
	 */
	public uint ToUInt {
		get {
			return (varray == null) ? (uint)small : varray[0];
		}
	}

	/*
	 * Convert this value to a 'long', using silent truncation if
	 * the value does not fit.
	 */
	public long ToLong {
		get {
			return (long)ToULong;
		}
	}

	/*
	 * Convert this value to an 'ulong', using silent truncation if
	 * the value does not fit.
	 */
	public ulong ToULong {
		get {
			if (varray == null) {
				return (ulong)small;
			} else if (varray.Length == 1) {
				uint iw = (uint)small;
				return (ulong)varray[0] | ((ulong)iw << 32);
			} else {
				return (ulong)varray[0]
					| ((ulong)varray[1] << 32);
			}
		}
	}

	/*
	 * Get the actual length of a varray encoding: this is the minimal
	 * length, in words, needed to encode the value. The value sign
	 * is provided as a negative or non-negative integer, and the
	 * encoding of minimal length does not necessarily include a
	 * sign bit. The value 0 is returned when the array encodes 0
	 * or -1 (depending on sign).
	 */
	static int Length(int sign, uint[] m)
	{
		if (m == null) {
			return 0;
		}
		uint sw = (uint)(sign >> 31);
		int n = m.Length;
		while (n > 0 && m[n - 1] == sw) {
			n --;
		}
		return n;
	}

	/*
	 * Trim an encoding to its minimal encoded length. If the provided
	 * array is already of minimal length, it is returned unchanged.
	 */
	static uint[] Trim(int sign, uint[] m)
	{
		int n = Length(sign, m);
		if (n == 0) {
			return null;
		} else if (n < m.Length) {
			uint[] mt = new uint[n];
			Array.Copy(m, 0, mt, 0, n);
			return mt;
		} else {
			return m;
		}
	}

	/*
	 * Trim or extend a value to the provided length. The returned
	 * array will have the length specified as "n" (if n == 0, then
	 * null is returned). If the source array already has the right
	 * size, then it is returned unchanged.
	 */
	static uint[] Trim(int sign, uint[] m, int n)
	{
		if (n == 0) {
			return null;
		} else if (m == null) {
			m = new uint[n];
			if (sign < 0) {
				Fill(0xFFFFFFFF, m);
			}
			return m;
		}
		int ct = m.Length;
		if (ct < n) {
			uint[] r = new uint[n];
			Array.Copy(m, 0, r, 0, ct);
			return r;
		} else if (ct == n) {
			return m;
		} else {
			uint[] r = new uint[n];
			Array.Copy(m, 0, r, 0, n);
			if (sign < 0) {
				Fill(0xFFFFFFFF, r, ct, n - ct);
			}
			return r;
		}
	}

	static void Fill(uint val, uint[] buf)
	{
		Fill(val, buf, 0, buf.Length);
	}

	static void Fill(uint val, uint[] buf, int off, int len)
	{
		while (len -- > 0) {
			buf[off ++] = val;
		}
	}

	// =================================================================
	/*
	 * Utility methods.
	 *
	 * The methods whose name begins with "Mutate" modify the array
	 * they are given as first parameter; the other methods instantiate
	 * a new array.
	 *
	 * As a rule, untrimmed arrays are accepted as input, and output
	 * may be untrimmed as well.
	 */

	/*
	 * Count the number of leading zeros for a 32-bit value (number of
	 * consecutive zeros, starting with the most significant bit). This
	 * value is between 0 (for a value equal to 2^31 or greater) and
	 * 32 (for zero).
	 */
	static int LeadingZeros(uint v)
	{
		if (v == 0) {
			return 32;
		}
		int n = 0;
		if (v > 0xFFFF) { v >>= 16; } else { n += 16; }
		if (v > 0x00FF) { v >>=  8; } else { n +=  8; }
		if (v > 0x000F) { v >>=  4; } else { n +=  4; }
		if (v > 0x0003) { v >>=  2; } else { n +=  2; }
		if (v <= 0x0001) { n ++; }
		return n;
	}

	/*
	 * Duplicate the provided magnitude array. No attempt is made at
	 * trimming. The source array MUST NOT be null.
	 */
	static uint[] Dup(uint[] m)
	{
		uint[] r = new uint[m.Length];
		Array.Copy(m, 0, r, 0, m.Length);
		return r;
	}

	/*
	 * Increment the provided array. If there is a resulting carry,
	 * then "true" is returned, "false" otherwise. The array MUST
	 * NOT be null.
	 */
	static bool MutateIncr(uint[] x)
	{
		int n = x.Length;
		for (int i = 0; i < n; i ++) {
			uint w = x[i] + 1;
			x[i] = w;
			if (w != 0) {
				return false;
			}
		}
		return true;
	}

	/*
	 * Decrement the provided array. If there is a resulting carry,
	 * then "true" is returned, "false" otherwise. The array MUST
	 * NOT be null.
	 */
	static bool MutateDecr(uint[] x)
	{
		int n = x.Length;
		for (int i = 0; i < n; i ++) {
			uint w = x[i];
			x[i] = w - 1;
			if (w != 0) {
				return false;
			}
		}
		return true;
	}

	/*
	 * Multiply a[] with b[] (unsigned multiplication).
	 */
	static uint[] Mul(uint[] a, uint[] b)
	{
		// TODO: use Karatsuba when operands are large.
		int na = Length(0, a);
		int nb = Length(0, b);
		if (na == 0 || nb == 0) {
			return null;
		}
		uint[] r = new uint[na + nb];
		for (int i = 0; i < na; i ++) {
			ulong ma = a[i];
			ulong carry = 0;
			for (int j = 0; j < nb; j ++) {
				ulong mb = (ulong)b[j];
				ulong mr = (ulong)r[i + j];
				ulong w = ma * mb + mr + carry;
				r[i + j] = (uint)w;
				carry = w >> 32;
			}
			r[i + nb] = (uint)carry;
		}
		return r;
	}

	/*
	 * Get the sign and magnitude of an integer. The sign is
	 * normalized to -1 (negative) or 0 (positive or zero). The
	 * magnitude is an array of length at least 1, containing the
	 * absolute value of this integer; if possible, the varray
	 * is reused (hence, the magnitude array MUST NOT be altered).
	 */
	static void ToAbs(ZInt x, out int sign, out uint[] magn)
	{
		if (x.small < 0) {
			sign = -1;
			x = -x;
		} else {
			sign = 0;
		}
		magn = x.varray;
		if (magn == null) {
			magn = new uint[1] { (uint)x.small }; 
		}
	}

	/*
	 * Compare two integers, yielding -1, 0 or 1.
	 */
	static int Compare(int a, int b)
	{
		if (a < b) {
			return -1;
		} else if (a == b) {
			return 0;
		} else {
			return 1;
		}
	}

	/*
	 * Compare a[] with b[] (unsigned). Returned value is 1 if a[]
	 * is greater than b[], 0 if they are equal, -1 otherwise.
	 */
	static int Compare(uint[] a, uint[] b)
	{
		int ka = Length(0, a);
		int kb = Length(0, b);
		if (ka < kb) {
			return -1;
		} else if (ka == kb) {
			while (ka > 0) {
				ka --;
				uint wa = a[ka];
				uint wb = b[ka];
				if (wa < wb) {
					return -1;
				} else if (wa > wb) {
					return 1;
				}
			}
			return 0;
		} else {
			return 1;
		}
	}

	/*
	 * Add b[] to a[] (unsigned). a[] is modified "in place". Only
	 * n words of a[] are modified. Moreover, the value of
	 * b[] which is added is left-shifted: words b[0]...b[n-1] are
	 * added to a[k]...a[k+n-1]. The final carry is returned ("true"
	 * for 1, "false" for 0). Neither a nor b may be null.
	 */
	static bool MutateAdd(uint[] a, int n, uint[] b, int k)
	{
		bool carry = false;
		for (int i = 0; i < n; i ++) {
			uint wa = a[i + k];
			uint wb = b[i];
			uint wc = wa + wb;
			if (carry) {
				wc ++;
				carry = wa >= wc;
			} else {
				carry = wa > wc;
			}
			a[i + k] = wc;
		}
		return carry;
	}

	/*
	 * Substract b[] from a[] (unsigned). a[] is modified "in
	 * place". Only n words of a[] are modified. Words
	 * b[0]...b[n-1] are subtracted from a[k]...a[k+n-1]. The final
	 * carry is returned ("true" for -1, "false" for 0). Neither a
	 * nor b may be null.
	 */
	static bool MutateSub(uint[] a, int n, uint[] b, int k)
	{
		bool carry = false;
		for (int i = 0; i < n; i ++) {
			uint wa = a[i + k];
			uint wb = b[i];
			uint wc = wa - wb;
			if (carry) {
				wc --;
				carry = wa <= wc;
			} else {
				carry = wa < wc;
			}
			a[i + k] = wc;
		}
		return carry;
	}

	/*
	 * Get the length (in words) of the result of a left-shift of
	 * the provided integer by k bits. If k < 0, then the value is
	 * computed for a right-shift by -k bits.
	 */
	static int GetLengthForLeftShift(ZInt x, int k)
	{
		if (k < 0) {
			if (k == Int32.MinValue) {
				return 0;
			}
			return GetLengthForRightShift(x, -k);
		}
		uint bl = (uint)x.BitLength + (uint)k;
		return (int)((bl + 31) >> 5);
	}

	/*
	 * Get the length (in words) of the result of a right-shift of
	 * the provided integer by k bits. If k < 0, then the value is
	 * computed for a left-shift by -k bits.
	 */
	static int GetLengthForRightShift(ZInt x, int k)
	{
		if (k < 0) {
			if (k == Int32.MinValue) {
				throw new OverflowException();
			}
			return GetLengthForLeftShift(x, -k);
		}
		uint bl = (uint)x.BitLength;
		if (bl <= (uint)k) {
			return 0;
		} else {
			return (int)((bl - k + 31) >> 5);
		}
	}

	/*
	 * Left-shift a[] (unsigned) by k bits. If k < 0, then this becomes
	 * a right-shift.
	 */
	static uint[] ShiftLeft(uint[] a, int k)
	{
		if (k < 0) {
			return ShiftRight(a, -k);
		} else if (k == 0) {
			return a;
		}
		int n = Length(0, a);
		if (n == 0) {
			return null;
		}

		/*
		 * Allocate the result array, with the exact proper size.
		 */
		int bl = ((n << 5) - LeadingZeros(a[n - 1])) + k;
		uint[] r = new uint[(bl + 31) >> 5];

		int kb = k & 31;
		int kw = k >> 5;

		/*
		 * Special case: shift by an integral amount of words.
		 */
		if (kb == 0) {
			Array.Copy(a, 0, r, kw, n);
			return r;
		}

		/*
		 * Copy the bits. This loop handles one source word at
		 * a time, and writes one destination word at a time.
		 * Some unhandled bits may remain at the end.
		 */
		uint bits = 0;
		int zkb = 32 - kb;
		for (int i = 0; i < n; i ++) {
			uint w = a[i];
			r[i + kw] = bits | (w << kb);
			bits = w >> zkb;
		}
		if (bits != 0) {
			r[n + kw] = bits;
		}
		return r;
	}

	/*
	 * Right-shift a[] by k bits. If k < 0, then this becomes
	 * a left-shift.
	 */
	static uint[] ShiftRight(uint[] a, int k)
	{
		if (k < 0) {
			return ShiftLeft(a, -k);
		} else if (k == 0) {
			return a;
		}
		int n = Length(0, a);
		if (n == 0) {
			return null;
		}
		int bl = (n << 5) - LeadingZeros(a[n - 1]) - k;
		if (bl <= 0) {
			return null;
		}
		uint[] r = new uint[(bl + 31) >> 5];

		int kb = k & 31;
		int kw = k >> 5;

		/*
		 * Special case: shift by an integral amount of words.
		 */
		if (kb == 0) {
			Array.Copy(a, kw, r, 0, r.Length);
			return r;
		}

		/*
		 * Copy the bits. This loop handles one source word at
		 * a time, and writes one destination word at a time.
		 * Some unhandled bits may remain at the end.
		 */
		uint bits = a[kw] >> kb;
		int zkb = 32 - kb;
		for (int i = kw + 1; i < n; i ++) {
			uint w = a[i];
			r[i - kw - 1] = bits | (w << zkb);
			bits = w >> kb;
		}
		if (bits != 0) {
			r[n - kw - 1] = bits;
		}
		return r;
	}

	/*
	 * Euclidian division of a[] (unsigned) by b (single word). This
	 * method assumes that b is not 0.
	 */
	static void DivRem(uint[] a, uint b, out uint[] q, out uint r)
	{
		int n = Length(0, a);
		if (n == 0) {
			q = null;
			r = 0;
			return;
		}
		q = new uint[n];
		ulong carry = 0;
		for (int i = n - 1; i >= 0; i --) {
			/*
			 * Performance: we strongly hope that the JIT
			 * compiler will notice that the "/" and "%"
			 * can be combined into a single operation.
			 * TODO: test whether we should replace the
			 * carry computation with:
			 *  carry = w - (ulong)q[i] * b;
			 */
			ulong w = (ulong)a[i] + (carry << 32);
			q[i] = (uint)(w / b);
			carry = w % b;
		}
		r = (uint)carry;
	}

	/*
	 * Euclidian division of a[] (unsigned) by b (single word). This
	 * method assumes that b is not 0. a[] is modified in place. The
	 * remainder (in the 0..b-1 range) is returned.
	 */
	static uint MutateDivRem(uint[] a, uint b)
	{
		int n = Length(0, a);
		if (n == 0) {
			return 0;
		}
		ulong carry = 0;
		for (int i = n - 1; i >= 0; i --) {
			/*
			 * Performance: we strongly hope that the JIT
			 * compiler will notice that the "/" and "%"
			 * can be combined into a single operation.
			 * TODO: test whether we should replace the
			 * carry computation with:
			 *  carry = w - (ulong)q[i] * b;
			 */
			ulong w = (ulong)a[i] + (carry << 32);
			a[i] = (uint)(w / b);
			carry = w % b;
		}
		return (uint)carry;
	}

	/*
	 * Euclidian division of a[] by b[] (unsigned). This method
	 * assumes that b[] is neither 0 or 1, and a[] is not smaller
	 * than b[] (this implies that the quotient won't be zero).
	 */
	static void DivRem(uint[] a, uint[] b, out uint[] q, out uint[] r)
	{
		int nb = Length(0, b);

		/*
		 * Special case when the divisor fits on one word.
		 */
		if (nb == 1) {
			r = new uint[1];
			DivRem(a, b[0], out q, out r[0]);
			return;
		}

		/*
		 * General case.
		 *
		 * We first normalize divisor and dividend such that the
		 * most significant bit of the most significant word of
		 * the divisor is set. We can then compute the quotient
		 * word by word. In details:
		 *
		 * Let:
		 *   w = 2^32 (one word)
		 *   a = (w*a0 + a1) * w^N + a2
		 *   b = b0 * w^N + b2
		 * such that:
		 *   0 <= a0 < w
		 *   0 <= a1 < w
		 *   0 <= a2 < w^N
		 *   w/2 <= b0 < w
		 *   0 <= b2 < w^N
		 *   a < w*b
		 * In other words, a0 and a1 are the two upper words of a[],
		 * b0 is the upper word of b[] and has length 32 bits exactly,
		 * and the quotient of a by b fits in one word.
		 *
		 * Under these conditions, define q and r such that:
		 *   a = b * q + r
		 *   q >= 0
		 *   0 <= r < b
		 * We can then compute a value u this way:
		 *   if a0 = b0, then let u = w-1
		 *   otherwise, let u be such that
		 *     (w*a0 + a1) = u*b0 + v, where 0 <= v < b0
		 * It can then be shown that all these inequations hold:
		 *   0 <= u < w
		 *   u-2 <= q <= u
		 *
		 * In plain words, this allows us to compute an almost-exact
		 * estimate of the upper word of the quotient, with only
		 * one 64-bit division.
		 */

		/*
		 * Normalize dividend and divisor. The normalized dividend
		 * will become the temporary array for the remainder, and
		 * we will modify it, so we make sure we have a copy.
		 */
		int norm = LeadingZeros(b[nb - 1]);
		r = ShiftLeft(a, norm);
		if (r == a) {
			r = new uint[a.Length];
			Array.Copy(a, 0, r, 0, a.Length);
		}
		uint[] b2 = ShiftLeft(b, norm);
		int nr = Length(0, r);
#if DEBUG
		if (Length(0, b2) != nb) {
			throw new Exception("normalize error 1");
		}
		if (b2[nb - 1] < 0x80000000) {
			throw new Exception("normalize error 2");
		}
		{
			uint[] ta = ShiftRight(r, norm);
			if (Compare(a, ta) != 0) {
				throw new Exception("normalize error 3");
			}
			uint[] tb = ShiftRight(b2, norm);
			if (Compare(b, tb) != 0) {
				throw new Exception("normalize error 4");
			}
		}
#endif
		b = b2;

		/*
		 * Length of the quotient will be (at most) k words. This
		 * is the number of iterations in the loop below.
		 */
		int k = (nr - nb) + 1;
#if DEBUG
		if (k <= 0) {
			throw new Exception("wrong iteration count: " + k);
		}
#endif
		q = new uint[k];

		/*
		 * The upper word of a[] (the one we modify, i.e. currently
		 * stored in r[]) is in a0; it is carried over from the
		 * previous loop iteration. Initially, it is zero.
		 */
		uint a0 = 0;
		uint b0 = b[nb - 1];
		int j = nr;
		while (k -- > 0) {
			uint a1 = r[-- j];
			uint u;
			if (a0 == b0) {
				u = 0xFFFFFFFF;
			} else {
				ulong ah = ((ulong)a0 << 32) | (ulong)a1;
				u = (uint)(ah / b0);
			}

			/*
			 * Candidate word for the quotient:
			 * -- if u = 0 then qw is necessarily 0, and the
			 *    rest of this iteration is trivial;
			 * -- if u = 1 then we try qw = 1;
			 * -- otherwise, we try qw = u-1.
			 */
			uint qw;
			if (u == 0) {
				q[k] = 0;
				a0 = a1;
				continue;
			} else if (u == 1) {
				qw = 1;
			} else {
				qw = u - 1;
			}

			/*
			 * "Trying" a candidate word means subtracting from
			 * r[] the product qw*b (b[] being shifted by k words).
			 * The result may be negative, in which case we
			 * overestimated qw; it may be greater than b or
			 * equal to b, in which case we underestimated qw;
			 * or it may be just fine.
			 */
			ulong carry = 0;
			bool tooBig = true;
			for (int i = 0; i < nb; i ++) {
				uint wb = b[i];
				ulong z = (ulong)wb * (ulong)qw + carry;
				carry = z >> 32;
				uint wa = r[i + k];
				uint wc = wa - (uint)z;
				if (wc > wa) {
					carry ++;
				}
				r[i + k] = wc;
				if (wc != wb) {
					tooBig = wc > wb;
				}
			}

			/*
			 * Once we have adjusted everything, the upper word
			 * of r[] will be nullified; wo do it now. Note that
			 * for the first loop iteration, that upper word
			 * may be absent (so already zero, but also "virtual").
			 */
			if (nb + k < nr) {
				r[nb + k] = 0;
			}

			/*
			 * At that point, "carry" should be equal to a0
			 * if we estimated right.
			 */
			if (carry < (ulong)a0) {
				/*
				 * Underestimate.
				 */
				qw ++;
#if DEBUG
				if (carry + 1 != (ulong)a0) {
					throw new Exception("div error 1");
				}
				if (!MutateSub(r, nb, b, k)) {
					throw new Exception("div error 2");
				}
#else
				MutateSub(r, nb, b, k);
#endif
			} else if (carry > (ulong)a0) {
				/*
				 * Overestimate.
				 */
				qw --;
#if DEBUG
				if (carry - 1 != (ulong)a0) {
					throw new Exception("div error 3");
				}
				if (!MutateAdd(r, nb, b, k)) {
					throw new Exception("div error 4");
				}
#else
				MutateAdd(r, nb, b, k);
#endif
			} else if (tooBig) {
				/*
				 * Underestimate, but no expected carry.
				 */
				qw ++;
#if DEBUG
				if (MutateSub(r, nb, b, k)) {
					throw new Exception("div error 5");
				}
#else
				MutateSub(r, nb, b, k);
#endif
			}

			q[k] = qw;
			a0 = r[j];
		}

		/*
		 * At that point, r[] contains the remainder but needs
		 * to be shifted back, to account for the normalization
		 * performed before. q[] is correct (but possibly
		 * untrimmed).
		 */
		r = ShiftRight(r, norm);
	}

	// =================================================================

	/*
	 * Conversion to sbyte; an OverflowException is thrown if the
	 * value does not fit. Use ToInt to get a truncating conversion.
	 */
	public static explicit operator sbyte(ZInt val)
	{
		int x = (int)val;
		if (x < SByte.MinValue || x > SByte.MaxValue) {
			throw new OverflowException();
		}
		return (sbyte)x;
	}

	/*
	 * Conversion to byte; an OverflowException is thrown if the
	 * value does not fit. Use ToInt to get a truncating conversion.
	 */
	public static explicit operator byte(ZInt val)
	{
		int x = (int)val;
		if (x > Byte.MaxValue) {
			throw new OverflowException();
		}
		return (byte)x;
	}

	/*
	 * Conversion to short; an OverflowException is thrown if the
	 * value does not fit. Use ToInt to get a truncating conversion.
	 */
	public static explicit operator short(ZInt val)
	{
		int x = (int)val;
		if (x < Int16.MinValue || x > Int16.MaxValue) {
			throw new OverflowException();
		}
		return (short)x;
	}

	/*
	 * Conversion to ushort; an OverflowException is thrown if the
	 * value does not fit. Use ToInt to get a truncating conversion.
	 */
	public static explicit operator ushort(ZInt val)
	{
		int x = (int)val;
		if (x > UInt16.MaxValue) {
			throw new OverflowException();
		}
		return (ushort)x;
	}

	/*
	 * Conversion to int; an OverflowException is thrown if the
	 * value does not fit. Use ToInt to get a truncating conversion.
	 */
	public static explicit operator int(ZInt val)
	{
		if (val.varray != null) {
			throw new OverflowException();
		}
		return val.small;
	}

	/*
	 * Conversion to uint; an OverflowException is thrown if the
	 * value does not fit. Use ToUInt to get a truncating conversion.
	 */
	public static explicit operator uint(ZInt val)
	{
		int s = val.small;
		if (s < 0) {
			throw new OverflowException();
		}
		uint[] m = val.varray;
		if (m == null) {
			return (uint)s;
		} else if (m.Length > 1) {
			throw new OverflowException();
		} else {
			return m[0];
		}
	}

	/*
	 * Conversion to long; an OverflowException is thrown if the
	 * value does not fit. Use ToLong to get a truncating conversion.
	 */
	public static explicit operator long(ZInt val)
	{
		int s = val.small;
		uint[] m = val.varray;
		if (m == null) {
			return (long)s;
		} else if (m.Length == 1) {
			return (long)m[0] | ((long)s << 32);
		} else if (m.Length == 2) {
			uint w0 = m[0];
			uint w1 = m[1];
			if (((w1 ^ (uint)s) >> 31) != 0) {
				throw new OverflowException();
			}
			return (long)w0 | ((long)w1 << 32);
		} else {
			throw new OverflowException();
		}
	}

	/*
	 * Conversion to ulong; an OverflowException is thrown if the
	 * value does not fit. Use ToULong to get a truncating conversion.
	 */
	public static explicit operator ulong(ZInt val)
	{
		int s = val.small;
		if (s < 0) {
			throw new OverflowException();
		}
		uint[] m = val.varray;
		if (m == null) {
			return (ulong)s;
		} else if (m.Length == 1) {
			return (ulong)m[0];
		} else if (m.Length == 2) {
			return (ulong)m[0] | ((ulong)m[1] << 32);
		} else {
			throw new OverflowException();
		}
	}

	/*
	 * By definition, conversion from sbyte conserves the value.
	 */
	public static implicit operator ZInt(sbyte val)
	{
		return new ZInt((int)val);
	}

	/*
	 * By definition, conversion from byte conserves the value.
	 */
	public static implicit operator ZInt(byte val)
	{
		return new ZInt((uint)val);
	}

	/*
	 * By definition, conversion from short conserves the value.
	 */
	public static implicit operator ZInt(short val)
	{
		return new ZInt((int)val);
	}

	/*
	 * By definition, conversion from ushort conserves the value.
	 */
	public static implicit operator ZInt(ushort val)
	{
		return new ZInt((uint)val);
	}

	/*
	 * By definition, conversion from int conserves the value.
	 */
	public static implicit operator ZInt(int val)
	{
		return new ZInt(val);
	}

	/*
	 * By definition, conversion from uint conserves the value.
	 */
	public static implicit operator ZInt(uint val)
	{
		return new ZInt(val);
	}

	/*
	 * By definition, conversion from long conserves the value.
	 */
	public static implicit operator ZInt(long val)
	{
		return new ZInt(val);
	}

	/*
	 * By definition, conversion from ulong conserves the value.
	 */
	public static implicit operator ZInt(ulong val)
	{
		return new ZInt(val);
	}

	/*
	 * Unary '+' operator is a no-operation.
	 */
	public static ZInt operator +(ZInt a)
	{
		return a;
	}

	/*
	 * Unary negation.
	 */
	public static ZInt operator -(ZInt a)
	{
		int s = a.small;
		uint[] m = a.varray;
		if (m == null) {
			if (s == Int32.MinValue) {
				return new ZInt(0, new uint[1] { 0x80000000 });
			} else {
				return new ZInt(-s, null);
			}
		}

		/*
		 * Two's complement: invert all bits, then add 1. The
		 * result array will usually have the same size, but may
		 * be one word longer or one word shorter.
		 */
		int n = Length(s, m);
		uint[] bm = new uint[n];
		for (int i = 0; i < n; i ++) {
			bm[i] = ~m[i];
		}
		if (MutateIncr(bm)) {
			/*
			 * Extra carry. This may happen only if the source
			 * array contained only zeros, which may happen only
			 * for a source value -2^(32*k) for some integer k
			 * (k > 0).
			 */
			bm = new uint[n + 1];
			bm[n] = 1;
			return new ZInt(0, bm);
		} else {
			/*
			 * The resulting array might be too big by one word,
			 * so we must not assume that it is trimmed.
			 */
			return Make((int)~(uint)s, bm);
		}
	}

	/*
	 * Addition operator.
	 */
	public static ZInt operator +(ZInt a, ZInt b)
	{
		int sa = a.small;
		int sb = b.small;
		uint[] ma = a.varray;
		uint[] mb = b.varray;
		if (ma == null) {
			if (sa == 0) {
				return b;
			}
			if (mb == null) {
				if (sb == 0) {
					return a;
				}
				return new ZInt((long)sa + (long)sb);
			}
			ma = new uint[1] { (uint)sa };
			sa >>= 31;
		} else if (mb == null) {
			if (sb == 0) {
				return a;
			}
			mb = new uint[1] { (uint)sb };
			sb >>= 31;
		}
		int na = ma.Length;
		int nb = mb.Length;
		int n = Math.Max(na, nb) + 1;
		uint[] mc = new uint[n];
		ulong carry = 0;
		for (int i = 0; i < n; i ++) {
			uint wa = i < na ? ma[i] : (uint)sa;
			uint wb = i < nb ? mb[i] : (uint)sb;
			ulong z = (ulong)wa + (ulong)wb + carry;
			mc[i] = (uint)z;
			carry = z >> 32;
		}
		return Make((-(int)carry) ^ sa ^ sb, mc);
	}

	/*
	 * Subtraction operator.
	 */
	public static ZInt operator -(ZInt a, ZInt b)
	{
		int sa = a.small;
		int sb = b.small;
		uint[] ma = a.varray;
		uint[] mb = b.varray;
		if (ma == null) {
			if (sa == 0) {
				return -b;
			}
			if (mb == null) {
				if (sb == 0) {
					return a;
				}
				return new ZInt((long)sa - (long)sb);
			}
			ma = new uint[1] { (uint)sa };
			sa >>= 31;
		} else if (mb == null) {
			if (sb == 0) {
				return a;
			}
			mb = new uint[1] { (uint)sb };
			sb >>= 31;
		}
		int na = ma.Length;
		int nb = mb.Length;
		int n = Math.Max(na, nb) + 1;
		uint[] mc = new uint[n];
		long carry = 0;
		for (int i = 0; i < n; i ++) {
			uint wa = i < na ? ma[i] : (uint)sa;
			uint wb = i < nb ? mb[i] : (uint)sb;
			long z = (long)wa - (long)wb + carry;
			mc[i] = (uint)z;
			carry = z >> 32;
		}
		return Make((int)carry ^ sa ^ sb, mc);
	}

	/*
	 * Increment operator.
	 */
	public static ZInt operator ++(ZInt a)
	{
		int s = a.small;
		uint[] ma = a.varray;
		if (ma == null) {
			return new ZInt((long)s + 1);
		}
		uint[] mb = Dup(ma);
		if (MutateIncr(mb)) {
			int n = ma.Length;
			mb = new uint[n + 1];
			mb[n] = 1;
			return new ZInt(0, mb);
		} else {
			return Make(s, mb);
		}
	}

	/*
	 * Decrement operator.
	 */
	public static ZInt operator --(ZInt a)
	{
		int s = a.small;
		uint[] ma = a.varray;
		if (ma == null) {
			return new ZInt((long)s - 1);
		}

		/*
		 * MutateDecr() will report a carry only if the varray
		 * contained only zeros; since this value was not small,
		 * then it must have been negative.
		 */
		uint[] mb = Dup(ma);
		if (MutateDecr(mb)) {
			int n = mb.Length;
			uint[] mc = new uint[n + 1];
			Array.Copy(mb, 0, mc, 0, n);
			mc[n] = 0xFFFFFFFE;
			return new ZInt(-1, mc);
		} else {
			return Make(s, mb);
		}
	}

	/*
	 * Multiplication operator.
	 */
	public static ZInt operator *(ZInt a, ZInt b)
	{
		int sa = a.small;
		int sb = b.small;
		uint[] ma = a.varray;
		uint[] mb = b.varray;

		/*
		 * Special cases:
		 * -- one of the operands is zero
		 * -- both operands are small
		 */
		if (ma == null) {
			if (sa == 0) {
				return Zero;
			}
			if (mb == null) {
				if (sb == 0) {
					return Zero;
				}
				return new ZInt((long)sa * (long)sb);
			}
		} else if (mb == null) {
			if (sb == 0) {
				return Zero;
			}
		}

		/*
		 * Get both values in sign+magnitude representation.
		 */
		ToAbs(a, out sa, out ma);
		ToAbs(b, out sb, out mb);

		/*
		 * Compute the product. Set the sign.
		 */
		ZInt r = Make(0, Mul(ma, mb));
		if ((sa ^ sb) < 0) {
			r = -r;
		}
		return r;
	}

	/*
	 * Integer division: the quotient is returned, and the remainder
	 * is written in 'r'.
	 *
	 * This operation follows the C# rules for integer division:
	 * -- rounding is towards 0
	 * -- quotient is positive if dividend and divisor have the same
	 *    sign, negative otherwise
	 * -- remainder has the sign of the dividend
	 *
	 * Attempt at dividing by zero triggers a DivideByZeroException.
	 */
	public static ZInt DivRem(ZInt a, ZInt b, out ZInt r)
	{
		ZInt q;
		DivRem(a, b, out q, out r);
		return q;
	}

	static void DivRem(ZInt a, ZInt b,
		out ZInt q, out ZInt r)
	{
		int sa = a.small;
		int sb = b.small;
		uint[] ma = a.varray;
		uint[] mb = b.varray;

		/*
		 * Division by zero triggers an exception.
		 */
		if (mb == null && sb == 0) {
			throw new DivideByZeroException();
		}

		/*
		 * If the dividend is zero, then both quotient and
		 * remainder are zero.
		 */
		if (ma == null && sa == 0) {
			q = Zero;
			r = Zero;
			return;
		}

		/*
		 * If both dividend and divisor are small, then we
		 * use the native 64-bit integer types. If only the
		 * divisor is small, then we have a special fast case
		 * for division by 1 or -1.
		 */
		if (ma == null && mb == null) {
			q = new ZInt((long)sa / (long)sb);
			r = new ZInt((long)sa % (long)sb);
			return;
		}
		if (mb == null) {
			if (sb == 1) {
				q = a;
				r = Zero;
				return;
			} else if (sb == -1) {
				q = -a;
				r = Zero;
				return;
			}
		}

		/*
		 * We know that the dividend is not 0, and the divisor
		 * is not -1, 0 or 1. We now want the sign+magnitude
		 * representations of both operands.
		 */
		ToAbs(a, out sa, out ma);
		ToAbs(b, out sb, out mb);

		/*
		 * If the divisor is greater (in magnitude) than the
		 * dividend, then the quotient is zero and the remainder
		 * is equal to the dividend. If the divisor and dividend
		 * are equal in magnitude, then the remainder is zero and
		 * the quotient is 1 if divisor and dividend have the same
		 * sign, -1 otherwise.
		 */
		int cc = Compare(ma, mb);
		if (cc < 0) {
			q = Zero;
			r = a;
			return;
		} else if (cc == 0) {
			q = (sa == sb) ? One : MinusOne;
			r = Zero;
			return;
		}

		/*
		 * At that point, we know that the divisor is not -1, 0
		 * or 1, and that the quotient will not be 0. We perform
		 * the unsigned division (with the magnitudes), then
		 * we adjust the signs.
		 */

		uint[] mq, mr;
		DivRem(ma, mb, out mq, out mr);

		/*
		 * Quotient is positive if divisor and dividend have the
		 * same sign, negative otherwise. Remainder always has
		 * the sign of the dividend, but it may be zero.
		 */
		q = Make(0, mq);
		if (sa != sb) {
			q = -q;
		}
		r = Make(0, mr);
		if (sa < 0) {
			r = -r;
		}
#if DEBUG
		if (q * b + r != a) {
			throw new Exception("division error");
		}
#endif
	}

	/*
	 * Division operator: see DivRem() for details.
	 */
	public static ZInt operator /(ZInt a, ZInt b)
	{
		ZInt q, r;
		DivRem(a, b, out q, out r);
		return q;
	}

	/*
	 * Remainder operator: see DivRem() for details.
	 */
	public static ZInt operator %(ZInt a, ZInt b)
	{
		ZInt q, r;
		DivRem(a, b, out q, out r);
		return r;
	}

	/*
	 * Reduce this value modulo the provided m. This differs from
	 * '%' in that the returned value is always in the 0 to abs(m)-1
	 * range.
	 */
	public ZInt Mod(ZInt m)
	{
		ZInt r = this % m;
		if (r.small < 0) {
			if (m.small < 0) {
				m = -m;
			}
			r += m;
		}
		return r;
	}

	/*
	 * Left-shift operator.
	 */
	public static ZInt operator <<(ZInt a, int n)
	{
		if (n < 0) {
			if (n == Int32.MinValue) {
				return Zero;
			}
			return a >> (-n);
		}
		int sa = a.small;
		uint[] ma = a.varray;
		if (ma == null) {
			if (n <= 32) {
				return new ZInt((long)sa << n);
			}
			if (sa == 0) {
				return Zero;
			}
		}
		uint[] mr = new uint[GetLengthForLeftShift(a, n)];

		/*
		 * Special case when the shift is a multiple of 32.
		 */
		int kw = n >> 5;
		int kb = n & 31;
		if (kb == 0) {
			if (ma == null) {
				mr[kw] = (uint)sa;
				return new ZInt(sa >> 31, mr);
			} else {
				Array.Copy(ma, 0, mr, kw, ma.Length);
				return new ZInt(sa, mr);
			}
		}

		/*
		 * At that point, we know that the source integer does
		 * not fit in a signed "int", or is shifted by more than
		 * 32 bits, or both. Either way, the result will not fit
		 * in an "int".
		 *
		 * We process all input words one by one.
		 */
		uint rem = 0;
		int ikb = 32 - kb;
		int j;
		if (ma == null) {
			j = 1;
			uint wa = (uint)sa;
			mr[kw] = wa << kb;
			rem = wa >> ikb;
		} else {
			j = ma.Length;
			for (int i = 0; i < j; i ++) {
				uint wa = ma[i];
				mr[i + kw] = rem | (wa << kb);
				rem = wa >> ikb;
			}
		}
		sa >>= 31;
#if DEBUG
		if ((j + kw) == mr.Length - 1) {
			if (rem == ((uint)sa >> ikb)) {
				throw new Exception(
					"Wrong left-shift: untrimmed");
			}
		} else if ((j + kw) == mr.Length) {
			if (rem != ((uint)sa >> ikb)) {
				throw new Exception(
					"Wrong left-shift: dropped bits");
			}
		} else {
			throw new Exception(
				"Wrong left-shift: oversized output length");
		}
#endif
		if ((j + kw) < mr.Length) {
			mr[j + kw] = rem | ((uint)sa << kb);
		}
		return new ZInt(sa, mr);
	}

	/*
	 * Right-shift operator.
	 */
	public static ZInt operator >>(ZInt a, int n)
	{
		if (n < 0) {
			if (n == Int32.MinValue) {
				throw new OverflowException();
			}
			return a << (-n);
		}
		int sa = a.small;
		uint[] ma = a.varray;
		if (ma == null) {
			/*
			 * If right-shifting a "small" value, then we can
			 * do the computation with the native ">>" operator
			 * on "int" values, unless the shift count is 32
			 * or more, in which case we get either 0 or -1,
			 * depending on the source value sign.
			 */
			if (n < 32) {
				return new ZInt(sa >> n, null);
			} else {
				return new ZInt(sa >> 31, null);
			}
		}

		/*
		 * At that point, we know that the source value uses
		 * a non-null varray. We compute the bit length of the
		 * result. If the result would fit in an "int" (bit length
		 * of 31 or less) then we handle it as a special case.
		 */
		int kw = n >> 5;
		int kb = n & 31;
		int bl = a.BitLength - n;
		if (bl <= 0) {
			return new ZInt(sa, null);
		} else if (bl <= 31) {
			if (kb == 0) {
				return new ZInt((int)ma[kw], null);
			} else {
				int p = ma.Length;
				uint w0 = ma[kw];
				uint w1 = (kw + 1) < p ? ma[kw + 1] : (uint)sa;
				return new ZInt((int)((w0 >> kb)
					| (w1 << (32 - kb))), null);
			}
		}

		/*
		 * Result will require an array. Let's allocate it.
		 */
		uint[] mr = new uint[(bl + 31) >> 5];

		/*
		 * Special case when the shift is a multiple of 32.
		 */
		if (kb == 0) {
#if DEBUG
			if (mr.Length != (ma.Length - kw)) {
				throw new Exception(
					"Wrong right-shift: output length");
			}
#endif
			Array.Copy(ma, kw, mr, 0, ma.Length - kw);
			return new ZInt(sa, mr);
		}

		/*
		 * We process all input words one by one.
		 */
		int ikb = 32 - kb;
		uint rem = ma[kw] >> kb;
		int j = ma.Length;
		for (int i = kw + 1; i < j; i ++) {
			uint wa = ma[i];
			mr[i - kw - 1] = rem | (wa << ikb);
			rem = wa >> kb;
		}
#if DEBUG
		if ((j - kw - 1) == mr.Length - 1) {
			if (rem == ((uint)sa >> kb)) {
				throw new Exception(
					"Wrong right-shift: untrimmed");
			}
		} else if ((j - kw - 1) == mr.Length) {
			if (rem != ((uint)sa >> kb)) {
				throw new Exception(
					"Wrong right-shift: dropped bits");
			}
		} else {
			throw new Exception(
				"Wrong right-shift: oversized output length");
		}
#endif
		if ((j - kw - 1) < mr.Length) {
			mr[j - kw - 1] = rem | ((uint)sa << ikb);
		}
		return new ZInt(sa, mr);
	}

	/*
	 * NOTES ON BITWISE BOOLEAN OPERATIONS
	 *
	 * When both operands are "small" then the result is necessarily
	 * small: in "small" encoding, all bits beyond bit 31 of the
	 * two's complement encoding are equal to bit 31, so the result
	 * of computing the operation on bits 31 will also be valid for
	 * all subsequent bits. Therefore, when the two operands are
	 * small, we can just do the operation on the "int" values and the
	 * result is guaranteed "small" as well.
	 */

	/*
	 * Compute the bitwise AND between a "big" and a "small" values.
	 */
	static ZInt AndSmall(int s, uint[] m, int x)
	{
		if (x < 0) {
			uint[] r = Dup(m);
			r[0] &= (uint)x;
			return new ZInt(s, r);
		} else {
			return new ZInt(x & (int)m[0], null);
		}
	}

	/*
	 * Bitwise AND operator.
	 */
	public static ZInt operator &(ZInt a, ZInt b)
	{
		int sa = a.small;
		int sb = b.small;
		uint[] ma = a.varray;
		uint[] mb = b.varray;
		if (ma == null) {
			if (mb == null) {
				return new ZInt(sa & sb, null);
			} else {
				return AndSmall(sb, mb, sa);
			}
		} else if (mb == null) {
			return AndSmall(sa, ma, sb);
		}

		/*
		 * Both values are big. Since upper zero bits force the
		 * result to contain zeros, the result size is that of the
		 * positive operand (the smallest of the two if both are
		 * positive). If both operands are negative, then the
		 * result magnitude may be as large as the largest of the
		 * two source magnitudes.
		 *
		 * Result is negative if and only if both operands are
		 * negative.
		 */
		int na = ma.Length;
		int nb = mb.Length;
		int nr;
		if (sa >= 0) {
			if (sb >= 0) {
				nr = Math.Min(na, nb);
			} else {
				nr = na;
			}
		} else {
			if (sb >= 0) {
				nr = nb;
			} else {
				nr = Math.Max(na, nb);
			}
		}
		uint[] mr = new uint[nr];
		for (int i = 0; i < nr; i ++) {
			uint wa = i < na ? ma[i] : (uint)sa;
			uint wb = i < nb ? mb[i] : (uint)sb;
			mr[i] = wa & wb;
		}
		return Make(sa & sb, mr);
	}

	/*
	 * Compute the bitwise OR between a "big" value (sign and
	 * magnitude, already normalized/trimmed), and a small value
	 * (which can be positive or negative).
	 */
	static ZInt OrSmall(int s, uint[] m, int x)
	{
		if (x < 0) {
			return new ZInt(x | (int)m[0], null);
		} else {
			uint[] r = Dup(m);
			r[0] |= (uint)x;
			return new ZInt(s, r);
		}
	}

	/*
	 * Bitwise OR operator.
	 */
	public static ZInt operator |(ZInt a, ZInt b)
	{
		int sa = a.small;
		int sb = b.small;
		uint[] ma = a.varray;
		uint[] mb = b.varray;
		if (ma == null) {
			if (mb == null) {
				return new ZInt(sa | sb, null);
			} else {
				return OrSmall(sb, mb, sa);
			}
		} else if (mb == null) {
			return OrSmall(sa, ma, sb);
		}

		/*
		 * Both values are big. Since upper one bits force the
		 * result to contain ones, the result size is that of
		 * the negative operand (the greater, i.e. "smallest" of
		 * the two if both are negative). If both operands are
		 * positive, then the result magnitude may be as large
		 * as the largest of the two source magnitudes.
		 *
		 * Result is positive if and only if both operands are
		 * positive.
		 */
		int na = ma.Length;
		int nb = mb.Length;
		int nr;
		if (sa >= 0) {
			if (sb >= 0) {
				nr = Math.Max(na, nb);
			} else {
				nr = nb;
			}
		} else {
			if (sb >= 0) {
				nr = na;
			} else {
				nr = Math.Min(na, nb);
			}
		}
		uint[] mr = new uint[nr];
		for (int i = 0; i < nr; i ++) {
			uint wa = i < na ? ma[i] : (uint)sa;
			uint wb = i < nb ? mb[i] : (uint)sb;
			mr[i] = wa | wb;
		}
		return Make(sa | sb, mr);
	}

	/*
	 * Bitwise XOR operator.
	 */
	public static ZInt operator ^(ZInt a, ZInt b)
	{
		int sa = a.small;
		int sb = b.small;
		uint[] ma = a.varray;
		uint[] mb = b.varray;
		if (ma == null && mb == null) {
			return new ZInt(sa ^ sb, null);
		}
		if (ma == null) {
			int st = sa;
			sa = sb;
			sb = st;
			uint[] mt = ma;
			ma = mb;
			mb = mt;
		}
		if (mb == null) {
			int nx = ma.Length;
			uint[] mx = new uint[nx];
			mx[0] = ma[0] ^ (uint)sb;
			if (nx > 1) {
				if (sb < 0) {
					for (int i = 1; i < nx; i ++) {
						mx[i] = ~ma[i];
					}
				} else {
					Array.Copy(ma, 1, mx, 1, nx - 1);
				}
			}
			return Make(sa ^ (sb >> 31), mx);
		}

		/*
		 * Both operands use varrays.
		 * Result can be as big as the bigger of the two operands
		 * (it _will_ be that big, necessarily, if the two operands
		 * have distinct sizes).
		 */
		int na = ma.Length;
		int nb = mb.Length;
		int nr = Math.Max(na, nb);
		uint[] mr = new uint[nr];
		for (int i = 0; i < nr; i ++) {
			uint wa = i < na ? ma[i] : (uint)sa;
			uint wb = i < nb ? mb[i] : (uint)sb;
			mr[i] = wa ^ wb;
		}
		return Make((sa ^ sb) >> 31, mr);
	}

	/*
	 * Bitwise inversion operator.
	 */
	public static ZInt operator ~(ZInt a)
	{
		int s = a.small;
		uint[] m = a.varray;
		if (m == null) {
			return new ZInt(~s, null);
		} else {
			int n = m.Length;
			uint[] r = new uint[n];
			for (int i = 0; i < n; i ++) {
				r[i] = ~m[i];
			}
			return new ZInt(~s, r);
		}
	}

	/*
	 * Basic comparison; returned value is -1, 0 or 1 depending on
	 * whether this instance is to be considered lower then, equal
	 * to, or greater than the provided object.
	 *
	 * All ZInt instances are considered greater than 'null', and
	 * lower than any non-null object that is not a ZInt.
	 */
	public int CompareTo(object obj)
	{
		if (obj == null) {
			return 1;
		}
		if (!(obj is ZInt)) {
			return -1;
		}
		return CompareTo((ZInt)obj);
	}

	/*
	 * Basic comparison; returned value is -1, 0 or 1 depending on
	 * whether this instance is to be considered lower then, equal
	 * to, or greater than the provided value.
	 */
	public int CompareTo(ZInt v)
	{
		int sv = v.small;
		uint[] mv = v.varray;
		int sign1 = small >> 31;
		int sign2 = sv >> 31;
		if (sign1 != sign2) {
			/*
			 * One of the sign* values is -1, the other is 0.
			 */
			return sign1 - sign2;
		}

		/*
		 * Both values have the same sign. Since the varrays are
		 * trimmed, we can use their presence and length to
		 * quickly resolve most cases.
		 */
		if (small < 0) {
			if (varray == null) {
				if (mv == null) {
					return Compare(small, sv);
				} else {
					return 1;
				}
			} else {
				if (mv == null) {
					return -1;
				} else {
					int n1 = varray.Length;
					int n2 = mv.Length;
					if (n1 < n2) {
						return 1;
					} else if (n1 == n2) {
						return Compare(varray, mv);
					} else {
						return -1;
					}
				}
			}
		} else {
			if (varray == null) {
				if (mv == null) {
					return Compare(small, sv);
				} else {
					return -1;
				}
			} else {
				if (mv == null) {
					return 1;
				} else {
					return Compare(varray, mv);
				}
			}
		}
	}

	/*
	 * Equality comparison: a ZInt instance is equal only to another
	 * ZInt instance that encodes the same integer value.
	 */
	public override bool Equals(object obj)
	{
		if (obj == null) {
			return false;
		}
		if (!(obj is ZInt)) {
			return false;
		}
		return CompareTo((ZInt)obj) == 0;
	}

	/*
	 * Equality comparison: a ZInt instance is equal only to another
	 * ZInt instance that encodes the same integer value.
	 */
	public bool Equals(ZInt v)
	{
		return CompareTo(v) == 0;
	}

	/*
	 * The hash code for a ZInt is equal to its lower 32 bits.
	 */
	public override int GetHashCode()
	{
		if (varray == null) {
			return small;
		} else {
			return (int)varray[0];
		}
	}

	/*
	 * Equality operator.
	 */
	public static bool operator ==(ZInt a, ZInt b)
	{
		return a.CompareTo(b) == 0;
	}

	/*
	 * Inequality operator.
	 */
	public static bool operator !=(ZInt a, ZInt b)
	{
		return a.CompareTo(b) != 0;
	}

	/*
	 * Lower-than operator.
	 */
	public static bool operator <(ZInt a, ZInt b)
	{
		return a.CompareTo(b) < 0;
	}

	/*
	 * Lower-or-equal operator.
	 */
	public static bool operator <=(ZInt a, ZInt b)
	{
		return a.CompareTo(b) <= 0;
	}

	/*
	 * Greater-than operator.
	 */
	public static bool operator >(ZInt a, ZInt b)
	{
		return a.CompareTo(b) > 0;
	}

	/*
	 * Greater-or-equal operator.
	 */
	public static bool operator >=(ZInt a, ZInt b)
	{
		return a.CompareTo(b) >= 0;
	}

	/*
	 * Power function: this raises x to the power e. The exponent e
	 * MUST NOT be negative. If x and e are both zero, then 1 is
	 * returned.
	 */
	public static ZInt Pow(ZInt x, int e)
	{
		if (e < 0) {
			throw new ArgumentOutOfRangeException();
		}
		if (e == 0) {
			return One;
		}
		if (e == 1 || x.IsZero || x.IsOne) {
			return x;
		}
		bool neg = false;
		if (x.Sign < 0) {
			x = -x;
			neg = (e & 1) != 0;
		}
		if (x.IsPowerOfTwo) {
			int t = x.BitLength - 1;
			long u = (long)t * (long)e;
			if (u > (long)Int32.MaxValue) {
				throw new OverflowException();
			}
			x = One << (int)u;
		} else {
			ZInt y = One;
			for (;;) {
				if ((e & 1) != 0) {
					y *= x;
				}
				e >>= 1;
				if (e == 0) {
					break;
				}
				x *= x;
			}
			x = y;
		}
		return neg ? -x : x;
	}

	/*
	 * Modular exponentation: this function raises v to the power e
	 * modulo m. The returned value is reduced modulo m: it will be
	 * in the 0 to abs(m)-1 range.
	 *
	 * The modulus m must be positive. If m is 1, then the result is
	 * 0 (regardless of the values of v and e).
	 *
	 * The exponent e must be nonnegative (this function does not
	 * compute modular inverses). If e is zero, then the result is 1
	 * (except if m is 1).
	 */
	public static ZInt ModPow(ZInt v, ZInt e, ZInt m)
	{
		int se = e.Sign;
		if (se < 0) {
			throw new ArgumentOutOfRangeException();
		}
		int sm = m.Sign;
		if (sm < 0) {
			m = -m;
		} else if (sm == 0) {
			throw new DivideByZeroException();
		}
		if (m.varray == null && m.small == 1) {
			return Zero;
		}
		if (se == 0) {
			return One;
		}
		if (v.IsZero) {
			return Zero;
		}

		// TODO: use Montgomery's multiplication when the exponent
		// is large.
		ZInt x = v.Mod(m);
		for (int n = e.BitLength - 2; n >= 0; n --) {
			x = (x * x).Mod(m);
			if (e.TestBit(n)) {
				x = (x * v).Mod(m);
			}
		}
		return x;
	}

	/*
	 * Get the absolute value of a ZInt.
	 */
	public static ZInt Abs(ZInt x)
	{
		return (x.Sign < 0) ? -x : x;
	}

	private static void AppendHex(StringBuilder sb, uint w, bool trim)
	{
		int i = 28;
		if (trim) {
			for (; i >= 0 && (w >> i) == 0; i -= 4);
			if (i < 0) {
				sb.Append("0");
				return;
			}
		}
		for (; i >= 0; i -= 4) {
			sb.Append("0123456789ABCDEF"[(int)((w >> i) & 0x0F)]);
		}
	}

	/*
	 * Convert this value to hexadecimal. If this instance is zero,
	 * then "0" is returned. Otherwise, the number of digits is
	 * minimal (no leading '0'). A leading '-' is used for negative
	 * values. Hexadecimal digits are uppercase.
	 */
	public string ToHexString()
	{
		if (varray == null && small == 0) {
			return "0";
		}
		StringBuilder sb = new StringBuilder();
		ZInt x = this;
		if (x.small < 0) {
			sb.Append('-');
			x = -x;
		}
		if (x.varray == null) {
			AppendHex(sb, (uint)x.small, true);
		} else {
			int n = x.varray.Length;
			AppendHex(sb, x.varray[n - 1], true);
			for (int j = n - 2; j >= 0; j --) {
				AppendHex(sb, x.varray[j], false);
			}
		}
		return sb.ToString();
	}

	/*
	 * Convert this value to decimal. A leading '-' sign is used for
	 * negative value. The number of digits is minimal (no leading '0',
	 * except for zero, which is returned as "0").
	 */
	public override string ToString()
	{
		return ToString(10);
	}

	private static int[] NDIGITS32 = {
		0, 0, 31, 20, 15, 13, 12, 11, 10, 10, 9, 9, 8, 8, 8, 8, 7, 7,
		7, 7, 7, 7, 7, 7, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6
	};

	private static uint[] RADIXPP32 = {
		0, 0, 2147483648, 3486784401, 1073741824, 1220703125,
		2176782336, 1977326743, 1073741824, 3486784401, 1000000000,
		2357947691, 429981696, 815730721, 1475789056, 2562890625,
		268435456, 410338673, 612220032, 893871739, 1280000000,
		1801088541, 2494357888, 3404825447, 191102976, 244140625,
		308915776, 387420489, 481890304, 594823321, 729000000,
		887503681, 1073741824, 1291467969, 1544804416, 1838265625,
		2176782336
	};

	private static char[] DCHAR =
		"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();

	static void AppendDigits(StringBuilder sb, uint v, int radix, int num)
	{
		while (num -- > 0) {
			sb.Append(DCHAR[v % (uint)radix]);
			v = v / (uint)radix;
		}
	}

	static void AppendDigits(StringBuilder sb, uint v, int radix)
	{
		while (v > 0) {
			sb.Append(DCHAR[v % (uint)radix]);
			v = v / (uint)radix;
		}
	}

	/*
	 * Convert this value to a string, in the provided radix. The
	 * radix must be in the 2 to 36 range (inclusive); uppercase
	 * letters 'A' to 'Z' are used for digits of value 10 to 35.
	 * If the value is zero, then "0" is returned; otherwise, leading
	 * '0' digits are removed. A leading '-' sign is added for negative
	 * values.
	 */
	public string ToString(int radix)
	{
		if (radix < 2 || radix > 36) {
			throw new ArgumentOutOfRangeException();
		}

		/*
		 * Special optimized case for base 16.
		 */
		if (radix == 16) {
			return ToHexString();
		}

		if (IsZero) {
			return "0";
		}

		ZInt x = this;
		if (x.Sign < 0) {
			x = -x;
		}
		StringBuilder sb = new StringBuilder();
		if (x.varray == null) {
			AppendDigits(sb, (uint)x.small, radix);
		} else {
			uint[] m = new uint[x.varray.Length];
			Array.Copy(x.varray, 0, m, 0, m.Length);
			uint prad = RADIXPP32[radix];
			int dnum = NDIGITS32[radix];
			for (;;) {
				uint v = MutateDivRem(m, prad);
				bool qz = Length(0, m) == 0;
				if (qz) {
					AppendDigits(sb, v, radix);
					break;
				} else {
					AppendDigits(sb, v, radix, dnum);
				}
			}
		}
		if (Sign < 0) {
			sb.Append('-');
		}
		return Reverse(sb);
	}

	static string Reverse(StringBuilder sb)
	{
		int n = sb.Length;
		char[] tc = new char[n];
		sb.CopyTo(0, tc, 0, n);
		for (int i = 0, j = n - 1; i < j; i ++, j --) {
			char c = tc[i];
			tc[i] = tc[j];
			tc[j] = c;
		}
		return new string(tc);
	}

	static uint DigitValue(char c, int radix)
	{
		int d;
		if (c >= '0' && c <= '9') {
			d = c - '0';
		} else if (c >= 'a' && c <= 'z') {
			d = (c - 'a') + 10;
		} else if (c >= 'A' && c <= 'Z') {
			d = (c - 'A') + 10;
		} else {
			d = -1;
		}
		if (d < 0 || d >= radix) {
			throw new ArgumentException();
		}
		return (uint)d;
	}

	static ZInt ParseUnsigned(string s, int radix)
	{
		if (s.Length == 0) {
			throw new ArgumentException();
		}
		ZInt x = Zero;
		uint acc = 0;
		int accNum = 0;
		uint prad = RADIXPP32[radix];
		int dnum = NDIGITS32[radix];
		foreach (char c in s) {
			uint d = DigitValue(c, radix);
			acc = acc * (uint)radix + d;
			if (++ accNum == dnum) {
				x = x * (ZInt)prad + (ZInt)acc;
				acc = 0;
				accNum = 0;
			}
		}
		if (accNum > 0) {
			uint p = 1;
			while (accNum -- > 0) {
				p *= (uint)radix;
			}
			x = x * (ZInt)p + (ZInt)acc;
		}
		return x;
	}

	/*
	 * Parse a string:
	 * -- A leading '-' is allowed, to denote a negative value.
	 * -- If there is a "0b" or "0B" header (after any '-' sign),
	 *    then the value is interpreted in base 2.
	 * -- If there is a "0x" or "0X" header (after any '-' sign),
	 *    then the value is interpreted in base 16 (hexadecimal).
	 *    Both uppercase and lowercase letters are accepted.
	 * -- If there is no header, then decimal interpretation is used.
	 *
	 * Unexpected characters (including spaces) trigger exceptions.
	 * There must be at least one digit.
	 */
	public static ZInt Parse(string s)
	{
		s = s.Trim();
		bool neg = false;
		if (s.StartsWith("-")) {
			neg = true;
			s = s.Substring(1);
		}
		int radix;
		if (s.StartsWith("0b") || s.StartsWith("0B")) {
			radix = 2;
			s = s.Substring(2);
		} else if (s.StartsWith("0x") || s.StartsWith("0X")) {
			radix = 16;
			s = s.Substring(2);
		} else {
			radix = 10;
		}
		ZInt x = ParseUnsigned(s, radix);
		return neg ? -x : x;
	}

	/*
	 * Parse a string in the specified radix. The radix must be in
	 * the 2 to 36 range (inclusive). Uppercase and lowercase letters
	 * are accepted for digits in the 10 to 35 range.
	 *
	 * A leading '-' sign is allowed, to denote a negative value.
	 * Otherwise, only digits (acceptable with regards to the radix)
	 * may appear. There must be at least one digit.
	 */
	public static ZInt Parse(string s, int radix)
	{
		if (radix < 2 || radix > 36) {
			throw new ArgumentOutOfRangeException();
		}
		s = s.Trim();
		bool neg = false;
		if (s.StartsWith("-")) {
			neg = true;
			s = s.Substring(1);
		}
		ZInt x = ParseUnsigned(s, radix);
		return neg ? -x : x;
	}

	static uint DecU32BE(byte[] buf, int off, int len)
	{
		switch (len) {
		case 0:
			return 0;
		case 1:
			return buf[off];
		case 2:
			return ((uint)buf[off] << 8)
				| (uint)buf[off + 1];
		case 3:
			return ((uint)buf[off] << 16)
				| ((uint)buf[off + 1] << 8)
				| (uint)buf[off + 2];
		default:
			return ((uint)buf[off] << 24)
				| ((uint)buf[off + 1] << 16)
				| ((uint)buf[off + 2] << 8)
				| (uint)buf[off + 3];
		}
	}

	/*
	 * Decode an integer, assuming unsigned big-endian encoding.
	 * An empty array is decoded as 0.
	 */
	public static ZInt DecodeUnsignedBE(byte[] buf)
	{
		return DecodeUnsignedBE(buf, 0, buf.Length);
	}

	/*
	 * Decode an integer, assuming unsigned big-endian encoding.
	 * An empty array is decoded as 0.
	 */
	public static ZInt DecodeUnsignedBE(byte[] buf, int off, int len)
	{
		while (len > 0 && buf[off] == 0) {
			off ++;
			len --;
		}
		if (len == 0) {
			return Zero;
		} else if (len <= 4) {
			return new ZInt(DecU32BE(buf, off, len));
		}
		uint[] m = new uint[(len + 3) >> 2];
		int i = 0;
		for (int j = len; j > 0; j -= 4) {
			int k = j - 4;
			uint w;
			if (k < 0) {
				w = DecU32BE(buf, off, j);
			} else {
				w = DecU32BE(buf, off + k, 4);
			}
			m[i ++] = w;
		}
		return new ZInt(0, m);
	}

	static RNGCryptoServiceProvider RNG = new RNGCryptoServiceProvider();

	/*
	 * Create a random integer of the provided size. Returned value
	 * is in the 0 (inclusive) to 2^size (exclusive) range. A
	 * cryptographically strong RNG is used to ensure uniform selection.
	 */
	public static ZInt MakeRand(int size)
	{
		if (size <= 0) {
			throw new ArgumentOutOfRangeException();
		}
		byte[] buf = new byte[(size + 7) >> 3];
		RNG.GetBytes(buf);
		int kb = size & 7;
		if (kb != 0) {
			buf[0] &= (byte)(0xFF >> (8 - kb));
		}
		return DecodeUnsignedBE(buf);
	}

	/*
	 * Create a random integer in the 0 (inclusive) to max (exclusive)
	 * range. 'max' must be positive. A cryptographically strong RNG
	 * is used to ensure uniform selection.
	 */
	public static ZInt MakeRand(ZInt max)
	{
		if (max.Sign <= 0) {
			throw new ArgumentOutOfRangeException();
		}
		int bl = max.BitLength;
		for (;;) {
			ZInt x = MakeRand(bl);
			if (x < max) {
				return x;
			}
		}
	}

	/*
	 * Create a random integer in the min (inclusive) to max (exclusive)
	 * range. 'max' must be greater than min. A cryptographically
	 * strong RNG is used to ensure uniform selection.
	 */
	public static ZInt MakeRand(ZInt min, ZInt max)
	{
		if (max <= min) {
			throw new ArgumentOutOfRangeException();
		}
		return min + MakeRand(max - min);
	}

	/*
	 * Check whether this integer is prime. A probabilistic algorithm
	 * is used, that theoretically ensures that a non-prime won't be
	 * declared prime with probability greater than 2^(-100). Note that
	 * this holds regardless of how the integer was generated (this
	 * method does not assume that uniform random selection was used).
	 *
	 * (Realistically, the probability of a computer hardware
	 * malfunction is way greater than 2^(-100), so this property
	 * returns the primality status with as much certainty as can be
	 * achieved with a computer.)
	 */
	public bool IsPrime {
		get {
			return IsProbablePrime(50);
		}
	}

	static uint[] PRIMES_BF = new uint[] {
		0xA08A28AC, 0x28208A20, 0x02088288, 0x800228A2,
		0x20A00A08, 0x80282088, 0x800800A2, 0x08028228,
		0x0A20A082, 0x22880020, 0x28020800, 0x88208082,
		0x02022020, 0x08828028, 0x8008A202, 0x20880880
	};

	private bool IsProbablePrime(int rounds)
	{
		ZInt x = this;
		int cc = x.Sign;
		if (cc == 0) {
			return false;
		} else if (cc < 0) {
			x = -x;
		}
		if (x.varray == null) {
			if (x.small < (PRIMES_BF.Length << 5)) {
				return (PRIMES_BF[x.small >> 5]
					& ((uint)1 << (x.small & 31))) != 0;
			}
		}
		if (!x.TestBit(0)) {
			return false;
		}

		ZInt xm1 = x;
		xm1 --;
		ZInt m = xm1;
		int a;
		for (a = 0; !m.TestBit(a); a ++);
		m >>= a;
		while (rounds -- > 0) {
			ZInt b = MakeRand(Two, x);
			ZInt z = ModPow(b, m, x);
			for (int j = 0; j < a; j ++) {
				if (z == One) {
					if (j > 0) {
						return false;
					}
					break;
				}
				if (z == xm1) {
					break;
				}
				if ((j + 1) < a) {
					z = (z * z) % x;
				} else {
					return false;
				}
			}
		}
		return true;
	}

	/*
	 * Encode this integer as bytes (signed big-endian convention).
	 * Encoding is of minimal length that still contains a sign bit
	 * (compatible with ASN.1 DER encoding).
	 */
	public byte[] ToBytesBE()
	{
		byte[] r = new byte[(BitLength + 8) >> 3];
		ToBytesBE(r, 0, r.Length);
		return r;
	}

	/*
	 * Encode this integer as bytes (signed little-endian convention).
	 * Encoding is of minimal length that still contains a sign bit.
	 */
	public byte[] ToBytesLE()
	{
		byte[] r = new byte[(BitLength + 8) >> 3];
		ToBytesLE(r, 0, r.Length);
		return r;
	}

	/*
	 * Encode this integer as bytes (signed big-endian convention).
	 * Output length is provided; exactly that many bytes will be
	 * written. The value is sign-extended or truncated if needed.
	 */
	public void ToBytesBE(byte[] buf, int off, int len)
	{
		ToBytes(true, buf, off, len);
	}

	/*
	 * Encode this integer as bytes (signed little-endian convention).
	 * Output length is provided; exactly that many bytes will be
	 * written. The value is sign-extended or truncated if needed.
	 */
	public void ToBytesLE(byte[] buf, int off, int len)
	{
		ToBytes(false, buf, off, len);
	}

	/*
	 * Encode this integer as bytes (unsigned big-endian convention).
	 * Encoding is of minimal length, possibly without a sign bit. If
	 * this value is zero, then an empty array is returned. If this
	 * value is negative, then an ArgumentOutOfRangeException is thrown.
	 */
	public byte[] ToBytesUnsignedBE()
	{
		if (Sign < 0) {
			throw new ArgumentOutOfRangeException();
		}
		byte[] r = new byte[(BitLength + 7) >> 3];
		ToBytesBE(r, 0, r.Length);
		return r;
	}

	/*
	 * Encode this integer as bytes (unsigned little-endian convention).
	 * Encoding is of minimal length, possibly without a sign bit. If
	 * this value is zero, then an empty array is returned. If this
	 * value is negative, then an ArgumentOutOfRangeException is thrown.
	 */
	public byte[] ToBytesUnsignedLE()
	{
		if (Sign < 0) {
			throw new ArgumentOutOfRangeException();
		}
		byte[] r = new byte[(BitLength + 7) >> 3];
		ToBytesLE(r, 0, r.Length);
		return r;
	}

	void ToBytes(bool be, byte[] buf, int off, int len)
	{
		uint iw = (uint)small >> 31;
		for (int i = 0; i < len; i ++) {
			int j = i >> 2;
			uint w;
			if (varray == null) {
				w = (j == 0) ? (uint)small : iw;
			} else {
				w = (j < varray.Length) ? varray[j] : iw;
			}
			byte v = (byte)(w >> ((i & 3) << 3));
			if (be) {
				buf[off + len - 1 - i] = v;
			} else {
				buf[off + i] = v;
			}
		}
	}
}
