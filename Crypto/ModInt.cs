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
 * Mutable container for a modular integer.
 *
 * Rules:
 *
 *   - Each instance is initialised over a given modulus, or by
 *     duplicating an existing instance.
 *
 *   - All operands for a given operation must share the same modulus,
 *     i.e. the instances must have been created with Dup() calls from
 *     a common ancestor.
 *
 *   - Modulus must be odd and greater than 1.
 */

public class ModInt {

	/*
	 * Dedicated class for a modulus. It maintains some useful
	 * values that depend only on the modulus.
	 */
	class ZMod {

		/*
		 * val = modulus value, 31 bits per word, little-endian
		 * bitLen = modulus bit length (exact)
		 * n0i is such that n0i * val[0] == -1 mod 2^31
		 * R = 2^(31*val.Length) (modular)
		 * R2 = 2^(31*(val.Length*2)) (modular)
		 * Rx[i] = 2^(31*(val.Length+(2^i))) (modular)
		 */
		internal uint[] val;
		internal int bitLen;
		internal uint n0i;
		internal uint[] R;
		internal uint[] R2;
		internal uint[][] Rx;
		internal byte[] vm2;

		internal ZMod(byte[] bmod, int off, int len)
		{
			bitLen = BigInt.BitLength(bmod, off, len);
			if (bitLen <= 1 || (bmod[off + len - 1] & 1) == 0) {
				throw new CryptoException("invalid modulus");
			}
			int n = (bitLen + 30) / 31;
			val = new uint[n];
			DecodeBE(bmod, off, len, val);
			uint x = val[0];
			uint y = 2 - x;
			y *= 2 - y * x;
			y *= 2 - y * x;
			y *= 2 - y * x;
			y *= 2 - y * x;
			n0i = (1 + ~y) & 0x7FFFFFFF;

			/*
			 * Compute the Rx[] values.
			 */
			int zk = 0;
			while ((n >> zk) != 0) {
				zk ++;
			}
			R = new uint[n];
			R[n - 1] = 1;
			for (int i = 0; i < 31; i ++) {
				ModMul2(R, val);
			}
			Rx = new uint[zk][];
			Rx[0] = new uint[n];
			Array.Copy(R, 0, Rx[0], 0, n);
			for (int i = 0; i < 31; i ++) {
				ModMul2(Rx[0], val);
			}
			for (int k = 1; k < zk; k ++) {
				Rx[k] = new uint[n];
				MontyMul(Rx[k - 1], Rx[k - 1], Rx[k], val, n0i);
			}

			/*
			 * Compute R2 by multiplying the relevant Rx[]
			 * values.
			 */
			R2 = null;
			uint[] tt = new uint[n];
			for (int k = 0; k < zk; k ++) {
				if (((n >> k) & 1) == 0) {
					continue;
				}
				if (R2 == null) {
					R2 = new uint[n];
					Array.Copy(Rx[k], 0, R2, 0, n);
				} else {
					MontyMul(Rx[k], R2, tt, val, n0i);
					Array.Copy(tt, 0, R2, 0, n);
				}
			}

			/*
			 * Compute N-2; used as an exponent for modular
			 * inversion. Since modulus N is odd and greater
			 * than 1, N-2 is necessarily positive.
			 */
			vm2 = new byte[(bitLen + 7) >> 3];
			int cc = 2;
			for (int i = 0; i < vm2.Length; i ++) {
				int b = bmod[off + len - 1 - i];
				b -= cc;
				vm2[vm2.Length - 1 - i] = (byte)b;
				cc = (b >> 8) & 1;
			}
		}
	}

	ZMod mod;
	uint[] val;
	uint[] tmp1, tmp2;

	/*
	 * Get the modulus bit length.
	 */
	public int ModBitLength {
		get {
			return mod.bitLen;
		}
	}

	/*
	 * Test whether this value is zero.
	 */
	public bool IsZero {
		get {
			return IsZeroCT != 0;
		}
	}

	public uint IsZeroCT {
		get {
			int z = (int)val[0];
			for (int i = 1; i < val.Length; i ++) {
				z |= (int)val[i];
			}
			return ~(uint)((z | -z) >> 31);
		}
	}

	/*
	 * Test whether this value is one.
	 */
	public bool IsOne {
		get {
			return IsOneCT != 0;
		}
	}

	public uint IsOneCT {
		get {
			int z = (int)val[0] ^ 1;
			for (int i = 1; i < val.Length; i ++) {
				z |= (int)val[i];
			}
			return ~(uint)((z | -z) >> 31);
		}
	}

	ModInt(ZMod m)
	{
		Init(m);
	}

	/*
	 * Create a new instance by decoding the provided modulus
	 * (unsigned big-endian). Value is zero.
	 */
	public ModInt(byte[] modulus)
		: this(modulus, 0, modulus.Length)
	{
	}

	/*
	 * Create a new instance by decoding the provided modulus
	 * (unsigned big-endian). Value is zero.
	 */
	public ModInt(byte[] modulus, int off, int len)
	{
		Init(new ZMod(modulus, off, len));
	}

	void Init(ZMod mod)
	{
		this.mod = mod;
		int n = mod.val.Length;
		val = new uint[n];
		tmp1 = new uint[n];
		tmp2 = new uint[n];
	}

	/*
	 * Duplicate this instance. The new instance uses the same
	 * modulus, and its value is initialized to the same value as
	 * this instance.
	 */
	public ModInt Dup()
	{
		ModInt m = new ModInt(mod);
		Array.Copy(val, 0, m.val, 0, val.Length);
		return m;
	}

	/*
	 * Set the value in this instance to a copy of the value in
	 * the provided instance. The 'm' instance may use a different
	 * modulus, in which case the value may incur modular reduction.
	 */
	public void Set(ModInt m)
	{
		/*
		 * If the instances use the same modulus array, then
		 * the value can simply be copied as is.
		 */
		if (mod == m.mod) {
			Array.Copy(m.val, 0, val, 0, val.Length);
			return;
		}
		Reduce(m.val);
	}

	/*
	 * Set the value in this instance to a copy of the value in
	 * the provided instance, but do so only conditionally. If
	 * 'ctl' is -1, then the copy is done. If 'ctl' is 0, then the
	 * copy is NOT done. This instance and the source instance
	 * MUST use the same modulus.
	 */
	public void CondCopy(ModInt m, uint ctl)
	{
		if (mod != m.mod) {
			throw new CryptoException("Not same modulus");
		}
		for (int i = 0; i < val.Length; i ++) {
			uint w = val[i];
			val[i] = w ^ (ctl & (m.val[i] ^ w));
		}
	}

	/*
	 * Set the value in this instance to a copy of either 'a'
	 * (if ctl is -1) or 'b' (if ctl is 0).
	 */
	public void CopyMux(uint ctl, ModInt a, ModInt b)
	{
		if (mod != a.mod || mod != b.mod) {
			throw new CryptoException("Not same modulus");
		}
		for (int i = 0; i < val.Length; i ++) {
			uint aw = a.val[i];
			uint bw = b.val[i];
			val[i] = bw ^ (ctl & (aw ^ bw));
		}
	}

	/*
	 * Set the value in this instance to the provided integer value
	 * (which MUST be nonnegative).
	 */
	public void Set(int x)
	{
		val[0] = (uint)x;
		for (int i = 1; i < val.Length; i ++) {
			val[i] = 0;
		}
	}

	/*
	 * Set this value to either 0 (if ctl is 0) or 1 (if ctl is -1),
	 * in Montgomery representation.
	 */
	public void SetMonty(uint ctl)
	{
		for (int i = 0; i < val.Length; i ++) {
			val[i] = ctl & mod.R[i];
		}
	}

	/*
	 * Set this value by decoding the provided integer (big-endian
	 * unsigned encoding). If the source value does not fit (it is
	 * not lower than the modulus), then this method return 0, and
	 * this instance is set to 0. Otherwise, it returns -1.
	 */
	public uint Decode(byte[] buf)
	{
		return Decode(buf, 0, buf.Length);
	}

	/*
	 * Set this value by decoding the provided integer (big-endian
	 * unsigned encoding). If the source value does not fit (it is
	 * not lower than the modulus), then this method return 0, and
	 * this instance is set to 0. Otherwise, it returns -1.
	 */
	public uint Decode(byte[] buf, int off, int len)
	{
		/*
		 * Decode into val[]; if the truncation loses some
		 * non-zero bytes, then this returns 0.
		 */
		uint x = DecodeBE(buf, off, len, val);

		/*
		 * Compare with modulus. We want to get a 0 if the
		 * subtraction would not yield a carry, i.e. the
		 * source value is not lower than the modulus.
		 */
		x &= Sub(val, mod.val, 0);

		/*
		 * At that point, x is -1 if the value fits, 0
		 * otherwise.
		 */
		for (int i = 0; i < val.Length; i ++) {
			val[i] &= x;
		}
		return x;
	}

	/*
	 * Set this value by decoding the provided integer (big-endian
	 * unsigned encoding). The source value is reduced if necessary.
	 */
	public void DecodeReduce(byte[] buf)
	{
		DecodeReduce(buf, 0, buf.Length);
	}

	/*
	 * Set this value by decoding the provided integer (big-endian
	 * unsigned encoding). The source value is reduced if necessary.
	 */
	public void DecodeReduce(byte[] buf, int off, int len)
	{
		uint[] x = new uint[((len << 3) + 30) / 31];
		DecodeBE(buf, off, len, x);
		Reduce(x);
	}

	/*
	 * Set the value from the provided source array, with modular
	 * reduction.
	 */
	void Reduce(uint[] b)
	{
		/*
		 * If the modulus uses only one word then we must use
		 * a special code path.
		 */
		if (mod.val.Length == 1) {
			ReduceSmallMod(b);
			return;
		}

		/*
		 * Fast copy of words that do not incur modular
		 * reduction.
		 */
		int aLen = mod.val.Length;
		int bLen = b.Length;
		int cLen = Math.Min(aLen - 1, bLen);
		Array.Copy(b, bLen - cLen, val, 0, cLen);
		for (int i = cLen; i < aLen; i ++) {
			val[i] = 0;
		}

		/*
		 * Inject extra words. We use the pre-computed
		 * Rx[] values to do shifts.
		 */
		for (int j = bLen - cLen; j > 0;) {
			/*
			 * We can add power-of-2 words, but less
			 * than the modulus size. Note that the modulus
			 * uses at least two words, so this process works.
			 */
			int k;
			for (k = 0;; k ++) {
				int nk = 1 << (k + 1);
				if (nk >= aLen || nk > j) {
					break;
				}
			}
			int num = 1 << k;
			MontyMul(val, mod.Rx[k], tmp1, mod.val, mod.n0i);
			j -= num;
			Array.Copy(b, j, tmp2, 0, num);
			for (int i = num; i < tmp2.Length; i ++) {
				tmp2[i] = 0;
			}
			ModAdd(tmp1, tmp2, val, mod.val, 0);
		}
	}

	/*
	 * Modular reduction in case the modulus fits on a single
	 * word.
	 */
	void ReduceSmallMod(uint[] b)
	{
		uint x = 0;
		uint n = mod.val[0];
		int nlen = mod.bitLen;
		uint n0i = mod.n0i;
		uint r2 = mod.R2[0];
		for (int i = b.Length - 1; i >= 0; i --) {
			/*
			 * Multiply x by R (Montgomery multiplication by R^2).
			 */
			ulong z = (ulong)x * (ulong)r2;
			uint u = ((uint)z * n0i) & 0x7FFFFFFF;
			z += (ulong)u * (ulong)n;
			x = (uint)(z >> 31);

			/*
			 * Ensure x fits on 31 bits (it may be up to twice
			 * the modulus at that point). If x >= 2^31 then,
			 * necessarily, x is greater than the modulus, and
			 * the subtraction is sound; moreover, in that case,
			 * subtracting the modulus brings back x to less
			 * than the modulus, hence fitting on 31 bits.
			 */
			x -= (uint)((int)x >> 31) & n;

			/*
			 * Add the next word, then reduce. The addition
			 * does not overflow since both operands fit on
			 * 31 bits.
			 *
			 * Since the modulus could be much smaller than
			 * 31 bits, we need a full remainder operation here.
			 */
			x += b[i];

			/*
			 * Constant-time modular reduction.
			 * We first perform two subtraction of the
			 * shifted modulus to ensure that the high bit
			 * is cleared. This allows the loop to work
			 * properly.
			 */
			x -= (uint)((int)x >> 31) & (n << (31 - nlen));
			x -= (uint)((int)x >> 31) & (n << (31 - nlen));
			for (int j = 31 - nlen; j >= 0; j --) {
				x -= (n << j);
				x += (uint)((int)x >> 31) & (n << j);
			}
		}
		val[0] = x;
	}

	/*
	 * Encode into bytes. Big-endian unsigned encoding is used, the
	 * returned array having the minimal length to encode the modulus.
	 */
	public byte[] Encode()
	{
		return Encode(false);
	}

	/*
	 * Encode into bytes. Big-endian encoding is used; if 'signed' is
	 * true, then signed encoding is used: returned value will have a
	 * leading bit set to 0. Returned array length is the minimal size
	 * for encoding the modulus (with a sign bit if using signed
	 * encoding).
	 */
	public byte[] Encode(bool signed)
	{
		int x = mod.bitLen;
		if (signed) {
			x ++;
		}
		byte[] buf = new byte[(x + 7) >> 3];
		Encode(buf, 0, buf.Length);
		return buf;
	}

	/*
	 * Encode into bytes. The provided array is fully set; big-endian
	 * encoding is used, and extra leading bytes of value 0 are added
	 * if necessary. If the destination array is too small, then the
	 * value is silently truncated.
	 */
	public void Encode(byte[] buf)
	{
		Encode(buf, 0, buf.Length);
	}

	/*
	 * Encode into bytes. The provided array chunk is fully set;
	 * big-endian encoding is used, and extra leading bytes of value
	 * 0 are added if necessary. If the destination array is too
	 * small, then the value is silently truncated.
	 */
	public void Encode(byte[] buf, int off, int len)
	{
		EncodeBE(val, buf, off, len);
	}

	/*
	 * Get the least significant bit of the value (0 or 1).
	 */
	public uint GetLSB()
	{
		return val[0] & (uint)1;
	}

	/*
	 * Add a small integer to this instance. The small integer
	 * 'x' MUST be lower than 2^31 and MUST be lower than the modulus.
	 */
	public void Add(uint x)
	{
		tmp1[0] = x;
		for (int i = 1; i < tmp1.Length; i ++) {
			tmp1[i] = 0;
		}
		ModAdd(val, tmp1, val, mod.val, 0);
	}

	/*
	 * Add another value to this instance. The operand 'b' may
	 * be the same as this instance.
	 */
	public void Add(ModInt b)
	{
		if (mod != b.mod) {
			throw new CryptoException("Not same modulus");
		}
		ModAdd(val, b.val, val, mod.val, 0);
	}

	/*
	 * Subtract a small integer from this instance. The small integer
	 * 'x' MUST be lower than 2^31 and MUST be lower than the modulus.
	 */
	public void Sub(uint x)
	{
		tmp1[0] = x;
		for (int i = 1; i < tmp1.Length; i ++) {
			tmp1[i] = 0;
		}
		ModSub(val, tmp1, val, mod.val);
	}

	/*
	 * Subtract another value from this instance. The operand 'b'
	 * may be the same as this instance.
	 */
	public void Sub(ModInt b)
	{
		if (mod != b.mod) {
			throw new CryptoException("Not same modulus");
		}
		ModSub(val, b.val, val, mod.val);
	}

	/*
	 * Negate this value.
	 */
	public void Negate()
	{
		ModSub(null, val, val, mod.val);
	}

	/*
	 * Convert this instance to Montgomery representation.
	 */
	public void ToMonty()
	{
		MontyMul(val, mod.R2, tmp1, mod.val, mod.n0i);
		Array.Copy(tmp1, 0, val, 0, val.Length);
	}

	/*
	 * Convert this instance back from Montgomery representation to
	 * normal representation.
	 */
	public void FromMonty()
	{
		tmp1[0] = 1;
		for (int i = 1; i < tmp1.Length; i ++) {
			tmp1[i] = 0;
		}
		MontyMul(val, tmp1, tmp2, mod.val, mod.n0i);
		Array.Copy(tmp2, 0, val, 0, val.Length);
	}

	/*
	 * Compute a Montgomery multiplication with the provided
	 * value. The other operand may be this instance.
	 */
	public void MontyMul(ModInt b)
	{
		if (mod != b.mod) {
			throw new CryptoException("Not same modulus");
		}
		MontyMul(val, b.val, tmp1, mod.val, mod.n0i);
		Array.Copy(tmp1, 0, val, 0, val.Length);
	}

	/*
	 * Montgomery-square this instance.
	 */
	public void MontySquare()
	{
		MontyMul(val, val, tmp1, mod.val, mod.n0i);
		Array.Copy(tmp1, 0, val, 0, val.Length);
	}

	/*
	 * Perform modular exponentiation. Exponent is in big-endian
	 * unsigned encoding.
	 */
	public void Pow(byte[] exp)
	{
		Pow(exp, 0, exp.Length);
	}

	/*
	 * Perform modular exponentiation. Exponent is in big-endian
	 * unsigned encoding.
	 */
	public void Pow(byte[] exp, int off, int len)
	{
		MontyMul(val, mod.R2, tmp1, mod.val, mod.n0i);
		val[0] = 1;
		for (int i = 1; i < val.Length; i ++) {
			val[i] = 0;
		}
		for (int i = 0; i < len; i ++) {
			int x = exp[off + len - 1 - i];
			for (int j = 0; j < 8; j ++) {
				MontyMul(val, tmp1, tmp2, mod.val, mod.n0i);
				uint ctl = (uint)-((x >> j) & 1);
				for (int k = 0; k < val.Length; k ++) {
					val[k] = (tmp2[k] & ctl)
						| (val[k] & ~ctl);
				}
				MontyMul(tmp1, tmp1, tmp2, mod.val, mod.n0i);
				Array.Copy(tmp2, 0, tmp1, 0, tmp2.Length);
			}
		}
	}

	/*
	 * Compute modular inverse of this value. If this instance is
	 * zero, then it remains equal to zero. If the modulus is not
	 * prime, then this function computes wrong values.
	 */
	public void Invert()
	{
		Pow(mod.vm2);
	}

	/*
	 * Compute the square root for this value. This method assumes
	 * that the modulus is prime, greater than or equal to 7, and
	 * equal to 3 modulo 4; if it is not, then the returned value
	 * and the contents of this instance are indeterminate.
	 *
	 * Returned value is -1 if the value was indeed a square, 0
	 * otherwise. In the latter case, array contents are the square
	 * root of the opposite of the original value.
	 */
	public uint SqrtBlum()
	{
		/*
		 * We suppose that p = 3 mod 4; we raise to the power
		 * (p-3)/4, then do an extra multiplication to go to
		 * power (p+1)/4.
		 *
		 * Since we know the modulus bit length, we can do
		 * the exponentiation from the high bits downwards.
		 */
		ToMonty();
		Array.Copy(val, 0, tmp1, 0, val.Length);
		int k = (mod.bitLen - 2) / 31;
		int j = mod.bitLen - 2 - k * 31;
		uint ew = mod.val[k];
		for (int i = mod.bitLen - 2; i >= 2; i --) {
			uint ctl = ~(uint)-((int)(ew >> j) & 1);
			MontyMul(tmp1, tmp1, tmp2, mod.val, mod.n0i);
			MontyMul(val, tmp2, tmp1, mod.val, mod.n0i);
			for (int m = 0; m < tmp1.Length; m ++) {
				uint w = tmp1[m];
				tmp1[m] = w ^ (ctl & (w ^ tmp2[m]));
			}
			if (-- j < 0) {
				j = 30;
				ew = mod.val[-- k];
			}
		}

		/*
		 * The extra multiplication. Square root is written in
		 * tmp2 (in Montgomery representation).
		 */
		MontyMul(val, tmp1, tmp2, mod.val, mod.n0i);

		/*
		 * Square it back in tmp1, to see if it indeed yields
		 * val.
		 */
		MontyMul(tmp2, tmp2, tmp1, mod.val, mod.n0i);
		int z = 0;
		for (int i = 0; i < val.Length; i ++) {
			z |= (int)(val[i] ^ tmp1[i]);
		}
		uint good = ~(uint)((z | -z) >> 31);

		/*
		 * Convert back the result to normal representation.
		 */
		Array.Copy(tmp2, 0, val, 0, val.Length);
		FromMonty();
		return good;
	}

	/*
	 * Conditionally swap this instance with the one provided in
	 * parameter. The swap is performed if ctl is -1, not performed
	 * if ctl is 0.
	 */
	public void CondSwap(ModInt b, uint ctl)
	{
		if (mod != b.mod) {
			throw new CryptoException("Not same modulus");
		}
		for (int i = 0; i < val.Length; i ++) {
			uint x = val[i];
			uint y = b.val[i];
			uint m = ctl & (x ^ y);
			val[i] = x ^ m;
			b.val[i] = y ^ m;
		}
	}

	/*
	 * Compare for equality this value with another. Comparison still
	 * works if the two values use distinct moduli.
	 */
	public bool Eq(ModInt b)
	{
		return EqCT(b) != 0;
	}

	/*
	 * Compare for equality this value with another. Comparison still
	 * works if the two values use distinct moduli. Returned value is
	 * -1 on equality, 0 otherwise.
	 */
	public uint EqCT(ModInt b)
	{
		uint z = 0;
		if (b.val.Length > val.Length) {
			for (int i = 0; i < val.Length; i ++) {
				z |= val[i] ^ b.val[i];
			}
			for (int i = val.Length; i < b.val.Length; i ++) {
				z |= b.val[i];
			}
		} else {
			for (int i = 0; i < b.val.Length; i ++) {
				z |= val[i] ^ b.val[i];
			}
			for (int i = b.val.Length; i < val.Length; i ++) {
				z |= b.val[i];
			}
		}
		int x = (int)z;
		return ~(uint)((x | -x) >> 31);
	}

	/* ============================================================== */

	/*
	 * Decode value (unsigned big-endian) into dst[] (little-endian,
	 * 31 bits per word). All words of dst[] are initialised.
	 * Returned value is -1 on success, 0 if some non-zero source
	 * bits had to be ignored.
	 */
	static uint DecodeBE(byte[] buf, int off, int len, uint[] dst)
	{
		int i = 0;
		uint acc = 0;
		int accLen = 0;
		off += len;
		while (i < dst.Length) {
			uint b;
			if (len > 0) {
				b = buf[-- off];
				len --;
			} else {
				b = 0;
			}
			acc |= (b << accLen);
			accLen += 8;
			if (accLen >= 31) {
				dst[i ++] = acc & 0x7FFFFFFF;
				accLen -= 31;
				acc = b >> (8 - accLen);
			}
		}
		while (len -- > 0) {
			acc |= buf[-- off];
		}
		int x = (int)acc;
		return ~(uint)((x | -x) >> 31);
	}

	/*
	 * Encode an integer (array of words, little-endian, 31 bits per
	 * word) into big-endian encoding, with the provided length (in
	 * bytes).
	 */
	static byte[] EncodeBE(uint[] x, int len)
	{
		byte[] val = new byte[len];
		EncodeBE(x, val, 0, len);
		return val;
	}

	/*
	 * Encode an integer (array of words, little-endian, 31 bits per
	 * word) into big-endian encoding, with the provided length (in
	 * bytes).
	 */
	static void EncodeBE(uint[] x, byte[] val)
	{
		EncodeBE(x, val, 0, val.Length);
	}

	/*
	 * Encode an integer (array of words, little-endian, 31 bits per
	 * word) into big-endian encoding, with the provided length (in
	 * bytes).
	 */
	static void EncodeBE(uint[] x, byte[] val, int off, int len)
	{
		uint acc = 0;
		int accLen = 0;
		int j = 0;
		for (int i = len - 1; i >= 0; i --) {
			uint b;
			if (accLen < 8) {
				uint z = (j < x.Length) ? x[j ++] : 0;
				b = acc | (z << accLen);
				acc = z >> (8 - accLen);
				accLen += 23;
			} else {
				b = acc;
				accLen -= 8;
				acc >>= 8;
			}
			val[off + i] = (byte)b;
		}
	}

	/*
	 * Subtract b from a; the carry is returned (-1 if carry, 0
	 * otherwise). The operation is done only if ctl is -1; if
	 * ctl is 0, then a[] is unmodified, but the carry is still
	 * computed and returned.
	 *
	 * The two operand arrays MUST have the same size.
	 */
	static uint Sub(uint[] a, uint[] b, uint ctl)
	{
		int n = a.Length;
		int cc = 0;
		ctl >>= 1;
		for (int i = 0; i < n; i ++) {
			uint aw = a[i];
			uint bw = b[i];
			uint cw = (uint)cc + aw - bw;
			cc = (int)cw >> 31;
			a[i] = (aw & ~ctl) | (cw & ctl);
		}
		return (uint)cc;
	}

	/*
	 * Left-shift value by one bit; the extra bit (carry) is
	 * return as -1 or 0.
	 */
	static uint LShift(uint[] a)
	{
		int n = a.Length;
		uint cc = 0;
		for (int i = 0; i < n; i ++) {
			uint aw = a[i];
			a[i] = (cc | (aw << 1)) & 0x7FFFFFFF;
			cc = aw >> 30;
		}
		return (uint)-(int)cc;
	}

	/*
	 * Modular left-shift value by one bit. Value and modulus MUST
	 * have the same length. Value MUST be lower than modulus.
	 */
	static void ModMul2(uint[] a, uint[] mod)
	{
		int n = a.Length;

		/*
		 * First pass: compute 2*a-mod, but don't keep the
		 * result, only the final carry (0 or -1).
		 */
		uint cc1 = 0;
		int cc2 = 0;
		for (int i = 0; i < n; i ++) {
			uint aw = a[i];
			uint aws = ((aw << 1) | cc1) & 0x7FFFFFFF;
			cc1 = aw >> 30;
			uint z = aws - mod[i] + (uint)cc2;
			cc2 = (int)z >> 31;
		}
		cc2 += (int)cc1;

		/*
		 * If cc2 is 0, then the subtraction yields no carry and
		 * must be done. Otherwise, cc2 is -1, and the subtraction
		 * must not be done.
		 */
		uint ctl = ~(uint)cc2;
		cc1 = 0;
		cc2 = 0;
		for (int i = 0; i < n; i ++) {
			uint aw = a[i];
			uint aws = ((aw << 1) | cc1) & 0x7FFFFFFF;
			cc1 = aw >> 30;
			uint z = aws - (mod[i] & ctl) + (uint)cc2;
			cc2 = (int)z >> 31;
			a[i] = z & 0x7FFFFFFF;
		}
	}

	/*
	 * Modular addition.
	 *
	 * If 'hi' is zero, then this computes a+b-n if a+b >= n,
	 * a+b otherwise.
	 *
	 * If 'hi' is non-zero, then this computes 2^k+a+b-n, where
	 * k = n.Length*31.
	 *
	 * Result is written in d[]. The same array may be used in
	 * several operands.
	 */
	static void ModAdd(uint[] a, uint[] b, uint[] d, uint[] n, uint hi)
	{
		/*
		 * Set ctl to -1 if hi is non-zero, 0 otherwise.
		 * 'ctl' computes whether the subtraction with n[]
		 * is needed in the second pass.
		 */
		int x = (int)hi;
		uint ctl = (uint)((x | -x) >> 31);

		for (int pass = 0; pass < 2; pass ++) {
			/*
			 * cc1 is the carry for a+b (0 or 1)
			 *
			 * cc2 is the carry for the modulus
			 * subtraction (0 or -1)
			 */
			uint cc1 = 0;
			int cc2 = 0;
			for (int i = 0; i < n.Length; i ++) {
				uint aw = a[i];
				uint bw = b[i];
				uint nw = n[i];
				uint sw = aw + bw + cc1;
				cc1 = sw >> 31;
				sw &= 0x7FFFFFFF;
				uint dw = sw - nw + (uint)cc2;
				cc2 = (int)dw >> 31;
				if (pass == 1) {
					dw &= 0x7FFFFFFF;
					d[i] = (dw & ctl) | (sw & ~ctl);
				}
			}

			/*
			 * Compute aggregate subtraction carry. This should
			 * not be 1 if the operands are correct (it would
			 * mean that a+b-n overflows, so both a and b are
			 * larger than n). If it is 0, then a+b-n >= 0,
			 * so the subtraction must be done; otherwise, the
			 * aggregate carry will be -1, and the subtraction
			 * should not be done (unless forced by a non-zero
			 * 'hi' value).
			 */
			cc2 += (int)cc1;
			ctl |= ~(uint)(cc2 >> 31);
		}
	}

	/*
	 * Modular subtraction.
	 *
	 * This computes a-b, then adds n if the result is negative.
	 * If a is null, then it is assumed to be all-zeros.
	 *
	 * Result is written in d[]. The same array may be used in
	 * several operands.
	 */
	static void ModSub(uint[] a, uint[] b, uint[] d, uint[] n)
	{
		uint ctl = 0;
		for (int pass = 0; pass < 2; pass ++) {
			/*
			 * cc1 = carry for a-b (0 or -1)
			 * cc2 = carry for modulus addition (0 or 1)
			 */
			int cc1 = 0;
			uint cc2 = 0;
			for (int i = 0; i < n.Length; i ++) {
				uint aw = (a == null) ? 0 : a[i];
				uint bw = b[i];
				uint nw = n[i];
				uint sw = aw - bw + (uint)cc1;
				cc1 = (int)sw >> 31;
				sw &= 0x7FFFFFFF;
				uint dw = sw + nw + cc2;
				cc2 = dw >> 31;
				if (pass == 1) {
					dw &= 0x7FFFFFFF;
					d[i] = (dw & ctl) | (sw & ~ctl);
				}
			}

			/*
			 * Modulus addition must be done if and only if
			 * a-b had a final carry.
			 */
			ctl = (uint)cc1;
		}
	}

	/*
	 * Compute Montgomery multiplication of a[] by b[], result in
	 * d[], with modulus n[]. All arrays must have the same length.
	 * d[] must be distinct from a[], b[] and n[]. Modulus must be
	 * odd. n0i must be such that n[0]*n0i = -1 mod 2^31. Values a[]
	 * and b[] must be lower than n[] (so, in particular, a[] and
	 * b[] cannot be the same array as n[]).
	 */
	static void MontyMul(uint[] a, uint[] b, uint[] d, uint[] n, uint n0i)
	{
		int len = n.Length;
		for (int i = 0; i < len; i ++) {
			d[i] = 0;
		}
		ulong dh = 0;
		for (int i = 0; i < len; i ++) {
			uint ai = a[i];
			uint u = ((d[0] + ai * b[0]) * n0i) & 0x7FFFFFFF;
			ulong cc = 0;
			for (int j = 0; j < len; j ++) {
				ulong z = (ulong)d[j]
					+ (ulong)ai * (ulong)b[j]
					+ (ulong)u * (ulong)n[j] + cc;
				cc = z >> 31;
				if (j > 0) {
					d[j - 1] = (uint)z & 0x7FFFFFFF;
				} else {
					// DEBUG
					if (((uint)z & 0x7FFFFFFF) != 0) {
						throw new Exception("BAD!");
					}
				}
			}
			dh += cc;
			d[len - 1] = (uint)dh & 0x7FFFFFFF;
			dh >>= 31;
		}
		int x = (int)dh;
		uint ctl = (uint)((x | -x) >> 31);
		Sub(d, n, ctl | ~Sub(d, n, 0));
	}
}

}
