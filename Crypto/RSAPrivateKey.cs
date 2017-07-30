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
 * This class contains a RSA private key. The private key elements can
 * be exported as arrays of bytes (minimal unsigned big-endian
 * representation).
 *
 * Private key elements are:
 *   n    modulus
 *   e    public exponent
 *   d    private exponent
 *   p    first modulus factor
 *   q    second modulus factor
 *   dp   d mod (p-1)
 *   dq   d mod (q-1)
 *   iq   (1/q) mod p
 */

public class RSAPrivateKey : IPrivateKey {

	public byte[] N {
		get {
			return n;
		}
	}

	public byte[] E {
		get {
			return e;
		}
	}

	public byte[] D {
		get {
			return d;
		}
	}

	public byte[] P {
		get {
			return p;
		}
	}

	public byte[] Q {
		get {
			return q;
		}
	}

	public byte[] DP {
		get {
			return dp;
		}
	}

	public byte[] DQ {
		get {
			return dq;
		}
	}

	public byte[] IQ {
		get {
			return iq;
		}
	}

	public int KeySizeBits {
		get {
			return ((n.Length - 1) << 3)
				+ BigInt.BitLength(n[0]);
		}
	}

	public string AlgorithmName {
		get {
			return "RSA";
		}
	}

	IPublicKey IPrivateKey.PublicKey {
		get {
			return this.PublicKey;
		}
	}

	public RSAPublicKey PublicKey {
		get {
			return new RSAPublicKey(n, e);
		}
	}

	byte[] n, e, d, p, q, dp, dq, iq;

	/*
	 * Create a new instance with the provided elements. Values are
	 * in unsigned big-endian representation.
	 *
	 *   n    modulus
	 *   e    public exponent
	 *   d    private exponent
	 *   p    first modulus factor
	 *   q    second modulus factor
	 *   dp   d mod (p-1)
	 *   dq   d mod (q-1)
	 *   iq   (1/q) mod p
	 *
	 * Rules verified by this constructor:
	 *   n must be odd and at least 512 bits
	 *   e must be odd
	 *   p must be odd
	 *   q must be odd
	 *   p and q are greater than 1
	 *   n is equal to p*q
	 *   dp must be non-zero and lower than p-1
	 *   dq must be non-zero and lower than q-1
	 *   iq must be non-zero and lower than p
	 *
	 * This constructor does NOT verify that:
	 *   p and q are prime
	 *   d is equal to dp modulo p-1
	 *   d is equal to dq modulo q-1
	 *   dp is the inverse of e modulo p-1
	 *   dq is the inverse of e modulo q-1
	 *   iq is the inverse of q modulo p
	 */
	public RSAPrivateKey(byte[] n, byte[] e, byte[] d,
		byte[] p, byte[] q, byte[] dp, byte[] dq, byte[] iq)
	{
		n = BigInt.NormalizeBE(n);
		e = BigInt.NormalizeBE(e);
		d = BigInt.NormalizeBE(d);
		p = BigInt.NormalizeBE(p);
		q = BigInt.NormalizeBE(q);
		dp = BigInt.NormalizeBE(dp);
		dq = BigInt.NormalizeBE(dq);
		iq = BigInt.NormalizeBE(iq);

		if (n.Length < 64 || (n.Length == 64 && n[0] < 0x80)) {
			throw new CryptoException(
				"Invalid RSA private key (less than 512 bits)");
		}
		if (!BigInt.IsOdd(n)) {
			throw new CryptoException(
				"Invalid RSA private key (even modulus)");
		}
		if (!BigInt.IsOdd(e)) {
			throw new CryptoException(
				"Invalid RSA private key (even exponent)");
		}
		if (!BigInt.IsOdd(p) || !BigInt.IsOdd(q)) {
			throw new CryptoException(
				"Invalid RSA private key (even factor)");
		}
		if (BigInt.IsOne(p) || BigInt.IsOne(q)) {
			throw new CryptoException(
				"Invalid RSA private key (trivial factor)");
		}
		if (BigInt.Compare(n, BigInt.Mul(p, q)) != 0) {
			throw new CryptoException(
				"Invalid RSA private key (bad factors)");
		}
		if (dp.Length == 0 || dq.Length == 0) {
			throw new CryptoException(
				"Invalid RSA private key"
				+ " (null reduced private exponent)");
		}

		/*
		 * We can temporarily modify p[] and q[] (to compute
		 * p-1 and q-1) since these are freshly produced copies.
		 */
		p[p.Length - 1] --;
		q[q.Length - 1] --;
		if (BigInt.Compare(dp, p) >= 0 || BigInt.Compare(dq, q) >= 0) {
			throw new CryptoException(
				"Invalid RSA private key"
				+ " (oversized reduced private exponent)");
		}
		p[p.Length - 1] ++;
		q[q.Length - 1] ++;
		if (iq.Length == 0 || BigInt.Compare(iq, p) >= 0) {
			throw new CryptoException(
				"Invalid RSA private key"
				+ " (out of range CRT coefficient)");
		}
		this.n = n;
		this.e = e;
		this.d = d;
		this.p = p;
		this.q = q;
		this.dp = dp;
		this.dq = dq;
		this.iq = iq;
	}

	/*
	 * Create a new instance with the provided elements: the two
	 * factors, and the public exponent. The other elements are
	 * computed. Values are in unsigned big-endian representation.
	 * Rules verified by this constructor:
	 *   p must be odd
	 *   q must be odd
	 *   e must be relatively prime to both p-1 and q-1
	 *   e must be greater than 1
	 *   p*q must have size at least 512 bits
	 * TODO: not implemented yet.
	 */
	public RSAPrivateKey(byte[] p, byte[] q, byte[] e)
	{
		throw new Exception("NYI");
	}

	/*
	 * Create a new instance with the provided elements: the two
	 * factors, and the public exponent. The other elements are
	 * computed. The factors are in unsigned big-endian
	 * representation; the public exponent is a small integer.
	 * Rules verified by this constructor:
	 *   p must be odd
	 *   q must be odd
	 *   e must be relatively prime to both p-1 and q-1
	 *   p*q must have size at least 512 bits
	 * TODO: not implemented yet.
	 */
	public RSAPrivateKey(byte[] p, byte[] q, uint e)
		: this(p, q, ToBytes(e))
	{
	}

	static byte[] ToBytes(uint x)
	{
		byte[] r = new byte[4];
		r[0] = (byte)(x >> 24);
		r[1] = (byte)(x >> 16);
		r[2] = (byte)(x >> 8);
		r[3] = (byte)x;
		return r;
	}

	/*
	 * CheckValid() will verify that the prime factors are indeed
	 * prime, and that all other values are correct.
	 */
	public void CheckValid()
	{
		/*
		 * Factors ought to be prime.
		 */
		if (!BigInt.IsPrime(p) || !BigInt.IsPrime(q)) {
			throw new CryptoException("Invalid RSA private key"
				+ " (non-prime factor)");
		}

		/*
		 * FIXME: Verify that:
		 *   dp = d mod p-1
		 *   e*dp = 1 mod p-1
		 *   dq = d mod q-1
		 *   e*dq = 1 mod q-1
		 * (This is not easy with existing code because p-1 and q-1
		 * are even, but ModInt tolerates only odd moduli.)
		 *
		CheckExp(p, d, dp, e);
		CheckExp(q, d, dq, e);
		 */

		/*
		 * Verify that:
		 *   q*iq = 1 mod p
		 */
		ModInt x = new ModInt(p);
		ModInt y = x.Dup();
		x.DecodeReduce(q);
		x.ToMonty();
		y.Decode(iq);
		x.MontyMul(y);
		if (!x.IsOne) {
			throw new CryptoException("Invalid RSA private key"
				+ " (wrong CRT coefficient)");
		}
	}
}

}
