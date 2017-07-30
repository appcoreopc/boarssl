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
 * This class contains a RSA public key, defined as a modulus and an
 * exponent. Both use big-endian representation. This class normalizes
 * the parameters provided to the constructor so that modulus and
 * exponent use their minimal unsigned big-endian representation.
 *
 * Modulus must have length at least 512 bits. Modulus and exponent
 * must be odd integers.
 */

public class RSAPublicKey : IPublicKey {

	public byte[] Modulus {
		get {
			return mod;
		}
	}

	public byte[] Exponent {
		get {
			return e;
		}
	}

	public int KeySizeBits {
		get {
			return ((mod.Length - 1) << 3)
				+ BigInt.BitLength(mod[0]);
		}
	}

	public string AlgorithmName {
		get {
			return "RSA";
		}
	}

	byte[] mod;
	byte[] e;
	int hashCode;

	/*
	 * Create a new instance with the provided element (unsigned,
	 * big-endian). This constructor checks the following rules:
	 *
	 *   the modulus size must be at least 512 bits
	 *   the modulus must be odd
	 *   the exponent must be odd and greater than 1
	 */
	public RSAPublicKey(byte[] modulus, byte[] exponent)
	{
		mod = BigInt.NormalizeBE(modulus, false);
		e = BigInt.NormalizeBE(exponent, false);
		if (mod.Length < 64 || (mod.Length == 64 && mod[0] < 0x80)) {
			throw new CryptoException(
				"Invalid RSA public key (less than 512 bits)");
		}
		if ((mod[mod.Length - 1] & 0x01) == 0) {
			throw new CryptoException(
				"Invalid RSA public key (even modulus)");
		}
		if (BigInt.IsZero(e)) {
			throw new CryptoException(
				"Invalid RSA public key (exponent is zero)");
		}
		if (BigInt.IsOne(e)) {
			throw new CryptoException(
				"Invalid RSA public key (exponent is one)");
		}
		if ((e[e.Length - 1] & 0x01) == 0) {
			throw new CryptoException(
				"Invalid RSA public key (even exponent)");
		}

		/*
		 * A simple hash code that will work well because RSA
		 * keys are in practice quite randomish.
		 */
		hashCode = (int)(BigInt.HashInt(modulus)
			^ BigInt.HashInt(exponent));
	}

	/*
	 * For a RSA public key, we cannot, in all generality, check
	 * any more things than we already did in the constructor.
	 * Notably, we cannot check whether the public exponent (e)
	 * is indeed relatively prime to phi(n) (the order of the
	 * invertible group modulo n).
	 */
	public void CheckValid()
	{
		/*
		 * We cannot check more than what we already checked in
		 * the constructor.
		 */
	}

	public override bool Equals(object obj)
	{
		RSAPublicKey p = obj as RSAPublicKey;
		if (p == null) {
			return false;
		}
		return BigInt.Compare(mod, p.mod) == 0
			&& BigInt.Compare(e, p.e) == 0;
	}

	public override int GetHashCode()
	{
		return hashCode;
	}
}

}
