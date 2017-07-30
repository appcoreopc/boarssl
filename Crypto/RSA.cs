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
 * This class implements the RSA encryption and signature algorithms.
 * The static methods provide access to the algorithm primitives. For
 * signatures, the hash of the signed data must be provided externally.
 */

public static class RSA {

	/*
	 * Get the maximum length (in bytes) of an RSA-encrypted value
	 * with the specified public key.
	 */
	public static int GetMaxEncryptedLength(RSAPublicKey pk)
	{
		return pk.Modulus.Length;
	}

	/*
	 * Encrypt a message with a public key. This applied PKCS#1 v1.5
	 * "type 2" padding. If the message length exceeds the maximum
	 * that can be processed with that public key, an exception is
	 * thrown.
	 *
	 * There are four methods, depending on the kind of source
	 * operand, and how the destination is to be obtained.
	 */

	public static byte[] Encrypt(RSAPublicKey pk, byte[] buf)
	{
		return Encrypt(pk, buf, 0, buf.Length);
	}

	public static byte[] Encrypt(RSAPublicKey pk,
		byte[] buf, int off, int len)
	{
		byte[] n = pk.Modulus;
		int modLen = n.Length;
		byte[] x = DoPKCS1Padding(modLen, true, null, buf, off, len);
		return BigInt.ModPow(x, pk.Exponent, n);
	}

	public static int Encrypt(RSAPublicKey pk,
		byte[] buf, byte[] outBuf, int outOff)
	{
		return Encrypt(pk, buf, 0, buf.Length, outBuf, outOff);
	}

	public static int Encrypt(RSAPublicKey pk,
		byte[] buf, int off, int len, byte[] outBuf, int outOff)
	{
		byte[] r = Encrypt(pk, buf, off, len);
		Array.Copy(r, 0, outBuf, outOff, r.Length);
		return r.Length;
	}

	/*
	 * Perform a RSA decryption. A PKCS#1 v1.5 "type 2" padding is
	 * expected, and removed. An exception is thrown on any error.
	 *
	 * WARNING: potentially vulnerable to Bleichenbacher's attack.
	 * Use with care.
	 *
	 * There are four methods, depending on input and output
	 * operands.
	 */
	public static byte[] Decrypt(RSAPrivateKey sk, byte[] buf)
	{
		return Decrypt(sk, buf, 0, buf.Length);
	}

	public static byte[] Decrypt(RSAPrivateKey sk,
		byte[] buf, int off, int len)
	{
		byte[] tmp = new byte[sk.N.Length];
		int outLen = Decrypt(sk, buf, off, len, tmp, 0);
		byte[] outBuf = new byte[outLen];
		Array.Copy(tmp, 0, outBuf, 0, outLen);
		return outBuf;
	}

	public static int Decrypt(RSAPrivateKey sk,
		byte[] buf, byte[] outBuf, int outOff)
	{
		return Decrypt(sk, buf, 0, buf.Length, outBuf, outOff);
	}

	public static int Decrypt(RSAPrivateKey sk,
		byte[] buf, int off, int len, byte[] outBuf, int outOff)
	{
		if (len != sk.N.Length) {
			throw new CryptoException(
				"Invalid RSA-encrypted message length");
		}

		/*
		 * Note: since RSAPrivateKey refuses a modulus of less
		 * than 64 bytes, we know that len >= 64 here.
		 */
		byte[] x = new byte[len];
		Array.Copy(buf, off, x, 0, len);
		DoPrivate(sk, x);
		if (x[0] != 0x00 || x[1] != 0x02) {
			throw new CryptoException(
				"Invalid PKCS#1 v1.5 encryption padding");
		}
		int i;
		for (i = 2; i < len && x[i] != 0x00; i ++);
		if (i < 10 || i >= len) {
			throw new CryptoException(
				"Invalid PKCS#1 v1.5 encryption padding");
		}
		i ++;
		int olen = len - i;
		Array.Copy(x, i, outBuf, outOff, olen);
		return olen;
	}

	/*
	 * Perform a RSA private key operation (modular exponentiation
	 * with the private exponent). The source array MUST have the
	 * same length as the modulus, and it is modified "in place".
	 *
	 * This function is constant-time, except if the source x[] does
	 * not have the proper length (it should be identical to the
	 * modulus length). If the source array has the proper length
	 * but the numerical value is not in the proper range, then it
	 * is first reduced modulo N.
	 */
	public static void DoPrivate(RSAPrivateKey sk, byte[] x)
	{
		DoPrivate(sk, x, 0, x.Length);
	}

	public static void DoPrivate(RSAPrivateKey sk,
		byte[] x, int off, int len)
	{
		/*
		 * Check that the source array has the proper length
		 * (identical to the length of the modulus).
		 */
		if (len != sk.N.Length) {
			throw new CryptoException(
				"Invalid source length for RSA private");
		}

		/*
		 * Reduce the source value to the proper range.
		 */
		ModInt mx = new ModInt(sk.N);
		mx.DecodeReduce(x, off, len);

		/*
		 * Compute m1 = x^dp mod p.
		 */
		ModInt m1 = new ModInt(sk.P);
		m1.Set(mx);
		m1.Pow(sk.DP);

		/*
		 * Compute m2 = x^dq mod q.
		 */
		ModInt m2 = new ModInt(sk.Q);
		m2.Set(mx);
		m2.Pow(sk.DQ);

		/*
		 * Compute h = (m1 - m2) / q mod p.
		 * (Result goes in m1.)
		 */
		ModInt m3 = m1.Dup();
		m3.Set(m2);
		m1.Sub(m3);
		m3.Decode(sk.IQ);
		m1.ToMonty();
		m1.MontyMul(m3);

		/*
		 * Compute m_2 + q*h. This works on plain integers, but
		 * we have efficient and constant-time code for modular
		 * integers, so we will do it modulo n.
		 */
		m3 = mx;
		m3.Set(m1);
		m1 = m3.Dup();
		m1.Decode(sk.Q);
		m1.ToMonty();
		m3.MontyMul(m1);
		m1.Set(m2);
		m3.Add(m1);

		/*
		 * Write result back in x[].
		 */
		m3.Encode(x, off, len);
	}

	/*
	 * Constant headers for PKCS#1 v1.5 "type 1" padding. There are
	 * two versions for each header, because of the PKCS#1 ambiguity
	 * with regards to hash function parameters (ASN.1 NULL value,
	 * or omitted).
	 */

	// PKCS#1 with no explicit digest function (special for SSL/TLS)
	public static byte[] PKCS1_ND = new byte[] { };

	// PKCS#1 with MD5
	public static byte[] PKCS1_MD5 = new byte[] {
		0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86,
		0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00,
		0x04, 0x10
	};

	// PKCS#1 with MD5 (alt)
	public static byte[] PKCS1_MD5_ALT = new byte[] {
		0x30, 0x1E, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86,
		0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x04, 0x10
	};

	// PKCS#1 with SHA-1
	public static byte[] PKCS1_SHA1 = new byte[] {
		0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E,
		0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14
	};

	// PKCS#1 with SHA-1 (alt)
	public static byte[] PKCS1_SHA1_ALT = new byte[] {
		0x30, 0x1F, 0x30, 0x07, 0x06, 0x05, 0x2B, 0x0E,
		0x03, 0x02, 0x1A, 0x04, 0x14
	};

	// PKCS#1 with SHA-224
	public static byte[] PKCS1_SHA224 = new byte[] {
		0x30, 0x2D, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
		0x00, 0x04, 0x1C
	};

	// PKCS#1 with SHA-224 (alt)
	public static byte[] PKCS1_SHA224_ALT = new byte[] {
		0x30, 0x2B, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x04,
		0x1C
	};

	// PKCS#1 with SHA-256
	public static byte[] PKCS1_SHA256 = new byte[] {
		0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
		0x00, 0x04, 0x20
	};

	// PKCS#1 with SHA-256 (alt)
	public static byte[] PKCS1_SHA256_ALT = new byte[] {
		0x30, 0x2F, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x04,
		0x20
	};

	// PKCS#1 with SHA-384
	public static byte[] PKCS1_SHA384 = new byte[] {
		0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
		0x00, 0x04, 0x30
	};

	// PKCS#1 with SHA-384 (alt)
	public static byte[] PKCS1_SHA384_ALT = new byte[] {
		0x30, 0x3F, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x04,
		0x30
	};

	// PKCS#1 with SHA-512
	public static byte[] PKCS1_SHA512 = new byte[] {
		0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
		0x00, 0x04, 0x40
	};

	// PKCS#1 with SHA-512 (alt)
	public static byte[] PKCS1_SHA512_ALT = new byte[] {
		0x30, 0x4F, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x04,
		0x40
	};

	/*
	 * Verify an "ND" signature (no digest header: this is for
	 * signatures in SSL/TLS up to TLS-1.1). The hash value
	 * (normally the 36-byte concatenation of MD5 and SHA-1 in
	 * the case of SSL/TLS) and the signature are provided.
	 * Returned value is true on success, false otherwise. No
	 * exception is thrown even if the public key is invalid.
	 */

	public static bool VerifyND(RSAPublicKey pk,
		byte[] hash, byte[] sig)
	{
		return Verify(pk, PKCS1_ND, null,
			hash, 0, hash.Length,
			sig, 0, sig.Length);
	}

	public static bool VerifyND(RSAPublicKey pk,
		byte[] hash, int hashOff, int hashLen, byte[] sig)
	{
		return Verify(pk, PKCS1_ND, null,
			hash, hashOff, hashLen,
			sig, 0, sig.Length);
	}

	public static bool VerifyND(RSAPublicKey pk,
		byte[] hash, byte[] sig, int sigOff, int sigLen)
	{
		return Verify(pk, PKCS1_ND, null,
			hash, 0, hash.Length,
			sig, sigOff, sigLen);
	}

	public static bool VerifyND(RSAPublicKey pk,
		byte[] hash, int hashOff, int hashLen,
		byte[] sig, int sigOff, int sigLen)
	{
		return Verify(pk, PKCS1_ND, null,
			hash, hashOff, hashLen,
			sig, sigOff, sigLen);
	}

	/*
	 * Verify a RSA signature, with PKCS#1 v1.5 "type 1" padding.
	 * The digest header, digest alternative header, hashed data,
	 * and signature value are provided. On any error (including
	 * an invalid RSA public key), false is returned.
	 *
	 * If 'headerAlt' is null, then the signature MUST use the
	 * header value provided in 'header'. Otherwise, the signature
	 * MUST use either 'header' or 'headerAlt'.
	 */

	public static bool Verify(RSAPublicKey pk,
		byte[] header, byte[] headerAlt,
		byte[] hash, byte[] sig)
	{
		return Verify(pk, header, headerAlt,
			hash, 0, hash.Length,
			sig, 0, sig.Length);
	}

	public static bool Verify(RSAPublicKey pk,
		byte[] header, byte[] headerAlt,
		byte[] hash, int hashOff, int hashLen, byte[] sig)
	{
		return Verify(pk, header, headerAlt,
			hash, hashOff, hashLen,
			sig, 0, sig.Length);
	}

	public static bool Verify(RSAPublicKey pk,
		byte[] header, byte[] headerAlt,
		byte[] hash, byte[] sig, int sigOff, int sigLen)
	{
		return Verify(pk, header, headerAlt,
			hash, 0, hash.Length,
			sig, sigOff, sigLen);
	}

	public static bool Verify(RSAPublicKey pk,
		byte[] header, byte[] headerAlt,
		byte[] hash, int hashOff, int hashLen,
		byte[] sig, int sigOff, int sigLen)
	{
		/*
		 * Signature must be an integer less than the modulus,
		 * but encoded over exactly the same size as the modulus.
		 */
		byte[] n = pk.Modulus;
		int modLen = n.Length;
		if (sigLen != modLen) {
			return false;
		}
		byte[] x = new byte[modLen];
		Array.Copy(sig, sigOff, x, 0, modLen);
		if (BigInt.Compare(x, n) >= 0) {
			return false;
		}

		/*
		 * Do the RSA exponentation, then verify and remove the
		 * "Type 1" padding (00 01 FF...FF 00 with at least
		 * eight bytes of value FF).
		 */
		x = BigInt.ModPow(x, pk.Exponent, n);
		if (x.Length < 11 || x[0] != 0x00 || x[1] != 0x01) {
			return false;
		}
		int k = 2;
		while (k < x.Length && x[k] == 0xFF) {
			k ++;
		}
		if (k < 10 || k == x.Length || x[k] != 0x00) {
			return false;
		}
		k ++;

		/*
		 * Check that the remaining byte end with the provided
		 * hash value.
		 */
		int len = modLen - k;
		if (len < hashLen) {
			return false;
		}
		for (int i = 0; i < hashLen; i ++) {
			if (x[modLen - hashLen + i] != hash[hashOff + i]) {
				return false;
			}
		}
		len -= hashLen;

		/*
		 * Header is at offset 'k', and length 'len'. Compare
		 * with the provided header(s).
		 */
		if (Eq(header, 0, header.Length, x, k, len)) {
			return true;
		}
		if (headerAlt != null) {
			if (Eq(headerAlt, 0, headerAlt.Length, x, k, len)) {
				return true;
			}
		}
		return false;
	}

	/*
	 * Compute a RSA signature (PKCS#1 v1.5 "type 1" padding).
	 * The digest header and the hashed data are provided. The
	 * header should be one of the standard PKCS#1 header; it
	 * may also be an empty array or null for a "ND" signature
	 * (this is normally used only in SSL/TLS up to TLS-1.1).
	 */

	public static byte[] Sign(RSAPrivateKey sk, byte[] header,
		byte[] hash)
	{
		return Sign(sk, header, hash, 0, hash.Length);
	}

	public static byte[] Sign(RSAPrivateKey sk, byte[] header,
		byte[] hash, int hashOff, int hashLen)
	{
		byte[] sig = new byte[sk.N.Length];
		Sign(sk, header, hash, hashOff, hashLen, sig, 0);
		return sig;
	}

	public static int Sign(RSAPrivateKey sk, byte[] header,
		byte[] hash, byte[] outBuf, int outOff)
	{
		return Sign(sk, header, hash, 0, hash.Length, outBuf, outOff);
	}

	public static int Sign(RSAPrivateKey sk, byte[] header,
		byte[] hash, int hashOff, int hashLen,
		byte[] outBuf, int outOff)
	{
		int modLen = sk.N.Length;
		byte[] x = DoPKCS1Padding(modLen, false,
			header, hash, hashOff, hashLen);
		DoPrivate(sk, x);
		Array.Copy(x, 0, outBuf, outOff, x.Length);
		return x.Length;
	}

	/*
	 * Apply PKCS#1 v1.5 padding. The data to pad is the concatenation
	 * of head[] and the chunk of val[] beginning at valOff and of
	 * length valLen. If 'head' is null, then an empty array is used.
	 *
	 * The returned array has length modLen (the modulus size, in bytes).
	 * Padding type 2 (random bytes, for encryption) is used if type2
	 * is true; otherwise, padding type 1 is applied (bytes 0xFF, for
	 * signatures).
	 */
	public static byte[] DoPKCS1Padding(int modLen, bool type2,
		byte[] head, byte[] val, int valOff, int valLen)
	{
		if (head == null) {
			head = PKCS1_ND;
		}
		int len = head.Length + valLen;
		int padLen = modLen - len - 3;
		if (padLen < 8) {
			throw new Exception(
				"modulus too short for PKCS#1 padding");
		}
		byte[] x = new byte[modLen];
		x[0] = 0x00;
		x[1] = (byte)(type2 ? 0x02 : 0x01);
		if (type2) {
			RNG.GetBytesNonZero(x, 2, padLen);
		} else {
			for (int i = 0; i < padLen; i ++) {
				x[i + 2] = 0xFF;
			}
		}
		x[padLen + 2] = 0x00;
		Array.Copy(head, 0, x, padLen + 3, head.Length);
		Array.Copy(val, valOff, x, modLen - valLen, valLen);
		return x;
	}

	/*
	 * Compare two byte chunks for equality.
	 */
	static bool Eq(byte[] a, int aoff, int alen,
		byte[] b, int boff, int blen)
	{
		if (alen != blen) {
			return false;
		}
		for (int i = 0; i < alen; i ++) {
			if (a[aoff + i] != b[boff + i]) {
				return false;
			}
		}
		return true;
	}
}

}
