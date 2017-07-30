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
using System.IO;

namespace Crypto {

/*
 * This class implements the ECDSA signature algorithm. The static methods
 * provide access to the algorithm primitives. The hash of the signed data
 * must be provided externally.
 *
 * Signatures may be encoded in either "ASN.1" or "raw" formats; "ASN.1"
 * is normally used (e.g. in SSL/TLS) but some protocols and API expect
 * the raw format (e.g. PKCS#11 and OpenPGP). An ECDSA signature consists
 * in two integers r and s, which are values modulo the subgroup order q.
 * In ASN.1 format, the signature is the DER encoding of the ASN.1
 * structure:
 *
 *    ECDSA-signature ::= SEQUENCE {
 *            r INTEGER,
 *            s INTEGER
 *    }
 *
 * In raw format, the two integers r and s are encoded with unsigned
 * big-endian encoding (with the same encoding length) and concatenated.
 *
 * The Sign() and Verify() methods use the ASN.1 format. The SignRaw()
 * and VerifyRaw() use the raw format. The SigRawToAsn1() and SigAsn1ToRaw()
 * allow for converting between the two formats.
 */

public class ECDSA : DSAUtils {

	/*
	 * Verify an ECDSA signature (ASN.1 format). Returned value is true
	 * on success. If the signature is invalid, then false is returned.
	 * Internal exceptions (due to an incorrect public key) are also
	 * converted to a returned value of false.
	 *
	 * There are four methods, depending on the source operands.
	 */

	public static bool Verify(ECPublicKey pk,
		byte[] hash, byte[] sig)
	{
		return Verify(pk, hash, 0, hash.Length, sig, 0, sig.Length);
	}

	public static bool Verify(ECPublicKey pk,
		byte[] hash, int hashOff, int hashLen, byte[] sig)
	{
		return Verify(pk, hash, hashOff, hashLen, sig, 0, sig.Length);
	}

	public static bool Verify(ECPublicKey pk,
		byte[] hash, byte[] sig, int sigOff, int sigLen)
	{
		return Verify(pk, hash, 0, hash.Length, sig, sigOff, sigLen);
	}

	public static bool Verify(ECPublicKey pk,
		byte[] hash, int hashOff, int hashLen,
		byte[] sig, int sigOff, int sigLen)
	{
		byte[] raw = SigAsn1ToRaw(sig, sigOff, sigLen);
		if (raw == null) {
			return false;
		}
		return VerifyRaw(pk,
			hash, hashOff, hashLen, raw, 0, raw.Length);
	}

	/*
	 * Verify an ECDSA signature (raw format). Returned value is true
	 * on success. If the signature is invalid, then false is returned.
	 * Internal exceptions (due to an incorrect public key) are also
	 * converted to a returned value of false.
	 *
	 * There are four methods, depending on the source operands.
	 */

	public static bool VerifyRaw(ECPublicKey pk,
		byte[] hash, byte[] sig)
	{
		return VerifyRaw(pk,
			hash, 0, hash.Length, sig, 0, sig.Length);
	}

	public static bool VerifyRaw(ECPublicKey pk,
		byte[] hash, int hashOff, int hashLen, byte[] sig)
	{
		return VerifyRaw(pk,
			hash, hashOff, hashLen, sig, 0, sig.Length);
	}

	public static bool VerifyRaw(ECPublicKey pk,
		byte[] hash, byte[] sig, int sigOff, int sigLen)
	{
		return VerifyRaw(pk,
			hash, 0, hash.Length, sig, sigOff, sigLen);
	}

	public static bool VerifyRaw(ECPublicKey pk,
		byte[] hash, int hashOff, int hashLen,
		byte[] sig, int sigOff, int sigLen)
	{
		try {
			/*
			 * Get the curve.
			 */
			ECCurve curve = pk.Curve;

			/*
			 * Get r and s from signature. This also verifies
			 * that they do not exceed the subgroup order.
			 */
			if (sigLen == 0 || (sigLen & 1) != 0) {
				return false;
			}
			int tlen = sigLen >> 1;
			ModInt oneQ = new ModInt(curve.SubgroupOrder);
			oneQ.Set(1);
			ModInt r = oneQ.Dup();
			ModInt s = oneQ.Dup();
			r.Decode(sig, sigOff, tlen);
			s.Decode(sig, sigOff + tlen, tlen);

			/*
			 * If either r or s was too large, it got set to
			 * zero. We also don't want real zeros.
			 */
			if (r.IsZero || s.IsZero) {
				return false;
			}

			/*
			 * Convert the hash value to an integer modulo q.
			 * As per FIPS 186-4, if the hash value is larger
			 * than q, then we keep the qlen leftmost bits of
			 * the hash value.
			 */
			int qBitLength = oneQ.ModBitLength;
			int hBitLength = hashLen << 3;
			byte[] hv;
			if (hBitLength <= qBitLength) {
				hv = new byte[hashLen];
				Array.Copy(hash, hashOff, hv, 0, hashLen);
			} else {
				int qlen = (qBitLength + 7) >> 3;
				hv = new byte[qlen];
				Array.Copy(hash, hashOff, hv, 0, qlen);
				int rs = (8 - (qBitLength & 7)) & 7;
				BigInt.RShift(hv, rs);
			}
			ModInt z = oneQ.Dup();
			z.DecodeReduce(hv);

			/*
			 * Apply the verification algorithm:
			 *   w = 1/s mod q
			 *   u = z*w mod q
			 *   v = r*w mod q
			 *   T = u*G + v*Pub
			 *   test whether T.x mod q == r.
			 */
			/*
			 * w = 1/s mod q
			 */
			ModInt w = s.Dup();
			w.Invert();

			/*
			 * u = z*w mod q
			 */
			w.ToMonty();
			ModInt u = w.Dup();
			u.MontyMul(z);

			/*
			 * v = r*w mod q
			 */
			ModInt v = w.Dup();
			v.MontyMul(r);

			/*
			 * Compute u*G
			 */
			MutableECPoint T = curve.MakeGenerator();
			uint good = T.MulSpecCT(u.Encode());

			/*
			 * Compute v*iPub
			 */
			MutableECPoint M = pk.iPub.Dup();
			good &= M.MulSpecCT(v.Encode());

			/*
			 * Compute T = u*G+v*iPub
			 */
			uint nd = T.AddCT(M);
			M.DoubleCT();
			T.Set(M, ~nd);
			good &= ~T.IsInfinityCT;

			/*
			 * Get T.x, reduced modulo q.
			 * Signature is valid if and only if we get
			 * the same value as r (and we did not encounter
			 * an error previously).
			 */
			s.DecodeReduce(T.X);
			return (good & r.EqCT(s)) != 0;

		} catch (CryptoException) {
			/*
			 * Exceptions may occur if the key or signature
			 * have invalid values (non invertible, out of
			 * range...). Any such occurrence means that the
			 * signature is not valid.
			 */
			return false;
		}
	}

	/*
	 * Compute an ECDSA signature (ASN.1 format). On error (e.g. due
	 * to an invalid private key), an exception is thrown.
	 *
	 * Internally, the process described in RFC 6979 is used to
	 * compute the per-signature random value 'k'. If 'rfc6979Hash'
	 * is not null, then a clone of that function is used for that
	 * process, and signatures are fully deterministic and should
	 * match RFC 6979 test vectors; if 'rfc6979Hash' is null, then
	 * the engine uses SHA-256 with additional randomness, resulting
	 * in randomized signatures. The systematic use of RFC 6979 in
	 * both cases ensures the safety of the private key even if the
	 * system RNG is predictible.
	 *
	 * There are four methods, depending on the source operands.
	 */

	public static byte[] Sign(ECPrivateKey sk, IDigest rfc6979Hash,
		byte[] hash)
	{
		return Sign(sk, rfc6979Hash, hash, 0, hash.Length);
	}

	public static byte[] Sign(ECPrivateKey sk, IDigest rfc6979Hash,
		byte[] hash, int hashOff, int hashLen)
	{
		return SigRawToAsn1(SignRaw(sk, rfc6979Hash,
			hash, hashOff, hashLen));
	}

	public static int Sign(ECPrivateKey sk, IDigest rfc6979Hash,
		byte[] hash, byte[] outBuf, int outOff)
	{
		return Sign(sk, rfc6979Hash,
			hash, 0, hash.Length, outBuf, outOff);
	}

	public static int Sign(ECPrivateKey sk, IDigest rfc6979Hash,
		byte[] hash, int hashOff, int hashLen,
		byte[] outBuf, int outOff)
	{
		byte[] sig = Sign(sk, rfc6979Hash, hash, hashOff, hashLen);
		Array.Copy(sig, 0, outBuf, outOff, sig.Length);
		return sig.Length;
	}

	/*
	 * Compute an ECDSA signature (raw format). On error (e.g. due
	 * to an invalid private key), an exception is thrown.
	 *
	 * Internally, the process described in RFC 6979 is used to
	 * compute the per-signature random value 'k'. If 'rfc6979Hash'
	 * is not null, then a clone of that function is used for that
	 * process, and signatures are fully deterministic and should
	 * match RFC 6979 test vectors; if 'rfc6979Hash' is null, then
	 * the engine uses SHA-256 with additional randomness, resulting
	 * in randomized signatures. The systematic use of RFC 6979 in
	 * both cases ensures the safety of the private key even if the
	 * system RNG is predictible.
	 *
	 * The signature returned by these methods always has length
	 * exactly twice that of the encoded subgroup order (they are
	 * not minimalized). Use SigRawMinimalize() to reduce the
	 * signature size to its minimum length.
	 *
	 * There are four methods, depending on the source operands.
	 */

	public static byte[] SignRaw(ECPrivateKey sk, IDigest rfc6979Hash,
		byte[] hash)
	{
		return SignRaw(sk, rfc6979Hash, hash, 0, hash.Length);
	}

	public static int SignRaw(ECPrivateKey sk, IDigest rfc6979Hash,
		byte[] hash, byte[] outBuf, int outOff)
	{
		return SignRaw(sk, rfc6979Hash,
			hash, 0, hash.Length, outBuf, outOff);
	}

	public static int SignRaw(ECPrivateKey sk, IDigest rfc6979Hash,
		byte[] hash, int hashOff, int hashLen,
		byte[] outBuf, int outOff)
	{
		byte[] sig = SignRaw(sk, rfc6979Hash, hash, hashOff, hashLen);
		Array.Copy(sig, 0, outBuf, outOff, sig.Length);
		return sig.Length;
	}

	public static byte[] SignRaw(ECPrivateKey sk, IDigest rfc6979Hash,
		byte[] hash, int hashOff, int hashLen)
	{
		ECCurve curve = sk.Curve;
		byte[] q = curve.SubgroupOrder;
		RFC6979 rf = new RFC6979(rfc6979Hash, q, sk.X,
			hash, hashOff, hashLen, rfc6979Hash != null);
		ModInt mh = rf.GetHashMod();
		ModInt mx = mh.Dup();
		mx.Decode(sk.X);

		/*
		 * Compute DSA signature. We use a loop to enumerate
		 * candidates for k until a proper one is found (it
		 * is VERY improbable that we may have to loop).
		 */
		ModInt mr = mh.Dup();
		ModInt ms = mh.Dup();
		ModInt mk = mh.Dup();
		byte[] k = new byte[q.Length];
		for (;;) {
			rf.NextK(k);
			MutableECPoint G = curve.MakeGenerator();
			if (G.MulSpecCT(k) == 0) {
				/*
				 * We may get an error here only if the
				 * curve is invalid (generator does not
				 * produce the expected subgroup).
				 */
				throw new CryptoException(
					"Invalid EC private key / curve");
			}
			mr.DecodeReduce(G.X);
			if (mr.IsZero) {
				continue;
			}
			ms.Set(mx);
			ms.ToMonty();
			ms.MontyMul(mr);
			ms.Add(mh);
			mk.Decode(k);
			mk.Invert();
			ms.ToMonty();
			ms.MontyMul(mk);

			byte[] sig = new byte[q.Length << 1];
			mr.Encode(sig, 0, q.Length);
			ms.Encode(sig, q.Length, q.Length);
			return sig;
		}
	}

	/*
	 * Generate a new EC key pair in the specified curve.
	 */
	public static ECPrivateKey Generate(ECCurve curve)
	{
		return new ECPrivateKey(curve,
			BigInt.RandIntNZ(curve.SubgroupOrder));
	}
}

}
