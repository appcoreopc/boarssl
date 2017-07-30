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
using System.Text;

using Asn1;
using Crypto;

namespace XKeys {

/*
 * The KF class contains static methods to decode and encode algorithm
 * parameters, public keys and private keys.
 */

public class KF {

	const string OID_RSA = "1.2.840.113549.1.1.1";
	const string OID_RSA_OAEP = "1.2.840.113549.1.1.7";
	const string OID_RSA_PSS = "1.2.840.113549.1.1.10";
	const string OID_DSA = "1.2.840.10040.4.1";
	const string OID_EC = "1.2.840.10045.2.1";

	/*
	 * Encode the private key. If 'pk8' is true, then this uses
	 * PKCS#8 format (unencrypted); otherwise, it uses the
	 * "internal" format that does not specifically identify the key
	 * type.
	 */
	public static byte[] EncodePrivateKey(IPrivateKey sk, bool pk8)
	{
		RSAPrivateKey rk = sk as RSAPrivateKey;
		/* disabled DSA
		DSAPrivateKey dk = sk as DSAPrivateKey;
		*/
		ECPrivateKey ek = sk as ECPrivateKey;
		if (rk != null) {
			AsnElt ark = AsnElt.Make(AsnElt.SEQUENCE,
				AsnElt.MakeInteger(0),
				AsnElt.MakeInteger(rk.N),
				AsnElt.MakeInteger(rk.E),
				AsnElt.MakeInteger(rk.D),
				AsnElt.MakeInteger(rk.P),
				AsnElt.MakeInteger(rk.Q),
				AsnElt.MakeInteger(rk.DP),
				AsnElt.MakeInteger(rk.DQ),
				AsnElt.MakeInteger(rk.IQ));
			byte[] enc = ark.Encode();
			if (pk8) {
				AsnElt apk8 = AsnElt.Make(AsnElt.SEQUENCE,
					AsnElt.MakeInteger(0),
					AsnElt.Make(AsnElt.SEQUENCE,
						AsnElt.MakeOID(OID_RSA),
						AsnElt.NULL_V),
					AsnElt.MakeBlob(enc));
				enc = apk8.Encode();
			}
			return enc;
		/* disabled DSA
		} else if (dk != null) {
			if (pk8) {
				AsnElt adx = AsnElt.MakeInteger(dk.X);
				AsnElt adp = AsnElt.Make(AsnElt.SEQUENCE,
					AsnElt.MakeInteger(dk.P),
					AsnElt.MakeInteger(dk.Q),
					AsnElt.MakeInteger(dk.G));
				AsnElt apk8 = AsnElt.Make(AsnElt.SEQUENCE,
					AsnElt.MakeInteger(0),
					AsnElt.Make(AsnElt.SEQUENCE,
						AsnElt.MakeOID(OID_DSA),
						adp),
					AsnElt.MakeBlob(adx.Encode()));
				return apk8.Encode();
			} else {
				AsnElt adk = AsnElt.Make(AsnElt.SEQUENCE,
					AsnElt.MakeInteger(0),
					AsnElt.MakeInteger(dk.P),
					AsnElt.MakeInteger(dk.Q),
					AsnElt.MakeInteger(dk.G),
					AsnElt.MakeInteger(dk.PublicKey.Y),
					AsnElt.MakeInteger(dk.X));
				return adk.Encode();
			}
		*/
		} else if (ek != null) {
			/*
			 * The ECPrivateKey class guarantees that the
			 * private key X is already encoded with the same
			 * length as the subgroup order.
			 * The ECPublicKey class provides the public key
			 * as an already encoded point.
			 */
			AsnElt acc = AsnElt.MakeOID(CurveToOID(ek.Curve));
			AsnElt apv = AsnElt.MakeExplicit(AsnElt.CONTEXT, 1,
				AsnElt.MakeBitString(ek.PublicKey.Pub));
			if (pk8) {
				AsnElt aek = AsnElt.Make(AsnElt.SEQUENCE,
					AsnElt.MakeInteger(1),
					AsnElt.MakeBlob(ek.X),
					apv);
				AsnElt apk8 = AsnElt.Make(AsnElt.SEQUENCE,
					AsnElt.MakeInteger(0),
					AsnElt.Make(AsnElt.SEQUENCE,
						AsnElt.MakeOID(OID_EC),
						acc),
					AsnElt.MakeBlob(aek.Encode()));
				return apk8.Encode();
			} else {
				AsnElt aek = AsnElt.Make(AsnElt.SEQUENCE,
					AsnElt.MakeInteger(1),
					AsnElt.MakeBlob(ek.X),
					AsnElt.MakeExplicit(
						AsnElt.CONTEXT, 0, acc),
					apv);
				return aek.Encode();
			}
		} else {
			if (sk == null) {
				throw new NullReferenceException();
			}
			throw new ArgumentException("Cannot encode "
				+ sk.AlgorithmName + " private key");
		}
	}

	/*
	 * Encode the private key into a PEM object. If 'pk8' is true,
	 * then unencrypted PKCS#8 format is used, and the PEM header
	 * is "BEGIN PRIVATE KEY"; otherwise, the "internal" private key
	 * format is used, and the PEM header identifies the key type.
	 *
	 * If 'crlf' is true, then PEM lines end with CR+LF; otherwise,
	 * they end with LF only.
	 */
	public static string EncodePrivateKeyPEM(IPrivateKey sk,
		bool pk8, bool crlf)
	{
		byte[] enc = EncodePrivateKey(sk, pk8);
		string objType;
		if (pk8) {
			objType = "PRIVATE KEY";
		} else {
			objType = sk.AlgorithmName + " PRIVATE KEY";
		}
		return ToPEM(objType, enc, crlf ? "\r\n" : "\n");
	}

	/*
	 * Decode the provided private key. This method accepts both
	 * PKCS#8 and the "internal" format; the source object may be
	 * raw DER, Base64-encoded DER, or PEM. The key type is
	 * automatically detected.
	 */
	public static IPrivateKey DecodePrivateKey(byte[] enc)
	{
		string pemType;
		enc = AsnIO.FindBER(enc, false, out pemType);
		if (enc == null) {
			throw new AsnException("Not an encoded object");
		}
		AsnElt ak = AsnElt.Decode(enc);
		ak.CheckConstructed();
		if (pemType != null) {
			switch (pemType) {
			case "RSA PRIVATE KEY":
				return DecodePrivateKeyRSA(ak);
			/* disabled DSA
			case "DSA PRIVATE KEY":
				return DecodePrivateKeyDSA(ak);
			*/
			case "EC PRIVATE KEY":
				return DecodePrivateKeyEC(ak);
			case "PRIVATE KEY":
				return DecodePrivateKeyPKCS8(ak);
			default:
				throw new AsnException(
					"Unknown PEM object: " + pemType);
			}
		}
		if (ak.Sub.Length == 3
			&& ak.GetSub(0).TagValue == AsnElt.INTEGER
			&& ak.GetSub(1).TagValue == AsnElt.SEQUENCE
			&& ak.GetSub(2).TagValue == AsnElt.OCTET_STRING)
		{
			return DecodePrivateKeyPKCS8(ak);
		}
		if (ak.Sub.Length >= 9) {
			bool mayBeRSA = true;
			for (int i = 0; i < 9; i ++) {
				if (ak.GetSub(i).TagValue != AsnElt.INTEGER) {
					mayBeRSA = false;
					break;
				}
			}
			if (mayBeRSA) {
				return DecodePrivateKeyRSA(ak);
			}
		}
		/* disabled DSA
		if (ak.Sub.Length >= 6) {
			bool mayBeDSA = true;
			for (int i = 0; i < 6; i ++) {
				if (ak.GetSub(i).TagValue != AsnElt.INTEGER) {
					mayBeDSA = false;
					break;
				}
			}
			if (mayBeDSA) {
				return DecodePrivateKeyDSA(ak);
			}
		}
		*/
		if (ak.Sub.Length >= 2
			&& ak.GetSub(0).TagValue == AsnElt.INTEGER
			&& ak.GetSub(1).TagValue == AsnElt.OCTET_STRING)
		{
			return DecodePrivateKeyEC(ak);
		}
		throw new AsnException("Unrecognized private key format");
	}

	static RSAPrivateKey DecodePrivateKeyRSA(AsnElt ak)
	{
		ak.CheckNumSubMin(9);
		ak.GetSub(0).CheckTag(AsnElt.INTEGER);
		long kt = ak.GetSub(0).GetInteger();
		if (kt != 0) {
			throw new AsnException(
				"Unsupported RSA key type: " + kt);
		}
		ak.CheckNumSub(9);
		return new RSAPrivateKey(
			GetPositiveInteger(ak.GetSub(1)),
			GetPositiveInteger(ak.GetSub(2)),
			GetPositiveInteger(ak.GetSub(3)),
			GetPositiveInteger(ak.GetSub(4)),
			GetPositiveInteger(ak.GetSub(5)),
			GetPositiveInteger(ak.GetSub(6)),
			GetPositiveInteger(ak.GetSub(7)),
			GetPositiveInteger(ak.GetSub(8)));
	}

	/* disabled DSA
	static DSAPrivateKey DecodePrivateKeyDSA(AsnElt ak)
	{
		ak.CheckNumSubMin(6);
		for (int i = 0; i < 6; i ++) {
			ak.GetSub(i).CheckTag(AsnElt.INTEGER);
		}
		long kt = ak.GetSub(0).GetInteger();
		if (kt != 0) {
			throw new AsnException(
				"Unsupported DSA key type: " + kt);
		}
		DSAPrivateKey dsk = new DSAPrivateKey(
			GetPositiveInteger(ak.GetSub(1)),
			GetPositiveInteger(ak.GetSub(2)),
			GetPositiveInteger(ak.GetSub(3)),
			GetPositiveInteger(ak.GetSub(5)));
		DSAPublicKey dpk = dsk.PublicKey;
		if (BigInt.Compare(dpk.Y,
			GetPositiveInteger(ak.GetSub(4))) != 0)
		{
			throw new CryptoException(
				"DSA key pair public/private mismatch");
		}
		return dsk;
	}
	*/

	static ECPrivateKey DecodePrivateKeyEC(AsnElt ak)
	{
		return DecodePrivateKeyEC(ak, null);
	}

	static ECPrivateKey DecodePrivateKeyEC(AsnElt ak, ECCurve curve)
	{
		ak.CheckNumSubMin(2);
		ak.GetSub(0).CheckTag(AsnElt.INTEGER);
		ak.GetSub(1).CheckTag(AsnElt.OCTET_STRING);
		long kt = ak.GetSub(0).GetInteger();
		if (kt != 1) {
			throw new AsnException(
				"Unsupported EC key type: " + kt);
		}
		byte[] x = ak.GetSub(1).CopyValue();
		byte[] pub = null;
		int n = ak.Sub.Length;
		int p = 2;
		if (p < n) {
			AsnElt acc = ak.GetSub(p);
			if (acc.TagClass == AsnElt.CONTEXT
				&& acc.TagValue == 0)
			{
				acc.CheckNumSub(1);
				acc = acc.GetSub(0);
				ECCurve curve2 = DecodeCurve(acc);

				/*
				 * Here, we support only named curves.
				 */
				/* obsolete
				*/
				if (curve == null) {
					curve = curve2;
				} else if (!curve.Equals(curve2)) {
					throw new AsnException(string.Format(
						"Inconsistent curve"
						+ " specification ({0} / {1})",
						curve.Name, curve2.Name));
				}

				p ++;
			}
		}
		if (p < n) {
			AsnElt acc = ak.GetSub(p);
			if (acc.TagClass == AsnElt.CONTEXT
				&& acc.TagValue == 1)
			{
				acc.CheckNumSub(1);
				acc = acc.GetSub(0);
				acc.CheckTag(AsnElt.BIT_STRING);
				pub = acc.GetBitString();
			}
		}

		if (curve == null) {
			throw new AsnException("No curve specified for EC key");
		}
		ECPrivateKey esk = new ECPrivateKey(curve, x);
		if (pub != null) {
			ECPublicKey epk = new ECPublicKey(curve, pub);
			if (!epk.Equals(esk.PublicKey)) {
				throw new CryptoException(
					"EC key pair public/private mismatch");
			}
		}
		return esk;
	}

	static ECCurve DecodeCurve(AsnElt acc)
	{
		/*
		 * We support only named curves for now. PKIX does not
		 * want to see any other kind of curve anyway (see RFC
		 * 5480).
		 */
		acc.CheckTag(AsnElt.OBJECT_IDENTIFIER);
		string oid = acc.GetOID();
		return OIDToCurve(oid);
	}

	static IPrivateKey DecodePrivateKeyPKCS8(AsnElt ak)
	{
		ak.CheckNumSub(3);
		ak.GetSub(0).CheckTag(AsnElt.INTEGER);
		long v = ak.GetSub(0).GetInteger();
		if (v != 0) {
			throw new AsnException(
				"Unsupported PKCS#8 version: " + v);
		}
		AsnElt aai = ak.GetSub(1);
		aai.CheckTag(AsnElt.SEQUENCE);
		aai.CheckNumSubMin(1);
		aai.CheckNumSubMin(2);
		aai.GetSub(0).CheckTag(AsnElt.OBJECT_IDENTIFIER);
		string oid = aai.GetSub(0).GetOID();
		ak.GetSub(2).CheckTag(AsnElt.OCTET_STRING);
		byte[] rawKey = ak.GetSub(2).CopyValue();
		AsnElt ark = AsnElt.Decode(rawKey);

		switch (oid) {
		case OID_RSA:
		case OID_RSA_OAEP:
		case OID_RSA_PSS:
			return DecodePrivateKeyRSA(ark);
		/* disabled DSA
		case OID_DSA:
			return DecodePrivateKeyDSA(ark);
		*/
		case OID_EC:
			/*
			 * For elliptic curves, the parameters may
			 * include the curve specification.
			 */
			ECCurve curve = (aai.Sub.Length == 2)
				? DecodeCurve(aai.GetSub(1)) : null;
			return DecodePrivateKeyEC(ark, curve);
		default:
			throw new AsnException(
				"Unknown PKCS#8 key type: " + oid);
		}
	}

	/*
	 * Encode a public key as a SubjectPublicKeyInfo structure.
	 */
	public static AsnElt EncodePublicKey(IPublicKey pk)
	{
		RSAPublicKey rk = pk as RSAPublicKey;
		/* disabled DSA
		DSAPublicKey dk = pk as DSAPublicKey;
		*/
		ECPublicKey ek = pk as ECPublicKey;
		string oid;
		AsnElt app;
		byte[] pkv;
		if (rk != null) {
			oid = OID_RSA;
			app = AsnElt.NULL_V;
			pkv = AsnElt.Make(AsnElt.SEQUENCE,
				AsnElt.MakeInteger(rk.Modulus),
				AsnElt.MakeInteger(rk.Exponent)).Encode();
		/* disabled DSA
		} else if (dk != null) {
			oid = OID_DSA;
			app = AsnElt.Make(AsnElt.SEQUENCE,
				AsnElt.MakeInteger(dk.P),
				AsnElt.MakeInteger(dk.Q),
				AsnElt.MakeInteger(dk.G));
			pkv = AsnElt.MakeInteger(dk.Y).Encode();
		*/
		} else if (ek != null) {
			oid = OID_EC;
			app = AsnElt.MakeOID(CurveToOID(ek.Curve));
			pkv = ek.Pub;
		} else {
			throw new ArgumentException(
				"Cannot encode key type: " + pk.AlgorithmName);
		}
		AsnElt ai;
		if (app == null) {
			ai = AsnElt.Make(AsnElt.SEQUENCE,
				AsnElt.MakeOID(oid));
		} else {
			ai = AsnElt.Make(AsnElt.SEQUENCE,
				AsnElt.MakeOID(oid),
				app);
		}
		return AsnElt.Make(AsnElt.SEQUENCE,
			ai,
			AsnElt.MakeBitString(pkv));
	}

	/*
	 * Decode a public key (SubjectPublicKeyInfo).
	 */
	public static IPublicKey DecodePublicKey(byte[] spki)
	{
		string pemType = null;
		spki = AsnIO.FindBER(spki, false, out pemType);
		if (spki == null) {
			throw new AsnException("Not an encoded object");
		}
		return DecodePublicKey(AsnElt.Decode(spki));
	}

	/*
	 * Decode a public key (SubjectPublicKeyInfo).
	 */
	public static IPublicKey DecodePublicKey(AsnElt ak)
	{
		ak.CheckNumSub(2);
		AlgorithmIdentifier ai = new AlgorithmIdentifier(ak.GetSub(0));
		AsnElt abs = ak.GetSub(1);
		abs.CheckTag(AsnElt.BIT_STRING);
		byte[] pub = abs.GetBitString();
		switch (ai.OID) {
		case OID_RSA:
		case OID_RSA_OAEP:
		case OID_RSA_PSS:
			return DecodePublicKeyRSA(pub);
		/* disabled DSA
		case OID_DSA:
			return DecodePublicKeyDSA(pub);
		*/
		case OID_EC:
			/*
			 * For elliptic curves, the parameters should
			 * include the curve specification.
			 */
			AsnElt ap = ai.Parameters;
			if (ap == null) {
				throw new AsnException("No curve specified"
					+ " for EC public key");
			}
			if (ap.TagClass != AsnElt.UNIVERSAL
				|| ap.TagValue != AsnElt.OBJECT_IDENTIFIER)
			{
				throw new AsnException("Unsupported type"
					+ " of curve specification");
			}
			return new ECPublicKey(OIDToCurve(ap.GetOID()), pub);
		default:
			throw new AsnException(
				"Unknown public key type: " + ai.OID);
		}
	}

	static IPublicKey DecodePublicKeyRSA(byte[] pub)
	{
		AsnElt ae = AsnElt.Decode(pub);
		ae.CheckTag(AsnElt.SEQUENCE);
		ae.CheckNumSub(2);
		byte[] n = GetPositiveInteger(ae.GetSub(0));
		byte[] e = GetPositiveInteger(ae.GetSub(1));
		return new RSAPublicKey(n, e);
	}

	static string CurveToOID(ECCurve curve)
	{
		switch (curve.Name) {
		case "P-192":
			return "1.2.840.10045.3.1.1";
		case "P-224":
			return "1.3.132.0.33";
		case "P-256":
			return "1.2.840.10045.3.1.7";
		case "P-384":
			return "1.3.132.0.34";
		case "P-521":
			return "1.3.132.0.35";
		}
		throw new ArgumentException(string.Format(
			"No known OID for curve '{0}'", curve.Name));
	}

	static ECCurve OIDToCurve(string oid)
	{
		switch (oid) {
		/*
		case "1.2.840.10045.3.1.1":
			return NIST.P192;
		case "1.3.132.0.33":
			return NIST.P224;
		*/
		case "1.2.840.10045.3.1.7":
			return NIST.P256;
		case "1.3.132.0.34":
			return NIST.P384;
		case "1.3.132.0.35":
			return NIST.P521;
		}
		throw new ArgumentException(string.Format(
			"No known curve for OID {0}", oid));
	}

	static byte[] GetPositiveInteger(AsnElt ae)
	{
		ae.CheckTag(AsnElt.INTEGER);
		byte[] x = ae.CopyValue();
		if (x.Length == 0) {
			throw new AsnException("Invalid integer (empty)");
		}
		if (x[0] >= 0x80) {
			throw new AsnException("Invalid integer (negative)");
		}
		return x;
	}

	static int Dec16be(byte[] buf, int off)
	{
		return (buf[off] << 8) + buf[off + 1];
	}

	static int Dec24be(byte[] buf, int off)
	{
		return (buf[off] << 16) + (buf[off + 1] << 8) + buf[off + 2];
	}

	const string B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		+ "abcdefghijklmnopqrstuvwxyz0123456789+/";

	public static string ToBase64(byte[] buf, int off, int len)
	{
		char[] tc = new char[((len + 2) / 3) << 2];
		for (int i = 0, j = 0; i < len; i += 3) {
			if ((i + 3) <= len) {
				int x = Dec24be(buf, off + i);
				tc[j ++] = B64[x >> 18];
				tc[j ++] = B64[(x >> 12) & 0x3F];
				tc[j ++] = B64[(x >> 6) & 0x3F];
				tc[j ++] = B64[x & 0x3F];
			} else if ((i + 2) == len) {
				int x = Dec16be(buf, off + i);
				tc[j ++] = B64[x >> 10];
				tc[j ++] = B64[(x >> 4) & 0x3F];
				tc[j ++] = B64[(x << 2) & 0x3F];
				tc[j ++] = '=';
			} else if ((i + 1) == len) {
				int x = buf[off + i];
				tc[j ++] = B64[(x >> 2) & 0x3F];
				tc[j ++] = B64[(x << 4) & 0x3F];
				tc[j ++] = '=';
				tc[j ++] = '=';
			}
		}
		return new string(tc);
	}

	public static void WritePEM(TextWriter w, string objType, byte[] buf)
	{
		w.WriteLine("-----BEGIN {0}-----", objType.ToUpperInvariant());
		int n = buf.Length;
		for (int i = 0; i < n; i += 57) {
			int len = Math.Min(57, n - i);
			w.WriteLine(ToBase64(buf, i, len));
		}
		w.WriteLine("-----END {0}-----", objType.ToUpperInvariant());
	}

	public static string ToPEM(string objType, byte[] buf)
	{
		return ToPEM(objType, buf, "\n");
	}

	public static string ToPEM(string objType, byte[] buf, string nl)
	{
		StringWriter w = new StringWriter();
		w.NewLine = nl;
		WritePEM(w, objType, buf);
		return w.ToString();
	}
}

}
