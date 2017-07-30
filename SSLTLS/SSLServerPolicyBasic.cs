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
using System.Collections.Generic;
using System.IO;

using Crypto;

namespace SSLTLS {

/*
 * Basic implementation of IServerPolicy: it uses a single certificate
 * chain and a software private key.
 */

public class SSLServerPolicyBasic : IServerPolicy {

	byte[][] chain;
	IPrivateKey skey;
	bool canSign, canEncrypt;

	/*
	 * Create the policy instance, with the provided certificate chain,
	 * private key, and allowed key usages.
	 */
	public SSLServerPolicyBasic(byte[][] chain,
		IPrivateKey skey, KeyUsage usage)
	{
		this.chain = chain;
		this.skey = skey;
		canEncrypt = false;
		canSign = false;
		switch (usage) {
		case KeyUsage.EncryptOnly:
			canEncrypt = true;
			break;
		case KeyUsage.SignOnly:
			canSign = true;
			break;
		case KeyUsage.EncryptAndSign:
			canEncrypt = true;
			canSign = true;
			break;
		}
	}

	public IServerChoices Apply(SSLServer server)
	{
		/*
		 * Conditions for selecting a cipher suite:
		 *
		 *   RSA           canEncrypt, key is RSA
		 *
		 *   ECDH          canEncrypt, key is EC, curve supported
		 *
		 *   ECDHE_RSA     canSign, key is RSA, have hash+RSA algo
		 *
		 *   ECDHE_ECDSA   canSign, key is EC, have hash+ECDSA algo,
		 *                 curve supported
		 *
		 * The engine already filtered things, so we know that:
		 *
		 *  - if an ECDHE suite is present, then there is a common
		 *    supported curve;
		 *
		 *  - if an ECDHE_RSA suite is present, then there is a
		 *    common hash+RSA algorithm;
		 *
		 *  - if an ECDHE_ECDSA suite is present, then there is a
		 *    common hash+ECDSA algorithm.
		 *
		 * We must still walk the list of algorithm to determine the
		 * proper hash to use for signatures; we also need to check
		 * that our EC curve is supported by the client.
		 */
		int curveID = -1;
		if (skey is ECPrivateKey) {
			curveID = SSL.CurveToID(((ECPrivateKey)skey).Curve);
		}
		bool canRSA = canEncrypt && (skey is RSAPrivateKey);
		bool canECDH = canEncrypt && (skey is ECPrivateKey)
			&& server.ClientCurves.Contains(curveID);
		bool canECDHE_RSA = canSign && (skey is RSAPrivateKey);
		bool canECDHE_ECDSA = canSign && (skey is ECPrivateKey);

		foreach (int cs in server.CommonCipherSuites) {
			if (SSL.IsRSA(cs)) {
				if (!canRSA) {
					continue;
				}
				return new ChoicesRSA(server.ClientVersionMax,
					cs, chain, skey as RSAPrivateKey);
			} else if (SSL.IsECDH(cs)) {
				if (!canECDH) {
					continue;
				}
				return new ChoicesECDH(cs, chain,
					skey as ECPrivateKey);
			} else if (SSL.IsECDHE_RSA(cs)) {
				if (!canECDHE_RSA) {
					continue;
				}
				int hashAlgo;
				if (server.Version <= SSL.TLS11) {
					hashAlgo = SSL.MD5SHA1;
				} else {
					hashAlgo = SelectHash(
						server.ClientHashAndSign,
						SSL.RSA);
				}
				return new ChoicesSign(cs, chain,
					hashAlgo, skey);
			} else if (SSL.IsECDHE_ECDSA(cs)) {
				if (!canECDHE_ECDSA) {
					continue;
				}
				int hashAlgo;
				if (server.Version <= SSL.TLS11) {
					hashAlgo = SSL.SHA1;
				} else {
					hashAlgo = SelectHash(
						server.ClientHashAndSign,
						SSL.ECDSA);
				}
				return new ChoicesSign(cs, chain,
					hashAlgo, skey);
			}
		}

		throw new SSLException("No suitable cipher suite");
	}

	static int SelectHash(List<int> hsl, int sigAlg)
	{
		foreach (int x in hsl) {
			if ((x & 0xFF) == sigAlg) {
				return x >> 8;
			}
		}

		/*
		 * This should never happen, because the offending
		 * cipher suites would have been filtered by the engine.
		 */
		throw new Exception();
	}
}

class ChoicesBase {

	int cipherSuite;
	byte[][] chain;

	internal ChoicesBase(int cipherSuite, byte[][] chain)
	{
		this.cipherSuite = cipherSuite;
		this.chain = chain;
	}

	public int GetCipherSuite()
	{
		return cipherSuite;
	}

	public byte[][] GetCertificateChain()
	{
		return chain;
	}

	public virtual byte[] DoKeyExchange(byte[] cke)
	{
		throw new Exception();
	}

	public virtual byte[] DoSign(byte[] ske,
		out int hashAlgo, out int sigAlgo)
	{
		throw new Exception();
	}
}

class ChoicesRSA : ChoicesBase, IServerChoices {

	int clientVersionMax;
	RSAPrivateKey rk;

	internal ChoicesRSA(int clientVersionMax, int cipherSuite,
		byte[][] chain, RSAPrivateKey rk)
		: base(cipherSuite, chain)
	{
		this.clientVersionMax = clientVersionMax;
		this.rk = rk;
	}

	public override byte[] DoKeyExchange(byte[] cke)
	{
		if (cke.Length < 59) {
			throw new CryptoException(
				"Invalid ClientKeyExchange (too short)");
		}
		RSA.DoPrivate(rk, cke);

		/*
		 * Constant-time check for PKCS#1 v1.5 padding. z is set
		 * to -1 if the padding is correct, 0 otherwise. We also
		 * check the two first PMS byte (they should be equal to
		 * the maximum protocol version announced by the client
		 * in its ClientHello).
		 */
		int z = 0;
		z |= cke[0];
		z |= cke[1] ^ 0x02;
		for (int i = 2; i < cke.Length - 49; i ++) {
			int y = cke[i];
			z |= ~((y | -y) >> 31);
		}
		z |= cke[cke.Length - 49];
		z |= cke[cke.Length - 48] ^ (clientVersionMax >> 8);
		z |= cke[cke.Length - 47] ^ (clientVersionMax & 0xFF);
		z = ~((z | -z) >> 31);

		/*
		 * Get a random premaster, then overwrite it with the
		 * decrypted value, but only if the padding was correct.
		 */
		byte[] pms = new byte[48];
		RNG.GetBytes(pms);
		for (int i = 0; i < 48; i ++) {
			int x = pms[i];
			int y = cke[cke.Length - 48 + i];
			pms[i] = (byte)(x ^ (z & (x ^ y)));
		}

		return pms;
	}
}

class ChoicesECDH : ChoicesBase, IServerChoices {

	ECPrivateKey ek;

	internal ChoicesECDH(int cipherSuite, byte[][] chain, ECPrivateKey ek)
		: base(cipherSuite, chain)
	{
		this.ek = ek;
	}

	public override byte[] DoKeyExchange(byte[] cke)
	{
		ECCurve curve = ek.Curve;
		byte[] tmp = new byte[curve.EncodedLength];
		if (curve.Mul(cke, ek.X, tmp, false) == 0) {
			throw new SSLException(
				"Invalid ClientKeyExchange EC point value");
		}
		int xlen;
		int xoff = curve.GetXoff(out xlen);
		byte[] pms = new byte[xlen];
		Array.Copy(tmp, xoff, pms, 0, xlen);
		return pms;
	}
}

class ChoicesSign : ChoicesBase, IServerChoices {

	int hashAlgo;
	IPrivateKey skey;

	internal ChoicesSign(int cipherSuite, byte[][] chain,
		int hashAlgo, IPrivateKey skey)
		: base(cipherSuite, chain)
	{
		this.hashAlgo = hashAlgo;
		this.skey = skey;
	}

	public override byte[] DoSign(byte[] ske,
		out int hashAlgo, out int signAlgo)
	{
		hashAlgo = this.hashAlgo;
		byte[] hv = Hash(hashAlgo, ske);
		if (skey is RSAPrivateKey) {
			RSAPrivateKey rk = skey as RSAPrivateKey;
			signAlgo = SSL.RSA;
			byte[] head;
			switch (hashAlgo) {
			case SSL.MD5SHA1: head = null; break;
			case SSL.SHA1:    head = RSA.PKCS1_SHA1; break;
			case SSL.SHA224:  head = RSA.PKCS1_SHA224; break;
			case SSL.SHA256:  head = RSA.PKCS1_SHA256; break;
			case SSL.SHA384:  head = RSA.PKCS1_SHA384; break;
			case SSL.SHA512:  head = RSA.PKCS1_SHA512; break;
			default:
				throw new Exception();
			}
			return RSA.Sign(rk, head, hv);
		} else if (skey is ECPrivateKey) {
			ECPrivateKey ek = skey as ECPrivateKey;
			signAlgo = SSL.ECDSA;
			return ECDSA.Sign(ek, null, hv);
		} else {
			throw new Exception("NYI");
		}
	}

	static byte[] Hash(int hashAlgo, byte[] data)
	{
		switch (hashAlgo) {
		case SSL.MD5SHA1:
			byte[] hv = new byte[36];
			MD5 md5 = new MD5();
			SHA1 sha1 = new SHA1();
			md5.Update(data);
			md5.DoFinal(hv, 0);
			sha1.Update(data);
			sha1.DoFinal(hv, 16);
			return hv;
		case SSL.MD5:
			return new MD5().Hash(data);
		case SSL.SHA1:
			return new SHA1().Hash(data);
		case SSL.SHA224:
			return new SHA224().Hash(data);
		case SSL.SHA256:
			return new SHA256().Hash(data);
		case SSL.SHA384:
			return new SHA384().Hash(data);
		case SSL.SHA512:
			return new SHA512().Hash(data);
		default:
			throw new Exception("NYI");
		}
	}
}

}
