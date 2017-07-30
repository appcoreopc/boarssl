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
using System.Text;

using Crypto;

namespace SSLTLS {

/*
 * Class for a SSL client connection.
 *
 * An instance is created over a specified transport stream. SSL session
 * parameters from a previous connection are optionally specified, to
 * attempt session resumption. The instance handles the connection but
 * cannot be "revived" after the connection was closed (the session
 * parameters, though, can be extracted and used with another instance).
 */

public class SSLClient : SSLEngine {

	/*
	 * Create the client over the provided stream. No attempt at
	 * session resumption will be made.
	 */
	public SSLClient(Stream sub) : this(sub, null)
	{
	}

	/*
	 * Create the client over the provided stream. If the
	 * 'sessionParameters' are not null, then the client will try to
	 * resume that session. Note that session parameters may include
	 * a "target server name", in which case the ServerName
	 * property will be set to that name, which will be included
	 * in the ClientHello as the Server Name Indication extension.
	 */
	public SSLClient(Stream sub, SSLSessionParameters sessionParameters)
		: base(sub)
	{
		sentExtensions = new List<int>();
		resumeParams = sessionParameters;
		if (resumeParams != null) {
			string name = resumeParams.ServerName;
			if (name != null) {
				ServerName = name;
			}
		}
	}

	/*
	 * Validator for the server certificate. This callback is
	 * responsible for obtaining the server's public key and making
	 * sure it is the right one. A normal, standard-compliant
	 * implementation should do the following:
	 *
	 * -- Validate the certificate as X.509 mandates (building
	 * a path to a trust anchor, and verifying all signatures, names
	 * and appropriate certificate extensions; also obtaining
	 * proper CRL or OCSP response for a fresh revocation status).
	 *
	 * -- Check that the intended server name (provided in the
	 * 'serverName' parameter) matches that which is found in the
	 * certificate (see RFC 2818 section 3.1 for details; also
	 * consider RFC 6125 section 6.4).
	 *
	 * -- Return the public key found in the server's certificate,
	 * along with its allowed usages (which may depend on the
	 * KeyUsage extensions found in the certificate).
	 *
	 * The certificate chain, as received from the server, is
	 * provided as parameter; it is non-empty (it contains at least
	 * one certificate). The server's certificate is the first one
	 * in the chain.
	 *
	 * The 'serverName' parameter is the intended server name, to
	 * match against the names found in the certificate. If it is
	 * null, then no matching is expected (this correspond to the
	 * ServerName property in this SSLClient instance).
	 *
	 * The 'usage' variable shall be set to a value that qualifies
	 * whether the key may be used for encryption and/or signatures.
	 */
	public delegate IPublicKey CertValidator(
		byte[][] chain, string serverName, out KeyUsage usage);
	public CertValidator ServerCertValidator {
		get; set;
	}

	/*
	 * A simple INSECURE certificate "validator" that does not validate
	 * anything: the public key is extracted and returned, with no
	 * other checks. THIS IS FOR TESTS ONLY. Using this validator
	 * basically voids all security properties of SSL.
	 */
	public static IPublicKey InsecureCertValidator(
		byte[][] chain, string serverName, out KeyUsage usage)
	{
		usage = KeyUsage.EncryptAndSign;
		return SSL.GetKeyFromCert(chain[0]);
	}

	List<int> sentExtensions;
	SSLSessionParameters resumeParams;

	internal override bool IsClient {
		get {
			return true;
		}
	}

	internal override bool DoHandshake()
	{
		CheckConfigHashAndSign();

		ResetHashes();
		MakeRandom(clientRandom);

		SendClientHello();
		FlushSub();

		bool resume;
		if (!ParseServerHello(out resume)) {
			return false;
		}
		HandshakeCount ++;
		if (resume) {
			/*
			 * Abbreviated handshake.
			 */
			ParseCCSAndFinished();
			SendCCSAndFinished();
			FlushSub();
			SetAppData();
			IsResume = true;
			return true;
		}

		KeyUsage usage;
		IPublicKey pkey = ParseCertificate(out usage);

		ECCurve curve;
		byte[] serverPoint;
		if (SSL.IsECDHE_RSA(CipherSuite)) {
			if (!(pkey is RSAPublicKey)) {
				throw new SSLException(
					"ECDHE_RSA needs a RSA public key");
			}
			if (usage != KeyUsage.SignOnly
				&& usage != KeyUsage.EncryptAndSign)
			{
				throw new SSLException("Server public key"
					+ " unfit for signatures");
			}
			serverPoint = ParseServerKeyExchange(out curve, pkey);
		} else if (SSL.IsECDHE_ECDSA(CipherSuite)) {
			if (!(pkey is ECPublicKey)) {
				throw new SSLException(
					"ECDHE_ECDSA needs an EC public key");
			}
			if (usage != KeyUsage.SignOnly
				&& usage != KeyUsage.EncryptAndSign)
			{
				throw new SSLException("Server public key"
					+ " unfit for signatures");
			}
			serverPoint = ParseServerKeyExchange(out curve, pkey);
		} else {
			curve = null;
			serverPoint = null;
		}

		bool reqClientCert = false;
		int mt;
		byte[] msg = ReadHandshakeMessage(out mt);
		if (mt == SSL.CERTIFICATE_REQUEST) {
			/*
			 * FIXME: parse message and select a client
			 * certificate.
			 */
			reqClientCert = true;
			msg = ReadHandshakeMessage(out mt);
		}
		if (mt != SSL.SERVER_HELLO_DONE) {
			throw new SSLException(string.Format("Unexpected"
				+ " handshake message {0}"
				+ " (expected: ServerHelloDone)", mt));
		}
		if (msg.Length != 0) {
			throw new SSLException(
				"Invalid ServerHelloDone (not empty)");
		}

		if (reqClientCert) {
			/*
			 * FIXME: right now, we send an empty Certificate
			 * message if the server asks for a client
			 * certificate; i.e., we claim we have none.
			 */
			MemoryStream ms =
				StartHandshakeMessage(SSL.CERTIFICATE);
			EndHandshakeMessage(ms);
		}

		if (SSL.IsRSA(CipherSuite)) {
			if (!(pkey is RSAPublicKey)) {
				throw new SSLException(
					"Server public key is not RSA");
			}
			if (usage != KeyUsage.EncryptOnly
				&& usage != KeyUsage.EncryptAndSign)
			{
				throw new SSLException("Server public key is"
					+ " not allowed for encryption");
			}
			SendClientKeyExchangeRSA(pkey as RSAPublicKey);
		} else if (SSL.IsECDH(CipherSuite)) {
			if (!(pkey is ECPublicKey)) {
				throw new SSLException(
					"Server public key is not EC");
			}
			if (usage != KeyUsage.EncryptOnly
				&& usage != KeyUsage.EncryptAndSign)
			{
				throw new SSLException("Server public key is"
					+ " not allowed for key exchange");
			}
			SendClientKeyExchangeECDH(pkey as ECPublicKey);
		} else if (serverPoint != null) {
			SendClientKeyExchangeECDH(curve, serverPoint);
		} else {
			/*
			 * TODO: Maybe support DHE cipher suites?
			 */
			throw new Exception("NYI");
		}

		/*
		 * FIXME: when client certificates are supported, we
		 * will need to send a CertificateVerify message here.
		 */

		SendCCSAndFinished();
		FlushSub();

		ParseCCSAndFinished();
		SetAppData();
		IsResume = false;

		return true;
	}

	void SendClientHello()
	{
		MemoryStream ms = StartHandshakeMessage(SSL.CLIENT_HELLO);

		// Maximum supported protocol version.
		IO.Write16(ms, VersionMax);

		// Client random.
		ms.Write(clientRandom, 0, clientRandom.Length);

		// Session ID.
		if (resumeParams != null) {
			byte[] id = resumeParams.SessionID;
			ms.WriteByte((byte)id.Length);
			ms.Write(id, 0, id.Length);
		} else {
			ms.WriteByte(0x00);
		}

		// List of supported cipher suites.
		int csLen = SupportedCipherSuites.Length << 1;
		int extraCS = GetQuirkInt("sendExtraCipherSuite", -1);
		if (extraCS >= 0) {
			csLen += 2;
		}
		IO.Write16(ms, csLen);
		foreach (int cs in SupportedCipherSuites) {
			IO.Write16(ms, cs);
		}
		if (extraCS >= 0) {
			IO.Write16(ms, extraCS);
		}

		// List of supported compression algorithms.
		ms.WriteByte(0x01);
		ms.WriteByte(0x00);

		// Extensions
		sentExtensions.Clear();
		MemoryStream chExt = new MemoryStream();

		// Server Name Indication
		if (ServerName != null && ServerName.Length > 0) {
			byte[] encName = Encoding.UTF8.GetBytes(ServerName);
			int elen = encName.Length;
			if (elen > 65530) {
				throw new SSLException("Oversized server name");
			}
			sentExtensions.Add(0x0000);
			IO.Write16(chExt, 0x0000);    // extension type
			IO.Write16(chExt, elen + 5);  // extension length
			IO.Write16(chExt, elen + 3);  // name list length
			chExt.WriteByte(0x00);        // name type
			IO.Write16(chExt, elen);      // name length
			chExt.Write(encName, 0, elen);
		}

		// Supported Curves and Supported Point Formats
		if (SupportedCurves != null && SupportedCurves.Length > 0) {
			int len = SupportedCurves.Length;
			sentExtensions.Add(0x000A);
			IO.Write16(chExt, 0x000A);
			IO.Write16(chExt, (len << 1) + 2);
			IO.Write16(chExt, len << 1);
			foreach (int cc in SupportedCurves) {
				IO.Write16(chExt, cc);
			}

			sentExtensions.Add(0x000B);
			IO.Write16(chExt, 0x000B);
			IO.Write16(chExt, 2);
			chExt.WriteByte(1);
			chExt.WriteByte(0x00);
		}

		// Supported Signatures
		if (VersionMax >= SSL.TLS12 && SupportedHashAndSign != null
			&& SupportedHashAndSign.Length > 0)
		{
			sentExtensions.Add(0x000D);
			IO.Write16(chExt, 0x000D);
			int num = SupportedHashAndSign.Length;
			IO.Write16(chExt, 2 + (num << 1));
			IO.Write16(chExt, num << 1);
			foreach (int hs in SupportedHashAndSign) {
				IO.Write16(chExt, hs);
			}
		}

		// Secure renegotiation
		if (!GetQuirkBool("noSecureReneg")) {
			sentExtensions.Add(0xFF01);
			IO.Write16(chExt, 0xFF01);
			byte[] exv;
			if (renegSupport > 0) {
				exv = savedClientFinished;
			} else {
				exv = new byte[0];
			}

			if (GetQuirkBool("forceEmptySecureReneg")) {
				exv = new byte[0];
			} else if (GetQuirkBool("forceNonEmptySecureReneg")) {
				exv = new byte[12];
			} else if (GetQuirkBool("alterNonEmptySecureReneg")) {
				if (exv.Length > 0) {
					exv[exv.Length - 1] ^= 0x01;
				}
			} else if (GetQuirkBool("oversizedSecureReneg")) {
				exv = new byte[255];
			}

			IO.Write16(chExt, exv.Length + 1);
			chExt.WriteByte((byte)exv.Length);
			chExt.Write(exv, 0, exv.Length);
		}

		// Extra extension with random contents.
		int extraExt = GetQuirkInt("sendExtraExtension", -1);
		if (extraExt >= 0) {
			byte[] exv = new byte[extraExt >> 16];
			RNG.GetBytes(exv);
			IO.Write16(chExt, extraExt & 0xFFFF);
			IO.Write16(chExt, exv.Length);
			chExt.Write(exv, 0, exv.Length);
		}

		// Max Fragment Length
		// ALPN
		// FIXME

		byte[] encExt = chExt.ToArray();
		if (encExt.Length > 0) {
			if (encExt.Length > 65535) {
				throw new SSLException("Oversized extensions");
			}
			IO.Write16(ms, encExt.Length);
			ms.Write(encExt, 0, encExt.Length);
		}

		EndHandshakeMessage(ms);
	}

	bool ParseServerHello(out bool resume)
	{
		resume = false;

		int mt;
		byte[] msg = ReadHandshakeMessage(out mt, FirstHandshakeDone);
		if (msg == null) {
			/*
			 * Server denies attempt explicitly.
			 */
			return false;
		}
		if (mt != SSL.SERVER_HELLO) {
			throw new SSLException(string.Format("Unexpected"
				+ " handshake message {0} (expecting a"
				+ " ServerHello)", mt));
		}

		if (msg.Length < 38) {
			throw new SSLException("Truncated ServerHello");
		}
		Version = IO.Dec16be(msg, 0);
		if (Version < VersionMin || Version > VersionMax) {
			throw new SSLException(string.Format(
				"Unsupported version: 0x{0:X4}", Version));
		}
		Array.Copy(msg, 2, serverRandom, 0, 32);
		int idLen = msg[34];
		if (idLen > 32) {
			throw new SSLException("Invalid session ID length");
		}
		if (idLen + 38 > msg.Length) {
			throw new SSLException("Truncated ServerHello");
		}
		sessionID = new byte[idLen];
		Array.Copy(msg, 35, sessionID, 0, idLen);
		int off = 35 + idLen;

		/*
		 * Cipher suite. It must be one of the suites we sent.
		 */
		CipherSuite = IO.Dec16be(msg, off);
		off += 2;
		bool found = false;
		foreach (int cs in SupportedCipherSuites) {
			if (cs == SSL.FALLBACK_SCSV
				|| cs == SSL.EMPTY_RENEGOTIATION_INFO_SCSV)
			{
				continue;
			}
			if (cs == CipherSuite) {
				found = true;
				break;
			}
		}
		if (!found) {
			throw new SSLException(string.Format(
				"Server selected cipher suite 0x{0:X4}"
				+ " which we did not advertise", CipherSuite));
		}

		/*
		 * Compression. Must be 0, since we do not support it.
		 */
		int comp = msg[off ++];
		if (comp != 0x00) {
			throw new SSLException(string.Format(
				"Server selected compression {0}"
				+ " which we did not advertise", comp));
		}

		/*
		 * Extensions. Each extension from the server should
		 * correspond to an extension sent in the ClientHello.
		 */
		bool secReneg = false;
		if (msg.Length > off) {
			if (msg.Length == off + 1) {
				throw new SSLException("Truncated ServerHello");
			}
			int tlen = IO.Dec16be(msg, off);
			off += 2;
			if (tlen != msg.Length - off) {
				throw new SSLException(
					"Invalid extension list length");
			}
			while (off < msg.Length) {
				if ((off + 4) > msg.Length) {
					throw new SSLException(
						"Truncated extention");
				}
				int etype = IO.Dec16be(msg, off);
				int elen = IO.Dec16be(msg, off + 2);
				off += 4;
				if (elen > msg.Length - off) {
					throw new SSLException(
						"Truncated extention");
				}
				if (!sentExtensions.Contains(etype)) {
					throw new SSLException(string.Format(
						"Server send unadvertised"
						+ " extenstion 0x{0:X4}",
						etype));
				}

				/*
				 * We have some processing to do on some
				 * specific server-side extensions.
				 */
				switch (etype) {

				case 0xFF01:
					secReneg = true;
					ParseExtSecureReneg(msg, off, elen);
					break;
				}

				off += elen;
			}
		}

		/*
		 * Renegotiation support: if we did not get the extension
		 * from the server, then secure renegotiation is
		 * definitely not supported. If it _was_ known as
		 * being supported (from a previous handshake) then this
		 * is a fatal error.
		 */
		if (!secReneg) {
			if (renegSupport > 0) {
				throw new SSLException("Missing Secure"
					+ " Renegotiation extension");
			}
			renegSupport = -1;
		}

		/*
		 * Check whether this is a session resumption: a session
		 * is resumed if we sent a non-empty session ID, and the
		 * ServerHello contained the same session ID.
		 *
		 * In case of resumption, the ServerHello must use the
		 * same version and cipher suite than in the saved
		 * parameters.
		 */
		if (resumeParams != null) {
			byte[] id = resumeParams.SessionID;
			if (id.Length > 0 && IO.Eq(id, sessionID)) {
				if (Version != resumeParams.Version) {
					throw new SSLException(
						"Resume version mismatch");
				}
				if (CipherSuite != resumeParams.CipherSuite) {
					throw new SSLException(
						"Resume cipher suite mismatch");
				}
				SetMasterSecret(resumeParams.MasterSecret);
				resume = true;
			}
		}

		return true;
	}

	void ParseExtSecureReneg(byte[] buf, int off, int len)
	{
		if (len < 1 || len != 1 + buf[off]) {
			throw new SSLException(
				"Invalid Secure Renegotiation extension");
		}
		len --;
		off ++;

		if (renegSupport == 0) {
			/*
			 * Initial handshake: extension MUST be empty.
			 */
			if (len != 0) {
				throw new SSLException(
					"Non-empty Secure Renegotation"
					+ " on initial handshake");
			}
			renegSupport = 1;
		} else {
			/*
			 * Renegotiation: extension MUST contain the
			 * concatenation of the saved client and
			 * server Finished messages (in that order).
			 */
			if (len != 24) {
				throw new SSLException(
					"Wrong Secure Renegotiation value");
			}
			int z = 0;
			for (int i = 0; i < 12; i ++) {
				z |= savedClientFinished[i] ^ buf[off + i];
				z |= savedServerFinished[i] ^ buf[off + 12 + i];
			}
			if (z != 0) {
				throw new SSLException(
					"Wrong Secure Renegotiation value");
			}
		}
	}

	IPublicKey ParseCertificate(out KeyUsage usage)
	{
		byte[] msg = ReadHandshakeMessageExpected(SSL.CERTIFICATE);
		if (msg.Length < 3) {
			throw new SSLException("Invalid Certificate message");
		}
		int tlen = IO.Dec24be(msg, 0);
		int off = 3;
		if (tlen != msg.Length - off) {
			throw new SSLException("Invalid Certificate message");
		}
		List<byte[]> certs = new List<byte[]>();
		while (off < msg.Length) {
			if (msg.Length - off < 3) {
				throw new SSLException(
					"Invalid Certificate message");
			}
			int clen = IO.Dec24be(msg, off);
			off += 3;
			if (clen > msg.Length - off) {
				throw new SSLException(
					"Invalid Certificate message");
			}
			byte[] ec = new byte[clen];
			Array.Copy(msg, off, ec, 0, clen);
			off += clen;
			certs.Add(ec);
		}

		return ServerCertValidator(
			certs.ToArray(), ServerName, out usage);
	}

	byte[] ParseServerKeyExchange(out ECCurve curve, IPublicKey pkey)
	{
		byte[] msg = ReadHandshakeMessageExpected(
			SSL.SERVER_KEY_EXCHANGE);
		if (msg.Length < 4) {
			throw new SSLException(
				"Invalid ServerKeyExchange message");
		}
		if (msg[0] != 0x03) {
			throw new SSLException("Unsupported unnamed curve");
		}
		curve = SSL.GetCurveByID(IO.Dec16be(msg, 1));
		int plen = msg[3];
		int off = 4;
		if (msg.Length - off < plen) {
			throw new SSLException(
				"Invalid ServerKeyExchange message");
		}
		byte[] point = new byte[plen];
		Array.Copy(msg, off, point, 0, plen);
		off += plen;
		int slen = off;

		int hashId, sigId;
		if (Version >= SSL.TLS12) {
			if (msg.Length - off < 2) {
				throw new SSLException(
					"Invalid ServerKeyExchange message");
			}
			hashId = msg[off ++];
			if (hashId == 0) {
				throw new SSLException(
					"Invalid hash identifier");
			}
			sigId = msg[off ++];
		} else {
			if (pkey is RSAPublicKey) {
				hashId = 0;
				sigId = 1;
			} else if (pkey is ECPublicKey) {
				hashId = 2;
				sigId = 3;
			} else {
				throw new SSLException(
					"Unsupported signature key type");
			}
		}
		
		if (msg.Length - off < 2) {
			throw new SSLException(
				"Invalid ServerKeyExchange message");
		}
		int sigLen = IO.Dec16be(msg, off);
		off += 2;
		if (sigLen != msg.Length - off) {
			throw new SSLException(
				"Invalid ServerKeyExchange message");
		}
		byte[] sig = new byte[sigLen];
		Array.Copy(msg, off, sig, 0, sigLen);

		byte[] hv;
		if (hashId == 0) {
			MD5 md5 = new MD5();
			SHA1 sha1 = new SHA1();
			md5.Update(clientRandom);
			md5.Update(serverRandom);
			md5.Update(msg, 0, slen);
			sha1.Update(clientRandom);
			sha1.Update(serverRandom);
			sha1.Update(msg, 0, slen);
			hv = new byte[36];
			md5.DoFinal(hv, 0);
			sha1.DoFinal(hv, 16);
		} else {
			IDigest h = SSL.GetHashByID(hashId);
			h.Update(clientRandom);
			h.Update(serverRandom);
			h.Update(msg, 0, slen);
			hv = h.DoFinal();
		}

		bool ok;
		if (sigId == 1) {
			RSAPublicKey rpk = pkey as RSAPublicKey;
			if (rpk == null) {
				throw new SSLException(
					"Wrong public key type for RSA");
			}
			if (hashId == 0) {
				ok = RSA.VerifyND(rpk, hv, sig);
			} else {
				byte[] head1, head2;

				switch (hashId) {
				case 1:
					head1 = RSA.PKCS1_MD5;
					head2 = RSA.PKCS1_MD5_ALT;
					break;
				case 2:
					head1 = RSA.PKCS1_SHA1;
					head2 = RSA.PKCS1_SHA1_ALT;
					break;
				case 3:
					head1 = RSA.PKCS1_SHA224;
					head2 = RSA.PKCS1_SHA224_ALT;
					break;
				case 4:
					head1 = RSA.PKCS1_SHA256;
					head2 = RSA.PKCS1_SHA256_ALT;
					break;
				case 5:
					head1 = RSA.PKCS1_SHA384;
					head2 = RSA.PKCS1_SHA384_ALT;
					break;
				case 6:
					head1 = RSA.PKCS1_SHA512;
					head2 = RSA.PKCS1_SHA512_ALT;
					break;
				default:
					throw new SSLException(
						"Unsupported hash algorithm: "
						+ hashId);
				}
				ok = RSA.Verify(rpk, head1, head2, hv, sig);
			}
		} else if (sigId == 3) {
			ECPublicKey epk = pkey as ECPublicKey;
			if (epk == null) {
				throw new SSLException(
					"Wrong public key type for ECDSA");
			}
			ok = ECDSA.Verify(epk, hv, sig);
		} else {
			throw new SSLException(
				"Unsupported signature type: " + sigId);
		}

		if (!ok) {
			throw new SSLException(
				"Invalid signature on ServerKeyExchange");
		}
		return point;
	}

	void SendClientKeyExchangeRSA(RSAPublicKey pkey)
	{
		byte[] pms = new byte[48];
		IO.Enc16be(Version, pms, 0);
		RNG.GetBytes(pms, 2, pms.Length - 2);
		byte[] epms = RSA.Encrypt(pkey, pms);
		MemoryStream ms =
			StartHandshakeMessage(SSL.CLIENT_KEY_EXCHANGE);
		IO.Write16(ms, epms.Length);
		ms.Write(epms, 0, epms.Length);
		EndHandshakeMessage(ms);
		ComputeMaster(pms);
	}

	void SendClientKeyExchangeECDH(ECPublicKey pkey)
	{
		ECCurve curve = pkey.Curve;
		SendClientKeyExchangeECDH(curve, pkey.Pub);
	}

	void SendClientKeyExchangeECDH(ECCurve curve, byte[] pub)
	{
		byte[] k = curve.MakeRandomSecret();

		/*
		 * Compute the point P = k*G that we will send.
		 */
		byte[] P = curve.GetGenerator(false);
		uint good = curve.Mul(P, k, P, false);

		/*
		 * Compute the shared secret Q = k*Pub.
		 */
		byte[] Q = new byte[P.Length];
		good &= curve.Mul(pub, k, Q, false);

		if (good == 0) {
			/*
			 * This might happen only if the server's public
			 * key is not part of the proper subgroup. This
			 * cannot happen with NIST's "P" curves.
			 */
			throw new SSLException("ECDH failed");
		}

		/*
		 * Send message.
		 */
		MemoryStream ms =
			StartHandshakeMessage(SSL.CLIENT_KEY_EXCHANGE);
		ms.WriteByte((byte)P.Length);
		ms.Write(P, 0, P.Length);
		EndHandshakeMessage(ms);

		/*
		 * Extract premaster secret.
		 */
		int xlen;
		int xoff = curve.GetXoff(out xlen);
		byte[] pms = new byte[xlen];
		Array.Copy(Q, xoff, pms, 0, xlen);
		ComputeMaster(pms);
	}

	internal override void ProcessExtraHandshake()
	{
		/*
		 * If we receive a non-empty handshake message, then
		 * it should be an HelloRequest. Note that we expect
		 * the request not to be mixed with application data
		 * records (though it could be split).
		 */
		ReadHelloRequests();

		/*
		 * We accept to renegotiate only if the server supports
		 * the Secure Renegotiation extension.
		 */
		if (renegSupport != 1) {
			SendWarning(SSL.NO_RENEGOTIATION);
			SetAppData();
			return;
		}

		/*
		 * We do a new handshake. We explicitly refuse to reuse
		 * session parameters, because there is no point in
		 * renegotiation if this resumes the same session.
		 */
		resumeParams = null;
		DoHandshake();
	}

	internal override void PrepareRenegotiate()
	{
		/*
		 * Nothing to do to trigger a new handshake, the client
		 * just has to send the ClientHello right away.
		 */
	}
}

}
