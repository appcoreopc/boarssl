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
 * Class for a SSL server connection.
 *
 * An instance is created over a specified transport stream. An optional
 * cache for session parameters can be provided, to support session
 * resumption. The instance handles the connection but cannot be
 * "revived" after the connection was closed (the session parameters,
 * though, can be extracted and used with another instance).
 */

public class SSLServer : SSLEngine {

	/*
	 * If true, then the server will enforce its own preference
	 * order for cipher suite selection; otherwise, it will follow
	 * the client's preferences. Default value is false.
	 */
	public bool EnforceServerOrder {
		get; set;
	}

	/*
	 * Server policy object, that selects cipher suite and certificate
	 * chain to send to client. Such a policy object MUST be set
	 * before the initial handshake takes place. This property is
	 * initialised to the value provided as second argument to the
	 * SSLServer constructor.
	 */
	public IServerPolicy ServerPolicy {
		get; set;
	}

	/*
	 * Optional session cache for SSL sessions. If null, then no
	 * cache is used. Default value is null.
	 */
	public ISessionCache SessionCache {
		get; set;
	}

	/*
	 * If this flag is set to true, then session resumption will be
	 * rejected; all handshakes will be full handshakes. Main
	 * intended usage is when a server wants to renegotiate and ask
	 * for a client certificate. Note that even if that flag is set,
	 * each session resulting from a full handshake is still pushed
	 * to the session cache (if configured in SessionCache).
	 * Default value is false, meaning that session resumption is
	 * allowed (but won't happen anyway if no session cache was
	 * set in SessionCache).
	 */
	public bool NoResume {
		get; set;
	}

	/*
	 * Get the maximum supported version announced by the client
	 * in its ClientHello message.
	 */
	public int ClientVersionMax {
		get; private set;
	}

	/*
	 * Get the list of hash and signature algorithms supported by the
	 * client. Each value is a 16-bit integer, with the high byte
	 * being the hash algorithm, and the low byte the signature
	 * algorithm.
	 *
	 * The list is trimmed to include only hash and signature algorithms
	 * that are supported by both client and server. It is ordered
	 * by client or server preference, depending on the value of
	 * the EnforceServerOrder flag.
	 *
	 * If the client did not send the dedicated extension, then the
	 * list is inferred from the sent cipher suite, as specified
	 * by RFC 5246, section 7.4.1.4.1.
	 */
	public List<int> ClientHashAndSign {
		get; internal set;
	}

	/*
	 * Get the list of elliptic curves supported by the client. Each
	 * entry is a 16-bit integer that identifies a named curve. The
	 * list is ordered by client preferences.
	 *
	 * If the client did not send the Supported Curves extension,
	 * then the list will be inferred to contain NIST P-256 only
	 * (if the client supports at least one ECDH, ECDHE or ECDSA
	 * cipher suite), or to be empty (if the client does not support
	 * any EC-based cipher suite).
	 */
	public List<int> ClientCurves {
		get; internal set;
	}

	/*
	 * Get the list of elliptic curves supported by both client and
	 * server. Each entry is a 16-bit integer that identifies a
	 * named curve. The list is ordered by preference (client or
	 * server, depending on configuration). This list is the one
	 * used for curve selection for ECDHE.
	 */
	public List<int> CommonCurves {
		get; internal set;
	}

	/*
	 * Get the list of cipher suites supported by the client. The
	 * order matches the configured preferences (client or server
	 * preference order, depending on the EnforceServerOrder flag).
	 * Moreover, the list is trimmed:
	 *
	 *  - Signalling cipher suites ("SCSV") have been removed.
	 *
	 *  - Only suites supported by both client and server are kept.
	 *
	 *  - Suites that require TLS 1.2 are omitted if the selected
	 *    protocol version is TLS 1.0 or 1.1.
	 *
	 *  - Suites that require client support for RSA signatures are
	 *    removed if there is no common support for RSA signatures.
	 *
	 *  - Suites that require client support for ECDSA signatures
	 *    are removed if there is no common support for ECDSA
	 *    signatures.
	 *
	 *  - ECDHE suites are removed if there is no common support for
	 *    elliptic curves.
	 */
	public List<int> CommonCipherSuites {
		get; internal set;
	}

	IServerChoices serverChoices;
	ECCurve ecdheCurve;
	byte[] ecdheSecret;

	/*
	 * Create an SSL server instance, over the provided stream.
	 * The 'serverPolicy' parameter is used as initial value to
	 * the ServerPolicy property.
	 */
	public SSLServer(Stream sub, IServerPolicy serverPolicy)
		: base(sub)
	{
		EnforceServerOrder = false;
		ServerPolicy = serverPolicy;
	}

	internal override bool IsClient {
		get {
			return false;
		}
	}

	internal override bool DoHandshake()
	{
		CheckConfigHashAndSign();

		ResetHashes();
		MakeRandom(serverRandom);

		bool resume;
		if (!ParseClientHello(out resume)) {
			return false;
		}
		HandshakeCount ++;
		SetOutputRecordVersion(Version);
		SetInputRecordVersion(Version);

		if (resume) {
			SendServerHello();
			SendCCSAndFinished();
			FlushSub();
			ParseCCSAndFinished();
			SetAppData();
			IsResume = true;
			return true;
		}

		SendServerHello();
		SendCertificate();
		if (SSL.IsECDHE(CipherSuite)) {
			SendServerKeyExchange();
		}
		SendServerHelloDone();
		FlushSub();

		ParseClientKeyExchange();
		ParseCCSAndFinished();
		SendCCSAndFinished();
		FlushSub();
		SetAppData();
		IsResume = false;
		if (SessionCache != null) {
			SessionCache.Store(SessionParameters);
		}
		return true;
	}

	bool ParseClientHello(out bool resume)
	{
		resume = false;
		int mt;
		byte[] msg = ReadHandshakeMessage(out mt, FirstHandshakeDone);
		if (msg == null) {
			/*
			 * Client rejected renegotiation attempt. This cannot
			 * happen if we are invoked from
			 * ProcessExtraHandshake() because that method is
			 * invoked only when there is buffered handshake
			 * data.
			 */
			return false;
		}
		if (mt != SSL.CLIENT_HELLO) {
			throw new SSLException(string.Format("Unexpected"
				+ " handshake message {0} (expecting a"
				+ " ClientHello)", mt));
		}

		/*
		 * Maximum protocol version supported by the client.
		 */
		if (msg.Length < 35) {
			throw new SSLException("Invalid ClientHello");
		}
		ClientVersionMax = IO.Dec16be(msg, 0);
		if (ClientVersionMax < VersionMin) {
			throw new SSLException(string.Format(
				"No acceptable version (client max = 0x{0:X4})",
				ClientVersionMax));
		}

		/*
		 * Client random (32 bytes).
		 */
		Array.Copy(msg, 2, clientRandom, 0, 32);

		/*
		 * Session ID sent by the client: at most 32 bytes.
		 */
		int idLen = msg[34];
		int off = 35;
		if (idLen > 32 || (off + idLen) > msg.Length) {
			throw new SSLException("Invalid ClientHello");
		}
		byte[] clientSessionID = new byte[idLen];
		Array.Copy(msg, off, clientSessionID, 0, idLen);
		off += idLen;

		/*
		 * List of client cipher suites.
		 */
		if ((off + 2) > msg.Length) {
			throw new SSLException("Invalid ClientHello");
		}
		int csLen = IO.Dec16be(msg, off);
		off += 2;
		if ((off + csLen) > msg.Length) {
			throw new SSLException("Invalid ClientHello");
		}
		List<int> clientSuites = new List<int>();
		bool seenReneg = false;
		while (csLen > 0) {
			int cs = IO.Dec16be(msg, off);
			off += 2;
			csLen -= 2;
			if (cs == SSL.FALLBACK_SCSV) {
				if (ClientVersionMax < VersionMax) {
					throw new SSLException(
						"Undue fallback detected");
				}
			} else if (cs == SSL.EMPTY_RENEGOTIATION_INFO_SCSV) {
				if (FirstHandshakeDone) {
					throw new SSLException(
						"Reneg SCSV in renegotiation");
				}
				seenReneg = true;
			} else {
				clientSuites.Add(cs);
			}
		}

		/*
		 * List of compression methods. We only accept method 0
		 * (no compression).
		 */
		if ((off + 1) > msg.Length) {
			throw new SSLException("Invalid ClientHello");
		}
		int compLen = msg[off ++];
		if ((off + compLen) > msg.Length) {
			throw new SSLException("Invalid ClientHello");
		}
		bool foundUncompressed = false;
		while (compLen -- > 0) {
			if (msg[off ++] == 0x00) {
				foundUncompressed = true;
			}
		}
		if (!foundUncompressed) {
			throw new SSLException("No common compression support");
		}

		/*
		 * Extensions.
		 */
		ClientHashAndSign = null;
		ClientCurves = null;
		if (off < msg.Length) {
			if ((off + 2) > msg.Length) {
				throw new SSLException("Invalid ClientHello");
			}
			int tlen = IO.Dec16be(msg, off);
			off += 2;
			if ((off + tlen) != msg.Length) {
				throw new SSLException("Invalid ClientHello");
			}
			while (off < msg.Length) {
				if ((off + 4) > msg.Length) {
					throw new SSLException(
						"Invalid ClientHello");
				}
				int etype = IO.Dec16be(msg, off);
				int elen = IO.Dec16be(msg, off + 2);
				off += 4;
				if ((off + elen) > msg.Length) {
					throw new SSLException(
						"Invalid ClientHello");
				}
				switch (etype) {

				case 0x0000:
					ParseExtSNI(msg, off, elen);
					break;

				case 0x000D:
					ParseExtSignatures(msg, off, elen);
					break;

				case 0x000A:
					ParseExtCurves(msg, off, elen);
					break;

				case 0xFF01:
					ParseExtSecureReneg(msg, off, elen);
					seenReneg = true;
					break;

				// Max Frag Length
				// ALPN
				// FIXME
				}

				off += elen;
			}
		}

		/*
		 * If we are renegotiating and we did not see the
		 * Secure Renegotiation extension, then this is an error.
		 */
		if (FirstHandshakeDone && !seenReneg) {
			throw new SSLException(
				"Missing Secure Renegotiation extension");
		}

		/*
		 * Use prescribed default values for supported algorithms
		 * and curves, when not otherwise advertised by the client.
		 */
		if (ClientCurves == null) {
			ClientCurves = new List<int>();
			foreach (int cs in clientSuites) {
				if (SSL.IsECDH(cs) || SSL.IsECDHE(cs)) {
					ClientCurves.Add(SSL.NIST_P256);
					break;
				}
			}
		}
		if (ClientHashAndSign == null) {
			bool withRSA = false;
			bool withECDSA = false;
			foreach (int cs in clientSuites) {
				if (SSL.IsRSA(cs)
					|| SSL.IsECDH_RSA(cs)
					|| SSL.IsECDHE_RSA(cs))
				{
					withRSA = true;
				}
				if (SSL.IsECDH_ECDSA(cs)
					|| SSL.IsECDHE_ECDSA(cs))
				{
					withECDSA = true;
				}
			}
			ClientHashAndSign = new List<int>();
			if (withRSA) {
				ClientHashAndSign.Add(SSL.RSA_SHA1);
			}
			if (withECDSA) {
				ClientHashAndSign.Add(SSL.ECDSA_SHA1);
			}
		}

		/*
		 * Filter curves and algorithms with regards to our own
		 * configuration.
		 */
		CommonCurves = FilterList(ClientCurves,
			SupportedCurves, EnforceServerOrder);
		ClientHashAndSign = FilterList(ClientHashAndSign,
			SupportedHashAndSign, EnforceServerOrder);

		/*
		 * Selected protocol version (can be overridden by
		 * resumption).
		 */
		Version = Math.Min(ClientVersionMax, VersionMax);
		string forcedVersion = GetQuirkString("forceVersion");
		if (forcedVersion != null) {
			switch (forcedVersion) {
			case "TLS10": Version = SSL.TLS10; break;
			case "TLS11": Version = SSL.TLS11; break;
			case "TLS12": Version = SSL.TLS12; break;
			default:
				throw new Exception(string.Format(
					"Unknown forced version: '{0}'", 
					forcedVersion));
			}
		}

		/*
		 * Recompute list of acceptable cipher suites. We keep
		 * only suites which are common to the client and server,
		 * with some extra filters.
		 *
		 * Note that when using static ECDH, it is up to the
		 * policy callback to determine whether the curves match
		 * the contents of the certificate.
		 *
		 * We also build a list of common suites for session
		 * resumption: this one may include suites whose
		 * asymmetric crypto is not supported, because session
		 * resumption uses only symmetric crypto.
		 */
		CommonCipherSuites = new List<int>();
		List<int> commonSuitesResume = new List<int>();
		bool canTLS12 = Version >= SSL.TLS12;
		bool mustTLS12 = false;
		if (GetQuirkBool("forceTls12CipherSuite")) {
			canTLS12 = true;
			mustTLS12 = true;
		}
		bool canSignRSA;
		bool canSignECDSA;
		if (Version >= SSL.TLS12) {
			canSignRSA = false;
			canSignECDSA = false;
			foreach (int alg in ClientHashAndSign) {
				int sa = alg & 0xFF;
				switch (sa) {
				case SSL.RSA:    canSignRSA = true;    break;
				case SSL.ECDSA:  canSignECDSA = true;  break;
				}
			}
		} else {
			/*
			 * For pre-1.2, the hash-and-sign configuration does
			 * not matter, only the cipher suites themselves. So
			 * we claim support of both RSA and ECDSA signatures
			 * to avoid trimming the list too much.
			 */
			canSignRSA = true;
			canSignECDSA = true;
		}
		bool canECDHE = CommonCurves.Count > 0;

		foreach (int cs in clientSuites) {
			if (!canTLS12 && SSL.IsTLS12(cs)) {
				continue;
			}
			if (mustTLS12 && !SSL.IsTLS12(cs)) {
				continue;
			}
			commonSuitesResume.Add(cs);
			if (!canECDHE && SSL.IsECDHE(cs)) {
				continue;
			}
			if (!canSignRSA && SSL.IsECDHE_RSA(cs)) {
				continue;
			}
			if (!canSignECDSA && SSL.IsECDHE_ECDSA(cs)) {
				continue;
			}
			CommonCipherSuites.Add(cs);
		}
		CommonCipherSuites = FilterList(CommonCipherSuites,
			SupportedCipherSuites, EnforceServerOrder);
		commonSuitesResume = FilterList(commonSuitesResume,
			SupportedCipherSuites, EnforceServerOrder);

		/*
		 * If resuming, then use the remembered session parameters,
		 * but only if they are compatible with what the client
		 * sent AND what we currently support.
		 */
		SSLSessionParameters sp = null;
		if (idLen > 0 && !NoResume && SessionCache != null) {
			sp = SessionCache.Retrieve(
				clientSessionID, ServerName);
			if (sp != null && sp.ServerName != null
				&& ServerName != null)
			{
				/*
				 * When resuming a session, if there is
				 * an explicit name sent by the client,
				 * and the cached parameters also include
				 * an explicit name, then both names
				 * shall match.
				 */
				string s1 = sp.ServerName.ToLowerInvariant();
				string s2 = ServerName.ToLowerInvariant();
				if (s1 != s2) {
					sp = null;
				}
			}
		}
		if (sp != null) {
			bool resumeOK = true;
			if (sp.Version < VersionMin
				|| sp.Version > VersionMax
				|| sp.Version > ClientVersionMax)
			{
				resumeOK = false;
			}
			if (!commonSuitesResume.Contains(sp.CipherSuite)) {
				resumeOK = false;
			}

			if (resumeOK) {
				/*
				 * Session resumption is acceptable.
				 */
				resume = true;
				sessionID = clientSessionID;
				Version = sp.Version;
				CipherSuite = sp.CipherSuite;
				sessionID = clientSessionID;
				SetMasterSecret(sp.MasterSecret);
				return true;
			}
		}

		/*
		 * Not resuming. Let's select parameters.
		 * Protocol version was already set.
		 */
		if (CommonCipherSuites.Count == 0) {
			throw new SSLException("No common cipher suite");
		}
		serverChoices = ServerPolicy.Apply(this);
		CipherSuite = serverChoices.GetCipherSuite();

		/*
		 * We create a new session ID, even if we don't have a
		 * session cache, because the session parameters could
		 * be extracted manually by the application.
		 */
		sessionID = new byte[32];
		RNG.GetBytes(sessionID);

		return true;
	}

	void ParseExtSNI(byte[] buf, int off, int len)
	{
		if (len < 2) {
			throw new SSLException("Invalid SNI extension");
		}
		int tlen = IO.Dec16be(buf, off);
		off += 2;
		if ((tlen + 2) != len) {
			throw new SSLException("Invalid SNI extension");
		}
		int lim = off + tlen;
		bool found = false;
		while (off < lim) {
			if ((off + 3) > lim) {
				throw new SSLException("Invalid SNI extension");
			}
			int ntype = buf[off ++];
			int nlen = IO.Dec16be(buf, off);
			off += 2;
			if ((off + nlen) > lim) {
				throw new SSLException("Invalid SNI extension");
			}
			if (ntype == 0) {
				/*
				 * Name type is "host name". There shall be
				 * only one (at most) in the extension.
				 */
				if (found) {
					throw new SSLException("Several host"
						+ " names in SNI extension");
				}
				found = true;

				/*
				 * Verify that the name contains only
				 * printable non-space ASCII, and normalise
				 * it to lowercase.
				 */
				char[] tc = new char[nlen];
				for (int i = 0; i < nlen; i ++) {
					int x = buf[off + i];
					if (x <= 32 || x >= 126) {
						throw new SSLException(
							"Invalid SNI hostname");
					}
					if (x >= 'A' && x <= 'Z') {
						x += ('a' - 'A');
					}
					tc[i] = (char)x;
				}
				ServerName = new string(tc);
			}
			off += nlen;
		}
	}

	void ParseExtSignatures(byte[] buf, int off, int len)
	{
		if (len < 2) {
			throw new SSLException("Invalid signatures extension");
		}
		int tlen = IO.Dec16be(buf, off);
		off += 2;
		if (len != (tlen + 2)) {
			throw new SSLException("Invalid signatures extension");
		}
		if ((tlen & 1) != 0) {
			throw new SSLException("Invalid signatures extension");
		}
		ClientHashAndSign = new List<int>();
		while (tlen > 0) {
			ClientHashAndSign.Add(IO.Dec16be(buf, off));
			off += 2;
			tlen -= 2;
		}
	}

	void ParseExtCurves(byte[] buf, int off, int len)
	{
		if (len < 2) {
			throw new SSLException("Invalid curves extension");
		}
		int tlen = IO.Dec16be(buf, off);
		off += 2;
		if (len != (tlen + 2)) {
			throw new SSLException("Invalid curves extension");
		}
		if ((tlen & 1) != 0) {
			throw new SSLException("Invalid curves extension");
		}
		ClientCurves = new List<int>();
		while (tlen > 0) {
			ClientCurves.Add(IO.Dec16be(buf, off));
			off += 2;
			tlen -= 2;
		}
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
			 * saved client Finished message.
			 */
			if (len != 12) {
				throw new SSLException(
					"Wrong Secure Renegotiation value");
			}
			int z = 0;
			for (int i = 0; i < 12; i ++) {
				z |= savedClientFinished[i] ^ buf[off + i];
			}
			if (z != 0) {
				throw new SSLException(
					"Wrong Secure Renegotiation value");
			}
		}
	}

	void SendServerHello()
	{
		MemoryStream ms = StartHandshakeMessage(SSL.SERVER_HELLO);

		// Protocol version
		IO.Write16(ms, Version);

		// Server random
		ms.Write(serverRandom, 0, serverRandom.Length);

		// Session ID
		ms.WriteByte((byte)sessionID.Length);
		ms.Write(sessionID, 0, sessionID.Length);

		// Cipher suite
		IO.Write16(ms, CipherSuite);

		// Compression
		ms.WriteByte(0x00);

		// Extensions
		MemoryStream chExt = new MemoryStream();

		// Secure renegotiation
		if (!GetQuirkBool("noSecureReneg")) {
			byte[] exv = null;
			if (renegSupport > 0) {
				if (FirstHandshakeDone) {
					exv = new byte[24];
					Array.Copy(savedClientFinished, 0,
						exv, 0, 12);
					Array.Copy(savedServerFinished, 0,
						exv, 12, 12);
				} else {
					exv = new byte[0];
				}
			}
			if (GetQuirkBool("forceEmptySecureReneg")) {
				exv = new byte[0];
			} else if (GetQuirkBool("forceNonEmptySecureReneg")) {
				exv = new byte[24];
			} else if (GetQuirkBool("alterNonEmptySecureReneg")) {
				if (exv.Length > 0) {
					exv[exv.Length - 1] ^= 0x01;
				}
			} else if (GetQuirkBool("oversizedSecureReneg")) {
				exv = new byte[255];
			}

			if (exv != null) {
				IO.Write16(chExt, 0xFF01);
				IO.Write16(chExt, exv.Length + 1);
				chExt.WriteByte((byte)exv.Length);
				chExt.Write(exv, 0, exv.Length);
			}
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

	void SendCertificate()
	{
		MemoryStream ms = StartHandshakeMessage(SSL.CERTIFICATE);
		byte[][] chain = serverChoices.GetCertificateChain();
		int tlen = 0;
		foreach (byte[] ec in chain) {
			tlen += 3 + ec.Length;
		}
		if (tlen > 0xFFFFFC) {
			throw new SSLException("Oversized certificate chain");
		}
		IO.Write24(ms, tlen);
		foreach (byte[] ec in chain) {
			IO.Write24(ms, ec.Length);
			ms.Write(ec, 0, ec.Length);
		}
		EndHandshakeMessage(ms);
	}

	void SendServerKeyExchange()
	{
		if (CommonCurves.Count == 0) {
			/*
			 * Since we filter cipher suites when parsing the
			 * ClientHello, this situation may happen only if
			 * the IServerPolicy callback goofed up.
			 */
			throw new SSLException("No curve for ECDHE");
		}
		int curveID = CommonCurves[0];
		ecdheCurve = SSL.GetCurveByID(curveID);

		/*
		 * Generate our ephemeral ECDH secret and the point to
		 * send to the peer.
		 */
		ecdheSecret = ecdheCurve.MakeRandomSecret();
		byte[] P = ecdheCurve.GetGenerator(false);
		ecdheCurve.Mul(P, ecdheSecret, P, false);

		/*
		 * Generate to-be-signed:
		 *   clientRandom   32 bytes
		 *   serverRandom   32 bytes
		 *   0x03           curve is a "named curve"
		 *   id             curve identifier (two bytes)
		 *   point          public point (one-byte length + value)
		 */
		byte[] tbs = new byte[64 + 4 + P.Length];
		Array.Copy(clientRandom, 0, tbs, 0, 32);
		Array.Copy(serverRandom, 0, tbs, 32, 32);
		tbs[64] = 0x03;
		IO.Enc16be(curveID, tbs, 65);
		tbs[67] = (byte)P.Length;
		Array.Copy(P, 0, tbs, 68, P.Length);

		/*
		 * Obtain server signature.
		 */
		int hashAlgo, sigAlgo;
		byte[] sig = serverChoices.DoSign(tbs,
			out hashAlgo, out sigAlgo);

		/*
		 * Encode message.
		 */
		MemoryStream ms = StartHandshakeMessage(
			SSL.SERVER_KEY_EXCHANGE);
		ms.Write(tbs, 64, tbs.Length - 64);
		if (Version >= SSL.TLS12) {
			ms.WriteByte((byte)hashAlgo);
			ms.WriteByte((byte)sigAlgo);
		}
		IO.Write16(ms, sig.Length);
		ms.Write(sig, 0, sig.Length);
		EndHandshakeMessage(ms);
	}

	void SendServerHelloDone()
	{
		MemoryStream ms = StartHandshakeMessage(SSL.SERVER_HELLO_DONE);
		EndHandshakeMessage(ms);
	}

	void ParseClientKeyExchange()
	{
		byte[] msg = ReadHandshakeMessageExpected(
			SSL.CLIENT_KEY_EXCHANGE);
		byte[] pms;
		if (SSL.IsECDHE(CipherSuite)) {
			/*
			 * Expecting a curve point; we are doing the
			 * ECDH ourselves.
			 */
			if (msg.Length < 1 || msg.Length != 1 + msg[0]) {
				throw new SSLException(
					"Invalid ClientKeyExchange");
			}
			byte[] P = new byte[msg.Length - 1];
			byte[] D = new byte[ecdheCurve.EncodedLength];
			Array.Copy(msg, 1, P, 0, P.Length);
			if (ecdheCurve.Mul(P, ecdheSecret, D, false) == 0) {
				throw new SSLException(
					"Invalid ClientKeyExchange");
			}
			int xlen;
			int xoff = ecdheCurve.GetXoff(out xlen);
			pms = new byte[xlen];
			Array.Copy(D, xoff, pms, 0, xlen);

			/*
			 * Memory wiping is out of scope for this library,
			 * and is unreliable anyway in the presence of
			 * a moving garbage collector. So we just unlink
			 * the secret array.
			 */
			ecdheSecret = null;
		} else {
			/*
			 * RSA or static ECDH. The crypto operation is done
			 * by the relevant callback.
			 */
			if (msg.Length < 2) {
				throw new SSLException(
					"Invalid ClientKeyExchange");
			}
			int off, len;
			if (SSL.IsRSA(CipherSuite)) {
				len = IO.Dec16be(msg, 0);
				off = 2;
			} else if (SSL.IsECDH(CipherSuite)) {
				len = msg[0];
				off = 1;
			} else {
				throw new Exception("NYI");
			}
			if (msg.Length != off + len) {
				throw new SSLException(
					"Invalid ClientKeyExchange");
			}
			byte[] cke = new byte[len];
			Array.Copy(msg, off, cke, 0, len);
			pms = serverChoices.DoKeyExchange(cke);
		}

		ComputeMaster(pms);
	}

	internal override void ProcessExtraHandshake()
	{
		/*
		 * If Secure Renegotiation is supported, then we accept
		 * to do a new handshake.
		 */
		if (renegSupport > 0) {
			DoHandshake();
			return;
		}

		/*
		 * We must read and discard an incoming ClientHello,
		 * then politely refuse.
		 */
		ReadHandshakeMessageExpected(SSL.CLIENT_HELLO);
		SendWarning(SSL.NO_RENEGOTIATION);
		SetAppData();
	}

	internal override void PrepareRenegotiate()
	{
		MemoryStream ms = StartHandshakeMessage(SSL.HELLO_REQUEST);
		EndHandshakeMessage(ms);
		FlushSub();
	}

	/*
	 * Compute the intersection of two lists of integers (the second
	 * list is provided as an array). The intersection is returned
	 * as a new List<int> instance. If enforceV2 is true, then the
	 * order of items in the returned list will be that of v2; otherwise,
	 * it will be that of v1. Duplicates are removed.
	 */
	static List<int> FilterList(List<int> v1, int[] v2, bool enforceV2)
	{
		List<int> r = new List<int>();
		if (enforceV2) {
			foreach (int x in v2) {
				if (v1.Contains(x) && !r.Contains(x)) {
					r.Add(x);
				}
			}
		} else {
			foreach (int x in v1) {
				foreach (int y in v2) {
					if (x == y) {
						if (!r.Contains(x)) {
							r.Add(x);
						}
						break;
					}
				}
			}
		}
		return r;
	}
}

}
