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
 * This is the base class common to SSLClient and SSLServer.
 */

public abstract class SSLEngine : Stream {

	Stream sub;
	InputRecord inRec;
	OutputRecord outRec;
	int deferredAlert;
	int state;
	int versionMin;
	int actualVersion;
	bool receivedNoReneg;

	/*
	 * Functions used to hash handshake messages.
	 */
	MD5 md5;
	SHA1 sha1;
	SHA256 sha256;
	SHA384 sha384;

	/*
	 * State:
	 *   STATE_HANDSHAKE   expecting handshake message only
	 *   STATE_CCS         expecting Change Cipher Spec message only
	 *   STATE_APPDATA     expecting application data or handshake
	 *   STATE_CLOSING     expecting only alert (close_notify)
	 *   STATE_CLOSED      closed
	 */
	internal const int STATE_CLOSED    = 0;
	internal const int STATE_HANDSHAKE = 1;
	internal const int STATE_CCS       = 2;
	internal const int STATE_APPDATA   = 3;
	internal const int STATE_CLOSING   = 4;

	/*
	 * Default cipher suites.
	 */
	static int[] DEFAULT_CIPHER_SUITES = {
		SSL.ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		SSL.ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,

		SSL.ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		SSL.ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		SSL.ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		SSL.ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		SSL.ECDHE_ECDSA_WITH_AES_128_CCM,
		SSL.ECDHE_ECDSA_WITH_AES_256_CCM,
		SSL.ECDHE_ECDSA_WITH_AES_128_CCM_8,
		SSL.ECDHE_ECDSA_WITH_AES_256_CCM_8,
		SSL.ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		SSL.ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		SSL.ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
		SSL.ECDHE_RSA_WITH_AES_256_CBC_SHA384,
		SSL.ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		SSL.ECDHE_RSA_WITH_AES_128_CBC_SHA,
		SSL.ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		SSL.ECDHE_RSA_WITH_AES_256_CBC_SHA,

		SSL.ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
		SSL.ECDH_RSA_WITH_AES_128_GCM_SHA256,
		SSL.ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
		SSL.ECDH_RSA_WITH_AES_256_GCM_SHA384,
		SSL.ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
		SSL.ECDH_RSA_WITH_AES_128_CBC_SHA256,
		SSL.ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
		SSL.ECDH_RSA_WITH_AES_256_CBC_SHA384,
		SSL.ECDH_ECDSA_WITH_AES_128_CBC_SHA,
		SSL.ECDH_RSA_WITH_AES_128_CBC_SHA,
		SSL.ECDH_ECDSA_WITH_AES_256_CBC_SHA,
		SSL.ECDH_RSA_WITH_AES_256_CBC_SHA,

		SSL.RSA_WITH_AES_128_GCM_SHA256,
		SSL.RSA_WITH_AES_256_GCM_SHA384,
		SSL.RSA_WITH_AES_128_CCM,
		SSL.RSA_WITH_AES_256_CCM,
		SSL.RSA_WITH_AES_128_CCM_8,
		SSL.RSA_WITH_AES_256_CCM_8,
		SSL.RSA_WITH_AES_128_CBC_SHA256,
		SSL.RSA_WITH_AES_256_CBC_SHA256,
		SSL.RSA_WITH_AES_128_CBC_SHA,
		SSL.RSA_WITH_AES_256_CBC_SHA,

		SSL.ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
		SSL.ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		SSL.ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
		SSL.ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
		SSL.RSA_WITH_3DES_EDE_CBC_SHA
	};

	/*
	 * Default curves.
	 */
	static int[] DEFAULT_CURVES = {
		SSL.Curve25519,
		SSL.NIST_P256,
		SSL.NIST_P384,
		SSL.NIST_P521
	};

	/*
	 * Default hash and sign algorithms.
	 */
	static int[] DEFAULT_HASHANDSIGN = {
		SSL.ECDSA_SHA256,
		SSL.RSA_SHA256,
		SSL.ECDSA_SHA224,
		SSL.RSA_SHA224,
		SSL.ECDSA_SHA384,
		SSL.RSA_SHA384,
		SSL.ECDSA_SHA512,
		SSL.RSA_SHA512,
		SSL.ECDSA_SHA1,
		SSL.RSA_SHA1
	};

	internal byte[] clientRandom;
	internal byte[] serverRandom;
	internal byte[] sessionID;

	/*
	 * 'renegSupport' is one of:
	 *    0   initial handshake not done yet
	 *    1   peer supports secure renegotiation
	 *   -1   peer does not support secure renegotiation
	 */
	internal int renegSupport;
	internal byte[] savedClientFinished;
	internal byte[] savedServerFinished;

	byte[] masterSecret;

	/*
	 * Create a new engine over the provided transport stream.
	 */
	public SSLEngine(Stream sub)
	{
		this.sub = sub;
		inRec = new InputRecord(sub);
		outRec = new OutputRecord(sub);
		md5 = new MD5();
		sha1 = new SHA1();
		sha256 = new SHA256();
		sha384 = new SHA384();
		state = STATE_HANDSHAKE;
		deferredAlert = -1;
		AutoFlush = true;
		CloseSub = true;
		OnClose = null;
		NoCloseNotify = false;
		ClosedWithoutNotify = false;
		MaximumHandshakeMessageLength = 65536;
		SupportedCipherSuites = DEFAULT_CIPHER_SUITES;
		SupportedCurves = DEFAULT_CURVES;
		SupportedHashAndSign = DEFAULT_HASHANDSIGN;
		VersionMin = SSL.TLS10;
		VersionMax = SSL.TLS12;
		AllowRenegotiation = true;
		receivedNoReneg = false;
		clientRandom = new byte[32];
		serverRandom = new byte[32];
		masterSecret = new byte[48];
		HandshakeCount = 0;
	}

	/*
	 * If 'NormalizeIOError' is true, then I/O errors while writing
	 * on the underlying stream will be reported as a generic
	 * SSLException with message "Unexpected transport closure".
	 * This helps test code that expects an asynchronous abort that
	 * may be detected during a read of a write operation, depending
	 * on the exact timing. Default is false.
	 */
	public bool NormalizeIOError {
		get {
			return outRec.NormalizeIOError;
		}
		set {
			outRec.NormalizeIOError = value;
		}
	}

	/*
	 * If 'AutoFlush' is true, then after every Write() or WriteByte()
	 * call, the current record is assembled and sent, leaving no
	 * buffered data yet to be sent. Default value is true.
	 */
	public bool AutoFlush {
		get; set;
	}

	/*
	 * If 'CloseSub' is true, then the underlying transport stream
	 * will be closed on normal closure or protocol failure. Default
	 * value is true. If a closure callback is set in 'OnClose',
	 * then this flag is ignored.
	 */
	public bool CloseSub {
		get; set;
	}

	/*
	 * A generic callback to be invoked when the SSL connection is
	 * closed. If a callback is specified here, then the 'CloseSub'
	 * flag is ignored; the callback is supposed to handle the
	 * closing of the transport stream, if necessary.
	 */
	public delegate void CloseGen(Stream sub);
	public CloseGen OnClose {
		get; set;
	}

	/*
	 * If 'NoCloseNotify' is true, then lack of a close_notify from
	 * the peer before closing the transport stream will NOT be
	 * considered erroneous; i.e. it won't trigger an exception.
	 * If that situation arises, the ClosedWithoutNotify flag will
	 * return true, so the caller may still test for it.
	 *
	 * Not sending close_notify alerts before closing is a widespread
	 * practice, since it simplifies timeout management. It is unsafe,
	 * in that it allows truncation attacks, unless the application
	 * protocol is self-terminated (e.g. HTTP/1.1 is self-terminated,
	 * HTTP/0.9 is not).
	 *
	 * Default value is false: lack of close_notify triggers an
	 * exception.
	 */
	public bool NoCloseNotify {
		get; set;
	}

	/*
	 * The 'ClosedWithoutNotify' flag is set to true if the connection
	 * was closed abruptly (no close_notify alert), but this engine
	 * was configured to tolerate that situation ('NoCloseNotify' was
	 * set to true).
	 */
	public bool ClosedWithoutNotify {
		get; private set;
	}

	/*
	 * Maximum allowed size for a handshake message. The protocol
	 * allows for messages up to 16 megabytes, but these hardly
	 * make sense in practice. In the interest of avoiding
	 * memory-based denials of service, a lower limit can be set.
	 * If an incoming handshake message exceeds that size, then
	 * an exception is thrown. Default value is 65536.
	 */
	public int MaximumHandshakeMessageLength {
		get; set;
	}

	/*
	 * Set the cipher suites supported by this engine, in preference
	 * order (most preferred comes first). Default value should ensure
	 * maximum interoperability and good security and performance.
	 */
	public int[] SupportedCipherSuites {
		get; set;
	}

	/*
	 * Set the elliptic curves supported by this engine, for ECDH
	 * and ECDHE. The list is in preference order (most preferred
	 * comes first). Default list is Curve25519 followed by the
	 * usual NIST curves (P-256, P-384 and P-521, in that order).
	 */
	public int[] SupportedCurves {
		get; set;
	}

	/*
	 * Set the supported hash and sign algorithm combinations. Each
	 * value is a 16-bit integer: high byte is the hash algorithm
	 * identifier, while low byte is the signature algorithm identifier.
	 * List is ordered by preference order. Default list applies the
	 * following rules:
	 *
	 *  - Hash function order is:
	 *    SHA-256, SHA-224, SHA-384, SHA-512, SHA-1
	 *
	 *  - For the same hash function, ECDSA is preferred over RSA.
	 *
	 * Note that the special RSA with MD5+SHA-1 shall not be part of
	 * this list. Its use is implicit when using TLS 1.0 or 1.1 with
	 * a cipher suite or client authentication that uses RSA signatures.
	 */
	public int[] SupportedHashAndSign {
		get; set;
	}

	/*
	 * Set the minimum supported protocol version. Default is TLS 1.0.
	 */
	public int VersionMin {
		get {
			return versionMin;
		}
		set {
			SetOutputRecordVersion(value);
			versionMin = value;
		}
	}

	/*
	 * Set the maximum supported protocol version. Default is TLS 1.2.
	 */
	public int VersionMax {
		get; set;
	}

	/*
	 * Get the actual protocol version. This is set only when the
	 * version is chosen, within the handshake.
	 */
	public int Version {
		get {
			return actualVersion;
		}
		internal set {
			actualVersion = value;
			SetOutputRecordVersion(value);
		}
	}

	/*
	 * Get the actual cipher suite. This is set only when it is chosen,
	 * within the handshake.
	 */
	public int CipherSuite {
		get; internal set;
	}

	/*
	 * Get or set the server name associated with this connection.
	 *
	 * On a client, the caller shall set that name; if non-null and
	 * non-empty, then it will be sent to the server as a SNI
	 * extension; it will moreover be matched against the names
	 * found in the server's certificate.
	 *
	 * On a server, this value is set to the host name received from
	 * the client as a SNI extension (if any).
	 */
	public string ServerName {
		get; set;
	}

	/*
	 * Get the current session parameters. If the initial handshake
	 * was not performed yet, then the handshake is performed now
	 * (thus, this call may trigger an exception in case of I/O or
	 * protocol error).
	 *
	 * The returned object is a freshly allocated copy, which is not
	 * impacted by further activity on this engine.
	 */
	public SSLSessionParameters SessionParameters {
		get {
			if (state == STATE_HANDSHAKE) {
				DoHandshakeWrapper();
			}
			return new SSLSessionParameters(sessionID, Version,
				CipherSuite, ServerName, masterSecret);
		}
	}

	/*
	 * Renegotiation support: if true, then renegotiations will be
	 * accepted (both explicit calls to Renegotiate(), and requests
	 * from the peer); if false, then all renegotiation attempts will
	 * be rejected.
	 *
	 * Default value is true. Regardless of the value of this flag,
	 * renegotiation attempts will be denied if the peer does not
	 * support the "Secure Renegotiation" extension (RFC 5746).
	 */
	public bool AllowRenegotiation {
		get; set;
	}

	/*
	 * Set "quirks" to alter engine behaviour. When null (which is the
	 * default), normal behaviour occurs.
	 */
	public SSLQuirks Quirks {
		get; set;
	}

	/*
	 * Get the current handshake count. This starts at 0 (before
	 * the initial handshake) and is incremented for each handshake.
	 * The increment occurs at the start of the handshake (after
	 * confirmation that a handshake will be indeed attempted, when
	 * doing a renegotiation).
	 */
	public long HandshakeCount {
		get; internal set;
	}

	/*
	 * Tell whether the last handshake was a session resumption or not.
	 * This flag is set at the end of the handshake.
	 */
	public bool IsResume {
		get; internal set;
	}

	/*
	 * Trigger a new handshake. If the initial handshake was not done
	 * yet, then it is performed at that point. Otherwise, this is
	 * a renegotiation attempt.
	 *
	 * Returned value is true if a new handshake happened, false
	 * otherwise. For the initial handshake, true is always returned
	 * (handshake failures trigger exceptions). For a renegotiation,
	 * a 'false' value may be returned if one of the following holds:
	 *  - This engine was configured not to use renegotiations.
	 *  - The peer does not support secure renegotiation.
	 *  - A renegotiation was attempted, but denied by the peer.
	 */
	public bool Renegotiate()
	{
		if (!FirstHandshakeDone) {
			DoHandshakeWrapper();
			return true;
		}

		if (!AllowRenegotiation) {
			return false;
		}
		if (!GetQuirkBool("noSecureReneg") && renegSupport < 0) {
			return false;
		}
		int rt = outRec.RecordType;
		try {
			PrepareRenegotiate();
		} catch {
			MarkFailed();
			throw;
		}
		if (!DoHandshakeWrapper()) {
			outRec.RecordType = rt;
			return false;
		}
		return true;
	}

	/* ============================================================ */
	/*
	 * Stream standard API.
	 */

	public override int ReadByte()
	{
		if (state == STATE_CLOSED) {
			return -1;
		}
		CheckAppData();
		try {
			return ZRead();
		} catch {
			MarkFailed();
			throw;
		}
	}

	public override int Read(byte[] buf, int off, int len)
	{
		if (state == STATE_CLOSED) {
			return -1;
		}
		CheckAppData();
		try {
			return ZRead(buf, off, len);
		} catch {
			MarkFailed();
			throw;
		}
	}

	public override void WriteByte(byte x)
	{
		CheckAppData();
		try {
			outRec.Write(x);
			if (AutoFlush) {
				outRec.Flush();
			}
		} catch {
			MarkFailed();
			throw;
		}
	}

	public override void Write(byte[] buf, int off, int len)
	{
		CheckAppData();
		try {
			outRec.Write(buf, off, len);
			if (AutoFlush) {
				outRec.Flush();
			}
		} catch {
			MarkFailed();
			throw;
		}
	}

	public override void Flush()
	{
		CheckAppData();
		try {
			outRec.Flush();
		} catch {
			MarkFailed();
			throw;
		}
	}

	public override void Close()
	{
		Close(true);
	}

	void Close(bool expectCloseNotify)
	{
		if (state == STATE_CLOSED) {
			return;
		}
		try {
			if (state == STATE_APPDATA) {
				SendWarning(SSL.CLOSE_NOTIFY);
				state = STATE_CLOSING;
				if (expectCloseNotify) {
					if (!NextRecord()) {
						return;
					}
					throw new SSLException(
						"Peer does not want to close");
				}
			}
		} catch {
			// ignored
		} finally {
			MarkFailed();
		}
	}

	public override long Seek(long off, SeekOrigin origin)
	{
		throw new NotSupportedException();
	}

	public override void SetLength(long len)
	{
		throw new NotSupportedException();
	}

	public override bool CanRead {
		get {
			return state != STATE_CLOSED;
		}
	}

	public override bool CanWrite {
		get {
			return state != STATE_CLOSED;
		}
	}

	public override bool CanSeek {
		get {
			return false;
		}
	}

	public override long Length {
		get {
			throw new NotSupportedException();
		}
	}

	public override long Position {
		get {
			throw new NotSupportedException();
		}
		set {
			throw new NotSupportedException();
		}
	}

	/* ============================================================ */

	/*
	 * Test whether this engine is a client or a server.
	 */
	internal abstract bool IsClient {
		get;
	}

	/*
	 * Test the configuration of hash-and-sign with regards to
	 * cipher suites: if the list of cipher suites includes an
	 * ECDHE suite, then there must be at least one supported
	 * hash-and-sign with the corresponding signature type.
	 */
	internal void CheckConfigHashAndSign()
	{
		/*
		 * The hash-and-sign are only for TLS 1.2.
		 */
		if (VersionMax < SSL.TLS12) {
			return;
		}

		/*
		 * If the list is empty then we will work over the default
		 * list inferred by the peer (no extension sent).
		 */
		if (SupportedHashAndSign == null
			|| SupportedHashAndSign.Length == 0)
		{
			return;
		}

		bool needRSA = false;
		bool needECDSA = false;
		foreach (int cs in SupportedCipherSuites) {
			if (SSL.IsECDHE_RSA(cs)) {
				needRSA = true;
			}
			if (SSL.IsECDHE_ECDSA(cs)) {
				needECDSA = true;
			}
		}
		foreach (int hs in SupportedHashAndSign) {
			int sa = hs & 0xFF;
			if (needRSA && sa == SSL.RSA) {
				needRSA = false;
			}
			if (needECDSA && sa == SSL.ECDSA) {
				needECDSA = false;
			}
		}
		if (needRSA) {
			throw new SSLException("Incoherent configuration:"
				+ " supports ECDHE_RSA but no RSA signature"
				+ " (for TLS 1.2)");
		}
		if (needECDSA) {
			throw new SSLException("Incoherent configuration:"
				+ " supports ECDHE_ECDSA but no ECDSA signature"
				+ " (for TLS 1.2)");
		}
	}

	internal bool HasQuirk(string name)
	{
		return Quirks != null && Quirks.GetString(name, null) != null;
	}

	internal bool GetQuirkBool(string name)
	{
		return GetQuirkBool(name, false);
	}

	internal bool GetQuirkBool(string name, bool defaultValue)
	{
		if (Quirks == null) {
			return false;
		}
		return Quirks.GetBoolean(name, defaultValue);
	}

	internal int GetQuirkInt(string name)
	{
		return GetQuirkInt(name, 0);
	}

	internal int GetQuirkInt(string name, int defaultValue)
	{
		if (Quirks == null) {
			return defaultValue;
		}
		return Quirks.GetInteger(name, defaultValue);
	}

	internal string GetQuirkString(string name)
	{
		return GetQuirkString(name, null);
	}

	internal string GetQuirkString(string name, string defaultValue)
	{
		if (Quirks == null) {
			return defaultValue;
		}
		return Quirks.GetString(name, defaultValue);
	}

	/*
	 * Test whether the first handshake has been done or not.
	 */
	internal bool FirstHandshakeDone {
		get {
			return savedClientFinished != null;
		}
	}

	/*
	 * Close the engine. No I/O may happen beyond this call.
	 */
	internal void MarkFailed()
	{
		if (sub != null) {
			try {
				if (OnClose != null) {
					OnClose(sub);
				} else if (CloseSub) {
					sub.Close();
				}
			} catch {
				// ignored
			}
			sub = null;
		}
		state = STATE_CLOSED;
	}

	/*
	 * Check that the current state is not closed.
	 */
	void CheckNotClosed()
	{
		if (state == STATE_CLOSED) {
			throw new SSLException("Connection is closed");
		}
	}

	/*
	 * Check that we are ready to exchange application data. A
	 * handshake is performed if necessary.
	 */
	void CheckAppData()
	{
		CheckNotClosed();
		if (!FirstHandshakeDone) {
			DoHandshakeWrapper();
		} else if (state != STATE_APPDATA) {
			throw new SSLException(
				"Connection not ready for application data");
		}
	}

	/*
	 * Set the version for outgoing records.
	 */
	internal void SetOutputRecordVersion(int version)
	{
		outRec.SetVersion(version);
	}

	/*
	 * Set the expected version for incoming records. This should be
	 * used by the server code just after parsing the ClientHello,
	 * because the client is supposed to send records matching the
	 * protocol version decided by the server and sent in the
	 * ServerHello.
	 *
	 * For a SSL client, this call in unnecessary because default
	 * behaviour is to look at the version of the first incoming
	 * record (containing the ServerHello for the server) and expect
	 * all subsequent records to have the same version.
	 */
	internal void SetInputRecordVersion(int version)
	{
		inRec.SetExpectedVersion(version);
	}

	/*
	 * Flush the underlying record engine.
	 */
	internal void FlushSub()
	{
		outRec.Flush();
	}

	/*
	 * Get next record. This returns false only if the connection
	 * turned out to be ended "properly".
	 *
	 * In all other cases, a record is obtained, and true is
	 * returned. It is possible that the record contains no unread
	 * data (it could be an empty record, or it could be an alert
	 * record whose contents are automatically processed).
	 */
	internal bool NextRecord()
	{
		if (!inRec.NextRecord()) {
			if (NoCloseNotify && (state == STATE_APPDATA
				|| state == STATE_CLOSING))
			{
				/*
				 * No close_notify, but we have been set
				 * to tolerate it.
				 */
				ClosedWithoutNotify = true;
				MarkFailed();
				return false;
			}
			throw new SSLException("Unexpected transport closure");
		}

		/*
		 * We basically ignore empty records, regardless of state.
		 */
		if (inRec.BufferedLength == 0) {
			return true;
		}

		int rt = inRec.RecordType;
		switch (rt) {

		case SSL.ALERT:
			/*
			 * Fatal alerts trigger an exception. Warnings are
			 * ignored, except close_notify and no_renegotiation.
			 */
			while (inRec.BufferedLength > 0) {
				int level = deferredAlert;
				deferredAlert = -1;
				if (level < 0) {
					level = inRec.Read();
					if (inRec.BufferedLength == 0) {
						deferredAlert = level;
						break;
					}
				}
				int desc = inRec.Read();
				if (level == SSL.FATAL) {
					throw new SSLException(desc);
				}
				if (level != SSL.WARNING) {
					throw new SSLException("Unknown"
						+ " alert level: " + level);
				}
				if (desc == SSL.CLOSE_NOTIFY) {
					if (state == STATE_CLOSING) {
						MarkFailed();
						return false;
					}
					if (state != STATE_APPDATA) {
						throw new SSLException(
							"Unexpected closure");
					}
					Close(false);
					return false;
				} else if (desc == SSL.NO_RENEGOTIATION) {
					receivedNoReneg = true;
				}
			}
			return true;

		case SSL.HANDSHAKE:
			switch (state) {
			case STATE_HANDSHAKE:
				return true;
			case STATE_APPDATA:
				ProcessExtraHandshakeWrapper();
				return true;
			}
			throw new SSLException("Unexpected handshake message");

		case SSL.CHANGE_CIPHER_SPEC:
			if (state == STATE_CCS) {
				return true;
			}
			throw new SSLException("Unexpected Change Cipher Spec");

		case SSL.APPLICATION_DATA:
			if (state == STATE_APPDATA) {
				return true;
			}
			throw new SSLException("Unexpected application data");

		default:
			throw new SSLException("Invalid record type: " + rt);

		}
	}

	/*
	 * ZRead() reads the next byte, possibly obtaining further records
	 * to do so. It may return -1 only if the end-of-stream was reached,
	 * which can happen only in "application data" state (after a
	 * successful handshake).
	 */
	int ZRead()
	{
		int x = ZReadNoHash();
		if (x >= 0 && inRec.RecordType == SSL.HANDSHAKE) {
			HashExtra((byte)x);
		}
		return x;
	}

	/*
	 * ZReadNoHash() is similar to ZRead() except that it skips
	 * the automatic hashing of handshake messages.
	 */
	int ZReadNoHash()
	{
		while (inRec.BufferedLength == 0) {
			if (!NextRecord()) {
				return -1;
			}
		}
		return inRec.Read();
	}

	/*
	 * ZReadNoHashNoReneg() is similar to ZReadNoHash() except
	 * that it may return -1 while being in state STATE_HANDSHAKE
	 * in case a no_renegotiation alert is received.
	 */
	int ZReadNoHashNoReneg()
	{
		while (inRec.BufferedLength == 0) {
			receivedNoReneg = false;
			if (!NextRecord() || receivedNoReneg) {
				return -1;
			}
		}
		return inRec.Read();
	}

	/*
	 * Read some bytes. At least one byte will be obtained, unless
	 * EOF is reached. Extra records are obtained if necessary.
	 */
	int ZRead(byte[] buf)
	{
		return ZRead(buf, 0, buf.Length);
	}

	/*
	 * Read some bytes. At least one byte will be obtained, unless
	 * EOF is reached. Extra records are obtained if necessary.
	 */
	int ZRead(byte[] buf, int off, int len)
	{
		while (inRec.BufferedLength == 0) {
			if (!NextRecord()) {
				return 0;
			}
		}
		int rlen = inRec.Read(buf, off, len);
		if (rlen > 0 && inRec.RecordType == SSL.HANDSHAKE) {
			md5.Update(buf, off, rlen);
			sha1.Update(buf, off, rlen);
			sha256.Update(buf, off, rlen);
			sha384.Update(buf, off, rlen);
		}
		return rlen;
	}

	bool DoHandshakeWrapper()
	{
		/*
		 * Record split mode syntax:  name:[types]
		 *
		 * 'name' is a symbolic name.
		 *
		 * 'types' is a comma-separated list of record types on
		 *  which the splitting mode applies. Record types are
		 *  numeric values (in decimal).
		 */
		string splitMode = GetQuirkString("recordSplitMode");
		if (splitMode != null) {
			splitMode = splitMode.Trim();
			int j = splitMode.IndexOf(':');
			int m = 0;
			if (j >= 0) {
				string w = splitMode.Substring(j + 1);
				foreach (string s in w.Split(',')) {
					m |= 1 << Int32.Parse(s.Trim());
				}
				splitMode = splitMode.Substring(0, j).Trim();
			}
			switch (splitMode.ToLowerInvariant()) {
			case "half":
				m |= OutputRecord.MODE_SPLIT_HALF;
				break;
			case "zero_before":
				m |= OutputRecord.MODE_SPLIT_ZERO_BEFORE;
				break;
			case "zero_half":
				m |= OutputRecord.MODE_SPLIT_ZERO_HALF;
				break;
			case "one_start":
				m |= OutputRecord.MODE_SPLIT_ONE_START;
				break;
			case "one_end":
				m |= OutputRecord.MODE_SPLIT_ONE_END;
				break;
			case "multi_one":
				m |= OutputRecord.MODE_SPLIT_MULTI_ONE;
				break;
			default:
				throw new SSLException(string.Format(
					"Bad recordSplitMode name: '{0}'",
					splitMode));
			}
			outRec.SetSplitMode(m);
		}

		/*
		 * Triggers for extra empty records.
		 */
		outRec.SetThresholdZeroHandshake(
			GetQuirkInt("thresholdZeroHandshake"));
		outRec.SetThresholdZeroAppData(
			GetQuirkInt("thresholdZeroAppData"));

		try {
			for (;;) {
				bool ret = DoHandshake();
				if (!ret) {
					return false;
				}
				/*
				 * There could be some extra handshake
				 * data lingering in the input buffer, in
				 * which case we must process it right away.
				 */
				if (HasBufferedHandshake) {
					ProcessExtraHandshakeWrapper();
				}
				return true;
			}
		} catch {
			MarkFailed();
			throw;
		}
	}

	void ProcessExtraHandshakeWrapper()
	{
		try {
			while (HasBufferedHandshake) {
				ProcessExtraHandshake();
			}
		} catch {
			MarkFailed();
			throw;
		}
	}

	/*
	 * Set the state to the provided value.
	 */
	internal void SetState(int state)
	{
		this.state = state;
	}

	/*
	 * Reset running hashes for handshake messages.
	 */
	internal void ResetHashes()
	{
		md5.Reset();
		sha1.Reset();
		sha256.Reset();
		sha384.Reset();
	}

	/*
	 * Inject a specific byte value in the hash functions for handshake
	 * messages.
	 */
	void HashExtra(byte b)
	{
		md5.Update(b);
		sha1.Update(b);
		sha256.Update(b);
		sha384.Update(b);
	}

	/*
	 * Run a handshake. This function normally returns true; it returns
	 * false only if the call was a renegotiation attempt AND it was
	 * denied by the peer.
	 */
	internal abstract bool DoHandshake();

	/*
	 * A non-empty handshake record has been received while we
	 * were in post-handshake "application data" state. This
	 * method should handle that message with the necessary
	 * actions; if it returns false then the caller will fail
	 * the connection with an exception.
	 */
	internal abstract void ProcessExtraHandshake();

	/*
	 * Perform the preparatory steps for a renegotiation. For a client,
	 * there are no such steps, so this call is a no-op. For a server,
	 * an HelloRequest should be sent.
	 */
	internal abstract void PrepareRenegotiate();

	/*
	 * Read the next handshake message. This also sets the state
	 * to STATE_HANDSHAKE.
	 */
	internal byte[] ReadHandshakeMessage(out int msgType)
	{
		return ReadHandshakeMessage(out msgType, false);
	}

	/*
	 * Read the next handshake message. This also sets the state
	 * to STATE_HANDSHAKE. If tolerateNoReneg is true, then a
	 * received no_renegotiation alert interrupts the reading, in
	 * which case this function sets the state back to its previous
	 * value and returns null.
	 */
	internal byte[] ReadHandshakeMessage(
		out int msgType, bool tolerateNoReneg)
	{
		int oldState = state;
		state = STATE_HANDSHAKE;

		/*
		 * In STATE_HANDSHAKE, an unexpected closure is never
		 * tolerated, so ZRead() won't return -1.
		 */
		for (;;) {
			msgType = ZReadNoHashNoReneg();
			if (msgType < 0) {
				if (tolerateNoReneg) {
					state = oldState;
					return null;
				}
				continue;
			}
			if (msgType == SSL.HELLO_REQUEST && IsClient) {
				/*
				 * Extra HelloRequest messages are ignored
				 * (as long as they are properly empty), and
				 * they don't contribute to the running hashes.
				 */
				if (ZReadNoHash() != 0
					|| ZReadNoHash() != 0
					|| ZReadNoHash() != 0)
				{
					throw new SSLException(
						"Non-empty HelloRequest");
				}
				continue;
			}
			HashExtra((byte)msgType);
			int len = ZRead();
			len = (len << 8) + ZRead();
			len = (len << 8) + ZRead();
			if (len > MaximumHandshakeMessageLength) {
				throw new SSLException(
					"Oversized handshake message: len="
					+ len);
			}
			byte[] buf = new byte[len];
			int off = 0;
			while (off < len) {
				off += ZRead(buf, off, len - off);
			}
			return buf;
		}
	}

	/*
	 * Read the next handshake message; fail (with an exception) if
	 * it does not have the specified type. This also sets the state
	 * to STATE_HANDSHAKE.
	 */
	internal byte[] ReadHandshakeMessageExpected(int msgType)
	{
		int rmt;
		byte[] msg = ReadHandshakeMessage(out rmt);
		if (rmt != msgType) {
			throw new SSLException(string.Format("Unexpected"
				+ " handshake message {0} (expected: {1})",
				rmt, msgType));
		}
		return msg;
	}

	/*
	 * Read an HelloRequest message. If, after reading an HelloRequest,
	 * the record is not empty, then other HelloRequest messages are
	 * read.
	 *
	 * This method shall be called only when a non-empty record of type
	 * handshake is buffered. It switches the state to STATE_HANDSHAKE.
	 */
	internal void ReadHelloRequests()
	{
		state = STATE_HANDSHAKE;
		while (inRec.BufferedLength > 0) {
			int x = ZReadNoHash();
			if (x != SSL.HELLO_REQUEST) {
				throw new SSLException(
					"Unexpected handshake message");
			}
			if (ZReadNoHash() != 0x00
				|| ZReadNoHash() != 0x00
				|| ZReadNoHash() != 0x00)
			{
				throw new SSLException(
					"Non-empty HelloRequest");
			}
		}
	}

	/*
	 * Test whether there is some buffered handshake data.
	 */
	internal bool HasBufferedHandshake {
		get {
			return inRec.RecordType == SSL.HANDSHAKE
				&& inRec.BufferedLength > 0;
		}
	}

	static DateTime EPOCH =
		new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

	/*
	 * Create a new client or server random.
	 */
	internal void MakeRandom(byte[] dst)
	{
		uint utc = (uint)((DateTime.UtcNow - EPOCH).Ticks / 10000000);
		IO.Enc32be(utc, dst, 0);
		RNG.GetBytes(dst, 4, dst.Length - 4);
	}

	/*
	 * Create a MemoryStream with preloaded 4-byte handshake message
	 * header.
	 */
	internal MemoryStream StartHandshakeMessage(int type)
	{
		MemoryStream ms = new MemoryStream();
		ms.WriteByte((byte)type);
		IO.Write24(ms, 0);
		return ms;
	}

	/*
	 * Finalise a handshake message, and send it.
	 */
	internal void EndHandshakeMessage(MemoryStream ms)
	{
		byte[] buf = ms.ToArray();
		IO.Enc24be(buf.Length - 4, buf, 1);
		outRec.RecordType = SSL.HANDSHAKE;
		outRec.Write(buf);
		md5.Update(buf);
		sha1.Update(buf);
		sha256.Update(buf);
		sha384.Update(buf);
	}

	/*
	 * Get the PRF corresponding to the negotiated protocol version
	 * and cipher suite.
	 */
	internal PRF GetPRF()
	{
		if (Version <= SSL.TLS11) {
			return new PRF();
		} else {
			return SSL.GetPRFForTLS12(CipherSuite);
		}
	}

	/*
	 * Compute the master secret from the provided premaster secret.
	 */
	internal void ComputeMaster(byte[] pms)
	{
		PRF prf = GetPRF();
		byte[] seed = new byte[64];
		Array.Copy(clientRandom, 0, seed, 0, 32);
		Array.Copy(serverRandom, 0, seed, 32, 32);
		prf.GetBytes(pms, PRF.LABEL_MASTER_SECRET, seed, masterSecret);
	}

	/*
	 * Set the master secret to the provided value. This is used when
	 * resuming a session.
	 */
	internal void SetMasterSecret(byte[] rms)
	{
		Array.Copy(rms, 0, masterSecret, 0, rms.Length);
	}

	/*
	 * Switch to new security parameters.
	 * 'write' is true if we switch encryption for our sending channel,
	 * false for our receiving channel.
	 */
	internal void SwitchEncryption(bool write)
	{
		int macLen, encLen, ivLen;
		IBlockCipher block = null;
		IDigest hash = null;
		Poly1305 pp = null;
		bool isCCM = false;
		bool isCCM8 = false;
		switch (CipherSuite) {
		case SSL.RSA_WITH_3DES_EDE_CBC_SHA:
		case SSL.DH_DSS_WITH_3DES_EDE_CBC_SHA:
		case SSL.DH_RSA_WITH_3DES_EDE_CBC_SHA:
		case SSL.DHE_DSS_WITH_3DES_EDE_CBC_SHA:
		case SSL.DHE_RSA_WITH_3DES_EDE_CBC_SHA:
		case SSL.DH_anon_WITH_3DES_EDE_CBC_SHA:
		case SSL.ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:
		case SSL.ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
		case SSL.ECDH_RSA_WITH_3DES_EDE_CBC_SHA:
		case SSL.ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
		case SSL.ECDH_anon_WITH_3DES_EDE_CBC_SHA:
			macLen = 20;
			encLen = 24;
			ivLen = 8;
			block = new DES();
			hash = new SHA1();
			break;

		case SSL.RSA_WITH_AES_128_CBC_SHA:
		case SSL.DH_DSS_WITH_AES_128_CBC_SHA:
		case SSL.DH_RSA_WITH_AES_128_CBC_SHA:
		case SSL.DHE_DSS_WITH_AES_128_CBC_SHA:
		case SSL.DHE_RSA_WITH_AES_128_CBC_SHA:
		case SSL.DH_anon_WITH_AES_128_CBC_SHA:
		case SSL.ECDH_ECDSA_WITH_AES_128_CBC_SHA:
		case SSL.ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		case SSL.ECDH_RSA_WITH_AES_128_CBC_SHA:
		case SSL.ECDHE_RSA_WITH_AES_128_CBC_SHA:
		case SSL.ECDH_anon_WITH_AES_128_CBC_SHA:
			macLen = 20;
			encLen = 16;
			ivLen = 16;
			block = new AES();
			hash = new SHA1();
			break;

		case SSL.RSA_WITH_AES_256_CBC_SHA:
		case SSL.DH_DSS_WITH_AES_256_CBC_SHA:
		case SSL.DH_RSA_WITH_AES_256_CBC_SHA:
		case SSL.DHE_DSS_WITH_AES_256_CBC_SHA:
		case SSL.DHE_RSA_WITH_AES_256_CBC_SHA:
		case SSL.DH_anon_WITH_AES_256_CBC_SHA:
		case SSL.ECDH_ECDSA_WITH_AES_256_CBC_SHA:
		case SSL.ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		case SSL.ECDH_RSA_WITH_AES_256_CBC_SHA:
		case SSL.ECDHE_RSA_WITH_AES_256_CBC_SHA:
		case SSL.ECDH_anon_WITH_AES_256_CBC_SHA:
			macLen = 20;
			encLen = 32;
			ivLen = 16;
			block = new AES();
			hash = new SHA1();
			break;

		case SSL.RSA_WITH_AES_128_CBC_SHA256:
		case SSL.DH_DSS_WITH_AES_128_CBC_SHA256:
		case SSL.DH_RSA_WITH_AES_128_CBC_SHA256:
		case SSL.DHE_DSS_WITH_AES_128_CBC_SHA256:
		case SSL.DHE_RSA_WITH_AES_128_CBC_SHA256:
		case SSL.DH_anon_WITH_AES_128_CBC_SHA256:
		case SSL.ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		case SSL.ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
		case SSL.ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		case SSL.ECDH_RSA_WITH_AES_128_CBC_SHA256:
			macLen = 32;
			encLen = 16;
			ivLen = 16;
			block = new AES();
			hash = new SHA256();
			break;

		case SSL.RSA_WITH_AES_256_CBC_SHA256:
		case SSL.DH_DSS_WITH_AES_256_CBC_SHA256:
		case SSL.DH_RSA_WITH_AES_256_CBC_SHA256:
		case SSL.DHE_DSS_WITH_AES_256_CBC_SHA256:
		case SSL.DHE_RSA_WITH_AES_256_CBC_SHA256:
		case SSL.DH_anon_WITH_AES_256_CBC_SHA256:
			macLen = 32;
			encLen = 32;
			ivLen = 16;
			block = new AES();
			hash = new SHA256();
			break;

		case SSL.ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
		case SSL.ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
		case SSL.ECDHE_RSA_WITH_AES_256_CBC_SHA384:
		case SSL.ECDH_RSA_WITH_AES_256_CBC_SHA384:
			macLen = 48;
			encLen = 32;
			ivLen = 16;
			block = new AES();
			hash = new SHA384();
			break;

		case SSL.RSA_WITH_AES_128_GCM_SHA256:
		case SSL.DHE_RSA_WITH_AES_128_GCM_SHA256:
		case SSL.DH_RSA_WITH_AES_128_GCM_SHA256:
		case SSL.DHE_DSS_WITH_AES_128_GCM_SHA256:
		case SSL.DH_DSS_WITH_AES_128_GCM_SHA256:
		case SSL.DH_anon_WITH_AES_128_GCM_SHA256:
		case SSL.ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		case SSL.ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
		case SSL.ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		case SSL.ECDH_RSA_WITH_AES_128_GCM_SHA256:
			macLen = 0;
			encLen = 16;
			ivLen = 4;
			block = new AES();
			break;

		case SSL.RSA_WITH_AES_256_GCM_SHA384:
		case SSL.DHE_RSA_WITH_AES_256_GCM_SHA384:
		case SSL.DH_RSA_WITH_AES_256_GCM_SHA384:
		case SSL.DHE_DSS_WITH_AES_256_GCM_SHA384:
		case SSL.DH_DSS_WITH_AES_256_GCM_SHA384:
		case SSL.DH_anon_WITH_AES_256_GCM_SHA384:
		case SSL.ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		case SSL.ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
		case SSL.ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		case SSL.ECDH_RSA_WITH_AES_256_GCM_SHA384:
			macLen = 0;
			encLen = 32;
			ivLen = 4;
			block = new AES();
			break;

		case SSL.RSA_WITH_AES_128_CCM:
		case SSL.ECDHE_ECDSA_WITH_AES_128_CCM:
			macLen = 0;
			encLen = 16;
			ivLen = 4;
			block = new AES();
			isCCM = true;
			break;

		case SSL.RSA_WITH_AES_256_CCM:
		case SSL.ECDHE_ECDSA_WITH_AES_256_CCM:
			macLen = 0;
			encLen = 32;
			ivLen = 4;
			block = new AES();
			isCCM = true;
			break;

		case SSL.RSA_WITH_AES_128_CCM_8:
		case SSL.ECDHE_ECDSA_WITH_AES_128_CCM_8:
			macLen = 0;
			encLen = 16;
			ivLen = 4;
			block = new AES();
			isCCM8 = true;
			break;

		case SSL.RSA_WITH_AES_256_CCM_8:
		case SSL.ECDHE_ECDSA_WITH_AES_256_CCM_8:
			macLen = 0;
			encLen = 32;
			ivLen = 4;
			block = new AES();
			isCCM8 = true;
			break;

		case SSL.ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		case SSL.ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		case SSL.DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
			macLen = 0;
			encLen = 32;
			ivLen = 12;
			pp = new Poly1305();
			pp.ChaCha = new ChaCha20();
			break;

		default:
			throw new SSLException("Unsupported cipher suite");
		}

		/*
		 * Normally we don't need IV when using CBC+HMAC with
		 * TLS 1.1+.
		 */
		if (Version >= SSL.TLS11 && hash != null) {
			ivLen = 0;
		}

		byte[] seed = new byte[64];
		Array.Copy(serverRandom, 0, seed, 0, 32);
		Array.Copy(clientRandom, 0, seed, 32, 32);
		byte[] kb = GetPRF().GetBytes(masterSecret,
			PRF.LABEL_KEY_EXPANSION, seed,
			(macLen + encLen + ivLen) << 1);

		/*
		 * Test whether we need the client write keys, or the
		 * server write keys.
		 */
		bool clientWrite = (IsClient == write);
		HMAC hm = null;
		if (macLen > 0) {
			hm = new HMAC(hash);
			hm.SetKey(kb, clientWrite ? 0 : macLen, macLen);
		}
		if (block != null) {
			block.SetKey(kb, (macLen << 1)
				+ (clientWrite ? 0 : encLen), encLen);
		} else if (pp != null) {
			pp.ChaCha.SetKey(kb, (macLen << 1)
				+ (clientWrite ? 0 : encLen), encLen);
		}
		byte[] iv = null;
		if (ivLen > 0) {
			iv = new byte[ivLen];
			Array.Copy(kb, ((macLen + encLen) << 1)
				+ (clientWrite ? 0 : ivLen), iv, 0, ivLen);
		}

		if (hm != null) {
			/*
			 * CBC+HMAC cipher suite.
			 */
			if (write) {
				outRec.SetEncryption(
					new RecordEncryptCBC(block, hm, iv));
			} else {
				inRec.SetDecryption(
					new RecordDecryptCBC(block, hm, iv));
			}
		} else if (isCCM) {
			/*
			 * CCM cipher suite.
			 */
			if (write) {
				outRec.SetEncryption(
					new RecordEncryptCCM(block, iv, false));
			} else {
				inRec.SetDecryption(
					new RecordDecryptCCM(block, iv, false));
			}
		} else if (isCCM8) {
			/*
			 * CCM cipher suite with truncated MAC value.
			 */
			if (write) {
				outRec.SetEncryption(
					new RecordEncryptCCM(block, iv, true));
			} else {
				inRec.SetDecryption(
					new RecordDecryptCCM(block, iv, true));
			}
		} else if (block != null) {
			/*
			 * GCM cipher suite.
			 */
			if (write) {
				outRec.SetEncryption(
					new RecordEncryptGCM(block, iv));
			} else {
				inRec.SetDecryption(
					new RecordDecryptGCM(block, iv));
			}
		} else if (pp != null) {
			/*
			 * ChaCha20 + Poly1305 cipher suite.
			 */
			if (write) {
				outRec.SetEncryption(
					new RecordEncryptChaPol(pp, iv));
			} else {
				inRec.SetDecryption(
					new RecordDecryptChaPol(pp, iv));
			}
		} else {
			throw new Exception("NYI");
		}
	}

	/*
	 * Compute Finished message. The 'client' flag is set to true
	 * for the Finished message sent by the client, false for the
	 * Finished message sent by the server.
	 */
	internal byte[] ComputeFinished(bool client)
	{
		PRF prf;
		byte[] seed;
		if (Version <= SSL.TLS11) {
			seed = new byte[36];
			md5.DoPartial(seed, 0);
			sha1.DoPartial(seed, 16);
			prf = new PRF();
		} else if (SSL.IsSHA384(CipherSuite)) {
			seed = sha384.DoPartial();
			prf = new PRF(new SHA384());
		} else {
			seed = sha256.DoPartial();
			prf = new PRF(new SHA256());
		}
		byte[] label = client
			? PRF.LABEL_CLIENT_FINISHED
			: PRF.LABEL_SERVER_FINISHED;
		return prf.GetBytes(masterSecret, label, seed, 12);
	}

	/*
	 * Send a ChangeCipherSpec, then a Finished message. This
	 * call implies switching to the new encryption parameters for
	 * the sending channel.
	 */
	internal void SendCCSAndFinished()
	{
		outRec.RecordType = SSL.CHANGE_CIPHER_SPEC;
		outRec.Write(0x01);
		outRec.RecordType = SSL.HANDSHAKE;
		SwitchEncryption(true);
		byte[] fin = ComputeFinished(IsClient);
		if (IsClient) {
			savedClientFinished = fin;
		} else {
			savedServerFinished = fin;
		}
		MemoryStream ms = StartHandshakeMessage(SSL.FINISHED);
		ms.Write(fin, 0, fin.Length);
		EndHandshakeMessage(ms);
	}

	/*
	 * Receive a ChangeCipherSpec, then a Finished message. This
	 * call implies switching to the new encryption parameters for
	 * the receiving channel.
	 */
	internal void ParseCCSAndFinished()
	{
		if (inRec.BufferedLength > 0) {
			throw new SSLException(
				"Buffered data while expecting CCS");
		}
		state = STATE_CCS;
		int x = ZRead();
		if (x != 0x01 || inRec.BufferedLength > 0) {
			throw new SSLException("Invalid CCS contents");
		}
		SwitchEncryption(false);
		state = STATE_HANDSHAKE;
		byte[] fin = ComputeFinished(!IsClient);
		byte[] msg = ReadHandshakeMessageExpected(SSL.FINISHED);
		if (!Eq(fin, msg)) {
			throw new SSLException("Wrong Finished value");
		}
		if (inRec.BufferedLength > 0) {
			throw new SSLException(
				"Extra handshake data after Finished message");
		}
		if (IsClient) {
			savedServerFinished = fin;
		} else {
			savedClientFinished = fin;
		}
	}

	/*
	 * Switch to "application data" state just after the handshake.
	 */
	internal void SetAppData()
	{
		SetState(STATE_APPDATA);
		outRec.RecordType = SSL.APPLICATION_DATA;
	}

	/*
	 * Send an alert of level "warning".
	 */
	internal void SendWarning(int type)
	{
		int rt = outRec.RecordType;
		outRec.RecordType = SSL.ALERT;
		outRec.Write(SSL.WARNING);
		outRec.Write((byte)type);
		outRec.Flush();
		outRec.RecordType = rt;
	}

	static bool Eq(byte[] a, byte[] b)
	{
		int n = a.Length;
		if (n != b.Length) {
			return false;
		}
		int z = 0;
		for (int i = 0; i < n; i ++) {
			z |= a[i] ^ b[i];
		}
		return z == 0;
	}
}

}
