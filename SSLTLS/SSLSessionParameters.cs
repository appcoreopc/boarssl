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

namespace SSLTLS {

/*
 * An SSLSessionParameters instance contains the "security parameters"
 * for a SSL session. Instances are obtained from an open instance
 * (after the handshake) and can be used to initialise new instances
 * so as to attempt a session resumption.
 */

public class SSLSessionParameters {

	/*
	 * Session ID (at most 32 bytes).
	 */
	public byte[] SessionID {
		get; set;
	}

	/*
	 * Protocol version.
	 */
	public int Version {
		get; set;
	}

	/*
	 * Used cipher suite.
	 */
	public int CipherSuite {
		get; set;
	}

	/*
	 * Server name attached to this session; it may be null.
	 */
	public string ServerName {
		get; set;
	}

	/*
	 * Negotiated master secret.
	 */
	public byte[] MasterSecret {
		get; set;
	}

	/*
	 * Create a new instance. The provided sessionID and masterSecret
	 * arrays are internally copied into new instances.
	 */
	public SSLSessionParameters(byte[] sessionID, int version,
		int cipherSuite, string serverName, byte[] masterSecret)
	{
		SessionID = IO.CopyBlob(sessionID);
		Version = version;
		CipherSuite = cipherSuite;
		ServerName = serverName;
		MasterSecret = IO.CopyBlob(masterSecret);
	}
}

}
