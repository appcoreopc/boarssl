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

namespace SSLTLS {

/*
 * An IServerPolicy instance is a callback object that selects the
 * cipher suite and certificate chain to send to the client, and
 * implements the private key operation (signature or key exchange).
 */

public interface IServerPolicy {

	/*
	 * Get the server policy choices for the provided connection.
	 * In the 'server' object, the following are already set:
	 *
	 *   Version               Selected protocol version.
	 *
	 *   CommonCipherSuites    Common cipher suites.
	 *
	 *   ClientCurves          Elliptic curve supported by the client.
	 *
	 *   CommonCurves          Common supported curves.
	 *
	 *   ClientHashAndSign     Common hash and signature algorithms.
	 *
	 * Returned value is a callback object that embodies the choices
	 * and will perform private key operations.
	 */
	IServerChoices Apply(SSLServer server);
}

}
