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
 * An IServerChoices instance represents the server policy choices for
 * a given connection. It returns the certificate chain and cipher suite
 * to send to the client, and it computes private key operations.
 */

public interface IServerChoices {

	/*
	 * Get the selected cipher suite.
	 */
	int GetCipherSuite();

	/*
	 * Get the certificate chain to send to the client.
	 */
	byte[][] GetCertificateChain();

	/*
	 * Compute the key exchange, based on the value sent by the
	 * client. Returned value is the premaster secret. This method
	 * is invoked only if the selected cipher suite is of type
	 * RSA or static ECDH.
	 */
	byte[] DoKeyExchange(byte[] cke);

	/*
	 * Compute the signature on the provided ServerKeyExchange
	 * message. The 'hashAlgo' and 'sigAlgo' values are set to
	 * the symbolic values corresponding to the used signature
	 * algorithm. This method is invoked only if the selected cipher
	 * suite is of type ECDHE.
	 */
	byte[] DoSign(byte[] ske, out int hashAlgo, out int sigAlgo);
}

}
