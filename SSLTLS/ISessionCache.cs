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
 * A session cache instance is able to cache and remember session
 * parameters; this is typically used on a SSL server.
 */

public interface ISessionCache {

	/*
	 * Retrieve session parameters by session ID. If the client sent
	 * an intended server name (SNI extension), then that name is
	 * also provided as parameter (printable ASCII, normalised to
	 * lowercase, no space); otherwise, that parameter is null.
	 * Session cache implementations are free to use the server name
	 * or not; if the client specified a target name, and the cache
	 * returns parameters with a different, non-null name, then the
	 * session resumption will be rejected by the engine.
	 *
	 * If no parameters are found for that ID (and optional server
	 * name), then this method shall return null.
	 */
	SSLSessionParameters Retrieve(byte[] id, string serverName);

	/*
	 * Record new session parameters. These should be internally
	 * indexed by their ID.
	 */
	void Store(SSLSessionParameters sp);
}

}
