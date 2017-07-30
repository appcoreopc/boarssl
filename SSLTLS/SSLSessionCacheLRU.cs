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
using System.Text;

namespace SSLTLS {

/*
 * A basic implementation of an SSL session cache. It stores up to a
 * predetermined number of sessions, and uses a least-recently-used
 * eviction policy. Sessions are kept in RAM.
 *
 * Instances use locking to be thread-safe, so that multiple SSL server
 * engines managed in different threads may share the same cache (though
 * each engine, individually, is not thread-safe).
 */

public class SSLSessionCacheLRU : ISessionCache {

	/*
	 * TODO: use a doubly-linked list for LRU policy. Right now,
	 * values are indexed in an array, and eviction/moving implies
	 * shifting many pointers in that array. This is fine for small
	 * caches, up to a few thousands of entries.
	 */

	object mutex;
	IDictionary<string, int> spx;
	SSLSessionParameters[] data;
	int count, maxCount;

	public SSLSessionCacheLRU(int maxCount)
	{
		spx = new Dictionary<string, int>();
		data = new SSLSessionParameters[maxCount];
		count = 0;
		this.maxCount = maxCount;
		mutex = new object();
	}

	/* see ISessionCache */
	public SSLSessionParameters Retrieve(byte[] id, string serverName)
	{
		lock (mutex) {
			int x;
			if (!spx.TryGetValue(IDToString(id), out x)) {
				return null;
			}
			SSLSessionParameters sp = data[x];
			if ((x + 1) < count) {
				Array.Copy(data, x + 1,	
					data, x, count - x - 1);
				data[count - 1] = sp;
			}
			return sp;
		}
	}

	/* see ISessionCache */
	public void Store(SSLSessionParameters sp)
	{
		lock (mutex) {
			string ids = IDToString(sp.SessionID);
			int x;
			if (spx.TryGetValue(ids, out x)) {
				if ((x + 1) < count) {
					Array.Copy(data, x + 1,
						data, x, count - x - 1);
				}
				spx[ids] = count - 1;
				data[count - 1] = sp;
				return;
			}
			if (count == maxCount) {
				SSLSessionParameters esp = data[0];
				Array.Copy(data, 1, data, 0, count - 1);
				count --;
				spx.Remove(IDToString(esp.SessionID));
			}
			spx[ids] = count;
			data[count] = sp;
			count ++;
		}
	}

	static string IDToString(byte[] id)
	{
		StringBuilder sb = new StringBuilder();
		foreach (byte b in id) {
			sb.AppendFormat("{0:x2}", b);
		}
		return sb.ToString();
	}
}

}
