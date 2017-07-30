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
using System.Text;

using Crypto;

namespace SSLTLS {

internal class RecordEncryptChaPol : RecordEncrypt {

	Poly1305 pp;
	byte[] iv;
	byte[] nonce;
	byte[] tmp;
	byte[] tag;
	ulong seq;

	internal RecordEncryptChaPol(Poly1305 pp, byte[] iv)
	{
		this.pp = pp;
		this.iv = new byte[12];
		Array.Copy(iv, 0, this.iv, 0, 12);
		nonce = new byte[12];
		tmp = new byte[13];
		tag = new byte[16];
		seq = 0;
	}

	internal override void GetMaxPlaintext(ref int start, ref int end)
	{
		/*
		 * We need room at the start for the record header (5 bytes)
		 * and some at the end for the MAC (16 bytes).
		 */
		start += 5;
		end -= 16;
		int len = Math.Min(end - start, 16384);
		end = start + len;
	}

	internal override void Encrypt(int recordType, int version,
		byte[] data, ref int off, ref int len)
	{
		/*
		 * Make the "additional data" for the MAC:
		 *  -- sequence number (8 bytes, big-endian)
		 *  -- header with plaintext length (5 bytes)
		 */
		IO.Enc64be(seq, tmp, 0);
		IO.WriteHeader(recordType, version, len, tmp, 8);

		/*
		 * The ChaCha20+Poly1305 IV consists in the
		 * implicit IV (12 bytes), with the sequence number
		 * "XORed" in the last 8 bytes (big-endian).
		 */
		Array.Copy(iv, 0, nonce, 0, 12);
		for (int i = 0; i < 8; i ++) {
			nonce[i + 4] ^= tmp[i];
		}

		/*
		 * Do encryption and compute tag.
		 */
		pp.Run(nonce, data, off, len, tmp, 0, 13, tag, true);

		/*
		 * Copy back tag where appropriate and add header.
		 */
		Array.Copy(tag, 0, data, off + len, 16);
		off -= 5;
		len += 16;
		IO.WriteHeader(recordType, version, len, data, off);
		len += 5;

		/*
		 * Each record has its own sequence number.
		 */
		seq ++;
	}
}

}
