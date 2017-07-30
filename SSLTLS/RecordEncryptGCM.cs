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

internal class RecordEncryptGCM : RecordEncrypt {

	IBlockCipher bc;
	byte[] iv;
	byte[] h;
	ulong seq;
	byte[] tmp, tag;

	internal RecordEncryptGCM(IBlockCipher bc, byte[] iv)
	{
		this.bc = bc;
		this.iv = new byte[12];
		Array.Copy(iv, 0, this.iv, 0, 4);
		h = new byte[16];
		bc.BlockEncrypt(h);
		seq = 0;
		tag = new byte[16];
		tmp = new byte[29];
	}

	internal override void GetMaxPlaintext(ref int start, ref int end)
	{
		/*
		 * We need room at the start for the record header (5 bytes)
		 * and the explicit nonce (8 bytes). We need room at the end
		 * for the MAC (16 bytes).
		 */
		start += 13;
		end -= 16;
		int len = Math.Min(end - start, 16384);
		end = start + len;
	}

	internal override void Encrypt(int recordType, int version,
		byte[] data, ref int off, ref int len)
	{
		/*
		 * Explicit nonce is the encoded sequence number. We
		 * encrypt the data itself; the counter starts at 2
		 * (value 1 is for the authentication tag).
		 */
		IO.Enc64be(seq, data, off - 8);
		Array.Copy(data, off - 8, iv, 4, 8);
		bc.CTRRun(iv, 2, data, off, len);

		/*
		 * For the authentication tag:
		 *   header = sequence + 5-byte "plain" header
		 *   footer = the two relevant lengths (in bits)
		 */
		IO.Enc64be(seq, tmp, 0);
		IO.WriteHeader(recordType, version, len, tmp, 8);
		IO.Enc64be(13 << 3, tmp, 13);
		IO.Enc64be((ulong)len << 3, tmp, 21);

		/*
		 * Compute clear authentication tag.
		 */
		for (int i = 0; i < 16; i ++) {
			tag[i] = 0;
		}
		GHASH.Run(tag, h, tmp, 0, 13);
		GHASH.Run(tag, h, data, off, len);
		GHASH.Run(tag, h, tmp, 13, 16);

		/*
		 * Copy authentication tag and apply final encryption on it.
		 */
		Array.Copy(tag, 0, data, off + len, 16);
		bc.CTRRun(iv, 1, data, off + len, 16);

		/*
		 * Each record uses one sequence number.
		 */
		seq ++;

		/*
		 * Write encrypted header and return adjusted offset/length.
		 */
		off -= 13;
		len += 24;
		IO.WriteHeader(recordType, version, len, data, off);
		len += 5;
	}
}

}
