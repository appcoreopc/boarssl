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

internal class RecordDecryptGCM : RecordDecrypt {

	IBlockCipher bc;
	byte[] iv;
	byte[] h;
	ulong seq;
	byte[] tmp, tag;

	internal RecordDecryptGCM(IBlockCipher bc, byte[] iv)
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

	internal override bool CheckLength(int len)
	{
		return len >= 24 && len <= (16384 + 24);
	}

	internal override bool Decrypt(int recordType, int version,
		byte[] data, ref int off, ref int len)
	{
		off += 8;
		len -= 24;
		IO.Enc64be(seq, tmp, 0);
		IO.WriteHeader(recordType, version, len, tmp, 8);
		IO.Enc64be(13 << 3, tmp, 13);
		IO.Enc64be((ulong)len << 3, tmp, 21);
		for (int i = 0; i < 16; i ++) {
			tag[i] = 0;
		}
		GHASH.Run(tag, h, tmp, 0, 13);
		GHASH.Run(tag, h, data, off, len);
		GHASH.Run(tag, h, tmp, 13, 16);
		seq ++;

		Array.Copy(data, off - 8, iv, 4, 8);
		bc.CTRRun(iv, 2, data, off, len);
		bc.CTRRun(iv, 1, data, off + len, 16);

		int z = 0;
		for (int i = 0; i < 16; i ++) {
			z |= tag[i] ^ data[off + len + i];
		}
		return z == 0;
	}
}

}
