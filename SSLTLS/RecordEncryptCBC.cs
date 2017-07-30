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

internal class RecordEncryptCBC : RecordEncrypt {

	IBlockCipher bc;
	HMAC hm;
	byte[] iv;
	bool explicitIV;
	ulong seq;
	byte[] tmp;

	internal RecordEncryptCBC(IBlockCipher bc, HMAC hm, byte[] iv)
	{
		this.bc = bc;
		this.hm = hm;
		this.iv = new byte[bc.BlockSize];
		if (iv == null) {
			explicitIV = true;
		} else {
			Array.Copy(iv, 0, this.iv, 0, iv.Length);
			explicitIV = false;
		}
		seq = 0;
		tmp = new byte[Math.Max(13, hm.MACSize)];
	}

	internal override void GetMaxPlaintext(ref int start, ref int end)
	{
		/*
		 * Add room for the record header.
		 */
		start += 5;

		int blen = bc.BlockSize;
		if (explicitIV) {
			start += blen;
		} else {
			/*
			 * We reserve room for an automatic 1/n-1 split.
			 */
			start += 4 + ((hm.MACSize + blen + 1) & ~(blen - 1));
		}
		int len = (end - start) & ~(blen - 1);
		len -= 1 + hm.MACSize;

		/*
		 * We keep a bit of extra room to try out overlong padding.
		 */
		len -= blen;

		if (len > 16384) {
			len = 16384;
		}
		end = start + len;
	}

	internal override void Encrypt(int recordType, int version,
		byte[] data, ref int off, ref int len)
	{
		if (explicitIV
			|| recordType != SSL.APPLICATION_DATA
			|| len <= 1)
		{
			EncryptInner(recordType, version,
				data, ref off, ref len);
			return;
		}

		/*
		 * Automatic 1/n-1 split. We do it only when there is
		 * no explicit IV (i.e. TLS 1.0, not TLS 1.1+), and there
		 * are at least two plaintext bytes in the record.
		 */
		int blen = bc.BlockSize;
		int off1 = off - (4 + ((hm.MACSize + blen + 1) & ~(blen - 1)));
		int len1 = 1;
		data[off1] = data[off];
		EncryptInner(recordType, version, data, ref off1, ref len1);
		int off2 = off + 1;
		int len2 = len - 1;
		EncryptInner(recordType, version, data, ref off2, ref len2);
		if (off1 + len1 != off2) {
			throw new Exception("Split gone wrong");
		}
		off = off1;
		len = len1 + len2;
	}

	void EncryptInner(int recordType, int version,
		byte[] data, ref int off, ref int len)
	{
		int blen = bc.BlockSize;
		int mlen = hm.MACSize;
		int doff = off;
		int dlen = len;

		if (explicitIV) {
			/*
			 * To make pseudorandom IV, we reuse HMAC, computed
			 * over the encoded sequence number. Since this
			 * input is distinct from all other HMAC inputs with
			 * the same key, this should be randomish enough
			 * (assuming HMAC is a good imitation of a random
			 * oracle).
			 */
			IO.Enc64be(seq, tmp, 0);
			hm.Update(tmp, 0, 8);
			hm.DoFinal(tmp, 0);
			Array.Copy(tmp, 0, data, off - blen, blen);
			off -= blen;
			len += blen;
		}

		/*
		 * Compute HMAC.
		 */
		IO.Enc64be(seq, tmp, 0);
		IO.WriteHeader(recordType, version, dlen, tmp, 8);
		hm.Update(tmp, 0, 13);
		hm.Update(data, doff, dlen);
		hm.DoFinal(data, off + len);
		len += mlen;
		seq ++;

		/*
		 * Add padding.
		 */
		int plen = blen - (len & (blen - 1));
		for (int i = 0; i < plen; i ++) {
			data[off + len + i] = (byte)(plen - 1);
		}
		len += plen;

		/*
		 * Perform CBC encryption. We use our saved IV. If there is
		 * an explicit IV, then it gets encrypted, which is fine
		 * (CBC encryption of randomness is equally good randomness).
		 */
		bc.CBCEncrypt(iv, data, off, len);
		Array.Copy(data, off + len - blen, iv, 0, blen);

		/*
		 * Add the header.
		 */
		off -= 5;
		IO.WriteHeader(recordType, version, len, data, off);
		len += 5;
	}
}

}
