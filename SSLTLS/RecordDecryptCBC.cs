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

internal class RecordDecryptCBC : RecordDecrypt {

	IBlockCipher bc;
	HMAC hm;
	byte[] iv, ivTmp;
	bool explicitIV;
	ulong seq;
	byte[] tmp1, tmp2;

	internal RecordDecryptCBC(IBlockCipher bc, HMAC hm, byte[] iv)
	{
		this.bc = bc;
		this.hm = hm;
		this.iv = new byte[bc.BlockSize];
		this.ivTmp = new byte[bc.BlockSize];
		if (iv == null) {
			explicitIV = true;
		} else {
			Array.Copy(iv, 0, this.iv, 0, iv.Length);
			explicitIV = false;
		}
		seq = 0;
		tmp1 = new byte[Math.Max(13, hm.MACSize)];
		tmp2 = new byte[Math.Max(13, hm.MACSize)];
	}

	internal override bool CheckLength(int len)
	{
		/*
		 * Record length (not counting the header) must be
		 * a multiple of the block size, and have enough room
		 * for the MAC and the padding-length byte. With
		 * TLS 1.1+, there must also be an explicit IV.
		 */
		int blen = bc.BlockSize;
		int hlen = hm.MACSize;
		if ((len & (blen - 1)) != 0) {
			return false;
		}
		int minLen = hlen + 1;
		int maxLen = (16384 + 256 + hlen) & ~(blen - 1);
		if (explicitIV) {
			minLen += blen;
			maxLen += blen;
		}
		return len >= minLen && len <= maxLen;
	}

	internal override bool Decrypt(int recordType, int version,
		byte[] data, ref int off, ref int len)
	{
		int blen = bc.BlockSize;
		int hlen = hm.MACSize;

		/*
		 * Grab a copy of the last encrypted block; this is
		 * the "saved IV" for the next record.
		 */
		Array.Copy(data, off + len - blen, ivTmp, 0, blen);

		/*
		 * Decrypt the data. The length has already been
		 * checked. If there is an explicit IV, it gets
		 * "decrypted" as well, which is not a problem.
		 */
		bc.CBCDecrypt(iv, data, off, len);
		Array.Copy(ivTmp, 0, iv, 0, blen);
		if (explicitIV) {
			off += blen;
			len -= blen;
		}

		/*
		 * Compute minimum and maximum length of plaintext + MAC.
		 * These can be inferred from the observable record length,
		 * and thus are not secret.
		 */
		int minLen = (hlen + 256 < len) ? len - 256 : hlen;
		int maxLen = len - 1;

		/*
		 * Get the actual padding length and check padding. The
		 * padding length must match the minLen/maxLen range.
		 */
		int padLen = data[off + len - 1];
		int good = ~(((maxLen - minLen) - padLen) >> 31);
		int lenWithMAC = minLen ^ (good & (minLen ^ (maxLen - padLen)));
		int dbb = 0;
		for (int i = minLen; i < maxLen; i ++) {
			dbb |= ~((i - lenWithMAC) >> 31)
				& (data[off + i] ^ padLen);
		}
		good &= ~((dbb | -dbb) >> 31);

		/*
		 * Extract the MAC value; this is done in one pass, but
		 * results in a "rotate" MAC value. The rotation count
		 * is kept in 'rotCount': this is the offset of the
		 * first MAC value byte in tmp1[].
		 */
		int lenNoMAC = lenWithMAC - hlen;
		minLen -= hlen;
		int rotCount = 0;
		for (int i = 0; i < hlen; i ++) {
			tmp1[i] = 0;
		}
		int v = 0;
		for (int i = minLen; i < maxLen; i ++) {
			int m = ~((i - lenNoMAC) >> 31)
				& ((i - lenWithMAC) >> 31);
			tmp1[v] |= (byte)(m & data[off + i]);
			m = i - lenNoMAC;
			rotCount |= ~((m | -m) >> 31) & v;
			if (++ v == hlen) {
				v = 0;
			}
		}
		maxLen -= hlen;

		/*
		 * Rotate back the MAC value. We do it bit by bit, with
		 * 6 iterations; this is good for all MAC value up to
		 * and including 64 bytes.
		 */
		for (int i = 5; i >= 0; i --) {
			int rc = 1 << i;
			if (rc >= hlen) {
				continue;
			}
			int ctl = -((rotCount >> i) & 1);
			for (int j = 0, k = rc; j < hlen; j ++) {
				int b1 = tmp1[j];
				int b2 = tmp1[k];
				tmp2[j] = (byte)(b1 ^ (ctl & (b1 ^ b2)));
				if (++ k == hlen) {
					k = 0;
				}
			}
			Array.Copy(tmp2, 0, tmp1, 0, hlen);
			rotCount &= ~rc;
		}

		/*
		 * Recompute the HMAC value. At that point, minLen and
		 * maxLen have been adjusted to match the plaintext
		 * without the MAC.
		 */
		IO.Enc64be(seq ++, tmp2, 0);
		IO.WriteHeader(recordType, version, lenNoMAC, tmp2, 8);
		hm.Update(tmp2, 0, 13);
		hm.ComputeCT(data, off, lenNoMAC, minLen, maxLen, tmp2, 0);

		/*
		 * Compare MAC values.
		 */
		dbb = 0;
		for (int i = 0; i < hlen; i ++) {
			dbb |= tmp1[i] ^ tmp2[i];
		}
		good &= ~((dbb | -dbb) >> 31);

		/*
		 * We must also check that the plaintext length fits in
		 * the maximum allowed by the standard (previous check
		 * was on the encrypted length).
		 */
		good &= (lenNoMAC - 16385) >> 31;
		len = lenNoMAC;
		return good != 0;
	}
}

}
