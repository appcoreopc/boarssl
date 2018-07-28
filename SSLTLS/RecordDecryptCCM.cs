/*
 * Copyright (c) 2018 Thomas Pornin <pornin@bolet.org>
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

internal class RecordDecryptCCM : RecordDecrypt {

	IBlockCipher bc;
	byte[] iv;
	ulong seq;
	byte[] tmp, tag, ctr, cbcmac;
	bool ccm8;

	internal RecordDecryptCCM(IBlockCipher bc, byte[] iv, bool ccm8)
	{
		this.bc = bc;
		this.iv = new byte[12];
		Array.Copy(iv, 0, this.iv, 0, 4);
		seq = 0;
		tag = new byte[16];
		tmp = new byte[32];
		ctr = new byte[16];
		cbcmac = new byte[16];
		this.ccm8 = ccm8;
	}

	internal override bool CheckLength(int len)
	{
		int tagLen = ccm8 ? 8 : 16;
		return len >= (8 + tagLen) && len <= (16384 + 8 + tagLen);
	}

	internal override bool Decrypt(int recordType, int version,
		byte[] data, ref int off, ref int len)
	{
		Array.Copy(data, off, iv, 4, 8);
		off += 8;
		len -= ccm8 ? 16 : 24;

		/*
		 * Assemble block B0 and AAD.
		 */
		tmp[0] = (byte)(0x40 | ((ccm8 ? 6 : 14) << 2) | 2);
		Array.Copy(iv, 0, tmp, 1, 12);
		tmp[13] = 0;
		IO.Enc16be(len, tmp, 14);

		tmp[16] = 0;
		tmp[17] = 13;
		IO.Enc64be(seq, tmp, 18);
		IO.WriteHeader(recordType, version, len, tmp, 26);
		tmp[31] = 0;
		seq ++;

		for (int i = 0; i < cbcmac.Length; i ++) {
			cbcmac[i] = 0;
		}
		bc.CBCMac(cbcmac, tmp, 0, 32);

		/*
		 * Make initial counter value, and compute tag mask.
		 * Since the counter least significant byte has value 0,
		 * getting it to the next value is simple and requires
		 * no carry propagation.
		 */
		ctr[0] = 2;
		Array.Copy(iv, 0, ctr, 1, 12);
		for (int i = 13; i < 16; i ++) {
			ctr[i] = 0;
		}
		Array.Copy(ctr, 0, tag, 0, 16);
		bc.BlockEncrypt(tag);
		ctr[15] = 1;

		/*
		 * Perform CTR decryption, and compute CBC-MAC. Since
		 * CBC-MAC requires full blocks, we have to do the
		 * processing of the last partial block in a temporary
		 * buffer. The CBC-MAC is computed on the plaintext,
		 * padded with zeros in the last block.
		 */
		int len1 = len & ~15;
		int len2 = len - len1;
		bc.CTRCBCRun(ctr, cbcmac, true, data, off, len1);
		if (len2 > 0) {
			bc.BlockEncrypt(ctr);
			for (int i = 0; i < len2; i ++) {
				data[off + len1 + i] ^= ctr[i];
			}
			Array.Copy(data, off + len1, tmp, 0, len2);
			for (int i = len2; i < 16; i ++) {
				tmp[i] = 0;
			}
			bc.CBCMac(cbcmac, tmp, 0, 16);
		}

		/*
		 * Check that the record MAC matches the expected value
		 * (taking into account the tag mask).
		 */
		int z = 0;
		for (int i = 0; i < (ccm8 ? 8 : 16); i ++) {
			z |= cbcmac[i] ^ tag[i] ^ data[off + len + i];
		}
		return z == 0;
	}
}

}
