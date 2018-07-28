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

internal class RecordEncryptCCM : RecordEncrypt {

	IBlockCipher bc;
	byte[] iv;
	ulong seq;
	byte[] tmp, tag, ctr, cbcmac;
	bool ccm8;

	internal RecordEncryptCCM(IBlockCipher bc, byte[] iv, bool ccm8)
	{
		this.bc = bc;
		this.iv = new byte[4];
		Array.Copy(iv, 0, this.iv, 0, 4);
		seq = 0;
		tag = new byte[16];
		tmp = new byte[32];
		ctr = new byte[16];
		cbcmac = new byte[16];
		this.ccm8 = ccm8;
	}

	internal override void GetMaxPlaintext(ref int start, ref int end)
	{
		/*
		 * We need room at the start for the record header (5 bytes)
		 * and the explicit nonce (8 bytes). We need room at the end
		 * for the MAC (16 bytes).
		 */
		start += 13;
		end -= ccm8 ? 8 : 16;
		int len = Math.Min(end - start, 16384);
		end = start + len;
	}

	internal override void Encrypt(int recordType, int version,
		byte[] data, ref int off, ref int len)
	{
		/*
		 * CBC-MAC starts with block B0, that encodes the
		 * nonce, tag length, and data length.
		 * It is then followed by the AAD:
		 *  - AAD header (length, over 2 bytes in our case)
		 *  - TLS sequence number (8 bytes)
		 *  - plain record header
		 */
		tmp[0] = (byte)(0x40 | ((ccm8 ? 6 : 14) << 2) | 2);
		Array.Copy(iv, 0, tmp, 1, 4);
		IO.Enc64be(seq, tmp, 5);
		tmp[13] = 0;
		IO.Enc16be(len, tmp, 14);

		tmp[16] = 0;
		tmp[17] = 13;
		IO.Enc64be(seq, tmp, 18);
		IO.WriteHeader(recordType, version, len, tmp, 26);
		tmp[31] = 0;

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
		Array.Copy(tmp, 1, ctr, 1, 12);
		for (int i = 13; i < 16; i ++) {
			ctr[i] = 0;
		}
		Array.Copy(ctr, 0, tag, 0, 16);
		bc.BlockEncrypt(tag);
		ctr[15] = 1;

		/*
		 * Perform CTR encryption and CBC-MAC. CCM is defined
		 * to use CBC-MAC on the plaintext, not the ciphertext,
		 * thus we need to set the 'encrypt' flag to false.
		 *
		 * When the last block is partial, then we must pad
		 * the plaintext with zeros, and compute the CBC-MAC
		 * on that plaintext.
		 */
		int len1 = len & ~15;
		int len2 = len - len1;
		bc.CTRCBCRun(ctr, cbcmac, false, data, off, len1);
		if (len2 > 0) {
			Array.Copy(data, off + len1, tmp, 0, len2);
			for (int i = len2; i < 16; i ++) {
				tmp[i] = 0;
			}
			bc.CBCMac(cbcmac, tmp, 0, 16);
			bc.BlockEncrypt(ctr);
			for (int i = 0; i < len2; i ++) {
				data[off + len1 + i] ^= ctr[i];
			}
		}

		/*
		 * XOR the CBC-MAC output with the tag mask.
		 */
		for (int i = 0; i < (ccm8 ? 8 : 16); i ++) {
			data[off + len + i] = (byte)(tag[i] ^ cbcmac[i]);
		}

		/*
		 * Encode the header, and adjust offset / length.
		 */
		off -= 13;
		len += ccm8 ? 16 : 24;
		IO.WriteHeader(recordType, version, len, data, off);
		IO.Enc64be(seq, data, off + 5);
		len += 5;

		seq ++;
	}
}

}
