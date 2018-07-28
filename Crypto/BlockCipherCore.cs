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

namespace Crypto {

/*
 * This class is a convenient base class for implementations of
 * IBlockCipher. Block cipher implementations must implement:
 *    int BlockSize { get; }
 *    void SetKey(byte[] key, int off, int len)
 *    void BlockEncrypt(byte[] data, int off)
 *    void BlockDecrypt(byte[] data, int off)
 *
 * Note that 'BlockSize' is invoked from the constructor of this class.
 *
 * Implementations MAY also override the default implementations of:
 *    void CBCEncrypt(byte[] iv, byte[] data)
 *    void CBCEncrypt(byte[] iv, byte[] data, int off, int len)
 *    void CBCDecrypt(byte[] iv, byte[] data)
 *    void CBCDecrypt(byte[] iv, byte[] data, int off, int len)
 *    uint CTRRun(byte[] iv, uint cc, byte[] data)
 *    uint CTRRun(byte[] iv, uint cc, byte[] data, int off, int len)
 *    void CTRCBCRun(byte[] ctr, byte[] cbcmac, bool encrypt, byte[] data)
 *    void CTRCBCRun(byte[] ctr, byte[] cbcmac, bool encrypt,
 *                   byte[] data, int off, int len)
 * Note that CBCEncrypt(byte[],byte[]) (respectively
 * CBCDecrypt(byte[],byte[]), CTRRun(byte[],uint,byte[]) and
 * CTRCBCRun(byte[],byte[],bool,byte[])) simply calls
 * CBCEncrypt(byte[],byte[],int,int) (respectively
 * CBCDecrypt(byte[],byte[],int,int), CTRRun(byte[],uint,byte[],int,int)
 * and CTRCBCRun(byte[],byte[],bool,byte[],int,int)) so implementations
 * who wish to override these methods may content themselves with
 * overriding the four methods with the "off" and "len" extra parameters.
 */

public abstract class BlockCipherCore : IBlockCipher {

	byte[] tmp;

	/*
	 * This constructor invokes 'BlockSize'.
	 */
	public BlockCipherCore()
	{
		tmp = new byte[BlockSize];
	}

	/* see IBlockCipher */
	public abstract int BlockSize { get; }

	/*
	 * This method is implemented by calling SetKey(byte[],int,int).
	 */
	public virtual void SetKey(byte[] key)
	{
		SetKey(key, 0, key.Length);
	}

	/* see IBlockCipher */
	public abstract void SetKey(byte[] key, int off, int len);

	/*
	 * This method is implemented by calling BlockEncrypt(byte[],int).
	 */
	public virtual void BlockEncrypt(byte[] buf)
	{
		BlockEncrypt(buf, 0);
	}

	/* see IBlockCipher */
	public abstract void BlockEncrypt(byte[] data, int off);

	/*
	 * This method is implemented by calling BlockDecrypt(byte[],int).
	 */
	public virtual void BlockDecrypt(byte[] buf)
	{
		BlockDecrypt(buf, 0);
	}

	/* see IBlockCipher */
	public abstract void BlockDecrypt(byte[] data, int off);

	/*
	 * This method is implemented by calling
	 * CBCEncrypt(byte[],byte[],int,int).
	 */
	public virtual void CBCEncrypt(byte[] iv, byte[] data)
	{
		CBCEncrypt(iv, data, 0, data.Length);
	}

	/* see IBlockCipher */
	public virtual void CBCEncrypt(
		byte[] iv, byte[] data, int off, int len)
	{
		int blen = BlockSize;
		if (iv.Length != blen) {
			throw new CryptoException("wrong IV length");
		}
		if (len >= blen) {
			for (int i = 0; i < blen; i ++) {
				data[off + i] ^= iv[i];
			}
			BlockEncrypt(data, off);
			off += blen;
			len -= blen;
			while (len >= blen) {
				for (int i = 0; i < blen; i ++) {
					data[off + i] ^= data[off + i - blen];
				}
				BlockEncrypt(data, off);
				off += blen;
				len -= blen;
			}
		}
		if (len != 0) {
			throw new CryptoException("data length is not"
				+ " multiple of the block size");
		}
	}

	/*
	 * This method is implemented by calling
	 * CBCDecrypt(byte[],byte[],int,int).
	 */
	public virtual void CBCDecrypt(byte[] iv, byte[] data)
	{
		CBCDecrypt(iv, data, 0, data.Length);
	}

	/* see IBlockCipher */
	public virtual void CBCDecrypt(
		byte[] iv, byte[] data, int off, int len)
	{
		int blen = BlockSize;
		if (iv.Length != blen) {
			throw new CryptoException("wrong IV length");
		}
		int dblen = blen << 1;
		off += len;
		while (len >= dblen) {
			off -= blen;
			BlockDecrypt(data, off);
			for (int i = 0; i < blen; i ++) {
				data[off + i] ^= data[off + i - blen];
			}
			len -= blen;
		}
		if (len >= blen) {
			off -= blen;
			BlockDecrypt(data, off);
			for (int i = 0; i < blen; i ++) {
				data[off + i] ^= iv[i];
			}
			len -= blen;
		}
		if (len != 0) {
			throw new CryptoException("data length is not"
				+ " multiple of the block size");
		}
	}

	/*
	 * This method is implemented by calling
	 * CTRRun(byte[],uint,byte[],int,int).
	 */
	public virtual uint CTRRun(byte[] iv, uint cc, byte[] data)
	{
		return CTRRun(iv, cc, data, 0, data.Length);
	}

	/* see IBlockCipher */
	public virtual uint CTRRun(
		byte[] iv, uint cc, byte[] data, int off, int len)
	{
		int blen = BlockSize;
		if (iv.Length != blen - 4) {
			throw new CryptoException("wrong IV length");
		}
		while (len > 0) {
			Array.Copy(iv, 0, tmp, 0, blen - 4);
			tmp[blen - 4] = (byte)(cc >> 24);
			tmp[blen - 3] = (byte)(cc >> 16);
			tmp[blen - 2] = (byte)(cc >> 8);
			tmp[blen - 1] = (byte)cc;
			BlockEncrypt(tmp, 0);
			int clen = Math.Min(blen, len);
			for (int i = 0; i < clen; i ++) {
				data[off + i] ^= tmp[i];
			}
			off += clen;
			len -= clen;
			cc ++;
		}
		return cc;
	}

	/*
	 * This method is implemented by calling
	 * CTRCBCRun(byte[],byte[],bool,byte[],int,int).
	 */
	public virtual void CTRCBCRun(byte[] ctr, byte[] cbcmac,
		bool encrypt, byte[] data)
	{
		CTRCBCRun(ctr, cbcmac, encrypt, data, 0, data.Length);
	}

	/* see IBlockCipher */
	public virtual void CTRCBCRun(byte[] ctr, byte[] cbcmac,
		bool encrypt, byte[] data, int off, int len)
	{
		if (!encrypt) {
			CBCMac(cbcmac, data, off, len);
		}
		DoCTRFull(ctr, data, off, len);
		if (encrypt) {
			CBCMac(cbcmac, data, off, len);
		}
	}

	void DoCTRFull(byte[] ctr, byte[] data, int off, int len)
	{
		int blen = BlockSize;
		if (ctr.Length != blen) {
			throw new CryptoException("wrong counter length");
		}
		while (len > 0) {
			Array.Copy(ctr, 0, tmp, 0, blen);
			uint cc = 1;
			for (int i = blen - 1; i >= 0; i --) {
				uint x = ctr[i] + cc;
				ctr[i] = (byte)x;
				cc = x >> 8;
			}
			BlockEncrypt(tmp, 0);
			int clen = Math.Min(blen, len);
			for (int i = 0; i < clen; i ++) {
				data[off + i] ^= tmp[i];
			}
			off += clen;
			len -= clen;
		}
	}

	/* see IBlockCipher */
	public void CBCMac(byte[] cbcmac, byte[] data, int off, int len)
	{
		int blen = BlockSize;
		if (cbcmac.Length != blen) {
			throw new CryptoException("wrong MAC length");
		}
		while (len > 0) {
			for (int i = 0; i < blen; i ++) {
				cbcmac[i] ^= data[off + i];
			}
			BlockEncrypt(cbcmac, 0);
			off += blen;
			len -= blen;
		}
	}

	/* see IBlockCipher */
	public abstract IBlockCipher Dup();
}

}
