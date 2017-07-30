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
 * Implementation of HMAC (RFC 2104).
 */

public sealed class HMAC {

	IDigest h;
	byte[] key;
	int keyLen;
	byte[] tmp, tmpCT;
	ulong dataLen;

	/*
	 * Create a new instance, using the provided hash function. The
	 * hash function instance will be used internally.
	 */
	public HMAC(IDigest h) : this(h, true)
	{
	}

	private HMAC(IDigest h, bool doReset)
	{
		this.h = h;
		int n = h.BlockSize;
		if (n < h.DigestSize) {
			throw new ArgumentException(
				"invalid hash function for HMAC");
		}
		key = new byte[n];
		keyLen = 0;
		tmp = new byte[h.DigestSize];
		tmpCT = new byte[h.DigestSize];
		if (doReset) {
			Reset();
		}
	}

	/*
	 * Duplicate this engine. The returned instance inherits the
	 * current state (key, data already processed...) but is
	 * thereafter independent.
	 */
	public HMAC Dup()
	{
		HMAC hm = new HMAC(h.Dup(), false);
		Array.Copy(key, 0, hm.key, 0, keyLen);
		hm.keyLen = keyLen;
		hm.dataLen = dataLen;
		return hm;
	}

	/*
	 * Get the HMAC output size (in bytes).
	 */
	public int MACSize {
		get {
			return h.DigestSize;
		}
	}

	/*
	 * Set the HMAC key. This implies a call to Reset() (thus,
	 * the key must be set before data begins to be inserted).
	 */
	public void SetKey(byte[] key)
	{
		SetKey(key, 0, key.Length);
	}

	/*
	 * Set the HMAC key ('len' bytes, starting at offset 'off' in key[]).
	 */
	public void SetKey(byte[] key, int off, int len)
	{
		h.Reset();
		if (len > h.BlockSize) {
			h.Update(key, off, len);
			h.DoFinal(this.key, 0);
			keyLen = h.DigestSize;
		} else {
			Array.Copy(key, off, this.key, 0, len);
			keyLen = len;
		}
		Reset();
	}

	/*
	 * Add one byte to the input to HMAC.
	 */
	public void Update(byte b)
	{
		h.Update(b);
		dataLen ++;
	}

	/*
	 * Add some bytes to the input to HMAC.
	 */
	public void Update(byte[] buf)
	{
		h.Update(buf, 0, buf.Length);
	}

	/*
	 * Add some bytes to the input to HMAC ('len' bytes from buf[],
	 * starting at offset 'off').
	 */
	public void Update(byte[] buf, int off, int len)
	{
		h.Update(buf, off, len);
		dataLen += (ulong)len;
	}

	/*
	 * Compute the HMAC value; it is written in outBuf[] at
	 * offset 'off'. The engine is also reset (as if Reset()
	 * was called).
	 */
	public void DoFinal(byte[] outBuf, int off)
	{
		h.DoFinal(tmp, 0);
		ProcessKey(0x5C);
		h.Update(tmp);
		h.DoFinal(outBuf, off);
		Reset();
	}

	/*
	 * Compute the HMAC value; it is written to a newly allocated
	 * array, which is returned. The engine is also reset (as if
	 * Reset() was called).
	 */
	public byte[] DoFinal()
	{
		byte[] r = new byte[h.DigestSize];
		DoFinal(r, 0);
		return r;
	}

	/*
	 * Reset the HMAC engine. This forgets all previously input
	 * data, but reuses the currently set key.
	 */
	public void Reset()
	{
		h.Reset();
		ProcessKey(0x36);
		dataLen = 0;
	}

	/*
	 * Process some bytes, then compute the output.
	 *
	 * This function is supposed to implement the processing in
	 * constant time (and thus constant memory access pattern) for
	 * all values of 'len' between 'minLen' and 'maxLen'
	 * (inclusive). This function works only for the supported
	 * underlying hash functions (MD5, SHA-1 and the SHA-2
	 * functions).
	 *
	 * The source array (buf[]) must contain at least maxLen bytes
	 * (starting at offset 'off'); they will all be read.
	 */
	public void ComputeCT(byte[] buf, int off, int len,
		int minLen, int maxLen, byte[] outBuf, int outOff)
	{
		/*
		 * Padding is 0x80, followed by 0 to 63 bytes of value
		 * 0x00 (up to 127 bytes for SHA-384 and SHA-512), then
		 * the input bit length expressed over 64 bits
		 * (little-endian for MD5, big-endian for
		 * the SHA-* functions)(for SHA-384 and SHA-512, this is
		 * 128 bits).
		 *
		 * Note that we only support bit lengths that fit on
		 * 64 bits, so we can handle SHA-384/SHA-512 padding
		 * almost as if it was the same as SHA-256; we just have
		 * to take care of the larger blocks (128 bytes instead
		 * of 64) and the larger minimal overhead (17 bytes
		 * instead of 9 bytes).
		 *
		 * be   true for big-endian length encoding
		 * bs   block size, in bytes (must be a power of 2)
		 * po   padding overhead (0x80 byte and length encoding)
		 */
		bool be;
		int bs, po;
		if (h is MD5) {
			be = false;
			bs = 64;
			po = 9;
		} else if ((h is SHA1) || (h is SHA2Small)) {
			be = true;
			bs = 64;
			po = 9;
		} else if (h is SHA2Big) {
			be = true;
			bs = 128;
			po = 17;
		} else {
			throw new NotSupportedException();
		}

		/*
		 * Method implemented here is inspired from the one
		 * described there:
		 * https://www.imperialviolet.org/2013/02/04/luckythirteen.html
		 */

		/*
		 * We compute the data bit length; let's not forget
		 * the initial first block (the one with the HMAC key).
		 */
		ulong bitLen = ((ulong)bs + dataLen + (ulong)len) << 3;

		/*
		 * All complete blocks before minLen can be processed
		 * efficiently.
		 */
		ulong nDataLen = (dataLen + (ulong)minLen) & ~(ulong)(bs - 1);
		if (nDataLen > dataLen) {
			int zlen = (int)(nDataLen - dataLen);
			h.Update(buf, off, (int)(nDataLen - dataLen));
			dataLen = nDataLen;
			off += zlen;
			len -= zlen;
			maxLen -= zlen;
		}

		/*
		 * At that point:
		 * -- dataLen contains the number of bytes already processed
		 * (in total, not counting the initial key block).
		 * -- We must input 'len' bytes, which may be up to 'maxLen'
		 * (inclusive).
		 *
		 * We compute kr, kl, kz and km:
		 *  kr   number of input bytes already in the current block
		 *  km   index of the first byte after the end of the last
		 *       padding block, if 'len' is equal to 'maxLen'
		 *  kz   index of the last byte of the actual last padding
		 *       block
		 *  kl   index of the start of the encoded length
		 */
		int kr = (int)dataLen & (bs - 1);
		int kz = ((kr + len + po + bs - 1) & ~(bs - 1)) - 1 - kr;
		int kl = kz - 7;
		int km = ((kr + maxLen + po + bs - 1) & ~(bs - 1)) - kr;

		/*
		 * We must process km bytes. For index i from 0 to km-1:
		 *   d is from data[] if i < maxLen, 0x00 otherwise
		 *   e is an encoded length byte or 0x00, depending on i
		 * These tests do not depend on the actual length, so
		 * they need not be constant-time.
		 *
		 * Actual input byte is:
		 *   d      if i < len
		 *   0x80   if i == len
		 *   0x00   if i > len and i < kl
		 *   e      if i >= kl
		 *
		 * We extract hash state whenever we reach a full block;
		 * we keep it only if i == kz.
		 */
		int hlen = h.DigestSize;
		for (int k = 0; k < hlen; k ++) {
			tmp[k] = 0;
		}
		for (int i = 0; i < km; i ++) {
			int d = (i < maxLen) ? buf[off + i] : 0x00;
			int e;
			int j = (kr + i) & (bs - 1);
			if (j >= (bs - 8)) {
				int k = (j - (bs - 8)) << 3;
				if (be) {
					e = (int)(bitLen >> (56 - k));
				} else {
					e = (int)(bitLen >> k);
				}
				e &= 0xFF;
			} else {
				e = 0x00;
			}

			/*
			 * x0 is 0x80 if i == len; otherwise it is d.
			 */
			int z = i - len;
			int x0 = 0x80 ^ (((z | -z) >> 31) & (0x80 ^ d));

			/*
			 * x1 is e if i >= kl; otherwise it is 0x00.
			 */
			int x1 = e & ~((i - kl) >> 31);

			/*
			 * We input x0 if i <= len, x1 otherwise.
			 */
			h.Update((byte)(x0 ^ (((len - i) >> 31) & (x0 ^ x1))));

			/*
			 * Get current state if we are at the end of a block,
			 * and keep it if i == kz.
			 */
			if (j == (bs - 1)) {
				h.CurrentState(tmpCT, 0);
				z = i - kz;
				z = ~((z | -z) >> 31);
				for (int k = 0; k < hlen; k ++) {
					tmp[k] |= (byte)(z & tmpCT[k]);
				}
			}
		}

		/*
		 * We got the hash output in tmp[]; we must complete
		 * the HMAC computation.
		 */
		h.Reset();
		ProcessKey(0x5C);
		h.Update(tmp);
		h.DoFinal(outBuf, outOff);
		Reset();
	}

	void ProcessKey(byte pad)
	{
		for (int i = 0; i < keyLen; i ++) {
			h.Update((byte)(key[i] ^ pad));
		}
		for (int i = h.BlockSize - keyLen; i > 0; i --) {
			h.Update(pad);
		}
	}
}

}
