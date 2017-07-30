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

/*
 * Implementation of the TLS PRF function. This class implements both the
 * PRF for TLS 1.0 and 1.1 (based on MD5 and SHA-1), and the PRF for
 * TLS 1.2 (based on a provided hash function).
 */

public sealed class PRF {

	public static byte[] LABEL_MASTER_SECRET =
		Encoding.UTF8.GetBytes("master secret");
	public static byte[] LABEL_KEY_EXPANSION =
		Encoding.UTF8.GetBytes("key expansion");
	public static byte[] LABEL_CLIENT_FINISHED =
		Encoding.UTF8.GetBytes("client finished");
	public static byte[] LABEL_SERVER_FINISHED =
		Encoding.UTF8.GetBytes("server finished");

	HMAC hm1, hm2;
	byte[] bufa1, bufa2;
	byte[] bufb1, bufb2;

	/*
	 * Create a PRF instance, using both MD5 and SHA-1 (for TLS 1.0
	 * and TLS 1.1).
	 */
	public PRF() : this(new MD5(), new SHA1())
	{
	}

	/*
	 * Create a PRF instance, using the provided hash function (for
	 * TLS 1.2). The 'h' instance will be used internally.
	 */
	public PRF(IDigest h) : this(h, null)
	{
	}

	/*
	 * Get the "natural" output length; this is the output size,
	 * or sum of output sizes, of the underlying hash function(s).
	 */
	public int NaturalOutputSize {
		get {
			int len = hm1.MACSize;
			if (hm2 != null) {
				len += hm2.MACSize;
			}
			return len;
		}
	}

	PRF(IDigest h1, IDigest h2)
	{
		hm1 = new HMAC(h1);
		bufa1 = new byte[hm1.MACSize];
		bufb1 = new byte[hm1.MACSize];
		if (h2 == null) {
			hm2 = null;
			bufa2 = null;
			bufb2 = null;
		} else {
			hm2 = new HMAC(h2);
			bufa2 = new byte[hm2.MACSize];
			bufb2 = new byte[hm2.MACSize];
		}
	}

	/*
	 * Compute the PRF, result in outBuf[].
	 */
	public void GetBytes(byte[] secret, byte[] label, byte[] seed,
		byte[] outBuf)
	{
		GetBytes(secret, label, seed, outBuf, 0, outBuf.Length);
	}

	/*
	 * Compute the PRF, result in outBuf[] (at offset 'off', producing
	 * exactly 'len' bytes).
	 */
	public void GetBytes(byte[] secret, byte[] label, byte[] seed,
		byte[] outBuf, int off, int len)
	{
		for (int i = 0; i < len; i ++) {
			outBuf[off + i] = 0;
		}
		if (hm2 == null) {
			Phash(hm1, secret, 0, secret.Length,
				bufa1, bufb1,
				label, seed, outBuf, off, len);
		} else {
			int n = (secret.Length + 1) >> 1;
			Phash(hm1, secret, 0, n,
				bufa1, bufb1,
				label, seed, outBuf, off, len);
			Phash(hm2, secret, secret.Length - n, n,
				bufa2, bufb2,
				label, seed, outBuf, off, len);
		}
	}

	/*
	 * Compute the PRF, result is written in a newly allocated
	 * array (of length 'outLen' bytes).
	 */
	public byte[] GetBytes(byte[] secret, byte[] label, byte[] seed,
		int outLen)
	{
		byte[] r = new byte[outLen];
		GetBytes(secret, label, seed, r, 0, outLen);
		return r;
	}

	/*
	 * This function computes Phash with the specified HMAC
	 * engine, XORing the output with the current contents of
	 * the outBuf[] buffer.
	 */
	static void Phash(HMAC hm, byte[] s, int soff, int slen,
		byte[] bufa, byte[] bufb,
		byte[] label, byte[] seed,
		byte[] outBuf, int outOff, int outLen)
	{
		/*
		 * Set the key for HMAC.
		 */
		hm.SetKey(s, soff, slen);

		/*
		 * Compute A(1) = HMAC(secret, seed).
		 */
		hm.Update(label);
		hm.Update(seed);
		hm.DoFinal(bufa, 0);
		while (outLen > 0) {
			/*
			 * Next chunk: HMAC(secret, A(i) + label + seed)
			 */
			hm.Update(bufa);
			hm.Update(label);
			hm.Update(seed);
			hm.DoFinal(bufb, 0);
			int clen = Math.Min(hm.MACSize, outLen);
			for (int i = 0; i < clen; i ++) {
				outBuf[outOff ++] ^= bufb[i];
			}
			outLen -= clen;

			/*
			 * If we are not finished, then compute:
			 * A(i+1) = HMAC(secret, A(i))
			 */
			if (outLen > 0) {
				hm.Update(bufa);
				hm.DoFinal(bufa, 0);
			}
		}
	}
}

}
