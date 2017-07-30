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
 * This class contains some utility methods used for DSA and ECDSA.
 */

public class DSAUtils {

	/*
	 * Convert an ASN.1 DSA signature to "raw" format. A "raw" signature
	 * is the concatenation of two unsigned big-endian integers of
	 * the same length. An ASN.1 signature is a DER-encoded SEQUENCE
	 * of two INTEGER values. The returned signature will have the
	 * minimum length that can hold the two signature elements; use
	 * SigRawNormalize() to adjust that length.
	 *
	 * If the source signature is syntaxically invalid (not valid DER),
	 * then null is returned.
	 */
	public static byte[] SigAsn1ToRaw(byte[] sig)
	{
		return SigAsn1ToRaw(sig, 0, sig.Length);
	}

	public static byte[] SigAsn1ToRaw(byte[] sig, int off, int len)
	{
		int lim = off + len;
		if (len <= 2 || sig[off ++] != 0x30) {
			return null;
		}
		int tlen = DecodeLength(sig, ref off, lim);
		if (tlen != (lim - off)) {
			return null;
		}
		int roff, rlen;
		int soff, slen;
		if (!DecodeInteger(sig, ref off, lim, out roff, out rlen)) {
			return null;
		}
		if (!DecodeInteger(sig, ref off, lim, out soff, out slen)) {
			return null;
		}
		if (off != lim) {
			return null;
		}
		int ulen = Math.Max(rlen, slen);
		byte[] raw = new byte[ulen << 1];
		Array.Copy(sig, roff, raw, ulen - rlen, rlen);
		Array.Copy(sig, soff, raw, (ulen << 1) - slen, slen);
		return raw;
	}

	static int DecodeLength(byte[] buf, ref int off, int lim)
	{
		if (off >= lim) {
			return -1;
		}
		int fb = buf[off ++];
		if (fb < 0x80) {
			return fb;
		}
		int elen = fb - 0x80;
		if (elen == 0) {
			return -1;
		}
		int acc = 0;
		while (elen -- > 0) {
			if (off >= lim) {
				return -1;
			}
			if (acc > 0x7FFFFF) {
				return -1;
			}
			acc = (acc << 8) + buf[off ++];
		}
		return acc;
	}

	static bool DecodeInteger(byte[] buf, ref int off, int lim,
		out int voff, out int vlen)
	{
		voff = -1;
		vlen = -1;
		if (off >= lim || buf[off ++] != 0x02) {
			return false;
		}
		int len = DecodeLength(buf, ref off, lim);
		if (len <= 0 || len > (lim - off)) {
			return false;
		}
		voff = off;
		vlen = len;
		off += len;
		while (vlen > 1 && buf[voff] == 0x00) {
			voff ++;
			vlen --;
		}
		return true;
	}

	/*
	 * Reduce a "raw" signature to its minimal length. The minimal
	 * length depends on the values of the inner elements; normally,
	 * that length is equal to twice the length of the encoded
	 * subgroup order, but it can be shorter by a few bytes
	 * (occasionally by two bytes; shorter signatures are very
	 * rare).
	 *
	 * If the source signature is null or has an odd length, then
	 * null is returned. If the source signature already has
	 * minimal length, then it is returned as is. Otherwise,
	 * a new array is created with the minimal length, filled,
	 * and returned.
	 */
	public static byte[] SigRawMinimalize(byte[] sigRaw)
	{
		int minLen = GetMinRawLength(sigRaw);
		if (minLen <= 0) {
			return null;
		}
		if (minLen == sigRaw.Length) {
			return sigRaw;
		}
		int m = sigRaw.Length >> 1;
		int lh = minLen >> 1;
		byte[] sig = new byte[lh + lh];
		Array.Copy(sigRaw, m - lh, sig, 0, lh);
		Array.Copy(sigRaw, m + m - lh, sig, lh, lh);
		return sig;
	}

	/*
	 * Normalize a "raw" signature to the specified length. If
	 * the source array already has the right length, then it is
	 * returned as is. Otherwise, a new array is created with the
	 * requested length, and filled with the signature elements.
	 *
	 * If the source signature is null, or has an odd length, then
	 * null is returned. If the requested length is not valid (odd
	 * length) or cannot be achieved (because the signature elements
	 * are too large), then null is returned.
	 */
	public static byte[] SigRawNormalize(byte[] sigRaw, int len)
	{
		int minLen = GetMinRawLength(sigRaw);
		if (minLen <= 0) {
			return null;
		}
		if ((len & 1) != 0) {
			return null;
		}
		int hlen = len >> 1;
		if (sigRaw.Length == len) {
			return sigRaw;
		}
		int m = sigRaw.Length >> 1;
		int lh = minLen >> 1;
		byte[] sig = new byte[len];
		Array.Copy(sigRaw, m - lh, sig, hlen - lh, lh);
		Array.Copy(sigRaw, m + m - lh, sig, len - lh, lh);
		return sig;
	}

	static int GetMinRawLength(byte[] sig)
	{
		if (sig == null || (sig.Length & 1) != 0) {
			return -1;
		}
		int m = sig.Length << 1;
		int lr, ls;
		for (lr = m; lr > 0; lr --) {
			if (sig[m - lr] != 0) {
				break;
			}
		}
		for (ls = m; ls > 0; ls --) {
			if (sig[m + m - ls] != 0) {
				break;
			}
		}
		return Math.Max(lr, ls) << 1;
	}

	/*
	 * Convert a "raw" DSA signature to ASN.1. A "raw" signature
	 * is the concatenation of two unsigned big-endian integers of
	 * the same length. An ASN.1 signature is a DER-encoded SEQUENCE
	 * of two INTEGER values.
	 *
	 * If the source signature is syntaxically invalid (zero length,
	 * or odd length), then null is returned.
	 */
	public static byte[] SigRawToAsn1(byte[] sig)
	{
		return SigRawToAsn1(sig, 0, sig.Length);
	}

	public static byte[] SigRawToAsn1(byte[] sig, int off, int len)
	{
		if (len <= 0 || (len & 1) != 0) {
			return null;
		}
		int tlen = len >> 1;
		int rlen = LengthOfInteger(sig, off, tlen);
		int slen = LengthOfInteger(sig, off + tlen, tlen);
		int ulen = 1 + LengthOfLength(rlen) + rlen
			+ 1 + LengthOfLength(slen) + slen;
		byte[] s = new byte[1 + LengthOfLength(ulen) + ulen];
		int k = 0;
		s[k ++] = 0x30;
		k += EncodeLength(ulen, s, k);
		k += EncodeInteger(sig, off, tlen, s, k);
		k += EncodeInteger(sig, off + tlen, tlen, s, k);
		// DEBUG
		if (k != s.Length) {
			throw new Exception("DSA internal error");
		}
		return s;
	}

	/*
	 * Get the length of the value of an INTEGER containing a
	 * specified value. Returned length includes the leading 0x00
	 * byte (if applicable) but not the tag or length fields.
	 */
	static int LengthOfInteger(byte[] x, int off, int len)
	{
		while (len > 0 && x[off] == 0) {
			off ++;
			len --;
		}
		if (len == 0) {
			return 1;
		}
		return (x[off] >= 0x80) ? len + 1 : len;
	}

	static int LengthOfLength(int len)
	{
		if (len < 0x80) {
			return 1;
		} else if (len < 0x100) {
			return 2;
		} else if (len < 0x10000) {
			return 3;
		} else if (len < 0x1000000) {
			return 4;
		} else {
			return 5;
		}
	}

	static int EncodeLength(int len, byte[] dst, int off)
	{
		if (len < 0x80) {
			dst[off] = (byte)len;
			return 1;
		}
		int k = 0;
		for (int z = len; z != 0; z >>= 8) {
			k ++;
		}
		dst[off] = (byte)(0x80 + k);
		for (int i = 0; i < k; i ++) {
			dst[off + k - i] = (byte)(len >> (i << 3));
		}
		return k + 1;
	}

	static int EncodeInteger(byte[] x, int off, int len,
		byte[] dst, int dstOff)
	{
		int orig = dstOff;
		dst[dstOff ++] = 0x02;
		while (len > 0 && x[off] == 0) {
			off ++;
			len --;
		}
		if (len == 0) {
			dst[dstOff ++] = 0x01;
			dst[dstOff ++] = 0x00;
			return dstOff - orig;
		}
		if (x[off] >= 0x80) {
			dstOff += EncodeLength(len + 1, dst, dstOff);
			dst[dstOff ++] = 0x00;
		} else {
			dstOff += EncodeLength(len, dst, dstOff);
		}
		Array.Copy(x, off, dst, dstOff, len);
		dstOff += len;
		return dstOff - orig;
	}
}

}
