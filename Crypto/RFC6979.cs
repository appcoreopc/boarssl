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
 * This class implements the computation of the transient secret value
 * "k" for DSA and ECDSA, using the method described in RFC 6979. It
 * can perform the deterministic computation, and optionally inject
 * extra random bytes when randomized signatures are needed.
 */

class RFC6979 {

	HMAC_DRBG drbg;
	byte[] q;
	int qlen;
	ModInt mh;

	internal RFC6979(IDigest h, byte[] q, byte[] x,
		byte[] hv, bool deterministic)
		: this(h, q, x, hv, 0, hv.Length, deterministic)
	{
	}

	internal RFC6979(IDigest h, byte[] q, byte[] x,
		byte[] hv, int hvOff, int hvLen, bool deterministic)
	{
		if (h == null) {
			h = new SHA256();
		} else {
			h = h.Dup();
			h.Reset();
		}
		drbg = new HMAC_DRBG(h);
		mh = new ModInt(q);
		qlen = mh.ModBitLength;
		int qolen = (qlen + 7) >> 3;
		this.q = new byte[qolen];
		Array.Copy(q, q.Length - qolen, this.q, 0, qolen);
		int hlen = hvLen << 3;
		if (hlen > qlen) {
			byte[] htmp = new byte[hvLen];
			Array.Copy(hv, hvOff, htmp, 0, hv.Length);
			BigInt.RShift(htmp, hlen - qlen);
			hv = htmp;
			hvOff = 0;
		}
		mh.DecodeReduce(hv, hvOff, hvLen);
		ModInt mx = mh.Dup();
		mx.Decode(x);

		byte[] seed = new byte[(qolen << 1) + (deterministic ? 0 : 32)];
		mx.Encode(seed, 0, qolen);
		mh.Encode(seed, qolen, qolen);
		if (!deterministic) {
			RNG.GetBytes(seed, qolen << 1,
				seed.Length - (qolen << 1));
		}
		drbg.SetSeed(seed);
	}

	internal ModInt GetHashMod()
	{
		return mh.Dup();
	}

	internal void NextK(byte[] k)
	{
		for (;;) {
			drbg.GetBytes(k);
			BigInt.RShift(k, (k.Length << 3) - qlen);
			if (!BigInt.IsZero(k) && BigInt.CompareCT(k, q) < 0) {
				return;
			}
		}
	}
}

}
