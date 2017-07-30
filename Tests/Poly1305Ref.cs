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

using Crypto;

/*
 * This is a "reference" implementation of Poly1305 that uses the
 * generic ZInt code for computations. It is not constant-time, and
 * it is very slow; it is meant to test other implementations.
 *
 * API is identical to the Poly1305 class.
 */

public class Poly1305Ref {

	public ChaCha20 ChaCha {
		get; set;
	}

	public Poly1305Ref()
	{
	}

	static ZInt p = ((ZInt)1 << 130) - (ZInt)5;
	static ZInt rmask = ((ZInt)1 << 124) - (ZInt)1
		- ((ZInt)15 << 28) - ((ZInt)15 << 60) - ((ZInt)15 << 92)
		- ((ZInt)3 << 32) - ((ZInt)3 << 64) - ((ZInt)3 << 96);

	public void Run(byte[] iv,
		byte[] data, int off, int len,
		byte[] aad, int offAAD, int lenAAD,
		byte[] tag, bool encrypt)
	{
		byte[] pkey = new byte[32];
		ChaCha.Run(iv, 0, pkey);
		if (encrypt) {
			ChaCha.Run(iv, 1, data, off, len);
		}

		ByteSwap(pkey, 0, 16);
		ZInt r = ZInt.DecodeUnsignedBE(pkey, 0, 16);
		r &= rmask;
		ZInt a = (ZInt)0;

		a = RunInner(a, r, aad, offAAD, lenAAD);
		a = RunInner(a, r, data, off, len);
		byte[] foot = new byte[16];
		foot[ 0] = (byte)lenAAD;
		foot[ 1] = (byte)(lenAAD >> 8);
		foot[ 2] = (byte)(lenAAD >> 16);
		foot[ 3] = (byte)(lenAAD >> 24);
		foot[ 8] = (byte)len;
		foot[ 9] = (byte)(len >> 8);
		foot[10] = (byte)(len >> 16);
		foot[11] = (byte)(len >> 24);
		a = RunInner(a, r, foot, 0, 16);

		ByteSwap(pkey, 16, 16);
		ZInt s = ZInt.DecodeUnsignedBE(pkey, 16, 16);
		a += s;
		a.ToBytesLE(tag, 0, 16);

		if (!encrypt) {
			ChaCha.Run(iv, 1, data, off, len);
		}
	}

	ZInt RunInner(ZInt a, ZInt r, byte[] data, int off, int len)
	{
		byte[] tmp = new byte[16];
		while (len > 0) {
			if (len >= 16) {
				Array.Copy(data, off, tmp, 0, 16);
			} else {
				Array.Copy(data, off, tmp, 0, len);
				for (int i = len; i < 16; i ++) {
					tmp[i] = 0;
				}
			}
			ByteSwap(tmp, 0, 16);
			ZInt v = ZInt.DecodeUnsignedBE(tmp) | ((ZInt)1 << 128);
			a = ((a + v) * r) % p;
			off += 16;
			len -= 16;
		}
		return a;
	}

	static void ByteSwap(byte[] buf, int off, int len)
	{
		for (int i = 0; (i + i) < len; i ++) {
			byte t = buf[off + i];
			buf[off + i] = buf[off + len - 1 - i];
			buf[off + len - 1 - i] = t;
		}
	}
}
