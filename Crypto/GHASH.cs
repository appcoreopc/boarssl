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
 * GHASH implementation using integer multiplications (32->64). It is
 * constant-time, provided that the platform multiplication opcode is
 * constant-time.
 */

public sealed class GHASH {

	/*
	 * Compute GHASH over the provided data. The y[] array is
	 * updated, using the h[] secret value. If the data length
	 * is not a multiple of 16 bytes, then it is right-padded
	 * with zeros.
	 */
	public static void Run(byte[] y, byte[] h, byte[] data)
	{
		Run(y, h, data, 0, data.Length);
	}

	/*
	 * Compute GHASH over the provided data. The y[] array is
	 * updated, using the h[] secret value. If the data length
	 * is not a multiple of 16 bytes, then it is right-padded
	 * with zeros.
	 */
	public static void Run(byte[] y, byte[] h,
		byte[] data, int off, int len)
	{
		uint y0, y1, y2, y3;
		uint h0, h1, h2, h3;
		y3 = Dec32be(y,  0);
		y2 = Dec32be(y,  4);
		y1 = Dec32be(y,  8);
		y0 = Dec32be(y, 12);
		h3 = Dec32be(h,  0);
		h2 = Dec32be(h,  4);
		h1 = Dec32be(h,  8);
		h0 = Dec32be(h, 12);

		while (len > 0) {
			/*
			 * Decode the next block and add it (XOR) into the
			 * current state.
			 */
			if (len >= 16) {
				y3 ^= Dec32be(data, off);
				y2 ^= Dec32be(data, off + 4);
				y1 ^= Dec32be(data, off + 8);
				y0 ^= Dec32be(data, off + 12);
			} else {
				y3 ^= Dec32bePartial(data, off +  0, len -  0);
				y2 ^= Dec32bePartial(data, off +  4, len -  4);
				y1 ^= Dec32bePartial(data, off +  8, len -  8);
				y0 ^= Dec32bePartial(data, off + 12, len - 12);
			}
			off += 16;
			len -= 16;

			/*
			 * We multiply two 128-bit field elements with
			 * two Karatsuba levels, to get down to nine
			 * 32->64 multiplications.
			 */
			uint a0 = y0;
			uint b0 = h0;
			uint a1 = y1;
			uint b1 = h1;
			uint a2 = a0 ^ a1;
			uint b2 = b0 ^ b1;

			uint a3 = y2;
			uint b3 = h2;
			uint a4 = y3;
			uint b4 = h3;
			uint a5 = a3 ^ a4;
			uint b5 = b3 ^ b4;

			uint a6 = a0 ^ a3;
			uint b6 = b0 ^ b3;
			uint a7 = a1 ^ a4;
			uint b7 = b1 ^ b4;
			uint a8 = a6 ^ a7;
			uint b8 = b6 ^ b7;

			ulong z0 = BMul(a0, b0);
			ulong z1 = BMul(a1, b1);
			ulong z2 = BMul(a2, b2);
			ulong z3 = BMul(a3, b3);
			ulong z4 = BMul(a4, b4);
			ulong z5 = BMul(a5, b5);
			ulong z6 = BMul(a6, b6);
			ulong z7 = BMul(a7, b7);
			ulong z8 = BMul(a8, b8);

			z2 ^= z0 ^ z1;
			z0 ^= z2 << 32;
			z1 ^= z2 >> 32;

			z5 ^= z3 ^ z4;
			z3 ^= z5 << 32;
			z4 ^= z5 >> 32;

			z8 ^= z6 ^ z7;
			z6 ^= z8 << 32;
			z7 ^= z8 >> 32;

			z6 ^= z0 ^ z3;
			z7 ^= z1 ^ z4;
			z1 ^= z6;
			z3 ^= z7;

			/*
			 * 255-bit product is now in z4:z3:z1:z0. Since
			 * the GHASH specification uses a "reversed"
			 * notation, our 255-bit result must be shifted
			 * by 1 bit to the left.
			 */
			z4 = (z4 << 1) | (z3 >> 63);
			z3 = (z3 << 1) | (z1 >> 63);
			z1 = (z1 << 1) | (z0 >> 63);
			z0 = (z0 << 1);

			/*
			 * Apply reduction modulo the degree-128
			 * polynomial that defines the field.
			 */
			z3 ^= z0 ^ (z0 >> 1) ^ (z0 >> 2) ^ (z0 >> 7);
			z1 ^= (z0 << 63) ^ (z0 << 62) ^ (z0 << 57);
			z4 ^= z1 ^ (z1 >> 1) ^ (z1 >> 2) ^ (z1 >> 7);
			z3 ^= (z1 << 63) ^ (z1 << 62) ^ (z1 << 57);

			/*
			 * The reduced result is the new "y" state.
			 */
			y0 = (uint)z3;
			y1 = (uint)(z3 >> 32);
			y2 = (uint)z4;
			y3 = (uint)(z4 >> 32);
		}

		Enc32be(y3, y,  0);
		Enc32be(y2, y,  4);
		Enc32be(y1, y,  8);
		Enc32be(y0, y, 12);
	}

	static ulong BMul(uint x, uint y)
	{
		ulong x0, x1, x2, x3;
		ulong y0, y1, y2, y3;
		ulong z0, z1, z2, z3;
		x0 = (ulong)(x & 0x11111111);
		x1 = (ulong)(x & 0x22222222);
		x2 = (ulong)(x & 0x44444444);
		x3 = (ulong)(x & 0x88888888);
		y0 = (ulong)(y & 0x11111111);
		y1 = (ulong)(y & 0x22222222);
		y2 = (ulong)(y & 0x44444444);
		y3 = (ulong)(y & 0x88888888);
		z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1);
		z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2);
		z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3);
		z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0);
		z0 &= 0x1111111111111111;
		z1 &= 0x2222222222222222;
		z2 &= 0x4444444444444444;
		z3 &= 0x8888888888888888;
		return z0 | z1 | z2 | z3;
	}

	static uint Dec32be(byte[] buf, int off)
	{
		return ((uint)buf[off + 0] << 24)
			| ((uint)buf[off + 1] << 16)
			| ((uint)buf[off + 2] << 8)
			| (uint)buf[off + 3];
	}

	static void Enc32be(uint x, byte[] buf, int off)
	{
		buf[off + 0] = (byte)(x >> 24);
		buf[off + 1] = (byte)(x >> 16);
		buf[off + 2] = (byte)(x >> 8);
		buf[off + 3] = (byte)x;
	}

	static uint Dec32bePartial(byte[] buf, int off, int len)
	{
		if (len >= 4) {
			return ((uint)buf[off + 0] << 24)
				| ((uint)buf[off + 1] << 16)
				| ((uint)buf[off + 2] << 8)
				| (uint)buf[off + 3];
		} else if (len >= 3) {
			return ((uint)buf[off + 0] << 24)
				| ((uint)buf[off + 1] << 16)
				| ((uint)buf[off + 2] << 8);
		} else if (len >= 2) {
			return ((uint)buf[off + 0] << 24)
				| ((uint)buf[off + 1] << 16);
		} else if (len >= 1) {
			return ((uint)buf[off + 0] << 24);
		} else {
			return 0;
		}
	}
}

}
