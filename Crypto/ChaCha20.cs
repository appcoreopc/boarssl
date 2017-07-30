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
 * ChaCha20 implementation. 
 */

public sealed class ChaCha20 {

	uint k0, k1, k2, k3, k4, k5, k6, k7;

	const uint CW0 = 0x61707865;
	const uint CW1 = 0x3320646E;
	const uint CW2 = 0x79622D32;
	const uint CW3 = 0x6B206574;

	/*
	 * Initialize a new instance.
	 */
	public ChaCha20()
	{
	}

	/*
	 * Set the key (32 bytes).
	 */
	public void SetKey(byte[] key)
	{
		SetKey(key, 0, key.Length);
	}

	/*
	 * Set the key (32 bytes).
	 */
	public void SetKey(byte[] key, int off, int len)
	{
		if (len != 32) {
			throw new ArgumentException(
				"bad ChaCha20 key length: " + len);
		}
		k0 = Dec32le(key, off +  0);
		k1 = Dec32le(key, off +  4);
		k2 = Dec32le(key, off +  8);
		k3 = Dec32le(key, off + 12);
		k4 = Dec32le(key, off + 16);
		k5 = Dec32le(key, off + 20);
		k6 = Dec32le(key, off + 24);
		k7 = Dec32le(key, off + 28);
	}

	/*
	 * Encrypt (or decrypt) some bytes. The current block counter
	 * is provided, and the new block counter value is returned.
	 * Each block is 64 bytes; if the data length is not a multiple
	 * of 64, then the extra bytes from the last block are dropped;
	 * thus, a long stream of bytes can be encrypted or decrypted
	 * in several calls, as long as all calls (except possibly the
	 * last) provide a length that is a multiple of 64.
	 *
	 * IV must be exactly 12 bytes.
	 */
	public uint Run(byte[] iv, uint cc, byte[] data)
	{
		return Run(iv, cc, data, 0, data.Length);
	}

	/*
	 * Encrypt (or decrypt) some bytes. The current block counter
	 * is provided, and the new block counter value is returned.
	 * Each block is 64 bytes; if the data length is not a multiple
	 * of 64, then the extra bytes from the last block are dropped;
	 * thus, a long stream of bytes can be encrypted or decrypted
	 * in several calls, as long as all calls (except possibly the
	 * last) provide a length that is a multiple of 64.
	 *
	 * IV must be exactly 12 bytes.
	 */
	public uint Run(byte[] iv, uint cc, byte[] data, int off, int len)
	{
		uint iv0 = Dec32le(iv, 0);
		uint iv1 = Dec32le(iv, 4);
		uint iv2 = Dec32le(iv, 8);
		while (len > 0) {
			uint s0, s1, s2, s3, s4, s5, s6, s7;
			uint s8, s9, sA, sB, sC, sD, sE, sF;

			s0 = CW0;
			s1 = CW1;
			s2 = CW2;
			s3 = CW3;
			s4 = k0;
			s5 = k1;
			s6 = k2;
			s7 = k3;
			s8 = k4;
			s9 = k5;
			sA = k6;
			sB = k7;
			sC = cc;
			sD = iv0;
			sE = iv1;
			sF = iv2;

			for (int i = 0; i < 10; i ++) {
				s0 += s4;
				sC ^= s0;
				sC = (sC << 16) | (sC >> 16);
				s8 += sC;
				s4 ^= s8;
				s4 = (s4 << 12) | (s4 >> 20);
				s0 += s4;
				sC ^= s0;
				sC = (sC <<  8) | (sC >> 24);
				s8 += sC;
				s4 ^= s8;
				s4 = (s4 <<  7) | (s4 >> 25);

				s1 += s5;
				sD ^= s1;
				sD = (sD << 16) | (sD >> 16);
				s9 += sD;
				s5 ^= s9;
				s5 = (s5 << 12) | (s5 >> 20);
				s1 += s5;
				sD ^= s1;
				sD = (sD <<  8) | (sD >> 24);
				s9 += sD;
				s5 ^= s9;
				s5 = (s5 <<  7) | (s5 >> 25);

				s2 += s6;
				sE ^= s2;
				sE = (sE << 16) | (sE >> 16);
				sA += sE;
				s6 ^= sA;
				s6 = (s6 << 12) | (s6 >> 20);
				s2 += s6;
				sE ^= s2;
				sE = (sE <<  8) | (sE >> 24);
				sA += sE;
				s6 ^= sA;
				s6 = (s6 <<  7) | (s6 >> 25);

				s3 += s7;
				sF ^= s3;
				sF = (sF << 16) | (sF >> 16);
				sB += sF;
				s7 ^= sB;
				s7 = (s7 << 12) | (s7 >> 20);
				s3 += s7;
				sF ^= s3;
				sF = (sF <<  8) | (sF >> 24);
				sB += sF;
				s7 ^= sB;
				s7 = (s7 <<  7) | (s7 >> 25);

				s0 += s5;
				sF ^= s0;
				sF = (sF << 16) | (sF >> 16);
				sA += sF;
				s5 ^= sA;
				s5 = (s5 << 12) | (s5 >> 20);
				s0 += s5;
				sF ^= s0;
				sF = (sF <<  8) | (sF >> 24);
				sA += sF;
				s5 ^= sA;
				s5 = (s5 <<  7) | (s5 >> 25);

				s1 += s6;
				sC ^= s1;
				sC = (sC << 16) | (sC >> 16);
				sB += sC;
				s6 ^= sB;
				s6 = (s6 << 12) | (s6 >> 20);
				s1 += s6;
				sC ^= s1;
				sC = (sC <<  8) | (sC >> 24);
				sB += sC;
				s6 ^= sB;
				s6 = (s6 <<  7) | (s6 >> 25);

				s2 += s7;
				sD ^= s2;
				sD = (sD << 16) | (sD >> 16);
				s8 += sD;
				s7 ^= s8;
				s7 = (s7 << 12) | (s7 >> 20);
				s2 += s7;
				sD ^= s2;
				sD = (sD <<  8) | (sD >> 24);
				s8 += sD;
				s7 ^= s8;
				s7 = (s7 <<  7) | (s7 >> 25);

				s3 += s4;
				sE ^= s3;
				sE = (sE << 16) | (sE >> 16);
				s9 += sE;
				s4 ^= s9;
				s4 = (s4 << 12) | (s4 >> 20);
				s3 += s4;
				sE ^= s3;
				sE = (sE <<  8) | (sE >> 24);
				s9 += sE;
				s4 ^= s9;
				s4 = (s4 <<  7) | (s4 >> 25);
			}

			s0 += CW0;
			s1 += CW1;
			s2 += CW2;
			s3 += CW3;
			s4 += k0;
			s5 += k1;
			s6 += k2;
			s7 += k3;
			s8 += k4;
			s9 += k5;
			sA += k6;
			sB += k7;
			sC += cc;
			sD += iv0;
			sE += iv1;
			sF += iv2;

			int limit = off + len;
			Xor32le(s0, data, off +  0, limit);
			Xor32le(s1, data, off +  4, limit);
			Xor32le(s2, data, off +  8, limit);
			Xor32le(s3, data, off + 12, limit);
			Xor32le(s4, data, off + 16, limit);
			Xor32le(s5, data, off + 20, limit);
			Xor32le(s6, data, off + 24, limit);
			Xor32le(s7, data, off + 28, limit);
			Xor32le(s8, data, off + 32, limit);
			Xor32le(s9, data, off + 36, limit);
			Xor32le(sA, data, off + 40, limit);
			Xor32le(sB, data, off + 44, limit);
			Xor32le(sC, data, off + 48, limit);
			Xor32le(sD, data, off + 52, limit);
			Xor32le(sE, data, off + 56, limit);
			Xor32le(sF, data, off + 60, limit);

			off += 64;
			len -= 64;
			cc ++;
		}
		return cc;
	}

	static uint Dec32le(byte[] buf, int off)
	{
		return (uint)buf[off]
			| ((uint)buf[off + 1] << 8)
			| ((uint)buf[off + 2] << 16)
			| ((uint)buf[off + 3] << 24);
	}

	static void Xor32le(uint x, byte[] buf, int off, int limit)
	{
		if (off + 4 <= limit) {
			buf[off] ^= (byte)x;
			buf[off + 1] ^= (byte)(x >> 8);
			buf[off + 2] ^= (byte)(x >> 16);
			buf[off + 3] ^= (byte)(x >> 24);
		} else {
			if (off + 2 <= limit) {
				if (off + 3 <= limit) {
					buf[off] ^= (byte)x;
					buf[off + 1] ^= (byte)(x >> 8);
					buf[off + 2] ^= (byte)(x >> 16);
				} else {
					buf[off] ^= (byte)x;
					buf[off + 1] ^= (byte)(x >> 8);
				}
			} else {
				if (off + 1 <= limit) {
					buf[off] ^= (byte)x;
				}
			}
		}
	}
}

}
