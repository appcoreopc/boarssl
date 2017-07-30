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
 * This class implements Poly1305, when used with ChaCha20. The
 * ChaCha20 instance (already set with the secret key) is passed as
 * parameter. Instances are not thread-safe.
 */

public sealed class Poly1305 {

	/*
	 * The ChaCha20 instance to use for encryption and decryption.
	 * That instance MUST be set, and it must have been initialised
	 * with the key to use.
	 */
	public ChaCha20 ChaCha {
		get; set;
	}

	byte[] pkey;
	uint[] r;
	uint[] acc;
	byte[] foot;
	byte[] tmp;

	/*
	 * Create a new instance. The ChaCha20 instance to use MUST be
	 * set in the 'ChaCha' property.
	 */
	public Poly1305()
	{
		pkey = new byte[32];
		r = new uint[5];
		acc = new uint[5];
		foot = new byte[16];
		tmp = new byte[16];
	}

	/*
	 * Run Poly1305 and ChaCha20 on the provided elements.
	 *
	 *   iv        Nonce for ChaCha20, exactly 12 bytes
	 *   data      data to encrypt or decrypt (buffer, off + len)
	 *   aad       additional authenticated data (buffer, offAAD + lenAAD)
	 *   tag       destination for computed authentication tag
	 *   encrypt   true to encrypt, false to decrypt
	 */
	public void Run(byte[] iv,
		byte[] data, int off, int len,
		byte[] aad, int offAAD, int lenAAD,
		byte[] tag, bool encrypt)
	{
		/*
		 * Compute Poly1305 key.
		 */
		for (int i = 0; i < pkey.Length; i ++) {
			pkey[i] = 0;
		}
		ChaCha.Run(iv, 0, pkey);

		/*
		 * If encrypting, ChaCha20 must run first (the MAC is
		 * computed on the ciphertext).
		 */
		if (encrypt) {
			ChaCha.Run(iv, 1, data, off, len);
		}

		/*
		 * Decode the 'r' value into 26-bit words, with the
		 * "clamping" operation applied.
		 */
		r[0] = Dec32le(pkey, 0) & 0x03FFFFFF;
		r[1] = (Dec32le(pkey, 3) >> 2) & 0x03FFFF03;
		r[2] = (Dec32le(pkey,  6) >> 4) & 0x03FFC0FF;
		r[3] = (Dec32le(pkey,  9) >> 6) & 0x03F03FFF;
		r[4] = (Dec32le(pkey, 12) >> 8) & 0x000FFFFF;

		/*
		 * Accumulator is 0.
		 */
		acc[0] = 0;
		acc[1] = 0;
		acc[2] = 0;
		acc[3] = 0;
		acc[4] = 0;

		/*
		 * Process AAD, ciphertext and footer.
		 */
		Enc32le(lenAAD, foot, 0);
		Enc32le(0, foot, 4);
		Enc32le(len, foot, 8);
		Enc32le(0, foot, 12);
		RunInner(aad, offAAD, lenAAD);
		RunInner(data, off, len);
		RunInner(foot, 0, 16);

		/*
		 * Finalize modular reduction. The output of RunInner() is
		 * already mostly reduced: only acc[1] may be (very slightly)
		 * above 2^26. Thus, we only need one loop, back to acc[1].
		 */
		uint cc = 0;
		for (int i = 1; i <= 6; i ++) {
			int j;

			j = (i >= 5) ? i - 5 : i;
			acc[j] += cc;
			cc = acc[j] >> 26;
			acc[j] &= 0x03FFFFFF;
		}

		/*
		 * The final value may still be in the 2^130-5..2^130-1
		 * range, in which case an additional subtraction must be
		 * performed, with constant-time code.
		 */
		cc = (uint)((int)(0x03FFFFFA - acc[0]) >> 31);
		for (int i = 1; i < 5; i ++) {
			int z = (int)(acc[i] - 0x03FFFFFF);
			cc &= ~(uint)((z | -z) >> 31);
		}
		cc &= 5;
		for (int i = 0; i < 5; i ++) {
			uint t = acc[i] + cc;
			cc = t >> 26;
			acc[i] = t & 0x03FFFFFF;
		}

		/*
		 * The tag is the sum of the 's' value (second half of
		 * the pkey[] array, little-endian encoding) and the
		 * current accumulator value. This addition is done modulo
		 * 2^128, i.e. with a simple truncation.
		 */
		cc = 0;
		uint aw = 0;
		int awLen = 0;
		for (int i = 0, j = 0; i < 16; i ++) {
			if (awLen < 8) {
				/*
				 * We "refill" our running byte buffer with
				 * a new extra accumulator word. Note that
				 * 'awLen' is always even, so at this point
				 * it must be 6 or less; since accumulator
				 * words fit on 32 bits, the operation
				 * below does not lose any bit.
				 */
				aw |= acc[j ++] << awLen;
				awLen += 26;
			}
			uint tb = (aw & 0xFF) + cc + pkey[16 + i];
			aw >>= 8;
			awLen -= 8;
			tag[i] = (byte)tb;
			cc = tb >> 8;
		}

		/*
		 * If decrypting, then we still have the ciphertext at
		 * this point, and we must perform the decryption.
		 */
		if (!encrypt) {
			ChaCha.Run(iv, 1, data, off, len);
		}
	}

	/*
	 * Inner processing of the provided data. The accumulator and 'r'
	 * value are set in the instance fields, and must be updated.
	 * All accumulator words fit on 26 bits each, except the second
	 * (acc[1]) which may be very slightly above 2^26.
	 */
	void RunInner(byte[] data, int off, int len)
	{
		/*
		 * Implementation is inspired from the public-domain code
		 * available there:
		 *    https://github.com/floodyberry/poly1305-donna
		 */
		uint r0 = r[0];
		uint r1 = r[1];
		uint r2 = r[2];
		uint r3 = r[3];
		uint r4 = r[4];

		uint u1 = r1 * 5;
		uint u2 = r2 * 5;
		uint u3 = r3 * 5;
		uint u4 = r4 * 5;

		uint a0 = acc[0];
		uint a1 = acc[1];
		uint a2 = acc[2];
		uint a3 = acc[3];
		uint a4 = acc[4];

		while (len > 0) {
			if (len < 16) {
				Array.Copy(data, off, tmp, 0, len);
				for (int i = len; i < 16; i ++) {
					tmp[i] = 0;
				}
				data = tmp;
				off = 0;
			}

			/*
			 * Decode next block, with the "high bit" applied,
			 * and add that value to the accumulator.
			 */
			a0 += Dec32le(data, off) & 0x03FFFFFF;
			a1 += (Dec32le(data, off +  3) >> 2) & 0x03FFFFFF;
			a2 += (Dec32le(data, off +  6) >> 4) & 0x03FFFFFF;
			a3 += (Dec32le(data, off +  9) >> 6) & 0x03FFFFFF;
			a4 += (Dec32le(data, off + 12) >> 8) | 0x01000000;

			/*
			 * Compute multiplication. All elementary
			 * multiplications are 32x32->64.
			 */
			ulong w0 = (ulong)a0 * r0
				+ (ulong)a1 * u4
				+ (ulong)a2 * u3
				+ (ulong)a3 * u2
				+ (ulong)a4 * u1;
			ulong w1 = (ulong)a0 * r1
				+ (ulong)a1 * r0
				+ (ulong)a2 * u4
				+ (ulong)a3 * u3
				+ (ulong)a4 * u2;
			ulong w2 = (ulong)a0 * r2
				+ (ulong)a1 * r1
				+ (ulong)a2 * r0
				+ (ulong)a3 * u4
				+ (ulong)a4 * u3;
			ulong w3 = (ulong)a0 * r3
				+ (ulong)a1 * r2
				+ (ulong)a2 * r1
				+ (ulong)a3 * r0
				+ (ulong)a4 * u4;
			ulong w4 = (ulong)a0 * r4
				+ (ulong)a1 * r3
				+ (ulong)a2 * r2
				+ (ulong)a3 * r1
				+ (ulong)a4 * r0;

			/*
			 * Most of the modular reduction was done by using
			 * the 'u*' multipliers. We still need to do some
			 * carry propagation.
			 */
			ulong c;
			c = w0 >> 26;
			a0 = (uint)w0 & 0x03FFFFFF;
			w1 += c;
			c = w1 >> 26;
			a1 = (uint)w1 & 0x03FFFFFF;
			w2 += c;
			c = w2 >> 26;
			a2 = (uint)w2 & 0x03FFFFFF;
			w3 += c;
			c = w3 >> 26;
			a3 = (uint)w3 & 0x03FFFFFF;
			w4 += c;
			c = w4 >> 26;
			a4 = (uint)w4 & 0x03FFFFFF;
			a0 += (uint)c * 5;
			a1 += a0 >> 26;
			a0 &= 0x03FFFFFF;

			off += 16;
			len -= 16;
		}

		acc[0] = a0;
		acc[1] = a1;
		acc[2] = a2;
		acc[3] = a3;
		acc[4] = a4;
	}

	static uint Dec32le(byte[] buf, int off)
	{
		return (uint)buf[off]
			| ((uint)buf[off + 1] << 8)
			| ((uint)buf[off + 2] << 16)
			| ((uint)buf[off + 3] << 24);
	}

	static void Enc32le(int x, byte[] buf, int off)
	{
		buf[off] = (byte)x;
		buf[off + 1] = (byte)(x >> 8);
		buf[off + 2] = (byte)(x >> 16);
		buf[off + 3] = (byte)(x >> 24);
	}
}

}
