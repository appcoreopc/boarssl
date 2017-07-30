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
 * Perfunctory implementation of the Triple-DES block cipher (also works
 * as "single DES" when used with an 8-byte DES key). It only processes
 * single blocks, and does it "in place" (the input block is replaced
 * with the output block in the same array). This code is a direct
 * translation of the specification and is not optimized for speed.
 *
 * Supported key sizes are 8, 16 and 24 bytes. When an 8-byte key is
 * used, this is the original DES (64-bit key, out of which 8 are
 * unused, so the "true key size" is 56 bits). When a 16-byte or 24-byte
 * key is used, this is Triple-DES (with a 16-byte key, the key is
 * expanded to 24 bytes by reusing bytes 0..7 as bytes 16..23 of the
 * key).
 *
 * Instances are not thread-safe; however, distinct threads may use
 * distinct instances concurrently.
 *
 * Since instances are pure managed code, there is no need for explicit
 * disposal after usage.
 */

public sealed class DES : BlockCipherCore {

	ulong[] skey;
	int rounds;

	/*
	 * Initialize a new instance.
	 */
	public DES()
	{
		skey = new ulong[48];
	}

	/* see IBlockCipher */
	public override IBlockCipher Dup()
	{
		DES d = new DES();
		Array.Copy(skey, 0, d.skey, 0, skey.Length);
		d.rounds = rounds;
		return d;
	}

	/*
	 * Get the block size in bytes (always 8).
	 */
	public override int BlockSize {
		get {
			return 8;
		}
	}

	/*
	 * Set the key (8, 16 or 24 bytes).
	 */
	public override void SetKey(byte[] key, int off, int len)
	{
		switch (len) {
		case 8:
			KeySchedule(key, off, 0);
			rounds = 1;
			break;
		case 16:
			KeySchedule(key, off, 0);
			KeySchedule(key, off + 8, 16);
			KeySchedule(key, off, 32);
			rounds = 3;
			break;
		case 24:
			KeySchedule(key, off, 0);
			KeySchedule(key, off + 8, 16);
			KeySchedule(key, off + 16, 32);
			rounds = 3;
			break;
		default:
			throw new ArgumentException(
				"bad DES/3DES key length: " + len);
		}

		/* 
		 * Inverse order of subkeys for the middle-DES (3DES
		 * uses the "EDE" configuration).
		 */
		for (int j = 16; j < 24; j ++) {
			ulong w = skey[j];
			skey[j] = skey[47 - j];
			skey[47 - j] = w;
		}
	}

	void KeySchedule(byte[] key, int off, int skeyOff)
	{
		ulong k = Dec64be(key, off);
		k = Perm(tabPC1, k);
		ulong kl = k >> 28;
		ulong kr = k & 0x0FFFFFFF;
		for (int i = 0; i < 16; i ++) {
			int r = rotK[i];
			kl = ((kl << r) | (kl >> (28 - r))) & 0x0FFFFFFF;
			kr = ((kr << r) | (kr >> (28 - r))) & 0x0FFFFFFF;
			skey[skeyOff + i] = Perm(tabPC2, (kl << 28) | kr);
		}
	}

	/*
	 * Encrypt one block; the block consists in the 8 bytes beginning
	 * at offset 'off'. Other bytes in the array are unaltered.
	 */
	public override void BlockEncrypt(byte[] buf, int off)
	{
		if (rounds == 0) {
			throw new Exception("no key provided");
		}
		ulong x = Dec64be(buf, off);
		x = DoIP(x);
		uint xl = (uint)(x >> 32);
		uint xr = (uint)x;
		for (int i = 0, k = 0; i < rounds; i ++) {
			xl ^= FConf(xr, skey[k ++]);
			xr ^= FConf(xl, skey[k ++]);
			xl ^= FConf(xr, skey[k ++]);
			xr ^= FConf(xl, skey[k ++]);
			xl ^= FConf(xr, skey[k ++]);
			xr ^= FConf(xl, skey[k ++]);
			xl ^= FConf(xr, skey[k ++]);
			xr ^= FConf(xl, skey[k ++]);
			xl ^= FConf(xr, skey[k ++]);
			xr ^= FConf(xl, skey[k ++]);
			xl ^= FConf(xr, skey[k ++]);
			xr ^= FConf(xl, skey[k ++]);
			xl ^= FConf(xr, skey[k ++]);
			xr ^= FConf(xl, skey[k ++]);
			xl ^= FConf(xr, skey[k ++]);
			uint tmp = xr ^ FConf(xl, skey[k ++]);
			xr = xl;
			xl = tmp;
		}
		x = ((ulong)xl << 32) | (ulong)xr;
		x = DoIPInv(x);
		Enc64be(x, buf, off);
	}

	/*
	 * Decrypt one block; the block consists in the 8 bytes beginning
	 * at offset 'off'. Other bytes in the array are unaltered.
	 */
	public override void BlockDecrypt(byte[] buf, int off)
	{
		if (rounds == 0) {
			throw new Exception("no key provided");
		}
		ulong x = Dec64be(buf, off);
		x = DoIP(x);
		uint xl = (uint)(x >> 32);
		uint xr = (uint)x;
		for (int i = 0, k = rounds << 4; i < rounds; i ++) {
			xl ^= FConf(xr, skey[-- k]);
			xr ^= FConf(xl, skey[-- k]);
			xl ^= FConf(xr, skey[-- k]);
			xr ^= FConf(xl, skey[-- k]);
			xl ^= FConf(xr, skey[-- k]);
			xr ^= FConf(xl, skey[-- k]);
			xl ^= FConf(xr, skey[-- k]);
			xr ^= FConf(xl, skey[-- k]);
			xl ^= FConf(xr, skey[-- k]);
			xr ^= FConf(xl, skey[-- k]);
			xl ^= FConf(xr, skey[-- k]);
			xr ^= FConf(xl, skey[-- k]);
			xl ^= FConf(xr, skey[-- k]);
			xr ^= FConf(xl, skey[-- k]);
			xl ^= FConf(xr, skey[-- k]);
			uint tmp = xr ^ FConf(xl, skey[-- k]);
			xr = xl;
			xl = tmp;
		}
		x = ((ulong)xl << 32) | (ulong)xr;
		x = DoIPInv(x);
		Enc64be(x, buf, off);
	}

	/*
	 * Arrays below are extracted exactly from FIPS 46-3. They use
	 * the conventions defined in that document:
	 *
	 * -- Bits are numbered from 1, in the left-to-right order; in
	 *    a 64-bit integer, the most significant (leftmost) bit is 1,
	 *    while the least significant (rightmost) bit is 64.
	 *
	 * -- For each permutation (or extraction), the defined array
	 *    lists the source index of each bit.
	 *
	 * -- For the S-boxes, bits 1 (leftmost) and 6 (rightmost) select
	 *    the row, and bits 2 to 5 select the index within the row.
	 */

	static uint[,] Sdef = {
		{
			14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
			0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
			4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
			15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
		}, {
			15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
			3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
			0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
			13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
		}, {
			10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
			13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
			13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
			1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
		}, {
			7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
			13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
			10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
			3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
		}, {
			2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
			14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
			4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
			11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
		}, {
			12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
			10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
			9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
			4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
		}, {
			4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
			13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
			1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
			6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
		}, {
			13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
			1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
			7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
			2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
		}
	};

	static int[] defP = {
		16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
		2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
	};

	static int[] defPC1 = {
		57, 49, 41, 33, 25, 17, 9,
		1, 58, 50, 42, 34, 26, 18,
		10, 2, 59, 51, 43, 35, 27,
		19, 11, 3, 60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15,
		7, 62, 54, 46, 38, 30, 22,
		14, 6, 61, 53, 45, 37, 29,
		21, 13, 5, 28, 20, 12, 4
	};

	static int[] defPC2 = {
		14, 17, 11, 24, 1, 5,
		3, 28, 15, 6, 21, 10,
		23, 19, 12, 4, 26, 8,
		16, 7, 27, 20, 13, 2,
		41, 52, 31, 37, 47, 55,
		30, 40, 51, 45, 33, 48,
		44, 49, 39, 56, 34, 53,
		46, 42, 50, 36, 29, 32
	};

	static int[] rotK = {
		1, 1, 2, 2, 2, 2, 2, 2,
		1, 2, 2, 2, 2, 2, 2, 1
	};

	/*
	 * Permutations (and extractions) are implemented with the
	 * following tables, that are initialized from the class
	 * initialization code. The representation of a permutation is
	 * an array of words, where word at index k is a one-bit mask
	 * that identifies the source bit that should go at position k
	 * in the output. The "k" index here is in right-to-left
	 * convention: least significant bit (rightmost) is numbered 0.
	 *
	 * The Perm() method applies a permutation, using one of the
	 * tab*[] arrays.
	 *
	 * The S*[] arrays contain the S-boxes, with the permutation P
	 * effect merged in, and expecting their 6-bit input "as is".
	 */
	static ulong[] tabPC1;
	static ulong[] tabPC2;

	static uint[] S1, S2, S3, S4, S5, S6, S7, S8;

	static DES()
	{
		tabPC1 = new ulong[defPC1.Length];
		for (int i = 0; i < defPC1.Length; i ++) {
			tabPC1[55 - i] = (ulong)1 << (64 - defPC1[i]);
		}
		tabPC2 = new ulong[defPC2.Length];
		for (int i = 0; i < defPC2.Length; i ++) {
			tabPC2[47 - i] = (ulong)1 << (56 - defPC2[i]);
		}

		int[] PInv = new int[32];
		for (int i = 0; i < defP.Length; i ++) {
			PInv[32 - defP[i]] = 31 - i;
		}
		S1 = MakeSbox(PInv, 0);
		S2 = MakeSbox(PInv, 1);
		S3 = MakeSbox(PInv, 2);
		S4 = MakeSbox(PInv, 3);
		S5 = MakeSbox(PInv, 4);
		S6 = MakeSbox(PInv, 5);
		S7 = MakeSbox(PInv, 6);
		S8 = MakeSbox(PInv, 7);
	}

	static uint[] MakeSbox(int[] PInv, int i)
	{
		uint[] S = new uint[64];
		for (int j = 0; j < 64; j ++) {
			int idx = ((j & 0x01) << 4) | (j & 0x20)
				| ((j & 0x1E) >> 1);
			uint zb = Sdef[i, idx];
			uint za = 0;
			for (int k = 0; k < 4; k ++) {
				za |= ((zb >> k) & 1)
					<< PInv[((7 - i) << 2) + k];
			}
			S[j] = za;
		}
		return S;
	}

	static ulong IPStep(ulong x, int size, ulong mask)
	{
		uint left = (uint)(x >> 32);
		uint right = (uint)x;
		uint tmp = ((left >> size) ^ right) & (uint)mask;
		right ^= tmp;
		left ^= tmp << size;
		return ((ulong)left << 32) | (ulong)right;
	}

	static ulong DoIP(ulong x)
	{
		/*
		 * Permutation algorithm is initially from Richard
		 * Outerbridge; this implementation has been adapted
		 * from Crypto++ "des.cpp" file (which is in public
		 * domain).
		 */
		uint l = (uint)(x >> 32);
		uint r = (uint)x;
		uint t;
		t = ((l >>  4) ^ r) & 0x0F0F0F0F;
		r ^= t;
		l ^= t <<  4;
		t = ((l >> 16) ^ r) & 0x0000FFFF;
		r ^= t;
		l ^= t << 16;
		t = ((r >>  2) ^ l) & 0x33333333;
		l ^= t;
		r ^= t <<  2;
		t = ((r >>  8) ^ l) & 0x00FF00FF;
		l ^= t;
		r ^= t <<  8;
		t = ((l >>  1) ^ r) & 0x55555555;
		r ^= t;
		l ^= t <<  1;
		x = ((ulong)l << 32) | (ulong)r;
		return x;
	}

	static ulong DoIPInv(ulong x)
	{
		/*
		 * See DoIP().
		 */
		uint l = (uint)(x >> 32);
		uint r = (uint)x;
		uint t;
		t = ((l >>  1) ^ r) & 0x55555555;
		r ^= t;
		l ^= t <<  1;
		t = ((r >>  8) ^ l) & 0x00FF00FF;
		l ^= t;
		r ^= t <<  8;
		t = ((r >>  2) ^ l) & 0x33333333;
		l ^= t;
		r ^= t <<  2;
		t = ((l >> 16) ^ r) & 0x0000FFFF;
		r ^= t;
		l ^= t << 16;
		t = ((l >>  4) ^ r) & 0x0F0F0F0F;
		r ^= t;
		l ^= t <<  4;
		x = ((ulong)l << 32) | (ulong)r;
		return x;
	}

	/*
	 * Apply a permutation or extraction. For all k, bit k of the
	 * output (right-to-left numbering) is set if and only if the
	 * source bit in x defined by the tab[k] mask is set.
	 */
	static ulong Perm(ulong[] tab, ulong x)
	{
		ulong y = 0;
		for (int i = 0; i < tab.Length; i ++) {
			if ((x & tab[i]) != 0) {
				y |= (ulong)1 << i;
			}
		}
		return y;
	}

	static uint FConf(uint r0, ulong sk)
	{
		uint skhi = (uint)(sk >> 24);
		uint sklo = (uint)sk;
		uint r1 = (r0 >> 16) | (r0 << 16);
		return
			  S1[((r1 >> 11) ^ (skhi >> 18)) & 0x3F]
			| S2[((r0 >> 23) ^ (skhi >> 12)) & 0x3F]
			| S3[((r0 >> 19) ^ (skhi >>  6)) & 0x3F]
			| S4[((r0 >> 15) ^ (skhi      )) & 0x3F]
			| S5[((r0 >> 11) ^ (sklo >> 18)) & 0x3F]
			| S6[((r0 >>  7) ^ (sklo >> 12)) & 0x3F]
			| S7[((r0 >>  3) ^ (sklo >>  6)) & 0x3F]
			| S8[((r1 >> 15) ^ (sklo      )) & 0x3F];
	}

	/*
	 * 64-bit big-endian decoding.
	 */
	static ulong Dec64be(byte[] buf, int off)
	{
		return ((ulong)buf[off] << 56)
			| ((ulong)buf[off + 1] << 48)
			| ((ulong)buf[off + 2] << 40)
			| ((ulong)buf[off + 3] << 32)
			| ((ulong)buf[off + 4] << 24)
			| ((ulong)buf[off + 5] << 16)
			| ((ulong)buf[off + 6] << 8)
			| (ulong)buf[off + 7];
	}

	/*
	 * 64-bit big-endian encoding.
	 */
	static void Enc64be(ulong v, byte[] buf, int off)
	{
		buf[off + 0] = (byte)(v >> 56);
		buf[off + 1] = (byte)(v >> 48);
		buf[off + 2] = (byte)(v >> 40);
		buf[off + 3] = (byte)(v >> 32);
		buf[off + 4] = (byte)(v >> 24);
		buf[off + 5] = (byte)(v >> 16);
		buf[off + 6] = (byte)(v >> 8);
		buf[off + 7] = (byte)v;
	}
}

}
