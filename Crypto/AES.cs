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
 * Classic AES implementation, with tables (8->32 lookup tables, four
 * tables for encryption, four other tables for decryption). This is
 * relatively efficient, but not constant-time.
 */

public sealed class AES : BlockCipherCore {

	uint[] skey;
	uint[] iskey;
	int rounds;

	/*
	 * Initialize a new instance.
	 */
	public AES()
	{
		skey = new uint[4 * 15];
		iskey = new uint[skey.Length];
	}

	/* see IBlockCipher */
	public override IBlockCipher Dup()
	{
		AES a = new AES();
		Array.Copy(skey, 0, a.skey, 0, skey.Length);
		Array.Copy(iskey, 0, a.iskey, 0, iskey.Length);
		a.rounds = rounds;
		return a;
	}

	/*
	 * Get the block size in bytes (always 16).
	 */
	public override int BlockSize {
		get {
			return 16;
		}
	}

	/*
	 * Set the key (16, 24 or 32 bytes).
	 */
	public override void SetKey(byte[] key, int off, int len)
	{
		switch (len) {
		case 16:
			rounds = 10;
			break;
		case 24:
			rounds = 12;
			break;
		case 32:
			rounds = 14;
			break;
		default:
			throw new ArgumentException(
				"bad AES key length: " + len);
		}
		int nk = len >> 2;
		int nkf = (rounds + 1) << 2;
		for (int i = 0; i < nk; i ++) {
			skey[i] = Dec32be(key, off + (i << 2));
		}
		for (int i = nk, j = 0, k = 0; i < nkf; i ++) {
			uint tmp = skey[i - 1];
			if (j == 0) {
				tmp = (tmp << 8) | (tmp >> 24);
				tmp = SubWord(tmp) ^ Rcon[k];
			} else if (nk > 6 && j == 4) {
				tmp = SubWord(tmp);
			}
			skey[i] = skey[i - nk] ^ tmp;
			if (++ j == nk) {
				j = 0;
				k ++;
			}
		}

		/*
		 * Subkeys for decryption (with InvMixColumns() already
		 * applied for the inner rounds).
		 */
		Array.Copy(skey, 0, iskey, 0, 4);
		for (int i = 4; i < (rounds << 2); i ++) {
			uint p = skey[i];
			uint p0 = p >> 24;
			uint p1 = (p >> 16) & 0xFF;
			uint p2 = (p >> 8) & 0xFF;
			uint p3 = p & 0xFF;
			uint q0 = mule(p0) ^ mulb(p1) ^ muld(p2) ^ mul9(p3);
			uint q1 = mul9(p0) ^ mule(p1) ^ mulb(p2) ^ muld(p3);
			uint q2 = muld(p0) ^ mul9(p1) ^ mule(p2) ^ mulb(p3);
			uint q3 = mulb(p0) ^ muld(p1) ^ mul9(p2) ^ mule(p3);
			iskey[i] = (q0 << 24) | (q1 << 16) | (q2 << 8) | q3;
		}
		Array.Copy(skey, rounds << 2, iskey, rounds << 2, 4);
	}

	/* see IBlockCipher */
	public override void BlockEncrypt(byte[] buf, int off)
	{
		uint s0 = Dec32be(buf, off);
		uint s1 = Dec32be(buf, off + 4);
		uint s2 = Dec32be(buf, off + 8);
		uint s3 = Dec32be(buf, off + 12);
		s0 ^= skey[0];
		s1 ^= skey[1];
		s2 ^= skey[2];
		s3 ^= skey[3];
		for (int i = 1; i < rounds; i ++) {
			uint v0 = Ssm0[s0 >> 24]
				^ Ssm1[(s1 >> 16) & 0xFF]
				^ Ssm2[(s2 >> 8) & 0xFF]
				^ Ssm3[s3 & 0xFF];
			uint v1 = Ssm0[s1 >> 24]
				^ Ssm1[(s2 >> 16) & 0xFF]
				^ Ssm2[(s3 >> 8) & 0xFF]
				^ Ssm3[s0 & 0xFF];
			uint v2 = Ssm0[s2 >> 24]
				^ Ssm1[(s3 >> 16) & 0xFF]
				^ Ssm2[(s0 >> 8) & 0xFF]
				^ Ssm3[s1 & 0xFF];
			uint v3 = Ssm0[s3 >> 24]
				^ Ssm1[(s0 >> 16) & 0xFF]
				^ Ssm2[(s1 >> 8) & 0xFF]
				^ Ssm3[s2 & 0xFF];
			s0 = v0;
			s1 = v1;
			s2 = v2;
			s3 = v3;
			s0 ^= skey[i << 2];
			s1 ^= skey[(i << 2) + 1];
			s2 ^= skey[(i << 2) + 2];
			s3 ^= skey[(i << 2) + 3];
		}
		uint t0 = (S[s0 >> 24] << 24)
			| (S[(s1 >> 16) & 0xFF] << 16)
			| (S[(s2 >> 8) & 0xFF] << 8)
			| S[s3 & 0xFF];
		uint t1 = (S[s1 >> 24] << 24)
			| (S[(s2 >> 16) & 0xFF] << 16)
			| (S[(s3 >> 8) & 0xFF] << 8)
			| S[s0 & 0xFF];
		uint t2 = (S[s2 >> 24] << 24)
			| (S[(s3 >> 16) & 0xFF] << 16)
			| (S[(s0 >> 8) & 0xFF] << 8)
			| S[s1 & 0xFF];
		uint t3 = (S[s3 >> 24] << 24)
			| (S[(s0 >> 16) & 0xFF] << 16)
			| (S[(s1 >> 8) & 0xFF] << 8)
			| S[s2 & 0xFF];
		s0 = t0 ^ skey[rounds << 2];
		s1 = t1 ^ skey[(rounds << 2) + 1];
		s2 = t2 ^ skey[(rounds << 2) + 2];
		s3 = t3 ^ skey[(rounds << 2) + 3];
		Enc32be(s0, buf, off);
		Enc32be(s1, buf, off + 4);
		Enc32be(s2, buf, off + 8);
		Enc32be(s3, buf, off + 12);
	}

	/* see IBlockCipher */
	public override void BlockDecrypt(byte[] buf, int off)
	{
		uint s0 = Dec32be(buf, off);
		uint s1 = Dec32be(buf, off + 4);
		uint s2 = Dec32be(buf, off + 8);
		uint s3 = Dec32be(buf, off + 12);
		s0 ^= iskey[rounds << 2];
		s1 ^= iskey[(rounds << 2) + 1];
		s2 ^= iskey[(rounds << 2) + 2];
		s3 ^= iskey[(rounds << 2) + 3];
		for (int i = rounds - 1; i > 0; i --) {
			uint v0 = iSsm0[s0 >> 24]
				^ iSsm1[(s3 >> 16) & 0xFF]
				^ iSsm2[(s2 >> 8) & 0xFF]
				^ iSsm3[s1 & 0xFF];
			uint v1 = iSsm0[s1 >> 24]
				^ iSsm1[(s0 >> 16) & 0xFF]
				^ iSsm2[(s3 >> 8) & 0xFF]
				^ iSsm3[s2 & 0xFF];
			uint v2 = iSsm0[s2 >> 24]
				^ iSsm1[(s1 >> 16) & 0xFF]
				^ iSsm2[(s0 >> 8) & 0xFF]
				^ iSsm3[s3 & 0xFF];
			uint v3 = iSsm0[s3 >> 24]
				^ iSsm1[(s2 >> 16) & 0xFF]
				^ iSsm2[(s1 >> 8) & 0xFF]
				^ iSsm3[s0 & 0xFF];
			s0 = v0;
			s1 = v1;
			s2 = v2;
			s3 = v3;
			s0 ^= iskey[i << 2];
			s1 ^= iskey[(i << 2) + 1];
			s2 ^= iskey[(i << 2) + 2];
			s3 ^= iskey[(i << 2) + 3];
		}
		uint t0 = (iS[s0 >> 24] << 24)
			| (iS[(s3 >> 16) & 0xFF] << 16)
			| (iS[(s2 >> 8) & 0xFF] << 8)
			| iS[s1 & 0xFF];
		uint t1 = (iS[s1 >> 24] << 24)
			| (iS[(s0 >> 16) & 0xFF] << 16)
			| (iS[(s3 >> 8) & 0xFF] << 8)
			| iS[s2 & 0xFF];
		uint t2 = (iS[s2 >> 24] << 24)
			| (iS[(s1 >> 16) & 0xFF] << 16)
			| (iS[(s0 >> 8) & 0xFF] << 8)
			| iS[s3 & 0xFF];
		uint t3 = (iS[s3 >> 24] << 24)
			| (iS[(s2 >> 16) & 0xFF] << 16)
			| (iS[(s1 >> 8) & 0xFF] << 8)
			| iS[s0 & 0xFF];
		s0 = t0 ^ iskey[0];
		s1 = t1 ^ iskey[1];
		s2 = t2 ^ iskey[2];
		s3 = t3 ^ iskey[3];
		Enc32be(s0, buf, off);
		Enc32be(s1, buf, off + 4);
		Enc32be(s2, buf, off + 8);
		Enc32be(s3, buf, off + 12);
	}

	static uint Dec32be(byte[] buf, int off)
	{
		return ((uint)buf[off] << 24)
			| ((uint)buf[off + 1] << 16)
			| ((uint)buf[off + 2] << 8)
			| (uint)buf[off + 3];
	}

	static void Enc32be(uint x, byte[] buf, int off)
	{
		buf[off] = (byte)(x >> 24);
		buf[off + 1] = (byte)(x >> 16);
		buf[off + 2] = (byte)(x >> 8);
		buf[off + 3] = (byte)x;
	}

	static uint mul2(uint x)
	{
		x <<= 1;
		return x ^ ((uint)(-(int)(x >> 8)) & 0x11B);
	}

	static uint mul3(uint x)
	{
		return x ^ mul2(x);
	}

	static uint mul9(uint x)
	{
		return x ^ mul2(mul2(mul2(x)));
	}

	static uint mulb(uint x)
	{
		uint x2 = mul2(x);
		return x ^ x2 ^ mul2(mul2(x2));
	}

	static uint muld(uint x)
	{
		uint x4 = mul2(mul2(x));
		return x ^ x4 ^ mul2(x4);
	}

	static uint mule(uint x)
	{
		uint x2 = mul2(x);
		uint x4 = mul2(x2);
		return x2 ^ x4 ^ mul2(x4);
	}

	static uint aff(uint x)
	{
		x |= x << 8;
		x ^= (x >> 4) ^ (x >> 5) ^ (x >> 6) ^ (x >> 7) ^ 0x63;
		return x & 0xFF;
	}

	static uint[] Rcon;
	static uint[] S;
	static uint[] Ssm0, Ssm1, Ssm2, Ssm3;
	static uint[] iS;
	static uint[] iSsm0, iSsm1, iSsm2, iSsm3;

	static uint SubWord(uint x)
	{
		return (S[x >> 24] << 24)
			| (S[(x >> 16) & 0xFF] << 16)
			| (S[(x >> 8) & 0xFF] << 8)
			| S[x & 0xFF];
	}

	static AES()
	{
		/*
		 * The Rcon[] constants are used in the key schedule.
		 */
		Rcon = new uint[10];
		uint x = 1;
		for (int i = 0; i < Rcon.Length; i ++) {
			Rcon[i] = x << 24;
			x = mul2(x);
		}

		/*
		 * Generate the map x -> 3^x in GF(2^8). "3" happens to
		 * be a generator for GF(2^8)*, so we get all 255 non-zero
		 * elements.
		 */
		uint[] pow3 = new uint[255];
		x = 1;
		for (int i = 0; i < 255; i ++) {
			pow3[i] = x;
			x ^= mul2(x);
		}

		/*
		 * Compute the log3 map 3^x -> x that maps any non-zero
		 * element in GF(2^8) to its logarithm in base 3 (in the
		 * 0..254 range).
		 */
		int[] log3 = new int[256];
		for (int i = 0; i < 255; i ++) {
			log3[pow3[i]] = i;
		}

		/*
		 * Compute the S-box.
		 */
		S = new uint[256];
		S[0] = aff(0);
		S[1] = aff(1);
		for (uint y = 2; y < 0x100; y ++) {
			S[y] = aff(pow3[255 - log3[y]]);
		}

		/*
		 * Compute the inverse S-box (for decryption).
		 */
		iS = new uint[256];
		for (uint y = 0; y < 0x100; y ++) {
			iS[S[y]] = y;
		}

		/*
		 * The Ssm*[] arrays combine SubBytes() and MixColumns():
		 * SsmX[v] is the effect of byte of value v when appearing
		 * on row X.
		 *
		 * The iSsm*[] arrays similarly combine InvSubBytes() and
		 * InvMixColumns(), for decryption.
		 */
		Ssm0 = new uint[256];
		Ssm1 = new uint[256];
		Ssm2 = new uint[256];
		Ssm3 = new uint[256];
		iSsm0 = new uint[256];
		iSsm1 = new uint[256];
		iSsm2 = new uint[256];
		iSsm3 = new uint[256];
		for (uint p = 0; p < 0x100; p ++) {
			uint q = S[p];
			Ssm0[p] = (mul2(q) << 24)
				| (q << 16)
				| (q << 8)
				| mul3(q);
			Ssm1[p] = (mul3(q) << 24)
				| (mul2(q) << 16)
				| (q << 8)
				| q;
			Ssm2[p] = (q << 24)
				| (mul3(q) << 16)
				| (mul2(q) << 8)
				| q;
			Ssm3[p] = (q << 24)
				| (q << 16)
				| (mul3(q) << 8)
				| mul2(q);
			q = iS[p];
			iSsm0[p] = (mule(q) << 24)
				| (mul9(q) << 16)
				| (muld(q) << 8)
				| mulb(q);
			iSsm1[p] = (mulb(q) << 24)
				| (mule(q) << 16)
				| (mul9(q) << 8)
				| muld(q);
			iSsm2[p] = (muld(q) << 24)
				| (mulb(q) << 16)
				| (mule(q) << 8)
				| mul9(q);
			iSsm3[p] = (mul9(q) << 24)
				| (muld(q) << 16)
				| (mulb(q) << 8)
				| mule(q);
		}
	}
}

}
