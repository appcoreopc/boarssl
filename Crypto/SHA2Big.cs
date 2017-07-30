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
 * Implementation of SHA-384 and SHA-512, as described in FIPS 180-4.
 */

public abstract class SHA2Big : DigestCore {

	const int BLOCK_LEN = 128;

	ulong[] state;
	byte[] block, saveBlock;
	int ptr;
	ulong byteCount;
	ulong[] W;

	/*
	 * Create a new instance, ready to process data bytes. The
	 * output length (in bytes) and initial value must be specified.
	 */
	internal SHA2Big()
	{
		state = new ulong[8];
		block = new byte[BLOCK_LEN];
		saveBlock = new byte[BLOCK_LEN];
		W = new ulong[80];
		Reset();
	}

	internal abstract ulong[] IV { get; }

	internal abstract SHA2Big DupInner();

	/* see IDigest */
	public override int BlockSize {
		get {
			return BLOCK_LEN;
		}
	}

	/* see IDigest */
	public override void Reset()
	{
		Array.Copy(IV, 0, state, 0, state.Length);
		byteCount = 0;
		ptr = 0;
	}

	/* see IDigest */
	public override void Update(byte b)
	{
		block[ptr ++] = b;
		byteCount ++;
		if (ptr == BLOCK_LEN) {
			ProcessBlock();
		}
	}

	/* see IDigest */
	public override void Update(byte[] buf, int off, int len)
	{
		if (len < 0) {
			throw new ArgumentException("negative chunk length");
		}
		byteCount += (ulong)len;
		while (len > 0) {
			int clen = Math.Min(len, BLOCK_LEN - ptr);
			Array.Copy(buf, off, block, ptr, clen);
			off += clen;
			len -= clen;
			ptr += clen;
			if (ptr == BLOCK_LEN) {
				ProcessBlock();
			}
		}
	}

	/* see IDigest */
	public override void DoPartial(byte[] outBuf, int off)
	{
		/*
		 * Save current state.
		 */
		ulong A = state[0];
		ulong B = state[1];
		ulong C = state[2];
		ulong D = state[3];
		ulong E = state[4];
		ulong F = state[5];
		ulong G = state[6];
		ulong H = state[7];
		int savePtr = ptr;
		Array.Copy(block, 0, saveBlock, 0, savePtr);

		/*
		 * Add padding. This may involve processing an extra block.
		 */
		block[ptr ++] = 0x80;
		if (ptr > BLOCK_LEN - 16) {
			for (int j = ptr; j < BLOCK_LEN; j ++) {
				block[j] = 0;
			}
			ProcessBlock();
		}
		for (int j = ptr; j < (BLOCK_LEN - 16); j ++) {
			block[j] = 0;
		}
		Enc64be(byteCount >> 61, block, BLOCK_LEN - 16);
		Enc64be(byteCount << 3, block, BLOCK_LEN - 8);

		/*
		 * Process final block and encode result.
		 */
		ProcessBlock();
		int n = DigestSize >> 3;
		for (int i = 0; i < n; i ++) {
			Enc64be(state[i], outBuf, off + (i << 3));
		}

		/*
		 * Restore current state.
		 */
		Array.Copy(saveBlock, 0, block, 0, savePtr);
		state[0] = A;
		state[1] = B;
		state[2] = C;
		state[3] = D;
		state[4] = E;
		state[5] = F;
		state[6] = G;
		state[7] = H;
		ptr = savePtr;
	}

	/* see IDigest */
	public override IDigest Dup()
	{
		SHA2Big h = DupInner();
		Array.Copy(state, 0, h.state, 0, state.Length);
		h.ptr = ptr;
		h.byteCount = byteCount;
		Array.Copy(block, 0, h.block, 0, ptr);
		return h;
	}

	/* see IDigest */
	public override void CurrentState(byte[] outBuf, int off)
	{
		int n = DigestSize >> 3;
		for (int i = 0; i < n; i ++) {
			Enc64be(state[i], outBuf, off + (i << 3));
		}
	}

	static ulong[] K = {
		0x428A2F98D728AE22, 0x7137449123EF65CD,
		0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
		0x3956C25BF348B538, 0x59F111F1B605D019,
		0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
		0xD807AA98A3030242, 0x12835B0145706FBE,
		0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
		0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1,
		0x9BDC06A725C71235, 0xC19BF174CF692694,
		0xE49B69C19EF14AD2, 0xEFBE4786384F25E3,
		0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
		0x2DE92C6F592B0275, 0x4A7484AA6EA6E483,
		0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
		0x983E5152EE66DFAB, 0xA831C66D2DB43210,
		0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
		0xC6E00BF33DA88FC2, 0xD5A79147930AA725,
		0x06CA6351E003826F, 0x142929670A0E6E70,
		0x27B70A8546D22FFC, 0x2E1B21385C26C926,
		0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
		0x650A73548BAF63DE, 0x766A0ABB3C77B2A8,
		0x81C2C92E47EDAEE6, 0x92722C851482353B,
		0xA2BFE8A14CF10364, 0xA81A664BBC423001,
		0xC24B8B70D0F89791, 0xC76C51A30654BE30,
		0xD192E819D6EF5218, 0xD69906245565A910,
		0xF40E35855771202A, 0x106AA07032BBD1B8,
		0x19A4C116B8D2D0C8, 0x1E376C085141AB53,
		0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
		0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB,
		0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
		0x748F82EE5DEFB2FC, 0x78A5636F43172F60,
		0x84C87814A1F0AB72, 0x8CC702081A6439EC,
		0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9,
		0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
		0xCA273ECEEA26619C, 0xD186B8C721C0C207,
		0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
		0x06F067AA72176FBA, 0x0A637DC5A2C898A6,
		0x113F9804BEF90DAE, 0x1B710B35131C471B,
		0x28DB77F523047D84, 0x32CAAB7B40C72493,
		0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
		0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A,
		0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817
	};

	void ProcessBlock()
	{
		/*
		 * Read state words.
		 */
		ulong A = state[0];
		ulong B = state[1];
		ulong C = state[2];
		ulong D = state[3];
		ulong E = state[4];
		ulong F = state[5];
		ulong G = state[6];
		ulong H = state[7];

		ulong T1, T2;
		ulong[] W = this.W;
		byte[] block = this.block;

		for (int i = 0, j = 0; i < 16; i ++, j += 8) {
			W[i] = Dec64be(block, j);
		}
		for (int i = 16; i < 80; i ++) {
			ulong w2 = W[i - 2];
			ulong w15 = W[i - 15];
			W[i] = (((w2 << 45) | (w2 >> 19))
				^ ((w2 << 3) | (w2 >> 61))
				^ (w2 >> 6))
				+ W[i - 7]
				+ (((w15 << 63) | (w15 >> 1))
				^ ((w15 << 56) | (w15 >> 8))
				^ (w15 >> 7))
				+ W[i - 16];
		}
		for (int i = 0; i < 80; i += 8) {
			T1 = H + (((E << 50) | (E >> 14))
				^ ((E << 46) | (E >> 18))
				^ ((E << 23) | (E >> 41)))
				+ (G ^ (E & (F ^ G)))
				+ K[i + 0] + W[i + 0];
			T2 = (((A << 36) | (A >> 28))
				^ ((A << 30) | (A >> 34))
				^ ((A << 25) | (A >> 39)))
				+ ((A & B) ^ (C & (A ^ B)));
			D += T1;
			H = T1 + T2;
			T1 = G + (((D << 50) | (D >> 14))
				^ ((D << 46) | (D >> 18))
				^ ((D << 23) | (D >> 41)))
				+ (F ^ (D & (E ^ F)))
				+ K[i + 1] + W[i + 1];
			T2 = (((H << 36) | (H >> 28))
				^ ((H << 30) | (H >> 34))
				^ ((H << 25) | (H >> 39)))
				+ ((H & A) ^ (B & (H ^ A)));
			C += T1;
			G = T1 + T2;
			T1 = F + (((C << 50) | (C >> 14))
				^ ((C << 46) | (C >> 18))
				^ ((C << 23) | (C >> 41)))
				+ (E ^ (C & (D ^ E)))
				+ K[i + 2] + W[i + 2];
			T2 = (((G << 36) | (G >> 28))
				^ ((G << 30) | (G >> 34))
				^ ((G << 25) | (G >> 39)))
				+ ((G & H) ^ (A & (G ^ H)));
			B += T1;
			F = T1 + T2;
			T1 = E + (((B << 50) | (B >> 14))
				^ ((B << 46) | (B >> 18))
				^ ((B << 23) | (B >> 41)))
				+ (D ^ (B & (C ^ D)))
				+ K[i + 3] + W[i + 3];
			T2 = (((F << 36) | (F >> 28))
				^ ((F << 30) | (F >> 34))
				^ ((F << 25) | (F >> 39)))
				+ ((F & G) ^ (H & (F ^ G)));
			A += T1;
			E = T1 + T2;
			T1 = D + (((A << 50) | (A >> 14))
				^ ((A << 46) | (A >> 18))
				^ ((A << 23) | (A >> 41)))
				+ (C ^ (A & (B ^ C)))
				+ K[i + 4] + W[i + 4];
			T2 = (((E << 36) | (E >> 28))
				^ ((E << 30) | (E >> 34))
				^ ((E << 25) | (E >> 39)))
				+ ((E & F) ^ (G & (E ^ F)));
			H += T1;
			D = T1 + T2;
			T1 = C + (((H << 50) | (H >> 14))
				^ ((H << 46) | (H >> 18))
				^ ((H << 23) | (H >> 41)))
				+ (B ^ (H & (A ^ B)))
				+ K[i + 5] + W[i + 5];
			T2 = (((D << 36) | (D >> 28))
				^ ((D << 30) | (D >> 34))
				^ ((D << 25) | (D >> 39)))
				+ ((D & E) ^ (F & (D ^ E)));
			G += T1;
			C = T1 + T2;
			T1 = B + (((G << 50) | (G >> 14))
				^ ((G << 46) | (G >> 18))
				^ ((G << 23) | (G >> 41)))
				+ (A ^ (G & (H ^ A)))
				+ K[i + 6] + W[i + 6];
			T2 = (((C << 36) | (C >> 28))
				^ ((C << 30) | (C >> 34))
				^ ((C << 25) | (C >> 39)))
				+ ((C & D) ^ (E & (C ^ D)));
			F += T1;
			B = T1 + T2;
			T1 = A + (((F << 50) | (F >> 14))
				^ ((F << 46) | (F >> 18))
				^ ((F << 23) | (F >> 41)))
				+ (H ^ (F & (G ^ H)))
				+ K[i + 7] + W[i + 7];
			T2 = (((B << 36) | (B >> 28))
				^ ((B << 30) | (B >> 34))
				^ ((B << 25) | (B >> 39)))
				+ ((B & C) ^ (D & (B ^ C)));
			E += T1;
			A = T1 + T2;
		}

		/*
		 * Update state words and reset block pointer.
		 */
		state[0] += A;
		state[1] += B;
		state[2] += C;
		state[3] += D;
		state[4] += E;
		state[5] += F;
		state[6] += G;
		state[7] += H;
		ptr = 0;
	}

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

	static void Enc64be(ulong x, byte[] buf, int off)
	{
		buf[off] = (byte)(x >> 56);
		buf[off + 1] = (byte)(x >> 48);
		buf[off + 2] = (byte)(x >> 40);
		buf[off + 3] = (byte)(x >> 32);
		buf[off + 4] = (byte)(x >> 24);
		buf[off + 5] = (byte)(x >> 16);
		buf[off + 6] = (byte)(x >> 8);
		buf[off + 7] = (byte)x;
	}
}

}
