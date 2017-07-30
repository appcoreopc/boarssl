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
 * Implementation of SHA-224 and SHA-256, as described in FIPS 180-4.
 */

public abstract class SHA2Small : DigestCore {

	const int BLOCK_LEN = 64;

	uint[] state;
	byte[] block, saveBlock;
	int ptr;
	ulong byteCount;
	uint[] W;

	/*
	 * Create a new instance, ready to process data bytes. The
	 * output length (in bytes) and initial value must be specified.
	 */
	internal SHA2Small()
	{
		state = new uint[8];
		block = new byte[BLOCK_LEN];
		saveBlock = new byte[BLOCK_LEN];
		W = new uint[64];
		Reset();
	}

	internal abstract uint[] IV { get; }

	internal abstract SHA2Small DupInner();

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
		uint A = state[0];
		uint B = state[1];
		uint C = state[2];
		uint D = state[3];
		uint E = state[4];
		uint F = state[5];
		uint G = state[6];
		uint H = state[7];
		int savePtr = ptr;
		Array.Copy(block, 0, saveBlock, 0, savePtr);

		/*
		 * Add padding. This may involve processing an extra block.
		 */
		block[ptr ++] = 0x80;
		if (ptr > BLOCK_LEN - 8) {
			for (int j = ptr; j < BLOCK_LEN; j ++) {
				block[j] = 0;
			}
			ProcessBlock();
		}
		for (int j = ptr; j < (BLOCK_LEN - 8); j ++) {
			block[j] = 0;
		}
		ulong x = byteCount << 3;
		Enc32be((uint)(x >> 32), block, BLOCK_LEN - 8);
		Enc32be((uint)x, block, BLOCK_LEN - 4);

		/*
		 * Process final block and encode result.
		 */
		ProcessBlock();
		int n = DigestSize >> 2;
		for (int i = 0; i < n; i ++) {
			Enc32be(state[i], outBuf, off + (i << 2));
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
		SHA2Small h = DupInner();
		Array.Copy(state, 0, h.state, 0, state.Length);
		h.ptr = ptr;
		h.byteCount = byteCount;
		Array.Copy(block, 0, h.block, 0, ptr);
		return h;
	}

	/* see IDigest */
	public override void CurrentState(byte[] outBuf, int off)
	{
		int n = DigestSize >> 2;
		for (int i = 0; i < n; i ++) {
			Enc32be(state[i], outBuf, off + (i << 2));
		}
	}

	static uint[] K = {
		0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
		0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
		0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
		0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
		0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
		0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
		0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
		0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
		0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
		0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
		0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
		0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
		0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
		0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
		0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
		0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
	};

	void ProcessBlock()
	{
		/*
		 * Read state words.
		 */
		uint A = state[0];
		uint B = state[1];
		uint C = state[2];
		uint D = state[3];
		uint E = state[4];
		uint F = state[5];
		uint G = state[6];
		uint H = state[7];

		uint T1, T2;
		uint[] W = this.W;
		byte[] block = this.block;

		for (int i = 0, j = 0; i < 16; i ++, j += 4) {
			W[i] = Dec32be(block, j);
		}
		for (int i = 16; i < 64; i ++) {
			uint w2 = W[i - 2];
			uint w15 = W[i - 15];
			W[i] = (((w2 << 15) | (w2 >> 17))
				^ ((w2 << 13) | (w2 >> 19))
				^ (w2 >> 10))
				+ W[i - 7]
				+ (((w15 << 25) | (w15 >> 7))
				^ ((w15 << 14) | (w15 >> 18))
				^ (w15 >> 3))
				+ W[i - 16];
		}
		for (int i = 0; i < 64; i += 8) {
			T1 = H + (((E << 26) | (E >> 6))
				^ ((E << 21) | (E >> 11))
				^ ((E << 7) | (E >> 25)))
				+ (G ^ (E & (F ^ G)))
				+ K[i + 0] + W[i + 0];
			T2 = (((A << 30) | (A >> 2))
				^ ((A << 19) | (A >> 13))
				^ ((A << 10) | (A >> 22)))
				+ ((A & B) ^ (C & (A ^ B)));
			D += T1;
			H = T1 + T2;
			T1 = G + (((D << 26) | (D >> 6))
				^ ((D << 21) | (D >> 11))
				^ ((D << 7) | (D >> 25)))
				+ (F ^ (D & (E ^ F)))
				+ K[i + 1] + W[i + 1];
			T2 = (((H << 30) | (H >> 2))
				^ ((H << 19) | (H >> 13))
				^ ((H << 10) | (H >> 22)))
				+ ((H & A) ^ (B & (H ^ A)));
			C += T1;
			G = T1 + T2;
			T1 = F + (((C << 26) | (C >> 6))
				^ ((C << 21) | (C >> 11))
				^ ((C << 7) | (C >> 25)))
				+ (E ^ (C & (D ^ E)))
				+ K[i + 2] + W[i + 2];
			T2 = (((G << 30) | (G >> 2))
				^ ((G << 19) | (G >> 13))
				^ ((G << 10) | (G >> 22)))
				+ ((G & H) ^ (A & (G ^ H)));
			B += T1;
			F = T1 + T2;
			T1 = E + (((B << 26) | (B >> 6))
				^ ((B << 21) | (B >> 11))
				^ ((B << 7) | (B >> 25)))
				+ (D ^ (B & (C ^ D)))
				+ K[i + 3] + W[i + 3];
			T2 = (((F << 30) | (F >> 2))
				^ ((F << 19) | (F >> 13))
				^ ((F << 10) | (F >> 22)))
				+ ((F & G) ^ (H & (F ^ G)));
			A += T1;
			E = T1 + T2;
			T1 = D + (((A << 26) | (A >> 6))
				^ ((A << 21) | (A >> 11))
				^ ((A << 7) | (A >> 25)))
				+ (C ^ (A & (B ^ C)))
				+ K[i + 4] + W[i + 4];
			T2 = (((E << 30) | (E >> 2))
				^ ((E << 19) | (E >> 13))
				^ ((E << 10) | (E >> 22)))
				+ ((E & F) ^ (G & (E ^ F)));
			H += T1;
			D = T1 + T2;
			T1 = C + (((H << 26) | (H >> 6))
				^ ((H << 21) | (H >> 11))
				^ ((H << 7) | (H >> 25)))
				+ (B ^ (H & (A ^ B)))
				+ K[i + 5] + W[i + 5];
			T2 = (((D << 30) | (D >> 2))
				^ ((D << 19) | (D >> 13))
				^ ((D << 10) | (D >> 22)))
				+ ((D & E) ^ (F & (D ^ E)));
			G += T1;
			C = T1 + T2;
			T1 = B + (((G << 26) | (G >> 6))
				^ ((G << 21) | (G >> 11))
				^ ((G << 7) | (G >> 25)))
				+ (A ^ (G & (H ^ A)))
				+ K[i + 6] + W[i + 6];
			T2 = (((C << 30) | (C >> 2))
				^ ((C << 19) | (C >> 13))
				^ ((C << 10) | (C >> 22)))
				+ ((C & D) ^ (E & (C ^ D)));
			F += T1;
			B = T1 + T2;
			T1 = A + (((F << 26) | (F >> 6))
				^ ((F << 21) | (F >> 11))
				^ ((F << 7) | (F >> 25)))
				+ (H ^ (F & (G ^ H)))
				+ K[i + 7] + W[i + 7];
			T2 = (((B << 30) | (B >> 2))
				^ ((B << 19) | (B >> 13))
				^ ((B << 10) | (B >> 22)))
				+ ((B & C) ^ (D & (B ^ C)));
			E += T1;
			A = T1 + T2;
		}

		/* obsolete
		for (int i = 0; i < 64; i ++) {
			uint T1 = H + (((E << 26) | (E >> 6))
				^ ((E << 21) | (E >> 11))
				^ ((E << 7) | (E >> 25)))
				+ (G ^ (E & (F ^ G)))
				+ K[i] + W[i];
			uint T2 = (((A << 30) | (A >> 2))
				^ ((A << 19) | (A >> 13))
				^ ((A << 10) | (A >> 22)))
				+ ((A & B) ^ (C & (A ^ B)));
			H = G; G = F; F = E; E = D + T1;
			D = C; C = B; B = A; A = T1 + T2;
		}
		*/

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
}

}
