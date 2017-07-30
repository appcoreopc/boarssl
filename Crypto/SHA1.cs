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
 * SHA-1 implementation. SHA-1 is described in FIPS 180-4. Note that
 * SHA-1 collisions can be computed more efficiently than what would be
 * expected from an ideal hash function with the same output size; and
 * this was actually done at least once. Use with care.
 */

public sealed class SHA1 : DigestCore {

	const int BLOCK_LEN = 64;

	uint A, B, C, D, E;
	byte[] block, saveBlock;
	int ptr;
	ulong byteCount;

	/* 
	 * Create a new instance. It is ready to process data bytes.
	 */
	public SHA1()
	{
		block = new byte[BLOCK_LEN];
		saveBlock = new byte[BLOCK_LEN];
		Reset();
	}

	/* see IDigest */
	public override string Name {
		get {
			return "SHA-1";
		}
	}

	/* see IDigest */
	public override int DigestSize {
		get {
			return 20;
		}
	}

	/* see IDigest */
	public override int BlockSize {
		get {
			return 64;
		}
	}

	/* see IDigest */
	public override void Reset()
	{
		A = 0x67452301;
		B = 0xEFCDAB89;
		C = 0x98BADCFE;
		D = 0x10325476;
		E = 0xC3D2E1F0;
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
		uint saveA = A;
		uint saveB = B;
		uint saveC = C;
		uint saveD = D;
		uint saveE = E;
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
		Enc32be(A, outBuf, off);
		Enc32be(B, outBuf, off + 4);
		Enc32be(C, outBuf, off + 8);
		Enc32be(D, outBuf, off + 12);
		Enc32be(E, outBuf, off + 16);

		/*
		 * Restore current state.
		 */
		Array.Copy(saveBlock, 0, block, 0, savePtr);
		A = saveA;
		B = saveB;
		C = saveC;
		D = saveD;
		E = saveE;
		ptr = savePtr;
	}

	/* see IDigest */
	public override IDigest Dup()
	{
		SHA1 h = new SHA1();
		h.A = A;
		h.B = B;
		h.C = C;
		h.D = D;
		h.E = E;
		h.ptr = ptr;
		h.byteCount = byteCount;
		Array.Copy(block, 0, h.block, 0, ptr);
		return h;
	}

	/* see IDigest */
	public override void CurrentState(byte[] outBuf, int off)
	{
		Enc32be(A, outBuf, off);
		Enc32be(B, outBuf, off + 4);
		Enc32be(C, outBuf, off + 8);
		Enc32be(D, outBuf, off + 12);
		Enc32be(E, outBuf, off + 16);
	}

	const uint K1 = 0x5A827999;
	const uint K2 = 0x6ED9EBA1;
	const uint K3 = 0x8F1BBCDC;
	const uint K4 = 0xCA62C1D6;

	void ProcessBlock()
	{
		/*
		 * Read state words.
		 */
		uint wa = A;
		uint wb = B;
		uint wc = C;
		uint wd = D;
		uint we = E;

		/*
		 * Rounds 0 to 19.
		 */
		uint x0 = Dec32be(block,  0);
		we += ((wa << 5) | (wa >> 27)) + (wd ^ (wb & (wc ^ wd))) + x0 + K1;
		wb = (wb << 30) | (wb >> 2);
		uint x1 = Dec32be(block,  4);
		wd += ((we << 5) | (we >> 27)) + (wc ^ (wa & (wb ^ wc))) + x1 + K1;
		wa = (wa << 30) | (wa >> 2);
		uint x2 = Dec32be(block,  8);
		wc += ((wd << 5) | (wd >> 27)) + (wb ^ (we & (wa ^ wb))) + x2 + K1;
		we = (we << 30) | (we >> 2);
		uint x3 = Dec32be(block, 12);
		wb += ((wc << 5) | (wc >> 27)) + (wa ^ (wd & (we ^ wa))) + x3 + K1;
		wd = (wd << 30) | (wd >> 2);
		uint x4 = Dec32be(block, 16);
		wa += ((wb << 5) | (wb >> 27)) + (we ^ (wc & (wd ^ we))) + x4 + K1;
		wc = (wc << 30) | (wc >> 2);
		uint x5 = Dec32be(block, 20);
		we += ((wa << 5) | (wa >> 27)) + (wd ^ (wb & (wc ^ wd))) + x5 + K1;
		wb = (wb << 30) | (wb >> 2);
		uint x6 = Dec32be(block, 24);
		wd += ((we << 5) | (we >> 27)) + (wc ^ (wa & (wb ^ wc))) + x6 + K1;
		wa = (wa << 30) | (wa >> 2);
		uint x7 = Dec32be(block, 28);
		wc += ((wd << 5) | (wd >> 27)) + (wb ^ (we & (wa ^ wb))) + x7 + K1;
		we = (we << 30) | (we >> 2);
		uint x8 = Dec32be(block, 32);
		wb += ((wc << 5) | (wc >> 27)) + (wa ^ (wd & (we ^ wa))) + x8 + K1;
		wd = (wd << 30) | (wd >> 2);
		uint x9 = Dec32be(block, 36);
		wa += ((wb << 5) | (wb >> 27)) + (we ^ (wc & (wd ^ we))) + x9 + K1;
		wc = (wc << 30) | (wc >> 2);
		uint xA = Dec32be(block, 40);
		we += ((wa << 5) | (wa >> 27)) + (wd ^ (wb & (wc ^ wd))) + xA + K1;
		wb = (wb << 30) | (wb >> 2);
		uint xB = Dec32be(block, 44);
		wd += ((we << 5) | (we >> 27)) + (wc ^ (wa & (wb ^ wc))) + xB + K1;
		wa = (wa << 30) | (wa >> 2);
		uint xC = Dec32be(block, 48);
		wc += ((wd << 5) | (wd >> 27)) + (wb ^ (we & (wa ^ wb))) + xC + K1;
		we = (we << 30) | (we >> 2);
		uint xD = Dec32be(block, 52);
		wb += ((wc << 5) | (wc >> 27)) + (wa ^ (wd & (we ^ wa))) + xD + K1;
		wd = (wd << 30) | (wd >> 2);
		uint xE = Dec32be(block, 56);
		wa += ((wb << 5) | (wb >> 27)) + (we ^ (wc & (wd ^ we))) + xE + K1;
		wc = (wc << 30) | (wc >> 2);
		uint xF = Dec32be(block, 60);
		we += ((wa << 5) | (wa >> 27)) + (wd ^ (wb & (wc ^ wd))) + xF + K1;
		wb = (wb << 30) | (wb >> 2);
		x0 ^= xD ^ x8 ^ x2;
		x0 = (x0 << 1) | (x0 >> 31);
		wd += ((we << 5) | (we >> 27)) + (wc ^ (wa & (wb ^ wc))) + x0 + K1;
		wa = (wa << 30) | (wa >> 2);
		x1 ^= xE ^ x9 ^ x3;
		x1 = (x1 << 1) | (x1 >> 31);
		wc += ((wd << 5) | (wd >> 27)) + (wb ^ (we & (wa ^ wb))) + x1 + K1;
		we = (we << 30) | (we >> 2);
		x2 ^= xF ^ xA ^ x4;
		x2 = (x2 << 1) | (x2 >> 31);
		wb += ((wc << 5) | (wc >> 27)) + (wa ^ (wd & (we ^ wa))) + x2 + K1;
		wd = (wd << 30) | (wd >> 2);
		x3 ^= x0 ^ xB ^ x5;
		x3 = (x3 << 1) | (x3 >> 31);
		wa += ((wb << 5) | (wb >> 27)) + (we ^ (wc & (wd ^ we))) + x3 + K1;
		wc = (wc << 30) | (wc >> 2);

		/*
		 * Rounds 20 to 39.
		 */
		x4 ^= x1 ^ xC ^ x6;
		x4 = (x4 << 1) | (x4 >> 31);
		we += ((wa << 5) | (wa >> 27)) + (wb ^ wc ^ wd) + x4 + K2;
		wb = (wb << 30) | (wb >> 2);
		x5 ^= x2 ^ xD ^ x7;
		x5 = (x5 << 1) | (x5 >> 31);
		wd += ((we << 5) | (we >> 27)) + (wa ^ wb ^ wc) + x5 + K2;
		wa = (wa << 30) | (wa >> 2);
		x6 ^= x3 ^ xE ^ x8;
		x6 = (x6 << 1) | (x6 >> 31);
		wc += ((wd << 5) | (wd >> 27)) + (we ^ wa ^ wb) + x6 + K2;
		we = (we << 30) | (we >> 2);
		x7 ^= x4 ^ xF ^ x9;
		x7 = (x7 << 1) | (x7 >> 31);
		wb += ((wc << 5) | (wc >> 27)) + (wd ^ we ^ wa) + x7 + K2;
		wd = (wd << 30) | (wd >> 2);
		x8 ^= x5 ^ x0 ^ xA;
		x8 = (x8 << 1) | (x8 >> 31);
		wa += ((wb << 5) | (wb >> 27)) + (wc ^ wd ^ we) + x8 + K2;
		wc = (wc << 30) | (wc >> 2);
		x9 ^= x6 ^ x1 ^ xB;
		x9 = (x9 << 1) | (x9 >> 31);
		we += ((wa << 5) | (wa >> 27)) + (wb ^ wc ^ wd) + x9 + K2;
		wb = (wb << 30) | (wb >> 2);
		xA ^= x7 ^ x2 ^ xC;
		xA = (xA << 1) | (xA >> 31);
		wd += ((we << 5) | (we >> 27)) + (wa ^ wb ^ wc) + xA + K2;
		wa = (wa << 30) | (wa >> 2);
		xB ^= x8 ^ x3 ^ xD;
		xB = (xB << 1) | (xB >> 31);
		wc += ((wd << 5) | (wd >> 27)) + (we ^ wa ^ wb) + xB + K2;
		we = (we << 30) | (we >> 2);
		xC ^= x9 ^ x4 ^ xE;
		xC = (xC << 1) | (xC >> 31);
		wb += ((wc << 5) | (wc >> 27)) + (wd ^ we ^ wa) + xC + K2;
		wd = (wd << 30) | (wd >> 2);
		xD ^= xA ^ x5 ^ xF;
		xD = (xD << 1) | (xD >> 31);
		wa += ((wb << 5) | (wb >> 27)) + (wc ^ wd ^ we) + xD + K2;
		wc = (wc << 30) | (wc >> 2);
		xE ^= xB ^ x6 ^ x0;
		xE = (xE << 1) | (xE >> 31);
		we += ((wa << 5) | (wa >> 27)) + (wb ^ wc ^ wd) + xE + K2;
		wb = (wb << 30) | (wb >> 2);
		xF ^= xC ^ x7 ^ x1;
		xF = (xF << 1) | (xF >> 31);
		wd += ((we << 5) | (we >> 27)) + (wa ^ wb ^ wc) + xF + K2;
		wa = (wa << 30) | (wa >> 2);
		x0 ^= xD ^ x8 ^ x2;
		x0 = (x0 << 1) | (x0 >> 31);
		wc += ((wd << 5) | (wd >> 27)) + (we ^ wa ^ wb) + x0 + K2;
		we = (we << 30) | (we >> 2);
		x1 ^= xE ^ x9 ^ x3;
		x1 = (x1 << 1) | (x1 >> 31);
		wb += ((wc << 5) | (wc >> 27)) + (wd ^ we ^ wa) + x1 + K2;
		wd = (wd << 30) | (wd >> 2);
		x2 ^= xF ^ xA ^ x4;
		x2 = (x2 << 1) | (x2 >> 31);
		wa += ((wb << 5) | (wb >> 27)) + (wc ^ wd ^ we) + x2 + K2;
		wc = (wc << 30) | (wc >> 2);
		x3 ^= x0 ^ xB ^ x5;
		x3 = (x3 << 1) | (x3 >> 31);
		we += ((wa << 5) | (wa >> 27)) + (wb ^ wc ^ wd) + x3 + K2;
		wb = (wb << 30) | (wb >> 2);
		x4 ^= x1 ^ xC ^ x6;
		x4 = (x4 << 1) | (x4 >> 31);
		wd += ((we << 5) | (we >> 27)) + (wa ^ wb ^ wc) + x4 + K2;
		wa = (wa << 30) | (wa >> 2);
		x5 ^= x2 ^ xD ^ x7;
		x5 = (x5 << 1) | (x5 >> 31);
		wc += ((wd << 5) | (wd >> 27)) + (we ^ wa ^ wb) + x5 + K2;
		we = (we << 30) | (we >> 2);
		x6 ^= x3 ^ xE ^ x8;
		x6 = (x6 << 1) | (x6 >> 31);
		wb += ((wc << 5) | (wc >> 27)) + (wd ^ we ^ wa) + x6 + K2;
		wd = (wd << 30) | (wd >> 2);
		x7 ^= x4 ^ xF ^ x9;
		x7 = (x7 << 1) | (x7 >> 31);
		wa += ((wb << 5) | (wb >> 27)) + (wc ^ wd ^ we) + x7 + K2;
		wc = (wc << 30) | (wc >> 2);

		/*
		 * Rounds 40 to 59.
		 */
		x8 ^= x5 ^ x0 ^ xA;
		x8 = (x8 << 1) | (x8 >> 31);
		we += ((wa << 5) | (wa >> 27)) + ((wc & wd) ^ (wb & (wc ^ wd))) + x8 + K3;
		wb = (wb << 30) | (wb >> 2);
		x9 ^= x6 ^ x1 ^ xB;
		x9 = (x9 << 1) | (x9 >> 31);
		wd += ((we << 5) | (we >> 27)) + ((wb & wc) ^ (wa & (wb ^ wc))) + x9 + K3;
		wa = (wa << 30) | (wa >> 2);
		xA ^= x7 ^ x2 ^ xC;
		xA = (xA << 1) | (xA >> 31);
		wc += ((wd << 5) | (wd >> 27)) + ((wa & wb) ^ (we & (wa ^ wb))) + xA + K3;
		we = (we << 30) | (we >> 2);
		xB ^= x8 ^ x3 ^ xD;
		xB = (xB << 1) | (xB >> 31);
		wb += ((wc << 5) | (wc >> 27)) + ((we & wa) ^ (wd & (we ^ wa))) + xB + K3;
		wd = (wd << 30) | (wd >> 2);
		xC ^= x9 ^ x4 ^ xE;
		xC = (xC << 1) | (xC >> 31);
		wa += ((wb << 5) | (wb >> 27)) + ((wd & we) ^ (wc & (wd ^ we))) + xC + K3;
		wc = (wc << 30) | (wc >> 2);
		xD ^= xA ^ x5 ^ xF;
		xD = (xD << 1) | (xD >> 31);
		we += ((wa << 5) | (wa >> 27)) + ((wc & wd) ^ (wb & (wc ^ wd))) + xD + K3;
		wb = (wb << 30) | (wb >> 2);
		xE ^= xB ^ x6 ^ x0;
		xE = (xE << 1) | (xE >> 31);
		wd += ((we << 5) | (we >> 27)) + ((wb & wc) ^ (wa & (wb ^ wc))) + xE + K3;
		wa = (wa << 30) | (wa >> 2);
		xF ^= xC ^ x7 ^ x1;
		xF = (xF << 1) | (xF >> 31);
		wc += ((wd << 5) | (wd >> 27)) + ((wa & wb) ^ (we & (wa ^ wb))) + xF + K3;
		we = (we << 30) | (we >> 2);
		x0 ^= xD ^ x8 ^ x2;
		x0 = (x0 << 1) | (x0 >> 31);
		wb += ((wc << 5) | (wc >> 27)) + ((we & wa) ^ (wd & (we ^ wa))) + x0 + K3;
		wd = (wd << 30) | (wd >> 2);
		x1 ^= xE ^ x9 ^ x3;
		x1 = (x1 << 1) | (x1 >> 31);
		wa += ((wb << 5) | (wb >> 27)) + ((wd & we) ^ (wc & (wd ^ we))) + x1 + K3;
		wc = (wc << 30) | (wc >> 2);
		x2 ^= xF ^ xA ^ x4;
		x2 = (x2 << 1) | (x2 >> 31);
		we += ((wa << 5) | (wa >> 27)) + ((wc & wd) ^ (wb & (wc ^ wd))) + x2 + K3;
		wb = (wb << 30) | (wb >> 2);
		x3 ^= x0 ^ xB ^ x5;
		x3 = (x3 << 1) | (x3 >> 31);
		wd += ((we << 5) | (we >> 27)) + ((wb & wc) ^ (wa & (wb ^ wc))) + x3 + K3;
		wa = (wa << 30) | (wa >> 2);
		x4 ^= x1 ^ xC ^ x6;
		x4 = (x4 << 1) | (x4 >> 31);
		wc += ((wd << 5) | (wd >> 27)) + ((wa & wb) ^ (we & (wa ^ wb))) + x4 + K3;
		we = (we << 30) | (we >> 2);
		x5 ^= x2 ^ xD ^ x7;
		x5 = (x5 << 1) | (x5 >> 31);
		wb += ((wc << 5) | (wc >> 27)) + ((we & wa) ^ (wd & (we ^ wa))) + x5 + K3;
		wd = (wd << 30) | (wd >> 2);
		x6 ^= x3 ^ xE ^ x8;
		x6 = (x6 << 1) | (x6 >> 31);
		wa += ((wb << 5) | (wb >> 27)) + ((wd & we) ^ (wc & (wd ^ we))) + x6 + K3;
		wc = (wc << 30) | (wc >> 2);
		x7 ^= x4 ^ xF ^ x9;
		x7 = (x7 << 1) | (x7 >> 31);
		we += ((wa << 5) | (wa >> 27)) + ((wc & wd) ^ (wb & (wc ^ wd))) + x7 + K3;
		wb = (wb << 30) | (wb >> 2);
		x8 ^= x5 ^ x0 ^ xA;
		x8 = (x8 << 1) | (x8 >> 31);
		wd += ((we << 5) | (we >> 27)) + ((wb & wc) ^ (wa & (wb ^ wc))) + x8 + K3;
		wa = (wa << 30) | (wa >> 2);
		x9 ^= x6 ^ x1 ^ xB;
		x9 = (x9 << 1) | (x9 >> 31);
		wc += ((wd << 5) | (wd >> 27)) + ((wa & wb) ^ (we & (wa ^ wb))) + x9 + K3;
		we = (we << 30) | (we >> 2);
		xA ^= x7 ^ x2 ^ xC;
		xA = (xA << 1) | (xA >> 31);
		wb += ((wc << 5) | (wc >> 27)) + ((we & wa) ^ (wd & (we ^ wa))) + xA + K3;
		wd = (wd << 30) | (wd >> 2);
		xB ^= x8 ^ x3 ^ xD;
		xB = (xB << 1) | (xB >> 31);
		wa += ((wb << 5) | (wb >> 27)) + ((wd & we) ^ (wc & (wd ^ we))) + xB + K3;
		wc = (wc << 30) | (wc >> 2);

		/*
		 * Rounds 60 to 79.
		 */
		xC ^= x9 ^ x4 ^ xE;
		xC = (xC << 1) | (xC >> 31);
		we += ((wa << 5) | (wa >> 27)) + (wb ^ wc ^ wd) + xC + K4;
		wb = (wb << 30) | (wb >> 2);
		xD ^= xA ^ x5 ^ xF;
		xD = (xD << 1) | (xD >> 31);
		wd += ((we << 5) | (we >> 27)) + (wa ^ wb ^ wc) + xD + K4;
		wa = (wa << 30) | (wa >> 2);
		xE ^= xB ^ x6 ^ x0;
		xE = (xE << 1) | (xE >> 31);
		wc += ((wd << 5) | (wd >> 27)) + (we ^ wa ^ wb) + xE + K4;
		we = (we << 30) | (we >> 2);
		xF ^= xC ^ x7 ^ x1;
		xF = (xF << 1) | (xF >> 31);
		wb += ((wc << 5) | (wc >> 27)) + (wd ^ we ^ wa) + xF + K4;
		wd = (wd << 30) | (wd >> 2);
		x0 ^= xD ^ x8 ^ x2;
		x0 = (x0 << 1) | (x0 >> 31);
		wa += ((wb << 5) | (wb >> 27)) + (wc ^ wd ^ we) + x0 + K4;
		wc = (wc << 30) | (wc >> 2);
		x1 ^= xE ^ x9 ^ x3;
		x1 = (x1 << 1) | (x1 >> 31);
		we += ((wa << 5) | (wa >> 27)) + (wb ^ wc ^ wd) + x1 + K4;
		wb = (wb << 30) | (wb >> 2);
		x2 ^= xF ^ xA ^ x4;
		x2 = (x2 << 1) | (x2 >> 31);
		wd += ((we << 5) | (we >> 27)) + (wa ^ wb ^ wc) + x2 + K4;
		wa = (wa << 30) | (wa >> 2);
		x3 ^= x0 ^ xB ^ x5;
		x3 = (x3 << 1) | (x3 >> 31);
		wc += ((wd << 5) | (wd >> 27)) + (we ^ wa ^ wb) + x3 + K4;
		we = (we << 30) | (we >> 2);
		x4 ^= x1 ^ xC ^ x6;
		x4 = (x4 << 1) | (x4 >> 31);
		wb += ((wc << 5) | (wc >> 27)) + (wd ^ we ^ wa) + x4 + K4;
		wd = (wd << 30) | (wd >> 2);
		x5 ^= x2 ^ xD ^ x7;
		x5 = (x5 << 1) | (x5 >> 31);
		wa += ((wb << 5) | (wb >> 27)) + (wc ^ wd ^ we) + x5 + K4;
		wc = (wc << 30) | (wc >> 2);
		x6 ^= x3 ^ xE ^ x8;
		x6 = (x6 << 1) | (x6 >> 31);
		we += ((wa << 5) | (wa >> 27)) + (wb ^ wc ^ wd) + x6 + K4;
		wb = (wb << 30) | (wb >> 2);
		x7 ^= x4 ^ xF ^ x9;
		x7 = (x7 << 1) | (x7 >> 31);
		wd += ((we << 5) | (we >> 27)) + (wa ^ wb ^ wc) + x7 + K4;
		wa = (wa << 30) | (wa >> 2);
		x8 ^= x5 ^ x0 ^ xA;
		x8 = (x8 << 1) | (x8 >> 31);
		wc += ((wd << 5) | (wd >> 27)) + (we ^ wa ^ wb) + x8 + K4;
		we = (we << 30) | (we >> 2);
		x9 ^= x6 ^ x1 ^ xB;
		x9 = (x9 << 1) | (x9 >> 31);
		wb += ((wc << 5) | (wc >> 27)) + (wd ^ we ^ wa) + x9 + K4;
		wd = (wd << 30) | (wd >> 2);
		xA ^= x7 ^ x2 ^ xC;
		xA = (xA << 1) | (xA >> 31);
		wa += ((wb << 5) | (wb >> 27)) + (wc ^ wd ^ we) + xA + K4;
		wc = (wc << 30) | (wc >> 2);
		xB ^= x8 ^ x3 ^ xD;
		xB = (xB << 1) | (xB >> 31);
		we += ((wa << 5) | (wa >> 27)) + (wb ^ wc ^ wd) + xB + K4;
		wb = (wb << 30) | (wb >> 2);
		xC ^= x9 ^ x4 ^ xE;
		xC = (xC << 1) | (xC >> 31);
		wd += ((we << 5) | (we >> 27)) + (wa ^ wb ^ wc) + xC + K4;
		wa = (wa << 30) | (wa >> 2);
		xD ^= xA ^ x5 ^ xF;
		xD = (xD << 1) | (xD >> 31);
		wc += ((wd << 5) | (wd >> 27)) + (we ^ wa ^ wb) + xD + K4;
		we = (we << 30) | (we >> 2);
		xE ^= xB ^ x6 ^ x0;
		xE = (xE << 1) | (xE >> 31);
		wb += ((wc << 5) | (wc >> 27)) + (wd ^ we ^ wa) + xE + K4;
		wd = (wd << 30) | (wd >> 2);
		xF ^= xC ^ x7 ^ x1;
		xF = (xF << 1) | (xF >> 31);
		wa += ((wb << 5) | (wb >> 27)) + (wc ^ wd ^ we) + xF + K4;
		wc = (wc << 30) | (wc >> 2);

		/*
		 * Update state words and reset block pointer.
		 */
		A += wa;
		B += wb;
		C += wc;
		D += wd;
		E += we;
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
