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
 * MD5 implementation. MD5 is described in RFC 1321.
 *
 * WARNING: as a cryptographic hash function, MD5 turned out to be
 * very weak with regards to collisions. Use with care.
 */

public sealed class MD5 : DigestCore {

	const int BLOCK_LEN = 64;

	uint A, B, C, D;
	byte[] block, saveBlock;
	int ptr;
	ulong byteCount;

	/*
	 * Create a new instance. It is ready to process data bytes.
	 */
	public MD5()
	{
		block = new byte[BLOCK_LEN];
		saveBlock = new byte[BLOCK_LEN];
		Reset();
	}

	/* see IDigest */
	public override string Name {
		get {
			return "MD5";
		}
	}

	/* see IDigest */
	public override int DigestSize {
		get {
			return 16;
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
		Enc32le((uint)x, block, BLOCK_LEN - 8);
		Enc32le((uint)(x >> 32), block, BLOCK_LEN - 4);

		/*
		 * Process final block and encode result.
		 */
		ProcessBlock();
		Enc32le(A, outBuf, off);
		Enc32le(B, outBuf, off + 4);
		Enc32le(C, outBuf, off + 8);
		Enc32le(D, outBuf, off + 12);

		/*
		 * Restore current state.
		 */
		Array.Copy(saveBlock, 0, block, 0, savePtr);
		A = saveA;
		B = saveB;
		C = saveC;
		D = saveD;
		ptr = savePtr;
	}

	/* see IDigest */
	public override IDigest Dup()
	{
		MD5 h = new MD5();
		h.A = A;
		h.B = B;
		h.C = C;
		h.D = D;
		h.ptr = ptr;
		h.byteCount = byteCount;
		Array.Copy(block, 0, h.block, 0, ptr);
		return h;
	}

	/* see IDigest */
	public override void CurrentState(byte[] outBuf, int off)
	{
		Enc32le(A, outBuf, off);
		Enc32le(B, outBuf, off + 4);
		Enc32le(C, outBuf, off + 8);
		Enc32le(D, outBuf, off + 12);
	}

	void ProcessBlock()
	{
		/*
		 * Decode input block (sixteen 32-bit words).
		 */
		uint x0 = Dec32le(block,  0);
		uint x1 = Dec32le(block,  4);
		uint x2 = Dec32le(block,  8);
		uint x3 = Dec32le(block, 12);
		uint x4 = Dec32le(block, 16);
		uint x5 = Dec32le(block, 20);
		uint x6 = Dec32le(block, 24);
		uint x7 = Dec32le(block, 28);
		uint x8 = Dec32le(block, 32);
		uint x9 = Dec32le(block, 36);
		uint xA = Dec32le(block, 40);
		uint xB = Dec32le(block, 44);
		uint xC = Dec32le(block, 48);
		uint xD = Dec32le(block, 52);
		uint xE = Dec32le(block, 56);
		uint xF = Dec32le(block, 60);

		/*
		 * Read state words.
		 */
		uint wa = A;
		uint wb = B;
		uint wc = C;
		uint wd = D;
		uint tmp;

		/*
		 * Rounds 0 to 15.
		 */
		tmp = wa + (wd ^ (wb & (wc ^ wd))) + x0 + 0xD76AA478;
		wa = wb + ((tmp << 7) | (tmp >> 25));
		tmp = wd + (wc ^ (wa & (wb ^ wc))) + x1 + 0xE8C7B756;
		wd = wa + ((tmp << 12) | (tmp >> 20));
		tmp = wc + (wb ^ (wd & (wa ^ wb))) + x2 + 0x242070DB;
		wc = wd + ((tmp << 17) | (tmp >> 15));
		tmp = wb + (wa ^ (wc & (wd ^ wa))) + x3 + 0xC1BDCEEE;
		wb = wc + ((tmp << 22) | (tmp >> 10));
		tmp = wa + (wd ^ (wb & (wc ^ wd))) + x4 + 0xF57C0FAF;
		wa = wb + ((tmp << 7) | (tmp >> 25));
		tmp = wd + (wc ^ (wa & (wb ^ wc))) + x5 + 0x4787C62A;
		wd = wa + ((tmp << 12) | (tmp >> 20));
		tmp = wc + (wb ^ (wd & (wa ^ wb))) + x6 + 0xA8304613;
		wc = wd + ((tmp << 17) | (tmp >> 15));
		tmp = wb + (wa ^ (wc & (wd ^ wa))) + x7 + 0xFD469501;
		wb = wc + ((tmp << 22) | (tmp >> 10));
		tmp = wa + (wd ^ (wb & (wc ^ wd))) + x8 + 0x698098D8;
		wa = wb + ((tmp << 7) | (tmp >> 25));
		tmp = wd + (wc ^ (wa & (wb ^ wc))) + x9 + 0x8B44F7AF;
		wd = wa + ((tmp << 12) | (tmp >> 20));
		tmp = wc + (wb ^ (wd & (wa ^ wb))) + xA + 0xFFFF5BB1;
		wc = wd + ((tmp << 17) | (tmp >> 15));
		tmp = wb + (wa ^ (wc & (wd ^ wa))) + xB + 0x895CD7BE;
		wb = wc + ((tmp << 22) | (tmp >> 10));
		tmp = wa + (wd ^ (wb & (wc ^ wd))) + xC + 0x6B901122;
		wa = wb + ((tmp << 7) | (tmp >> 25));
		tmp = wd + (wc ^ (wa & (wb ^ wc))) + xD + 0xFD987193;
		wd = wa + ((tmp << 12) | (tmp >> 20));
		tmp = wc + (wb ^ (wd & (wa ^ wb))) + xE + 0xA679438E;
		wc = wd + ((tmp << 17) | (tmp >> 15));
		tmp = wb + (wa ^ (wc & (wd ^ wa))) + xF + 0x49B40821;
		wb = wc + ((tmp << 22) | (tmp >> 10));

		/*
		 * Rounds 16 to 31.
		 */
		tmp = wa + (wc ^ (wd & (wb ^ wc))) + x1 + 0xF61E2562;
		wa = wb + ((tmp << 5) | (tmp >> 27));
		tmp = wd + (wb ^ (wc & (wa ^ wb))) + x6 + 0xC040B340;
		wd = wa + ((tmp << 9) | (tmp >> 23));
		tmp = wc + (wa ^ (wb & (wd ^ wa))) + xB + 0x265E5A51;
		wc = wd + ((tmp << 14) | (tmp >> 18));
		tmp = wb + (wd ^ (wa & (wc ^ wd))) + x0 + 0xE9B6C7AA;
		wb = wc + ((tmp << 20) | (tmp >> 12));
		tmp = wa + (wc ^ (wd & (wb ^ wc))) + x5 + 0xD62F105D;
		wa = wb + ((tmp << 5) | (tmp >> 27));
		tmp = wd + (wb ^ (wc & (wa ^ wb))) + xA + 0x02441453;
		wd = wa + ((tmp << 9) | (tmp >> 23));
		tmp = wc + (wa ^ (wb & (wd ^ wa))) + xF + 0xD8A1E681;
		wc = wd + ((tmp << 14) | (tmp >> 18));
		tmp = wb + (wd ^ (wa & (wc ^ wd))) + x4 + 0xE7D3FBC8;
		wb = wc + ((tmp << 20) | (tmp >> 12));
		tmp = wa + (wc ^ (wd & (wb ^ wc))) + x9 + 0x21E1CDE6;
		wa = wb + ((tmp << 5) | (tmp >> 27));
		tmp = wd + (wb ^ (wc & (wa ^ wb))) + xE + 0xC33707D6;
		wd = wa + ((tmp << 9) | (tmp >> 23));
		tmp = wc + (wa ^ (wb & (wd ^ wa))) + x3 + 0xF4D50D87;
		wc = wd + ((tmp << 14) | (tmp >> 18));
		tmp = wb + (wd ^ (wa & (wc ^ wd))) + x8 + 0x455A14ED;
		wb = wc + ((tmp << 20) | (tmp >> 12));
		tmp = wa + (wc ^ (wd & (wb ^ wc))) + xD + 0xA9E3E905;
		wa = wb + ((tmp << 5) | (tmp >> 27));
		tmp = wd + (wb ^ (wc & (wa ^ wb))) + x2 + 0xFCEFA3F8;
		wd = wa + ((tmp << 9) | (tmp >> 23));
		tmp = wc + (wa ^ (wb & (wd ^ wa))) + x7 + 0x676F02D9;
		wc = wd + ((tmp << 14) | (tmp >> 18));
		tmp = wb + (wd ^ (wa & (wc ^ wd))) + xC + 0x8D2A4C8A;
		wb = wc + ((tmp << 20) | (tmp >> 12));

		/*
		 * Rounds 32 to 47.
		 */
		tmp = wa + (wb ^ wc ^ wd) + x5 + 0xFFFA3942;
		wa = wb + ((tmp << 4) | (tmp >> 28));
		tmp = wd + (wa ^ wb ^ wc) + x8 + 0x8771F681;
		wd = wa + ((tmp << 11) | (tmp >> 21));
		tmp = wc + (wd ^ wa ^ wb) + xB + 0x6D9D6122;
		wc = wd + ((tmp << 16) | (tmp >> 16));
		tmp = wb + (wc ^ wd ^ wa) + xE + 0xFDE5380C;
		wb = wc + ((tmp << 23) | (tmp >> 9));
		tmp = wa + (wb ^ wc ^ wd) + x1 + 0xA4BEEA44;
		wa = wb + ((tmp << 4) | (tmp >> 28));
		tmp = wd + (wa ^ wb ^ wc) + x4 + 0x4BDECFA9;
		wd = wa + ((tmp << 11) | (tmp >> 21));
		tmp = wc + (wd ^ wa ^ wb) + x7 + 0xF6BB4B60;
		wc = wd + ((tmp << 16) | (tmp >> 16));
		tmp = wb + (wc ^ wd ^ wa) + xA + 0xBEBFBC70;
		wb = wc + ((tmp << 23) | (tmp >> 9));
		tmp = wa + (wb ^ wc ^ wd) + xD + 0x289B7EC6;
		wa = wb + ((tmp << 4) | (tmp >> 28));
		tmp = wd + (wa ^ wb ^ wc) + x0 + 0xEAA127FA;
		wd = wa + ((tmp << 11) | (tmp >> 21));
		tmp = wc + (wd ^ wa ^ wb) + x3 + 0xD4EF3085;
		wc = wd + ((tmp << 16) | (tmp >> 16));
		tmp = wb + (wc ^ wd ^ wa) + x6 + 0x04881D05;
		wb = wc + ((tmp << 23) | (tmp >> 9));
		tmp = wa + (wb ^ wc ^ wd) + x9 + 0xD9D4D039;
		wa = wb + ((tmp << 4) | (tmp >> 28));
		tmp = wd + (wa ^ wb ^ wc) + xC + 0xE6DB99E5;
		wd = wa + ((tmp << 11) | (tmp >> 21));
		tmp = wc + (wd ^ wa ^ wb) + xF + 0x1FA27CF8;
		wc = wd + ((tmp << 16) | (tmp >> 16));
		tmp = wb + (wc ^ wd ^ wa) + x2 + 0xC4AC5665;
		wb = wc + ((tmp << 23) | (tmp >> 9));

		/*
		 * Rounds 48 to 63.
		 */
		tmp = wa + (wc ^ (wb | ~wd)) + x0 + 0xF4292244;
		wa = wb + ((tmp << 6) | (tmp >> 26));
		tmp = wd + (wb ^ (wa | ~wc)) + x7 + 0x432AFF97;
		wd = wa + ((tmp << 10) | (tmp >> 22));
		tmp = wc + (wa ^ (wd | ~wb)) + xE + 0xAB9423A7;
		wc = wd + ((tmp << 15) | (tmp >> 17));
		tmp = wb + (wd ^ (wc | ~wa)) + x5 + 0xFC93A039;
		wb = wc + ((tmp << 21) | (tmp >> 11));
		tmp = wa + (wc ^ (wb | ~wd)) + xC + 0x655B59C3;
		wa = wb + ((tmp << 6) | (tmp >> 26));
		tmp = wd + (wb ^ (wa | ~wc)) + x3 + 0x8F0CCC92;
		wd = wa + ((tmp << 10) | (tmp >> 22));
		tmp = wc + (wa ^ (wd | ~wb)) + xA + 0xFFEFF47D;
		wc = wd + ((tmp << 15) | (tmp >> 17));
		tmp = wb + (wd ^ (wc | ~wa)) + x1 + 0x85845DD1;
		wb = wc + ((tmp << 21) | (tmp >> 11));
		tmp = wa + (wc ^ (wb | ~wd)) + x8 + 0x6FA87E4F;
		wa = wb + ((tmp << 6) | (tmp >> 26));
		tmp = wd + (wb ^ (wa | ~wc)) + xF + 0xFE2CE6E0;
		wd = wa + ((tmp << 10) | (tmp >> 22));
		tmp = wc + (wa ^ (wd | ~wb)) + x6 + 0xA3014314;
		wc = wd + ((tmp << 15) | (tmp >> 17));
		tmp = wb + (wd ^ (wc | ~wa)) + xD + 0x4E0811A1;
		wb = wc + ((tmp << 21) | (tmp >> 11));
		tmp = wa + (wc ^ (wb | ~wd)) + x4 + 0xF7537E82;
		wa = wb + ((tmp << 6) | (tmp >> 26));
		tmp = wd + (wb ^ (wa | ~wc)) + xB + 0xBD3AF235;
		wd = wa + ((tmp << 10) | (tmp >> 22));
		tmp = wc + (wa ^ (wd | ~wb)) + x2 + 0x2AD7D2BB;
		wc = wd + ((tmp << 15) | (tmp >> 17));
		tmp = wb + (wd ^ (wc | ~wa)) + x9 + 0xEB86D391;
		wb = wc + ((tmp << 21) | (tmp >> 11));

		/*
		 * Update state words and reset block pointer.
		 */
		A += wa;
		B += wb;
		C += wc;
		D += wd;
		ptr = 0;
	}

	static uint Dec32le(byte[] buf, int off)
	{
		return (uint)buf[off]
			| ((uint)buf[off + 1] << 8)
			| ((uint)buf[off + 2] << 16)
			| ((uint)buf[off + 3] << 24);
	}

	static void Enc32le(uint x, byte[] buf, int off)
	{
		buf[off] = (byte)x;
		buf[off + 1] = (byte)(x >> 8);
		buf[off + 2] = (byte)(x >> 16);
		buf[off + 3] = (byte)(x >> 24);
	}
}

}
