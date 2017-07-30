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
using System.IO;

namespace SSLTLS {

internal class IO {

	internal static void Enc16be(int x, byte[] buf, int off)
	{
		buf[off + 0] = (byte)(x >> 8);
		buf[off + 1] = (byte)x;
	}

	internal static void Enc24be(int x, byte[] buf, int off)
	{
		buf[off + 0] = (byte)(x >> 16);
		buf[off + 1] = (byte)(x >> 8);
		buf[off + 2] = (byte)x;
	}

	internal static void Enc32be(uint x, byte[] buf, int off)
	{
		buf[off + 0] = (byte)(x >> 24);
		buf[off + 1] = (byte)(x >> 16);
		buf[off + 2] = (byte)(x >> 8);
		buf[off + 3] = (byte)x;
	}

	internal static void Enc64be(ulong x, byte[] buf, int off)
	{
		for (int i = 0; i < 8; i ++) {
			buf[off + 7 - i] = (byte)x;
			x >>= 8;
		}
	}

	internal static int Dec16be(byte[] buf, int off)
	{
		return (buf[off + 0] << 8)
			| buf[off + 1];
	}

	internal static int Dec24be(byte[] buf, int off)
	{
		return (buf[off + 0] << 16)
			| (buf[off + 1] << 8)
			| buf[off + 2];
	}

	internal static uint Dec32be(byte[] buf, int off)
	{
		return ((uint)buf[off + 0] << 24)
			| ((uint)buf[off + 1] << 16)
			| ((uint)buf[off + 2] << 8)
			| (uint)buf[off + 3];
	}

	internal static ulong Dec64be(byte[] buf, int off)
	{
		ulong x = 0;
		for (int i = 0; i < 8; i ++) {
			x = (x << 8) | buf[off + i];
		}
		return x;
	}

	internal static void Write16(Stream s, int x)
	{
		s.WriteByte((byte)(x >> 8));
		s.WriteByte((byte)x);
	}

	internal static void Write24(Stream s, int x)
	{
		s.WriteByte((byte)(x >> 16));
		s.WriteByte((byte)(x >> 8));
		s.WriteByte((byte)x);
	}

	/*
	 * Write a 5-byte record header at the specified offset.
	 */
	internal static void WriteHeader(int recordType, int version,
		int length, byte[] buf, int off)
	{
		buf[off] = (byte)recordType;
		IO.Enc16be(version, buf, off + 1);
		IO.Enc16be(length, buf, off + 3);
	}

	/*
	 * Read all requested bytes. Fail on unexpected EOF, unless
	 * 'eof' is true, in which case an EOF is acceptable at the
	 * very beginning (i.e. no byte read at all).
	 *
	 * Returned value is true, unless there was an EOF at the
	 * start and 'eof' is true, in which case returned value is
	 * false.
	 */
	internal static bool ReadAll(Stream s, byte[] buf, bool eof)
	{
		return ReadAll(s, buf, 0, buf.Length, eof);
	}

	/*
	 * Read all requested bytes. Fail on unexpected EOF, unless
	 * 'eof' is true, in which case an EOF is acceptable at the
	 * very beginning (i.e. no byte read at all).
	 *
	 * Returned value is true, unless there was an EOF at the
	 * start and 'eof' is true, in which case returned value is
	 * false.
	 */
	internal static bool ReadAll(Stream s,
		byte[] buf, int off, int len, bool eof)
	{
		int tlen = 0;
		while (tlen < len) {
			int rlen = s.Read(buf, off + tlen, len - tlen);
			if (rlen <= 0) {
				if (eof && tlen == 0) {
					return false;
				}
				throw new SSLException("Unexpected EOF");
			}
			tlen += rlen;
		}
		return true;
	}

	/*
	 * Compare two arrays of bytes for equality.
	 */
	internal static bool Eq(byte[] a, byte[] b)
	{
		return EqCT(a, b) != 0;
	}

	/*
	 * Compare two arrays of bytes for equality. This is constant-time
	 * if both arrays have the same length. Returned value is 0xFFFFFFFF
	 * on equality, 0 otherwise.
	 */
	internal static uint EqCT(byte[] a, byte[] b)
	{
		int n = a.Length;
		if (n != b.Length) {
			return 0;
		}
		int z = 0;
		for (int i = 0; i < n; i ++) {
			z |= a[i] ^ b[i];
		}
		return ~(uint)((z | -z) >> 31);
	}

	/*
	 * Duplicate an array of bytes. null is duplicated into null.
	 */
	internal static byte[] CopyBlob(byte[] x)
	{
		if (x == null) {
			return null;
		}
		byte[] y = new byte[x.Length];
		Array.Copy(x, 0, y, 0, x.Length);
		return y;
	}
}

}
