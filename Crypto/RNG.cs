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
using System.Text;

using NC = System.Security.Cryptography;

namespace Crypto {

/*
 * Random generator.
 */

public sealed class RNG {

	/*
	 * To ensure efficient generation of random numbers, we use
	 * our own PRNG, seeded with a strong value (from the operating
	 * system), and based on AES-CTR. We obtain a random 128-bit
	 * key from the OS (RNGCryptoServiceProvider); then we use it
	 * to encrypt successive values for a 128-bit counter (also
	 * initialized from RNGCryptoServiceProvider). This is AES-CTR
	 * mode and thus provably as strong as AES-128 encryption as it
	 * is practiced in SSL/TLS.
	 *
	 * A mutex is used to ensure safe access in a multi-threaded
	 * context. Once initialized, random generation proceeds at
	 * the same speed as AES encryption, i.e. fast enough for
	 * our purposes.
	 *
	 * As a special action for debugging, it is possible to reset
	 * the state to an explicit seed value. Of course, this tends
	 * to kill security, so it should be used only to make actions
	 * reproducible, as part of systematic tests.
	 */

	static object rngMutex = new object();
	static IBlockCipher rngAES = null;
	static byte[] counter, rblock;

	static void Init()
	{
		if (rngAES == null) {
			NC.RNGCryptoServiceProvider srng =
				new NC.RNGCryptoServiceProvider();
			byte[] key = new byte[16];
			byte[] iv = new byte[16];
			srng.GetBytes(key);
			srng.GetBytes(iv);
			Init(key, iv);
		}
	}

	static void Init(byte[] key, byte[] iv)
	{
		if (rngAES == null) {
			rngAES = new AES();
			counter = new byte[16];
			rblock = new byte[16];
		}
		rngAES.SetKey(key);
		Array.Copy(iv, 0, rblock, 0, 16);
	}

	static void NextBlock()
	{
		int len = counter.Length;
		int carry = 1;
		for (int i = 0; i < len; i ++) {
			int v = counter[i] + carry;
			counter[i] = (byte)v;
			carry = v >> 8;
		}
		Array.Copy(counter, 0, rblock, 0, len);
		rngAES.BlockEncrypt(rblock);
	}

	/*
	 * Set or reset the state to the provided seed. All subsequent
	 * output will depend only on that seed value. This function shall
	 * be used ONLY for debug/test purposes, since it replaces the
	 * automatic seeding that uses OS-provided entropy.
	 */
	public static void SetSeed(byte[] seed)
	{
		byte[] s32 = new SHA256().Hash(seed);
		byte[] key = new byte[16];
		byte[] iv = new byte[16];
		Array.Copy(s32, 0, key, 0, 16);
		Array.Copy(s32, 16, iv, 0, 16);
		lock (rngMutex) {
			Init(key, iv);
		}
	}

	/*
	 * Fill the provided array with random bytes.
	 */
	public static void GetBytes(byte[] buf)
	{
		GetBytes(buf, 0, buf.Length);
	}

	/*
	 * Fill the provided array chunk with random bytes.
	 */
	public static void GetBytes(byte[] buf, int off, int len)
	{
		lock (rngMutex) {
			Init();
			while (len > 0) {
				NextBlock();
				int clen = Math.Min(len, rblock.Length);
				Array.Copy(rblock, 0, buf, off, clen);
				off += clen;
				len -= clen;
			}
		}
	}

	/*
	 * Get a new random 32-bit integer (uniform generation).
	 */
	public static uint U32()
	{
		lock (rngMutex) {
			Init();
			NextBlock();
			return (uint)rblock[0]
				| ((uint)rblock[1] << 8)
				| ((uint)rblock[2] << 16)
				| ((uint)rblock[3] << 24);
		}
	}

	/*
	 * Convert integer value x (0 to 15) to an hexadecimal character
	 * (lowercase).
	 */
	static char ToHex(int x)
	{
		int hi = -(((x + 6) >> 4) & 1);
		return (char)(x + 48 + (hi & 39));
	}

	/*
	 * Get a string of random hexadecimal characters. The 'len'
	 * parameter specifies the string length in characters (it
	 * may be odd).
	 */
	public static string GetHex(int len)
	{
		byte[] buf = new byte[(len + 1) >> 1];
		GetBytes(buf);
		StringBuilder sb = new StringBuilder();
		foreach (byte b in buf) {
			sb.Append(b >> 4);
			sb.Append(b & 15);
		}
		string s = sb.ToString();
		if (s.Length > len) {
			s = s.Substring(0, len);
		}
		return s;
	}

	/*
	 * Get a sequence of random non-zero bytes.
	 */
	public static void GetBytesNonZero(byte[] buf)
	{
		GetBytesNonZero(buf, 0, buf.Length);
	}

	/*
	 * Get a sequence of random non-zero bytes.
	 */
	public static void GetBytesNonZero(byte[] buf, int off, int len)
	{
		if (len <= 0) {
			return;
		}
		lock (rngMutex) {
			Init();
			for (;;) {
				NextBlock();
				for (int i = 0; i < rblock.Length; i ++) {
					byte x = rblock[i];
					if (x == 0) {
						continue;
					}
					buf[off ++] = x;
					if (-- len == 0) {
						return;
					}
				}
			}
		}
	}
}

}
