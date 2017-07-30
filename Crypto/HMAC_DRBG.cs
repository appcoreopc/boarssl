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
 * Implementation of HMAC_DRBG (NIST SP800-90A).
 *
 * This class provides HMAC_DRBG as a deterministic PRNG from a given
 * seed. Once a seed is set, chunks of data are obtained with
 * GetBytes(). The GetBytes() methods can be called several times;
 * the internal state is updated after each call. Setting a new seed
 * resets the internal state.
 */

public sealed class HMAC_DRBG {

	HMAC hm;
	byte[] K, V;
	bool seeded;

	/*
	 * Create the instance over the provided hash function
	 * implementation. The digest instance is linked in and will
	 * be used repeatedly. The engine is not seeded yet.
	 */
	public HMAC_DRBG(IDigest h)
	{
		hm = new HMAC(h.Dup());
		int len = h.DigestSize;
		K = new byte[len];
		V = new byte[len];
		seeded = false;
		Reset();
	}

	/*
	 * Reset the engine. A seed will have to be provided before
	 * generating pseudorandom bytes.
	 */
	public void Reset()
	{
		for (int i = 0; i < K.Length; i ++) {
			K[i] = 0x00;
			V[i] = 0x01;
		}
		hm.SetKey(K);
	}

	/*
	 * Reset the engine with the provided seed.
	 */
	public void SetSeed(byte[] seed)
	{
		Reset();
		Update(seed);
	}

	/*
	 * Reset the engine with the provided seed.
	 */
	public void SetSeed(byte[] seed, int off, int len)
	{
		Reset();
		Update(seed, off, len);
	}

	/*
	 * Inject an additional seed. This may be null, in which case
	 * the state is modified but the engine is not marked as "seeded"
	 * (if it was not already marked so).
	 */
	public void Update(byte[] seed)
	{
		if (seed != null) {
			Update(seed, 0, seed.Length);
		} else {
			Update(null, 0, 0);
		}
	}

	/*
	 * Inject an additional seed. If the seed length is 0, then the
	 * state is modified, but the engine is not marked as "seeded"
	 * (if it was not already marked so).
	 */
	public void Update(byte[] seed, int off, int len)
	{
		/* K = HMAC_K(V || 0x00 || seed) */
		hm.Update(V);
		hm.Update((byte)0x00);
		hm.Update(seed, off, len);
		hm.DoFinal(K, 0);
		hm.SetKey(K);

		/* V = HMAC_K(V) */
		hm.Update(V);
		hm.DoFinal(V, 0);

		/*
		 * Stop there if the additional seed is empty.
		 */
		if (len == 0) {
			return;
		}

		/* K = HMAC_K(V || 0x01 || seed) */
		hm.Update(V);
		hm.Update((byte)0x01);
		hm.Update(seed, off, len);
		hm.DoFinal(K, 0);
		hm.SetKey(K);

		/* V = HMAC_K(V) */
		hm.Update(V);
		hm.DoFinal(V, 0);

		/*
		 * We get there only if a non-empty seed is used.
		 */
		seeded = true;
	}

	/*
	 * Generate some pseudorandom bytes. The engine MUST have been
	 * seeded.
	 */
	public void GetBytes(byte[] buf)
	{
		GetBytes(buf, 0, buf.Length);
	}

	/*
	 * Generate some pseudorandom bytes. The engine MUST have been
	 * seeded.
	 */
	public void GetBytes(byte[] buf, int off, int len)
	{
		if (!seeded) {
			throw new CryptoException(
				"HMAC_DRBG engine was not seeded");
		}
		while (len > 0) {
			/* V = HMAC_K(V) */
			hm.Update(V);
			hm.DoFinal(V, 0);
			int clen = Math.Min(V.Length, len);
			Array.Copy(V, 0, buf, off, clen);
			off += clen;
			len -= clen;
		}

		/* K = HMAC_K(V || 0x00) */
		hm.Update(V);
		hm.Update((byte)0x00);
		hm.DoFinal(K, 0);
		hm.SetKey(K);

		/* V = HMAC_K(V) */
		hm.Update(V);
		hm.DoFinal(V, 0);
	}
}

}
