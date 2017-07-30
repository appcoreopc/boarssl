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
 * SHA-512 implementation. SHA-512 is described in FIPS 180-4.
 */

public sealed class SHA512 : SHA2Big {

	/*
	 * Create a new instance, ready to process data bytes.
	 */
	public SHA512()
	{
	}

	/* see IDigest */
	public override string Name {
		get {
			return "SHA-512";
		}
	}

	/* see IDigest */
	public override int DigestSize {
		get {
			return 64;
		}
	}

	internal override ulong[] IV {
		get {
			return IV512;
		}
	}

	internal override SHA2Big DupInner()
	{
		return new SHA512();
	}

	static ulong[] IV512 = {
		0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
		0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
		0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
		0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
	};
}

}
