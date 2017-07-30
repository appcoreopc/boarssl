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
 * SHA-384 implementation. SHA-384 is described in FIPS 180-4.
 */

public sealed class SHA384 : SHA2Big {

	/*
	 * Create a new instance, ready to process data bytes.
	 */
	public SHA384()
	{
	}

	/* see IDigest */
	public override string Name {
		get {
			return "SHA-384";
		}
	}

	/* see IDigest */
	public override int DigestSize {
		get {
			return 48;
		}
	}

	internal override ulong[] IV {
		get {
			return IV384;
		}
	}

	internal override SHA2Big DupInner()
	{
		return new SHA384();
	}

	static ulong[] IV384 = {
		0xCBBB9D5DC1059ED8, 0x629A292A367CD507,
		0x9159015A3070DD17, 0x152FECD8F70E5939,
		0x67332667FFC00B31, 0x8EB44A8768581511,
		0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4
	};
}

}
