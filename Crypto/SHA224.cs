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
 * SHA-224 implementation. SHA-224 is described in FIPS 180-4.
 */

public sealed class SHA224 : SHA2Small {

	/*
	 * Create a new instance, ready to process data bytes.
	 */
	public SHA224()
	{
	}

	/* see IDigest */
	public override string Name {
		get {
			return "SHA-224";
		}
	}

	/* see IDigest */
	public override int DigestSize {
		get {
			return 28;
		}
	}

	internal override uint[] IV {
		get {
			return IV224;
		}
	}

	internal override SHA2Small DupInner()
	{
		return new SHA224();
	}

	static uint[] IV224 = {
		0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
		0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4
	};
}

}
