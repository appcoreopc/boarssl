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
 * This class contains an EC private key, consisting of two elements:
 * -- an elliptic curve
 * -- the private integer (X)
 *
 * The private integer is always handled as an integer modulo the
 * curve subbroup order. Its binary representation is unsigned big-endian
 * with exactly the same length as the subgroup order.
 */

public class ECPrivateKey : IPrivateKey {

	public ECCurve Curve {
		get {
			return curve;
		}
	}

	public byte[] X {
		get {
			return priv;
		}
	}

	public int KeySizeBits {
		get {
			return BigInt.BitLength(curve.SubgroupOrder);
		}
	}

	public string AlgorithmName {
		get {
			return "EC";
		}
	}

	IPublicKey IPrivateKey.PublicKey {
		get {
			return this.PublicKey;
		}
	}

	public ECPublicKey PublicKey {
		get {
			if (dpk == null) {
				MutableECPoint G = curve.MakeGenerator();
				G.MulSpecCT(priv);
				dpk = new ECPublicKey(curve, G.Encode(false));
			}
			return dpk;
		}
	}

	ECCurve curve;
	byte[] priv;
	ECPublicKey dpk;

	/*
	 * Create a new instance with the provided elements. The
	 * constructor verifies that the provided private integer
	 * is non-zero and is less than the subgroup order.
	 */
	public ECPrivateKey(ECCurve curve, byte[] X)
	{
		this.curve = curve;
		ModInt ms = new ModInt(curve.SubgroupOrder);
		uint good = ms.Decode(X);
		good &= ~ms.IsZeroCT;
		if (good == 0) {
			throw new CryptoException("Invalid private key");
		}
		priv = ms.Encode();
		dpk = null;
	}

	/*
	 * CheckValid() runs the validity tests on the curve.
	 */
	public void CheckValid()
	{
		curve.CheckValid();
	}
}

}
