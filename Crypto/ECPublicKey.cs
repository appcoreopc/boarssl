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
 * This class contains an EC public key, consisting of two elements:
 * -- an elliptic curve
 * -- a non-zero point on that curve (called "Pub")
 */

public class ECPublicKey : IPublicKey {

	public ECCurve Curve {
		get {
			return curve;
		}
	}

	public byte[] Pub {
		get {
			return pub;
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

	ECCurve curve;
	byte[] pub;
	int hashCode;

	internal MutableECPoint iPub;

	/*
	 * Create a new instance with the provided elements. The
	 * constructor verifies that the provided point is part of
	 * the curve.
	 */
	public ECPublicKey(ECCurve curve, byte[] Pub)
	{
		this.curve = curve;
		this.pub = Pub;
		iPub = curve.Decode(Pub);
		if (iPub.IsInfinity) {
			throw new CryptoException(
				"Public key point is infinity");
		}
		hashCode = curve.GetHashCode()
			^ (int)BigInt.HashInt(iPub.X)
			^ (int)BigInt.HashInt(iPub.Y);
	}

	/*
	 * CheckValid() runs the validity tests on the curve, and
	 * verifies that provided point is part of a subgroup with
	 * the advertised subgroup order.
	 */
	public void CheckValid()
	{
		curve.CheckValid();
		MutableECPoint P = iPub.Dup();
		if (P.MulSpecCT(curve.SubgroupOrder) == 0
			|| !P.IsInfinity)
		{
			throw new CryptoException(
				"Public key point not on the defined subgroup");
		}
	}

	public override bool Equals(object obj)
	{
		ECPublicKey pk = obj as ECPublicKey;
		if (pk == null) {
			return false;
		}
		if (hashCode != pk.hashCode) {
			return false;
		}
		return iPub.Eq(pk.iPub);
	}

	public override int GetHashCode()
	{
		return hashCode;
	}
}

}
