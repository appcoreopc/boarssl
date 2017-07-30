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
 * Implementation for Curve25519.
 */

internal class ECCurve25519 : ECCurve {

	public override string Name {
		get {
			return "Curve25519";
		}
	}

	public override ECCurveType CurveType {
		get {
			return ECCurveType.Montgomery;
		}
	}

	public override int EncodedLength {
		get {
			return 32;
		}
	}

	public override int EncodedLengthCompressed {
		get {
			return 32;
		}
	}

	public override byte[] GetGenerator(bool compressed)
	{
		byte[] G = new byte[32];
		G[0] = 9;
		return G;
	}

	private static byte[] ORDER = {
		0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x14, 0xDE, 0xF9, 0xDE, 0xA2, 0xF7, 0x9C, 0xD6,
		0x58, 0x12, 0x63, 0x1A, 0x5C, 0xF5, 0xD3, 0xED
	};

	private static byte[] COFACTOR = {
		0x08
	};

	private static byte[] MOD = {
		0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xED
	};

	internal ModInt mp;
	internal ModInt ma24;

	internal ECCurve25519() : base(ORDER, COFACTOR)
	{
		mp = new ModInt(MOD);
		ma24 = mp.Dup();
		ma24.Set(121665);
		ma24.ToMonty();
	}

	public override void CheckValid()
	{
		/* Nothing to do, the curve is valid by construction. */
	}

	public override int GetXoff(out int len)
	{
		len = 32;
		return 0;
	}

	/* obsolete
	public override uint Mul(byte[] G, byte[] x, byte[] D, bool compressed)
	{
		if (G.Length != 32 || D.Length != 32 || x.Length > 32) {
			return 0;
		}

		byte[] k = new byte[32];
		Array.Copy(x, 0, k, 32 - x.Length, x.Length);

		k[31] &= 0xF8;
		k[0] &= 0x7F;
		k[0] |= 0x40;

		byte[] u = new byte[32];
		for (int i = 0; i < 32; i ++) {
			u[i] = G[31 - i];
		}
		u[0] &= 0x7F;

		ModInt x1 = mp.Dup();
		x1.DecodeReduce(u);
		x1.ToMonty();
		ModInt x2 = mp.Dup();
		x2.SetMonty(0xFFFFFFFF);
		ModInt z2 = mp.Dup();
		ModInt x3 = x1.Dup();
		ModInt z3 = x2.Dup();
		uint swap = 0;

		ModInt a = mp.Dup();
		ModInt aa = mp.Dup();
		ModInt b = mp.Dup();
		ModInt bb = mp.Dup();
		ModInt c = mp.Dup();
		ModInt d = mp.Dup();
		ModInt e = mp.Dup();

		for (int t = 254; t >= 0; t --) {
			uint kt = (uint)-((k[31 - (t >> 3)] >> (t & 7)) & 1);
			swap ^= kt;
			x2.CondSwap(x3, swap);
			z2.CondSwap(z3, swap);
			swap = kt;

			a.Set(x2);
			a.Add(z2);
			aa.Set(a);
			aa.MontySquare();
			b.Set(x2);
			b.Sub(z2);
			bb.Set(b);
			bb.MontySquare();
			e.Set(aa);
			e.Sub(bb);
			c.Set(x3);
			c.Add(z3);
			d.Set(x3);
			d.Sub(z3);
			d.MontyMul(a);
			c.MontyMul(b);
			x3.Set(d);
			x3.Add(c);
			x3.MontySquare();
			z3.Set(d);
			z3.Sub(c);
			z3.MontySquare();
			z3.MontyMul(x1);
			x2.Set(aa);
			x2.MontyMul(bb);
			z2.Set(e);
			z2.MontyMul(ma24);
			z2.Add(aa);
			z2.MontyMul(e);
		}
		x2.CondSwap(x3, swap);
		z2.CondSwap(z3, swap);

		z2.FromMonty();
		z2.Invert();
		x2.MontyMul(z2);

		x2.Encode(u);
		for (int i = 0; i < 32; i ++) {
			D[i] = u[31 - i];
		}
		return 0xFFFFFFFF;
	}

	public override uint MulAdd(byte[] A, byte[] x, byte[] B, byte[] y,
		byte[] D, bool compressed)
	{
		throw new CryptoException(
			"Operation not supported for Curve25519");
	}
	*/

	public override bool Equals(object obj)
	{
		return (obj as ECCurve25519) != null;
	}
	
	public override int GetHashCode()
	{
		return 0x3E96D5F6;
	}

	public override byte[] MakeRandomSecret()
	{
		/*
		 * For Curve25519, we simply generate a random 32-byte
		 * array, to which we apply the "clamping" that will
		 * be done for point multiplication anyway.
		 */
		byte[] x = new byte[32];
		RNG.GetBytes(x);
		x[0] &= 0x7F;
		x[0] |= 0x40;
		x[31] &= 0xF8;
		return x;
	}

	internal override MutableECPoint MakeZero()
	{
		return new MutableECPointCurve25519();
	}

	internal override MutableECPoint MakeGenerator()
	{
		MutableECPointCurve25519 G = new MutableECPointCurve25519();
		G.Decode(GetGenerator(false));
		return G;
	}

	internal override MutableECPoint Decode(byte[] enc)
	{
		MutableECPointCurve25519 P = new MutableECPointCurve25519();
		P.Decode(enc);
		return P;
	}
}

}
