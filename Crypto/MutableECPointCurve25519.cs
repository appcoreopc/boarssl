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
 * An implementation of MutableECPoint for Curve25519.
 * This is a partial implementation that only supports multiplication
 * by a scalar, not general addition.
 */

internal class MutableECPointCurve25519 : MutableECPoint {

	ModInt x;
	ModInt x1, x2, z2, x3, z3;
	ModInt a, aa, b, bb, c, d, e;
	byte[] u;

	/*
	 * Create a new instance. It is initialized to the point at
	 * infinity (represented with a 0).
	 */
	internal MutableECPointCurve25519()
	{
		ECCurve25519 ccc = (ECCurve25519)EC.Curve25519;
		x = ccc.mp.Dup();
		x1 = ccc.mp.Dup();
		x2 = ccc.mp.Dup();
		z2 = ccc.mp.Dup();
		x3 = ccc.mp.Dup();
		z3 = ccc.mp.Dup();
		a = ccc.mp.Dup();
		aa = ccc.mp.Dup();
		b = ccc.mp.Dup();
		bb = ccc.mp.Dup();
		c = ccc.mp.Dup();
		d = ccc.mp.Dup();
		e = ccc.mp.Dup();
		u = new byte[32];
	}

	internal override ECCurve Curve {
		get {
			return EC.Curve25519;
		}
	}

	internal override uint IsInfinityCT {
		get {
			return 0;
		}
	}

	internal override void Normalize()
	{
	}

	internal override byte[] Encode(bool compressed)
	{
		byte[] r = new byte[32];
		Encode(r, false);
		return r;
	}

	internal override uint Encode(byte[] dst, bool compressed)
	{
		if (dst.Length != 32) {
			throw new CryptoException("invalid output length");
		}
		x.Encode(u, 0, 32);
		for (int i = 0; i < 32; i ++) {
			dst[i] = u[31 - i];
		}
		return 0xFFFFFFFF;
	}

	internal override uint DecodeCT(byte[] enc)
	{
		if (enc.Length != 32) {
			return 0;
		}
		for (int i = 0; i < 32; i ++) {
			u[i] = enc[31 - i];
		}
		u[0] &= 0x7F;
		x.DecodeReduce(u);
		return 0xFFFFFFFF;
	}

	internal override byte[] X {
		get {
			return x.Encode();
		}
	}

	internal override byte[] Y {
		get {
			throw new CryptoException(
				"Not implemented for Curve25519");
		}
	}

	internal override MutableECPoint Dup()
	{
		MutableECPointCurve25519 Q = new MutableECPointCurve25519();
		Q.Set(this);
		return Q;
	}

	internal void Set(byte[] X, byte[] Y, bool check)
	{
		throw new CryptoException("Not implemented for Curve25519");
	}

	internal void Set(ModInt X, ModInt Y, bool check)
	{
		throw new CryptoException("Not implemented for Curve25519");
	}

	internal override void SetZero()
	{
		throw new CryptoException("Not implemented for Curve25519");
	}

	internal override void Set(MutableECPoint Q)
	{
		MutableECPointCurve25519 R = SameCurve(Q);
		x.Set(R.x);
	}

	internal override void Set(MutableECPoint Q, uint ctl)
	{
		MutableECPointCurve25519 R = SameCurve(Q);
		x.CondCopy(R.x, ctl);
	}

	internal override void SetMux(uint ctl,
		MutableECPoint P1, MutableECPoint P2)
	{
		SetMuxInner(ctl, SameCurve(P1), SameCurve(P2));
	}

	void SetMuxInner(uint ctl,
		MutableECPointCurve25519 P1, MutableECPointCurve25519 P2)
	{
		x.CopyMux(ctl, P1.x, P2.x);
	}

	internal override void DoubleCT()
	{
		throw new CryptoException("Not implemented for Curve25519");
	}

	internal override uint AddCT(MutableECPoint Q)
	{
		throw new CryptoException("Not implemented for Curve25519");
	}

	internal override void NegCT()
	{
		throw new CryptoException("Not implemented for Curve25519");
	}

	internal override uint MulSpecCT(byte[] n)
	{
		/*
		 * Copy scalar into a temporary array (u[]) for
		 * normalisation to 32 bytes and clamping.
		 */
		if (n.Length > 32) {
			return 0;
		}
		Array.Copy(n, 0, u, 32 - n.Length, n.Length);
		for (int i = 0; i < 32 - n.Length; i ++) {
			u[i] = 0;
		}
		u[31] &= 0xF8;
		u[0] &= 0x7F;
		u[0] |= 0x40;

		x1.Set(x);
		x1.ToMonty();
		x2.SetMonty(0xFFFFFFFF);
		z2.Set(0);
		x3.Set(x1);
		z3.Set(x2);
		uint swap = 0;
		ModInt ma24 = ((ECCurve25519)EC.Curve25519).ma24;

		for (int t = 254; t >= 0; t --) {
			uint kt = (uint)-((u[31 - (t >> 3)] >> (t & 7)) & 1);
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

		/*
		 * We need to restore z2 to normal representation before
		 * inversion. Then the final Montgomery multiplication
		 * will cancel out with x2, which is still in Montgomery
		 * representation.
		 */
		z2.FromMonty();
		z2.Invert();
		x2.MontyMul(z2);

		/*
		 * x2 now contains the result.
		 */
		x.Set(x2);
		return 0xFFFFFFFF;
	}

	internal override uint EqCT(MutableECPoint Q)
	{
		MutableECPointCurve25519 R = SameCurve(Q);
		return x.EqCT(R.x);
	}

	MutableECPointCurve25519 SameCurve(MutableECPoint Q)
	{
		MutableECPointCurve25519 R = Q as MutableECPointCurve25519;
		if (R == null) {
			throw new CryptoException("Mixed curves");
		}
		return R;
	}
}

}
