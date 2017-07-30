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
 * An implementation of MutableECPoint for curves in a prime field.
 * Jacobian coordinates are used.
 */

internal class MutableECPointPrime : MutableECPoint {

	/*
	 * Internal representation:
	 *    x = X / (Z^2)
	 *    y = Y / (Z^3)
	 * For the point at infinity, Z == 0.
	 *
	 * When 'affine' is true (0xFFFFFFFF), then mx and my are in
	 * normal representation, and mz is either 0 (point at infinity)
	 * or 1 (otherwise). When 'affine' is false (0x00000000), then
	 * mx, my and mz are in Montgomery representation.
	 *
	 * Note that in affine coordinates, the point at infinity admits
	 * several equivalent representations. In non-affine
	 * coordinates, all points have several equivalent
	 * representations.
	 */

	ECCurvePrime curve;
	ModInt mx, my, mz;
	uint affine;
	ModInt mt1, mt2, mt3, mt4, mt5;
	ModInt ms1, ms2, ms3, ms4, ms5, ms6;

	/*
	 * Create a new instance. It is initialized to the point at
	 * infinity.
	 */
	internal MutableECPointPrime(ECCurvePrime curve)
	{
		this.curve = curve;
		mx = curve.mp.Dup();
		my = curve.mp.Dup();
		mz = curve.mp.Dup();
		mt1 = curve.mp.Dup();
		mt2 = curve.mp.Dup();
		mt3 = curve.mp.Dup();
		mt4 = curve.mp.Dup();
		mt5 = curve.mp.Dup();
		ms1 = curve.mp.Dup();
		ms2 = curve.mp.Dup();
		ms3 = curve.mp.Dup();
		ms4 = curve.mp.Dup();
		ms5 = curve.mp.Dup();
		ms6 = curve.mp.Dup();
		affine = 0xFFFFFFFF;
	}

	internal override ECCurve Curve {
		get {
			return curve;
		}
	}

	internal override uint IsInfinityCT {
		get {
			return mz.IsZeroCT;
		}
	}

	internal override void Normalize()
	{
		ToAffine();
	}

	internal override byte[] Encode(bool compressed)
	{
		ToAffine();
		if (IsInfinity) {
			return new byte[1];
		}
		if (compressed) {
			byte[] enc = new byte[curve.EncodedLengthCompressed];
			enc[0] = (byte)(0x02 + my.GetLSB());
			mx.Encode(enc, 1, enc.Length - 1);
			return enc;
		} else {
			byte[] enc = new byte[curve.EncodedLength];
			int flen = (enc.Length - 1) >> 1;
			enc[0] = 0x04;
			mx.Encode(enc, 1, flen);
			my.Encode(enc, 1 + flen, flen);
			return enc;
		}
	}

	internal override uint Encode(byte[] dst, bool compressed)
	{
		ToAffine();
		if (compressed) {
			int len = curve.EncodedLengthCompressed;
			if (dst.Length != len) {
				throw new CryptoException(
					"invalid output length");
			}
			dst[0] = (byte)(0x02 + my.GetLSB());
			mx.Encode(dst, 1, len - 1);
		} else {
			int len = curve.EncodedLength;
			if (dst.Length != len) {
				throw new CryptoException(
					"invalid output length");
			}
			int flen = (len - 1) >> 1;
			dst[0] = 0x04;
			mx.Encode(dst, 1, flen);
			my.Encode(dst, 1 + flen, flen);
		}
		return ~IsInfinityCT;
	}

	internal override uint DecodeCT(byte[] enc)
	{
		/*
		 * Format (specified in IEEE P1363, annex E):
		 *
		 *   0x00             point at infinity
		 *   0x02+b <X>       compressed, b = lsb of Y
		 *   0x04 <X> <Y>     uncompressed
		 *   0x06+b <X> <Y>   uncompressed, b = lsb of Y
		 *
		 * Coordinates X and Y are in unsigned big-endian
		 * notation with exactly the length of the modulus.
		 *
		 * We want constant-time decoding, up to the encoded
		 * length. This means that the four following situations
		 * can be differentiated:
		 * -- Point is zero (length = 1)
		 * -- Point is compressed (length = 1 + flen)
		 * -- Point is uncompressed or hybrid (length = 1 + 2*flen)
		 * -- Length is neither 1, 1+flen or 1+2*flen.
		 */

		int flen = curve.flen;
		uint good = 0xFFFFFFFF;
		if (enc.Length == 1) {
			/*
			 * 1-byte encoding is point at infinity; the
			 * byte shall have value 0.
			 */
			int z = enc[0];
			good &= ~(uint)((z | -z) >> 31);
			SetZero();
		} else if (enc.Length == 1 + flen) {
			/*
			 * Compressed encoding. Leading byte is 0x02 or
			 * 0x03.
			 */
			int z = (enc[0] & 0xFE) - 0x02;
			good &= ~(uint)((z | -z) >> 31);
			uint lsbValue = (uint)(enc[0] & 1);
			good &= mx.Decode(enc, 1, flen);
			RebuildY2();
			if (curve.pMod4 == 3) {
				good &= my.SqrtBlum();
			} else {
				/*
				 * Square roots modulo a non-Blum prime
				 * are a bit more complex. We do not
				 * support them yet (TODO).
				 */
				good = 0x00000000;
			}

			/*
			 * Adjust Y depending on LSB.
			 */
			mt1.Set(my);
			mt1.Negate();
			uint dn = (uint)-(int)(my.GetLSB() ^ lsbValue);
			my.CondCopy(mt1, dn);

			/*
			 * A corner case: LSB adjustment works only if
			 * Y != 0. If Y is 0 and requested LSB is 1,
			 * then the decoding fails. Note that this case
			 * cannot happen with usual prime curves, because
			 * they have a prime order, implying that there is
			 * no valid point such that Y = 0 (that would be
			 * a point of order 2).
			 */
			good &= ~(uint)-(int)(my.GetLSB() ^ lsbValue);

			mz.Set(1);
		} else if (enc.Length == 1 + (flen << 1)) {
			/*
			 * Uncompressed or hybrid. Leading byte is either
			 * 0x04, 0x06 or 0x07. We verify that the X and
			 * Y coordinates fulfill the curve equation.
			 */
			int fb = enc[0];
			int z = (fb & 0xFC) - 0x04;
			good &= ~(uint)((z | -z) >> 31);
			z = fb - 0x05;
			good &= (uint)((z | -z) >> 31);
			good &= mx.Decode(enc, 1, flen);
			RebuildY2();
			mt1.Set(my);
			mt1.FromMonty();
			good &= my.Decode(enc, 1 + flen, flen);
			mt2.Set(my);
			mt2.MontySquare();
			good &= mt1.EqCT(mt2);

			/*
			 * We must check the LSB for hybrid encoding.
			 * The check fails if the encoding is marked as
			 * hybrid AND the LSB does not match.
			 */
			int lm = (fb >> 1) & ((int)my.GetLSB() ^ fb) & 1;
			good &= ~(uint)-lm;

			mz.Set(1);
		} else {
			good = 0x00000000;
		}

		/*
		 * If decoding failed, then we force the value to 0.
		 * Otherwise, we got a value. Either way, this uses
		 * affine coordinates.
		 */
		mx.CondCopy(curve.mp, ~good);
		my.CondCopy(curve.mp, ~good);
		mz.CondCopy(curve.mp, ~good);
		affine = 0xFFFFFFFF;
		return good;
	}

	internal override byte[] X {
		get {
			ToAffine();
			return mx.Encode();
		}
	}

	internal override byte[] Y {
		get {
			ToAffine();
			return my.Encode();
		}
	}

	internal override MutableECPoint Dup()
	{
		MutableECPointPrime Q = new MutableECPointPrime(curve);
		Q.Set(this);
		return Q;
	}

	internal void Set(byte[] X, byte[] Y, bool check)
	{
		mx.Decode(X);
		my.Decode(Y);
		mz.Set(1);
		affine = 0xFFFFFFFF;
		if (check) {
			CheckEquation();
		}
	}

	internal void Set(ModInt X, ModInt Y, bool check)
	{
		mx.Set(X);
		my.Set(Y);
		mz.Set(1);
		affine = 0xFFFFFFFF;
		if (check) {
			CheckEquation();
		}
	}

	void CheckEquation()
	{
		curve.RebuildY2(mx, mt1, mt2);
		mt2.Set(my);
		mt2.ToMonty();
		mt2.MontyMul(my);
		if (!mt1.Eq(mt2)) {
			throw new CryptoException(
				"Point is not on the curve");
		}
	}

	internal override void SetZero()
	{
		mx.Set(0);
		my.Set(0);
		mz.Set(0);
		affine = 0xFFFFFFFF;
	}

	internal override void Set(MutableECPoint Q)
	{
		MutableECPointPrime R = SameCurve(Q);
		mx.Set(R.mx);
		my.Set(R.my);
		mz.Set(R.mz);
		affine = R.affine;
	}

	internal override void Set(MutableECPoint Q, uint ctl)
	{
		MutableECPointPrime R = SameCurve(Q);
		mx.CondCopy(R.mx, ctl);
		my.CondCopy(R.my, ctl);
		mz.CondCopy(R.mz, ctl);
		affine ^= ctl & (affine ^ R.affine);
	}

	internal override void SetMux(uint ctl,
		MutableECPoint P1, MutableECPoint P2)
	{
		SetMuxInner(ctl, SameCurve(P1), SameCurve(P2));
	}

	void SetMuxInner(uint ctl,
		MutableECPointPrime P1, MutableECPointPrime P2)
	{
		mx.CopyMux(ctl, P1.mx, P2.mx);
		my.CopyMux(ctl, P1.my, P2.my);
		mz.CopyMux(ctl, P1.mz, P2.mz);
		affine = P2.affine ^ (ctl & (P1.affine ^ P2.affine));
	}

	internal override void DoubleCT()
	{
		ToJacobian();

		/*
		 * Formulas are:
		 *   S = 4*X*Y^2
		 *   M = 3*X^2 + a*Z^4
		 *   X' = M^2 - 2*S
		 *   Y' = M*(S - X') - 8*Y^4
		 *   Z' = 2*Y*Z
		 *
		 * These formulas also happen to work properly (with our
		 * chosen representation) when the source point has
		 * order 2 (Y = 0 implies Z' = 0) and when the source
		 * point is already the point at infinity (Z = 0 implies
		 * Z' = 0).
		 *
		 * When a = -3, the value of M can be computed with the
		 * more efficient formula:
		 *   M = 3*(X+Z^2)*(X-Z^2)
		 */

		/*
		 * Compute M in t1.
		 */
		if (curve.aIsM3) {
			/*
			 * Set t1 = Z^2.
			 */
			mt1.Set(mz);
			mt1.MontySquare();

			/*
			 * Set t2 = X-Z^2 and then t1 = X+Z^2.
			 */
			mt2.Set(mx);
			mt2.Sub(mt1);
			mt1.Add(mx);

			/*
			 * Set t1 = 3*(X+Z^2)*(X-Z^2).
			 */
			mt1.MontyMul(mt2);
			mt2.Set(mt1);
			mt1.Add(mt2);
			mt1.Add(mt2);
		} else {
			/*
			 * Set t1 = 3*X^2.
			 */
			mt1.Set(mx);
			mt1.MontySquare();
			mt2.Set(mt1);
			mt1.Add(mt2);
			mt1.Add(mt2);

			/*
			 * Set t2 = a*Z^4.
			 */
			mt2.Set(mz);
			mt2.MontySquare();
			mt2.MontySquare();
			mt2.MontyMul(curve.ma);

			/*
			 * Set t1 = 3*X^2 + a*Z^4.
			 */
			mt1.Add(mt2);
		}

		/*
		 * Compute S = 4*X*Y^2 in t2. We also save 2*Y^2 in mt3.
		 */
		mt2.Set(my);
		mt2.MontySquare();
		mt2.Add(mt2);
		mt3.Set(mt2);
		mt2.Add(mt2);
		mt2.MontyMul(mx);

		/*
		 * Compute X' = M^2 - 2*S.
		 */
		mx.Set(mt1);
		mx.MontySquare();
		mx.Sub(mt2);
		mx.Sub(mt2);

		/*
		 * Compute Z' = 2*Y*Z.
		 */
		mz.MontyMul(my);
		mz.Add(mz);

		/*
		 * Compute Y' = M*(S - X') - 8*Y^4. We already have
		 * 4*Y^2 in t3.
		 */
		mt2.Sub(mx);
		mt2.MontyMul(mt1);
		mt3.MontySquare();
		mt3.Add(mt3);
		my.Set(mt2);
		my.Sub(mt3);
	}

	internal override uint AddCT(MutableECPoint Q)
	{
		MutableECPointPrime P2 = SameCurve(Q);

		if (P2.affine != 0) {
			ms4.Set(P2.mx);
			ms5.Set(P2.my);
			ms6.Set(P2.mz);
			ms4.ToMonty();
			ms5.ToMonty();
			ms6.SetMonty(~ms6.IsZeroCT);
			return AddCTInner(ms4, ms5, ms6, true);
		} else {
			return AddCTInner(P2.mx, P2.my, P2.mz, false);
		}
	}

	/*
	 * Inner function for addition. The Jacobian coordinates for
	 * the operand are provided in Montogomery representation. If
	 * p2affine is true, then it is guaranteed that p2z is 1
	 * (converted to Montogomery).
	 */
	uint AddCTInner(ModInt p2x, ModInt p2y, ModInt p2z, bool p2affine)
	{
		/*
		 * In this comment, the two operands are called P1 and
		 * P2. P1 is this instance; P2 is the operand. Coordinates
		 * of P1 are (X1,Y1,Z1). Coordinates of P2 are (X2,Y2,Z2).
		 *
		 * Formulas:
		 *   U1 = X1 * Z2^2
		 *   U2 = X2 * Z1^2
		 *   S1 = Y1 * Z2^3
		 *   S2 = Y2 * Z1^3
		 *   H = U2 - U1
		 *   R = S2 - S1
		 *   X3 = R^2 - H^3 - 2*U1*H^2
		 *   Y3 = R*(U1*H^2 - X3) - S1*H^3
		 *   Z3 = H*Z1*Z2
		 *
		 * If both P1 and P2 are 0, then the formulas yield 0,
		 * which is fine. If one of P1 and P2 is 0 (but not both),
		 * then we get 0 as result, which is wrong and must be
		 * fixed at the end.
		 *
		 * If U1 == U2 and S1 == S2 then this means that either
		 * P1 or P2 is 0 (or both), or P1 == P2. In the latter
		 * case, the formulas are wrong and we must report
		 * an error.
		 *
		 * If U1 == U2 and S1 != S2 then P1 + P2 = 0. We get H = 0,
		 * which implies that we obtain the point at infinity,
		 * which is fine.
		 */

		uint P1IsZero = mz.IsZeroCT;
		uint P2IsZero = p2z.IsZeroCT;

		ToJacobian();

		/*
		 * Save this value, in case the operand turns out to
		 * be the point at infinity.
		 */
		ms1.Set(mx);
		ms2.Set(my);
		ms3.Set(mz);

		/*
		 * Compute U1 = X1*Z2^2 in t1, and S1 = Y1*Z2^3 in t3.
		 */
		if (p2affine) {
			mt1.Set(mx);
			mt3.Set(my);
		} else {
			mt3.Set(p2z);
			mt3.MontySquare();
			mt1.Set(mx);
			mt1.MontyMul(mt3);
			mt3.MontyMul(p2z);
			mt3.MontyMul(my);
		}
		//PrintMR(" u1 = x1*z2^2", mt1);
		//PrintMR(" s1 = y1*z2^3", mt3);

		/*
		 * Compute U2 = X2*Z1^2 in t2, and S2 = Y2*Z1^3 in t4.
		 */
		mt4.Set(mz);
		mt4.MontySquare();
		mt2.Set(p2x);
		mt2.MontyMul(mt4);
		mt4.MontyMul(mz);
		mt4.MontyMul(p2y);
		//PrintMR(" u2 = x2*z1^2", mt2);
		//PrintMR(" s2 = y2*z1^3", mt4);

		/*
		 * Compute H = U2 - U1 in t2, and R = S2 - S1 in t4.
		 */
		mt2.Sub(mt1);
		mt4.Sub(mt3);
		//PrintMR(" h = u2-u1", mt2);
		//PrintMR(" r = s2-s1", mt4);

		/*
		 * If both H and R are 0, then we may have a problem
		 * (either P1 == P2, or P1 == 0, or P2 == 0).
		 */
		uint formProb = mt2.IsZeroCT & mt4.IsZeroCT;

		/*
		 * Compute U1*H^2 in t1 and H^3 in t5.
		 */
		mt5.Set(mt2);
		mt5.MontySquare();
		mt1.MontyMul(mt5);
		mt5.MontyMul(mt2);
		//PrintMR(" u1*h^2", mt1);
		//PrintMR(" h^3", mt5);

		/*
		 * Compute X3 = R^2 - H^3 - 2*U1*H^2.
		 */
		mx.Set(mt4);
		mx.MontySquare();
		mx.Sub(mt5);
		mx.Sub(mt1);
		mx.Sub(mt1);
		//PrintMR(" x3 = r^2-h^3-2*u1*h^2", mx);

		/*
		 * Compute Y3 = R*(U1*H^2 - X3) - S1*H^3.
		 */
		mt1.Sub(mx);
		mt1.MontyMul(mt4);
		mt5.MontyMul(mt3);
		mt1.Sub(mt5);
		my.Set(mt1);
		//PrintMR(" y3 = r*(u1*h^2-x3)-s1*h^3", my);

		/*
		 * Compute Z3 = H*Z1*Z2.
		 */
		mz.MontyMul(mt2);
		if (!p2affine) {
			mz.MontyMul(p2z);
		}
		//PrintMR(" z3 = h*z1*z2", mz);

		/*
		 * Fixup: handle the cases where P1 = 0 or P2 = 0.
		 */
		mx.CondCopy(ms1, P2IsZero);
		my.CondCopy(ms2, P2IsZero);
		mz.CondCopy(ms3, P2IsZero);
		mx.CondCopy(p2x, P1IsZero);
		my.CondCopy(p2y, P1IsZero);
		mz.CondCopy(p2z, P1IsZero);

		/*
		 * Report failure when P1 == P2, except when one of
		 * the points was zero (or both) because that case
		 * was properly handled.
		 */
		return (~formProb) | P1IsZero | P2IsZero;
	}

	internal override void NegCT()
	{
		my.Negate();
	}

	internal override uint MulSpecCT(byte[] n)
	{
		uint good = 0xFFFFFFFF;

		/*
		 * Create and populate window.
		 *
		 * If this instance is 0, then we only add 0 to 0 and
		 * double 0, for which DoubleCT() and AddCT() work
		 * properly.
		 *
		 * If this instance (P) is non-zero, then x*P for all
		 * x in the 1..16 range shall be non-zero and distinct,
		 * since the subgroup order is prime and at least 17.
		 * Thus, we never add two equal points together in the
		 * window construction.
		 *
		 * We MUST ensure that all points are in the same
		 * coordinate convention (affine or Jacobian) to ensure
		 * constant-time execution. TODO: measure to see which
		 * is best: all affine or all Jacobian. All affine implies
		 * 14 or 15 extra divisions, but saves a few hundreds of
		 * multiplications.
		 */
		MutableECPointPrime[] w = new MutableECPointPrime[16];
		w[0] = new MutableECPointPrime(curve);
		w[0].ToJacobian();
		w[1] = new MutableECPointPrime(curve);
		w[1].Set(this);
		w[1].ToJacobian();
		for (int i = 2; (i + 1) < w.Length; i += 2) {
			w[i] = new MutableECPointPrime(curve);
			w[i].Set(w[i >> 1]);
			w[i].DoubleCT();
			w[i + 1] = new MutableECPointPrime(curve);
			w[i + 1].Set(w[i]);
			good &= w[i + 1].AddCT(this);
		}

		/* obsolete
		for (int i = 0; i < w.Length; i ++) {
			w[i].ToAffine();
			w[i].Print("Win " + i);
			w[i].ToJacobian();
		}
		Console.WriteLine("good = {0}", (int)good);
		*/

		/*
		 * Set this value to 0. We also set it already to
		 * Jacobian coordinates, since it will be done that
		 * way anyway. This instance will serve as accumulator.
		 */
		mx.Set(0);
		my.Set(0);
		mz.Set(0);
		affine = 0x00000000;

		/*
		 * We process the multiplier by 4-bit nibbles, starting
		 * with the most-significant one (the high nibble of the
		 * first byte, since we use big-endian notation).
		 *
		 * For each nibble, we perform a constant-time lookup
		 * in the window, to obtain the point to add to the
		 * current value of the accumulator. Thanks to the
		 * conditions on the operands (prime subgroup order and
		 * so on), all the additions below must work.
		 */
		MutableECPointPrime t = new MutableECPointPrime(curve);
		for (int i = (n.Length << 1) - 1; i >= 0; i --) {
			int b = n[n.Length - 1 - (i >> 1)];
			int j = (b >> ((i & 1) << 2)) & 0x0F;
			for (int k = 0; k < 16; k ++) {
				t.Set(w[k], ~(uint)(((j - k) | (k - j)) >> 31));
			}
			good &= AddCT(t);
			if (i > 0) {
				DoubleCT();
				DoubleCT();
				DoubleCT();
				DoubleCT();
			}
		}

		return good;
	}

	internal override uint EqCT(MutableECPoint Q)
	{
		MutableECPointPrime R = SameCurve(Q);
		if (affine != 0) {
			if (R.affine != 0) {
				return mx.EqCT(R.mx)
					& my.EqCT(R.my)
					& mz.EqCT(R.mz);
			} else {
				return EqCTMixed(R, this);
			}
		} else if (R.affine != 0) {
			return EqCTMixed(this, R);
		}

		/*
		 * Both points are in Jacobian coordinates.
		 * If Z1 and Z2 are non-zero, then equality is
		 * achieved if and only if both following equations
		 * are true:
		 *     X1*(Z2^2) = X2*(Z1^2)
		 *     Y1*(Z2^3) = Y2*(Z1^3)
		 * If Z1 or Z2 is zero, then equality is achieved
		 * if and only if both are zero.
		 */
		mt1.Set(mz);
		mt1.MontySquare();
		mt2.Set(R.mz);
		mt2.MontySquare();
		mt3.Set(mx);
		mt3.MontyMul(mt2);
		mt4.Set(R.mx);
		mt4.MontyMul(mt1);
		uint r = mt3.EqCT(mt4);
		mt1.MontyMul(mz);
		mt2.MontyMul(R.mz);
		mt3.Set(my);
		mt3.MontyMul(mt2);
		mt4.Set(R.my);
		mt4.MontyMul(mt1);
		r &= mt3.EqCT(mt4);
		uint z1z = mz.IsZeroCT;
		uint z2z = R.mz.IsZeroCT;
		return (r & ~(z1z | z2z)) ^ (z1z & z2z);
	}

	/*
	 * Mixed comparison: P1 is in Jacobian coordinates, P2 is in
	 * affine coordinates.
	 */
	uint EqCTMixed(MutableECPointPrime P1, MutableECPointPrime P2)
	{
		/*
		 * If either P1 or P2 is infinity, then they are equal
		 * if and only if they both are infinity.
		 *
		 * If neither is infinity, then we must check the following:
		 *    X1 = X2*(Z1^2)
		 *    Y1 = Y2*(Z1^3)
		 * Beware that X1, Y1 and Z1 are in Montgomery representation,
		 * while X2 and Y2 are not.
		 */
		mt1.Set(P1.mz);
		mt1.MontySquare();
		mt2.Set(P2.mx);
		mt2.MontyMul(mt1);
		mt3.Set(P1.mx);
		mt3.FromMonty();
		uint r = mt2.EqCT(mt3);
		mt1.MontyMul(P1.mz);
		mt1.MontyMul(P2.my);
		mt2.Set(P1.my);
		mt2.FromMonty();
		r &= mt1.EqCT(mt2);
		uint z1z = P1.mz.IsZeroCT;
		uint z2z = P2.mz.IsZeroCT;
		return (r & ~(z1z | z2z)) ^ (z1z & z2z);
	}

	MutableECPointPrime SameCurve(MutableECPoint Q)
	{
		MutableECPointPrime R = Q as MutableECPointPrime;
		if (R == null || !curve.Equals(R.curve)) {
			throw new CryptoException("Mixed curves");
		}
		return R;
	}

	/*
	 * Convert to Jabobian coordinates (if not already done).
	 */
	void ToJacobian()
	{
		if (affine == 0) {
			return;
		}

		/*
		 * Since Z = 0 or 1 in affine coordinates, we can
		 * use SetMonty().
		 */
		mx.ToMonty();
		my.ToMonty();
		mz.SetMonty(~mz.IsZeroCT);
		affine = 0x00000000;
	}

	/*
	 * Convert to affine coordinates (if not already done).
	 */
	void ToAffine()
	{
		if (affine != 0) {
			return;
		}

		/*
		 * Divisions are expensive, so we want to make only one,
		 * not two. This involves some games with Montgomery
		 * representation.
		 *
		 * A number a in Montgomery representation means that
		 * the value we have is equal to aR. Montgomery
		 * multiplication of a by b yields ab/R (so, if we
		 * apply it to aR and bR, we get abR).
		 */

		/* Save Z*R in mt1. */
		mt1.Set(mz);

		/* Compute Z^3 in mz. */
		mz.MontySquare();
		mz.MontyMul(mt1);
		mz.FromMonty();

		/* Compute t2 = 1/Z^3. */
		mt2.Set(mz);
		mt2.Invert();
		uint cc = ~mt2.IsZeroCT;
		
		/* Compute y. */
		my.MontyMul(mt2);

		/* Compute t2 = 1/Z^2. */
		mt2.MontyMul(mt1);

		/* Compute x. */
		mx.MontyMul(mt2);

		/*
		 * If the point is infinity (division by Z^2 failed),
		 * then set all coordinates to 0. Otherwise, set mz
		 * to exactly 1.
		 */
		mx.CondCopy(curve.mp, ~cc);
		my.CondCopy(curve.mp, ~cc);
		mz.Set((int)cc & 1);

		affine = 0xFFFFFFFF;
	}

	/*
	 * Compute Y^2 into my, using the value in mx as X. Both values
	 * are in normal (non-Montgomery) representation.
	 */
	void RebuildY2()
	{
		my.Set(mx);
		my.ToMonty();
		mt1.Set(my);
		my.MontySquare();
		my.MontyMul(mx);
		mt1.MontyMul(curve.ma);
		my.Add(mt1);
		my.Add(curve.mb);
	}
}

}
