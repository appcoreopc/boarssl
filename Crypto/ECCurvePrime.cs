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
 * Implementation for elliptic curves in a prime field.
 */

internal class ECCurvePrime : ECCurve {

	public override string Name {
		get {
			return name;
		}
	}

	public override ECCurveType CurveType {
		get {
			return ECCurveType.Prime;
		}
	}

	public override int EncodedLength {
		get {
			return 1 + (flen << 1);
		}
	}

	public override int EncodedLengthCompressed {
		get {
			return 1 + flen;
		}
	}

	string name;

	/*
	 * 'mp' always contains 0 modulo p.
	 * 'ma' contains a.
	 * 'mb' contains b.
	 * pMod4 is p modulo 4.
	 */
	internal ModInt mp;
	internal ModInt ma;
	internal ModInt mb;
	internal int pMod4;

	/*
	 * a and b are in unsigned big-endian notation.
	 * aIsM3 is true when a == -3 modulo p.
	 */
	internal byte[] a;
	internal byte[] b;
	internal bool aIsM3;

	internal byte[] mod;
	internal int flen;
	byte[] gx;
	byte[] gy;
	int hashCode;

	/*
	 * Checks enforced by the constructor:
	 * -- modulus is odd and at least 80-bit long
	 * -- subgroup order is odd and at least 30-bit long
	 * -- parameters a[] and b[] are lower than modulus
	 * -- coordinates gx and gy are lower than modulus
	 * -- coordinates gx and gy match curve equation
	 */
	internal ECCurvePrime(string name, byte[] mod, byte[] a, byte[] b,
		byte[] gx, byte[] gy, byte[] subgroupOrder, byte[] cofactor)
		: base(subgroupOrder, cofactor)
	{
		this.mod = mod = BigInt.NormalizeBE(mod);
		int modLen = BigInt.BitLength(mod);
		if (modLen < 80) {
			throw new CryptoException(
				"Invalid curve: modulus is too small");
		}
		if ((mod[mod.Length - 1] & 0x01) == 0) {
			throw new CryptoException(
				"Invalid curve: modulus is even");
		}
		int sgLen = BigInt.BitLength(subgroupOrder);
		if (sgLen < 30) {
			throw new CryptoException(
				"Invalid curve: subgroup is too small");
		}
		if ((subgroupOrder[subgroupOrder.Length - 1] & 0x01) == 0) {
			throw new CryptoException(
				"Invalid curve: subgroup order is even");
		}

		mp = new ModInt(mod);
		flen = (modLen + 7) >> 3;
		pMod4 = mod[mod.Length - 1] & 3;

		this.a = a = BigInt.NormalizeBE(a);
		this.b = b = BigInt.NormalizeBE(b);
		if (BigInt.CompareCT(a, mod) >= 0
			|| BigInt.CompareCT(b, mod) >= 0)
		{
			throw new CryptoException(
				"Invalid curve: out-of-range parameter");
		}
		ma = mp.Dup();
		ma.Decode(a);
		ma.Add(3);
		aIsM3 = ma.IsZero;
		ma.Sub(3);
		mb = mp.Dup();
		mb.Decode(b);

		this.gx = gx = BigInt.NormalizeBE(gx);
		this.gy = gy = BigInt.NormalizeBE(gy);
		if (BigInt.CompareCT(gx, mod) >= 0
			|| BigInt.CompareCT(gy, mod) >= 0)
		{
			throw new CryptoException(
				"Invalid curve: out-of-range coordinates");
		}
		MutableECPointPrime G = new MutableECPointPrime(this);
		G.Set(gx, gy, true);

		hashCode = (int)(BigInt.HashInt(mod)
			^ BigInt.HashInt(a) ^ BigInt.HashInt(b)
			^ BigInt.HashInt(gx) ^ BigInt.HashInt(gy));

		if (name == null) {
			name = string.Format("generic prime {0}/{1}",
				modLen, sgLen);
		}
		this.name = name;
	}

	/*
	 * Extra checks:
	 * -- modulus is prime
	 * -- subgroup order is prime
	 * -- generator indeed generates subgroup
	 */
	public override void CheckValid()
	{
		/*
		 * Check that the modulus is prime.
		 */
		if (!BigInt.IsPrime(mod)) {
			throw new CryptoException(
				"Invalid curve: modulus is not prime");
		}

		/*
		 * Check that the subgroup order is prime.
		 */
		if (!BigInt.IsPrime(SubgroupOrder)) {
			throw new CryptoException(
				"Invalid curve: subgroup order is not prime");
		}

		/*
		 * Check that the G point is indeed a generator of the
		 * subgroup. Note that since it has explicit coordinates,
		 * it cannot be the point at infinity; it suffices to
		 * verify that, when multiplied by the subgroup order,
		 * it yields infinity.
		 */
		MutableECPointPrime G = new MutableECPointPrime(this);
		G.Set(gx, gy, false);
		if (G.MulSpecCT(SubgroupOrder) == 0 || !G.IsInfinity) {
			throw new CryptoException(
				"Invalid curve: generator does not match"
				+ " subgroup order");
		}

		/*
		 * TODO: check cofactor.
		 *
		 * If the cofactor is small, then we can simply compute
		 * the complete curve order by multiplying the cofactor
		 * with the subgroup order, and see whether it is in the
		 * proper range with regards to the field cardinal (by
		 * using Hasse's theorem). However, if the cofactor is
		 * larger than the subgroup order, then detecting a
		 * wrong cofactor value is a bit more complex. We could
		 * generate a few random points and multiply them by
		 * the computed order, but this may be expensive.
		 */
	}

	public override int GetXoff(out int len)
	{
		len = flen;
		return 1;
	}

	/* obsolete
	public override uint Mul(byte[] G, byte[] x, byte[] D, bool compressed)
	{
		MutableECPointPrime P = new MutableECPointPrime(this);
		uint good = P.DecodeCT(G);
		good &= ~P.IsInfinityCT;
		good &= P.MulSpecCT(x);
		good &= P.Encode(D, compressed);
		return good;
	}

	public override uint MulAdd(byte[] A, byte[] x, byte[] B, byte[] y,
		byte[] D, bool compressed)
	{
		MutableECPointPrime P = new MutableECPointPrime(this);
		MutableECPointPrime Q = new MutableECPointPrime(this);

		uint good = P.DecodeCT(A);
		good &= Q.DecodeCT(B);
		good &= ~P.IsInfinityCT & ~Q.IsInfinityCT;

		good &= P.MulSpecCT(x);
		good &= Q.MulSpecCT(y);
		good &= ~P.IsInfinityCT & ~Q.IsInfinityCT;

		uint z = P.AddCT(Q);
		Q.DoubleCT();
		P.Set(Q, ~z);

		good &= P.Encode(D, compressed);
		return good;
	}
	*/

	public override byte[] MakeRandomSecret()
	{
		/*
		 * We force the top bits to 0 to guarantee that the value
		 * is less than the subgroup order; and we force the
		 * least significant bit to 0 so that the value is not null.
		 * This is good enough for ECDH.
		 */
		byte[] q = SubgroupOrder;
		byte[] x = new byte[q.Length];
		int mask = 0xFF;
		while (mask >= q[0]) {
			mask >>= 1;
		}
		RNG.GetBytes(x);
		x[0] &= (byte)mask;
		x[x.Length - 1] |= (byte)0x01;
		return x;
	}

	internal override MutableECPoint MakeZero()
	{
		return new MutableECPointPrime(this);
	}

	internal override MutableECPoint MakeGenerator()
	{
		/*
		 * We do not have to check the generator, since
		 * it was already done in the constructor.
		 */
		MutableECPointPrime G = new MutableECPointPrime(this);
		G.Set(gx, gy, false);
		return G;
	}

	internal override MutableECPoint Decode(byte[] enc)
	{
		MutableECPointPrime P = new MutableECPointPrime(this);
		P.Decode(enc);
		return P;
	}
	
	public override bool Equals(object obj)
	{
		return Equals(obj as ECCurvePrime);
	}
	
	internal bool Equals(ECCurvePrime curve)
	{
		if (this == curve) {
			return true;
		}
		return BigInt.Compare(mod, curve.mod) == 0
			&& BigInt.Compare(a, curve.a) == 0
			&& BigInt.Compare(b, curve.b) == 0
			&& BigInt.Compare(gx, curve.gx) == 0
			&& BigInt.Compare(gy, curve.gy) == 0;
	}

	public override int GetHashCode()
	{
		return hashCode;
	}

	/*
	 * Given a value X in sx, this method computes X^3+aX+b into sd.
	 * 'sx' is unmodified. 'st' is modified (it receives a*X).
	 * The sx, sd and st instances MUST be distinct.
	 */
	internal void RebuildY2(ModInt sx, ModInt sd, ModInt st)
	{
		sd.Set(sx);
		sd.ToMonty();
		st.Set(sd);
		sd.MontySquare();
		sd.MontyMul(sx);
		st.MontyMul(ma);
		sd.Add(st);
		sd.Add(mb);
	}
}

}
