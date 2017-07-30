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
 * This class represents an elliptic curve.
 */

public abstract class ECCurve {

	/*
	 * Get the subgroup order for this curve (big-endian unsigned
	 * notation). The subgroup order is supposed to be a prime
	 * integer.
	 */
	public byte[] SubgroupOrder {
		get {
			return subgroupOrder;
		}
	}

	/*
	 * Get the cofactor fors this curve (big-endian unsigned notation).
	 * The cofactor is the quotient of the curve order by the subgroup
	 * order.
	 */
	public byte[] Cofactor {
		get {
			return cofactor;
		}
	}

	/*
	 * Get the curve symbolic name.
	 */
	public abstract string Name {
		get;
	}

	/*
	 * Get the curve type.
	 */
	public abstract ECCurveType CurveType {
		get;
	}

	/*
	 * Get the length (in bytes) of an encoded point. The "point at
	 * infinity" may use a shorter encoding than other points. This
	 * uses the "normal" encoding (not compressed).
	 */
	public abstract int EncodedLength {
		get;
	}

	/*
	 * Get the length (in bytes) of an encoded compressed point.
	 * The "point at infinity" may use a shorter encoding than
	 * other points.
	 */
	public abstract int EncodedLengthCompressed {
		get;
	}

	/*
	 * Perform extensive curve validity checks. These tests may be
	 * computationally expensive.
	 */
	public abstract void CheckValid();

	/*
	 * Get the encoded generator for this curve. This is
	 * a conventional point that generates the subgroup of prime
	 * order on which computations are normally done.
	 */
	public virtual byte[] GetGenerator(bool compressed)
	{
		return MakeGenerator().Encode(compressed);
	}

	/*
	 * Get the offset and length of the X coordinate of a point,
	 * within its encoded representation. When doing a Diffie-Hellman
	 * key exchange, the resulting shared secret is the X coordinate
	 * of the resulting point.
	 */
	public abstract int GetXoff(out int len);

	/*
	 * Multiply the provided (encoded) point G by a scalar x. Scalar
	 * encoding is big-endian. The scalar value shall be non-zero and
	 * lower than the subgroup order (exception: some curves allow
	 * larger ranges).
	 *
	 * The result is written in the provided D[] array, using either
	 * compressed or uncompressed format (for some curves, output is
	 * always compressed). The array shall have the appropriate length.
	 * Returned value is -1 on success, 0 on error. If 0 is returned
	 * then the array contents are indeterminate.
	 *
	 * G and D need not be distinct arrays.
	 */
	public uint Mul(byte[] G, byte[] x, byte[] D, bool compressed)
	{
		MutableECPoint P = MakeZero();
		uint good = P.DecodeCT(G);
		good &= ~P.IsInfinityCT;
		good &= P.MulSpecCT(x);
		good &= P.Encode(D, compressed);
		return good;
	}

	/*
	 * Given points A and B, and scalar x and y, return x*A+y*B. This
	 * is used for ECDSA. Scalars use big-endian encoding and must be
	 * non-zero and lower than the subgroup order.
	 *
	 * The result is written in the provided D[] array, using either
	 * compressed or uncompressed format (for some curves, output is
	 * always compressed). The array shall have the appropriate length.
	 * Returned value is -1 on success, 0 on error. If 0 is returned
	 * then the array contents are indeterminate.
	 *
	 * Not all curves support this operation; if the curve does not,
	 * then an exception is thrown.
	 *
	 * A, B and D need not be distinct arrays.
	 */
	public uint MulAdd(byte[] A, byte[] x, byte[] B, byte[] y,
		byte[] D, bool compressed)
	{
		MutableECPoint P = MakeZero();
		MutableECPoint Q = MakeZero();

		/*
		 * Decode both points.
		 */
		uint good = P.DecodeCT(A);
		good &= Q.DecodeCT(B);
		good &= ~P.IsInfinityCT & ~Q.IsInfinityCT;

		/*
		 * Perform both point multiplications.
		 */
		good &= P.MulSpecCT(x);
		good &= Q.MulSpecCT(y);
		good &= ~P.IsInfinityCT & ~Q.IsInfinityCT;

		/*
		 * Perform addition. The AddCT() function may fail if
		 * P = Q, in which case we must compute 2Q and use that
		 * value instead.
		 */
		uint z = P.AddCT(Q);
		Q.DoubleCT();
		P.Set(Q, ~z);

		/*
		 * Encode the result. The Encode() function will report
		 * an error if the addition result is infinity.
		 */
		good &= P.Encode(D, compressed);
		return good;
	}

	/*
	 * Generate a new random secret value appropriate for an ECDH
	 * key exchange (WARNING: this might not be sufficiently uniform
	 * for the generation of the per-signature secret value 'k' for
	 * ECDSA).
	 *
	 * The value is returned in unsigned big-endian order, in an array
	 * of the same size of the subgroup order.
	 */
	public abstract byte[] MakeRandomSecret();

	/* ============================================================= */

	byte[] subgroupOrder;
	byte[] cofactor;

	internal ECCurve(byte[] subgroupOrder, byte[] cofactor)
	{
		this.subgroupOrder = subgroupOrder;
		this.cofactor = cofactor;
	}

	/*
	 * Create a new mutable point instance, initialized to the point
	 * at infinity.
	 *
	 * (On some curves whose implementations do not support generic
	 * point addition, this method may return a non-infinity point
	 * which serves as placeholder to obtain MutableECPoint instances.)
	 */
	internal abstract MutableECPoint MakeZero();

	/*
	 * Create a new mutable point instance, initialized to the
	 * defined subgroup generator.
	 */
	internal abstract MutableECPoint MakeGenerator();

	/*
	 * Create a new mutable point instance by decoding the provided
	 * value.
	 */
	internal abstract MutableECPoint Decode(byte[] enc);
}

}
