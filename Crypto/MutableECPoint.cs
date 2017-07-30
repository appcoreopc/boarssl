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
 * A MutableECPoint instance contains an elliptic curve point, in a
 * given curve. It may be modified to contain another point, but not
 * on another curve.
 *
 * Constant-time guarantees: IsInfinityCT, DoubleCT(), NegCT() and
 * AddCT() are constant-time with regards to the represented curve
 * point. Execution time may vary depending on the sequence of calls,
 * but not on the point data. In particular, points may be internally
 * "normalized" or not, and operations involving normalized points can
 * be faster; however, normalization happens only upon an explicit call.
 * The normalization process itself (Normalize()) is constant-time.
 */

internal abstract class MutableECPoint {

	internal MutableECPoint()
	{
	}

	internal abstract ECCurve Curve {
		get;
	}

	/*
	 * Test whether this point is the point at infinity.
	 */
	internal bool IsInfinity {
		get {
			return IsInfinityCT != 0;
		}
	}

	/*
	 * Test whether this point is the point at infinity (returns
	 * 0xFFFFFFFF or 0x00000000).
	 */
	internal abstract uint IsInfinityCT {
		get;
	}

	/*
	 * Normalize this instance. What this entails depends on the
	 * curve type, but it will typically means computing affine
	 * coordinates in case this instance was using some sort of
	 * projective system.
	 */
	internal abstract void Normalize();

	/*
	 * Encode this point into some bytes. If "compressed" is true,
	 * then a compressed format will be used.
	 *
	 * This call may entail normalization. If the point is not the
	 * infinity point, then this method is constant-time.
	 */
	internal abstract byte[] Encode(bool compressed);

	/*
	 * Encode this point into some bytes. If "compressed is true,
	 * then a compressed format will be used. The destination array
	 * must have the proper length for the requested point format.
	 *
	 * This call may entail normalization. If the point is invalid
	 * or is the point at infinity, then the returned value is 0
	 * and what gets written in the array is indeterminate. Otherwise,
	 * the encoded point is written and -1 is returned. Either way,
	 * this call is constant-time.
	 */
	internal abstract uint Encode(byte[] dst, bool compressed);

	/*
	 * Set this point by decoding the provided value. An invalid
	 * encoding sets this point to 0 (infinity) and triggers an
	 * exception.
	 */
	internal void Decode(byte[] enc)
	{
		if (DecodeCT(enc) == 0) {
			throw new CryptoException("Invalid encoded point");
		}
	}

	/*
	 * Set this point by decoding the provided value. This is
	 * constant-time (up to the encoded point length). Returned
	 * value is 0xFFFFFFFF if the encoded point was valid,
	 * 0x00000000 otherwise. If the decoding failed, then this
	 * value is set to 0 (infinity).
	 */
	internal abstract uint DecodeCT(byte[] enc);

	/*
	 * Get the X coordinate for this point. This implies
	 * normalization. If the point is the point at infinity,
	 * then the returned array contains the encoding of 0.
	 * This is constant-time.
	 */
	internal abstract byte[] X {
		get;
	}

	/*
	 * Get the Y coordinate for this point. This implies
	 * normalization. If the point is the point at infinity,
	 * then the returned array contains the encoding of 0.
	 * This is constant-time.
	 */
	internal abstract byte[] Y {
		get;
	}

	/*
	 * Create a new instance that starts with the same contents as
	 * this point.
	 */
	internal abstract MutableECPoint Dup();

	/*
	 * Set this instance to the point at infinity.
	 */
	internal abstract void SetZero();

	/*
	 * Set this instance to the same contents as the provided point.
	 * The operand Q must be part of the same curve.
	 */
	internal abstract void Set(MutableECPoint Q);

	/*
	 * Set this instance to the same contents as the provided point,
	 * but only if ctl == 0xFFFFFFFFF. If ctl == 0x00000000, then
	 * this instance is unmodified. The operand Q must be part of
	 * the same curve.
	 */
	internal abstract void Set(MutableECPoint Q, uint ctl);

	/*
	 * Set this instance to the same contents as point P1 if
	 * ctl == 0xFFFFFFFF, or point P2 if ctl == 0x00000000.
	 * Both operands must use the same curve as this instance.
	 */
	internal abstract void SetMux(uint ctl,
		MutableECPoint P1, MutableECPoint P2);

	/*
	 * DoubleCT() is constant-time. It works for all points
	 * (including points of order 2 and the infinity point).
	 */
	internal abstract void DoubleCT();

	/*
	 * AddCT() computes P+Q (P is this instance, Q is the operand).
	 * It may assume that P != Q. If P = Q and the method could not
	 * compute the correct result, then it shall set this instance to
	 * 0 (infinity) and return 0x00000000. In all other cases, it must
	 * compute the correct point and return 0xFFFFFFFF. In particular,
	 * it should properly handle cases where P = 0 or Q = 0. This
	 * function is allowed to handle doubling cases as well, if it
	 * can.
	 *
	 * This method may be more efficient if the operand is
	 * normalized. Execution time and memory access may depend on
	 * whether this instance or the other operand is normalized,
	 * but not on the actual point values (including if the points
	 * do not fulfill the properties above).
	 */
	internal abstract uint AddCT(MutableECPoint Q);

	/*
	 * Negate this point. It also works on the point at infinity,
	 * and it is constant-time.
	 */
	internal abstract void NegCT();

	/*
	 * Multiply this point by the provided integer (unsigned
	 * big-endian representation). This is constant-time. This
	 * method assumes that:
	 * -- the point on which we are operating is part of the curve
	 *    defined subgroup;
	 * -- the defined subgroup has a prime order which is no less
	 *    than 17;
	 * -- the point is not the point at infinity;
	 * -- the multiplier operand is no more than the subgroup order.
	 * If these conditions are met, then the resulting point will
	 * be the proper element of the defined subgroup (it will be
	 * the point at infinity only if the multiplier is 0 or is
	 * equal to the subgroup order). If they are NOT met, then the
	 * resulting point is undefined (but will still be part of the
	 * curve).
	 *
	 * This method is constant-time.
	 *
	 * Returned value is 0xFFFFFFFF if none of the internal
	 * operations reached a problematic state (i.e. that we tried to
	 * perform an addition and the two operands turned out to be
	 * equal to each other). If the conditions above are met, then
	 * this is always the case. If a problematic state was reached,
	 * then the returned value is 0x00000000. Callers MUST be very
	 * cautious about using that reported error state, since it is
	 * not guaranteed that all invalid points would be reported as
	 * such. There thus is potential for leakage of secret data.
	 */
	internal abstract uint MulSpecCT(byte[] n);

	/*
	 * Compare this point to another. This method throws an
	 * exception if the provided point is not on the same curve as
	 * this instance. It otherwise returns 0xFFFFFFFF if both points
	 * are equal, 0x00000000 otherwise. This method is constant-time
	 * (its execution time may depend on whether this and/or the
	 * other point is normalized or not, but not on the actual
	 * values).
	 */
	internal abstract uint EqCT(MutableECPoint Q);

	internal bool Eq(MutableECPoint Q)
	{
		return EqCT(Q) != 0;
	}
}

}
