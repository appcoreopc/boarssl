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

using Asn1;

/*
 * A wrapper class for an AlgorithmIdentifier (SEQUENCE of an OID
 * then optional parameters).
 */

class AlgorithmIdentifier {

	/*
	 * Get the OID that identifies the algorithm.
	 */
	internal string OID {
		get {
			return oid;
		}
	}

	/*
	 * Get the algorithm parameters. This may be null if the
	 * structure did not contain parameters.
	 */
	internal AsnElt Parameters {
		get {
			return parameters;
		}
	}

	string oid;
	AsnElt parameters;

	/*
	 * Create an instance over the provided ASN.1 element. The
	 * outer tag will be checked to match the universal tag for
	 * SEQUENCE.
	 */
	internal AlgorithmIdentifier(AsnElt ai) : this(ai, true)
	{
	}

	/*
	 * Create an instance over the provided ASN.1 element. If
	 * 'checkTag' is true, then the outer tag will be checked to
	 * match the universal tag for SEQUENCE. Set 'checkTag' to
	 * false if the tag was already checked, or if it has been
	 * overwritten with an implicit tag.
	 */
	internal AlgorithmIdentifier(AsnElt ai, bool checkTag)
	{
		if (checkTag) {
			ai.CheckTag(AsnElt.SEQUENCE);
		}
		ai.CheckNumSubMin(1);
		ai.CheckNumSubMax(2);
		AsnElt ao = ai.GetSub(0);
		ao.CheckTag(AsnElt.OBJECT_IDENTIFIER);
		oid = ao.GetOID();
		if (ai.Sub.Length >= 2) {
			parameters = ai.GetSub(1);
		} else {
			parameters = null;
		}
	}

	/*
	 * Create a new instance for a given OID, with no parameters.
	 */
	internal AlgorithmIdentifier(string oid) : this(oid, null)
	{
	}

	/*
	 * Create a new instance for a given OID, with the provided
	 * parameters (which may be null).
	 */
	internal AlgorithmIdentifier(string oid, AsnElt parameters)
	{
		this.oid = oid;
		this.parameters = parameters;
	}

	/*
	 * Encode this instance as a new ASN.1 object.
	 */
	internal AsnElt ToAsn1()
	{
		AsnElt ao = AsnElt.MakeOID(oid);
		if (parameters == null) {
			return AsnElt.Make(AsnElt.SEQUENCE, ao);
		} else {
			return AsnElt.Make(AsnElt.SEQUENCE, ao, parameters);
		}
	}
}
