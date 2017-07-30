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
 * This class is a convenient base class for implementations of IDigest.
 * Hash function implementations must implement:
 *    int DigestSize { get; }
 *    int BlockSize { get; }
 *    int PaddingOverhead { get; }
 *    void Update(byte b)
 *    void Update(byte[] buf, int off, int len)
 *    void DoPartial(byte[] outBuf, int off)
 *    void Reset()
 *    IDigest Dup()
 *
 * Implementations SHOULD provide overrides for:
 *    void CurrentState(byte[], int)
 *
 * In this class:
 *    Update(byte[]) calls Update(byte[],int,int)
 *    DoPartial() calls DoPartial(byte[],int)
 *    DoFinal() calls DoPartial() and Reset()
 *    DoFinal(byte[],int) calls DoPartial(byte[],int) and Reset()
 */

public abstract class DigestCore : IDigest {

	/* see IDigest */
	public abstract string Name { get; }

	/* see IDigest */
	public abstract int DigestSize { get; }

	/* see IDigest */
	public abstract int BlockSize { get; }

	/* see IDigest */
	public abstract void Update(byte b);

	/* see IDigest */
	public virtual void Update(byte[] buf)
	{
		Update(buf, 0, buf.Length);
	}

	/* see IDigest */
	public abstract void Update(byte[] buf, int off, int len);

	/* see IDigest */
	public abstract void DoPartial(byte[] outBuf, int off);

	/* see IDigest */
	public virtual byte[] DoPartial()
	{
		byte[] buf = new byte[DigestSize];
		DoPartial(buf, 0);
		return buf;
	}

	/* see IDigest */
	public virtual void DoFinal(byte[] outBuf, int off)
	{
		DoPartial(outBuf, off);
		Reset();
	}

	/* see IDigest */
	public virtual byte[] DoFinal()
	{
		byte[] r = DoPartial();
		Reset();
		return r;
	}

	/* see IDigest */
	public abstract void Reset();

	/* see IDigest */
	public abstract IDigest Dup();

	/*
	 * Default implementation throws a NotSupportedException.
	 */
	public virtual void CurrentState(byte[] outBuf, int off)
	{
		throw new NotSupportedException();
	}

	/* see IDigest */
	public virtual byte[] Hash(byte[] buf)
	{
		return Hash(buf, 0, buf.Length);
	}

	/* see IDigest */
	public virtual byte[] Hash(byte[] buf, int off, int len)
	{
		IDigest h = Dup();
		h.Reset();
		h.Update(buf, off, len);
		return h.DoFinal();
	}
}

}
