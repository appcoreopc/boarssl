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
using System.IO;

namespace IO {

/*
 * This class merges two underlying streams (one for reading, the other
 * for writing) into a single Stream object. It can also optionally dump
 * all read and written bytes, in hexadecimal, on an provided text
 * stream (for debugging purposes).
 */

public class MergeStream : Stream {

	Stream subIn, subOut;

	/*
	 * Text stream on which to write an hexadecimal dump of the data
	 * which is read from or written to this stream. If null (the
	 * default), then no dump is written.
	 */
	public TextWriter Debug {
		get; set;
	}

	/*
	 * Create this stream over the two underlying substreams:
	 * 'subIn', from which data is read, and 'subOut', to which data
	 * is written. The two substreams may be the same object.
	 */
	public MergeStream(Stream subIn, Stream subOut)
	{
		this.subIn = subIn;
		this.subOut = subOut;
	}

	public override int ReadByte()
	{
		int x = subIn.ReadByte();
		if (Debug != null) {
			if (x >= 0) {
				Debug.WriteLine("recv:");
				Debug.WriteLine("   {0:x2}", x);
			} else {
				Debug.WriteLine("recv: EOF");
			}
		}
		return x;
	}

	public override int Read(byte[] buf, int off, int len)
	{
		int rlen = subIn.Read(buf, off, len);
		if (Debug != null) {
			if (rlen <= 0) {
				Debug.WriteLine("recv: EOF");
			} else {
				Debug.Write("recv:");
				for (int i = 0; i < rlen; i ++) {
					if ((i & 15) == 0) {
						Debug.WriteLine();
						Debug.Write("   ");
					} else if ((i & 7) == 0) {
						Debug.Write("  ");
					} else {
						Debug.Write(" ");
					}
					Debug.Write("{0:x2}", buf[i]);
				}
				Debug.WriteLine();
			}
		}
		return rlen;
	}

	public override void WriteByte(byte x)
	{
		if (Debug != null) {
			Debug.WriteLine("send:");
			Debug.WriteLine("   {0:x2}", x);
		}
		subOut.WriteByte(x);
	}

	public override void Write(byte[] buf, int off, int len)
	{
		if (Debug != null) {
			Debug.Write("send:");
			for (int i = 0; i < len; i ++) {
				if ((i & 15) == 0) {
					Debug.WriteLine();
					Debug.Write("   ");
				} else if ((i & 7) == 0) {
					Debug.Write("  ");
				} else {
					Debug.Write(" ");
				}
				Debug.Write("{0:x2}", buf[i]);
			}
			Debug.WriteLine();
		}
		subOut.Write(buf, off, len);
	}

	public override void Flush()
	{
		subOut.Flush();
	}

	public override void Close()
	{
		Exception ex1 = null, ex2 = null;
		try {
			subIn.Close();
		} catch (Exception ex) {
			ex1 = ex;
		}
		try {
			subOut.Close();
		} catch (Exception ex) {
			ex2 = ex;
		}
		if (ex2 != null) {
			throw ex2;
		} else if (ex1 != null) {
			throw ex1;
		}
	}

	public override long Seek(long off, SeekOrigin origin)
	{
		throw new NotSupportedException();
	}

	public override void SetLength(long len)
	{
		throw new NotSupportedException();
	}

	public override bool CanRead {
		get {
			return subIn.CanRead;
		}
	}

	public override bool CanWrite {
		get {
			return subOut.CanWrite;
		}
	}

	public override bool CanSeek {
		get {
			return false;
		}
	}

	public override long Length {
		get {
			throw new NotSupportedException();
		}
	}

	public override long Position {
		get {
			throw new NotSupportedException();
		}
		set {
			throw new NotSupportedException();
		}
	}
}

}
