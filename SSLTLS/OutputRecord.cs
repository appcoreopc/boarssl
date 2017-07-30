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

namespace SSLTLS {

internal class OutputRecord {

	/*
	 * Splitting modes are for debugging and tests. Note that the
	 * automatic 1/n-1 split for CBC cipher suites in TLS 1.0 is
	 * handled independently in RecordEncryptCBC.
	 */

	/* No split. */
	internal const int MODE_NORMAL = 0;

	/* Each record is split into two, of approximately the same size. */
	internal const int MODE_SPLIT_HALF = 1;

	/* Each record is preceded with an extra record of size 0. */
	internal const int MODE_SPLIT_ZERO_BEFORE = 2;

	/* Each record is split into two records (like SPLIT_HALF), and
	   an extra zero-length record is added between the two halves. */
	internal const int MODE_SPLIT_ZERO_HALF = 3;

	/* The first byte of each record is separated into its own record. */
	internal const int MODE_SPLIT_ONE_START = 4;

	/* The last byte of each record is separated into its own record. */
	internal const int MODE_SPLIT_ONE_END = 5;

	/* The record is split into records of length 1 byte each. */
	internal const int MODE_SPLIT_MULTI_ONE = 6;

	/*
	 * Spliting modes are only applied on the specified record types
	 * (these are bit flags that can be combined).
	 */
	internal const int MODE_MT_CCS = 1 << SSL.CHANGE_CIPHER_SPEC;
	internal const int MODE_MT_ALERT = 1 << SSL.ALERT;
	internal const int MODE_MT_HANDSHAKE = 1 << SSL.HANDSHAKE;
	internal const int MODE_MT_APPLICATION_DATA = 1 << SSL.APPLICATION_DATA;

	const int MODE_MASK = 0xFFFF;

	Stream sub;
	byte[] buffer;
	int ptr, basePtr, maxPtr;
	int version;
	int recordType;
	RecordEncrypt renc;

	int splitMode;
	byte[] extra;

	long countHandshake;
	long countAppData;
	long thresholdZeroHandshake;
	long thresholdZeroAppData;
	byte[] extra2;

	internal OutputRecord(Stream sub)
	{
		this.sub = sub;
		buffer = new byte[16384 + 500];
		version = 0;
		recordType = -1;
		splitMode = MODE_NORMAL;
		extra = null;
		countHandshake = 0;
		countAppData = 0;
		thresholdZeroHandshake = 0;
		thresholdZeroAppData = 0;
		extra2 = new byte[500];
		renc = new RecordEncryptPlain();
		PrepNew();
	}

	/*
	 * If set, then all I/O errors while writing on the underlying
	 * stream will be converted to a generic SSLException with message
	 * "Unexpected transport closure". This helps test code that
	 * expects the peer to abort asynchronously, so the error may
	 * be detected during both reading or writing.
	 */
	internal bool NormalizeIOError {
		get; set;
	}

	internal void SetVersion(int version)
	{
		if (version != this.version) {
			if (ptr != basePtr) {
				FlushInner();
			}
			this.version = version;
			PrepNew();
		}
	}

	internal int RecordType {
		get {
			return recordType;
		}
		set {
			if (value != recordType) {
				if (ptr != basePtr) {
					FlushInner();
				}
				recordType = value;
			}
		}
	}

	internal void SetEncryption(RecordEncrypt renc)
	{
		if (ptr != basePtr) {
			FlushInner();
		}
		this.renc = renc;
		PrepNew();
	}

	internal void SetSplitMode(int splitMode)
	{
		this.splitMode = splitMode;
		if ((splitMode & MODE_MASK) != MODE_NORMAL && extra == null) {
			extra = new byte[buffer.Length];
		}
	}

	internal void SetThresholdZeroAppData(long t)
	{
		thresholdZeroAppData = t;
	}

	internal void SetThresholdZeroHandshake(long t)
	{
		thresholdZeroAppData = t;
	}

	void PrepNew()
	{
		int start = 0;
		int end = buffer.Length;
		renc.GetMaxPlaintext(ref start, ref end);
		ptr = start;
		basePtr = start;
		maxPtr = end;
	}

	internal void Flush()
	{
		if (ptr == basePtr) {
			return;
		}
		FlushInner();
		sub.Flush();
	}

	internal void SendZeroLength(int type)
	{
		Flush();
		int rt = RecordType;
		RecordType = type;
		FlushInner();
		RecordType = rt;
		sub.Flush();
	}

	void FlushInner()
	{
		int off = basePtr;
		int len = ptr - basePtr;
		if (version == 0) {
			throw new Exception("Record version is not set");
		}
		int m = splitMode & MODE_MASK;
		if (m == MODE_NORMAL || (splitMode & (1 << recordType)) == 0) {
			EncryptAndWrite(off, len);
		} else {
			Array.Copy(buffer, off, extra, off, len);
			switch (m) {
			case MODE_SPLIT_HALF:
			case MODE_SPLIT_ZERO_HALF:
				int hlen = (len >> 1);
				if (hlen > 0) {
					EncryptAndWrite(off, hlen);
				}
				if (m == MODE_SPLIT_ZERO_HALF) {
					EncryptAndWrite(off, 0);
				}
				Array.Copy(extra, off + hlen,
					buffer, off, len - hlen);
				hlen = len - hlen;
				if (hlen > 0) {
					EncryptAndWrite(off, hlen);
				}
				break;
			case MODE_SPLIT_ZERO_BEFORE:
				EncryptAndWrite(off, 0);
				Array.Copy(extra, off, buffer, off, len);
				if (len > 0) {
					EncryptAndWrite(off, len);
				}
				break;
			case MODE_SPLIT_ONE_START:
				if (len > 0) {
					EncryptAndWrite(off, 1);
				}
				if (len > 1) {
					Array.Copy(extra, off + 1,
						buffer, off, len - 1);
					EncryptAndWrite(off, len - 1);
				}
				break;
			case MODE_SPLIT_ONE_END:
				if (len > 1) {
					EncryptAndWrite(off, len - 1);
				}
				if (len > 0) {
					buffer[off] = extra[off + len - 1];
					EncryptAndWrite(off, 1);
				}
				break;
			case MODE_SPLIT_MULTI_ONE:
				for (int i = 0; i < len; i ++) {
					buffer[off] = extra[off + i];
					EncryptAndWrite(off, 1);
				}
				break;
			default:
				throw new SSLException(string.Format(
					"Bad record splitting value: {0}", m));
			}
		}
		PrepNew();
	}

	void EncryptAndWrite(int off, int len)
	{
		try {
			EncryptAndWriteInner(off, len);
		} catch {
			if (NormalizeIOError) {
				throw new SSLException(
					"Unexpected transport closure");
			} else {
				throw;
			}
		}
	}

	void EncryptAndWriteInner(int off, int len)
	{
		if (recordType == SSL.HANDSHAKE) {
			countHandshake ++;
			if (countHandshake == thresholdZeroAppData) {
				int start = 0;
				int end = extra2.Length;
				renc.GetMaxPlaintext(ref start, ref end);
				int zoff = start;
				int zlen = 0;
				renc.Encrypt(SSL.APPLICATION_DATA, version,
					extra2, ref zoff, ref zlen);
				sub.Write(extra2, zoff, zlen);
			}
		} else if (recordType == SSL.APPLICATION_DATA) {
			countAppData ++;
			if (countAppData == thresholdZeroHandshake) {
				int start = 0;
				int end = extra2.Length;
				renc.GetMaxPlaintext(ref start, ref end);
				int zoff = start;
				int zlen = 0;
				renc.Encrypt(SSL.HANDSHAKE, version,
					extra2, ref zoff, ref zlen);
				sub.Write(extra2, zoff, zlen);
			}
		}

		renc.Encrypt(recordType, version, buffer, ref off, ref len);
		sub.Write(buffer, off, len);
	}

	internal void Write(byte x)
	{
		buffer[ptr ++] = x;
		if (ptr == maxPtr) {
			FlushInner();
		}
	}

	internal void Write(byte[] data)
	{
		Write(data, 0, data.Length);
	}

	internal void Write(byte[] data, int off, int len)
	{
		while (len > 0) {
			int clen = Math.Min(len, maxPtr - ptr);
			Array.Copy(data, off, buffer, ptr, clen);
			ptr += clen;
			off += clen;
			len -= clen;
			if (ptr == maxPtr) {
				FlushInner();
			}
		}
	}
}

}
