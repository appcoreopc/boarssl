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

internal class InputRecord {

	Stream sub;
	byte[] buffer;
	int recordPtr, recordEnd;
	int recordType;
	int recordVersion;
	int expectedVersion;
	RecordDecrypt rdec;

	/*
	 * Get the length (in bytes) of the data that remains to be
	 * read from the received buffer.
	 */
	internal int BufferedLength {
		get {
			return recordEnd - recordPtr;
		}
	}

	/*
	 * Get the current record type (-1 if no record was read yet).
	 */
	internal int RecordType {
		get {
			return recordType;
		}
	}

	/*
	 * Get the current record version (-1 if no record was read yet).
	 */
	internal int RecordVersion {
		get {
			return recordVersion;
		}
	}

	internal InputRecord(Stream sub)
	{
		this.sub = sub;
		buffer = new byte[16384 + 500];
		recordPtr = 0;
		recordEnd = 0;
		recordType = -1;
		recordVersion = -1;
		expectedVersion = -1;
		rdec = new RecordDecryptPlain();
	}

	/*
	 * Set the expected version. If this value is nonnegative, then
	 * all subsequent records are expected to match this version; a
	 * version mismatch will trigger an exception.
	 *
	 * If not initially set explicitly, then this value is automatically
	 * set to the version of the first incoming record.
	 */
	internal void SetExpectedVersion(int expectedVersion)
	{
		this.expectedVersion = expectedVersion;
	}

	/*
	 * Set the new decryption engine. This is possible only if the
	 * end of the current record was reached.
	 */
	internal void SetDecryption(RecordDecrypt rdec)
	{
		if (recordPtr != recordEnd) {
			throw new SSLException(
				"Cannot switch encryption: buffered data");
		}
		this.rdec = rdec;
	}

	/*
	 * Get next record. Returned value is false if EOF was reached
	 * before obtaining the first record header byte.
	 */
	internal bool NextRecord()
	{
		if (!IO.ReadAll(sub, buffer, 0, 5, true)) {
			return false;
		}
		recordType = buffer[0];
		recordVersion = IO.Dec16be(buffer, 1);
		int len = IO.Dec16be(buffer, 3);
		if (expectedVersion >= 0 && expectedVersion != recordVersion) {
			throw new SSLException(string.Format(
				"Wrong record version: 0x{0:X4}"
				+ " (expected: 0x{1:X4})",
				recordVersion, expectedVersion));
		} else {
			if ((recordVersion >> 8) != 0x03) {
				throw new SSLException(string.Format(
					"Unsupported record version: 0x{0:X4}",
					recordVersion));
			}
			if (expectedVersion < 0) {
				expectedVersion = recordVersion;
			}
		}
		if (!rdec.CheckLength(len)) {
			throw new SSLException("Wrong record length: " + len);
		}
		IO.ReadAll(sub, buffer, 0, len, false);
		int off = 0;
		if (!rdec.Decrypt(recordType, recordVersion,
			buffer, ref off, ref len))
		{
			throw new SSLException("Decryption failure");
		}
		recordPtr = off;
		recordEnd = off + len;
		return true;
	}

	/*
	 * Read the next byte from the current record. -1 is returned if
	 * the current record is finished.
	 */
	internal int Read()
	{
		if (recordPtr == recordEnd) {
			return -1;
		} else {
			return buffer[recordPtr ++];
		}
	}

	/*
	 * Read some bytes from the current record. The number of
	 * obtained bytes is returned; a short count (including 0)
	 * is possible only if the end of the current record was
	 * reached.
	 */
	internal int Read(byte[] buf)
	{
		return Read(buf, 0, buf.Length);
	}

	/*
	 * Read some bytes from the current record. The number of
	 * obtained bytes is returned; a short count (including 0)
	 * is possible only if the end of the current record was
	 * reached.
	 */
	internal int Read(byte[] buf, int off, int len)
	{
		int clen = Math.Min(len, recordEnd - recordPtr);
		Array.Copy(buffer, recordPtr, buf, off, clen);
		recordPtr += clen;
		return clen;
	}
}

}
