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
 * This interface qualifies a hash function implementation.
 */

public interface IDigest {

	/*
	 * Get the hash function symbolic name.
	 */
	string Name { get; }

	/*
	 * Get the hash function output size, in bytes.
	 */
	int DigestSize { get; }

	/*
	 * Get the hash function block size, in bytes (the block
	 * size is used in the definition of HMAC).
	 */
	int BlockSize { get; }

	/*
	 * Add one byte to the current input.
	 */
	void Update(byte b);

	/*
	 * Add some bytes to the current input.
	 */
	void Update(byte[] buf);

	/*
	 * Add some bytes to the current input ('len' bytes from buf[],
	 * starting at offset 'off').
	 */
	void Update(byte[] buf, int off, int len);

	/*
	 * Finalize the hash computation and write the output in the
	 * provided outBuf[] array (starting at offset 'off'). This
	 * instance is also automatically reset (as if by a Reset() call).
	 */
	void DoFinal(byte[] outBuf, int off);

	/*
	 * Finalize the hash computation and write the output into a
	 * newly allocated buffer, which is returned. This instance
	 * is also automatically reset (as if by a Reset() call).
	 */
	byte[] DoFinal();

	/*
	 * Finalize the current hash computation but keep it active;
	 * this thus returns the hash value computed over the input
	 * bytes injected so far, but new bytes may be added afterwards.
	 * The output is written in outBuf[] at offset 'off'.
	 */
	void DoPartial(byte[] outBuf, int off);

	/*
	 * Finalize the current hash computation but keep it active;
	 * this thus returns the hash value computed over the input
	 * bytes injected so far, but new bytes may be added afterwards.
	 * The output is written into a newly allocated array, which
	 * is returned.
	 */
	byte[] DoPartial();

	/*
	 * Encode the current running state into the provided buffer.
	 * This is defined for functions that employ an internal padding
	 * but no special finalization step (e.g. MD5, SHA-1, SHA-256);
	 * the running state is the one resulting from the last
	 * processed block.
	 *
	 * Note: for SHA-224, SHA-384 and similar functions, the current
	 * state as returned by this method will be truncated to the
	 * actual hash output length.
	 */
	void CurrentState(byte[] outBuf, int off);

	/*
	 * Reset the internal state, to start a new computation. This
	 * can be called at any time.
	 */
	void Reset();

	/*
	 * Duplicate this engine. This creates a new, independent
	 * instance that implements the same function, and starts with
	 * the current state.
	 */
	IDigest Dup();

	/*
	 * Compute the hash of a given input in one call; this does NOT
	 * change the internal state.
	 */
	byte[] Hash(byte[] buf);

	/*
	 * Compute the hash of a given input in one call; this does NOT
	 * change the internal state.
	 */
	byte[] Hash(byte[] buf, int off, int len);
}

}
