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
 * Interface for a block cipher implementation. Each instance has a
 * state, which contains (at least) the current secret key, but may also
 * have other internal values. Thereby, instances are not thread-safe.
 * The Dup() method may be used to "clone" an instance into a new,
 * independent instance that starts its life configured with the same
 * secret key.
 */

public interface IBlockCipher {

	/*
	 * Get the block size in bytes.
	 */
	int BlockSize { get; }

	/*
	 * Set the key.
	 */
	void SetKey(byte[] key);

	/*
	 * Set the key.
	 */
	void SetKey(byte[] key, int off, int len);

	/*
	 * Encrypt one block.
	 */
	void BlockEncrypt(byte[] buf);

	/*
	 * Encrypt one block.
	 */
	void BlockEncrypt(byte[] buf, int off);

	/*
	 * Decrypt one block.
	 */
	void BlockDecrypt(byte[] buf);

	/*
	 * Encrypt one block.
	 */
	void BlockDecrypt(byte[] buf, int off);

	/*
	 * Do CBC encryption. There is no padding; the source array
	 * must already have a length multiple of the block size.
	 * The provided iv[] array must have the same length as a
	 * block. The data is encrypted in-place. The iv[] array is
	 * unmodified.
	 */
	void CBCEncrypt(byte[] iv, byte[] data);

	/*
	 * Do CBC encryption. There is no padding; the source array
	 * must already have a length multiple of the block size.
	 * The provided iv[] array must have the same length as a
	 * block. The data is encrypted in-place. The iv[] array is
	 * unmodified.
	 */
	void CBCEncrypt(byte[] iv, byte[] data, int off, int len);

	/*
	 * Do CBC decryption. The source array must have a length
	 * multiple of the block size; no attempt at padding removal is
	 * performed. The provided iv[] array must have the same length
	 * as a block. The data is decrypted in-place. The iv[] array is
	 * unmodified.
	 */
	void CBCDecrypt(byte[] iv, byte[] data);

	/*
	 * Do CBC decryption. The source array must have a length
	 * multiple of the block size; no attempt at padding removal is
	 * performed. The provided iv[] array must have the same length
	 * as a block. The data is decrypted in-place. The iv[] array is
	 * unmodified.
	 */
	void CBCDecrypt(byte[] iv, byte[] data, int off, int len);

	/*
	 * Do CTR encryption or decryption. This implements the variant
	 * used in GCM:
	 *  - IV length is 4 bytes less than the block length
	 *  - The block counter is used for the last 4 bytes of the
	 *    block input; big-endian encoding is used.
	 *  - Counter arithmetic is done modulo 2^32.
	 *
	 * The starting counter value is provided as parameter; the new
	 * counter value is returned. This allows computing a long CTR
	 * run in several chunks, as long as all chunks (except possibly
	 * the last one) have a length which is multiple of the block size.
	 */
	uint CTRRun(byte[] iv, uint cc, byte[] data);

	/*
	 * Do CTR encryption or decryption. This implements the variant
	 * used in GCM:
	 *  - IV length is 4 bytes less than the block length
	 *  - The block counter is used for the last 4 bytes of the
	 *    block input; big-endian encoding is used.
	 *  - Counter arithmetic is done modulo 2^32.
	 *
	 * The starting counter value is provided as parameter; the new
	 * counter value is returned. This allows computing a long CTR
	 * run in several chunks, as long as all chunks (except possibly
	 * the last one) have a length which is multiple of the block size.
	 */
	uint CTRRun(byte[] iv, uint cc, byte[] data, int off, int len);

	/*
	 * Duplicate this engine. This creates a new, independent
	 * instance that implements the same function, and starts with
	 * the same currently set key.
	 */
	IBlockCipher Dup();
}

}
