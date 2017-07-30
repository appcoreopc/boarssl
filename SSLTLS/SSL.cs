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
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Asn1;
using Crypto;
using XKeys;

namespace SSLTLS {

/*
 * A fake class that serves as container for various constants.
 */

public sealed class SSL {

	/*
	 * Protocol versions.
	 */
	public const int SSL30 = 0x0300;
	public const int TLS10 = 0x0301;
	public const int TLS11 = 0x0302;
	public const int TLS12 = 0x0303;

	/*
	 * Record types.
	 */
	public const int CHANGE_CIPHER_SPEC  = 20;
	public const int ALERT               = 21;
	public const int HANDSHAKE           = 22;
	public const int APPLICATION_DATA    = 23;

	/*
	 * Alert levels.
	 */
	public const int WARNING  = 1;
	public const int FATAL    = 2;

	/*
	 * Alert messages.
	 */
	public const int CLOSE_NOTIFY             = 0;
	public const int UNEXPECTED_MESSAGE       = 10;
	public const int BAD_RECORD_MAC           = 20;
	public const int DECRYPTION_FAILED        = 21;
	public const int RECORD_OVERFLOW          = 22;
	public const int DECOMPRESSION_FAILURE    = 30;
	public const int HANDSHAKE_FAILURE        = 40;
	public const int BAD_CERTIFICATE          = 42;
	public const int UNSUPPORTED_CERTIFICATE  = 43;
	public const int CERTIFICATE_REVOKED      = 44;
	public const int CERTIFICATE_EXPIRED      = 45;
	public const int CERTIFICATE_UNKNOWN      = 46;
	public const int ILLEGAL_PARAMETER        = 47;
	public const int UNKNOWN_CA               = 48;
	public const int ACCESS_DENIED            = 49;
	public const int DECODE_ERROR             = 50;
	public const int DECRYPT_ERROR            = 51;
	public const int EXPORT_RESTRICTION       = 60;
	public const int PROTOCOL_VERSION         = 70;
	public const int INSUFFICIENT_SECURITY    = 71;
	public const int INTERNAL_ERROR           = 80;
	public const int USER_CANCELED            = 90;
	public const int NO_RENEGOTIATION         = 100;

	/*
	 * Handshake message types.
	 */
	public const int HELLO_REQUEST        = 0;
	public const int CLIENT_HELLO         = 1;
	public const int SERVER_HELLO         = 2;
	public const int CERTIFICATE          = 11;
	public const int SERVER_KEY_EXCHANGE  = 12;
	public const int CERTIFICATE_REQUEST  = 13;
	public const int SERVER_HELLO_DONE    = 14;
	public const int CERTIFICATE_VERIFY   = 15;
	public const int CLIENT_KEY_EXCHANGE  = 16;
	public const int FINISHED             = 20;

	/*
	 * Cipher suites.
	 */

	/* From RFC 5246 */
	public const int NULL_WITH_NULL_NULL                    = 0x0000;
	public const int RSA_WITH_NULL_MD5                      = 0x0001;
	public const int RSA_WITH_NULL_SHA                      = 0x0002;
	public const int RSA_WITH_NULL_SHA256                   = 0x003B;
	public const int RSA_WITH_RC4_128_MD5                   = 0x0004;
	public const int RSA_WITH_RC4_128_SHA                   = 0x0005;
	public const int RSA_WITH_3DES_EDE_CBC_SHA              = 0x000A;
	public const int RSA_WITH_AES_128_CBC_SHA               = 0x002F;
	public const int RSA_WITH_AES_256_CBC_SHA               = 0x0035;
	public const int RSA_WITH_AES_128_CBC_SHA256            = 0x003C;
	public const int RSA_WITH_AES_256_CBC_SHA256            = 0x003D;
	public const int DH_DSS_WITH_3DES_EDE_CBC_SHA           = 0x000D;
	public const int DH_RSA_WITH_3DES_EDE_CBC_SHA           = 0x0010;
	public const int DHE_DSS_WITH_3DES_EDE_CBC_SHA          = 0x0013;
	public const int DHE_RSA_WITH_3DES_EDE_CBC_SHA          = 0x0016;
	public const int DH_DSS_WITH_AES_128_CBC_SHA            = 0x0030;
	public const int DH_RSA_WITH_AES_128_CBC_SHA            = 0x0031;
	public const int DHE_DSS_WITH_AES_128_CBC_SHA           = 0x0032;
	public const int DHE_RSA_WITH_AES_128_CBC_SHA           = 0x0033;
	public const int DH_DSS_WITH_AES_256_CBC_SHA            = 0x0036;
	public const int DH_RSA_WITH_AES_256_CBC_SHA            = 0x0037;
	public const int DHE_DSS_WITH_AES_256_CBC_SHA           = 0x0038;
	public const int DHE_RSA_WITH_AES_256_CBC_SHA           = 0x0039;
	public const int DH_DSS_WITH_AES_128_CBC_SHA256         = 0x003E;
	public const int DH_RSA_WITH_AES_128_CBC_SHA256         = 0x003F;
	public const int DHE_DSS_WITH_AES_128_CBC_SHA256        = 0x0040;
	public const int DHE_RSA_WITH_AES_128_CBC_SHA256        = 0x0067;
	public const int DH_DSS_WITH_AES_256_CBC_SHA256         = 0x0068;
	public const int DH_RSA_WITH_AES_256_CBC_SHA256         = 0x0069;
	public const int DHE_DSS_WITH_AES_256_CBC_SHA256        = 0x006A;
	public const int DHE_RSA_WITH_AES_256_CBC_SHA256        = 0x006B;
	public const int DH_anon_WITH_RC4_128_MD5               = 0x0018;
	public const int DH_anon_WITH_3DES_EDE_CBC_SHA          = 0x001B;
	public const int DH_anon_WITH_AES_128_CBC_SHA           = 0x0034;
	public const int DH_anon_WITH_AES_256_CBC_SHA           = 0x003A;
	public const int DH_anon_WITH_AES_128_CBC_SHA256        = 0x006C;
	public const int DH_anon_WITH_AES_256_CBC_SHA256        = 0x006D;

	/* From RFC 4492 */
	public const int ECDH_ECDSA_WITH_NULL_SHA               = 0xC001;
	public const int ECDH_ECDSA_WITH_RC4_128_SHA            = 0xC002;
	public const int ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA       = 0xC003;
	public const int ECDH_ECDSA_WITH_AES_128_CBC_SHA        = 0xC004;
	public const int ECDH_ECDSA_WITH_AES_256_CBC_SHA        = 0xC005;
	public const int ECDHE_ECDSA_WITH_NULL_SHA              = 0xC006;
	public const int ECDHE_ECDSA_WITH_RC4_128_SHA           = 0xC007;
	public const int ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA      = 0xC008;
	public const int ECDHE_ECDSA_WITH_AES_128_CBC_SHA       = 0xC009;
	public const int ECDHE_ECDSA_WITH_AES_256_CBC_SHA       = 0xC00A;
	public const int ECDH_RSA_WITH_NULL_SHA                 = 0xC00B;
	public const int ECDH_RSA_WITH_RC4_128_SHA              = 0xC00C;
	public const int ECDH_RSA_WITH_3DES_EDE_CBC_SHA         = 0xC00D;
	public const int ECDH_RSA_WITH_AES_128_CBC_SHA          = 0xC00E;
	public const int ECDH_RSA_WITH_AES_256_CBC_SHA          = 0xC00F;
	public const int ECDHE_RSA_WITH_NULL_SHA                = 0xC010;
	public const int ECDHE_RSA_WITH_RC4_128_SHA             = 0xC011;
	public const int ECDHE_RSA_WITH_3DES_EDE_CBC_SHA        = 0xC012;
	public const int ECDHE_RSA_WITH_AES_128_CBC_SHA         = 0xC013;
	public const int ECDHE_RSA_WITH_AES_256_CBC_SHA         = 0xC014;
	public const int ECDH_anon_WITH_NULL_SHA                = 0xC015;
	public const int ECDH_anon_WITH_RC4_128_SHA             = 0xC016;
	public const int ECDH_anon_WITH_3DES_EDE_CBC_SHA        = 0xC017;
	public const int ECDH_anon_WITH_AES_128_CBC_SHA         = 0xC018;
	public const int ECDH_anon_WITH_AES_256_CBC_SHA         = 0xC019;

	/* From RFC 5288 */
	public const int RSA_WITH_AES_128_GCM_SHA256            = 0x009C;
	public const int RSA_WITH_AES_256_GCM_SHA384            = 0x009D;
	public const int DHE_RSA_WITH_AES_128_GCM_SHA256        = 0x009E;
	public const int DHE_RSA_WITH_AES_256_GCM_SHA384        = 0x009F;
	public const int DH_RSA_WITH_AES_128_GCM_SHA256         = 0x00A0;
	public const int DH_RSA_WITH_AES_256_GCM_SHA384         = 0x00A1;
	public const int DHE_DSS_WITH_AES_128_GCM_SHA256        = 0x00A2;
	public const int DHE_DSS_WITH_AES_256_GCM_SHA384        = 0x00A3;
	public const int DH_DSS_WITH_AES_128_GCM_SHA256         = 0x00A4;
	public const int DH_DSS_WITH_AES_256_GCM_SHA384         = 0x00A5;
	public const int DH_anon_WITH_AES_128_GCM_SHA256        = 0x00A6;
	public const int DH_anon_WITH_AES_256_GCM_SHA384        = 0x00A7;

	/* From RFC 5289 */
	public const int ECDHE_ECDSA_WITH_AES_128_CBC_SHA256    = 0xC023;
	public const int ECDHE_ECDSA_WITH_AES_256_CBC_SHA384    = 0xC024;
	public const int ECDH_ECDSA_WITH_AES_128_CBC_SHA256     = 0xC025;
	public const int ECDH_ECDSA_WITH_AES_256_CBC_SHA384     = 0xC026;
	public const int ECDHE_RSA_WITH_AES_128_CBC_SHA256      = 0xC027;
	public const int ECDHE_RSA_WITH_AES_256_CBC_SHA384      = 0xC028;
	public const int ECDH_RSA_WITH_AES_128_CBC_SHA256       = 0xC029;
	public const int ECDH_RSA_WITH_AES_256_CBC_SHA384       = 0xC02A;
	public const int ECDHE_ECDSA_WITH_AES_128_GCM_SHA256    = 0xC02B;
	public const int ECDHE_ECDSA_WITH_AES_256_GCM_SHA384    = 0xC02C;
	public const int ECDH_ECDSA_WITH_AES_128_GCM_SHA256     = 0xC02D;
	public const int ECDH_ECDSA_WITH_AES_256_GCM_SHA384     = 0xC02E;
	public const int ECDHE_RSA_WITH_AES_128_GCM_SHA256      = 0xC02F;
	public const int ECDHE_RSA_WITH_AES_256_GCM_SHA384      = 0xC030;
	public const int ECDH_RSA_WITH_AES_128_GCM_SHA256       = 0xC031;
	public const int ECDH_RSA_WITH_AES_256_GCM_SHA384       = 0xC032;

	/* From RFC 7905 */
	public const int ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256      = 0xCCA8;
	public const int ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256    = 0xCCA9;
	public const int DHE_RSA_WITH_CHACHA20_POLY1305_SHA256        = 0xCCAA;
	public const int PSK_WITH_CHACHA20_POLY1305_SHA256            = 0xCCAB;
	public const int ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256      = 0xCCAC;
	public const int DHE_PSK_WITH_CHACHA20_POLY1305_SHA256        = 0xCCAD;
	public const int RSA_PSK_WITH_CHACHA20_POLY1305_SHA256        = 0xCCAE;

	/* From RFC 7507 */
	public const int FALLBACK_SCSV                          = 0x5600;

	/* From RFC 5746 */
	public const int EMPTY_RENEGOTIATION_INFO_SCSV          = 0x00FF;

	/*
	 * Client certificate types.
	 */
	public const int RSA_SIGN      = 1;
	public const int DSS_SIGN      = 2;
	public const int RSA_FIXED_DH  = 3;
	public const int DSS_FIXED_DH  = 4;

	/*
	 * Hash algorithm identifiers. The special "MD5SHA1" is for use
	 * with RSA signatures in TLS 1.0 and 1.1 only.
	 */
	public const int MD5SHA1 = 0;
	public const int MD5     = 1;
	public const int SHA1    = 2;
	public const int SHA224  = 3;
	public const int SHA256  = 4;
	public const int SHA384  = 5;
	public const int SHA512  = 6;

	/*
	 * Signature algorithm identifiers.
	 */
	public const int RSA     = 1;
	public const int DSA     = 2;
	public const int ECDSA   = 3;

	/*
	 * Combined hash-and-sign algorithms.
	 */
	public const int RSA_MD5SHA1   = (MD5SHA1 << 8) + RSA;
	public const int RSA_MD5       = (MD5 << 8) + RSA;
	public const int RSA_SHA1      = (SHA1 << 8) + RSA;
	public const int RSA_SHA224    = (SHA224 << 8) + RSA;
	public const int RSA_SHA256    = (SHA256 << 8) + RSA;
	public const int RSA_SHA384    = (SHA384 << 8) + RSA;
	public const int RSA_SHA512    = (SHA512 << 8) + RSA;
	public const int ECDSA_MD5     = (MD5 << 8) + ECDSA;
	public const int ECDSA_SHA1    = (SHA1 << 8) + ECDSA;
	public const int ECDSA_SHA224  = (SHA224 << 8) + ECDSA;
	public const int ECDSA_SHA256  = (SHA256 << 8) + ECDSA;
	public const int ECDSA_SHA384  = (SHA384 << 8) + ECDSA;
	public const int ECDSA_SHA512  = (SHA512 << 8) + ECDSA;

	/*
	 * Symbolic identifiers for named curves.
	 */
	public const int NIST_P256   = 23;
	public const int NIST_P384   = 24;
	public const int NIST_P521   = 25;
	public const int Curve25519  = 29;

	/*
	 * Get a human-readable name for a version.
	 */
	public static string VersionName(int version)
	{
		switch (version) {
		case SSL30: return "SSL 3.0";
		case TLS10: return "TLS 1.0";
		case TLS11: return "TLS 1.1";
		case TLS12: return "TLS 1.2";
		}
		if ((version >> 8) == 3) {
			return String.Format("TLS 1.{0}", (version & 0xFF) - 1);
		}
		return String.Format("UNKNOWN:0x{0:X4}", version);
	}

	/*
	 * Get a human-readable name for a cipher suite.
	 */
	public static string CipherSuiteName(int cipherSuite)
	{
		switch (cipherSuite) {
		case NULL_WITH_NULL_NULL:
			return "NULL_WITH_NULL_NULL";
		case RSA_WITH_NULL_MD5:
			return "RSA_WITH_NULL_MD5";
		case RSA_WITH_NULL_SHA:
			return "RSA_WITH_NULL_SHA";
		case RSA_WITH_NULL_SHA256:
			return "RSA_WITH_NULL_SHA256";
		case RSA_WITH_RC4_128_MD5:
			return "RSA_WITH_RC4_128_MD5";
		case RSA_WITH_RC4_128_SHA:
			return "RSA_WITH_RC4_128_SHA";
		case RSA_WITH_3DES_EDE_CBC_SHA:
			return "RSA_WITH_3DES_EDE_CBC_SHA";
		case RSA_WITH_AES_128_CBC_SHA:
			return "RSA_WITH_AES_128_CBC_SHA";
		case RSA_WITH_AES_256_CBC_SHA:
			return "RSA_WITH_AES_256_CBC_SHA";
		case RSA_WITH_AES_128_CBC_SHA256:
			return "RSA_WITH_AES_128_CBC_SHA256";
		case RSA_WITH_AES_256_CBC_SHA256:
			return "RSA_WITH_AES_256_CBC_SHA256";
		case DH_DSS_WITH_3DES_EDE_CBC_SHA:
			return "DH_DSS_WITH_3DES_EDE_CBC_SHA";
		case DH_RSA_WITH_3DES_EDE_CBC_SHA:
			return "DH_RSA_WITH_3DES_EDE_CBC_SHA";
		case DHE_DSS_WITH_3DES_EDE_CBC_SHA:
			return "DHE_DSS_WITH_3DES_EDE_CBC_SHA";
		case DHE_RSA_WITH_3DES_EDE_CBC_SHA:
			return "DHE_RSA_WITH_3DES_EDE_CBC_SHA";
		case DH_DSS_WITH_AES_128_CBC_SHA:
			return "DH_DSS_WITH_AES_128_CBC_SHA";
		case DH_RSA_WITH_AES_128_CBC_SHA:
			return "DH_RSA_WITH_AES_128_CBC_SHA";
		case DHE_DSS_WITH_AES_128_CBC_SHA:
			return "DHE_DSS_WITH_AES_128_CBC_SHA";
		case DHE_RSA_WITH_AES_128_CBC_SHA:
			return "DHE_RSA_WITH_AES_128_CBC_SHA";
		case DH_DSS_WITH_AES_256_CBC_SHA:
			return "DH_DSS_WITH_AES_256_CBC_SHA";
		case DH_RSA_WITH_AES_256_CBC_SHA:
			return "DH_RSA_WITH_AES_256_CBC_SHA";
		case DHE_DSS_WITH_AES_256_CBC_SHA:
			return "DHE_DSS_WITH_AES_256_CBC_SHA";
		case DHE_RSA_WITH_AES_256_CBC_SHA:
			return "DHE_RSA_WITH_AES_256_CBC_SHA";
		case DH_DSS_WITH_AES_128_CBC_SHA256:
			return "DH_DSS_WITH_AES_128_CBC_SHA256";
		case DH_RSA_WITH_AES_128_CBC_SHA256:
			return "DH_RSA_WITH_AES_128_CBC_SHA256";
		case DHE_DSS_WITH_AES_128_CBC_SHA256:
			return "DHE_DSS_WITH_AES_128_CBC_SHA256";
		case DHE_RSA_WITH_AES_128_CBC_SHA256:
			return "DHE_RSA_WITH_AES_128_CBC_SHA256";
		case DH_DSS_WITH_AES_256_CBC_SHA256:
			return "DH_DSS_WITH_AES_256_CBC_SHA256";
		case DH_RSA_WITH_AES_256_CBC_SHA256:
			return "DH_RSA_WITH_AES_256_CBC_SHA256";
		case DHE_DSS_WITH_AES_256_CBC_SHA256:
			return "DHE_DSS_WITH_AES_256_CBC_SHA256";
		case DHE_RSA_WITH_AES_256_CBC_SHA256:
			return "DHE_RSA_WITH_AES_256_CBC_SHA256";
		case DH_anon_WITH_RC4_128_MD5:
			return "DH_anon_WITH_RC4_128_MD5";
		case DH_anon_WITH_3DES_EDE_CBC_SHA:
			return "DH_anon_WITH_3DES_EDE_CBC_SHA";
		case DH_anon_WITH_AES_128_CBC_SHA:
			return "DH_anon_WITH_AES_128_CBC_SHA";
		case DH_anon_WITH_AES_256_CBC_SHA:
			return "DH_anon_WITH_AES_256_CBC_SHA";
		case DH_anon_WITH_AES_128_CBC_SHA256:
			return "DH_anon_WITH_AES_128_CBC_SHA256";
		case DH_anon_WITH_AES_256_CBC_SHA256:
			return "DH_anon_WITH_AES_256_CBC_SHA256";
		case ECDH_ECDSA_WITH_NULL_SHA:
			return "ECDH_ECDSA_WITH_NULL_SHA";
		case ECDH_ECDSA_WITH_RC4_128_SHA:
			return "ECDH_ECDSA_WITH_RC4_128_SHA";
		case ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:
			return "ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA";
		case ECDH_ECDSA_WITH_AES_128_CBC_SHA:
			return "ECDH_ECDSA_WITH_AES_128_CBC_SHA";
		case ECDH_ECDSA_WITH_AES_256_CBC_SHA:
			return "ECDH_ECDSA_WITH_AES_256_CBC_SHA";
		case ECDHE_ECDSA_WITH_NULL_SHA:
			return "ECDHE_ECDSA_WITH_NULL_SHA";
		case ECDHE_ECDSA_WITH_RC4_128_SHA:
			return "ECDHE_ECDSA_WITH_RC4_128_SHA";
		case ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
			return "ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA";
		case ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
			return "ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
		case ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
			return "ECDHE_ECDSA_WITH_AES_256_CBC_SHA";
		case ECDH_RSA_WITH_NULL_SHA:
			return "ECDH_RSA_WITH_NULL_SHA";
		case ECDH_RSA_WITH_RC4_128_SHA:
			return "ECDH_RSA_WITH_RC4_128_SHA";
		case ECDH_RSA_WITH_3DES_EDE_CBC_SHA:
			return "ECDH_RSA_WITH_3DES_EDE_CBC_SHA";
		case ECDH_RSA_WITH_AES_128_CBC_SHA:
			return "ECDH_RSA_WITH_AES_128_CBC_SHA";
		case ECDH_RSA_WITH_AES_256_CBC_SHA:
			return "ECDH_RSA_WITH_AES_256_CBC_SHA";
		case ECDHE_RSA_WITH_NULL_SHA:
			return "ECDHE_RSA_WITH_NULL_SHA";
		case ECDHE_RSA_WITH_RC4_128_SHA:
			return "ECDHE_RSA_WITH_RC4_128_SHA";
		case ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
			return "ECDHE_RSA_WITH_3DES_EDE_CBC_SHA";
		case ECDHE_RSA_WITH_AES_128_CBC_SHA:
			return "ECDHE_RSA_WITH_AES_128_CBC_SHA";
		case ECDHE_RSA_WITH_AES_256_CBC_SHA:
			return "ECDHE_RSA_WITH_AES_256_CBC_SHA";
		case ECDH_anon_WITH_NULL_SHA:
			return "ECDH_anon_WITH_NULL_SHA";
		case ECDH_anon_WITH_RC4_128_SHA:
			return "ECDH_anon_WITH_RC4_128_SHA";
		case ECDH_anon_WITH_3DES_EDE_CBC_SHA:
			return "ECDH_anon_WITH_3DES_EDE_CBC_SHA";
		case ECDH_anon_WITH_AES_128_CBC_SHA:
			return "ECDH_anon_WITH_AES_128_CBC_SHA";
		case ECDH_anon_WITH_AES_256_CBC_SHA:
			return "ECDH_anon_WITH_AES_256_CBC_SHA";
		case RSA_WITH_AES_128_GCM_SHA256:
			return "RSA_WITH_AES_128_GCM_SHA256";
		case RSA_WITH_AES_256_GCM_SHA384:
			return "RSA_WITH_AES_256_GCM_SHA384";
		case DHE_RSA_WITH_AES_128_GCM_SHA256:
			return "DHE_RSA_WITH_AES_128_GCM_SHA256";
		case DHE_RSA_WITH_AES_256_GCM_SHA384:
			return "DHE_RSA_WITH_AES_256_GCM_SHA384";
		case DH_RSA_WITH_AES_128_GCM_SHA256:
			return "DH_RSA_WITH_AES_128_GCM_SHA256";
		case DH_RSA_WITH_AES_256_GCM_SHA384:
			return "DH_RSA_WITH_AES_256_GCM_SHA384";
		case DHE_DSS_WITH_AES_128_GCM_SHA256:
			return "DHE_DSS_WITH_AES_128_GCM_SHA256";
		case DHE_DSS_WITH_AES_256_GCM_SHA384:
			return "DHE_DSS_WITH_AES_256_GCM_SHA384";
		case DH_DSS_WITH_AES_128_GCM_SHA256:
			return "DH_DSS_WITH_AES_128_GCM_SHA256";
		case DH_DSS_WITH_AES_256_GCM_SHA384:
			return "DH_DSS_WITH_AES_256_GCM_SHA384";
		case DH_anon_WITH_AES_128_GCM_SHA256:
			return "DH_anon_WITH_AES_128_GCM_SHA256";
		case DH_anon_WITH_AES_256_GCM_SHA384:
			return "DH_anon_WITH_AES_256_GCM_SHA384";
		case ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
			return "ECDHE_ECDSA_WITH_AES_128_CBC_SHA256";
		case ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
			return "ECDHE_ECDSA_WITH_AES_256_CBC_SHA384";
		case ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
			return "ECDH_ECDSA_WITH_AES_128_CBC_SHA256";
		case ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
			return "ECDH_ECDSA_WITH_AES_256_CBC_SHA384";
		case ECDHE_RSA_WITH_AES_128_CBC_SHA256:
			return "ECDHE_RSA_WITH_AES_128_CBC_SHA256";
		case ECDHE_RSA_WITH_AES_256_CBC_SHA384:
			return "ECDHE_RSA_WITH_AES_256_CBC_SHA384";
		case ECDH_RSA_WITH_AES_128_CBC_SHA256:
			return "ECDH_RSA_WITH_AES_128_CBC_SHA256";
		case ECDH_RSA_WITH_AES_256_CBC_SHA384:
			return "ECDH_RSA_WITH_AES_256_CBC_SHA384";
		case ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
			return "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
		case ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
			return "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
		case ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
			return "ECDH_ECDSA_WITH_AES_128_GCM_SHA256";
		case ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
			return "ECDH_ECDSA_WITH_AES_256_GCM_SHA384";
		case ECDHE_RSA_WITH_AES_128_GCM_SHA256:
			return "ECDHE_RSA_WITH_AES_128_GCM_SHA256";
		case ECDHE_RSA_WITH_AES_256_GCM_SHA384:
			return "ECDHE_RSA_WITH_AES_256_GCM_SHA384";
		case ECDH_RSA_WITH_AES_128_GCM_SHA256:
			return "ECDH_RSA_WITH_AES_128_GCM_SHA256";
		case ECDH_RSA_WITH_AES_256_GCM_SHA384:
			return "ECDH_RSA_WITH_AES_256_GCM_SHA384";
		case ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
			return "ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
		case ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
			return "ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
		case DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
			return "DHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
		case PSK_WITH_CHACHA20_POLY1305_SHA256:
			return "PSK_WITH_CHACHA20_POLY1305_SHA256";
		case ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
			return "ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256";
		case DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
			return "DHE_PSK_WITH_CHACHA20_POLY1305_SHA256";
		case RSA_PSK_WITH_CHACHA20_POLY1305_SHA256:
			return "RSA_PSK_WITH_CHACHA20_POLY1305_SHA256";
		case FALLBACK_SCSV:
			return "FALLBACK_SCSV";
		case EMPTY_RENEGOTIATION_INFO_SCSV:
			return "EMPTY_RENEGOTIATION_INFO_SCSV";
		default:
			return String.Format("UNKNOWN:0x{0:X4}", cipherSuite);
		}
	}

	/*
	 * Get a human-readable name for a hash-and-sign algorithm.
	 */
	public static string HashAndSignName(int hs)
	{
		switch (hs) {
		case RSA_MD5:       return "RSA_MD5";
		case RSA_SHA1:      return "RSA_SHA1";
		case RSA_SHA224:    return "RSA_SHA224";
		case RSA_SHA256:    return "RSA_SHA256";
		case RSA_SHA384:    return "RSA_SHA384";
		case RSA_SHA512:    return "RSA_SHA512";
		case ECDSA_MD5:     return "ECDSA_MD5";
		case ECDSA_SHA1:    return "ECDSA_SHA1";
		case ECDSA_SHA224:  return "ECDSA_SHA224";
		case ECDSA_SHA256:  return "ECDSA_SHA256";
		case ECDSA_SHA384:  return "ECDSA_SHA384";
		case ECDSA_SHA512:  return "ECDSA_SHA512";
		default:
			return String.Format("UNKNOWN:0x{0:X4}", hs);
		}
	}

	/*
	 * Get a human-readable name for a curve.
	 */
	public static string CurveName(int id)
	{
		switch (id) {
		case Curve25519:  return "Curve25519";
		case NIST_P256:   return "NIST_P256";
		case NIST_P384:   return "NIST_P384";
		case NIST_P521:   return "NIST_P521";
		default:
			return String.Format("UNKNOWN:0x{0:X4}", id);
		}
	}

	/*
	 * Extract the public key from an encoded X.509 certificate.
	 * This does NOT make any attempt at validating the certificate.
	 */
	internal static IPublicKey GetKeyFromCert(byte[] cert)
	{
		AsnElt ae = AsnElt.Decode(cert);
		ae.CheckTag(AsnElt.SEQUENCE);
		ae.CheckNumSub(3);
		ae = ae.GetSub(0);
		ae.CheckTag(AsnElt.SEQUENCE);
		ae.CheckNumSubMin(6);
		int off = 5;
		if (ae.GetSub(0).TagValue != AsnElt.INTEGER) {
			ae.CheckNumSubMin(7);
			off ++;
		}
		return KF.DecodePublicKey(ae.GetSub(off));
	}

	internal static bool IsRSA(int cs)
	{
		switch (cs) {
		case RSA_WITH_RC4_128_MD5:
		case RSA_WITH_RC4_128_SHA:
		case RSA_WITH_3DES_EDE_CBC_SHA:
		case RSA_WITH_AES_128_CBC_SHA:
		case RSA_WITH_AES_256_CBC_SHA:
		case RSA_WITH_AES_128_CBC_SHA256:
		case RSA_WITH_AES_256_CBC_SHA256:
		case RSA_WITH_AES_128_GCM_SHA256:
		case RSA_WITH_AES_256_GCM_SHA384:
			return true;
		default:
			return false;
		}
	}

	internal static bool IsDH_DSA(int cs)
	{
		switch (cs) {
		case DH_DSS_WITH_3DES_EDE_CBC_SHA:
		case DH_DSS_WITH_AES_128_CBC_SHA:
		case DH_DSS_WITH_AES_256_CBC_SHA:
		case DH_DSS_WITH_AES_128_CBC_SHA256:
		case DH_DSS_WITH_AES_256_CBC_SHA256:
		case DH_DSS_WITH_AES_128_GCM_SHA256:
		case DH_DSS_WITH_AES_256_GCM_SHA384:
			return true;
		default:
			return false;
		}
	}

	internal static bool IsDH_RSA(int cs)
	{
		switch (cs) {
		case DH_RSA_WITH_3DES_EDE_CBC_SHA:
		case DH_RSA_WITH_AES_128_CBC_SHA:
		case DH_RSA_WITH_AES_256_CBC_SHA:
		case DH_RSA_WITH_AES_128_CBC_SHA256:
		case DH_RSA_WITH_AES_256_CBC_SHA256:
		case DH_RSA_WITH_AES_128_GCM_SHA256:
		case DH_RSA_WITH_AES_256_GCM_SHA384:
			return true;
		default:
			return false;
		}
	}

	internal static bool IsDH(int cs)
	{
		return IsDH_DSA(cs) || IsDH_RSA(cs);
	}

	internal static bool IsDHE_DSS(int cs)
	{
		switch (cs) {
		case DHE_DSS_WITH_3DES_EDE_CBC_SHA:
		case DHE_DSS_WITH_AES_128_CBC_SHA:
		case DHE_DSS_WITH_AES_256_CBC_SHA:
		case DHE_DSS_WITH_AES_128_CBC_SHA256:
		case DHE_DSS_WITH_AES_256_CBC_SHA256:
		case DHE_DSS_WITH_AES_128_GCM_SHA256:
		case DHE_DSS_WITH_AES_256_GCM_SHA384:
			return true;
		default:
			return false;
		}
	}

	internal static bool IsDHE_RSA(int cs)
	{
		switch (cs) {
		case DHE_RSA_WITH_3DES_EDE_CBC_SHA:
		case DHE_RSA_WITH_AES_128_CBC_SHA:
		case DHE_RSA_WITH_AES_256_CBC_SHA:
		case DHE_RSA_WITH_AES_128_CBC_SHA256:
		case DHE_RSA_WITH_AES_256_CBC_SHA256:
		case DHE_RSA_WITH_AES_128_GCM_SHA256:
		case DHE_RSA_WITH_AES_256_GCM_SHA384:
		case DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
			return true;
		default:
			return false;
		}
	}

	internal static bool IsECDH_ECDSA(int cs)
	{
		switch (cs) {
		case ECDH_ECDSA_WITH_NULL_SHA:
		case ECDH_ECDSA_WITH_RC4_128_SHA:
		case ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:
		case ECDH_ECDSA_WITH_AES_128_CBC_SHA:
		case ECDH_ECDSA_WITH_AES_256_CBC_SHA:
		case ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
		case ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
		case ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
		case ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
			return true;
		default:
			return false;
		}
	}

	internal static bool IsECDH_RSA(int cs)
	{
		switch (cs) {
		case ECDH_RSA_WITH_NULL_SHA:
		case ECDH_RSA_WITH_RC4_128_SHA:
		case ECDH_RSA_WITH_3DES_EDE_CBC_SHA:
		case ECDH_RSA_WITH_AES_128_CBC_SHA:
		case ECDH_RSA_WITH_AES_256_CBC_SHA:
		case ECDH_RSA_WITH_AES_128_CBC_SHA256:
		case ECDH_RSA_WITH_AES_256_CBC_SHA384:
		case ECDH_RSA_WITH_AES_128_GCM_SHA256:
		case ECDH_RSA_WITH_AES_256_GCM_SHA384:
			return true;
		default:
			return false;
		}
	}

	internal static bool IsECDH(int cs)
	{
		return IsECDH_ECDSA(cs) || IsECDH_RSA(cs);
	}

	internal static bool IsECDHE_ECDSA(int cs)
	{
		switch (cs) {
		case ECDHE_ECDSA_WITH_NULL_SHA:
		case ECDHE_ECDSA_WITH_RC4_128_SHA:
		case ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
		case ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		case ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		case ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		case ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
		case ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		case ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		case ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
			return true;
		default:
			return false;
		}
	}

	internal static bool IsECDHE_RSA(int cs)
	{
		switch (cs) {
		case ECDHE_RSA_WITH_NULL_SHA:
		case ECDHE_RSA_WITH_RC4_128_SHA:
		case ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
		case ECDHE_RSA_WITH_AES_128_CBC_SHA:
		case ECDHE_RSA_WITH_AES_256_CBC_SHA:
		case ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		case ECDHE_RSA_WITH_AES_256_CBC_SHA384:
		case ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		case ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		case ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
			return true;
		default:
			return false;
		}
	}

	internal static bool IsECDHE(int cs)
	{
		return IsECDHE_RSA(cs) || IsECDHE_ECDSA(cs);
	}

	internal static bool IsSHA384(int cs)
	{
		switch (cs) {
		case RSA_WITH_AES_256_GCM_SHA384:
		case DH_DSS_WITH_AES_256_GCM_SHA384:
		case DH_RSA_WITH_AES_256_GCM_SHA384:
		case DHE_DSS_WITH_AES_256_GCM_SHA384:
		case DHE_RSA_WITH_AES_256_GCM_SHA384:
		case ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
		case ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
		case ECDH_RSA_WITH_AES_256_CBC_SHA384:
		case ECDH_RSA_WITH_AES_256_GCM_SHA384:
		case ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
		case ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		case ECDHE_RSA_WITH_AES_256_CBC_SHA384:
		case ECDHE_RSA_WITH_AES_256_GCM_SHA384:
			return true;
		default:
			return false;
		}
	}

	internal static bool IsTLS12(int cs)
	{
		switch (cs) {
		case RSA_WITH_NULL_SHA256:
		case RSA_WITH_AES_128_CBC_SHA256:
		case RSA_WITH_AES_256_CBC_SHA256:
		case DH_DSS_WITH_AES_128_CBC_SHA256:
		case DH_RSA_WITH_AES_128_CBC_SHA256:
		case DHE_DSS_WITH_AES_128_CBC_SHA256:
		case DHE_RSA_WITH_AES_128_CBC_SHA256:
		case DH_DSS_WITH_AES_256_CBC_SHA256:
		case DH_RSA_WITH_AES_256_CBC_SHA256:
		case DHE_DSS_WITH_AES_256_CBC_SHA256:
		case DHE_RSA_WITH_AES_256_CBC_SHA256:
		case DH_anon_WITH_AES_128_CBC_SHA256:
		case DH_anon_WITH_AES_256_CBC_SHA256:
		case RSA_WITH_AES_128_GCM_SHA256:
		case RSA_WITH_AES_256_GCM_SHA384:
		case DHE_RSA_WITH_AES_128_GCM_SHA256:
		case DHE_RSA_WITH_AES_256_GCM_SHA384:
		case DH_RSA_WITH_AES_128_GCM_SHA256:
		case DH_RSA_WITH_AES_256_GCM_SHA384:
		case DHE_DSS_WITH_AES_128_GCM_SHA256:
		case DHE_DSS_WITH_AES_256_GCM_SHA384:
		case DH_DSS_WITH_AES_128_GCM_SHA256:
		case DH_DSS_WITH_AES_256_GCM_SHA384:
		case DH_anon_WITH_AES_128_GCM_SHA256:
		case DH_anon_WITH_AES_256_GCM_SHA384:
		case ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		case ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
		case ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
		case ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
		case ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		case ECDHE_RSA_WITH_AES_256_CBC_SHA384:
		case ECDH_RSA_WITH_AES_128_CBC_SHA256:
		case ECDH_RSA_WITH_AES_256_CBC_SHA384:
		case ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		case ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		case ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
		case ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
		case ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		case ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		case ECDH_RSA_WITH_AES_128_GCM_SHA256:
		case ECDH_RSA_WITH_AES_256_GCM_SHA384:
		case ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		case ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		case DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		case PSK_WITH_CHACHA20_POLY1305_SHA256:
		case ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
		case DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
		case RSA_PSK_WITH_CHACHA20_POLY1305_SHA256:
			return true;
		default:
			return false;
		}
	}

	internal static PRF GetPRFForTLS12(int cs)
	{
		return new PRF(IsSHA384(cs)
			? (IDigest)new SHA384()
			: (IDigest)new SHA256());
	}

	internal static ECCurve GetCurveByID(int id)
	{
		switch (id) {
		case NIST_P256: return EC.P256;
		case NIST_P384: return EC.P384;
		case NIST_P521: return EC.P521;
		case Curve25519: return EC.Curve25519;
		default:
			throw new SSLException("Unknown curve: " + id);
		}
	}

	/*
	 * Get ID for a curve. This returns -1 if the curve is not
	 * recognised.
	 */
	internal static int CurveToID(ECCurve curve)
	{
		switch (curve.Name) {
		case "P-256":       return SSL.NIST_P256;
		case "P-384":       return SSL.NIST_P384;
		case "P-521":       return SSL.NIST_P521;
		case "Curve25519":  return SSL.Curve25519;
		default:
			return -1;
		}
	}

	internal static IDigest GetHashByID(int id)
	{
		switch (id) {
		case 1: return new MD5();
		case 2: return new SHA1();
		case 3: return new SHA224();
		case 4: return new SHA256();
		case 5: return new SHA384();
		case 6: return new SHA512();
		default:
			throw new SSLException("Unknown hash: " + id);
		}
	}
}

}
