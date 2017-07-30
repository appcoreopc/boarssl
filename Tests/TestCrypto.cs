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
using System.IO;
using System.Text;

using Crypto;

public class TestCrypto {

	public static void Main(string[] args)
	{
		IDictionary<string, bool> d =
			new SortedDictionary<string, bool>(
				StringComparer.OrdinalIgnoreCase);
		foreach (string a in args) {
			StringBuilder sb = new StringBuilder();
			foreach (char c in a.ToLowerInvariant()) {
				if ((c >= 'a' && c <= 'z')
					|| (c >= '0' && c <= '9'))
				{
					sb.Append(c);
				}
			}
			d[sb.ToString()] = true;
		}
		bool all = (d.Count == 0);
		try {
			if (all || d.ContainsKey("md5")) {
				TestMD5();
			}
			if (all || d.ContainsKey("sha1")) {
				TestSHA1();
			}
			if (all || d.ContainsKey("sha224")) {
				TestSHA224();
			}
			if (all || d.ContainsKey("sha256")) {
				TestSHA256();
			}
			if (all || d.ContainsKey("sha384")) {
				TestSHA384();
			}
			if (all || d.ContainsKey("sha512")) {
				TestSHA512();
			}
			if (all || d.ContainsKey("hmac")) {
				TestHMAC();
			}
			if (all || d.ContainsKey("hmacdrbg")) {
				TestHMAC_DRBG();
			}
			if (all || d.ContainsKey("aes")) {
				TestAES();
			}
			if (all || d.ContainsKey("des")) {
				TestDES();
			}
			if (all || d.ContainsKey("chacha20")) {
				TestChaCha20();
			}
			if (all || d.ContainsKey("poly1305")) {
				TestPoly1305();
			}
			if (all || d.ContainsKey("ghash")) {
				TestGHASH();
			}
			if (all || d.ContainsKey("int")) {
				TestMath.TestModInt();
			}
			if (all || d.ContainsKey("rsa")) {
				TestRSA();
			}
			if (all || d.ContainsKey("ec")) {
				TestEC.TestECInt();
			}
			if (all || d.ContainsKey("ecdsa")) {
				TestECDSA();
			}
		} catch (Exception e) {
			Console.WriteLine(e.ToString());
			Environment.Exit(1);
		}
	}

	static void TestMD5()
	{
		Console.Write("Testing MD5... ");
		DoKATHash(new MD5(), KAT_MD5);
		Console.WriteLine("done.");
	}

	static void TestSHA1()
	{
		Console.Write("Testing SHA-1... ");
		DoKATHash(new SHA1(), KAT_SHA1);
		DoKATHashLong(new SHA1(), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
		Console.WriteLine("done.");
	}

	static void TestSHA224()
	{
		Console.Write("Testing SHA-224... ");
		DoKATHash(new SHA224(), KAT_SHA224);
		DoKATHashLong(new SHA224(), "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67");
		Console.WriteLine("done.");
	}

	static void TestSHA256()
	{
		Console.Write("Testing SHA-256... ");
		DoKATHash(new SHA256(), KAT_SHA256);
		DoKATHashLong(new SHA256(), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
		Console.WriteLine("done.");
	}

	static void TestSHA384()
	{
		Console.Write("Testing SHA-384... ");
		DoKATHash(new SHA384(), KAT_SHA384);
		DoKATHashLong(new SHA384(), "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985");
		Console.WriteLine("done.");
	}

	static void TestSHA512()
	{
		Console.Write("Testing SHA-512... ");
		DoKATHash(new SHA512(), KAT_SHA512);
		DoKATHashLong(new SHA512(), "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
		Console.WriteLine("done.");
	}

	static void DoKATHash(IDigest h, string[] katTab)
	{
		for (int i = 0; i < katTab.Length; i += 2) {
			DoKATHash(h,
				Encoding.UTF8.GetBytes(katTab[i]),
				ToBin(katTab[i + 1]));
		}
	}

	static void TestHMAC()
	{
		Console.Write("Testing HMAC... ");

		DoKATHMAC(new HMAC(new MD5()),
			ToBin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
			Encoding.UTF8.GetBytes("Hi There"),
			ToBin("9294727a3638bb1c13f48ef8158bfc9d"));
		DoKATHMAC(new HMAC(new MD5()),
			Encoding.UTF8.GetBytes("Jefe"),
			Encoding.UTF8.GetBytes("what do ya want for nothing?"),
			ToBin("750c783e6ab0b503eaa86e310a5db738"));
		DoKATHMAC(new HMAC(new MD5()),
			ToBin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
			ToBin("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"),
			ToBin("56be34521d144c88dbb8c733f0e8b3f6"));
		DoKATHMAC(new HMAC(new MD5()),
			ToBin("0102030405060708090a0b0c0d0e0f10111213141516171819"),
			ToBin("CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD"),
			ToBin("697eaf0aca3a3aea3a75164746ffaa79"));
		DoKATHMAC(new HMAC(new MD5()),
			ToBin("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"),
			Encoding.UTF8.GetBytes("Test With Truncation"),
			ToBin("56461ef2342edc00f9bab995690efd4c"));
		DoKATHMAC(new HMAC(new MD5()),
			ToBin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
			Encoding.UTF8.GetBytes("Test Using Larger Than Block-Size Key - Hash Key First"),
			ToBin("6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd"));
		DoKATHMAC(new HMAC(new MD5()),
			ToBin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
			Encoding.UTF8.GetBytes("Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"),
			ToBin("6f630fad67cda0ee1fb1f562db3aa53e"));

		DoKATHMAC(new HMAC(new SHA1()),
			ToBin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
			Encoding.UTF8.GetBytes("Hi There"),
			ToBin("b617318655057264e28bc0b6fb378c8ef146be00"));
		DoKATHMAC(new HMAC(new SHA1()),
			Encoding.UTF8.GetBytes("Jefe"),
			Encoding.UTF8.GetBytes("what do ya want for nothing?"),
			ToBin("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"));
		DoKATHMAC(new HMAC(new SHA1()),
			ToBin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
			ToBin("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"),
			ToBin("125d7342b9ac11cd91a39af48aa17b4f63f175d3"));
		DoKATHMAC(new HMAC(new SHA1()),
			ToBin("0102030405060708090a0b0c0d0e0f10111213141516171819"),
			ToBin("CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD"),
			ToBin("4c9007f4026250c6bc8414f9bf50c86c2d7235da"));
		DoKATHMAC(new HMAC(new SHA1()),
			ToBin("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"),
			Encoding.UTF8.GetBytes("Test With Truncation"),
			ToBin("4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"));
		DoKATHMAC(new HMAC(new SHA1()),
			ToBin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
			Encoding.UTF8.GetBytes("Test Using Larger Than Block-Size Key - Hash Key First"),
			ToBin("aa4ae5e15272d00e95705637ce8a3b55ed402112"));
		DoKATHMAC(new HMAC(new SHA1()),
			ToBin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
			Encoding.UTF8.GetBytes("Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"),
			ToBin("e8e99d0f45237d786d6bbaa7965c7808bbff1a91"));

		TestHMAC_CT(new MD5());
		TestHMAC_CT(new SHA1());
		TestHMAC_CT(new SHA256());
		TestHMAC_CT(new SHA512());

		Console.WriteLine("done.");
	}

	static void TestHMAC_CT(IDigest h)
	{
		Console.Write("[{0}]", h.Name);
		int hlen = h.DigestSize;
		HMAC hm = new HMAC(h);
		byte[] key = new byte[hlen];
		RNG.GetBytes(key);
		hm.SetKey(key);
		byte[] data = new byte[384];
		RNG.GetBytes(data);
		byte[] tmp1 = new byte[hlen];
		byte[] tmp2 = new byte[hlen];
		for (int i = 0; i < 256; i ++) {
			int i1 = i >> 1;
			int i2 = i - i1;
			for (int j = 0; j <= 128; j ++) {
				hm.Update(data, 0, i1);
				hm.ComputeCT(data, i1, i2 + j, i2, i2 + j,
					tmp1, 0);
				hm.Update(data, 0, i + j);
				hm.DoFinal(tmp2, 0);
				CheckEq(tmp1, tmp2, "CT");
			}
			Console.Write(".");
		}
	}

	static void TestHMAC_DRBG()
	{
		Console.Write("Testing HMAC_DRBG... ");
		byte[] tmp = new byte[30];

		HMAC_DRBG drbg = new HMAC_DRBG(new SHA256());
		drbg.Update(ToBin("009A4D6792295A7F730FC3F2B49CBC0F62E862272F01795EDF0D54DB760F156D0DAC04C0322B3A204224"));
		drbg.GetBytes(tmp);
		CheckEq(tmp, ToBin("9305A46DE7FF8EB107194DEBD3FD48AA20D5E7656CBE0EA69D2A8D4E7C67"), "KAT 1");
		drbg.GetBytes(tmp);
		CheckEq(tmp, ToBin("C70C78608A3B5BE9289BE90EF6E81A9E2C1516D5751D2F75F50033E45F73"), "KAT 2");
		drbg.GetBytes(tmp);
		CheckEq(tmp, ToBin("475E80E992140567FCC3A50DAB90FE84BCD7BB03638E9C4656A06F37F650"), "KAT 3");

		Console.WriteLine("done.");
	}

	static void TestAES()
	{
		Console.Write("Testing AES... ");

		AES bc = new AES();
		DoKATBlockCipherRaw(bc, KAT_AES_RAW);
		DoKATBlockCipherCBC(bc, KAT_AES_CBC);
		DoKATBlockCipherCTR(bc, KAT_AES_CTR);

		DoMonteCarloAESEncrypt(bc,
			"139a35422f1d61de3c91787fe0507afd",
			"b9145a768b7dc489a096b546f43b231f",
			"fb2649694783b551eacd9d5db6126d47");
		DoMonteCarloAESDecrypt(bc,
			"0c60e7bf20ada9baa9e1ddf0d1540726",
			"b08a29b11a500ea3aca42c36675b9785",
			"d1d2bfdc58ffcad2341b095bce55221e");

		DoMonteCarloAESEncrypt(bc,
			"b9a63e09e1dfc42e93a90d9bad739e5967aef672eedd5da9",
			"85a1f7a58167b389cddc8a9ff175ee26",
			"5d1196da8f184975e240949a25104554");
		DoMonteCarloAESDecrypt(bc,
			"4b97585701c03fbebdfa8555024f589f1482c58a00fdd9fd",
			"d0bd0e02ded155e4516be83f42d347a4",
			"b63ef1b79507a62eba3dafcec54a6328");

		DoMonteCarloAESEncrypt(bc,
			"f9e8389f5b80712e3886cc1fa2d28a3b8c9cd88a2d4a54c6aa86ce0fef944be0",
			"b379777f9050e2a818f2940cbbd9aba4",
			"c5d2cb3d5b7ff0e23e308967ee074825");
		DoMonteCarloAESDecrypt(bc,
			"2b09ba39b834062b9e93f48373b8dd018dedf1e5ba1b8af831ebbacbc92a2643",
			"89649bd0115f30bd878567610223a59d",
			"e3d3868f578caf34e36445bf14cefc68");

		Console.WriteLine("done.");
	}

	static void TestDES()
	{
		Console.Write("Testing DES... ");

		DES bc = new DES();
		DoKATBlockCipherRaw(bc, KAT_DES_RAW);
		DoKATBlockCipherCBC(bc, KAT_DES_CBC);
		DoMonteCarloDESEncrypt(bc);
		DoMonteCarloDESDecrypt(bc);

		Console.WriteLine("done.");
	}

	static void TestChaCha20()
	{
		Console.Write("Testing ChaCha20... ");

		for (int i = 0; i < KAT_CHACHA20.Length; i += 5) {
			byte[] key = ToBin(KAT_CHACHA20[i + 0]);
			byte[] iv = ToBin(KAT_CHACHA20[i + 1]);
			uint cc = UInt32.Parse(KAT_CHACHA20[i + 2]);
			byte[] plain = ToBin(KAT_CHACHA20[i + 3]);
			byte[] cipher = ToBin(KAT_CHACHA20[i + 4]);

			ChaCha20 chacha = new ChaCha20();
			chacha.SetKey(key);
			byte[] tmp = new byte[plain.Length];

			for (int j = 0; j <= plain.Length; j ++) {
				for (int k = 0; k < tmp.Length; k ++) {
					tmp[k] = 0;
				}
				Array.Copy(plain, 0, tmp, 0, j);
				if (chacha.Run(iv, cc, tmp, 0, j)
					!= cc + (uint)((j + 63) >> 6))
				{
					throw new Exception(
						"ChaCha20: wrong counter");
				}
				CheckEq(tmp, 0, cipher, 0, j, "KAT 1");
				for (int k = j; k < tmp.Length; k ++) {
					if (tmp[k] != 0) {
						throw new Exception(
							"ChaCha20: overrun");
					}
				}

				uint cc2 = cc;
				for (int k = 0; k < j; k += 64) {
					int clen = Math.Min(64, j - k);
					cc2 = chacha.Run(iv, cc2, tmp, k, clen);
				}
				CheckEq(tmp, 0, plain, 0, j, "KAT 2");
			}
		}

		Console.WriteLine("done.");
	}

	static void TestPoly1305()
	{
		Console.Write("Testing Poly1305... ");

		byte[] plain = ToBin("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e");
		byte[] aad = ToBin("50515253c0c1c2c3c4c5c6c7");
		byte[] key = ToBin("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
		byte[] iv = ToBin("070000004041424344454647");
		byte[] cipher = ToBin("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116");
		byte[] tag = ToBin("1ae10b594f09e26a7e902ecbd0600691");

		byte[] data = new byte[plain.Length];
		Array.Copy(plain, 0, data, 0, plain.Length);
		byte[] tt = new byte[16];

		ChaCha20 cc = new ChaCha20();
		cc.SetKey(key);
		Poly1305 pp = new Poly1305();
		pp.ChaCha = cc;
		pp.Run(iv, data, 0, data.Length, aad, 0, aad.Length, tt, true);
		CheckEq(data, cipher, "KAT 1");
		CheckEq(tt, tag, "KAT 2");
		for (int i = 0; i < tt.Length; i ++) {
			tt[i] = 0;
		}
		pp.Run(iv, data, 0, data.Length, aad, 0, aad.Length, tt, false);
		CheckEq(data, plain, "KAT 3");
		CheckEq(tt, tag, "KAT 4");

		/*
		 * Make random messages and keys, and test the implementation
		 * against the ZInt-based reference code.
		 */
		Poly1305Ref ppref = new Poly1305Ref();
		ppref.ChaCha = new ChaCha20();
		data = new byte[100];
		aad = new byte[data.Length];
		byte[] tmp = new byte[data.Length];
		key = new byte[32];
		iv = new byte[12];
		byte[] tag1 = new byte[16];
		byte[] tag2 = new byte[16];
		for (int i = 0; i < data.Length; i ++) {
			RNG.GetBytes(key);
			RNG.GetBytes(iv);
			RNG.GetBytes(data, 0, i);
			RNG.GetBytes(aad, 0, i);

			Array.Copy(data, 0, tmp, 0, i);
			for (int j = i; j < tmp.Length; j ++) {
				tmp[j] = 0xFF;
			}
			pp.ChaCha.SetKey(key);
			pp.Run(iv, tmp, 0, i, aad, 0, i, tag1, true);

			for (int j = i; j < tmp.Length; j ++) {
				tmp[j] = 0x00;
			}
			ppref.ChaCha.SetKey(key);
			ppref.Run(iv, tmp, 0, i, aad, 0, i, tag2, false);

			CheckEq(data, 0, tmp, 0, i, "cross enc/dec");
			CheckEq(tag1, tag2, "cross MAC");
			Console.Write(".");
		}

		Console.WriteLine("done.");
	}

	static void TestGHASH()
	{
		Console.Write("Testing GHASH... ");

		for (int i = 0; i < KAT_GHASH.Length; i += 4) {
			byte[] h = ToBin(KAT_GHASH[i]);
			byte[] a = ToBin(KAT_GHASH[i + 1]);
			byte[] c = ToBin(KAT_GHASH[i + 2]);
			byte[] r = ToBin(KAT_GHASH[i + 3]);
			byte[] y = new byte[16];
			byte[] p = new byte[16];
			GHASH.Run(y, h, a);
			GHASH.Run(y, h, c);
			uint alen = (uint)a.Length << 3;
			uint clen = (uint)c.Length << 3;
			p[ 4] = (byte)(alen >> 24);
			p[ 5] = (byte)(alen >> 16);
			p[ 6] = (byte)(alen >>  8);
			p[ 7] = (byte)alen;
			p[12] = (byte)(clen >> 24);
			p[13] = (byte)(clen >> 16);
			p[14] = (byte)(clen >>  8);
			p[15] = (byte)clen;
			GHASH.Run(y, h, p);
			CheckEq(y, r, "KAT " + (i / 4 + 1));
		}

		Console.WriteLine("done.");
	}

	static void TestRSA()
	{
		Console.Write("Testing RSA... ");

		DoRSASelfTests(1024);
		DoRSASelfTests(1231);
		DoRSASelfTests(2048);

		Console.WriteLine("done.");
	}

	static void PrintInt(string name, byte[] x)
	{
		Console.Write("{0} = 0x", name);
		foreach (byte b in x) {
			Console.Write("{0:X2}", b);
		}
		Console.WriteLine();
	}

	static ZInt MakePrime(int size)
	{
		ZInt m = ((ZInt)3 << (size - 2)) + (ZInt)3;
		for (;;) {
			ZInt r = ZInt.MakeRand(size - 4);
			ZInt p = (r << 2) + m;
			if (p % (ZInt)65537 != 1 && p.IsPrime) {
				return p;
			}
		}
	}

	static ZInt ExtendedGCD(ZInt a, ZInt b, out ZInt u, out ZInt v)
	{
		ZInt s = 0, sp = 1;
		ZInt t = 1, tp = 0;
		while (b != 0) {
			ZInt q = a / b;
			ZInt bn = a - q * b;
			ZInt sn = sp - q * s;
			ZInt tn = tp - q * t;
			a = b;
			sp = s;
			tp = t;
			b = bn;
			s = sn;
			t = tn;
		}
		u = sp;
		v = tp;
		return a;
	}

	static ZInt ModInverse(ZInt x, ZInt n)
	{
		ZInt u, v;
		ZInt d = ExtendedGCD(x, n, out u, out v);
		if (x * u + v * n != d) {
			throw new Exception("bad extended GCD");
		}
		if (d != 1) {
			throw new Exception("not invertible");
		}
		return u.Mod(n);
	}

	static void DoRSASelfTests(int size)
	{
		Console.Write("   key gen ({0}): ", size);
		long begin = DateTime.UtcNow.Ticks;

		/*
		 * Use ZInt to generate new RSA key.
		 */
		ZInt p = MakePrime(size - (size >> 1));
		ZInt q;
		do {
			q = MakePrime(size >> 1);
		} while (p == q);
		if (p < q) {
			ZInt t = p;
			p = q;
			q = t;
		}
		ZInt n = p * q;
		ZInt e = 65537;
		ZInt d = ModInverse(65537, (p - 1) * (q - 1));
		ZInt dp = d % (p - 1);
		ZInt dq = d % (q - 1);
		ZInt iq = ModInverse(q, p);

		long end = DateTime.UtcNow.Ticks;
		Console.WriteLine("done in {0} ms.", (end - begin) / 10000);

		/*
		Console.WriteLine("n  = {0}", n);
		Console.WriteLine("e  = {0}", e);
		Console.WriteLine("d  = {0}", d);
		Console.WriteLine("p  = {0}", p);
		Console.WriteLine("q  = {0}", q);
		Console.WriteLine("dp = {0}", dp);
		Console.WriteLine("dq = {0}", dq);
		Console.WriteLine("iq = {0}", iq);
		*/

		RSAPrivateKey sk = new RSAPrivateKey(
			n.ToBytesUnsignedBE(),
			e.ToBytesUnsignedBE(),
			d.ToBytesUnsignedBE(),
			p.ToBytesUnsignedBE(),
			q.ToBytesUnsignedBE(),
			dp.ToBytesUnsignedBE(),
			dq.ToBytesUnsignedBE(),
			iq.ToBytesUnsignedBE());

		/*
		Console.Write("   key gen ({0}): ", size);
		long begin = DateTime.UtcNow.Ticks;
		RSAPrivateKey sk = RSA.Generate(size);
		long end = DateTime.UtcNow.Ticks;
		Console.WriteLine("done in {0} ms.", (end - begin) / 10000);
		*/

		/*
		PrintInt("n ", sk.N);
		PrintInt("e ", sk.E);
		PrintInt("d ", sk.D);
		PrintInt("p ", sk.P);
		PrintInt("q ", sk.Q);
		PrintInt("dp", sk.DP);
		PrintInt("dq", sk.DQ);
		PrintInt("iq", sk.IQ);
		*/

		RSAPublicKey pk = (RSAPublicKey)sk.PublicKey;
		for (int i = 0; i < ((size + 7) >> 3) - 11; i ++) {
			byte[] msg = new byte[i];
			RNG.GetBytes(msg);
			IDigest h = new SHA256();
			h.Update(msg);
			byte[] hv = h.DoFinal();
			byte[] sig = RSA.Sign(sk, RSA.PKCS1_SHA256, hv);
			if (!RSA.Verify(pk, RSA.PKCS1_SHA256, null, hv, sig)) {
				throw new Exception(String.Format(
					"RSA sign/verify 1 (len = {0})", i));
			}
			if (!RSA.Verify(pk, RSA.PKCS1_SHA256_ALT,
				RSA.PKCS1_SHA256, hv, sig))
			{
				throw new Exception(String.Format(
					"RSA sign/verify 2 (len = {0})", i));
			}
			if (RSA.Verify(pk, RSA.PKCS1_SHA1, null, hv, sig)) {
				throw new Exception(String.Format(
					"RSA sign/verify 3 (len = {0})", i));
			}
			hv[21] ^= 0x01;
			if (RSA.Verify(pk, RSA.PKCS1_SHA256, null, hv, sig)) {
				throw new Exception(String.Format(
					"RSA sign/verify 4 (len = {0})", i));
			}

			byte[] enc = RSA.Encrypt(pk, msg);
			byte[] dec = RSA.Decrypt(sk, enc);
			if (!Eq(msg, dec)) {
				throw new Exception(String.Format(
					"RSA encrypt/decrypt (len = {0})", i));
			}
		}
	}

	static void TestECDSA()
	{
		Console.WriteLine("Testing ECDSA... ");

		DoKATECDSA(NIST.P256, ECDSA_K_P256, ECDSA_SIGS_P256);
		DoKATECDSA(NIST.P384, ECDSA_K_P384, ECDSA_SIGS_P384);
		DoKATECDSA(NIST.P521, ECDSA_K_P521, ECDSA_SIGS_P521);
		DoECDSASelfTests(NIST.P256);
		DoECDSASelfTests(NIST.P384);
		DoECDSASelfTests(NIST.P521);

		Console.WriteLine("done.");
	}

	static void DoKATECDSA(ECCurve curve, string[] ks, string[] sigs)
	{
		Console.Write("   KAT ({0}): ", curve.Name);
		ECPublicKey pk = new ECPublicKey(curve, ToBin(ks[0]));
		pk.CheckValid();
		Console.Write("<valid pub> ");
		ECPrivateKey sk = new ECPrivateKey(curve, ToBin(ks[1]));
		sk.CheckValid();
		Console.Write("<valid priv> ");
		IPublicKey pk2 = sk.PublicKey;
		if (!pk.Equals(pk2) || !pk2.Equals(pk)) {
			throw new Exception("ECDSA mismatch public/private");
		}
		if (!pk.Equals(pk2) || !pk2.Equals(pk)) {
			throw new Exception("ECDSA mismatch public/private");
		}
		for (int i = 0; i < 10; i ++) {
			byte[] r = ToBin(sigs[i << 1]);
			byte[] s = ToBin(sigs[(i << 1) + 1]);
			byte[] msg = Encoding.UTF8.GetBytes(
				(i < 5) ? "sample" : "test");
			IDigest dig;
			switch (i % 5) {
			case 0:  dig = new SHA1(); break;
			case 1:  dig = new SHA224(); break;
			case 2:  dig = new SHA256(); break;
			case 3:  dig = new SHA384(); break;
			default: dig = new SHA512(); break;
			}
			dig.Update(msg);
			byte[] hv = dig.DoFinal();
			DoKATECDSA(pk, sk, dig, r, s, hv);
			Console.Write(".");
		}
		Console.WriteLine();
	}

	static void DoKATECDSA(ECPublicKey pk, ECPrivateKey sk,
		IDigest dig, byte[] r, byte[] s, byte[] hv)
	{
		if (r.Length != s.Length) {
			throw new ArgumentException();
		}
		byte[] sig1 = new byte[r.Length + s.Length];
		Array.Copy(r, 0, sig1, 0, r.Length);
		Array.Copy(s, 0, sig1, r.Length, s.Length);
		byte[] sig2 = ECDSA.SigRawToAsn1(sig1);
		byte[] sig3 = ECDSA.SigRawToAsn1(ECDSA.SigAsn1ToRaw(sig2));
		if (!Eq(sig2, sig3)) {
			throw new Exception("ECDSA sig enc/dec");
		}

		if (!ECDSA.VerifyRaw(pk, hv, sig1)) {
			throw new Exception("ECDSA verify 1");
		}
		if (!ECDSA.Verify(pk, hv, sig2)) {
			throw new Exception("ECDSA verify 2");
		}
		byte[] hv2 = new byte[hv.Length + 2];
		Array.Copy(hv, 0, hv2, 1, hv.Length);
		if (!ECDSA.VerifyRaw(pk, hv2, 1, hv.Length, sig1)) {
			throw new Exception("ECDSA verify 3");
		}
		hv2[1] ^= (byte)0x02;
		if (ECDSA.VerifyRaw(pk, hv2, 1, hv.Length, sig1)) {
			throw new Exception("ECDSA verify 4");
		}

		byte[] sig4 = ECDSA.SignRaw(sk, null, hv);
		if (Eq(sig1, sig4)) {
			throw new Exception("ECDSA sig randomized");
		}
		if (!ECDSA.VerifyRaw(pk, hv, sig4)) {
			throw new Exception("ECDSA verify 5");
		}
		byte[] sig5 = ECDSA.SignRaw(sk, dig, hv);
		if (!Eq(sig1, sig5)) {
			throw new Exception("ECDSA sig deterministic");
		}
	}

	static void DoECDSASelfTests(ECCurve curve)
	{
		Console.Write("   self ({0}): ", curve.Name);
		ECPrivateKey sk = ECDSA.Generate(curve);
		sk.CheckValid();
		Console.Write("<valid> ");
		ECPublicKey pk = sk.PublicKey;
		IDigest h = new SHA256();
		byte[] msg = new byte[32];
		for (int i = 0; i < 10; i ++) {
			RNG.GetBytes(msg);
			byte[] hv = h.Hash(msg);
			byte[] sig = ECDSA.Sign(sk, null, hv);
			if (!ECDSA.Verify(pk, hv, sig)) {
				throw new Exception("ECDSA sign/verify");
			}
			Console.Write(".");
		}
		Console.WriteLine();
	}

	static void DoKATHash(IDigest h, byte[] data, byte[] refOut)
	{
		h.Update(data);
		CheckEq(h.DoFinal(), refOut, "KAT 1");
		h.Update(data, 0, data.Length);
		byte[] tmp = new byte[h.DigestSize];
		h.DoFinal(tmp, 0);
		CheckEq(tmp, refOut, "KAT 2");
		foreach (byte b in data) {
			h.Update(b);
		}
		CheckEq(h.DoFinal(), refOut, "KAT 3");
		for (int t = 0; t < data.Length; t ++) {
			h.Update(data, 0, t);
			h.Update(data, t, data.Length - t);
			h.DoFinal(tmp, 0);
			CheckEq(tmp, refOut, "KAT 4." + t);
		}
		foreach (byte b in data) {
			h.Update(b);
			h.DoPartial(tmp, 0);
		}
		CheckEq(tmp, refOut, "KAT 5");
		h.Reset();
		h.Update(data);
		CheckEq(h.DoFinal(), refOut, "KAT 6");
		for (int t = 0; t < data.Length; t ++) {
			h.Update(data, 0, t);
			IDigest h2 = h.Dup();
			h.Update(data, t, data.Length - t);
			h.DoFinal(tmp, 0);
			CheckEq(tmp, refOut, "KAT 7." + t);
			h2.Update(data, t, data.Length - t);
			h2.DoFinal(tmp, 0);
			CheckEq(tmp, refOut, "KAT 8." + t);
		}
	}

	static void DoKATHashLong(IDigest h, string refOut)
	{
		byte[] buf = new byte[1000];
		for (int i = 0; i < buf.Length; i ++) {
			buf[i] = (byte)'a';
		}
		for (int i = 0; i < 1000; i ++) {
			h.Update(buf);
		}
		CheckEq(h.DoFinal(), ToBin(refOut), "KAT Long");
	}

	static void DoKATHMAC(HMAC hm, byte[] key, byte[] data, byte[] refOut)
	{
		hm.SetKey(key);
		hm.Update(data);
		CheckEq(hm.DoFinal(), refOut, "KAT 1");
		hm.Update(data, 0, data.Length);
		byte[] tmp = new byte[hm.MACSize];
		hm.DoFinal(tmp, 0);
		CheckEq(tmp, refOut, "KAT 2");
		foreach (byte b in data) {
			hm.Update(b);
		}
		CheckEq(hm.DoFinal(), refOut, "KAT 3");
		for (int t = 0; t < data.Length; t ++) {
			hm.Update(data, 0, t);
			hm.Update(data, t, data.Length - t);
			hm.DoFinal(tmp, 0);
			CheckEq(tmp, refOut, "KAT 4." + t);
		}
		for (int t = 0; t < data.Length; t ++) {
			hm.Update(data, 0, t);
			HMAC hm2 = hm.Dup();
			hm.Update(data, t, data.Length - t);
			hm.DoFinal(tmp, 0);
			CheckEq(tmp, refOut, "KAT 5." + t);
			hm2.Update(data, t, data.Length - t);
			hm2.DoFinal(tmp, 0);
			CheckEq(tmp, refOut, "KAT 6." + t);
		}
	}

	static void DoKATBlockCipherRaw(IBlockCipher bc, string[] kat)
	{
		for (int i = 0; i < kat.Length; i += 3) {
			byte[] key = ToBin(kat[i]);
			byte[] plain = ToBin(kat[i + 1]);
			byte[] cipher = ToBin(kat[i + 2]);
			int blen = bc.BlockSize;
			if (blen != plain.Length || blen != cipher.Length) {
				throw new Exception(string.Format(
					"block size mismatch: {0} / {1},{2}",
					blen, plain.Length, cipher.Length));
			}
			bc.SetKey(key);
			byte[] tmp = new byte[blen];
			Array.Copy(plain, 0, tmp, 0, blen);
			bc.BlockEncrypt(tmp, 0);
			CheckEq(tmp, cipher, "KAT encrypt");
			bc.BlockDecrypt(tmp, 0);
			CheckEq(tmp, plain, "KAT decrypt");
		}
	}

	static void DoKATBlockCipherCBC(IBlockCipher bc, string[] kat)
	{
		for (int i = 0; i < kat.Length; i += 4) {
			byte[] key = ToBin(kat[i]);
			byte[] iv = ToBin(kat[i + 1]);
			byte[] plain = ToBin(kat[i + 2]);
			byte[] cipher = ToBin(kat[i + 3]);
			int blen = bc.BlockSize;
			if (blen != iv.Length
				|| (plain.Length % blen) != 0
				|| (cipher.Length % blen) != 0
				|| plain.Length != cipher.Length)
			{
				throw new Exception(string.Format(
					"block size mismatch:"
					+ " {0} / {1},{2},{3}",
					blen, iv.Length,
					plain.Length, cipher.Length));
			}
			bc.SetKey(key);
			byte[] tmp = new byte[plain.Length];
			Array.Copy(plain, 0, tmp, 0, tmp.Length);
			bc.CBCEncrypt(iv, tmp);
			CheckEq(tmp, cipher, "KAT CBC encrypt (1)");
			bc.CBCDecrypt(iv, tmp);
			CheckEq(tmp, plain, "KAT CBC decrypt (1)");

			byte[] iv2 = new byte[blen];
			Array.Copy(iv, 0, iv2, 0, blen);
			for (int j = 0; j < tmp.Length; j += blen) {
				bc.CBCEncrypt(iv2, tmp, j, blen);
				Array.Copy(tmp, j, iv2, 0, blen);
			}
			CheckEq(tmp, cipher, "KAT CBC encrypt (2)");
			byte[] iv3 = new byte[blen];
			Array.Copy(iv, 0, iv2, 0, blen);
			for (int j = 0; j < tmp.Length; j += blen) {
				Array.Copy(tmp, j, iv3, 0, blen);
				bc.CBCDecrypt(iv2, tmp, j, blen);
				Array.Copy(iv3, 0, iv2, 0, blen);
			}
			CheckEq(tmp, plain, "KAT CBC decrypt (2)");
		}
	}

	static void DoKATBlockCipherCTR(IBlockCipher bc, string[] kat)
	{
		for (int i = 0; i < kat.Length; i += 4) {
			byte[] key = ToBin(kat[i]);
			byte[] iv = ToBin(kat[i + 1]);
			byte[] plain = ToBin(kat[i + 2]);
			byte[] cipher = ToBin(kat[i + 3]);
			int blen = bc.BlockSize;
			if (blen != (iv.Length + 4)
				|| plain.Length != cipher.Length)
			{
				throw new Exception(string.Format(
					"block size mismatch:"
					+ " {0} / {1},{2},{3}",
					blen, iv.Length,
					plain.Length, cipher.Length));
			}
			bc.SetKey(key);
			byte[] tmp = new byte[plain.Length];
			Array.Copy(plain, 0, tmp, 0, tmp.Length);
			uint cc;
			cc = bc.CTRRun(iv, 1, tmp);
			CheckEq(tmp, cipher, "KAT CTR encrypt (1)");
			if (cc != 1 + ((tmp.Length + blen - 1) / blen)) {
				throw new Exception(string.Format(
					"wrong CTR counter: {0} / {1}",
					cc, tmp.Length));
			}
			cc = bc.CTRRun(iv, 1, tmp);
			CheckEq(tmp, plain, "KAT CTR decrypt (1)");
			if (cc != 1 + ((tmp.Length + blen - 1) / blen)) {
				throw new Exception(string.Format(
					"wrong CTR counter: {0} / {1}",
					cc, tmp.Length));
			}

			cc = 1;
			for (int j = 0; j < tmp.Length; j += blen) {
				int clen = Math.Min(blen, tmp.Length - j);
				uint cc2 = bc.CTRRun(iv, cc, tmp, j, clen);
				if (cc2 != cc + 1) {
					throw new Exception(
						"wrong CTR counter update");
				}
				cc = cc2;
			}
			CheckEq(tmp, cipher, "KAT CTR encrypt (2)");
		}
	}

	static void DoMonteCarloAESEncrypt(IBlockCipher bc,
		string skey, string splain, string scipher)
	{
		byte[] key = ToBin(skey);
		byte[] buf = ToBin(splain);
		byte[] pbuf = new byte[buf.Length];
		byte[] cipher = ToBin(scipher);
		for (int i = 0; i < 100; i ++) {
			bc.SetKey(key);
			for (int j = 0; j < 1000; j ++) {
				Array.Copy(buf, 0, pbuf, 0, pbuf.Length);
				bc.BlockEncrypt(buf);
			}
			switch (key.Length) {
			case 16:
				for (int k = 0; k < 16; k ++) {
					key[k] ^= buf[k];
				}
				break;
			case 24:
				for (int k = 0; k < 8; k ++) {
					key[k] ^= pbuf[8 + k];
				}
				for (int k = 0; k < 16; k ++) {
					key[8 + k] ^= buf[k];
				}
				break;
			case 32:
				for (int k = 0; k < 16; k ++) {
					key[k] ^= pbuf[k];
				}
				for (int k = 0; k < 16; k ++) {
					key[16 + k] ^= buf[k];
				}
				break;
			}
			Console.Write(".");
		}
		Console.Write(" ");
		CheckEq(buf, cipher, "MC AES encrypt");
	}

	static void DoMonteCarloAESDecrypt(IBlockCipher bc,
		string skey, string splain, string scipher)
	{
		byte[] key = ToBin(skey);
		byte[] buf = ToBin(splain);
		byte[] pbuf = new byte[buf.Length];
		byte[] cipher = ToBin(scipher);
		for (int i = 0; i < 100; i ++) {
			bc.SetKey(key);
			for (int j = 0; j < 1000; j ++) {
				Array.Copy(buf, 0, pbuf, 0, pbuf.Length);
				bc.BlockDecrypt(buf);
			}
			switch (key.Length) {
			case 16:
				for (int k = 0; k < 16; k ++) {
					key[k] ^= buf[k];
				}
				break;
			case 24:
				for (int k = 0; k < 8; k ++) {
					key[k] ^= pbuf[8 + k];
				}
				for (int k = 0; k < 16; k ++) {
					key[8 + k] ^= buf[k];
				}
				break;
			case 32:
				for (int k = 0; k < 16; k ++) {
					key[k] ^= pbuf[k];
				}
				for (int k = 0; k < 16; k ++) {
					key[16 + k] ^= buf[k];
				}
				break;
			}
			Console.Write(".");
		}
		Console.Write(" ");
		CheckEq(buf, cipher, "MC AES decrypt");
	}

	static void DoMonteCarloDESEncrypt(IBlockCipher bc)
	{
		byte[] k1 = ToBin("9ec2372c86379df4");
		byte[] k2 = ToBin("ad7ac4464f73805d");
		byte[] k3 = ToBin("20c4f87564527c91");
		byte[] buf = ToBin("b624d6bd41783ab1");
		byte[] cipher = ToBin("eafd97b190b167fe");
		byte[] key = new byte[24];
		for (int i = 0; i < 400; i ++) {
			Array.Copy(k1, 0, key, 0, 8);
			Array.Copy(k2, 0, key, 8, 8);
			Array.Copy(k3, 0, key, 16, 8);
			bc.SetKey(key);
			for (int j = 0; j < 10000; j ++) {
				bc.BlockEncrypt(buf, 0);
				switch (j) {
				case 9997:
					for (int n = 0; n < 8; n ++) {
						k3[n] ^= buf[n];
					}
					break;
				case 9998:
					for (int n = 0; n < 8; n ++) {
						k2[n] ^= buf[n];
					}
					break;
				case 9999:
					for (int n = 0; n < 8; n ++) {
						k1[n] ^= buf[n];
					}
					break;
				}
			}
			Console.Write(".");
		}
		Console.Write(" ");
		CheckEq(buf, cipher, "MC DES encrypt");
	}

	static void DoMonteCarloDESDecrypt(IBlockCipher bc)
	{
		byte[] k1 = ToBin("79b63486e0ce37e0");
		byte[] k2 = ToBin("08e65231abae3710");
		byte[] k3 = ToBin("1f5eb69e925ef185");
		byte[] buf = ToBin("2783aa729432fe96");
		byte[] cipher = ToBin("44937ca532cdbf98");
		byte[] key = new byte[24];
		for (int i = 0; i < 400; i ++) {
			Array.Copy(k1, 0, key, 0, 8);
			Array.Copy(k2, 0, key, 8, 8);
			Array.Copy(k3, 0, key, 16, 8);
			bc.SetKey(key);
			for (int j = 0; j < 10000; j ++) {
				bc.BlockDecrypt(buf, 0);
				switch (j) {
				case 9997:
					for (int n = 0; n < 8; n ++) {
						k3[n] ^= buf[n];
					}
					break;
				case 9998:
					for (int n = 0; n < 8; n ++) {
						k2[n] ^= buf[n];
					}
					break;
				case 9999:
					for (int n = 0; n < 8; n ++) {
						k1[n] ^= buf[n];
					}
					break;
				}
			}
			Console.Write(".");
		}
		Console.Write(" ");
		CheckEq(buf, cipher, "MC DES decrypt");
	}

	static bool Eq(byte[] a1, byte[] a2)
	{
		if (a1 == a2) {
			return true;
		}
		if (a1 == null || a2 == null) {
			return false;
		}
		int n = a1.Length;
		if (n != a2.Length) {
			return false;
		}
		for (int i = 0; i < n; i ++) {
			if (a1[i] != a2[i]) {
				return false;
			}
		}
		return true;
	}

	static bool Eq(byte[] a1, int off1, byte[] a2, int off2, int len)
	{
		for (int i = 0; i < len; i ++) {
			if (a1[off1 + i] != a2[off1 + i]) {
				return false;
			}
		}
		return true;
	}

	static void CheckEq(byte[] a1, byte[] a2, string msg)
	{
		if (Eq(a1, a2)) {
			return;
		}
		throw new Exception(string.Format(
			"Not equal ({0}):\nv1 = {1}\nv2 = {2}",
			msg, ToHex(a1), ToHex(a2)));
	}

	static void CheckEq(byte[] a1, int off1,
		byte[] a2, int off2, int len, string msg)
	{
		if (Eq(a1, off1, a2, off2, len)) {
			return;
		}
		throw new Exception(string.Format(
			"Not equal ({0}):\nv1 = {1}\nv2 = {2}",
			msg, ToHex(a1, off1, len), ToHex(a2, off2, len)));
	}

	static byte[] ToBin(string str)
	{
		MemoryStream ms = new MemoryStream();
		bool z = true;
		int acc = 0;
		foreach (char c in str) {
			int d;
			if (c >= '0' && c <= '9') {
				d = c - '0';
			} else if (c >= 'A' && c <= 'F') {
				d = c - ('A' - 10);
			} else if (c >= 'a' && c <= 'f') {
				d = c - ('a' - 10);
			} else if (c == ' ' || c == '\t' || c == ':') {
				continue;
			} else {
				throw new ArgumentException(String.Format(
					"not hex: U+{0:X4}", (int)c));
			}
			if (z) {
				acc = d;
			} else {
				ms.WriteByte((byte)((acc << 4) + d));
			}
			z = !z;
		}
		if (!z) {
			throw new ArgumentException("final half byte");
		}
		return ms.ToArray();
	}

	static string ToHex(byte[] buf)
	{
		return ToHex(buf, 0, buf.Length);
	}

	static string ToHex(byte[] buf, int off, int len)
	{
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < len; i ++) {
			sb.AppendFormat("{0:X2}", buf[off + i]);
		}
		return sb.ToString();
	}

	static string[] KAT_MD5 = {
		"",
		"d41d8cd98f00b204e9800998ecf8427e",
		"a",
		"0cc175b9c0f1b6a831c399e269772661",
		"abc",
		"900150983cd24fb0d6963f7d28e17f72",
		"message digest",
		"f96b697d7cb7938d525a2f31aaf161d0",
		"abcdefghijklmnopqrstuvwxyz",
		"c3fcd3d76192e4007dfb496cca67e13b",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		"d174ab98d277d9f5a5611c2c9f419d9f",
		"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
		"57edf4a22be3c955ac49da2e2107b67a"
	};

	static string[] KAT_SHA1 = {
		"abc",
		"a9993e364706816aba3e25717850c26c9cd0d89d",
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		"84983e441c3bd26ebaae4aa1f95129e5e54670f1"
	};

	static string[] KAT_SHA224 = {
		"abc",
		"23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		"75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
	};

	static string[] KAT_SHA256 = {
		"abc",
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
	};

	static string[] KAT_SHA384 = {
		"abc",
		"cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
		"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		"09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
	};

	static string[] KAT_SHA512 = {
		"abc",
		"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
		"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		"8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
	};

	/*
	 * AES known-answer tests.
	 * Order: key, plaintext, ciphertext.
	 */
	static string[] KAT_AES_RAW = {
		/*
		 * From FIPS-197.
		 */
		"000102030405060708090a0b0c0d0e0f",
		"00112233445566778899aabbccddeeff",
		"69c4e0d86a7b0430d8cdb78070b4c55a",

		"000102030405060708090a0b0c0d0e0f1011121314151617",
		"00112233445566778899aabbccddeeff",
		"dda97ca4864cdfe06eaf70a0ec0d7191",

		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"00112233445566778899aabbccddeeff",
		"8ea2b7ca516745bfeafc49904b496089",

		/*
		 * From NIST validation suite (ECBVarTxt128.rsp).
		 */
		"00000000000000000000000000000000",
		"80000000000000000000000000000000",
		"3ad78e726c1ec02b7ebfe92b23d9ec34",

		"00000000000000000000000000000000",
		"c0000000000000000000000000000000",
		"aae5939c8efdf2f04e60b9fe7117b2c2",

		"00000000000000000000000000000000",
		"e0000000000000000000000000000000",
		"f031d4d74f5dcbf39daaf8ca3af6e527",

		"00000000000000000000000000000000",
		"f0000000000000000000000000000000",
		"96d9fd5cc4f07441727df0f33e401a36",

		"00000000000000000000000000000000",
		"f8000000000000000000000000000000",
		"30ccdb044646d7e1f3ccea3dca08b8c0",

		"00000000000000000000000000000000",
		"fc000000000000000000000000000000",
		"16ae4ce5042a67ee8e177b7c587ecc82",

		"00000000000000000000000000000000",
		"fe000000000000000000000000000000",
		"b6da0bb11a23855d9c5cb1b4c6412e0a",

		"00000000000000000000000000000000",
		"ff000000000000000000000000000000",
		"db4f1aa530967d6732ce4715eb0ee24b",

		"00000000000000000000000000000000",
		"ff800000000000000000000000000000",
		"a81738252621dd180a34f3455b4baa2f",

		"00000000000000000000000000000000",
		"ffc00000000000000000000000000000",
		"77e2b508db7fd89234caf7939ee5621a",

		"00000000000000000000000000000000",
		"ffe00000000000000000000000000000",
		"b8499c251f8442ee13f0933b688fcd19",

		"00000000000000000000000000000000",
		"fff00000000000000000000000000000",
		"965135f8a81f25c9d630b17502f68e53",

		"00000000000000000000000000000000",
		"fff80000000000000000000000000000",
		"8b87145a01ad1c6cede995ea3670454f",

		"00000000000000000000000000000000",
		"fffc0000000000000000000000000000",
		"8eae3b10a0c8ca6d1d3b0fa61e56b0b2",

		"00000000000000000000000000000000",
		"fffe0000000000000000000000000000",
		"64b4d629810fda6bafdf08f3b0d8d2c5",

		"00000000000000000000000000000000",
		"ffff0000000000000000000000000000",
		"d7e5dbd3324595f8fdc7d7c571da6c2a",

		"00000000000000000000000000000000",
		"ffff8000000000000000000000000000",
		"f3f72375264e167fca9de2c1527d9606",

		"00000000000000000000000000000000",
		"ffffc000000000000000000000000000",
		"8ee79dd4f401ff9b7ea945d86666c13b",

		"00000000000000000000000000000000",
		"ffffe000000000000000000000000000",
		"dd35cea2799940b40db3f819cb94c08b",

		"00000000000000000000000000000000",
		"fffff000000000000000000000000000",
		"6941cb6b3e08c2b7afa581ebdd607b87",

		"00000000000000000000000000000000",
		"fffff800000000000000000000000000",
		"2c20f439f6bb097b29b8bd6d99aad799",

		"00000000000000000000000000000000",
		"fffffc00000000000000000000000000",
		"625d01f058e565f77ae86378bd2c49b3",

		"00000000000000000000000000000000",
		"fffffe00000000000000000000000000",
		"c0b5fd98190ef45fbb4301438d095950",

		"00000000000000000000000000000000",
		"ffffff00000000000000000000000000",
		"13001ff5d99806efd25da34f56be854b",

		"00000000000000000000000000000000",
		"ffffff80000000000000000000000000",
		"3b594c60f5c8277a5113677f94208d82",

		"00000000000000000000000000000000",
		"ffffffc0000000000000000000000000",
		"e9c0fc1818e4aa46bd2e39d638f89e05",

		"00000000000000000000000000000000",
		"ffffffe0000000000000000000000000",
		"f8023ee9c3fdc45a019b4e985c7e1a54",

		"00000000000000000000000000000000",
		"fffffff0000000000000000000000000",
		"35f40182ab4662f3023baec1ee796b57",

		"00000000000000000000000000000000",
		"fffffff8000000000000000000000000",
		"3aebbad7303649b4194a6945c6cc3694",

		"00000000000000000000000000000000",
		"fffffffc000000000000000000000000",
		"a2124bea53ec2834279bed7f7eb0f938",

		"00000000000000000000000000000000",
		"fffffffe000000000000000000000000",
		"b9fb4399fa4facc7309e14ec98360b0a",

		"00000000000000000000000000000000",
		"ffffffff000000000000000000000000",
		"c26277437420c5d634f715aea81a9132",

		"00000000000000000000000000000000",
		"ffffffff800000000000000000000000",
		"171a0e1b2dd424f0e089af2c4c10f32f",

		"00000000000000000000000000000000",
		"ffffffffc00000000000000000000000",
		"7cadbe402d1b208fe735edce00aee7ce",

		"00000000000000000000000000000000",
		"ffffffffe00000000000000000000000",
		"43b02ff929a1485af6f5c6d6558baa0f",

		"00000000000000000000000000000000",
		"fffffffff00000000000000000000000",
		"092faacc9bf43508bf8fa8613ca75dea",

		"00000000000000000000000000000000",
		"fffffffff80000000000000000000000",
		"cb2bf8280f3f9742c7ed513fe802629c",

		"00000000000000000000000000000000",
		"fffffffffc0000000000000000000000",
		"215a41ee442fa992a6e323986ded3f68",

		"00000000000000000000000000000000",
		"fffffffffe0000000000000000000000",
		"f21e99cf4f0f77cea836e11a2fe75fb1",

		"00000000000000000000000000000000",
		"ffffffffff0000000000000000000000",
		"95e3a0ca9079e646331df8b4e70d2cd6",

		"00000000000000000000000000000000",
		"ffffffffff8000000000000000000000",
		"4afe7f120ce7613f74fc12a01a828073",

		"00000000000000000000000000000000",
		"ffffffffffc000000000000000000000",
		"827f000e75e2c8b9d479beed913fe678",

		"00000000000000000000000000000000",
		"ffffffffffe000000000000000000000",
		"35830c8e7aaefe2d30310ef381cbf691",

		"00000000000000000000000000000000",
		"fffffffffff000000000000000000000",
		"191aa0f2c8570144f38657ea4085ebe5",

		"00000000000000000000000000000000",
		"fffffffffff800000000000000000000",
		"85062c2c909f15d9269b6c18ce99c4f0",

		"00000000000000000000000000000000",
		"fffffffffffc00000000000000000000",
		"678034dc9e41b5a560ed239eeab1bc78",

		"00000000000000000000000000000000",
		"fffffffffffe00000000000000000000",
		"c2f93a4ce5ab6d5d56f1b93cf19911c1",

		"00000000000000000000000000000000",
		"ffffffffffff00000000000000000000",
		"1c3112bcb0c1dcc749d799743691bf82",

		"00000000000000000000000000000000",
		"ffffffffffff80000000000000000000",
		"00c55bd75c7f9c881989d3ec1911c0d4",

		"00000000000000000000000000000000",
		"ffffffffffffc0000000000000000000",
		"ea2e6b5ef182b7dff3629abd6a12045f",

		"00000000000000000000000000000000",
		"ffffffffffffe0000000000000000000",
		"22322327e01780b17397f24087f8cc6f",

		"00000000000000000000000000000000",
		"fffffffffffff0000000000000000000",
		"c9cacb5cd11692c373b2411768149ee7",

		"00000000000000000000000000000000",
		"fffffffffffff8000000000000000000",
		"a18e3dbbca577860dab6b80da3139256",

		"00000000000000000000000000000000",
		"fffffffffffffc000000000000000000",
		"79b61c37bf328ecca8d743265a3d425c",

		"00000000000000000000000000000000",
		"fffffffffffffe000000000000000000",
		"d2d99c6bcc1f06fda8e27e8ae3f1ccc7",

		"00000000000000000000000000000000",
		"ffffffffffffff000000000000000000",
		"1bfd4b91c701fd6b61b7f997829d663b",

		"00000000000000000000000000000000",
		"ffffffffffffff800000000000000000",
		"11005d52f25f16bdc9545a876a63490a",

		"00000000000000000000000000000000",
		"ffffffffffffffc00000000000000000",
		"3a4d354f02bb5a5e47d39666867f246a",

		"00000000000000000000000000000000",
		"ffffffffffffffe00000000000000000",
		"d451b8d6e1e1a0ebb155fbbf6e7b7dc3",

		"00000000000000000000000000000000",
		"fffffffffffffff00000000000000000",
		"6898d4f42fa7ba6a10ac05e87b9f2080",

		"00000000000000000000000000000000",
		"fffffffffffffff80000000000000000",
		"b611295e739ca7d9b50f8e4c0e754a3f",

		"00000000000000000000000000000000",
		"fffffffffffffffc0000000000000000",
		"7d33fc7d8abe3ca1936759f8f5deaf20",

		"00000000000000000000000000000000",
		"fffffffffffffffe0000000000000000",
		"3b5e0f566dc96c298f0c12637539b25c",

		"00000000000000000000000000000000",
		"ffffffffffffffff0000000000000000",
		"f807c3e7985fe0f5a50e2cdb25c5109e",

		"00000000000000000000000000000000",
		"ffffffffffffffff8000000000000000",
		"41f992a856fb278b389a62f5d274d7e9",

		"00000000000000000000000000000000",
		"ffffffffffffffffc000000000000000",
		"10d3ed7a6fe15ab4d91acbc7d0767ab1",

		"00000000000000000000000000000000",
		"ffffffffffffffffe000000000000000",
		"21feecd45b2e675973ac33bf0c5424fc",

		"00000000000000000000000000000000",
		"fffffffffffffffff000000000000000",
		"1480cb3955ba62d09eea668f7c708817",

		"00000000000000000000000000000000",
		"fffffffffffffffff800000000000000",
		"66404033d6b72b609354d5496e7eb511",

		"00000000000000000000000000000000",
		"fffffffffffffffffc00000000000000",
		"1c317a220a7d700da2b1e075b00266e1",

		"00000000000000000000000000000000",
		"fffffffffffffffffe00000000000000",
		"ab3b89542233f1271bf8fd0c0f403545",

		"00000000000000000000000000000000",
		"ffffffffffffffffff00000000000000",
		"d93eae966fac46dca927d6b114fa3f9e",

		"00000000000000000000000000000000",
		"ffffffffffffffffff80000000000000",
		"1bdec521316503d9d5ee65df3ea94ddf",

		"00000000000000000000000000000000",
		"ffffffffffffffffffc0000000000000",
		"eef456431dea8b4acf83bdae3717f75f",

		"00000000000000000000000000000000",
		"ffffffffffffffffffe0000000000000",
		"06f2519a2fafaa596bfef5cfa15c21b9",

		"00000000000000000000000000000000",
		"fffffffffffffffffff0000000000000",
		"251a7eac7e2fe809e4aa8d0d7012531a",

		"00000000000000000000000000000000",
		"fffffffffffffffffff8000000000000",
		"3bffc16e4c49b268a20f8d96a60b4058",

		"00000000000000000000000000000000",
		"fffffffffffffffffffc000000000000",
		"e886f9281999c5bb3b3e8862e2f7c988",

		"00000000000000000000000000000000",
		"fffffffffffffffffffe000000000000",
		"563bf90d61beef39f48dd625fcef1361",

		"00000000000000000000000000000000",
		"ffffffffffffffffffff000000000000",
		"4d37c850644563c69fd0acd9a049325b",

		"00000000000000000000000000000000",
		"ffffffffffffffffffff800000000000",
		"b87c921b91829ef3b13ca541ee1130a6",

		"00000000000000000000000000000000",
		"ffffffffffffffffffffc00000000000",
		"2e65eb6b6ea383e109accce8326b0393",

		"00000000000000000000000000000000",
		"ffffffffffffffffffffe00000000000",
		"9ca547f7439edc3e255c0f4d49aa8990",

		"00000000000000000000000000000000",
		"fffffffffffffffffffff00000000000",
		"a5e652614c9300f37816b1f9fd0c87f9",

		"00000000000000000000000000000000",
		"fffffffffffffffffffff80000000000",
		"14954f0b4697776f44494fe458d814ed",

		"00000000000000000000000000000000",
		"fffffffffffffffffffffc0000000000",
		"7c8d9ab6c2761723fe42f8bb506cbcf7",

		"00000000000000000000000000000000",
		"fffffffffffffffffffffe0000000000",
		"db7e1932679fdd99742aab04aa0d5a80",

		"00000000000000000000000000000000",
		"ffffffffffffffffffffff0000000000",
		"4c6a1c83e568cd10f27c2d73ded19c28",

		"00000000000000000000000000000000",
		"ffffffffffffffffffffff8000000000",
		"90ecbe6177e674c98de412413f7ac915",

		"00000000000000000000000000000000",
		"ffffffffffffffffffffffc000000000",
		"90684a2ac55fe1ec2b8ebd5622520b73",

		"00000000000000000000000000000000",
		"ffffffffffffffffffffffe000000000",
		"7472f9a7988607ca79707795991035e6",

		"00000000000000000000000000000000",
		"fffffffffffffffffffffff000000000",
		"56aff089878bf3352f8df172a3ae47d8",

		"00000000000000000000000000000000",
		"fffffffffffffffffffffff800000000",
		"65c0526cbe40161b8019a2a3171abd23",

		"00000000000000000000000000000000",
		"fffffffffffffffffffffffc00000000",
		"377be0be33b4e3e310b4aabda173f84f",

		"00000000000000000000000000000000",
		"fffffffffffffffffffffffe00000000",
		"9402e9aa6f69de6504da8d20c4fcaa2f",

		"00000000000000000000000000000000",
		"ffffffffffffffffffffffff00000000",
		"123c1f4af313ad8c2ce648b2e71fb6e1",

		"00000000000000000000000000000000",
		"ffffffffffffffffffffffff80000000",
		"1ffc626d30203dcdb0019fb80f726cf4",

		"00000000000000000000000000000000",
		"ffffffffffffffffffffffffc0000000",
		"76da1fbe3a50728c50fd2e621b5ad885",

		"00000000000000000000000000000000",
		"ffffffffffffffffffffffffe0000000",
		"082eb8be35f442fb52668e16a591d1d6",

		"00000000000000000000000000000000",
		"fffffffffffffffffffffffff0000000",
		"e656f9ecf5fe27ec3e4a73d00c282fb3",

		"00000000000000000000000000000000",
		"fffffffffffffffffffffffff8000000",
		"2ca8209d63274cd9a29bb74bcd77683a",

		"00000000000000000000000000000000",
		"fffffffffffffffffffffffffc000000",
		"79bf5dce14bb7dd73a8e3611de7ce026",

		"00000000000000000000000000000000",
		"fffffffffffffffffffffffffe000000",
		"3c849939a5d29399f344c4a0eca8a576",

		"00000000000000000000000000000000",
		"ffffffffffffffffffffffffff000000",
		"ed3c0a94d59bece98835da7aa4f07ca2",

		"00000000000000000000000000000000",
		"ffffffffffffffffffffffffff800000",
		"63919ed4ce10196438b6ad09d99cd795",

		"00000000000000000000000000000000",
		"ffffffffffffffffffffffffffc00000",
		"7678f3a833f19fea95f3c6029e2bc610",

		"00000000000000000000000000000000",
		"ffffffffffffffffffffffffffe00000",
		"3aa426831067d36b92be7c5f81c13c56",

		"00000000000000000000000000000000",
		"fffffffffffffffffffffffffff00000",
		"9272e2d2cdd11050998c845077a30ea0",

		"00000000000000000000000000000000",
		"fffffffffffffffffffffffffff80000",
		"088c4b53f5ec0ff814c19adae7f6246c",

		"00000000000000000000000000000000",
		"fffffffffffffffffffffffffffc0000",
		"4010a5e401fdf0a0354ddbcc0d012b17",

		"00000000000000000000000000000000",
		"fffffffffffffffffffffffffffe0000",
		"a87a385736c0a6189bd6589bd8445a93",

		"00000000000000000000000000000000",
		"ffffffffffffffffffffffffffff0000",
		"545f2b83d9616dccf60fa9830e9cd287",

		"00000000000000000000000000000000",
		"ffffffffffffffffffffffffffff8000",
		"4b706f7f92406352394037a6d4f4688d",

		"00000000000000000000000000000000",
		"ffffffffffffffffffffffffffffc000",
		"b7972b3941c44b90afa7b264bfba7387",

		"00000000000000000000000000000000",
		"ffffffffffffffffffffffffffffe000",
		"6f45732cf10881546f0fd23896d2bb60",

		"00000000000000000000000000000000",
		"fffffffffffffffffffffffffffff000",
		"2e3579ca15af27f64b3c955a5bfc30ba",

		"00000000000000000000000000000000",
		"fffffffffffffffffffffffffffff800",
		"34a2c5a91ae2aec99b7d1b5fa6780447",

		"00000000000000000000000000000000",
		"fffffffffffffffffffffffffffffc00",
		"a4d6616bd04f87335b0e53351227a9ee",

		"00000000000000000000000000000000",
		"fffffffffffffffffffffffffffffe00",
		"7f692b03945867d16179a8cefc83ea3f",

		"00000000000000000000000000000000",
		"ffffffffffffffffffffffffffffff00",
		"3bd141ee84a0e6414a26e7a4f281f8a2",

		"00000000000000000000000000000000",
		"ffffffffffffffffffffffffffffff80",
		"d1788f572d98b2b16ec5d5f3922b99bc",

		"00000000000000000000000000000000",
		"ffffffffffffffffffffffffffffffc0",
		"0833ff6f61d98a57b288e8c3586b85a6",

		"00000000000000000000000000000000",
		"ffffffffffffffffffffffffffffffe0",
		"8568261797de176bf0b43becc6285afb",

		"00000000000000000000000000000000",
		"fffffffffffffffffffffffffffffff0",
		"f9b0fda0c4a898f5b9e6f661c4ce4d07",

		"00000000000000000000000000000000",
		"fffffffffffffffffffffffffffffff8",
		"8ade895913685c67c5269f8aae42983e",

		"00000000000000000000000000000000",
		"fffffffffffffffffffffffffffffffc",
		"39bde67d5c8ed8a8b1c37eb8fa9f5ac0",

		"00000000000000000000000000000000",
		"fffffffffffffffffffffffffffffffe",
		"5c005e72c1418c44f569f2ea33ba54f3",

		"00000000000000000000000000000000",
		"ffffffffffffffffffffffffffffffff",
		"3f5b8cc9ea855a0afa7347d23e8d664e",

		/*
		 * From NIST validation suite (ECBVarTxt192.rsp).
		 */
		"000000000000000000000000000000000000000000000000",
		"80000000000000000000000000000000",
		"6cd02513e8d4dc986b4afe087a60bd0c",

		"000000000000000000000000000000000000000000000000",
		"c0000000000000000000000000000000",
		"2ce1f8b7e30627c1c4519eada44bc436",

		"000000000000000000000000000000000000000000000000",
		"e0000000000000000000000000000000",
		"9946b5f87af446f5796c1fee63a2da24",

		"000000000000000000000000000000000000000000000000",
		"f0000000000000000000000000000000",
		"2a560364ce529efc21788779568d5555",

		"000000000000000000000000000000000000000000000000",
		"f8000000000000000000000000000000",
		"35c1471837af446153bce55d5ba72a0a",

		"000000000000000000000000000000000000000000000000",
		"fc000000000000000000000000000000",
		"ce60bc52386234f158f84341e534cd9e",

		"000000000000000000000000000000000000000000000000",
		"fe000000000000000000000000000000",
		"8c7c27ff32bcf8dc2dc57c90c2903961",

		"000000000000000000000000000000000000000000000000",
		"ff000000000000000000000000000000",
		"32bb6a7ec84499e166f936003d55a5bb",

		"000000000000000000000000000000000000000000000000",
		"ff800000000000000000000000000000",
		"a5c772e5c62631ef660ee1d5877f6d1b",

		"000000000000000000000000000000000000000000000000",
		"ffc00000000000000000000000000000",
		"030d7e5b64f380a7e4ea5387b5cd7f49",

		"000000000000000000000000000000000000000000000000",
		"ffe00000000000000000000000000000",
		"0dc9a2610037009b698f11bb7e86c83e",

		"000000000000000000000000000000000000000000000000",
		"fff00000000000000000000000000000",
		"0046612c766d1840c226364f1fa7ed72",

		"000000000000000000000000000000000000000000000000",
		"fff80000000000000000000000000000",
		"4880c7e08f27befe78590743c05e698b",

		"000000000000000000000000000000000000000000000000",
		"fffc0000000000000000000000000000",
		"2520ce829a26577f0f4822c4ecc87401",

		"000000000000000000000000000000000000000000000000",
		"fffe0000000000000000000000000000",
		"8765e8acc169758319cb46dc7bcf3dca",

		"000000000000000000000000000000000000000000000000",
		"ffff0000000000000000000000000000",
		"e98f4ba4f073df4baa116d011dc24a28",

		"000000000000000000000000000000000000000000000000",
		"ffff8000000000000000000000000000",
		"f378f68c5dbf59e211b3a659a7317d94",

		"000000000000000000000000000000000000000000000000",
		"ffffc000000000000000000000000000",
		"283d3b069d8eb9fb432d74b96ca762b4",

		"000000000000000000000000000000000000000000000000",
		"ffffe000000000000000000000000000",
		"a7e1842e8a87861c221a500883245c51",

		"000000000000000000000000000000000000000000000000",
		"fffff000000000000000000000000000",
		"77aa270471881be070fb52c7067ce732",

		"000000000000000000000000000000000000000000000000",
		"fffff800000000000000000000000000",
		"01b0f476d484f43f1aeb6efa9361a8ac",

		"000000000000000000000000000000000000000000000000",
		"fffffc00000000000000000000000000",
		"1c3a94f1c052c55c2d8359aff2163b4f",

		"000000000000000000000000000000000000000000000000",
		"fffffe00000000000000000000000000",
		"e8a067b604d5373d8b0f2e05a03b341b",

		"000000000000000000000000000000000000000000000000",
		"ffffff00000000000000000000000000",
		"a7876ec87f5a09bfea42c77da30fd50e",

		"000000000000000000000000000000000000000000000000",
		"ffffff80000000000000000000000000",
		"0cf3e9d3a42be5b854ca65b13f35f48d",

		"000000000000000000000000000000000000000000000000",
		"ffffffc0000000000000000000000000",
		"6c62f6bbcab7c3e821c9290f08892dda",

		"000000000000000000000000000000000000000000000000",
		"ffffffe0000000000000000000000000",
		"7f5e05bd2068738196fee79ace7e3aec",

		"000000000000000000000000000000000000000000000000",
		"fffffff0000000000000000000000000",
		"440e0d733255cda92fb46e842fe58054",

		"000000000000000000000000000000000000000000000000",
		"fffffff8000000000000000000000000",
		"aa5d5b1c4ea1b7a22e5583ac2e9ed8a7",

		"000000000000000000000000000000000000000000000000",
		"fffffffc000000000000000000000000",
		"77e537e89e8491e8662aae3bc809421d",

		"000000000000000000000000000000000000000000000000",
		"fffffffe000000000000000000000000",
		"997dd3e9f1598bfa73f75973f7e93b76",

		"000000000000000000000000000000000000000000000000",
		"ffffffff000000000000000000000000",
		"1b38d4f7452afefcb7fc721244e4b72e",

		"000000000000000000000000000000000000000000000000",
		"ffffffff800000000000000000000000",
		"0be2b18252e774dda30cdda02c6906e3",

		"000000000000000000000000000000000000000000000000",
		"ffffffffc00000000000000000000000",
		"d2695e59c20361d82652d7d58b6f11b2",

		"000000000000000000000000000000000000000000000000",
		"ffffffffe00000000000000000000000",
		"902d88d13eae52089abd6143cfe394e9",

		"000000000000000000000000000000000000000000000000",
		"fffffffff00000000000000000000000",
		"d49bceb3b823fedd602c305345734bd2",

		"000000000000000000000000000000000000000000000000",
		"fffffffff80000000000000000000000",
		"707b1dbb0ffa40ef7d95def421233fae",

		"000000000000000000000000000000000000000000000000",
		"fffffffffc0000000000000000000000",
		"7ca0c1d93356d9eb8aa952084d75f913",

		"000000000000000000000000000000000000000000000000",
		"fffffffffe0000000000000000000000",
		"f2cbf9cb186e270dd7bdb0c28febc57d",

		"000000000000000000000000000000000000000000000000",
		"ffffffffff0000000000000000000000",
		"c94337c37c4e790ab45780bd9c3674a0",

		"000000000000000000000000000000000000000000000000",
		"ffffffffff8000000000000000000000",
		"8e3558c135252fb9c9f367ed609467a1",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffc000000000000000000000",
		"1b72eeaee4899b443914e5b3a57fba92",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffe000000000000000000000",
		"011865f91bc56868d051e52c9efd59b7",

		"000000000000000000000000000000000000000000000000",
		"fffffffffff000000000000000000000",
		"e4771318ad7a63dd680f6e583b7747ea",

		"000000000000000000000000000000000000000000000000",
		"fffffffffff800000000000000000000",
		"61e3d194088dc8d97e9e6db37457eac5",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffc00000000000000000000",
		"36ff1ec9ccfbc349e5d356d063693ad6",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffe00000000000000000000",
		"3cc9e9a9be8cc3f6fb2ea24088e9bb19",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffff00000000000000000000",
		"1ee5ab003dc8722e74905d9a8fe3d350",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffff80000000000000000000",
		"245339319584b0a412412869d6c2eada",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffc0000000000000000000",
		"7bd496918115d14ed5380852716c8814",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffe0000000000000000000",
		"273ab2f2b4a366a57d582a339313c8b1",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffff0000000000000000000",
		"113365a9ffbe3b0ca61e98507554168b",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffff8000000000000000000",
		"afa99c997ac478a0dea4119c9e45f8b1",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffc000000000000000000",
		"9216309a7842430b83ffb98638011512",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffe000000000000000000",
		"62abc792288258492a7cb45145f4b759",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffff000000000000000000",
		"534923c169d504d7519c15d30e756c50",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffff800000000000000000",
		"fa75e05bcdc7e00c273fa33f6ee441d2",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffc00000000000000000",
		"7d350fa6057080f1086a56b17ec240db",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffe00000000000000000",
		"f34e4a6324ea4a5c39a661c8fe5ada8f",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffff00000000000000000",
		"0882a16f44088d42447a29ac090ec17e",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffff80000000000000000",
		"3a3c15bfc11a9537c130687004e136ee",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffc0000000000000000",
		"22c0a7678dc6d8cf5c8a6d5a9960767c",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffe0000000000000000",
		"b46b09809d68b9a456432a79bdc2e38c",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffff0000000000000000",
		"93baaffb35fbe739c17c6ac22eecf18f",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffff8000000000000000",
		"c8aa80a7850675bc007c46df06b49868",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffc000000000000000",
		"12c6f3877af421a918a84b775858021d",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffe000000000000000",
		"33f123282c5d633924f7d5ba3f3cab11",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffff000000000000000",
		"a8f161002733e93ca4527d22c1a0c5bb",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffff800000000000000",
		"b72f70ebf3e3fda23f508eec76b42c02",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffc00000000000000",
		"6a9d965e6274143f25afdcfc88ffd77c",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffe00000000000000",
		"a0c74fd0b9361764ce91c5200b095357",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffff00000000000000",
		"091d1fdc2bd2c346cd5046a8c6209146",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffff80000000000000",
		"e2a37580116cfb71856254496ab0aca8",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffc0000000000000",
		"e0b3a00785917c7efc9adba322813571",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffe0000000000000",
		"733d41f4727b5ef0df4af4cf3cffa0cb",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffff0000000000000",
		"a99ebb030260826f981ad3e64490aa4f",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffff8000000000000",
		"73f34c7d3eae5e80082c1647524308ee",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffc000000000000",
		"40ebd5ad082345b7a2097ccd3464da02",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffe000000000000",
		"7cc4ae9a424b2cec90c97153c2457ec5",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffff000000000000",
		"54d632d03aba0bd0f91877ebdd4d09cb",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffff800000000000",
		"d3427be7e4d27cd54f5fe37b03cf0897",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffc00000000000",
		"b2099795e88cc158fd75ea133d7e7fbe",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffe00000000000",
		"a6cae46fb6fadfe7a2c302a34242817b",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffff00000000000",
		"026a7024d6a902e0b3ffccbaa910cc3f",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffff80000000000",
		"156f07767a85a4312321f63968338a01",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffc0000000000",
		"15eec9ebf42b9ca76897d2cd6c5a12e2",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffe0000000000",
		"db0d3a6fdcc13f915e2b302ceeb70fd8",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffff0000000000",
		"71dbf37e87a2e34d15b20e8f10e48924",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffff8000000000",
		"c745c451e96ff3c045e4367c833e3b54",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffc000000000",
		"340da09c2dd11c3b679d08ccd27dd595",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffe000000000",
		"8279f7c0c2a03ee660c6d392db025d18",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffff000000000",
		"a4b2c7d8eba531ff47c5041a55fbd1ec",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffff800000000",
		"74569a2ca5a7bd5131ce8dc7cbfbf72f",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffc00000000",
		"3713da0c0219b63454035613b5a403dd",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffe00000000",
		"8827551ddcc9df23fa72a3de4e9f0b07",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffff00000000",
		"2e3febfd625bfcd0a2c06eb460da1732",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffff80000000",
		"ee82e6ba488156f76496311da6941deb",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffc0000000",
		"4770446f01d1f391256e85a1b30d89d3",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffe0000000",
		"af04b68f104f21ef2afb4767cf74143c",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffff0000000",
		"cf3579a9ba38c8e43653173e14f3a4c6",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffff8000000",
		"b3bba904f4953e09b54800af2f62e7d4",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffc000000",
		"fc4249656e14b29eb9c44829b4c59a46",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffe000000",
		"9b31568febe81cfc2e65af1c86d1a308",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffff000000",
		"9ca09c25f273a766db98a480ce8dfedc",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffff800000",
		"b909925786f34c3c92d971883c9fbedf",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffc00000",
		"82647f1332fe570a9d4d92b2ee771d3b",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffe00000",
		"3604a7e80832b3a99954bca6f5b9f501",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffff00000",
		"884607b128c5de3ab39a529a1ef51bef",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffff80000",
		"670cfa093d1dbdb2317041404102435e",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffffc0000",
		"7a867195f3ce8769cbd336502fbb5130",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffffe0000",
		"52efcf64c72b2f7ca5b3c836b1078c15",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffff0000",
		"4019250f6eefb2ac5ccbcae044e75c7e",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffff8000",
		"022c4f6f5a017d292785627667ddef24",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffffc000",
		"e9c21078a2eb7e03250f71000fa9e3ed",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffffe000",
		"a13eaeeb9cd391da4e2b09490b3e7fad",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffffff000",
		"c958a171dca1d4ed53e1af1d380803a9",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffffff800",
		"21442e07a110667f2583eaeeee44dc8c",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffffffc00",
		"59bbb353cf1dd867a6e33737af655e99",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffffffe00",
		"43cd3b25375d0ce41087ff9fe2829639",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffffff00",
		"6b98b17e80d1118e3516bd768b285a84",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffffff80",
		"ae47ed3676ca0c08deea02d95b81db58",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffffffc0",
		"34ec40dc20413795ed53628ea748720b",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffffffe0",
		"4dc68163f8e9835473253542c8a65d46",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffffffff0",
		"2aabb999f43693175af65c6c612c46fb",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffffffff8",
		"e01f94499dac3547515c5b1d756f0f58",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffffffffc",
		"9d12435a46480ce00ea349f71799df9a",

		"000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffffffffe",
		"cef41d16d266bdfe46938ad7884cc0cf",

		"000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffffffff",
		"b13db4da1f718bc6904797c82bcf2d32",

		/*
		 * From NIST validation suite (ECBVarTxt256.rsp).
		 */
		"0000000000000000000000000000000000000000000000000000000000000000",
		"80000000000000000000000000000000",
		"ddc6bf790c15760d8d9aeb6f9a75fd4e",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"c0000000000000000000000000000000",
		"0a6bdc6d4c1e6280301fd8e97ddbe601",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"e0000000000000000000000000000000",
		"9b80eefb7ebe2d2b16247aa0efc72f5d",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"f0000000000000000000000000000000",
		"7f2c5ece07a98d8bee13c51177395ff7",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"f8000000000000000000000000000000",
		"7818d800dcf6f4be1e0e94f403d1e4c2",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fc000000000000000000000000000000",
		"e74cd1c92f0919c35a0324123d6177d3",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fe000000000000000000000000000000",
		"8092a4dcf2da7e77e93bdd371dfed82e",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ff000000000000000000000000000000",
		"49af6b372135acef10132e548f217b17",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ff800000000000000000000000000000",
		"8bcd40f94ebb63b9f7909676e667f1e7",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffc00000000000000000000000000000",
		"fe1cffb83f45dcfb38b29be438dbd3ab",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffe00000000000000000000000000000",
		"0dc58a8d886623705aec15cb1e70dc0e",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fff00000000000000000000000000000",
		"c218faa16056bd0774c3e8d79c35a5e4",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fff80000000000000000000000000000",
		"047bba83f7aa841731504e012208fc9e",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffc0000000000000000000000000000",
		"dc8f0e4915fd81ba70a331310882f6da",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffe0000000000000000000000000000",
		"1569859ea6b7206c30bf4fd0cbfac33c",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffff0000000000000000000000000000",
		"300ade92f88f48fa2df730ec16ef44cd",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffff8000000000000000000000000000",
		"1fe6cc3c05965dc08eb0590c95ac71d0",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffc000000000000000000000000000",
		"59e858eaaa97fec38111275b6cf5abc0",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffe000000000000000000000000000",
		"2239455e7afe3b0616100288cc5a723b",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffff000000000000000000000000000",
		"3ee500c5c8d63479717163e55c5c4522",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffff800000000000000000000000000",
		"d5e38bf15f16d90e3e214041d774daa8",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffc00000000000000000000000000",
		"b1f4066e6f4f187dfe5f2ad1b17819d0",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffe00000000000000000000000000",
		"6ef4cc4de49b11065d7af2909854794a",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffff00000000000000000000000000",
		"ac86bc606b6640c309e782f232bf367f",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffff80000000000000000000000000",
		"36aff0ef7bf3280772cf4cac80a0d2b2",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffc0000000000000000000000000",
		"1f8eedea0f62a1406d58cfc3ecea72cf",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffe0000000000000000000000000",
		"abf4154a3375a1d3e6b1d454438f95a6",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffff0000000000000000000000000",
		"96f96e9d607f6615fc192061ee648b07",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffff8000000000000000000000000",
		"cf37cdaaa0d2d536c71857634c792064",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffc000000000000000000000000",
		"fbd6640c80245c2b805373f130703127",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffe000000000000000000000000",
		"8d6a8afe55a6e481badae0d146f436db",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffff000000000000000000000000",
		"6a4981f2915e3e68af6c22385dd06756",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffff800000000000000000000000",
		"42a1136e5f8d8d21d3101998642d573b",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffc00000000000000000000000",
		"9b471596dc69ae1586cee6158b0b0181",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffe00000000000000000000000",
		"753665c4af1eff33aa8b628bf8741cfd",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffff00000000000000000000000",
		"9a682acf40be01f5b2a4193c9a82404d",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffff80000000000000000000000",
		"54fafe26e4287f17d1935f87eb9ade01",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffc0000000000000000000000",
		"49d541b2e74cfe73e6a8e8225f7bd449",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffe0000000000000000000000",
		"11a45530f624ff6f76a1b3826626ff7b",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffff0000000000000000000000",
		"f96b0c4a8bc6c86130289f60b43b8fba",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffff8000000000000000000000",
		"48c7d0e80834ebdc35b6735f76b46c8b",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffc000000000000000000000",
		"2463531ab54d66955e73edc4cb8eaa45",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffe000000000000000000000",
		"ac9bd8e2530469134b9d5b065d4f565b",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffff000000000000000000000",
		"3f5f9106d0e52f973d4890e6f37e8a00",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffff800000000000000000000",
		"20ebc86f1304d272e2e207e59db639f0",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffc00000000000000000000",
		"e67ae6426bf9526c972cff072b52252c",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffe00000000000000000000",
		"1a518dddaf9efa0d002cc58d107edfc8",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffff00000000000000000000",
		"ead731af4d3a2fe3b34bed047942a49f",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffff80000000000000000000",
		"b1d4efe40242f83e93b6c8d7efb5eae9",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffc0000000000000000000",
		"cd2b1fec11fd906c5c7630099443610a",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffe0000000000000000000",
		"a1853fe47fe29289d153161d06387d21",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffff0000000000000000000",
		"4632154179a555c17ea604d0889fab14",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffff8000000000000000000",
		"dd27cac6401a022e8f38f9f93e774417",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffc000000000000000000",
		"c090313eb98674f35f3123385fb95d4d",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffe000000000000000000",
		"cc3526262b92f02edce548f716b9f45c",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffff000000000000000000",
		"c0838d1a2b16a7c7f0dfcc433c399c33",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffff800000000000000000",
		"0d9ac756eb297695eed4d382eb126d26",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffc00000000000000000",
		"56ede9dda3f6f141bff1757fa689c3e1",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffe00000000000000000",
		"768f520efe0f23e61d3ec8ad9ce91774",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffff00000000000000000",
		"b1144ddfa75755213390e7c596660490",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffff80000000000000000",
		"1d7c0c4040b355b9d107a99325e3b050",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffc0000000000000000",
		"d8e2bb1ae8ee3dcf5bf7d6c38da82a1a",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffe0000000000000000",
		"faf82d178af25a9886a47e7f789b98d7",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffff0000000000000000",
		"9b58dbfd77fe5aca9cfc190cd1b82d19",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffff8000000000000000",
		"77f392089042e478ac16c0c86a0b5db5",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffc000000000000000",
		"19f08e3420ee69b477ca1420281c4782",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffe000000000000000",
		"a1b19beee4e117139f74b3c53fdcb875",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffff000000000000000",
		"a37a5869b218a9f3a0868d19aea0ad6a",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffff800000000000000",
		"bc3594e865bcd0261b13202731f33580",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffc00000000000000",
		"811441ce1d309eee7185e8c752c07557",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffe00000000000000",
		"959971ce4134190563518e700b9874d1",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffff00000000000000",
		"76b5614a042707c98e2132e2e805fe63",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffff80000000000000",
		"7d9fa6a57530d0f036fec31c230b0cc6",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffc0000000000000",
		"964153a83bf6989a4ba80daa91c3e081",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffe0000000000000",
		"a013014d4ce8054cf2591d06f6f2f176",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffff0000000000000",
		"d1c5f6399bf382502e385eee1474a869",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffff8000000000000",
		"0007e20b8298ec354f0f5fe7470f36bd",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffc000000000000",
		"b95ba05b332da61ef63a2b31fcad9879",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffe000000000000",
		"4620a49bd967491561669ab25dce45f4",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffff000000000000",
		"12e71214ae8e04f0bb63d7425c6f14d5",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffff800000000000",
		"4cc42fc1407b008fe350907c092e80ac",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffc00000000000",
		"08b244ce7cbc8ee97fbba808cb146fda",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffe00000000000",
		"39b333e8694f21546ad1edd9d87ed95b",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffff00000000000",
		"3b271f8ab2e6e4a20ba8090f43ba78f3",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffff80000000000",
		"9ad983f3bf651cd0393f0a73cccdea50",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffc0000000000",
		"8f476cbff75c1f725ce18e4bbcd19b32",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffe0000000000",
		"905b6267f1d6ab5320835a133f096f2a",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffff0000000000",
		"145b60d6d0193c23f4221848a892d61a",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffff8000000000",
		"55cfb3fb6d75cad0445bbc8dafa25b0f",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffc000000000",
		"7b8e7098e357ef71237d46d8b075b0f5",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffe000000000",
		"2bf27229901eb40f2df9d8398d1505ae",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffff000000000",
		"83a63402a77f9ad5c1e931a931ecd706",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffff800000000",
		"6f8ba6521152d31f2bada1843e26b973",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffc00000000",
		"e5c3b8e30fd2d8e6239b17b44bd23bbd",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffe00000000",
		"1ac1f7102c59933e8b2ddc3f14e94baa",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffff00000000",
		"21d9ba49f276b45f11af8fc71a088e3d",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffff80000000",
		"649f1cddc3792b4638635a392bc9bade",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffc0000000",
		"e2775e4b59c1bc2e31a2078c11b5a08c",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffe0000000",
		"2be1fae5048a25582a679ca10905eb80",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffff0000000",
		"da86f292c6f41ea34fb2068df75ecc29",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffff8000000",
		"220df19f85d69b1b562fa69a3c5beca5",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffc000000",
		"1f11d5d0355e0b556ccdb6c7f5083b4d",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffe000000",
		"62526b78be79cb384633c91f83b4151b",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffff000000",
		"90ddbcb950843592dd47bbef00fdc876",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffff800000",
		"2fd0e41c5b8402277354a7391d2618e2",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffc00000",
		"3cdf13e72dee4c581bafec70b85f9660",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffe00000",
		"afa2ffc137577092e2b654fa199d2c43",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffff00000",
		"8d683ee63e60d208e343ce48dbc44cac",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffff80000",
		"705a4ef8ba2133729c20185c3d3a4763",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffffc0000",
		"0861a861c3db4e94194211b77ed761b9",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffffe0000",
		"4b00c27e8b26da7eab9d3a88dec8b031",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffff0000",
		"5f397bf03084820cc8810d52e5b666e9",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffff8000",
		"63fafabb72c07bfbd3ddc9b1203104b8",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffffc000",
		"683e2140585b18452dd4ffbb93c95df9",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffffe000",
		"286894e48e537f8763b56707d7d155c8",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffffff000",
		"a423deabc173dcf7e2c4c53e77d37cd1",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffffff800",
		"eb8168313e1cfdfdb5e986d5429cf172",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffffffc00",
		"27127daafc9accd2fb334ec3eba52323",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffffffe00",
		"ee0715b96f72e3f7a22a5064fc592f4c",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffffff00",
		"29ee526770f2a11dcfa989d1ce88830f",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffffff80",
		"0493370e054b09871130fe49af730a5a",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffffffc0",
		"9b7b940f6c509f9e44a4ee140448ee46",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffffffe0",
		"2915be4a1ecfdcbe3e023811a12bb6c7",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffffffff0",
		"7240e524bc51d8c4d440b1be55d1062c",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffffffff8",
		"da63039d38cb4612b2dc36ba26684b93",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffffffffc",
		"0f59cb5a4b522e2ac56c1a64f558ad9a",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"fffffffffffffffffffffffffffffffe",
		"7bfe9d876c6d63c1d035da8fe21c409d",

		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffffffff",
		"acdace8078a32b1a182bfa4987ca1347"
	};

	/*
	 * AES known-answer tests for CBC.
	 * Order: key, IV, plaintext, ciphertext.
	 */
	static string[] KAT_AES_CBC = {
		/*
		 * From NIST validation suite "Multiblock Message Test"
		 * (cbcmmt128.rsp).
		 */
		"1f8e4973953f3fb0bd6b16662e9a3c17",
		"2fe2b333ceda8f98f4a99b40d2cd34a8",
		"45cf12964fc824ab76616ae2f4bf0822",
		"0f61c4d44c5147c03c195ad7e2cc12b2",

		"0700d603a1c514e46b6191ba430a3a0c",
		"aad1583cd91365e3bb2f0c3430d065bb",
		"068b25c7bfb1f8bdd4cfc908f69dffc5ddc726a197f0e5f720f730393279be91",
		"c4dc61d9725967a3020104a9738f23868527ce839aab1752fd8bdb95a82c4d00",

		"3348aa51e9a45c2dbe33ccc47f96e8de",
		"19153c673160df2b1d38c28060e59b96",
		"9b7cee827a26575afdbb7c7a329f887238052e3601a7917456ba61251c214763d5e1847a6ad5d54127a399ab07ee3599",
		"d5aed6c9622ec451a15db12819952b6752501cf05cdbf8cda34a457726ded97818e1f127a28d72db5652749f0c6afee5",

		"b7f3c9576e12dd0db63e8f8fac2b9a39",
		"c80f095d8bb1a060699f7c19974a1aa0",
		"9ac19954ce1319b354d3220460f71c1e373f1cd336240881160cfde46ebfed2e791e8d5a1a136ebd1dc469dec00c4187722b841cdabcb22c1be8a14657da200e",
		"19b9609772c63f338608bf6eb52ca10be65097f89c1e0905c42401fd47791ae2c5440b2d473116ca78bd9ff2fb6015cfd316524eae7dcb95ae738ebeae84a467",

		"b6f9afbfe5a1562bba1368fc72ac9d9c",
		"3f9d5ebe250ee7ce384b0d00ee849322",
		"db397ec22718dbffb9c9d13de0efcd4611bf792be4fce0dc5f25d4f577ed8cdbd4eb9208d593dda3d4653954ab64f05676caa3ce9bfa795b08b67ceebc923fdc89a8c431188e9e482d8553982cf304d1",
		"10ea27b19e16b93af169c4a88e06e35c99d8b420980b058e34b4b8f132b13766f72728202b089f428fecdb41c79f8aa0d0ef68f5786481cca29e2126f69bc14160f1ae2187878ba5c49cf3961e1b7ee9",

		"bbe7b7ba07124ff1ae7c3416fe8b465e",
		"7f65b5ee3630bed6b84202d97fb97a1e",
		"2aad0c2c4306568bad7447460fd3dac054346d26feddbc9abd9110914011b4794be2a9a00a519a51a5b5124014f4ed2735480db21b434e99a911bb0b60fe0253763725b628d5739a5117b7ee3aefafc5b4c1bf446467e7bf5f78f31ff7caf187",
		"3b8611bfc4973c5cd8e982b073b33184cd26110159172e44988eb5ff5661a1e16fad67258fcbfee55469267a12dc374893b4e3533d36f5634c3095583596f135aa8cd1138dc898bc5651ee35a92ebf89ab6aeb5366653bc60a70e0074fc11efe",

		"89a553730433f7e6d67d16d373bd5360",
		"f724558db3433a523f4e51a5bea70497",
		"807bc4ea684eedcfdcca30180680b0f1ae2814f35f36d053c5aea6595a386c1442770f4d7297d8b91825ee7237241da8925dd594ccf676aecd46ca2068e8d37a3a0ec8a7d5185a201e663b5ff36ae197110188a23503763b8218826d23ced74b31e9f6e2d7fbfa6cb43420c7807a8625",
		"406af1429a478c3d07e555c5287a60500d37fc39b68e5bbb9bafd6ddb223828561d6171a308d5b1a4551e8a5e7d572918d25c968d3871848d2f16635caa9847f38590b1df58ab5efb985f2c66cfaf86f61b3f9c0afad6c963c49cee9b8bc81a2ddb06c967f325515a4849eec37ce721a",

		"c491ca31f91708458e29a925ec558d78",
		"9ef934946e5cd0ae97bd58532cb49381",
		"cb6a787e0dec56f9a165957f81af336ca6b40785d9e94093c6190e5152649f882e874d79ac5e167bd2a74ce5ae088d2ee854f6539e0a94796b1e1bd4c9fcdbc79acbef4d01eeb89776d18af71ae2a4fc47dd66df6c4dbe1d1850e466549a47b636bcc7c2b3a62495b56bb67b6d455f1eebd9bfefecbca6c7f335cfce9b45cb9d",
		"7b2931f5855f717145e00f152a9f4794359b1ffcb3e55f594e33098b51c23a6c74a06c1d94fded7fd2ae42c7db7acaef5844cb33aeddc6852585ed0020a6699d2cb53809cefd169148ce42292afab063443978306c582c18b9ce0da3d084ce4d3c482cfd8fcf1a85084e89fb88b40a084d5e972466d07666126fb761f84078f2",

		"f6e87d71b0104d6eb06a68dc6a71f498",
		"1c245f26195b76ebebc2edcac412a2f8",
		"f82bef3c73a6f7f80db285726d691db6bf55eec25a859d3ba0e0445f26b9bb3b16a3161ed1866e4dd8f2e5f8ecb4e46d74a7a78c20cdfc7bcc9e479ba7a0caba9438238ad0c01651d5d98de37f03ddce6e6b4bd4ab03cf9e8ed818aedfa1cf963b932067b97d776dce1087196e7e913f7448e38244509f0caf36bd8217e15336d35c149fd4e41707893fdb84014f8729",
		"b09512f3eff9ed0d85890983a73dadbb7c3678d52581be64a8a8fc586f490f2521297a478a0598040ebd0f5509fafb0969f9d9e600eaef33b1b93eed99687b167f89a5065aac439ce46f3b8d22d30865e64e45ef8cd30b6984353a844a11c8cd60dba0e8866b3ee30d24b3fa8a643b328353e06010fa8273c8fd54ef0a2b6930e5520aae5cd5902f9b86a33592ca4365",

		"2c14413751c31e2730570ba3361c786b",
		"1dbbeb2f19abb448af849796244a19d7",
		"40d930f9a05334d9816fe204999c3f82a03f6a0457a8c475c94553d1d116693adc618049f0a769a2eed6a6cb14c0143ec5cccdbc8dec4ce560cfd206225709326d4de7948e54d603d01b12d7fed752fb23f1aa4494fbb00130e9ded4e77e37c079042d828040c325b1a5efd15fc842e44014ca4374bf38f3c3fc3ee327733b0c8aee1abcd055772f18dc04603f7b2c1ea69ff662361f2be0a171bbdcea1e5d3f",
		"6be8a12800455a320538853e0cba31bd2d80ea0c85164a4c5c261ae485417d93effe2ebc0d0a0b51d6ea18633d210cf63c0c4ddbc27607f2e81ed9113191ef86d56f3b99be6c415a4150299fb846ce7160b40b63baf1179d19275a2e83698376d28b92548c68e06e6d994e2c1501ed297014e702cdefee2f656447706009614d801de1caaf73f8b7fa56cf1ba94b631933bbe577624380850f117435a0355b2b",

		/*
		 * From NIST validation suite "Multiblock Message Test"
		 * (cbcmmt192.rsp).
		 */
		"ba75f4d1d9d7cf7f551445d56cc1a8ab2a078e15e049dc2c",
		"531ce78176401666aa30db94ec4a30eb",
		"c51fc276774dad94bcdc1d2891ec8668",
		"70dd95a14ee975e239df36ff4aee1d5d",

		"eab3b19c581aa873e1981c83ab8d83bbf8025111fb2e6b21",
		"f3d6667e8d4d791e60f7505ba383eb05",
		"9d4e4cccd1682321856df069e3f1c6fa391a083a9fb02d59db74c14081b3acc4",
		"51d44779f90d40a80048276c035cb49ca2a47bcb9b9cf7270b9144793787d53f",

		"16c93bb398f1fc0cf6d68fc7a5673cdf431fa147852b4a2d",
		"eaaeca2e07ddedf562f94df63f0a650f",
		"c5ce958613bf741718c17444484ebaf1050ddcacb59b9590178cbe69d7ad7919608cb03af13bbe04f3506b718a301ea0",
		"ed6a50e0c6921d52d6647f75d67b4fd56ace1fedb8b5a6a997b4d131640547d22c5d884a75e6752b5846b5b33a5181f4",

		"067bb17b4df785697eaccf961f98e212cb75e6797ce935cb",
		"8b59c9209c529ca8391c9fc0ce033c38",
		"db3785a889b4bd387754da222f0e4c2d2bfe0d79e05bc910fba941beea30f1239eacf0068f4619ec01c368e986fca6b7c58e490579d29611bd10087986eff54f",
		"d5f5589760bf9c762228fde236de1fa2dd2dad448db3fa9be0c4196efd46a35c84dd1ac77d9db58c95918cb317a6430a08d2fb6a8e8b0f1c9b72c7a344dc349f",

		"0fd39de83e0be77a79c8a4a612e3dd9c8aae2ce35e7a2bf8",
		"7e1d629b84f93b079be51f9a5f5cb23c",
		"38fbda37e28fa86d9d83a4345e419dea95d28c7818ff25925db6ac3aedaf0a86154e20a4dfcc5b1b4192895393e5eb5846c88bdbd41ecf7af3104f410eaee470f5d9017ed460475f626953035a13db1f",
		"edadae2f9a45ff3473e02d904c94d94a30a4d92da4deb6bcb4b0774472694571842039f21c496ef93fd658842c735f8a81fcd0aa578442ab893b18f606aed1bab11f81452dd45e9b56adf2eccf4ea095",

		"e3fecc75f0075a09b383dfd389a3d33cc9b854b3b254c0f4",
		"36eab883afef936cc38f63284619cd19",
		"931b2f5f3a5820d53a6beaaa6431083a3488f4eb03b0f5b57ef838e1579623103bd6e6800377538b2e51ef708f3c4956432e8a8ee6a34e190642b26ad8bdae6c2af9a6c7996f3b6004d2671e41f1c9f40ee03d1c4a52b0a0654a331f15f34dce",
		"75395974bd32b3665654a6c8e396b88ae34b123575872a7ab687d8e76b46df911a8a590cd01d2f5c330be3a6626e9dd3aa5e10ed14e8ff829811b6fed50f3f533ca4385a1cbca78f5c4744e50f2f8359165c2485d1324e76c3eae76a0ccac629",

		"f9c27565eb07947c8cb51b79248430f7b1066c3d2fdc3d13",
		"2bd67cc89ab7948d644a49672843cbd9",
		"6abcc270173cf114d44847e911a050db57ba7a2e2c161c6f37ccb6aaa4677bddcaf50cad0b5f8758fcf7c0ebc650ceb5cd52cafb8f8dd3edcece55d9f1f08b9fa8f54365cf56e28b9596a7e1dd1d3418e4444a7724add4cf79d527b183ec88de4be4eeff29c80a97e54f85351cb189ee",
		"ca282924a61187feb40520979106e5cc861957f23828dcb7285e0eaac8a0ca2a6b60503d63d6039f4693dba32fa1f73ae2e709ca94911f28a5edd1f30eaddd54680c43acc9c74cd90d8bb648b4e544275f47e514daa20697f66c738eb30337f017fca1a26da4d1a0cc0a0e98e2463070",

		"fb09cf9e00dbf883689d079c920077c0073c31890b55bab5",
		"e3c89bd097c3abddf64f4881db6dbfe2",
		"c1a37683fb289467dd1b2c89efba16bbd2ee24cf18d19d44596ded2682c79a2f711c7a32bf6a24badd32a4ee637c73b7a41da6258635650f91fb9ffa45bdfc3cb122136241b3deced8996aa51ea8d3e81c9d70e006a44bc0571ed48623a0d622a93fa9da290baaedf5d9e876c94620945ff8ecc83f27379ed55cf490c5790f27",
		"8158e21420f25b59d6ae943fa1cbf21f02e979f419dab0126a721b7eef55bee9ad97f5ccff7d239057bbc19a8c378142f7672f1d5e7e17d7bebcb0070e8355cace6660171a53b61816ae824a6ef69ce470b6ffd3b5bb4b438874d91d27854d3b6f25860d3868958de3307d62b1339bdddb8a318c0ce0f33c17caf0e9f6040820",

		"bca6fa3c67fd294e958f66fe8bd64f45f428f5bc8e9733a7",
		"92a47f2833f1450d1da41717bdc6e83c",
		"5becbc31d8bead6d36ae014a5863d14a431e6b55d29ea6baaa417271716db3a33b2e506b452086dfe690834ac2de30bc41254ec5401ec47d064237c7792fdcd7914d8af20eb114756642d519021a8c75a92f6bc53d326ae9a5b7e1b10a9756574692934d9939fc399e0c203f7edf8e7e6482eadd31a0400770e897b48c6bca2b404593045080e93377358c42a0f4dede",
		"926db248cc1ba20f0c57631a7c8aef094f791937b905949e3460240e8bfa6fa483115a1b310b6e4369caebc5262888377b1ddaa5800ea496a2bdff0f9a1031e7129c9a20e35621e7f0b8baca0d87030f2ae7ca8593c8599677a06fd4b26009ead08fecac24caa9cf2cad3b470c8227415a7b1e0f2eab3fad96d70a209c8bb26c627677e2531b9435ca6e3c444d195b5f",

		"162ad50ee64a0702aa551f571dedc16b2c1b6a1e4d4b5eee",
		"24408038161a2ccae07b029bb66355c1",
		"be8abf00901363987a82cc77d0ec91697ba3857f9e4f84bd79406c138d02698f003276d0449120bef4578d78fecabe8e070e11710b3f0a2744bd52434ec70015884c181ebdfd51c604a71c52e4c0e110bc408cd462b248a80b8a8ac06bb952ac1d7faed144807f1a731b7febcaf7835762defe92eccfc7a9944e1c702cffe6bc86733ed321423121085ac02df8962bcbc1937092eebf0e90a8b20e3dd8c244ae",
		"c82cf2c476dea8cb6a6e607a40d2f0391be82ea9ec84a537a6820f9afb997b76397d005424faa6a74dc4e8c7aa4a8900690f894b6d1dca80675393d2243adac762f159301e357e98b724762310cd5a7bafe1c2a030dba46fd93a9fdb89cc132ca9c17dc72031ec6822ee5a9d99dbca66c784c01b0885cbb62e29d97801927ec415a5d215158d325f9ee689437ad1b7684ad33c0d92739451ac87f39ff8c31b84",

		/*
		 * From NIST validation suite "Multiblock Message Test"
		 * (cbcmmt256.rsp).
		 */
		"6ed76d2d97c69fd1339589523931f2a6cff554b15f738f21ec72dd97a7330907",
		"851e8764776e6796aab722dbb644ace8",
		"6282b8c05c5c1530b97d4816ca434762",
		"6acc04142e100a65f51b97adf5172c41",

		"dce26c6b4cfb286510da4eecd2cffe6cdf430f33db9b5f77b460679bd49d13ae",
		"fdeaa134c8d7379d457175fd1a57d3fc",
		"50e9eee1ac528009e8cbcd356975881f957254b13f91d7c6662d10312052eb00",
		"2fa0df722a9fd3b64cb18fb2b3db55ff2267422757289413f8f657507412a64c",

		"fe8901fecd3ccd2ec5fdc7c7a0b50519c245b42d611a5ef9e90268d59f3edf33",
		"bd416cb3b9892228d8f1df575692e4d0",
		"8d3aa196ec3d7c9b5bb122e7fe77fb1295a6da75abe5d3a510194d3a8a4157d5c89d40619716619859da3ec9b247ced9",
		"608e82c7ab04007adb22e389a44797fed7de090c8c03ca8a2c5acd9e84df37fbc58ce8edb293e98f02b640d6d1d72464",

		"0493ff637108af6a5b8e90ac1fdf035a3d4bafd1afb573be7ade9e8682e663e5",
		"c0cd2bebccbb6c49920bd5482ac756e8",
		"8b37f9148df4bb25956be6310c73c8dc58ea9714ff49b643107b34c9bff096a94fedd6823526abc27a8e0b16616eee254ab4567dd68e8ccd4c38ac563b13639c",
		"05d5c77729421b08b737e41119fa4438d1f570cc772a4d6c3df7ffeda0384ef84288ce37fc4c4c7d1125a499b051364c389fd639bdda647daa3bdadab2eb5594",

		"9adc8fbd506e032af7fa20cf5343719de6d1288c158c63d6878aaf64ce26ca85",
		"11958dc6ab81e1c7f01631e9944e620f",
		"c7917f84f747cd8c4b4fedc2219bdbc5f4d07588389d8248854cf2c2f89667a2d7bcf53e73d32684535f42318e24cd45793950b3825e5d5c5c8fcd3e5dda4ce9246d18337ef3052d8b21c5561c8b660e",
		"9c99e68236bb2e929db1089c7750f1b356d39ab9d0c40c3e2f05108ae9d0c30b04832ccdbdc08ebfa426b7f5efde986ed05784ce368193bb3699bc691065ac62e258b9aa4cc557e2b45b49ce05511e65",

		"73b8faf00b3302ac99855cf6f9e9e48518690a5906a4869d4dcf48d282faae2a",
		"b3cb97a80a539912b8c21f450d3b9395",
		"3adea6e06e42c4f041021491f2775ef6378cb08824165edc4f6448e232175b60d0345b9f9c78df6596ec9d22b7b9e76e8f3c76b32d5d67273f1d83fe7a6fc3dd3c49139170fa5701b3beac61b490f0a9e13f844640c4500f9ad3087adfb0ae10",
		"ac3d6dbafe2e0f740632fd9e820bf6044cd5b1551cbb9cc03c0b25c39ccb7f33b83aacfca40a3265f2bbff879153448acacb88fcfb3bb7b10fe463a68c0109f028382e3e557b1adf02ed648ab6bb895df0205d26ebbfa9a5fd8cebd8e4bee3dc",

		"9ddf3745896504ff360a51a3eb49c01b79fccebc71c3abcb94a949408b05b2c9",
		"e79026639d4aa230b5ccffb0b29d79bc",
		"cf52e5c3954c51b94c9e38acb8c9a7c76aebdaa9943eae0a1ce155a2efdb4d46985d935511471452d9ee64d2461cb2991d59fc0060697f9a671672163230f367fed1422316e52d29eceacb8768f56d9b80f6d278093c9a8acd3cfd7edd8ebd5c293859f64d2f8486ae1bd593c65bc014",
		"34df561bd2cfebbcb7af3b4b8d21ca5258312e7e2e4e538e35ad2490b6112f0d7f148f6aa8d522a7f3c61d785bd667db0e1dc4606c318ea4f26af4fe7d11d4dcff0456511b4aed1a0d91ba4a1fd6cd9029187bc5881a5a07fe02049d39368e83139b12825bae2c7be81e6f12c61bb5c5",

		"458b67bf212d20f3a57fce392065582dcefbf381aa22949f8338ab9052260e1d",
		"4c12effc5963d40459602675153e9649",
		"256fd73ce35ae3ea9c25dd2a9454493e96d8633fe633b56176dce8785ce5dbbb84dbf2c8a2eeb1e96b51899605e4f13bbc11b93bf6f39b3469be14858b5b720d4a522d36feed7a329c9b1e852c9280c47db8039c17c4921571a07d1864128330e09c308ddea1694e95c84500f1a61e614197e86a30ecc28df64ccb3ccf5437aa",
		"90b7b9630a2378f53f501ab7beff039155008071bc8438e789932cfd3eb1299195465e6633849463fdb44375278e2fdb1310821e6492cf80ff15cb772509fb426f3aeee27bd4938882fd2ae6b5bd9d91fa4a43b17bb439ebbe59c042310163a82a5fe5388796eee35a181a1271f00be29b852d8fa759bad01ff4678f010594cd",

		"d2412db0845d84e5732b8bbd642957473b81fb99ca8bff70e7920d16c1dbec89",
		"51c619fcf0b23f0c7925f400a6cacb6d",
		"026006c4a71a180c9929824d9d095b8faaa86fc4fa25ecac61d85ff6de92dfa8702688c02a282c1b8af4449707f22d75e91991015db22374c95f8f195d5bb0afeb03040ff8965e0e1339dba5653e174f8aa5a1b39fe3ac839ce307a4e44b4f8f1b0063f738ec18acdbff2ebfe07383e734558723e741f0a1836dafdf9de82210a9248bc113b3c1bc8b4e252ca01bd803",
		"0254b23463bcabec5a395eb74c8fb0eb137a07bc6f5e9f61ec0b057de305714f8fa294221c91a159c315939b81e300ee902192ec5f15254428d8772f79324ec43298ca21c00b370273ee5e5ed90e43efa1e05a5d171209fe34f9f29237dba2a6726650fd3b1321747d1208863c6c3c6b3e2d879ab5f25782f08ba8f2abbe63e0bedb4a227e81afb36bb6645508356d34",

		"48be597e632c16772324c8d3fa1d9c5a9ecd010f14ec5d110d3bfec376c5532b",
		"d6d581b8cf04ebd3b6eaa1b53f047ee1",
		"0c63d413d3864570e70bb6618bf8a4b9585586688c32bba0a5ecc1362fada74ada32c52acfd1aa7444ba567b4e7daaecf7cc1cb29182af164ae5232b002868695635599807a9a7f07a1f137e97b1e1c9dabc89b6a5e4afa9db5855edaa575056a8f4f8242216242bb0c256310d9d329826ac353d715fa39f80cec144d6424558f9f70b98c920096e0f2c855d594885a00625880e9dfb734163cecef72cf030b8",
		"fc5873e50de8faf4c6b84ba707b0854e9db9ab2e9f7d707fbba338c6843a18fc6facebaf663d26296fb329b4d26f18494c79e09e779647f9bafa87489630d79f4301610c2300c19dbf3148b7cac8c4f4944102754f332e92b6f7c5e75bc6179eb877a078d4719009021744c14f13fd2a55a2b9c44d18000685a845a4f632c7c56a77306efa66a24d05d088dcd7c13fe24fc447275965db9e4d37fbc9304448cd"
	};

	/*
	 * AES known-answer tests for CTR.
	 * Order: key, IV, plaintext, ciphertext.
	 */
	static string[] KAT_AES_CTR = {
		/*
		 * From RFC 3686.
		 */
		"ae6852f8121067cc4bf7a5765577f39e",
		"000000300000000000000000",
		"53696e676c6520626c6f636b206d7367",
		"e4095d4fb7a7b3792d6175a3261311b8",

		"7e24067817fae0d743d6ce1f32539163",
		"006cb6dbc0543b59da48d90b",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"5104a106168a72d9790d41ee8edad388eb2e1efc46da57c8fce630df9141be28",

		"7691be035e5020a8ac6e618529f9a0dc",
		"00e0017b27777f3f4a1786f0",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223",
		"c1cf48a89f2ffdd9cf4652e9efdb72d74540a42bde6d7836d59a5ceaaef3105325b2072f",

		"16af5b145fc9f579c175f93e3bfb0eed863d06ccfdb78515",
		"0000004836733c147d6d93cb",
		"53696e676c6520626c6f636b206d7367",
		"4b55384fe259c9c84e7935a003cbe928",

		"7c5cb2401b3dc33c19e7340819e0f69c678c3db8e6f6a91a",
		"0096b03b020c6eadc2cb500d",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"453243fc609b23327edfaafa7131cd9f8490701c5ad4a79cfc1fe0ff42f4fb00",

		"02bf391ee8ecb159b959617b0965279bf59b60a786d3e0fe",
		"0007bdfd5cbd60278dcc0912",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223",
		"96893fc55e5c722f540b7dd1ddf7e758d288bc95c69165884536c811662f2188abee0935",

		"776beff2851db06f4c8a0542c8696f6c6a81af1eec96b4d37fc1d689e6c1c104",
		"00000060db5672c97aa8f0b2",
		"53696e676c6520626c6f636b206d7367",
		"145ad01dbf824ec7560863dc71e3e0c0",

		"f6d66d6bd52d59bb0796365879eff886c66dd51a5b6a99744b50590c87a23884",
		"00faac24c1585ef15a43d875",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"f05e231b3894612c49ee000b804eb2a9b8306b508f839d6a5530831d9344af1c",

		"ff7a617ce69148e4f1726e2f43581de2aa62d9f805532edff1eed687fb54153d",
		"001cc5b751a51d70a1c11148",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223",
		"eb6c52821d0bbbf7ce7594462aca4faab407df866569fd07f48cc0b583d6071f1ec0e6b8"
	};

	/*
	 * DES known-answer tests.
	 * Order: plaintext, key, ciphertext.
	 * (mostly from NIST SP 800-20).
	 */
	static string[] KAT_DES_RAW = {
		"10316E028C8F3B4A", "0000000000000000", "82DCBAFBDEAB6602",
		"8000000000000000", "0000000000000000", "95A8D72813DAA94D",
		"4000000000000000", "0000000000000000", "0EEC1487DD8C26D5",
		"2000000000000000", "0000000000000000", "7AD16FFB79C45926",
		"1000000000000000", "0000000000000000", "D3746294CA6A6CF3",
		"0800000000000000", "0000000000000000", "809F5F873C1FD761",
		"0400000000000000", "0000000000000000", "C02FAFFEC989D1FC",
		"0200000000000000", "0000000000000000", "4615AA1D33E72F10",
		"0100000000000000", "0000000000000000", "8CA64DE9C1B123A7",
		"0080000000000000", "0000000000000000", "2055123350C00858",
		"0040000000000000", "0000000000000000", "DF3B99D6577397C8",
		"0020000000000000", "0000000000000000", "31FE17369B5288C9",
		"0010000000000000", "0000000000000000", "DFDD3CC64DAE1642",
		"0008000000000000", "0000000000000000", "178C83CE2B399D94",
		"0004000000000000", "0000000000000000", "50F636324A9B7F80",
		"0002000000000000", "0000000000000000", "A8468EE3BC18F06D",
		"0001000000000000", "0000000000000000", "8CA64DE9C1B123A7",
		"0000800000000000", "0000000000000000", "A2DC9E92FD3CDE92",
		"0000400000000000", "0000000000000000", "CAC09F797D031287",
		"0000200000000000", "0000000000000000", "90BA680B22AEB525",
		"0000100000000000", "0000000000000000", "CE7A24F350E280B6",
		"0000080000000000", "0000000000000000", "882BFF0AA01A0B87",
		"0000040000000000", "0000000000000000", "25610288924511C2",
		"0000020000000000", "0000000000000000", "C71516C29C75D170",
		"0000010000000000", "0000000000000000", "8CA64DE9C1B123A7",
		"0000008000000000", "0000000000000000", "5199C29A52C9F059",
		"0000004000000000", "0000000000000000", "C22F0A294A71F29F",
		"0000002000000000", "0000000000000000", "EE371483714C02EA",
		"0000001000000000", "0000000000000000", "A81FBD448F9E522F",
		"0000000800000000", "0000000000000000", "4F644C92E192DFED",
		"0000000400000000", "0000000000000000", "1AFA9A66A6DF92AE",
		"0000000200000000", "0000000000000000", "B3C1CC715CB879D8",
		"0000000100000000", "0000000000000000", "8CA64DE9C1B123A7",
		"0000000080000000", "0000000000000000", "19D032E64AB0BD8B",
		"0000000040000000", "0000000000000000", "3CFAA7A7DC8720DC",
		"0000000020000000", "0000000000000000", "B7265F7F447AC6F3",
		"0000000010000000", "0000000000000000", "9DB73B3C0D163F54",
		"0000000008000000", "0000000000000000", "8181B65BABF4A975",
		"0000000004000000", "0000000000000000", "93C9B64042EAA240",
		"0000000002000000", "0000000000000000", "5570530829705592",
		"0000000001000000", "0000000000000000", "8CA64DE9C1B123A7",
		"0000000000800000", "0000000000000000", "8638809E878787A0",
		"0000000000400000", "0000000000000000", "41B9A79AF79AC208",
		"0000000000200000", "0000000000000000", "7A9BE42F2009A892",
		"0000000000100000", "0000000000000000", "29038D56BA6D2745",
		"0000000000080000", "0000000000000000", "5495C6ABF1E5DF51",
		"0000000000040000", "0000000000000000", "AE13DBD561488933",
		"0000000000020000", "0000000000000000", "024D1FFA8904E389",
		"0000000000010000", "0000000000000000", "8CA64DE9C1B123A7",
		"0000000000008000", "0000000000000000", "D1399712F99BF02E",
		"0000000000004000", "0000000000000000", "14C1D7C1CFFEC79E",
		"0000000000002000", "0000000000000000", "1DE5279DAE3BED6F",
		"0000000000001000", "0000000000000000", "E941A33F85501303",
		"0000000000000800", "0000000000000000", "DA99DBBC9A03F379",
		"0000000000000400", "0000000000000000", "B7FC92F91D8E92E9",
		"0000000000000200", "0000000000000000", "AE8E5CAA3CA04E85",
		"0000000000000100", "0000000000000000", "8CA64DE9C1B123A7",
		"0000000000000080", "0000000000000000", "9CC62DF43B6EED74",
		"0000000000000040", "0000000000000000", "D863DBB5C59A91A0",
		"0000000000000020", "0000000000000000", "A1AB2190545B91D7",
		"0000000000000010", "0000000000000000", "0875041E64C570F7",
		"0000000000000008", "0000000000000000", "5A594528BEBEF1CC",
		"0000000000000004", "0000000000000000", "FCDB3291DE21F0C0",
		"0000000000000002", "0000000000000000", "869EFD7F9F265A09",
		"0000000000000001", "0000000000000000", "8CA64DE9C1B123A7",
		"0000000000000000", "8000000000000000", "95F8A5E5DD31D900",
		"0000000000000000", "4000000000000000", "DD7F121CA5015619",
		"0000000000000000", "2000000000000000", "2E8653104F3834EA",
		"0000000000000000", "1000000000000000", "4BD388FF6CD81D4F",
		"0000000000000000", "0800000000000000", "20B9E767B2FB1456",
		"0000000000000000", "0400000000000000", "55579380D77138EF",
		"0000000000000000", "0200000000000000", "6CC5DEFAAF04512F",
		"0000000000000000", "0100000000000000", "0D9F279BA5D87260",
		"0000000000000000", "0080000000000000", "D9031B0271BD5A0A",
		"0000000000000000", "0040000000000000", "424250B37C3DD951",
		"0000000000000000", "0020000000000000", "B8061B7ECD9A21E5",
		"0000000000000000", "0010000000000000", "F15D0F286B65BD28",
		"0000000000000000", "0008000000000000", "ADD0CC8D6E5DEBA1",
		"0000000000000000", "0004000000000000", "E6D5F82752AD63D1",
		"0000000000000000", "0002000000000000", "ECBFE3BD3F591A5E",
		"0000000000000000", "0001000000000000", "F356834379D165CD",
		"0000000000000000", "0000800000000000", "2B9F982F20037FA9",
		"0000000000000000", "0000400000000000", "889DE068A16F0BE6",
		"0000000000000000", "0000200000000000", "E19E275D846A1298",
		"0000000000000000", "0000100000000000", "329A8ED523D71AEC",
		"0000000000000000", "0000080000000000", "E7FCE22557D23C97",
		"0000000000000000", "0000040000000000", "12A9F5817FF2D65D",
		"0000000000000000", "0000020000000000", "A484C3AD38DC9C19",
		"0000000000000000", "0000010000000000", "FBE00A8A1EF8AD72",
		"0000000000000000", "0000008000000000", "750D079407521363",
		"0000000000000000", "0000004000000000", "64FEED9C724C2FAF",
		"0000000000000000", "0000002000000000", "F02B263B328E2B60",
		"0000000000000000", "0000001000000000", "9D64555A9A10B852",
		"0000000000000000", "0000000800000000", "D106FF0BED5255D7",
		"0000000000000000", "0000000400000000", "E1652C6B138C64A5",
		"0000000000000000", "0000000200000000", "E428581186EC8F46",
		"0000000000000000", "0000000100000000", "AEB5F5EDE22D1A36",
		"0000000000000000", "0000000080000000", "E943D7568AEC0C5C",
		"0000000000000000", "0000000040000000", "DF98C8276F54B04B",
		"0000000000000000", "0000000020000000", "B160E4680F6C696F",
		"0000000000000000", "0000000010000000", "FA0752B07D9C4AB8",
		"0000000000000000", "0000000008000000", "CA3A2B036DBC8502",
		"0000000000000000", "0000000004000000", "5E0905517BB59BCF",
		"0000000000000000", "0000000002000000", "814EEB3B91D90726",
		"0000000000000000", "0000000001000000", "4D49DB1532919C9F",
		"0000000000000000", "0000000000800000", "25EB5FC3F8CF0621",
		"0000000000000000", "0000000000400000", "AB6A20C0620D1C6F",
		"0000000000000000", "0000000000200000", "79E90DBC98F92CCA",
		"0000000000000000", "0000000000100000", "866ECEDD8072BB0E",
		"0000000000000000", "0000000000080000", "8B54536F2F3E64A8",
		"0000000000000000", "0000000000040000", "EA51D3975595B86B",
		"0000000000000000", "0000000000020000", "CAFFC6AC4542DE31",
		"0000000000000000", "0000000000010000", "8DD45A2DDF90796C",
		"0000000000000000", "0000000000008000", "1029D55E880EC2D0",
		"0000000000000000", "0000000000004000", "5D86CB23639DBEA9",
		"0000000000000000", "0000000000002000", "1D1CA853AE7C0C5F",
		"0000000000000000", "0000000000001000", "CE332329248F3228",
		"0000000000000000", "0000000000000800", "8405D1ABE24FB942",
		"0000000000000000", "0000000000000400", "E643D78090CA4207",
		"0000000000000000", "0000000000000200", "48221B9937748A23",
		"0000000000000000", "0000000000000100", "DD7C0BBD61FAFD54",
		"0000000000000000", "0000000000000080", "2FBC291A570DB5C4",
		"0000000000000000", "0000000000000040", "E07C30D7E4E26E12",
		"0000000000000000", "0000000000000020", "0953E2258E8E90A1",
		"0000000000000000", "0000000000000010", "5B711BC4CEEBF2EE",
		"0000000000000000", "0000000000000008", "CC083F1E6D9E85F6",
		"0000000000000000", "0000000000000004", "D2FD8867D50D2DFE",
		"0000000000000000", "0000000000000002", "06E7EA22CE92708F",
		"0000000000000000", "0000000000000001", "166B40B44ABA4BD6",
		"0000000000000000", "0000000000000000", "8CA64DE9C1B123A7",
		"0101010101010101", "0101010101010101", "994D4DC157B96C52",
		"0202020202020202", "0202020202020202", "E127C2B61D98E6E2",
		"0303030303030303", "0303030303030303", "984C91D78A269CE3",
		"0404040404040404", "0404040404040404", "1F4570BB77550683",
		"0505050505050505", "0505050505050505", "3990ABF98D672B16",
		"0606060606060606", "0606060606060606", "3F5150BBA081D585",
		"0707070707070707", "0707070707070707", "C65242248C9CF6F2",
		"0808080808080808", "0808080808080808", "10772D40FAD24257",
		"0909090909090909", "0909090909090909", "F0139440647A6E7B",
		"0A0A0A0A0A0A0A0A", "0A0A0A0A0A0A0A0A", "0A288603044D740C",
		"0B0B0B0B0B0B0B0B", "0B0B0B0B0B0B0B0B", "6359916942F7438F",
		"0C0C0C0C0C0C0C0C", "0C0C0C0C0C0C0C0C", "934316AE443CF08B",
		"0D0D0D0D0D0D0D0D", "0D0D0D0D0D0D0D0D", "E3F56D7F1130A2B7",
		"0E0E0E0E0E0E0E0E", "0E0E0E0E0E0E0E0E", "A2E4705087C6B6B4",
		"0F0F0F0F0F0F0F0F", "0F0F0F0F0F0F0F0F", "D5D76E09A447E8C3",
		"1010101010101010", "1010101010101010", "DD7515F2BFC17F85",
		"1111111111111111", "1111111111111111", "F40379AB9E0EC533",
		"1212121212121212", "1212121212121212", "96CD27784D1563E5",
		"1313131313131313", "1313131313131313", "2911CF5E94D33FE1",
		"1414141414141414", "1414141414141414", "377B7F7CA3E5BBB3",
		"1515151515151515", "1515151515151515", "701AA63832905A92",
		"1616161616161616", "1616161616161616", "2006E716C4252D6D",
		"1717171717171717", "1717171717171717", "452C1197422469F8",
		"1818181818181818", "1818181818181818", "C33FD1EB49CB64DA",
		"1919191919191919", "1919191919191919", "7572278F364EB50D",
		"1A1A1A1A1A1A1A1A", "1A1A1A1A1A1A1A1A", "69E51488403EF4C3",
		"1B1B1B1B1B1B1B1B", "1B1B1B1B1B1B1B1B", "FF847E0ADF192825",
		"1C1C1C1C1C1C1C1C", "1C1C1C1C1C1C1C1C", "521B7FB3B41BB791",
		"1D1D1D1D1D1D1D1D", "1D1D1D1D1D1D1D1D", "26059A6A0F3F6B35",
		"1E1E1E1E1E1E1E1E", "1E1E1E1E1E1E1E1E", "F24A8D2231C77538",
		"1F1F1F1F1F1F1F1F", "1F1F1F1F1F1F1F1F", "4FD96EC0D3304EF6",
		"2020202020202020", "2020202020202020", "18A9D580A900B699",
		"2121212121212121", "2121212121212121", "88586E1D755B9B5A",
		"2222222222222222", "2222222222222222", "0F8ADFFB11DC2784",
		"2323232323232323", "2323232323232323", "2F30446C8312404A",
		"2424242424242424", "2424242424242424", "0BA03D9E6C196511",
		"2525252525252525", "2525252525252525", "3E55E997611E4B7D",
		"2626262626262626", "2626262626262626", "B2522FB5F158F0DF",
		"2727272727272727", "2727272727272727", "2109425935406AB8",
		"2828282828282828", "2828282828282828", "11A16028F310FF16",
		"2929292929292929", "2929292929292929", "73F0C45F379FE67F",
		"2A2A2A2A2A2A2A2A", "2A2A2A2A2A2A2A2A", "DCAD4338F7523816",
		"2B2B2B2B2B2B2B2B", "2B2B2B2B2B2B2B2B", "B81634C1CEAB298C",
		"2C2C2C2C2C2C2C2C", "2C2C2C2C2C2C2C2C", "DD2CCB29B6C4C349",
		"2D2D2D2D2D2D2D2D", "2D2D2D2D2D2D2D2D", "7D07A77A2ABD50A7",
		"2E2E2E2E2E2E2E2E", "2E2E2E2E2E2E2E2E", "30C1B0C1FD91D371",
		"2F2F2F2F2F2F2F2F", "2F2F2F2F2F2F2F2F", "C4427B31AC61973B",
		"3030303030303030", "3030303030303030", "F47BB46273B15EB5",
		"3131313131313131", "3131313131313131", "655EA628CF62585F",
		"3232323232323232", "3232323232323232", "AC978C247863388F",
		"3333333333333333", "3333333333333333", "0432ED386F2DE328",
		"3434343434343434", "3434343434343434", "D254014CB986B3C2",
		"3535353535353535", "3535353535353535", "B256E34BEDB49801",
		"3636363636363636", "3636363636363636", "37F8759EB77E7BFC",
		"3737373737373737", "3737373737373737", "5013CA4F62C9CEA0",
		"3838383838383838", "3838383838383838", "8940F7B3EACA5939",
		"3939393939393939", "3939393939393939", "E22B19A55086774B",
		"3A3A3A3A3A3A3A3A", "3A3A3A3A3A3A3A3A", "B04A2AAC925ABB0B",
		"3B3B3B3B3B3B3B3B", "3B3B3B3B3B3B3B3B", "8D250D58361597FC",
		"3C3C3C3C3C3C3C3C", "3C3C3C3C3C3C3C3C", "51F0114FB6A6CD37",
		"3D3D3D3D3D3D3D3D", "3D3D3D3D3D3D3D3D", "9D0BB4DB830ECB73",
		"3E3E3E3E3E3E3E3E", "3E3E3E3E3E3E3E3E", "E96089D6368F3E1A",
		"3F3F3F3F3F3F3F3F", "3F3F3F3F3F3F3F3F", "5C4CA877A4E1E92D",
		"4040404040404040", "4040404040404040", "6D55DDBC8DEA95FF",
		"4141414141414141", "4141414141414141", "19DF84AC95551003",
		"4242424242424242", "4242424242424242", "724E7332696D08A7",
		"4343434343434343", "4343434343434343", "B91810B8CDC58FE2",
		"4444444444444444", "4444444444444444", "06E23526EDCCD0C4",
		"4545454545454545", "4545454545454545", "EF52491D5468D441",
		"4646464646464646", "4646464646464646", "48019C59E39B90C5",
		"4747474747474747", "4747474747474747", "0544083FB902D8C0",
		"4848484848484848", "4848484848484848", "63B15CADA668CE12",
		"4949494949494949", "4949494949494949", "EACC0C1264171071",
		"4A4A4A4A4A4A4A4A", "4A4A4A4A4A4A4A4A", "9D2B8C0AC605F274",
		"4B4B4B4B4B4B4B4B", "4B4B4B4B4B4B4B4B", "C90F2F4C98A8FB2A",
		"4C4C4C4C4C4C4C4C", "4C4C4C4C4C4C4C4C", "03481B4828FD1D04",
		"4D4D4D4D4D4D4D4D", "4D4D4D4D4D4D4D4D", "C78FC45A1DCEA2E2",
		"4E4E4E4E4E4E4E4E", "4E4E4E4E4E4E4E4E", "DB96D88C3460D801",
		"4F4F4F4F4F4F4F4F", "4F4F4F4F4F4F4F4F", "6C69E720F5105518",
		"5050505050505050", "5050505050505050", "0D262E418BC893F3",
		"5151515151515151", "5151515151515151", "6AD84FD7848A0A5C",
		"5252525252525252", "5252525252525252", "C365CB35B34B6114",
		"5353535353535353", "5353535353535353", "1155392E877F42A9",
		"5454545454545454", "5454545454545454", "531BE5F9405DA715",
		"5555555555555555", "5555555555555555", "3BCDD41E6165A5E8",
		"5656565656565656", "5656565656565656", "2B1FF5610A19270C",
		"5757575757575757", "5757575757575757", "D90772CF3F047CFD",
		"5858585858585858", "5858585858585858", "1BEA27FFB72457B7",
		"5959595959595959", "5959595959595959", "85C3E0C429F34C27",
		"5A5A5A5A5A5A5A5A", "5A5A5A5A5A5A5A5A", "F9038021E37C7618",
		"5B5B5B5B5B5B5B5B", "5B5B5B5B5B5B5B5B", "35BC6FF838DBA32F",
		"5C5C5C5C5C5C5C5C", "5C5C5C5C5C5C5C5C", "4927ACC8CE45ECE7",
		"5D5D5D5D5D5D5D5D", "5D5D5D5D5D5D5D5D", "E812EE6E3572985C",
		"5E5E5E5E5E5E5E5E", "5E5E5E5E5E5E5E5E", "9BB93A89627BF65F",
		"5F5F5F5F5F5F5F5F", "5F5F5F5F5F5F5F5F", "EF12476884CB74CA",
		"6060606060606060", "6060606060606060", "1BF17E00C09E7CBF",
		"6161616161616161", "6161616161616161", "29932350C098DB5D",
		"6262626262626262", "6262626262626262", "B476E6499842AC54",
		"6363636363636363", "6363636363636363", "5C662C29C1E96056",
		"6464646464646464", "6464646464646464", "3AF1703D76442789",
		"6565656565656565", "6565656565656565", "86405D9B425A8C8C",
		"6666666666666666", "6666666666666666", "EBBF4810619C2C55",
		"6767676767676767", "6767676767676767", "F8D1CD7367B21B5D",
		"6868686868686868", "6868686868686868", "9EE703142BF8D7E2",
		"6969696969696969", "6969696969696969", "5FDFFFC3AAAB0CB3",
		"6A6A6A6A6A6A6A6A", "6A6A6A6A6A6A6A6A", "26C940AB13574231",
		"6B6B6B6B6B6B6B6B", "6B6B6B6B6B6B6B6B", "1E2DC77E36A84693",
		"6C6C6C6C6C6C6C6C", "6C6C6C6C6C6C6C6C", "0F4FF4D9BC7E2244",
		"6D6D6D6D6D6D6D6D", "6D6D6D6D6D6D6D6D", "A4C9A0D04D3280CD",
		"6E6E6E6E6E6E6E6E", "6E6E6E6E6E6E6E6E", "9FAF2C96FE84919D",
		"6F6F6F6F6F6F6F6F", "6F6F6F6F6F6F6F6F", "115DBC965E6096C8",
		"7070707070707070", "7070707070707070", "AF531E9520994017",
		"7171717171717171", "7171717171717171", "B971ADE70E5C89EE",
		"7272727272727272", "7272727272727272", "415D81C86AF9C376",
		"7373737373737373", "7373737373737373", "8DFB864FDB3C6811",
		"7474747474747474", "7474747474747474", "10B1C170E3398F91",
		"7575757575757575", "7575757575757575", "CFEF7A1C0218DB1E",
		"7676767676767676", "7676767676767676", "DBAC30A2A40B1B9C",
		"7777777777777777", "7777777777777777", "89D3BF37052162E9",
		"7878787878787878", "7878787878787878", "80D9230BDAEB67DC",
		"7979797979797979", "7979797979797979", "3440911019AD68D7",
		"7A7A7A7A7A7A7A7A", "7A7A7A7A7A7A7A7A", "9626FE57596E199E",
		"7B7B7B7B7B7B7B7B", "7B7B7B7B7B7B7B7B", "DEA0B796624BB5BA",
		"7C7C7C7C7C7C7C7C", "7C7C7C7C7C7C7C7C", "E9E40542BDDB3E9D",
		"7D7D7D7D7D7D7D7D", "7D7D7D7D7D7D7D7D", "8AD99914B354B911",
		"7E7E7E7E7E7E7E7E", "7E7E7E7E7E7E7E7E", "6F85B98DD12CB13B",
		"7F7F7F7F7F7F7F7F", "7F7F7F7F7F7F7F7F", "10130DA3C3A23924",
		"8080808080808080", "8080808080808080", "EFECF25C3C5DC6DB",
		"8181818181818181", "8181818181818181", "907A46722ED34EC4",
		"8282828282828282", "8282828282828282", "752666EB4CAB46EE",
		"8383838383838383", "8383838383838383", "161BFABD4224C162",
		"8484848484848484", "8484848484848484", "215F48699DB44A45",
		"8585858585858585", "8585858585858585", "69D901A8A691E661",
		"8686868686868686", "8686868686868686", "CBBF6EEFE6529728",
		"8787878787878787", "8787878787878787", "7F26DCF425149823",
		"8888888888888888", "8888888888888888", "762C40C8FADE9D16",
		"8989898989898989", "8989898989898989", "2453CF5D5BF4E463",
		"8A8A8A8A8A8A8A8A", "8A8A8A8A8A8A8A8A", "301085E3FDE724E1",
		"8B8B8B8B8B8B8B8B", "8B8B8B8B8B8B8B8B", "EF4E3E8F1CC6706E",
		"8C8C8C8C8C8C8C8C", "8C8C8C8C8C8C8C8C", "720479B024C397EE",
		"8D8D8D8D8D8D8D8D", "8D8D8D8D8D8D8D8D", "BEA27E3795063C89",
		"8E8E8E8E8E8E8E8E", "8E8E8E8E8E8E8E8E", "468E5218F1A37611",
		"8F8F8F8F8F8F8F8F", "8F8F8F8F8F8F8F8F", "50ACE16ADF66BFE8",
		"9090909090909090", "9090909090909090", "EEA24369A19F6937",
		"9191919191919191", "9191919191919191", "6050D369017B6E62",
		"9292929292929292", "9292929292929292", "5B365F2FB2CD7F32",
		"9393939393939393", "9393939393939393", "F0B00B264381DDBB",
		"9494949494949494", "9494949494949494", "E1D23881C957B96C",
		"9595959595959595", "9595959595959595", "D936BF54ECA8BDCE",
		"9696969696969696", "9696969696969696", "A020003C5554F34C",
		"9797979797979797", "9797979797979797", "6118FCEBD407281D",
		"9898989898989898", "9898989898989898", "072E328C984DE4A2",
		"9999999999999999", "9999999999999999", "1440B7EF9E63D3AA",
		"9A9A9A9A9A9A9A9A", "9A9A9A9A9A9A9A9A", "79BFA264BDA57373",
		"9B9B9B9B9B9B9B9B", "9B9B9B9B9B9B9B9B", "C50E8FC289BBD876",
		"9C9C9C9C9C9C9C9C", "9C9C9C9C9C9C9C9C", "A399D3D63E169FA9",
		"9D9D9D9D9D9D9D9D", "9D9D9D9D9D9D9D9D", "4B8919B667BD53AB",
		"9E9E9E9E9E9E9E9E", "9E9E9E9E9E9E9E9E", "D66CDCAF3F6724A2",
		"9F9F9F9F9F9F9F9F", "9F9F9F9F9F9F9F9F", "E40E81FF3F618340",
		"A0A0A0A0A0A0A0A0", "A0A0A0A0A0A0A0A0", "10EDB8977B348B35",
		"A1A1A1A1A1A1A1A1", "A1A1A1A1A1A1A1A1", "6446C5769D8409A0",
		"A2A2A2A2A2A2A2A2", "A2A2A2A2A2A2A2A2", "17ED1191CA8D67A3",
		"A3A3A3A3A3A3A3A3", "A3A3A3A3A3A3A3A3", "B6D8533731BA1318",
		"A4A4A4A4A4A4A4A4", "A4A4A4A4A4A4A4A4", "CA439007C7245CD0",
		"A5A5A5A5A5A5A5A5", "A5A5A5A5A5A5A5A5", "06FC7FDE1C8389E7",
		"A6A6A6A6A6A6A6A6", "A6A6A6A6A6A6A6A6", "7A3C1F3BD60CB3D8",
		"A7A7A7A7A7A7A7A7", "A7A7A7A7A7A7A7A7", "E415D80048DBA848",
		"A8A8A8A8A8A8A8A8", "A8A8A8A8A8A8A8A8", "26F88D30C0FB8302",
		"A9A9A9A9A9A9A9A9", "A9A9A9A9A9A9A9A9", "D4E00A9EF5E6D8F3",
		"AAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAA", "C4322BE19E9A5A17",
		"ABABABABABABABAB", "ABABABABABABABAB", "ACE41A06BFA258EA",
		"ACACACACACACACAC", "ACACACACACACACAC", "EEAAC6D17880BD56",
		"ADADADADADADADAD", "ADADADADADADADAD", "3C9A34CA4CB49EEB",
		"AEAEAEAEAEAEAEAE", "AEAEAEAEAEAEAEAE", "9527B0287B75F5A3",
		"AFAFAFAFAFAFAFAF", "AFAFAFAFAFAFAFAF", "F2D9D1BE74376C0C",
		"B0B0B0B0B0B0B0B0", "B0B0B0B0B0B0B0B0", "939618DF0AEFAAE7",
		"B1B1B1B1B1B1B1B1", "B1B1B1B1B1B1B1B1", "24692773CB9F27FE",
		"B2B2B2B2B2B2B2B2", "B2B2B2B2B2B2B2B2", "38703BA5E2315D1D",
		"B3B3B3B3B3B3B3B3", "B3B3B3B3B3B3B3B3", "FCB7E4B7D702E2FB",
		"B4B4B4B4B4B4B4B4", "B4B4B4B4B4B4B4B4", "36F0D0B3675704D5",
		"B5B5B5B5B5B5B5B5", "B5B5B5B5B5B5B5B5", "62D473F539FA0D8B",
		"B6B6B6B6B6B6B6B6", "B6B6B6B6B6B6B6B6", "1533F3ED9BE8EF8E",
		"B7B7B7B7B7B7B7B7", "B7B7B7B7B7B7B7B7", "9C4EA352599731ED",
		"B8B8B8B8B8B8B8B8", "B8B8B8B8B8B8B8B8", "FABBF7C046FD273F",
		"B9B9B9B9B9B9B9B9", "B9B9B9B9B9B9B9B9", "B7FE63A61C646F3A",
		"BABABABABABABABA", "BABABABABABABABA", "10ADB6E2AB972BBE",
		"BBBBBBBBBBBBBBBB", "BBBBBBBBBBBBBBBB", "F91DCAD912332F3B",
		"BCBCBCBCBCBCBCBC", "BCBCBCBCBCBCBCBC", "46E7EF47323A701D",
		"BDBDBDBDBDBDBDBD", "BDBDBDBDBDBDBDBD", "8DB18CCD9692F758",
		"BEBEBEBEBEBEBEBE", "BEBEBEBEBEBEBEBE", "E6207B536AAAEFFC",
		"BFBFBFBFBFBFBFBF", "BFBFBFBFBFBFBFBF", "92AA224372156A00",
		"C0C0C0C0C0C0C0C0", "C0C0C0C0C0C0C0C0", "A3B357885B1E16D2",
		"C1C1C1C1C1C1C1C1", "C1C1C1C1C1C1C1C1", "169F7629C970C1E5",
		"C2C2C2C2C2C2C2C2", "C2C2C2C2C2C2C2C2", "62F44B247CF1348C",
		"C3C3C3C3C3C3C3C3", "C3C3C3C3C3C3C3C3", "AE0FEEB0495932C8",
		"C4C4C4C4C4C4C4C4", "C4C4C4C4C4C4C4C4", "72DAF2A7C9EA6803",
		"C5C5C5C5C5C5C5C5", "C5C5C5C5C5C5C5C5", "4FB5D5536DA544F4",
		"C6C6C6C6C6C6C6C6", "C6C6C6C6C6C6C6C6", "1DD4E65AAF7988B4",
		"C7C7C7C7C7C7C7C7", "C7C7C7C7C7C7C7C7", "76BF084C1535A6C6",
		"C8C8C8C8C8C8C8C8", "C8C8C8C8C8C8C8C8", "AFEC35B09D36315F",
		"C9C9C9C9C9C9C9C9", "C9C9C9C9C9C9C9C9", "C8078A6148818403",
		"CACACACACACACACA", "CACACACACACACACA", "4DA91CB4124B67FE",
		"CBCBCBCBCBCBCBCB", "CBCBCBCBCBCBCBCB", "2DABFEB346794C3D",
		"CCCCCCCCCCCCCCCC", "CCCCCCCCCCCCCCCC", "FBCD12C790D21CD7",
		"CDCDCDCDCDCDCDCD", "CDCDCDCDCDCDCDCD", "536873DB879CC770",
		"CECECECECECECECE", "CECECECECECECECE", "9AA159D7309DA7A0",
		"CFCFCFCFCFCFCFCF", "CFCFCFCFCFCFCFCF", "0B844B9D8C4EA14A",
		"D0D0D0D0D0D0D0D0", "D0D0D0D0D0D0D0D0", "3BBD84CE539E68C4",
		"D1D1D1D1D1D1D1D1", "D1D1D1D1D1D1D1D1", "CF3E4F3E026E2C8E",
		"D2D2D2D2D2D2D2D2", "D2D2D2D2D2D2D2D2", "82F85885D542AF58",
		"D3D3D3D3D3D3D3D3", "D3D3D3D3D3D3D3D3", "22D334D6493B3CB6",
		"D4D4D4D4D4D4D4D4", "D4D4D4D4D4D4D4D4", "47E9CB3E3154D673",
		"D5D5D5D5D5D5D5D5", "D5D5D5D5D5D5D5D5", "2352BCC708ADC7E9",
		"D6D6D6D6D6D6D6D6", "D6D6D6D6D6D6D6D6", "8C0F3BA0C8601980",
		"D7D7D7D7D7D7D7D7", "D7D7D7D7D7D7D7D7", "EE5E9FD70CEF00E9",
		"D8D8D8D8D8D8D8D8", "D8D8D8D8D8D8D8D8", "DEF6BDA6CABF9547",
		"D9D9D9D9D9D9D9D9", "D9D9D9D9D9D9D9D9", "4DADD04A0EA70F20",
		"DADADADADADADADA", "DADADADADADADADA", "C1AA16689EE1B482",
		"DBDBDBDBDBDBDBDB", "DBDBDBDBDBDBDBDB", "F45FC26193E69AEE",
		"DCDCDCDCDCDCDCDC", "DCDCDCDCDCDCDCDC", "D0CFBB937CEDBFB5",
		"DDDDDDDDDDDDDDDD", "DDDDDDDDDDDDDDDD", "F0752004EE23D87B",
		"DEDEDEDEDEDEDEDE", "DEDEDEDEDEDEDEDE", "77A791E28AA464A5",
		"DFDFDFDFDFDFDFDF", "DFDFDFDFDFDFDFDF", "E7562A7F56FF4966",
		"E0E0E0E0E0E0E0E0", "E0E0E0E0E0E0E0E0", "B026913F2CCFB109",
		"E1E1E1E1E1E1E1E1", "E1E1E1E1E1E1E1E1", "0DB572DDCE388AC7",
		"E2E2E2E2E2E2E2E2", "E2E2E2E2E2E2E2E2", "D9FA6595F0C094CA",
		"E3E3E3E3E3E3E3E3", "E3E3E3E3E3E3E3E3", "ADE4804C4BE4486E",
		"E4E4E4E4E4E4E4E4", "E4E4E4E4E4E4E4E4", "007B81F520E6D7DA",
		"E5E5E5E5E5E5E5E5", "E5E5E5E5E5E5E5E5", "961AEB77BFC10B3C",
		"E6E6E6E6E6E6E6E6", "E6E6E6E6E6E6E6E6", "8A8DD870C9B14AF2",
		"E7E7E7E7E7E7E7E7", "E7E7E7E7E7E7E7E7", "3CC02E14B6349B25",
		"E8E8E8E8E8E8E8E8", "E8E8E8E8E8E8E8E8", "BAD3EE68BDDB9607",
		"E9E9E9E9E9E9E9E9", "E9E9E9E9E9E9E9E9", "DFF918E93BDAD292",
		"EAEAEAEAEAEAEAEA", "EAEAEAEAEAEAEAEA", "8FE559C7CD6FA56D",
		"EBEBEBEBEBEBEBEB", "EBEBEBEBEBEBEBEB", "C88480835C1A444C",
		"ECECECECECECECEC", "ECECECECECECECEC", "D6EE30A16B2CC01E",
		"EDEDEDEDEDEDEDED", "EDEDEDEDEDEDEDED", "6932D887B2EA9C1A",
		"EEEEEEEEEEEEEEEE", "EEEEEEEEEEEEEEEE", "0BFC865461F13ACC",
		"EFEFEFEFEFEFEFEF", "EFEFEFEFEFEFEFEF", "228AEA0D403E807A",
		"F0F0F0F0F0F0F0F0", "F0F0F0F0F0F0F0F0", "2A2891F65BB8173C",
		"F1F1F1F1F1F1F1F1", "F1F1F1F1F1F1F1F1", "5D1B8FAF7839494B",
		"F2F2F2F2F2F2F2F2", "F2F2F2F2F2F2F2F2", "1C0A9280EECF5D48",
		"F3F3F3F3F3F3F3F3", "F3F3F3F3F3F3F3F3", "6CBCE951BBC30F74",
		"F4F4F4F4F4F4F4F4", "F4F4F4F4F4F4F4F4", "9CA66E96BD08BC70",
		"F5F5F5F5F5F5F5F5", "F5F5F5F5F5F5F5F5", "F5D779FCFBB28BF3",
		"F6F6F6F6F6F6F6F6", "F6F6F6F6F6F6F6F6", "0FEC6BBF9B859184",
		"F7F7F7F7F7F7F7F7", "F7F7F7F7F7F7F7F7", "EF88D2BF052DBDA8",
		"F8F8F8F8F8F8F8F8", "F8F8F8F8F8F8F8F8", "39ADBDDB7363090D",
		"F9F9F9F9F9F9F9F9", "F9F9F9F9F9F9F9F9", "C0AEAF445F7E2A7A",
		"FAFAFAFAFAFAFAFA", "FAFAFAFAFAFAFAFA", "C66F54067298D4E9",
		"FBFBFBFBFBFBFBFB", "FBFBFBFBFBFBFBFB", "E0BA8F4488AAF97C",
		"FCFCFCFCFCFCFCFC", "FCFCFCFCFCFCFCFC", "67B36E2875D9631C",
		"FDFDFDFDFDFDFDFD", "FDFDFDFDFDFDFDFD", "1ED83D49E267191D",
		"FEFEFEFEFEFEFEFE", "FEFEFEFEFEFEFEFE", "66B2B23EA84693AD",
		"FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "7359B2163E4EDC58",
		"0001020304050607", "0011223344556677", "3EF0A891CF8ED990",
		"2BD6459F82C5B300", "EA024714AD5C4D84", "126EFE8ED312190A"
	};

	/*
	 * Known-answer tests for DES/3DES in CBC mode.
	 * Order: key, IV, plaintext, ciphertext.
	 */
	static string[] KAT_DES_CBC = {
		/*
		 * From NIST validation suite (tdesmmt.zip).
		 */
		"34a41a8c293176c1b30732ecfe38ae8a34a41a8c293176c1",
		"f55b4855228bd0b4",
		"7dd880d2a9ab411c",
		"c91892948b6cadb4",

		"70a88fa1dfb9942fa77f40157ffef2ad70a88fa1dfb9942f",
		"ece08ce2fdc6ce80",
		"bc225304d5a3a5c9918fc5006cbc40cc",
		"27f67dc87af7ddb4b68f63fa7c2d454a",

		"e091790be55be0bc0780153861a84adce091790be55be0bc",
		"fd7d430f86fbbffe",
		"03c7fffd7f36499c703dedc9df4de4a92dd4382e576d6ae9",
		"053aeba85dd3a23bfbe8440a432f9578f312be60fb9f0035",

		"857feacd16157c58e5347a70e56e578a857feacd16157c58",
		"002dcb6d46ef0969",
		"1f13701c7f0d7385307507a18e89843ebd295bd5e239ef109347a6898c6d3fd5",
		"a0e4edde34f05bd8397ce279e49853e9387ba04be562f5fa19c3289c3f5a3391",

		"a173545b265875ba852331fbb95b49a8a173545b265875ba",
		"ab385756391d364c",
		"d08894c565608d9ae51dda63b85b3b33b1703bb5e4f1abcbb8794e743da5d6f3bf630f2e9b6d5b54",
		"370b47acf89ac6bdbb13c9a7336787dc41e1ad8beead32281d0609fb54968404bdf2894892590658",

		"26376bcb2f23df1083cd684fe00ed3c726376bcb2f23df10",
		"33acfb0f3d240ea6",
		"903a1911da1e6877f23c1985a9b61786ef438e0ce1240885035ad60fc916b18e5d71a1fb9c5d1eff61db75c0076f6efb",
		"7a4f7510f6ec0b93e2495d21a8355684d303a770ebda2e0e51ff33d72b20cb73e58e2e3de2ef6b2e12c504c0f181ba63",

		"3e1f98135d027cec752f67765408a7913e1f98135d027cec",
		"11f5f2304b28f68b",
		"7c022f5af24f7925d323d4d0e20a2ce49272c5e764b22c806f4b6ddc406d864fe5bd1c3f45556d3eb30c8676c2f8b54a5a32423a0bd95a07",
		"2bb4b131fa4ae0b4f0378a2cdb68556af6eee837613016d7ea936f3931f25f8b3ae351d5e9d00be665676e2400408b5db9892d95421e7f1a",

		"13b9d549cd136ec7bf9e9810ef2cdcbf13b9d549cd136ec7",
		"a82c1b1057badcc8",
		"1fff1563bc1645b55cb23ea34a0049dfc06607150614b621dedcb07f20433402a2d869c95ac4a070c7a3da838c928a385f899c5d21ecb58f4e5cbdad98d39b8c",
		"75f804d4a2c542a31703e23df26cc38861a0729090e6eae5672c1db8c0b09fba9b125bbca7d6c7d330b3859e6725c6d26de21c4e3af7f5ea94df3cde2349ce37",

		"20320dfdad579bb57c6e4acd769dbadf20320dfdad579bb5",
		"879201b5857ccdea",
		"0431283cc8bb4dc7750a9d5c68578486932091632a12d0a79f2c54e3d122130881fff727050f317a40fcd1a8d13793458b99fc98254ba6a233e3d95b55cf5a3faff78809999ea4bf",
		"85d17840eb2af5fc727027336bfd71a2b31bd14a1d9eb64f8a08bfc4f56eaa9ca7654a5ae698287869cc27324813730de4f1384e0b8cfbc472ff5470e3c5e4bd8ceb23dc2d91988c",

		"23abb073a2df34cb3d1fdce6b092582c23abb073a2df34cb",
		"7d7fbf19e8562d32",
		"31e718fd95e6d7ca4f94763191add2674ab07c909d88c486916c16d60a048a0cf8cdb631cebec791362cd0c202eb61e166b65c1f65d0047c8aec57d3d84b9e17032442dce148e1191b06a12c284cc41e",
		"c9a3f75ab6a7cd08a7fd53ca540aafe731d257ee1c379fadcc4cc1a06e7c12bddbeb7562c436d1da849ed072629e82a97b56d9becc25ff4f16f21c5f2a01911604f0b5c49df96cb641faee662ca8aa68",

		"b5cb1504802326c73df186e3e352a20de643b0d63ee30e37",
		"43f791134c5647ba",
		"dcc153cef81d6f24",
		"92538bd8af18d3ba",

		"a49d7564199e97cb529d2c9d97bf2f98d35edf57ba1f7358",
		"c2e999cb6249023c",
		"c689aee38a301bb316da75db36f110b5",
		"e9afaba5ec75ea1bbe65506655bb4ecb",

		"1a5d4c0825072a15a8ad9dfdaeda8c048adffb85bc4fced0",
		"7fcfa736f7548b6f",
		"983c3edacd939406010e1bc6ff9e12320ac5008117fa8f84",
		"d84fa24f38cf451ca2c9adc960120bd8ff9871584fe31cee",

		"d98aadc76d4a3716158c32866efbb9ce834af2297379a49d",
		"3c5220327c502b44",
		"6174079dda53ca723ebf00a66837f8d5ce648c08acaa5ee45ffe62210ef79d3e",
		"f5bd4d600bed77bec78409e3530ebda1d815506ed53103015b87e371ae000958",

		"ef6d3e54266d978ffb0b8ce6689d803e2cd34cc802fd0252",
		"38bae5bce06d0ad9",
		"c4f228b537223cd01c0debb5d9d4e12ba71656618d119b2f8f0af29d23efa3a9e43c4c458a1b79a0",
		"9e3289fb18379f55aa4e45a7e0e6df160b33b75f8627ad0954f8fdcb78cee55a4664caeda1000fe5",

		"625bc19b19df83abfb2f5bec9d4f2062017525a75bc26e70",
		"bd0cff364ff69a91",
		"8152d2ab876c3c8201403a5a406d3feaf27319dbea6ad01e24f4d18203704b86de70da6bbb6d638e5aba3ff576b79b28",
		"706fe7a973fac40e25b2b4499ce527078944c70e976d017b6af86a3a7a6b52943a72ba18a58000d2b61fdc3bfef2bc4a",

		"b6383176046e6880a1023bf45768b5bf5119022fe054bfe5",
		"ec13ca541c43401e",
		"cd5a886e9af011346c4dba36a424f96a78a1ddf28aaa4188bf65451f4efaffc7179a6dd237c0ae35d9b672314e5cb032612597f7e462c6f3",
		"b030f976f46277ee211c4a324d5c87555d1084513a1223d3b84416b52bbc28f4b77f3a9d8d0d91dc37d3dbe8af8be98f74674b02f9a38527",

		"3d8cf273d343b9aedccddacb91ad86206737adc86b4a49a7",
		"bb3a9a0c71c62ef0",
		"1fde3991c32ce220b5b6666a9234f2fd7bd24b921829fd9cdc6eb4218be9eac9faa9c2351777349128086b6d58776bc86ff2f76ee1b3b2850a318462b8983fa1",
		"422ce705a46bb52ad928dab6c863166d617c6fc24003633120d91918314bbf464cea7345c3c35f2042f2d6929735d74d7728f22fea618a0b9cf5b1281acb13fb",

		"fbceb5cb646b925be0b92f7f6b493d5e5b16e9159732732a",
		"2e17b3c7025ae86b",
		"4c309bc8e1e464fdd2a2b8978645d668d455f7526bd8d7b6716a722f6a900b815c4a73cc30e788065c1dfca7bf5958a6cc5440a5ebe7f8691c20278cde95db764ff8ce8994ece89c",
		"c02129bdf4bbbd75e71605a00b12c80db6b4e05308e916615011f09147ed915dd1bc67f27f9e027e4e13df36b55464a31c11b4d1fe3d855d89df492e1a7201b995c1ba16a8dbabee",

		"9b162a0df8ad9b61c88676e3d586434570b902f12a2046e0",
		"ebd6fefe029ad54b",
		"f4c1c918e77355c8156f0fd778da52bff121ae5f2f44eaf4d2754946d0e10d1f18ce3a0176e69c18b7d20b6e0d0bee5eb5edfe4bd60e4d92adcd86bce72e76f94ee5cbcaa8b01cfddcea2ade575e66ac",
		"1ff3c8709f403a8eff291aedf50c010df5c5ff64a8b205f1fce68564798897a390db16ee0d053856b75898009731da290fcc119dad987277aacef694872e880c4bb41471063fae05c89f25e4bd0cad6a"
	};

	/*
	 * From RFC 7539. Each vector consists in 5 values:
	 *    key (hex)
	 *    iv (hex)
	 *    counter (decimal)
	 *    plain (hex)
	 *    cipher (hex)
	 */
	static string[] KAT_CHACHA20 = {
		"0000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000",
		"0",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",

		"0000000000000000000000000000000000000000000000000000000000000001",
		"000000000000000000000002",
		"1",
		"416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f",
		"a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221",

		"1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
		"000000000000000000000002",
		"42",
		"2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
		"62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1"
	};

	/*
	 * From: http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
	 */
	static string[] KAT_GHASH = {

		"66e94bd4ef8a2c3b884cfa59ca342b2e",
		"",
		"",
		"00000000000000000000000000000000",

		"66e94bd4ef8a2c3b884cfa59ca342b2e",
		"",
		"0388dace60b6a392f328c2b971b2fe78",
		"f38cbb1ad69223dcc3457ae5b6b0f885",

		"b83b533708bf535d0aa6e52980d53b78",
		"",
		"42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
		"7f1b32b81b820d02614f8895ac1d4eac",

		"b83b533708bf535d0aa6e52980d53b78",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
		"698e57f70e6ecc7fd9463b7260a9ae5f",

		"b83b533708bf535d0aa6e52980d53b78",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
		"df586bb4c249b92cb6922877e444d37b",

		"b83b533708bf535d0aa6e52980d53b78",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
		"1c5afe9760d3932f3c9a878aac3dc3de",

		"aae06992acbf52a3e8f4a96ec9300bd7",
		"",
		"98e7247c07f0fe411c267e4384b0f600",
		"e2c63f0ac44ad0e02efa05ab6743d4ce",

		"466923ec9ae682214f2c082badb39249",
		"",
		"3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256",
		"51110d40f6c8fff0eb1ae33445a889f0",

		"466923ec9ae682214f2c082badb39249",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
		"ed2ce3062e4a8ec06db8b4c490e8a268",

		"466923ec9ae682214f2c082badb39249",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057fddc29df9a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7",
		"1e6a133806607858ee80eaf237064089",

		"466923ec9ae682214f2c082badb39249",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"d27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e4581e79012af34ddd9e2f037589b292db3e67c036745fa22e7e9b7373b",
		"82567fb0b4cc371801eadec005968e94",

		"dc95c078a2408989ad48a21492842087",
		"",
		"cea7403d4d606b6e074ec5d3baf39d18",
		"83de425c5edc5d498f382c441041ca92",

		"acbef20579b4b8ebce889bac8732dad7",
		"",
		"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
		"4db870d37cb75fcb46097c36230d1612",

		"acbef20579b4b8ebce889bac8732dad7",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
		"8bd0c4d8aacd391e67cca447e8c38f65",

		"acbef20579b4b8ebce889bac8732dad7",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f",
		"75a34288b8c68f811c52b2e9a2f97f63",

		"acbef20579b4b8ebce889bac8732dad7",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f",
		"d5ffcf6fc5ac4d69722187421a7f170b"
	};

	static string[] ECDSA_K_P256 = {
  "04"
+ "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
+ "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",

  "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
	};

	static string[] ECDSA_SIGS_P256 = {
  "61340C88C3AAEBEB4F6D667F672CA9759A6CCAA9FA8811313039EE4A35471D32",
  "6D7F147DAC089441BB2E2FE8F7A3FA264B9C475098FDCF6E00D7C996E1B8B7EB",

  "53B2FFF5D1752B2C689DF257C04C40A587FABABB3F6FC2702F1343AF7CA9AA3F",
  "B9AFB64FDC03DC1A131C7D2386D11E349F070AA432A4ACC918BEA988BF75C74C",

  "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
  "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",

  "0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF7719",
  "4861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954",

  "8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00",
  "2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE",

  "0CBCC86FD6ABD1D99E703E1EC50069EE5C0B4BA4B9AC60E409E8EC5910D81A89",
  "01B9D7B73DFAA60D5651EC4591A0136F87653E0FD780C3B1BC872FFDEAE479B1",

  "C37EDB6F0AE79D47C3C27E962FA269BB4F441770357E114EE511F662EC34A692",
  "C820053A05791E521FCAAD6042D40AEA1D6B1A540138558F47D0719800E18F2D",

  "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
  "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083",

  "83910E8B48BB0C74244EBDF7F07A1C5413D61472BD941EF3920E623FBCCEBEB6",
  "8DDBEC54CF8CD5874883841D712142A56A8D0F218F5003CB0296B6B509619F2C",

  "461D93F31B6540894788FD206C07CFA0CC35F46FA3C91816FFF1040AD1581A04",
  "39AF9F15DE0DB8D97E72719C74820D304CE5226E32DEDAE67519E840D1194E55"
	};

	static string[] ECDSA_K_P384 = {
		"04"
		+ "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E"
		+ "06AAE5286B300C64DEF8F0EA9055866064A254515480BC13"
		+ "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9"
		+ "F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720",

		  "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA"
		+ "9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5"
	};

	static string[] ECDSA_SIGS_P384 = {
		  "EC748D839243D6FBEF4FC5C4859A7DFFD7F3ABDDF7201454"
		+ "0C16D73309834FA37B9BA002899F6FDA3A4A9386790D4EB2",
		  "A3BCFA947BEEF4732BF247AC17F71676CB31A847B9FF0CBC"
		+ "9C9ED4C1A5B3FACF26F49CA031D4857570CCB5CA4424A443",

		  "42356E76B55A6D9B4631C865445DBE54E056D3B3431766D0"
		+ "509244793C3F9366450F76EE3DE43F5A125333A6BE060122",
		  "9DA0C81787064021E78DF658F2FBB0B042BF304665DB721F"
		+ "077A4298B095E4834C082C03D83028EFBF93A3C23940CA8D",

		  "21B13D1E013C7FA1392D03C5F99AF8B30C570C6F98D4EA8E"
		+ "354B63A21D3DAA33BDE1E888E63355D92FA2B3C36D8FB2CD",
		  "F3AA443FB107745BF4BD77CB3891674632068A10CA67E3D4"
		+ "5DB2266FA7D1FEEBEFDC63ECCD1AC42EC0CB8668A4FA0AB0",

		  "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA7"
		+ "3D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46",
		  "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526"
		+ "203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8",

		  "ED0959D5880AB2D869AE7F6C2915C6D60F96507F9CB3E047"
		+ "C0046861DA4A799CFE30F35CC900056D7C99CD7882433709",
		  "512C8CCEEE3890A84058CE1E22DBC2198F42323CE8ACA913"
		+ "5329F03C068E5112DC7CC3EF3446DEFCEB01A45C2667FDD5",

		  "4BC35D3A50EF4E30576F58CD96CE6BF638025EE624004A1F"
		+ "7789A8B8E43D0678ACD9D29876DAF46638645F7F404B11C7",
		  "D5A6326C494ED3FF614703878961C0FDE7B2C278F9A65FD8"
		+ "C4B7186201A2991695BA1C84541327E966FA7B50F7382282",

		  "E8C9D0B6EA72A0E7837FEA1D14A1A9557F29FAA45D3E7EE8"
		+ "88FC5BF954B5E62464A9A817C47FF78B8C11066B24080E72",
		  "07041D4A7A0379AC7232FF72E6F77B6DDB8F09B16CCE0EC3"
		+ "286B2BD43FA8C6141C53EA5ABEF0D8231077A04540A96B66",

		  "6D6DEFAC9AB64DABAFE36C6BF510352A4CC27001263638E5"
		+ "B16D9BB51D451559F918EEDAF2293BE5B475CC8F0188636B",
		  "2D46F3BECBCC523D5F1A1256BF0C9B024D879BA9E838144C"
		+ "8BA6BAEB4B53B47D51AB373F9845C0514EEFB14024787265",

		  "8203B63D3C853E8D77227FB377BCF7B7B772E97892A80F36"
		+ "AB775D509D7A5FEB0542A7F0812998DA8F1DD3CA3CF023DB",
		  "DDD0760448D42D8A43AF45AF836FCE4DE8BE06B485E9B61B"
		+ "827C2F13173923E06A739F040649A667BF3B828246BAA5A5",

		  "A0D5D090C9980FAF3C2CE57B7AE951D31977DD11C775D314"
		+ "AF55F76C676447D06FB6495CD21B4B6E340FC236584FB277",
		  "976984E59B4C77B0E8E4460DCA3D9F20E07B9BB1F63BEEFA"
		+ "F576F6B2E8B224634A2092CD3792E0159AD9CEE37659C736"
	};

	static string[] ECDSA_K_P521 = {
  "04"
+ "01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD37"
+ "1123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4"
+ "00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28"
+ "A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5",

  "00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CA"
+ "A896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538"
	};

	static string[] ECDSA_SIGS_P521 = {
  "00343B6EC45728975EA5CBA6659BBB6062A5FF89EEA58BE3C80B619F322C87910F"
+ "E092F7D45BB0F8EEE01ED3F20BABEC079D202AE677B243AB40B5431D497C55D75D",
  "00E7B0E675A9B24413D448B8CC119D2BF7B2D2DF032741C096634D6D65D0DBE3D5"
+ "694625FB9E8104D3B842C1B0E2D0B98BEA19341E8676AEF66AE4EBA3D5475D5D16",

  "01776331CFCDF927D666E032E00CF776187BC9FDD8E69D0DABB4109FFE1B5E2A30"
+ "715F4CC923A4A5E94D2503E9ACFED92857B7F31D7152E0F8C00C15FF3D87E2ED2E",
  "0050CB5265417FE2320BBB5A122B8E1A32BD699089851128E360E620A30C7E17BA"
+ "41A666AF126CE100E5799B153B60528D5300D08489CA9178FB610A2006C254B41F",

  "01511BB4D675114FE266FC4372B87682BAECC01D3CC62CF2303C92B3526012659D"
+ "16876E25C7C1E57648F23B73564D67F61C6F14D527D54972810421E7D87589E1A7",
  "004A171143A83163D6DF460AAF61522695F207A58B95C0644D87E52AA1A347916E"
+ "4F7A72930B1BC06DBE22CE3F58264AFD23704CBB63B29B931F7DE6C9D949A7ECFC",

  "01EA842A0E17D2DE4F92C15315C63DDF72685C18195C2BB95E572B9C5136CA4B4B"
+ "576AD712A52BE9730627D16054BA40CC0B8D3FF035B12AE75168397F5D50C67451",
  "01F21A3CEE066E1961025FB048BD5FE2B7924D0CD797BABE0A83B66F1E35EEAF5F"
+ "DE143FA85DC394A7DEE766523393784484BDF3E00114A1C857CDE1AA203DB65D61",

  "00C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F17"
+ "4E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E377FA",
  "00617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF28"
+ "2623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A67A",

  "013BAD9F29ABE20DE37EBEB823C252CA0F63361284015A3BF430A46AAA80B87B06"
+ "93F0694BD88AFE4E661FC33B094CD3B7963BED5A727ED8BD6A3A202ABE009D0367",
  "01E9BB81FF7944CA409AD138DBBEE228E1AFCC0C890FC78EC8604639CB0DBDC90F"
+ "717A99EAD9D272855D00162EE9527567DD6A92CBD629805C0445282BBC916797FF",

  "01C7ED902E123E6815546065A2C4AF977B22AA8EADDB68B2C1110E7EA44D42086B"
+ "FE4A34B67DDC0E17E96536E358219B23A706C6A6E16BA77B65E1C595D43CAE17FB",
  "0177336676304FCB343CE028B38E7B4FBA76C1C1B277DA18CAD2A8478B2A9A9F5B"
+ "EC0F3BA04F35DB3E4263569EC6AADE8C92746E4C82F8299AE1B8F1739F8FD519A4",

  "000E871C4A14F993C6C7369501900C4BC1E9C7B0B4BA44E04868B30B41D8071042"
+ "EB28C4C250411D0CE08CD197E4188EA4876F279F90B3D8D74A3C76E6F1E4656AA8",
  "00CD52DBAA33B063C3A6CD8058A1FB0A46A4754B034FCC644766CA14DA8CA5CA9F"
+ "DE00E88C1AD60CCBA759025299079D7A427EC3CC5B619BFBC828E7769BCD694E86",

  "014BEE21A18B6D8B3C93FAB08D43E739707953244FDBE924FA926D76669E7AC8C8"
+ "9DF62ED8975C2D8397A65A49DCC09F6B0AC62272741924D479354D74FF6075578C",
  "0133330865C067A0EAF72362A65E2D7BC4E461E8C8995C3B6226A21BD1AA78F0ED"
+ "94FE536A0DCA35534F0CD1510C41525D163FE9D74D134881E35141ED5E8E95B979",

  "013E99020ABF5CEE7525D16B69B229652AB6BDF2AFFCAEF38773B4B7D08725F10C"
+ "DB93482FDCC54EDCEE91ECA4166B2A7C6265EF0CE2BD7051B7CEF945BABD47EE6D",
  "01FBD0013C674AA79CB39849527916CE301C66EA7CE8B80682786AD60F98F7E78A"
+ "19CA69EFF5C57400E3B3A0AD66CE0978214D13BAF4E9AC60752F7B155E2DE4DCE3"
	};
}
