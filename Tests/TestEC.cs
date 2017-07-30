using System;
using System.IO;
using System.Text;

using Crypto;

internal class TestEC {

	internal static void Main(string[] args)
	{
		try {
			TestECInt();
		} catch (Exception e) {
			Console.WriteLine(e.ToString());
			Environment.Exit(1);
		}
	}

	internal static void TestECInt()
	{
		TestCurve25519();
		SpeedCurve(EC.Curve25519);

		TestCurve(NIST.P256, KAT_P256);
		TestCurve(NIST.P384, KAT_P384);
		TestCurve(NIST.P521, KAT_P521);

		SpeedCurve(NIST.P256);
		SpeedCurve(NIST.P384);
		SpeedCurve(NIST.P521);
	}

	static void TestCurve25519()
	{
		Console.Write("Test Curve25519: ");

		TestCurve25519KAT(
    "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
    "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
    "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
		TestCurve25519KAT(
    "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
    "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
    "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");

		byte[] u = EC.Curve25519.GetGenerator(false);
		byte[] k = new byte[u.Length];
		Array.Copy(u, 0, k, 0, u.Length);
		Byteswap(k);
		byte[] nk = new byte[u.Length];

		for (int i = 1; i <= 1000; i ++) {
			EC.Curve25519.Mul(u, k, nk, false);
			Array.Copy(k, 0, u, 0, u.Length);
			Byteswap(u);
			Array.Copy(nk, 0, k, 0, u.Length);
			Byteswap(k);
			if (i == 1) {
				byte[] z = ToBin(C25519_MC_1);
				Byteswap(z);
				if (!Eq(k, z)) {
					throw new Exception(
						"Curve25519 MC 1");
				}
			} else if (i == 1000) {
				byte[] z = ToBin(C25519_MC_1000);
				Byteswap(z);
				if (!Eq(k, z)) {
					throw new Exception(
						"Curve25519 MC 1000");
				}
			}
			if (i % 1000 == 0) {
				Console.Write(".");
			}
		}

		/*
		Byteswap(k);
		if (!Eq(k, ToBin(C25519_MC_1000000))) {
			throw new Exception("Curve25519 MC 1000");
		}
		*/

		Console.WriteLine(" done.");
	}

	static string C25519_MC_1 = "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079";
	static string C25519_MC_1000 = "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51";
	/*
	static string C25519_MC_1000000 = "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424";
	*/

	static void Byteswap(byte[] t)
	{
		for (int i = 0; i < (t.Length >> 1); i ++) {
			byte x = t[i];
			t[i] = t[t.Length - 1 - i];
			t[t.Length - 1 - i] = x;
		}
	}

	static void TestCurve25519KAT(string sscalar, string s_in, string s_out)
	{
		byte[] tmp = ToBin(sscalar);
		byte[] scalar = new byte[tmp.Length];
		for (int i = 0; i < tmp.Length; i ++) {
			scalar[i] = tmp[tmp.Length - 1 - i];
		}
		byte[] A = ToBin(s_in);
		byte[] B = new byte[A.Length];
		if (EC.Curve25519.Mul(A, scalar, B, false) != 0xFFFFFFFF) {
			throw new Exception("Curve25519 multiplication failed");
		}
		byte[] C = ToBin(s_out);
		if (!Eq(B, C)) {
			throw new Exception("Curve25519 KAT failed");
		}
		Console.Write(".");
	}

	static void TestCurve(ECCurve curve, string[] kat)
	{
		Console.Write("Test {0}: ", curve.Name);

		// ====================================================

		/* obsolete -- DEBUG
		Console.WriteLine();
		ZInt p = ZInt.DecodeUnsignedBE(((ECCurvePrime)curve).mod);
		ZInt a = ZInt.DecodeUnsignedBE(((ECCurvePrime)curve).a);
		ZInt b = ZInt.DecodeUnsignedBE(((ECCurvePrime)curve).b);
		Console.WriteLine("p  = {0}", p.ToHexString());
		Console.WriteLine("a  = {0}", a.ToHexString());
		Console.WriteLine("b  = {0}", b.ToHexString());
		MutableECPoint F1 = curve.MakeGenerator();
		byte[] enc = F1.Encode(false);
		int flen = enc.Length >> 1;
		for (int i = 0; i < enc.Length; i ++) {
			if (i == 1 || i == 1 + (enc.Length >> 1)) {
				Console.Write(" ");
			}
			Console.Write("{0:X2}", enc[i]);
		}
		Console.WriteLine();
		byte[] X = new byte[flen];
		byte[] Y = new byte[flen];
		Array.Copy(enc, 1, X, 0, flen);
		Array.Copy(enc, 1 + flen, Y, 0, flen);
		ZInt x1 = ZInt.DecodeUnsignedBE(X);
		ZInt y1 = ZInt.DecodeUnsignedBE(Y);
		Console.WriteLine("X1 = {0}", x1.ToHexString());
		Console.WriteLine("Y1 = {0}", y1.ToHexString());
		MutableECPoint F2 = F1.Dup();
		F2.DoubleCT();
		MutableECPoint F3 = F2.Dup();
		MutableECPoint F4 = F2.Dup();
		enc = F2.Encode(false);
		for (int i = 0; i < enc.Length; i ++) {
			if (i == 1 || i == 1 + (enc.Length >> 1)) {
				Console.Write(" ");
			}
			Console.Write("{0:X2}", enc[i]);
		}
		Console.WriteLine();
		Array.Copy(enc, 1, X, 0, flen);
		Array.Copy(enc, 1 + flen, Y, 0, flen);
		ZInt x2 = ZInt.DecodeUnsignedBE(X);
		ZInt y2 = ZInt.DecodeUnsignedBE(Y);
		Console.WriteLine("X2 = {0}", x2.ToHexString());
		Console.WriteLine("Y2 = {0}", y2.ToHexString());
		if ((x1 * x1 * x1 + a * x1 + b - y1 * y1) % p != 0) {
			throw new Exception("Generator not on curve");
		}
		if ((x2 * x2 * x2 + a * x2 + b - y2 * y2) % p != 0) {
			throw new Exception("Double not on curve");
		}

		if (F3.AddCT(F1) == 0) {
			throw new Exception("Addition failed");
		}
		MutableECPoint F5 = F3.Dup();
		enc = F3.Encode(false);
		for (int i = 0; i < enc.Length; i ++) {
			if (i == 1 || i == 1 + (enc.Length >> 1)) {
				Console.Write(" ");
			}
			Console.Write("{0:X2}", enc[i]);
		}
		Console.WriteLine();
		Array.Copy(enc, 1, X, 0, flen);
		Array.Copy(enc, 1 + flen, Y, 0, flen);
		ZInt x3 = ZInt.DecodeUnsignedBE(X);
		ZInt y3 = ZInt.DecodeUnsignedBE(Y);
		Console.WriteLine("X3 = {0}", x3.ToHexString());
		Console.WriteLine("Y3 = {0}", y3.ToHexString());
		if ((x3 * x3 * x3 + a * x3 + b - y3 * y3) % p != 0) {
			throw new Exception("Triple not on curve");
		}
		ZInt l3 = ((p + y2 - y1)
			* ZInt.ModPow(p + x2 - x1, p - 2, p)) % p;
		ZInt x3p = (l3 * l3 + p + p - x1 - x2) % p;
		ZInt y3p = (l3 * (p + x1 - x3p) + p - y1) % p;
		Console.WriteLine("X3p = {0}", x3p.ToHexString());
		Console.WriteLine("Y3p = {0}", y3p.ToHexString());
		Console.WriteLine("[X:{0}, Y:{1}]", x3 == x3p, y3 == y3p);

		if (F5.AddCT(F4) == 0) {
			throw new Exception("Addition failed");
		}
		enc = F5.Encode(false);
		for (int i = 0; i < enc.Length; i ++) {
			if (i == 1 || i == 1 + (enc.Length >> 1)) {
				Console.Write(" ");
			}
			Console.Write("{0:X2}", enc[i]);
		}
		Console.WriteLine();
		Array.Copy(enc, 1, X, 0, flen);
		Array.Copy(enc, 1 + flen, Y, 0, flen);
		ZInt x5 = ZInt.DecodeUnsignedBE(X);
		ZInt y5 = ZInt.DecodeUnsignedBE(Y);
		Console.WriteLine("X5 = {0}", x5.ToHexString());
		Console.WriteLine("Y5 = {0}", y5.ToHexString());
		if ((x5 * x5 * x5 + a * x5 + b - y5 * y5) % p != 0) {
			throw new Exception("Quintuple not on curve");
		}
		ZInt l5 = ((p + y3 - y2)
			* ZInt.ModPow(p + x3 - x2, p - 2, p)) % p;
		ZInt x5p = (l5 * l5 + p + p - x2 - x3) % p;
		ZInt y5p = (l5 * (p + x2 - x5p) + p - y2) % p;
		Console.WriteLine("X5p = {0}", x5p.ToHexString());
		Console.WriteLine("Y5p = {0}", y5p.ToHexString());
		Console.WriteLine("[X:{0}, Y:{1}]", x5 == x5p, y5 == y5p);

		F1.Set(curve.MakeGenerator());
		if (F1.MulSpecCT(new byte[] { 0x05 }) == 0) {
			throw new Exception("Multiplication failed");
		}
		enc = F1.Encode(false);
		for (int i = 0; i < enc.Length; i ++) {
			if (i == 1 || i == 1 + (enc.Length >> 1)) {
				Console.Write(" ");
			}
			Console.Write("{0:X2}", enc[i]);
		}
		Console.WriteLine();
		Array.Copy(enc, 1, X, 0, flen);
		Array.Copy(enc, 1 + flen, Y, 0, flen);
		ZInt x5t = ZInt.DecodeUnsignedBE(X);
		ZInt y5t = ZInt.DecodeUnsignedBE(Y);
		Console.WriteLine("X5t = {0}", x5t.ToHexString());
		Console.WriteLine("Y5t = {0}", y5t.ToHexString());
		if ((x5t * x5t * x5t + a * x5t + b - y5t * y5t) % p != 0) {
			throw new Exception("Quintuple not on curve (2)");
		}
		Console.WriteLine("[X:{0}, Y:{1}]", x5t == x5p, y5t == y5p);

		F1.Set(F5);
		F2.SetZero();
		if (F1.AddCT(F2) == 0) {
			throw new Exception("Addition failed (+0)");
		}
		enc = F1.Encode(false);
		for (int i = 0; i < enc.Length; i ++) {
			if (i == 1 || i == 1 + (enc.Length >> 1)) {
				Console.Write(" ");
			}
			Console.Write("{0:X2}", enc[i]);
		}
		Console.WriteLine();
		Array.Copy(enc, 1, X, 0, flen);
		Array.Copy(enc, 1 + flen, Y, 0, flen);
		ZInt x5q = ZInt.DecodeUnsignedBE(X);
		ZInt y5q = ZInt.DecodeUnsignedBE(Y);
		Console.WriteLine("X5q = {0}", x5q.ToHexString());
		Console.WriteLine("Y5q = {0}", y5q.ToHexString());
		Console.WriteLine("[X:{0}, Y:{1}]", x5q == x5p, y5q == y5p);

		F2.SetZero();
		if (F2.AddCT(F1) == 0) {
			throw new Exception("Addition failed (0+)");
		}
		enc = F2.Encode(false);
		for (int i = 0; i < enc.Length; i ++) {
			if (i == 1 || i == 1 + (enc.Length >> 1)) {
				Console.Write(" ");
			}
			Console.Write("{0:X2}", enc[i]);
		}
		Console.WriteLine();
		Array.Copy(enc, 1, X, 0, flen);
		Array.Copy(enc, 1 + flen, Y, 0, flen);
		ZInt x5r = ZInt.DecodeUnsignedBE(X);
		ZInt y5r = ZInt.DecodeUnsignedBE(Y);
		Console.WriteLine("X5r = {0}", x5r.ToHexString());
		Console.WriteLine("Y5r = {0}", y5r.ToHexString());
		Console.WriteLine("[X:{0}, Y:{1}]", x5r == x5p, y5r == y5p);

		EC rG = EC.Make(p.ToBytesUnsignedBE(),
			a.ToBytesUnsignedBE(), b.ToBytesUnsignedBE());
		rG.Set(x1.ToBytesUnsignedBE(), y1.ToBytesUnsignedBE());
		for (int i = 1; i <= 30; i ++) {
			Console.Write(".");
			ZInt n = ZInt.MakeRand(i);
			byte[] nb = n.ToBytesUnsignedBE();
			F1 = curve.MakeGenerator();
			if (F1.MulSpecCT(nb) == 0) {
				throw new Exception("Multiplication error");
			}
			enc = F1.Encode(false);
			ZInt xp, yp;
			if (enc.Length == 1) {
				xp = 0;
				yp = 0;
			} else {
				Array.Copy(enc, 1, X, 0, flen);
				Array.Copy(enc, 1 + flen, Y, 0, flen);
				xp = ZInt.DecodeUnsignedBE(X);
				yp = ZInt.DecodeUnsignedBE(Y);
			}
			EC rH = rG.Dup();
			rH.Mul(nb);
			ZInt xh = ZInt.DecodeUnsignedBE(rH.X);
			ZInt yh = ZInt.DecodeUnsignedBE(rH.Y);
			if (xp != xh || yp != yh) {
				Console.WriteLine();
				Console.WriteLine("n = {0}", n);
				Console.WriteLine("xp = {0}", xp.ToHexString());
				Console.WriteLine("yp = {0}", yp.ToHexString());
				Console.WriteLine("xh = {0}", xh.ToHexString());
				Console.WriteLine("yh = {0}", yh.ToHexString());
				throw new Exception("Bad mult result");
			}
		}
		Console.WriteLine();
		*/

		// ====================================================

		curve.CheckValid();
		MutableECPoint G = curve.MakeGenerator();
		if (G.IsInfinity) {
			throw new Exception("Generator is infinity");
		}
		MutableECPoint P = G.Dup();
		MutableECPoint Q = G.Dup();
		MutableECPoint R = G.Dup();
		MutableECPoint S = G.Dup();
		MutableECPoint T = G.Dup();

		for (int i = 0; i < 10; i ++) {
			Console.Write(".");
			byte[] u, v, w;
			u = MakeRandPoint(P);
			do {
				v = MakeRandPoint(Q);
			} while (BigInt.Compare(u, v) == 0);
			// byte[] s = BigInt.Add(u, v);
			byte[] t;
			do {
				w = MakeRandPoint(R);
				t = BigInt.Add(v, w);
			} while (BigInt.Compare(u, w) == 0
				|| BigInt.Compare(v, w) == 0
				|| BigInt.Compare(u, t) == 0);
			if (P.Eq(Q) || P.Eq(R) || Q.Eq(R)) {
				throw new Exception("Equal points");
			}
			S.Set(P);
			Add(S, Q);
			Add(S, R);
			T.Set(Q);
			Add(T, R);
			Add(T, P);
			if (!S.Eq(T) || !T.Eq(S)) {
				throw new Exception("Associativity error");
			}
			S.Normalize();
			if (!S.Eq(T) || !T.Eq(S)) {
				throw new Exception("Normalization error (1)");
			}
			T.Normalize();
			if (!S.Eq(T) || !T.Eq(S)) {
				throw new Exception("Normalization error (2)");
			}

			byte[] enc1 = P.Encode(false);
			byte[] enc2 = P.Encode(true);
			byte[] enc3 = new byte[enc1.Length];
			Array.Copy(enc1, 1, enc3, 1, enc1.Length - 1);
			enc3[0] = (byte)(enc2[0] | 0x04);
			Q.Decode(enc1);
			if (!P.Eq(Q) || !Q.Eq(P)) {
				throw new Exception("Encode/decode error 1");
			}
			Q.Decode(enc2);
			if (!P.Eq(Q) || !Q.Eq(P)) {
				throw new Exception("Encode/decode error 2");
			}
			Q.Decode(enc3);
			if (!P.Eq(Q) || !Q.Eq(P)) {
				throw new Exception("Encode/decode error 3");
			}
		}

		Console.Write(" ");
		for (int i = 0; i < kat.Length; i += 2) {
			P.Set(G);
			byte[] n = ToBin(kat[i]);
			if (P.MulSpecCT(n) == 0) {
				throw new Exception("Multiplication error");
			}
			byte[] er = ToBin(kat[i + 1]);
			if (!Eq(er, P.Encode(false))) {
				throw new Exception("KAT failed");
			}
			byte[] eg = curve.GetGenerator(false);
			byte[] ed = new byte[eg.Length];
			curve.Mul(eg, n, ed, false);
			if (!Eq(ed, er)) {
				throw new Exception("KAT failed (API 2)");
			}
			Console.Write(".");
		}

		Console.WriteLine();
	}

	static void SpeedCurve(ECCurve curve)
	{
		byte[][] nn = new byte[100][];
		for (int i = 0; i < nn.Length; i ++) {
			nn[i] = BigInt.RandIntNZ(curve.SubgroupOrder);
		}
		MutableECPoint G = curve.MakeGenerator();
		MutableECPoint P = G.Dup();
		int num = 1;
		for (;;) {
			long orig = DateTime.Now.Ticks;
			for (int i = 0, j = 0; i < num; i ++) {
				P.MulSpecCT(nn[j]);
				if (++ j == nn.Length) {
					j = 0;
				}
			}
			long end = DateTime.Now.Ticks;
			double tt = (double)(end - orig) / 10000000.0;
			if (tt < 2.0) {
				num <<= 1;
				continue;
			}
			double f = (double)num / tt;
			Console.WriteLine("{0,10}  {1,9:f3} mul/s",
				curve.Name, f);
			return;
		}
	}

	/*
	 * Create a random non-infinity point by multiplying the
	 * curve subgroup generator with a random non-zero integer
	 * modulo the subgroup order. The multiplier is returned.
	 */
	static byte[] MakeRandPoint(MutableECPoint P)
	{
		ECCurve curve = P.Curve;
		P.Set(curve.MakeGenerator());
		byte[] n = BigInt.RandIntNZ(curve.SubgroupOrder);
		if (P.MulSpecCT(n) == 0) {
			throw new Exception("Multiplication failed");
		}
		return n;
	}

	static void Add(MutableECPoint P, MutableECPoint Q)
	{
		if (P.Eq(Q)) {
			P.DoubleCT();
		} else {
			if (P.AddCT(Q) == 0) {
				throw new Exception("Addition failed");
			}
		}
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

	static string[] KAT_P256 = {
		"C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
		"0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
	};

	static string[] KAT_P384 = {
		"6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5",
		"04EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC138015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720"
	};

	static string[] KAT_P521 = {
		"00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538",
		"0401894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A400493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5"
	};
}
