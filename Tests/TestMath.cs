using System;
using System.IO;
using System.Reflection;
using System.Text;

using Crypto;

internal class TestMath {

	internal static void Main(string[] args)
	{
		try {
			TestModInt();
		} catch (Exception e) {
			Console.WriteLine(e.ToString());
			Environment.Exit(1);
		}
	}

	static ZInt RandPrime(int k)
	{
		if (k < 2) {
			throw new ArgumentException();
		}
		ZInt min = ZInt.One << (k - 1);
		ZInt max = ZInt.One << k;
		for (;;) {
			ZInt p = ZInt.MakeRand(min, max) | 1;
			if (p.IsPrime) {
				return p;
			}
		}
	}

	internal static void TestModInt()
	{
		Console.Write("Test ModInt: ");
		for (int k = 2; k <= 128; k ++) {
			for (int i = 0; i < 10; i ++) {
				int kwlen = (k + 30) / 31;
				int kwb = 31 * kwlen;

				ZInt p;
				if (k >= 9) {
					p = ZInt.DecodeUnsignedBE(
						BigInt.RandPrime(k));
					if (p.BitLength != k) {
						throw new Exception(
							"wrong prime size");
					}
					if (!p.IsPrime) {
						throw new Exception(
							"not prime");
					}
				} else {
					p = RandPrime(k);
				}

				ZInt a = ZInt.MakeRand(p);
				ZInt b = ZInt.MakeRand(p);
				ZInt v = ZInt.MakeRand(k + 60);
				if (b == ZInt.Zero) {
					b = ZInt.One;
				}
				byte[] ea = a.ToBytesBE();
				byte[] eb = b.ToBytesBE();
				byte[] ev = v.ToBytesBE();
				ModInt mz = new ModInt(p.ToBytesBE());
				ModInt ma = mz.Dup();
				ModInt mb = mz.Dup();

				ma.Decode(ea);
				CheckEq(ma, a);

				ma.Decode(ea);
				mb.Decode(eb);
				ma.Add(mb);
				CheckEq(ma, (a + b).Mod(p));

				ma.Decode(ea);
				mb.Decode(eb);
				ma.Sub(mb);
				CheckEq(ma, (a - b).Mod(p));

				ma.Decode(ea);
				ma.Negate();
				CheckEq(ma, (-a).Mod(p));

				ma.Decode(ea);
				mb.Decode(eb);
				ma.MontyMul(mb);
				CheckEq((ZInt.DecodeUnsignedBE(ma.Encode())
					<< kwb).Mod(p), (a * b).Mod(p));

				ma.Decode(ea);
				ma.ToMonty();
				CheckEq(ma, (a << kwb).Mod(p));
				ma.FromMonty();
				CheckEq(ma, a);

				ma.Decode(ea);
				mb.Decode(eb);
				ma.ToMonty();
				mb.ToMonty();
				ma.MontyMul(mb);
				ma.FromMonty();
				CheckEq(ma, (a * b).Mod(p));

				mb.Decode(eb);
				mb.Invert();
				ZInt r = ZInt.DecodeUnsignedBE(mb.Encode());
				CheckEq(ZInt.One, (r * b).Mod(p));

				ma.Decode(ea);
				ma.Pow(ev);
				CheckEq(ma, ZInt.ModPow(a, v, p));

				ma.DecodeReduce(ev);
				CheckEq(ma, v.Mod(p));

				mb.Decode(eb);
				ma.Set(mb);
				CheckEq(ma, b);

				ModInt mv = new ModInt(
					((p << 61) + 1).ToBytesBE());
				mv.Decode(ev);
				ma.Set(mv);
				CheckEq(ma, v.Mod(p));

				if (k >= 9) {
					ma.Decode(ea);
					mb.Set(ma);
					mb.ToMonty();
					mb.MontyMul(ma);
					if ((int)mb.SqrtBlum() != -1) {
						throw new CryptoException(
							"square root failed");
					}
					if (!mb.Eq(ma)) {
						mb.Negate();
					}
					CheckEq(mb, a);

					mb.Decode(eb);
					mb.ToMonty();
					mb.MontySquare();
					mb.FromMonty();
					mb.Negate();
					if (mb.SqrtBlum() != 0) {
						throw new CryptoException(
							"square root should"
							+ " have failed");
					}
				}
			}
			Console.Write(".");
		}
		Console.WriteLine(" done.");
	}

	static void CheckEq(ModInt m, ZInt z)
	{
		CheckEq(ZInt.DecodeUnsignedBE(m.Encode()), z);
	}

	static void CheckEq(ZInt x, ZInt z)
	{
		if (x != z) {
			throw new Exception(String.Format(
				"mismatch: x={0} z={1}", x, z));
		}
	}
}
