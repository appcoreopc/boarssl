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
using System.Diagnostics;
using System.IO;
using System.Text;

using Asn1;
using Crypto;
using IO;
using SSLTLS;
using XKeys;

/*
 * This is the main Twrch class implementation: it provides the entry
 * point for the command-line application.
 */

public class Twrch {

	public static void Main(string[] args)
	{
		try {
			new Twrch().Run(args);
		} catch (Exception e) {
			Console.WriteLine(e.ToString());
			Environment.Exit(1);
		}
	}

	bool trace;
	object conf;
	string commandFile;
	string commandArgs;
	bool commandVerbose;
	string chainRSAFile;
	byte[][] chainRSA;
	string skeyRSAFile;
	IPrivateKey skeyRSA;
	string chainECFile;
	byte[][] chainEC;
	string skeyECFile;
	IPrivateKey skeyEC;
	int[] versions;
	int versionMin;
	int versionMax;
	int[] cipherSuites;
	int[] hashAndSigns;
	int[] curves;
	bool noCloseNotify;
	object[] tests;
	IDictionary<string, object> testsByName;

	int totalTests;
	int totalSuccess;
	int totalFailures;

	void Run(string[] args)
	{
		List<string> r = new List<string>();
		string confName = null;
		int doEnum = 0;
		foreach (string a in args) {
			string b = a.ToLowerInvariant();
			switch (b) {
			case "-trace":
				trace = true;
				break;
			case "-enum":
				doEnum = 1;
				break;
			case "-noenum":
				doEnum = -1;
				break;
			case "-cv":
				commandVerbose = true;
				break;
			default:
				if (confName == null) {
					confName = a;
				} else {
					r.Add(a);
				}
				break;
			}
		}
		if (confName == null) {
			Usage();
		}
		string[] testNames = r.ToArray();
		conf = ReadConfig(confName);
		if (doEnum == 0) {
			doEnum = (testNames.Length == 0) ? 1 : -1;
		}
		commandFile = JSON.GetString(conf, "commandFile");
		commandArgs = JSON.GetString(conf, "commandArgs");
		chainRSAFile = JSON.GetString(conf, "chainRSA");
		chainECFile = JSON.GetString(conf, "chainEC");
		skeyRSAFile = JSON.GetString(conf, "skeyRSA");
		skeyECFile = JSON.GetString(conf, "skeyEC");
		chainRSA = DecodeChain(chainRSAFile);
		skeyRSA = DecodePrivateKey(skeyRSAFile);
		chainEC = DecodeChain(chainECFile);
		skeyEC = DecodePrivateKey(skeyECFile);
		versions = GetVersions();
		if (versions.Length == 0) {
			throw new Exception("Bad config: no versions");
		}
		versionMin = Int32.MaxValue;
		versionMax = -1;
		foreach (int v in versions) {
			versionMin = Math.Min(v, versionMin);
			versionMax = Math.Max(v, versionMax);
		}
		cipherSuites = GetCipherSuites();
		if (cipherSuites.Length == 0) {
			throw new Exception("Bad config: no cipher suites");
		}
		hashAndSigns = GetHashAndSigns();
		if (hashAndSigns.Length == 0) {
			throw new Exception("Bad config: no hash-and-signs");
		}
		curves = GetCurves();
		noCloseNotify = JSON.GetBool(conf, "noCloseNotify");
		tests = JSON.GetArray(conf, "tests");
		testsByName = new SortedDictionary<string, object>(
			StringComparer.Ordinal);
		foreach (object obj in tests) {
			string name = JSON.GetString(obj, "name");
			testsByName[name] = obj;
		}

		totalTests = 0;
		totalSuccess = 0;
		totalFailures = 0;
		if (doEnum > 0) {
			totalTests += ComputeTotalEnum();
		}
		if (testNames.Length == 0) {
			foreach (object obj in tests) {
				totalTests += GetNumTests(obj);
			}
		} else {
			foreach (string name in testNames) {
				bool client;
				int version, suite, curve, hs;
				if (StringToTEnum(name, out client, out version,
					out suite, out curve, out hs))
				{
					totalTests ++;
					continue;
				}
				if (name.EndsWith("_client")
					|| name.EndsWith("_server"))
				{
					totalTests ++;
				} else {
					totalTests += GetNumTests(
						testsByName[name]);
				}
			}
		}

		if (doEnum > 0) {
			RunEnum();
		}
		if (testNames.Length == 0) {
			foreach (object obj in tests) {
				RunTest(obj);
			}
		} else {
			foreach (string name in testNames) {
				bool client;
				int version, suite, curve, hs;
				if (StringToTEnum(name, out client, out version,
					out suite, out curve, out hs))
				{
					RunEnum(client, version,
						suite, curve, hs);
					continue;
				}
				if (name.EndsWith("_client")) {
					client = true;
				} else if (name.EndsWith("_server")) {
					client = false;
				} else {
					RunTest(testsByName[name]);
					continue;
				}
				string s = name.Substring(0, name.Length - 7);
				RunTest(client, testsByName[s]);
			}
		}

		Console.WriteLine();
		Console.WriteLine("\rtotal = {0}, failed = {1}",
			totalTests, totalFailures);
	}

	static void Usage()
	{
		Console.WriteLine(
"usage: Twrch.exe [ options ] config [ test... ]");
		Console.WriteLine(
"options:");
		Console.WriteLine(
"   -trace    enable trace mode (hex dump of all exchanged bytes)");
		Console.WriteLine(
"   -cv       pass the '-v' argument to the test command");
		Console.WriteLine(
"   -enum     perform all version/suite/curve/hash&sign combination tests");
		Console.WriteLine(
"   -noenum   do NOT perform the version/suite/curve/hash&sign tests");
		Environment.Exit(1);
	}

	static object ReadConfig(string fname)
	{
		using (TextReader r = File.OpenText(fname)) {
			return JSON.Parse(r);
		}
	}

	int[] GetVersions()
	{
		string[] r = JSON.GetStringArray(conf, "versions");
		int[] vv = new int[r.Length];
		for (int i = 0; i < r.Length; i ++) {
			vv[i] = SSL.GetVersionByName(r[i]);
		}
		return vv;
	}

	/* obsolete
	internal static int GetVersionByName(string s)
	{
		s = s.Replace(" ", "").Replace(".", "").ToUpperInvariant();
		switch (s) {
		case "TLS10": return SSL.TLS10;
		case "TLS11": return SSL.TLS11;
		case "TLS12": return SSL.TLS12;
		default:
			throw new Exception(string.Format(
				"Unknown version: '{0}'", s));
		}
	}
	*/

	int[] GetCipherSuites()
	{
		return GetSuitesByName(
			JSON.GetStringArray(conf, "cipherSuites"));
	}

	internal static int[] GetSuitesByName(string[] ss)
	{
		int[] r = new int[ss.Length];
		for (int i = 0; i < ss.Length; i ++) {
			r[i] = SSL.GetSuiteByName(ss[i]);
		}
		return r;
	}

	/* obsolete
	internal static int GetSuiteByName(string s)
	{
		switch (s) {
		case "NULL_WITH_NULL_NULL":
			return SSL.NULL_WITH_NULL_NULL;
		case "RSA_WITH_NULL_MD5":
			return SSL.RSA_WITH_NULL_MD5;
		case "RSA_WITH_NULL_SHA":
			return SSL.RSA_WITH_NULL_SHA;
		case "RSA_WITH_NULL_SHA256":
			return SSL.RSA_WITH_NULL_SHA256;
		case "RSA_WITH_RC4_128_MD5":
			return SSL.RSA_WITH_RC4_128_MD5;
		case "RSA_WITH_RC4_128_SHA":
			return SSL.RSA_WITH_RC4_128_SHA;
		case "RSA_WITH_3DES_EDE_CBC_SHA":
			return SSL.RSA_WITH_3DES_EDE_CBC_SHA;
		case "RSA_WITH_AES_128_CBC_SHA":
			return SSL.RSA_WITH_AES_128_CBC_SHA;
		case "RSA_WITH_AES_256_CBC_SHA":
			return SSL.RSA_WITH_AES_256_CBC_SHA;
		case "RSA_WITH_AES_128_CBC_SHA256":
			return SSL.RSA_WITH_AES_128_CBC_SHA256;
		case "RSA_WITH_AES_256_CBC_SHA256":
			return SSL.RSA_WITH_AES_256_CBC_SHA256;
		case "DH_DSS_WITH_3DES_EDE_CBC_SHA":
			return SSL.DH_DSS_WITH_3DES_EDE_CBC_SHA;
		case "DH_RSA_WITH_3DES_EDE_CBC_SHA":
			return SSL.DH_RSA_WITH_3DES_EDE_CBC_SHA;
		case "DHE_DSS_WITH_3DES_EDE_CBC_SHA":
			return SSL.DHE_DSS_WITH_3DES_EDE_CBC_SHA;
		case "DHE_RSA_WITH_3DES_EDE_CBC_SHA":
			return SSL.DHE_RSA_WITH_3DES_EDE_CBC_SHA;
		case "DH_DSS_WITH_AES_128_CBC_SHA":
			return SSL.DH_DSS_WITH_AES_128_CBC_SHA;
		case "DH_RSA_WITH_AES_128_CBC_SHA":
			return SSL.DH_RSA_WITH_AES_128_CBC_SHA;
		case "DHE_DSS_WITH_AES_128_CBC_SHA":
			return SSL.DHE_DSS_WITH_AES_128_CBC_SHA;
		case "DHE_RSA_WITH_AES_128_CBC_SHA":
			return SSL.DHE_RSA_WITH_AES_128_CBC_SHA;
		case "DH_DSS_WITH_AES_256_CBC_SHA":
			return SSL.DH_DSS_WITH_AES_256_CBC_SHA;
		case "DH_RSA_WITH_AES_256_CBC_SHA":
			return SSL.DH_RSA_WITH_AES_256_CBC_SHA;
		case "DHE_DSS_WITH_AES_256_CBC_SHA":
			return SSL.DHE_DSS_WITH_AES_256_CBC_SHA;
		case "DHE_RSA_WITH_AES_256_CBC_SHA":
			return SSL.DHE_RSA_WITH_AES_256_CBC_SHA;
		case "DH_DSS_WITH_AES_128_CBC_SHA256":
			return SSL.DH_DSS_WITH_AES_128_CBC_SHA256;
		case "DH_RSA_WITH_AES_128_CBC_SHA256":
			return SSL.DH_RSA_WITH_AES_128_CBC_SHA256;
		case "DHE_DSS_WITH_AES_128_CBC_SHA256":
			return SSL.DHE_DSS_WITH_AES_128_CBC_SHA256;
		case "DHE_RSA_WITH_AES_128_CBC_SHA256":
			return SSL.DHE_RSA_WITH_AES_128_CBC_SHA256;
		case "DH_DSS_WITH_AES_256_CBC_SHA256":
			return SSL.DH_DSS_WITH_AES_256_CBC_SHA256;
		case "DH_RSA_WITH_AES_256_CBC_SHA256":
			return SSL.DH_RSA_WITH_AES_256_CBC_SHA256;
		case "DHE_DSS_WITH_AES_256_CBC_SHA256":
			return SSL.DHE_DSS_WITH_AES_256_CBC_SHA256;
		case "DHE_RSA_WITH_AES_256_CBC_SHA256":
			return SSL.DHE_RSA_WITH_AES_256_CBC_SHA256;
		case "DH_anon_WITH_RC4_128_MD5":
			return SSL.DH_anon_WITH_RC4_128_MD5;
		case "DH_anon_WITH_3DES_EDE_CBC_SHA":
			return SSL.DH_anon_WITH_3DES_EDE_CBC_SHA;
		case "DH_anon_WITH_AES_128_CBC_SHA":
			return SSL.DH_anon_WITH_AES_128_CBC_SHA;
		case "DH_anon_WITH_AES_256_CBC_SHA":
			return SSL.DH_anon_WITH_AES_256_CBC_SHA;
		case "DH_anon_WITH_AES_128_CBC_SHA256":
			return SSL.DH_anon_WITH_AES_128_CBC_SHA256;
		case "DH_anon_WITH_AES_256_CBC_SHA256":
			return SSL.DH_anon_WITH_AES_256_CBC_SHA256;
		case "ECDH_ECDSA_WITH_NULL_SHA":
			return SSL.ECDH_ECDSA_WITH_NULL_SHA;
		case "ECDH_ECDSA_WITH_RC4_128_SHA":
			return SSL.ECDH_ECDSA_WITH_RC4_128_SHA;
		case "ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA":
			return SSL.ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA;
		case "ECDH_ECDSA_WITH_AES_128_CBC_SHA":
			return SSL.ECDH_ECDSA_WITH_AES_128_CBC_SHA;
		case "ECDH_ECDSA_WITH_AES_256_CBC_SHA":
			return SSL.ECDH_ECDSA_WITH_AES_256_CBC_SHA;
		case "ECDHE_ECDSA_WITH_NULL_SHA":
			return SSL.ECDHE_ECDSA_WITH_NULL_SHA;
		case "ECDHE_ECDSA_WITH_RC4_128_SHA":
			return SSL.ECDHE_ECDSA_WITH_RC4_128_SHA;
		case "ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA":
			return SSL.ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA;
		case "ECDHE_ECDSA_WITH_AES_128_CBC_SHA":
			return SSL.ECDHE_ECDSA_WITH_AES_128_CBC_SHA;
		case "ECDHE_ECDSA_WITH_AES_256_CBC_SHA":
			return SSL.ECDHE_ECDSA_WITH_AES_256_CBC_SHA;
		case "ECDH_RSA_WITH_NULL_SHA":
			return SSL.ECDH_RSA_WITH_NULL_SHA;
		case "ECDH_RSA_WITH_RC4_128_SHA":
			return SSL.ECDH_RSA_WITH_RC4_128_SHA;
		case "ECDH_RSA_WITH_3DES_EDE_CBC_SHA":
			return SSL.ECDH_RSA_WITH_3DES_EDE_CBC_SHA;
		case "ECDH_RSA_WITH_AES_128_CBC_SHA":
			return SSL.ECDH_RSA_WITH_AES_128_CBC_SHA;
		case "ECDH_RSA_WITH_AES_256_CBC_SHA":
			return SSL.ECDH_RSA_WITH_AES_256_CBC_SHA;
		case "ECDHE_RSA_WITH_NULL_SHA":
			return SSL.ECDHE_RSA_WITH_NULL_SHA;
		case "ECDHE_RSA_WITH_RC4_128_SHA":
			return SSL.ECDHE_RSA_WITH_RC4_128_SHA;
		case "ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":
			return SSL.ECDHE_RSA_WITH_3DES_EDE_CBC_SHA;
		case "ECDHE_RSA_WITH_AES_128_CBC_SHA":
			return SSL.ECDHE_RSA_WITH_AES_128_CBC_SHA;
		case "ECDHE_RSA_WITH_AES_256_CBC_SHA":
			return SSL.ECDHE_RSA_WITH_AES_256_CBC_SHA;
		case "ECDH_anon_WITH_NULL_SHA":
			return SSL.ECDH_anon_WITH_NULL_SHA;
		case "ECDH_anon_WITH_RC4_128_SHA":
			return SSL.ECDH_anon_WITH_RC4_128_SHA;
		case "ECDH_anon_WITH_3DES_EDE_CBC_SHA":
			return SSL.ECDH_anon_WITH_3DES_EDE_CBC_SHA;
		case "ECDH_anon_WITH_AES_128_CBC_SHA":
			return SSL.ECDH_anon_WITH_AES_128_CBC_SHA;
		case "ECDH_anon_WITH_AES_256_CBC_SHA":
			return SSL.ECDH_anon_WITH_AES_256_CBC_SHA;
		case "RSA_WITH_AES_128_GCM_SHA256":
			return SSL.RSA_WITH_AES_128_GCM_SHA256;
		case "RSA_WITH_AES_256_GCM_SHA384":
			return SSL.RSA_WITH_AES_256_GCM_SHA384;
		case "DHE_RSA_WITH_AES_128_GCM_SHA256":
			return SSL.DHE_RSA_WITH_AES_128_GCM_SHA256;
		case "DHE_RSA_WITH_AES_256_GCM_SHA384":
			return SSL.DHE_RSA_WITH_AES_256_GCM_SHA384;
		case "DH_RSA_WITH_AES_128_GCM_SHA256":
			return SSL.DH_RSA_WITH_AES_128_GCM_SHA256;
		case "DH_RSA_WITH_AES_256_GCM_SHA384":
			return SSL.DH_RSA_WITH_AES_256_GCM_SHA384;
		case "DHE_DSS_WITH_AES_128_GCM_SHA256":
			return SSL.DHE_DSS_WITH_AES_128_GCM_SHA256;
		case "DHE_DSS_WITH_AES_256_GCM_SHA384":
			return SSL.DHE_DSS_WITH_AES_256_GCM_SHA384;
		case "DH_DSS_WITH_AES_128_GCM_SHA256":
			return SSL.DH_DSS_WITH_AES_128_GCM_SHA256;
		case "DH_DSS_WITH_AES_256_GCM_SHA384":
			return SSL.DH_DSS_WITH_AES_256_GCM_SHA384;
		case "DH_anon_WITH_AES_128_GCM_SHA256":
			return SSL.DH_anon_WITH_AES_128_GCM_SHA256;
		case "DH_anon_WITH_AES_256_GCM_SHA384":
			return SSL.DH_anon_WITH_AES_256_GCM_SHA384;
		case "ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":
			return SSL.ECDHE_ECDSA_WITH_AES_128_CBC_SHA256;
		case "ECDHE_ECDSA_WITH_AES_256_CBC_SHA384":
			return SSL.ECDHE_ECDSA_WITH_AES_256_CBC_SHA384;
		case "ECDH_ECDSA_WITH_AES_128_CBC_SHA256":
			return SSL.ECDH_ECDSA_WITH_AES_128_CBC_SHA256;
		case "ECDH_ECDSA_WITH_AES_256_CBC_SHA384":
			return SSL.ECDH_ECDSA_WITH_AES_256_CBC_SHA384;
		case "ECDHE_RSA_WITH_AES_128_CBC_SHA256":
			return SSL.ECDHE_RSA_WITH_AES_128_CBC_SHA256;
		case "ECDHE_RSA_WITH_AES_256_CBC_SHA384":
			return SSL.ECDHE_RSA_WITH_AES_256_CBC_SHA384;
		case "ECDH_RSA_WITH_AES_128_CBC_SHA256":
			return SSL.ECDH_RSA_WITH_AES_128_CBC_SHA256;
		case "ECDH_RSA_WITH_AES_256_CBC_SHA384":
			return SSL.ECDH_RSA_WITH_AES_256_CBC_SHA384;
		case "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":
			return SSL.ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
		case "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":
			return SSL.ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
		case "ECDH_ECDSA_WITH_AES_128_GCM_SHA256":
			return SSL.ECDH_ECDSA_WITH_AES_128_GCM_SHA256;
		case "ECDH_ECDSA_WITH_AES_256_GCM_SHA384":
			return SSL.ECDH_ECDSA_WITH_AES_256_GCM_SHA384;
		case "ECDHE_RSA_WITH_AES_128_GCM_SHA256":
			return SSL.ECDHE_RSA_WITH_AES_128_GCM_SHA256;
		case "ECDHE_RSA_WITH_AES_256_GCM_SHA384":
			return SSL.ECDHE_RSA_WITH_AES_256_GCM_SHA384;
		case "ECDH_RSA_WITH_AES_128_GCM_SHA256":
			return SSL.ECDH_RSA_WITH_AES_128_GCM_SHA256;
		case "ECDH_RSA_WITH_AES_256_GCM_SHA384":
			return SSL.ECDH_RSA_WITH_AES_256_GCM_SHA384;
		case "ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":
			return SSL.ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
		case "ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256":
			return SSL.ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
		case "DHE_RSA_WITH_CHACHA20_POLY1305_SHA256":
			return SSL.DHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
		case "PSK_WITH_CHACHA20_POLY1305_SHA256":
			return SSL.PSK_WITH_CHACHA20_POLY1305_SHA256;
		case "ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256":
			return SSL.ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256;
		case "DHE_PSK_WITH_CHACHA20_POLY1305_SHA256":
			return SSL.DHE_PSK_WITH_CHACHA20_POLY1305_SHA256;
		case "RSA_PSK_WITH_CHACHA20_POLY1305_SHA256":
			return SSL.RSA_PSK_WITH_CHACHA20_POLY1305_SHA256;
		default:
			throw new Exception(string.Format(
				"Unknown cipher suite: '{0}'", s));
		}
	}
	*/

	int[] GetHashAndSigns()
	{
		return GetHashAndSignsByName(
			JSON.GetStringArray(conf, "hashAndSigns"));
	}

	internal static int[] GetHashAndSignsByName(string[] ss)
	{
		int[] r = new int[ss.Length];
		for (int i = 0; i < ss.Length; i ++) {
			r[i] = SSL.GetHashAndSignByName(ss[i]);
		}
		return r;
	}

	/* obsolete
	internal static int GetHashAndSignByName(string s)
	{
		switch (s) {
		case "RSA_MD5":       return SSL.RSA_MD5;
		case "RSA_SHA1":      return SSL.RSA_SHA1;
		case "RSA_SHA224":    return SSL.RSA_SHA224;
		case "RSA_SHA256":    return SSL.RSA_SHA256;
		case "RSA_SHA384":    return SSL.RSA_SHA384;
		case "RSA_SHA512":    return SSL.RSA_SHA512;
		case "ECDSA_MD5":     return SSL.ECDSA_MD5;
		case "ECDSA_SHA1":    return SSL.ECDSA_SHA1;
		case "ECDSA_SHA224":  return SSL.ECDSA_SHA224;
		case "ECDSA_SHA256":  return SSL.ECDSA_SHA256;
		case "ECDSA_SHA384":  return SSL.ECDSA_SHA384;
		case "ECDSA_SHA512":  return SSL.ECDSA_SHA512;
		default:
			throw new Exception(string.Format(
				"Unknown hash-and-sign: '{0}'", s));
		}
	}
	*/

	int[] GetCurves()
	{
		return GetCurvesByName(JSON.GetStringArray(conf, "curves"));
	}

	internal static int[] GetCurvesByName(string[] ss)
	{
		int[] r = new int[ss.Length];
		for (int i = 0; i < ss.Length; i ++) {
			r[i] = SSL.GetCurveByName(ss[i]);
		}
		return r;
	}

	/* obsolete
	internal static int GetCurveByName(string s)
	{
		switch (s) {
		case "Curve25519":  return SSL.Curve25519;
		case "NIST_P256":   return SSL.NIST_P256;
		case "NIST_P384":   return SSL.NIST_P384;
		case "NIST_P521":   return SSL.NIST_P521;
		default:
			throw new Exception(string.Format(
				"Unknown curve: '{0}'", s));
		}
	}
	*/

	/*
	 * RunEnum() builds and runs synthetic tests that exercise all
	 * combinations of protocol version, cipher suites, curves
	 * and hash-and-sign. Curves and hash-and-sign are enumerated
	 * only for ECDHE suites.
	 */
	void RunEnum()
	{
		RunEnum(true, true);
		RunEnum(false, true);
	}

	int RunEnum(bool cmdClient, bool doit)
	{
		int count = 0;
		foreach (int version in versions) {
			foreach (int suite in cipherSuites) {
				if (version < SSL.TLS12 && SSL.IsTLS12(suite)) {
					continue;
				}
				if (!SSL.IsECDHE(suite)) {
					if (doit) {
						RunEnum(cmdClient,
							version, suite, -1, -1);
					}
					count ++;
					continue;
				}
				bool needRSA = (version >= SSL.TLS12)
					&& SSL.IsECDHE_RSA(suite);
				bool needECDSA = (version >= SSL.TLS12)
					&& SSL.IsECDHE_ECDSA(suite);
				foreach (int hs in hashAndSigns) {
					int sa = hs & 0xFF;
					if (needRSA && sa != SSL.RSA) {
						continue;
					}
					if (needECDSA && sa != SSL.ECDSA) {
						continue;
					}
					foreach (int curve in curves) {
						if (doit) {
							RunEnum(cmdClient,
								version,
								suite,
								curve, hs);
						}
						count ++;
					}
				}
			}
		}
		return count;
	}

	int ComputeTotalEnum()
	{
		return RunEnum(true, false) + RunEnum(false, false);
	}

	static string TEnumToString(
		int version, int suite, int curve, int hs)
	{
		StringBuilder sb = new StringBuilder();
		sb.AppendFormat("enum_{0:X4}_{1:X4}", version, suite);
		if (curve >= 0 && hs >= 0) {
			sb.AppendFormat("_{0}_{1}", curve, hs);
		}
		return sb.ToString();
	}

	static bool StringToTEnum(string s,
		out bool cmdClient,
		out int version, out int suite,
		out int curve, out int hs)
	{
		cmdClient = false;
		version = -1;
		suite = -1;
		curve = -1;
		hs = -1;
		s = s.Trim();
		if (!s.StartsWith("enum_")) {
			return false;
		}
		s = s.Substring(5);
		if (s.EndsWith("_client")) {
			cmdClient = true;
		} else if (s.EndsWith("_server")) {
			cmdClient = false;
		} else {
			return false;
		}
		s = s.Substring(0, s.Length - 7);
		string[] ww = s.Split('_');
		if (ww.Length != 2 && ww.Length != 4) {
			return false;
		}
		version = ParseHex4(ww[0]);
		suite = ParseHex4(ww[1]);
		if (ww.Length == 2) {
			return version >= 0 && suite >= 0;
		} else {
			curve = ParseDec(ww[2]);
			hs = ParseDec(ww[3]);
			return version >= 0 && suite >= 0
				&& curve >= 0 && hs >= 0;
		}
	}

	static int HexVal(int cp)
	{
		if (cp >= '0' && cp <= '9') {
			return cp - '0';
		} else if (cp >= 'A' && cp <= 'F') {
			return cp - ('A' - 10);
		} else if (cp >= 'a' && cp <= 'f') {
			return cp - ('a' - 10);
		} else {
			return -1;
		}
	}

	static int ParseHex4(string s)
	{
		if (s.Length != 4) {
			return -1;
		}
		return ParseHex(s);
	}

	static int ParseHex(string s)
	{
		int acc = 0;
		for (int i = 0; i < 4; i ++) {
			int v = HexVal(s[i]);
			if (v < 0) {
				return -1;
			}
			acc = (acc << 4) + v;
		}
		return acc;
	}

	static int ParseDec(string s)
	{
		int n = s.Length;
		int acc = 0;
		for (int i = 0; i < n; i ++) {
			int v = HexVal(s[i]);
			if (v < 0 || v >= 10) {
				return -1;
			}
			acc = (acc * 10) + v;
		}
		return acc;
	}

	void RunEnum(bool cmdClient, int version, int suite, int curve, int hs)
	{
		IDictionary<string, object> d =
			new SortedDictionary<string, object>(
				StringComparer.Ordinal);
		d["name"] = TEnumToString(version, suite, curve, hs);
		d["versionMin"] = SSL.VersionName(version);
		d["versionMax"] = SSL.VersionName(version);
		d["cipherSuites"] = new string[] {
			SSL.CipherSuiteName(suite)
		};
		if (curve >= 0) {
			d["curves"] = new string[] {
				SSL.CurveName(curve)
			};
			d["hashAndSigns"] = new string[] {
				SSL.HashAndSignName(hs)
			};
		} else {
			d["curves"] = new string[0];
			d["hashAndSigns"] = new string[0];
		}
		if (SSL.IsRSA(suite) || SSL.IsECDHE_RSA(suite)) {
			d["serverCertType"] = "RSA";
		}
		if (SSL.IsECDH(suite) || SSL.IsECDHE_ECDSA(suite)) {
			d["serverCertType"] = "EC";
		}
		RunTest(cmdClient, d);
	}

	/*
	 * Get certificate type for the provided test (client-side or
	 * server-side certificate, depending on 'client').
	 *
	 * If the test does not contain an explicit indication, then
	 * the certificate type will be "none" for a client, "RSA" for
	 * a server.
	 */
	string GetCertType(object obj, bool client)
	{
		string name = client ? "clientCertType" : "serverCertType";
		string ct;
		if (JSON.TryGetString(obj, name, out ct)) {
			return ct;
		}
		return client ? "none" : "RSA";
	}

	int GetNumTests(object obj)
	{
		int num = 0;
		bool v;
		if (!JSON.TryGetBool(obj, "serverOnly", out v) || !v) {
			num ++;
		}
		if (!JSON.TryGetBool(obj, "clientOnly", out v) || !v) {
			num ++;
		}
		return num;
	}

	void RunTest(object obj)
	{
		bool v;
		if (!JSON.TryGetBool(obj, "serverOnly", out v) || !v) {
			RunTest(true, obj);
		}
		if (!JSON.TryGetBool(obj, "clientOnly", out v) || !v) {
			RunTest(false, obj);
		}
	}

	void RunTest(bool cmdClient, object obj)
	{
		string name = JSON.GetString(obj, "name")
			+ (cmdClient ? "_client" : "_server");
		Console.Write("\r({0}/{1})",
			totalSuccess + totalFailures + 1, totalTests);
		// Console.Write("{0}:", name);

		/*
		 * Expected command exit code:
		 *
		 *   0 if the command is supposed to exit gracefully
		 *   1 if the command should detect and report an error
		 */
		int expectedExitCode;
		JSON.TryGetInt32(obj, "expectedExitCode", out expectedExitCode);

		/*
		 * Expected failure: if defined, then we expect our
		 * library to throw an exception, and the message should
		 * contain that specific string.
		 */
		string expectedFailure;
		JSON.TryGetString(obj, "expectedFailure", out expectedFailure);

		/*
		 * Assemble the sub-process command line:
		 *
		 *  - Always one of "-client" or "-server"
		 *  - For a server command, a certificate and key are
		 *    always provided (defaults to RSA); for a client,
		 *    only if explicitly asked for.
		 */
		StringBuilder sb = new StringBuilder();
		if (cmdClient) {
			sb.Append("-client");
		} else {
			sb.Append("-server");
		}
		if (commandVerbose) {
			sb.Append(" -v");
		}
		string certType = GetCertType(obj, cmdClient);
		switch (certType) {
		case "RSA":
			sb.AppendFormat(" -cert \"{0}\" -key \"{1}\"",
				chainRSAFile, skeyRSAFile);
			break;
		case "EC":
			sb.AppendFormat(" -cert \"{0}\" -key \"{1}\"",
				chainECFile, skeyECFile);
			break;
		case "none":
			break;
		default:
			throw new Exception("Unknown certType: " + certType);
		}
		string extra;
		if (JSON.TryGetString(obj, "extraArgs", out extra)) {
			sb.Append(' ');
			sb.Append(extra);
		}

		/*
		 * Run the sub-process.
		 */
		ProcessStartInfo si = new ProcessStartInfo();
		si.FileName = commandFile;
		si.Arguments = string.Format(commandArgs, sb.ToString());
		si.UseShellExecute = false;
		si.ErrorDialog = false;
		si.CreateNoWindow = true;
		si.RedirectStandardInput = true;
		si.RedirectStandardOutput = true;

		using (Process pp = new Process()) {
			pp.StartInfo = si;
			pp.Start();
			Exception delayed = null;
			try {
				/*
				 * TODO: add a time-out on the streams
				 * so that the test never stalls
				 * indefinitely if the two SSL engines
				 * lose synchronisation.
				 */
				MergeStream ms = new MergeStream(
					pp.StandardOutput.BaseStream,
					pp.StandardInput.BaseStream);
				if (trace) {
					ms.Debug = Console.Out;
				}
				RunTestInner(cmdClient, obj, ms);
			} catch (Exception ex) {
				delayed = ex;
			}

			/*
			 * Once the test has run, we must make sure that
			 * the sub-processed is finished. It _should_ end
			 * properly by itself for all successful test cases,
			 * so if we have to kill it, then it's a bug.
			 */
			bool killed = false;
			if (!pp.WaitForExit(2000)) {
				try {
					pp.Kill();
				} catch {
					// ignored
				}
				pp.WaitForExit();
				killed = true;
			}
			int exc = pp.ExitCode;

			/*
			 * If we had to kill the command, then that is
			 * always a bug. Otherwise, we compare what we
			 * got with the expected outcomes.
			 */
			List<string> msg = new List<string>();
			if (killed) {
				msg.Add("COMMAND KILLED");
			}
			if (exc != expectedExitCode) {
				msg.Add("Wrong exit code: "
					+ exc + " (expected: "
					+ expectedExitCode + ")");
			}
			if (delayed == null) {
				if (expectedFailure != null) {
					msg.Add("An exception was expected");
				}
			} else {
				if (expectedFailure == null) {
					msg.Add(delayed.ToString());
				} else {
					string s = delayed.Message;
					if (s == null) {
						s = "";
					}
					if (s.IndexOf(expectedFailure) < 0) {
						msg.Add(delayed.ToString());
					}
				}
			}
			if (msg.Count == 0) {
				totalSuccess ++;
			} else {
				Console.WriteLine("{0}: FAIL:", name);
				foreach (string s in msg) {
					Console.WriteLine(s);
				}
				totalFailures ++;
			}
		}
	}

	void RunTestInner(bool cmdClient, object obj, Stream peer)
	{
		/*
		 * Create the SSL engine, and configure it as specified
		 * in the configuration object (with the default
		 * configuration as fallback).
		 */

		SSLEngine eng;
		byte[][] chain = null;
		IPrivateKey skey = null;
		string certType = GetCertType(obj, !cmdClient);
		switch (certType) {
		case "RSA":
			chain = chainRSA;
			skey = skeyRSA;
			break;
		case "EC":
			chain = chainEC;
			skey = skeyEC;
			break;
		case "none":
			break;
		default:
			throw new Exception("Unknown certType: " + certType);
		}
		if (cmdClient) {
			IServerPolicy spol = new SSLServerPolicyBasic(
				chain, skey, KeyUsage.EncryptAndSign);
			SSLServer ss = new SSLServer(peer, spol);
			ss.SessionCache = new SSLSessionCacheLRU(20);
			eng = ss;
		} else {
			SSLClient sc = new SSLClient(peer);
			sc.ServerCertValidator =
				SSLClient.InsecureCertValidator;
			eng = sc;
		}
		eng.NormalizeIOError = true;
		eng.AutoFlush = false;

		/*
		 * Minimum version.
		 */
		string svmin;
		if (JSON.TryGetString(obj, "versionMin", out svmin)) {
			eng.VersionMin = SSL.GetVersionByName(svmin);
		} else {
			eng.VersionMin = versionMin;
		}

		/*
		 * Maximum version.
		 */
		string svmax;
		if (JSON.TryGetString(obj, "versionMax", out svmax)) {
			eng.VersionMax = SSL.GetVersionByName(svmax);
		} else {
			eng.VersionMax = versionMax;
		}

		/*
		 * Supported cipher suites.
		 */
		string[] sccs;
		if (JSON.TryGetStringArray(obj, "cipherSuites", out sccs)) {
			eng.SupportedCipherSuites = GetSuitesByName(sccs);
		} else {
			eng.SupportedCipherSuites = cipherSuites;
		}

		/*
		 * Supported hash-and-sign algorithms.
		 */
		string[] shss;
		if (JSON.TryGetStringArray(obj, "hashAndSigns", out shss)) {
			eng.SupportedHashAndSign = GetHashAndSignsByName(shss);
		} else {
			eng.SupportedHashAndSign = hashAndSigns;
		}

		/*
		 * Supported elliptic curves.
		 */
		string[] secc;
		if (JSON.TryGetStringArray(obj, "curves", out secc)) {
			eng.SupportedCurves = GetCurvesByName(secc);
		} else {
			eng.SupportedCurves = curves;
		}

		/*
		 * What to do when there is no close_notify.
		 */
		bool ncn;
		if (JSON.TryGetBool(obj, "noCloseNotify", out ncn)) {
			eng.NoCloseNotify = ncn;
		} else {
			eng.NoCloseNotify = noCloseNotify;
		}

		/*
		 * Quirks.
		 */
		IDictionary<string, object> qm;
		if (JSON.TryGetObjectMap(obj, "quirks", out qm)) {
			SSLQuirks q = new SSLQuirks();
			foreach (string name in qm.Keys) {
				q[name] = JSON.GetString(qm, name);
			}
			eng.Quirks = q;
		}

		bool askClose;
		JSON.TryGetBool(obj, "askClose", out askClose);
		bool renegotiate, renegotiateAccepted;
		renegotiate = JSON.TryGetBool(obj, "renegotiate",
			out renegotiateAccepted);
		bool askRenegotiate, askRenegotiateAccepted;
		askRenegotiate = JSON.TryGetBool(obj, "askRenegotiate",
			out askRenegotiateAccepted);

		bool reconnectSelf = false, reconnectPeer = false;
		string rcs;
		if (JSON.TryGetString(obj, "reconnect", out rcs)) {
			switch (rcs) {
			case "self": reconnectSelf = true; break;
			case "peer": reconnectPeer = true; break;
			default:
				throw new Exception("Unknown 'reconnect' type: "
					+ rcs);
			}
		}

		bool forgetSelf = false, forgetPeer = false;
		string fgs;
		if (JSON.TryGetString(obj, "forget", out fgs)) {
			switch (fgs) {
			case "self": forgetSelf = true; break;
			case "peer": forgetPeer = true; break;
			default:
				throw new Exception("Unknown 'forget' type: "
					+ fgs);
			}
		}

		if (askClose) {
			SendCommand(eng, 'C');
			if (eng.ReadByte() != -1) {
				throw new Exception("Peer did not close");
			}
		} else if (renegotiate) {
			SendMessageNormal(eng, 10);
			if (eng.Renegotiate()) {
				if (!renegotiateAccepted) {
					throw new Exception("Renegotiation"
						+ " should have been rejected");
				}
			} else {
				if (renegotiateAccepted) {
					throw new Exception("Renegotiation"
						+ " should have been accepted");
				}
			}
			SendMessageNormal(eng, 9);
		} else if (askRenegotiate) {
			SendMessageNormal(eng, 10);
			long rc = eng.HandshakeCount;
			SendCommand(eng, 'G');
			string s = ReadLine(eng);
			switch (s) {
			case "DENIED":
				if (askRenegotiateAccepted) {
					throw new Exception("Renegotiation"
						+ " should have been accepted");
				}
				break;
			case "OK":
				if (!askRenegotiateAccepted) {
					throw new Exception("Renegotiation"
						+ " should have been rejected");
				}
				long nrc = eng.HandshakeCount;
				if (nrc != rc + 1) {
					throw new Exception(string.Format(
						"Wrong handshake count"
						+ " (old={0}, new={1})",
						rc, nrc));
				}
				break;
			default:
				throw new Exception(string.Format(
					"Unexpected answer string '{0}'", s));
			}
			SendMessageNormal(eng, 8);
		} else if (reconnectSelf || reconnectPeer) {
			SendMessageNormal(eng, 50);
			SendMessageNormal(eng, 100);
			if (forgetPeer) {
				SendCommand(eng, 'U');
				string s = ReadLine(eng);
				if (s != "DONE") {
					throw new Exception(string.Format(
						"Unexpected answer '{0}'", s));
				}
			}
			eng.CloseSub = false;
			if (reconnectPeer) {
				SendCommand(eng, 'T');
				if (eng.ReadByte() != -1) {
					throw new Exception(
						"Peer did not close");
				}
			} else {
				SendCommand(eng, 'R');
				string s = ReadLine(eng);
				if (s != "OK") {
					throw new Exception(string.Format(
						"Unexpected answer '{0}'", s));
				}
				eng.Close();
			}
			SSLEngine eng2;
			if (cmdClient) {
				IServerPolicy spol = new SSLServerPolicyBasic(
					chain, skey, KeyUsage.EncryptAndSign);
				SSLServer ss = new SSLServer(peer, spol);
				if (forgetSelf) {
					ss.SessionCache =
						new SSLSessionCacheLRU(20);
				} else {
					ss.SessionCache =
						((SSLServer)eng).SessionCache;
				}
				eng2 = ss;
			} else {
				SSLSessionParameters sp;
				if (forgetSelf) {
					sp = null;
				} else {
					sp = eng.SessionParameters;
				}
				SSLClient sc = new SSLClient(peer, sp);
				sc.ServerCertValidator =
					SSLClient.InsecureCertValidator;
				eng2 = sc;
			}
			eng2.NormalizeIOError = eng.NormalizeIOError;
			eng2.AutoFlush = eng.AutoFlush;
			eng2.VersionMin = eng.VersionMin;
			eng2.VersionMax = eng.VersionMax;
			eng2.SupportedCipherSuites = eng.SupportedCipherSuites;
			eng2.SupportedHashAndSign = eng.SupportedHashAndSign;
			eng2.SupportedCurves = eng.SupportedCurves;
			eng2.NoCloseNotify = eng.NoCloseNotify;
			eng2.Quirks = eng.Quirks;
			eng = eng2;
			SendMessageNormal(eng, 60);
			SendMessageNormal(eng, 90);
			if (forgetSelf || forgetPeer) {
				if (eng.IsResume) {
					throw new Exception(
						"Session was resumed");
				}
			} else {
				if (!eng.IsResume) {
					throw new Exception(
						"Session was not resumed");
				}
			}
		} else {
			for (int i = 0; i <= 38; i ++) {
				int len;
				if (i <= 20) {
					len = i;
				} else {
					len = 20 + (1 << (i - 20));
				}
				SendMessageNormal(eng, len);
			}
		}

		eng.Close();
	}

	/*
	 * Send a "normal" message to the peer, of the specified
	 * length: this is a sequence of 'len' random bytes, distinct
	 * from 0x0A, followed one 0x0A byte. The peer is supposed to
	 * respond with the SHA-1 hash of the message bytes (excluding
	 * the final 0x0A), encoded in hexadecimal (lowercase) and
	 * followed by a newline (0x0A). An exception is thrown if the
	 * expected value is not obtained.
	 */
	void SendMessageNormal(SSLEngine eng, int len)
	{
		SHA1 sha1 = new SHA1();
		byte[] buf = new byte[len + 1];
		RNG.GetBytesNonZero(buf, 0, len);
		for (int i = 0; i < len; i ++) {
			buf[i] ^= 0x0A;
		}
		buf[len] = 0x0A;
		if (len == 1) {
			buf[0] = (byte)('a' + (buf[0] & 0x0F));
		}
		StringBuilder sb = new StringBuilder();
		foreach (byte b in sha1.Hash(buf, 0, len)) {
			sb.AppendFormat("{0:x2}", b);
		}
		sb.Append('\n');
		eng.Write(buf, 0, buf.Length);
		eng.Flush();
		for (int i = 0; i < sb.Length; i ++) {
			int x = eng.ReadByte();
			int y = sb[i];
			if (x != y) {
				throw new Exception(string.Format(
					"received {0} (exp: {1})", y, x));
			}
		}
	}

	void SendCommand(SSLEngine eng, char cmd)
	{
		eng.WriteByte((byte)cmd);
		eng.WriteByte(0x0A);
		eng.Flush();
	}

	string ReadLine(SSLEngine eng)
	{
		StringBuilder sb = new StringBuilder();
		for (;;) {
			int c = eng.ReadByte();
			if (c < 0) {
				throw new Exception("Unexpected EOF");
			}
			if (c == 0x0A) {
				return sb.ToString();
			}
			sb.Append((char)c);
		}
	}

	static byte[][] DecodeChain(string fname)
	{
		byte[] buf = File.ReadAllBytes(fname);
		PEMObject[] fpo = AsnIO.DecodePEM(buf);
		if (fpo.Length == 0) {
			buf = AsnIO.FindBER(buf);
			if (buf == null) {
				throw new Exception(string.Format(
					"No certificate in file '{0}'", fname));
			}
			return new byte[][] { buf };
		}
		List<byte[]> r = new List<byte[]>();
		foreach (PEMObject po in fpo) {
			string tt = po.type.ToUpperInvariant();
			if (tt == "CERTIFICATE" || tt == "X509 CERTIFICATE") {
				r.Add(po.data);
			}
		}
		if (r.Count == 0) {
			throw new Exception(string.Format(
				"No certificate in file '{0}'", fname));
		}
		return r.ToArray();
	}

	static IPrivateKey DecodePrivateKey(string fname)
	{
		byte[] buf = File.ReadAllBytes(fname);
		PEMObject[] fpo = AsnIO.DecodePEM(buf);
		if (fpo.Length == 0) {
			buf = AsnIO.FindBER(buf);
		} else {
			buf = null;
			foreach (PEMObject po in fpo) {
				string tt = po.type.ToUpperInvariant();
				if (tt.IndexOf("PRIVATE KEY") >= 0) {
					if (buf != null) {
						throw new Exception(
							"Multiple keys in '"
							+ fname + "'");
					}
					buf = po.data;
				}
			}
		}
		if (buf == null) {
			throw new Exception(string.Format(
				"No private key in file '{0}'", fname));
		}
		return KF.DecodePrivateKey(buf);
	}
}
