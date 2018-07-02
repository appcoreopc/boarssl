/*
 * Copyright (c) 2018 Thomas Pornin <pornin@bolet.org>
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
using System.Net.Sockets;
using System.Text;
using System.Threading;

using Asn1;
using Crypto;
using IO;
using SSLTLS;
using XKeys;

/*
 * A simple command-line application that runs a client that connects
 * to a provided server. This is meant for debug purposes.
 */

public class Client {

	public static void Main(string[] args)
	{
		try {
			new Client().Run(args);
		} catch (Exception e) {
			Console.WriteLine(e.ToString());
			Environment.Exit(1);
		}
	}

	void Run(string[] args)
	{
		bool verbose = true;
		bool trace = false;
		string host = null;
		string sni = null;
		List<string> csNames = null;
		List<string> hsNames = null;
		int vmin = 0;
		int vmax = 0;
		for (int i = 0; i < args.Length; i ++) {
			string a = args[i];
			if (!a.StartsWith("-")) {
				if (host != null) {
					throw new Exception(
						"duplicate host name");
				}
				host = a;
				continue;
			}
			a = a.Substring(1).ToLowerInvariant();
			switch (a) {
			case "v":
				verbose = true;
				break;
			case "q":
				verbose = false;
				break;
			case "trace":
				trace = true;
				break;
			case "sni":
				if (sni != null) {
					throw new Exception(
						"duplicate SNI");
				}
				if (++ i >= args.Length) {
					throw new Exception(
						"no SNI provided");
				}
				sni = args[i];
				break;
			case "nosni":
				if (sni != null) {
					throw new Exception(
						"duplicate SNI");
				}
				sni = "";
				break;
			case "cs":
				if (++ i >= args.Length) {
					throw new Exception(
						"no cipher names provided");
				}
				if (csNames == null) {
					csNames = new List<string>();
				}
				AddNames(csNames, args[i]);
				break;
			case "hs":
				if (++ i >= args.Length) {
					throw new Exception(
						"no hash-and-sign provided");
				}
				if (hsNames == null) {
					hsNames = new List<string>();
				}
				AddNames(hsNames, args[i]);
				break;
			case "vmin":
				if (vmin != 0) {
					throw new Exception(
						"duplicate minimum version");
				}
				if (++ i >= args.Length) {
					throw new Exception(
						"no minimum version provided");
				}
				vmin = SSL.GetVersionByName(args[i]);
				break;
			case "vmax":
				if (vmax != 0) {
					throw new Exception(
						"duplicate maximum version");
				}
				if (++ i >= args.Length) {
					throw new Exception(
						"no maximum version provided");
				}
				vmax = SSL.GetVersionByName(args[i]);
				break;
			default:
				throw new Exception(string.Format(
					"Unknown option: '-{0}'", a));
			}
		}

		if (host == null) {
			throw new Exception("no host name provided");
		}
		int j = host.LastIndexOf(':');
		int port;
		if (j < 0) {
			port = 443;
		} else {
			if (!Int32.TryParse(host.Substring(j + 1), out port)
				|| port <= 0 || port > 65535)
			{
				throw new Exception("invalid port number");
			}
			host = host.Substring(0, j);
		}
		if (sni == null) {
			sni = host;
		}
		int[] css = null;
		if (csNames != null) {
			css = new int[csNames.Count];
			for (int i = 0; i < css.Length; i ++) {
				css[i] = SSL.GetSuiteByName(csNames[i]);
			}
		}
		int[] hss = null;
		if (hsNames != null) {
			hss = new int[hsNames.Count];
			for (int i = 0; i < hss.Length; i ++) {
				hss[i] = SSL.GetHashAndSignByName(hsNames[i]);
			}
		}
		if (vmin != 0 && vmax != 0 && vmin > vmax) {
			throw new Exception("invalid version range");
		}

		/*
		 * Connect to the designated server.
		 */
		TcpClient tc = new TcpClient(host, port);
		Socket sock = tc.Client;
		Stream ns = tc.GetStream();
		if (trace) {
			MergeStream ms = new MergeStream(ns, ns);
			ms.Debug = Console.Out;
			ns = ms;
		}
		SSLClient ssl = new SSLClient(ns);
		if (sni != "") {
			ssl.ServerName = sni;
		}
		if (css != null) {
			ssl.SupportedCipherSuites = css;
		}
		if (hss != null) {
			ssl.SupportedHashAndSign = hss;
		}
		if (vmin != 0) {
			ssl.VersionMin = vmin;
		}
		if (vmax != 0) {
			ssl.VersionMax = vmax;
		}

		/*
		 * This is a debug tool; we accept the server certificate
		 * without validation.
		 */
		ssl.ServerCertValidator = SSLClient.InsecureCertValidator;

		/*
		 * Force a Flush. There is no application data to flush
		 * at this point, but as a side-effect it forces the
		 * handshake to complete.
		 */
		ssl.Flush();

		if (verbose) {
			Console.WriteLine("Handshake completed:");
			Console.WriteLine("  Version      = {0}",
				SSL.VersionName(ssl.Version));
			Console.WriteLine("  Cipher suite = {0}",
				SSL.CipherSuiteName(ssl.CipherSuite));
		}

		/*
		 * Now relay data back and forth between the connection
		 * and the console. Since the underlying SSL stream does
		 * not support simultaneous reads and writes, we use
		 * the following approximation:
		 *
		 *  - We poll on the socket for incoming data. When there
		 *    is some activity, we assume that some application
		 *    data (or closure) follows, and we read it. It is
		 *    then immediately written out (synchronously) on
		 *    standard output.
		 *
		 *  - When waiting for read activity on the socket, we
		 *    regularly (every 200 ms) check for data to read on
		 *    standard input. If there is, we read it, and send
		 *    it synchronously on the SSL stream.
		 *
		 *  - The data reading from console is performed by
		 *    another thread.
		 *
		 * Since SSL records are read one by one, we know that,
		 * by using a buffer larger than 16 kB, a single Read()
		 * call cannot leave any buffered application data.
		 */
		ssl.CloseSub = false;
		Thread t = new Thread(new ThreadStart(CRThread));
		t.IsBackground = true;
		t.Start();
		byte[] buf = new byte[16384];
		Stream stdout = Console.OpenStandardOutput();
		for (;;) {
			if (sock.Poll(200000, SelectMode.SelectRead)) {
				int rlen = ssl.Read(buf, 0, buf.Length);
				if (rlen < 0) {
					Console.WriteLine(
						"Connection closed.\n");
					break;
				}
				stdout.Write(buf, 0, rlen);
			} else {
				while (CRHasData()) {
					int rlen = CRRead(buf, 0, buf.Length);
					if (rlen < 0) {
						ssl.Close();
						break;
					}
					if (rlen > 0) {
						ssl.Write(buf, 0, rlen);
					}
				}
			}
		}
		sock.Close();
	}

	static void AddNames(List<string> d, string str)
	{
		foreach (string name in str.Split(
			new char[] { ',', ':', ';' },
			StringSplitOptions.RemoveEmptyEntries))
		{
			d.Add(name.Trim());
		}
	}

	object consoleReadLock = new object();
	byte[] crBuf = new byte[16384];
	int crPtr = 0;
	bool crClosed = false;

	bool CRHasData()
	{
		lock (consoleReadLock) {
			return crPtr != 0 || crClosed;
		}
	}

	int CRRead(byte[] buf, int off, int len)
	{
		lock (consoleReadLock) {
			if (crPtr == 0 && crClosed) {
				return -1;
			}
			int rlen = Math.Min(len, crPtr);
			Array.Copy(crBuf, 0, buf, off, rlen);
			if (rlen > 0 && rlen < crPtr) {
				Array.Copy(crBuf, rlen, crBuf, 0, crPtr - rlen);
			}
			crPtr -= rlen;
			Monitor.PulseAll(consoleReadLock);
			return rlen;
		}
	}

	void CRThread()
	{
		byte[] buf = new byte[crBuf.Length];
		Stream stdin = Console.OpenStandardInput();

		for (;;) {
			lock (consoleReadLock) {
				while (crPtr == crBuf.Length) {
					Monitor.Wait(consoleReadLock);
				}
			}
			int rlen = stdin.Read(buf, 0, buf.Length);
			lock (consoleReadLock) {
				Monitor.PulseAll(consoleReadLock);
				if (rlen < 0) {
					crClosed = true;
					break;
				}
				Array.Copy(buf, 0, crBuf, crPtr, rlen);
				crPtr += rlen;
			}
		}
	}
}
