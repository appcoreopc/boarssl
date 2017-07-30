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

namespace SSLTLS {

/*
 * An SSLQuirks instance is a set of named parameters that can be
 * applied to an SSL engine (client or server) and alter its behaviour.
 * Some of these variants are rarely used options permitted by the
 * standard; others are downright invalid, and are meant to verify that
 * a peer implementation is properly reacting to malformed messages
 * and other anomalous conditions.
 *
 * Parameter names and values are strings. Parameter names are
 * case-sensitive. As a matter of convention:
 *
 *   - Boolean values are set as "true" or "false" string values.
 *
 *   - Integers are encoded in decimal or hexadecimal; hexadecimal
 *     values have a leading "0x" header (or "-0x" for a negative
 *     hexadecimal value).
 */

public class SSLQuirks {

	/*
	 * When reading a parameter value, and the parameter is not
	 * defined, null is returned.
	 */
	public string this[string name] {
		get {
			string v;
			if (d.TryGetValue(name, out v)) {
				return v;
			} else {
				return null;
			}
		}
		set {
			d[name] = value;
		}
	}

	IDictionary<string, string> d;

	public SSLQuirks()
	{
		d = new SortedDictionary<string, string>(
			StringComparer.Ordinal);
	}

	/*
	 * Get a boolean quirk. If defined, then the boolean value is
	 * written in 'val' and true is returned; otherwise, 'val' is
	 * set to false, and false is returned.
	 */
	public bool TryGetBoolean(string name, out bool val)
	{
		string s;
		if (!d.TryGetValue(name, out s)) {
			val = false;
			return false;
		}
		switch (s) {
		case "true":   val = true; return true;
		case "false":  val = false; return true;
		}
		s = s.ToLowerInvariant();
		switch (s) {
		case "true":   val = true; return true;
		case "false":  val = false; return true;
		}
		throw new Exception("Quirk value is not a boolean");
	}

	/*
	 * Get a boolean quirk. If undefined, the provided default value
	 * is returned.
	 */
	public bool GetBoolean(string name, bool defaultValue)
	{
		bool val;
		if (TryGetBoolean(name, out val)) {
			return val;
		} else {
			return defaultValue;
		}
	}

	/*
	 * Get an integer quirk. If defined, then the integer value is
	 * written in 'val' and true is returned; otherwise, 'val' is
	 * set to 0, and false is returned.
	 */
	public bool TryGetInteger(string name, out int val)
	{
		string s;
		if (!d.TryGetValue(name, out s)) {
			val = 0;
			return false;
		}
		bool neg = false;
		if (s.StartsWith("-")) {
			neg = true;
			s = s.Substring(1);
		}
		int radix;
		if (s.StartsWith("0x")) {
			radix = 16;
			s = s.Substring(2);
		} else {
			radix = 10;
		}
		int acc = 0;
		if (s.Length == 0) {
			throw new Exception("Quirk value is not an integer");
		}
		foreach (char c in s) {
			int x;
			if (c >= '0' && c <= '9') {
				x = c - '0';
			} else if (c >= 'A' && c <= 'F') {
				x = c - ('A' - 10);
			} else if (c >= 'a' && c <= 'f') {
				x = c - ('a' - 10);
			} else {
				throw new Exception(
					"Quirk value is not an integer");
			}
			if (x >= radix) {
				throw new Exception(
					"Quirk value is not an integer");
			}
			acc = (acc * radix) + x;
		}
		if (neg) {
			acc = -acc;
		}
		val = acc;
		return true;
	}

	/*
	 * Get an integer quirk. If undefined, the provided default value
	 * is returned.
	 */
	public int GetInteger(string name, int defaultValue)
	{
		int val;
		if (TryGetInteger(name, out val)) {
			return val;
		} else {
			return defaultValue;
		}
	}

	/*
	 * Get a string quirk. If undefined, the provided default value
	 * is returned.
	 */
	public string GetString(string name, string defaultValue)
	{
		string s;
		if (d.TryGetValue(name, out s)) {
			return s;
		} else {
			return defaultValue;
		}
	}
}

}
