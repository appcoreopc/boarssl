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

/*
 * A simple JSON parser.
 *
 * A JSON value is returned as:
 *
 *   - null, if the value is a JSON null;
 *
 *   - a string, if the value is a JSON string, a JSON number or a
 *     JSON boolean;
 *
 *   - an IDictionary<string, object>, if the value is a JSON object;
 *
 *   - an array (object[]), if the value is a JSON array.
 *
 * This parser is lenient with numbers, in that it will gleefully
 * accumulate digits, dots, minus sign, plus sign, lowercase 'e'
 * and uppercase 'E' characters in any order.
 */

public static class JSON {

	/*
	 * Parse a source stream as a JSON object.
	 */
	public static object Parse(Stream src)
	{
		return Parse(new StreamReader(src));
	}

	/*
	 * Parse a source stream as a JSON object.
	 */
	public static object Parse(TextReader tr)
	{
		int cp = NextNonWS(tr, ' ');
		object val;
		cp = ReadValue(tr, cp, out val);
		while (cp >= 0) {
			if (!IsWS(cp)) {
				throw new Exception(
					"Trailing garbage after JSON value");
			}
			cp = tr.Read();
		}
		return val;
	}

	/*
	 * Encode a JSON object onto a stream.
	 */
	public static void Encode(object obj, Stream dst)
	{
		TextWriter tw = new StreamWriter(dst);
		Encode(obj, tw);
		tw.Flush();
	}

	/*
	 * Encode a JSON object onto a stream.
	 */
	public static void Encode(object obj, TextWriter tw)
	{
		EncodeValue(0, obj, tw);
		tw.WriteLine();
	}

	/*
	 * Get a value by path. If the value is present, then 'val'
	 * is set to that value (which may be null) and true is returned;
	 * otherwise, 'val' is set to null and false is written.
	 *
	 * An exception is still thrown if one of the upper path elements
	 * does not have the expected type.
	 */
	public static bool TryGet(object obj, string path, out object val)
	{
		int n = path.Length;
		int p = 0;
		while (p < n) {
			int q = path.IndexOf('/', p);
			if (q < 0) {
				q = n;
			}
			IDictionary<string, object> d =
				obj as IDictionary<string, object>;
			if (d == null) {
				throw new Exception(string.Format(
					"Path '{0}': not an object",
					path.Substring(0, p)));
			}
			string name = path.Substring(p, q - p);
			if (!d.ContainsKey(name)) {
				val = null;
				return false;
			}
			obj = d[name];
			p = q + 1;
		}
		val = obj;
		return true;
	}

	/*
	 * Get a value by path.
	 */
	public static object Get(object obj, string path)
	{
		object val;
		if (!TryGet(obj, path, out val)) {
			throw new Exception("No such value: " + path);
		}
		return val;
	}

	/*
	 * Try to get a value by path; value (if present) should be a
	 * string.
	 */
	public static bool TryGetString(object obj, string path, out string val)
	{
		object gv;
		if (!TryGet(obj, path, out gv)) {
			val = null;
			return false;
		}
		if (!(gv is string)) {
			throw new Exception("Value at " + path
				+ " is not a string");
		}
		val = gv as string;
		return true;
	}

	/*
	 * Get a value by path; value should be a string.
	 */
	public static string GetString(object obj, string path)
	{
		string str;
		if (!TryGetString(obj, path, out str)) {
			throw new Exception("No such value: " + path);
		}
		return str;
	}

	/*
	 * Try to get a value by path; value should be an array.
	 */
	public static bool TryGetArray(object obj, string path,
		out object[] val)
	{
		object gv;
		if (!TryGet(obj, path, out gv)) {
			val = null;
			return false;
		}
		val = gv as object[];
		if (val == null) {
			throw new Exception("Value at " + path
				+ " is not an array");
		}
		return true;
	}

	/*
	 * Get a value by path; value should be an array.
	 */
	public static object[] GetArray(object obj, string path)
	{
		object[] a;
		if (!TryGetArray(obj, path, out a)) {
			throw new Exception("No such value: " + path);
		}
		return a;
	}

	/*
	 * Try to get a value by path; if present, value should be an
	 * array, whose elements are all strings. A new, properly typed
	 * array is returned, containing the strings.
	 */
	public static bool TryGetStringArray(object obj, string path,
		out string[] a)
	{
		object[] g;
		if (!TryGetArray(obj, path, out g)) {
			a = null;
			return false;
		}
		string[] r = new string[g.Length];
		for (int i = 0; i < g.Length; i ++) {
			string s = g[i] as string;
			if (s == null) {
				throw new Exception(string.Format("Element {0}"
					+ " in array {1} is not a string",
					i, path));
			}
			r[i] = s;
		}
		a = r;
		return true;
	}

	/*
	 * Get a value by path; value should be an array, whose
	 * elements are all strings. A new, properly typed array is
	 * returned, containing the strings.
	 */
	public static string[] GetStringArray(object obj, string path)
	{
		string[] a;
		if (!TryGetStringArray(obj, path, out a)) {
			throw new Exception("No such value: " + path);
		}
		return a;
	}

	/*
	 * Try to get a value by path; value should a boolean.
	 */
	public static bool TryGetBool(object obj, string path, out bool val)
	{
		object gv;
		if (!TryGet(obj, path, out gv)) {
			val = false;
			return false;
		}
		if (gv is bool) {
			val = (bool)gv;
			return true;
		} else if (gv is string) {
			switch (gv as string) {
			case "true":   val = true; return true;
			case "false":  val = false; return true;
			}
		}
		throw new Exception("Value at " + path + " is not a boolean");
	}

	/*
	 * Get a value by path; value should a boolean.
	 */
	public static bool GetBool(object obj, string path)
	{
		bool v;
		if (!TryGetBool(obj, path, out v)) {
			throw new Exception("No such value: " + path);
		}
		return v;
	}

	/*
	 * Try to get a value by path; value should an integer.
	 */
	public static bool TryGetInt32(object obj, string path, out int val)
	{
		object gv;
		if (!TryGet(obj, path, out gv)) {
			val = 0;
			return false;
		}
		if (gv is int) {
			val = (int)gv;
			return true;
		} else if (gv is uint) {
			uint x = (uint)gv;
			if (x <= (uint)Int32.MaxValue) {
				val = (int)x;
				return true;
			}
		} else if (gv is long) {
			long x = (long)gv;
			if (x >= (long)Int32.MinValue
				&& x <= (long)Int32.MaxValue)
			{
				val = (int)x;
				return true;
			}
		} else if (gv is ulong) {
			ulong x = (ulong)gv;
			if (x <= (ulong)Int32.MaxValue) {
				val = (int)x;
				return true;
			}
		} else if (gv is string) {
			int x;
			if (Int32.TryParse((string)gv, out x)) {
				val = x;
				return true;
			}
		}
		throw new Exception("Value at " + path + " is not a boolean");
	}

	/*
	 * Get a value by path; value should an integer.
	 */
	public static int GetInt32(object obj, string path)
	{
		int v;
		if (!TryGetInt32(obj, path, out v)) {
			throw new Exception("No such value: " + path);
		}
		return v;
	}

	/*
	 * Try to get a value by path; value should be an object map.
	 */
	public static bool TryGetObjectMap(object obj, string path,
		out IDictionary<string, object> val)
	{
		object gv;
		if (!TryGet(obj, path, out gv)) {
			val = null;
			return false;
		}
		val = gv as IDictionary<string, object>;
		if (val == null) {
			throw new Exception("Value at " + path
				+ " is not an object map");
		}
		return true;
	}

	/*
	 * Get a value by path; value should be an object map.
	 */
	public static IDictionary<string, object> GetObjectMap(
		object obj, string path)
	{
		IDictionary<string, object> v;
		if (!TryGetObjectMap(obj, path, out v)) {
			throw new Exception("No such value: " + path);
		}
		return v;
	}

	static void EncodeValue(int indent, object obj, TextWriter tw)
	{
		if (obj == null) {
			tw.Write("null");
			return;
		}
		if (obj is bool) {
			tw.Write((bool)obj ? "true" : "false");
			return;
		}
		if (obj is string) {
			EncodeString((string)obj, tw);
			return;
		}
		if (obj is int || obj is uint || obj is long || obj is ulong) {
			tw.Write(obj.ToString());
			return;
		}
		if (obj is Array) {
			tw.Write("[");
			Array a = (Array)obj;
			for (int i = 0; i < a.Length; i ++) {
				if (i != 0) {
					tw.Write(",");
				}
				tw.WriteLine();
				Indent(indent + 1, tw);
				EncodeValue(indent + 1, a.GetValue(i), tw);
			}
			tw.WriteLine();
			Indent(indent, tw);
			tw.Write("]");
			return;
		}
		if (obj is IDictionary<string, object>) {
			tw.Write("{");
			IDictionary<string, object> d =
				(IDictionary<string, object>)obj;
			bool first = true;
			foreach (string name in d.Keys) {
				if (first) {
					first = false;
				} else {
					tw.Write(",");
				}
				tw.WriteLine();
				Indent(indent + 1, tw);
				EncodeString(name, tw);
				tw.Write(" : ");
				EncodeValue(indent + 1, d[name], tw);
			}
			tw.WriteLine();
			Indent(indent, tw);
			tw.Write("}");
			return;
		}
		throw new Exception("Unknown value type: "
			+ obj.GetType().FullName);
	}

	static void Indent(int indent, TextWriter tw)
	{
		while (indent -- > 0) {
			tw.Write("  ");
		}
	}

	static void EncodeString(string str, TextWriter tw)
	{
		tw.Write('\"');
		foreach (char c in str) {
			if (c >= 32 && c <= 126) {
				if (c == '\\' || c == '"') {
					tw.Write('\\');
				}
				tw.Write(c);
			} else {
				switch (c) {
				case '\b':
					tw.Write("\\b");
					break;
				case '\f':
					tw.Write("\\f");
					break;
				case '\n':
					tw.Write("\\n");
					break;
				case '\r':
					tw.Write("\\r");
					break;
				case '\t':
					tw.Write("\\t");
					break;
				default:
					tw.Write("\\u{0:X4}", (int)c);
					break;
				}
			}
		}
		tw.Write('\"');
	}

	/*
	 * Read a value, that starts with the provided character. The
	 * value is written in 'val'. Returned value is the next
	 * character in the stream, or a synthetic space if the next
	 * character was not read.
	 */
	static int ReadValue(TextReader tr, int cp, out object val)
	{
		switch (cp) {
		case '"':
			val = ReadString(tr);
			return ' ';
		case '{':
			val = ReadObject(tr);
			return ' ';
		case '[':
			val = ReadArray(tr);
			return ' ';
		case 't':
			CheckKeyword(tr, "true");
			val = "true";
			return ' ';
		case 'f':
			CheckKeyword(tr, "false");
			val = "false";
			return ' ';
		case 'n':
			CheckKeyword(tr, "null");
			val = null;
			return ' ';
		case '-':
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			StringBuilder sb = new StringBuilder();
			sb.Append((char)cp);
			cp = ReadNumber(tr, sb);
			val = sb.ToString();
			return cp;
		default:
			throw Unexpected(cp);
		}
	}

	static string ReadString(TextReader tr)
	{
		StringBuilder sb = new StringBuilder();
		bool lcwb = false;
		for (;;) {
			int cp = Next(tr);
			if (lcwb) {
				lcwb = false;
				switch (cp) {
				case '"': case '\\': case '/':
					sb.Append((char)cp);
					break;
				case 'b':
					sb.Append('\b');
					break;
				case 'f':
					sb.Append('\f');
					break;
				case 'n':
					sb.Append('\n');
					break;
				case 'r':
					sb.Append('\r');
					break;
				case 't':
					sb.Append('\t');
					break;
				case 'u':
					sb.Append(ReadUnicodeEscape(tr));
					break;
				default:
					throw Unexpected(cp);
				}
			} else {
				if (cp == '\\') {
					lcwb = true;
				} else if (cp == '"') {
					return sb.ToString();
				} else if (cp <= 0x1F) {
					throw Unexpected(cp);
				} else {
					sb.Append((char)cp);
				}
			}
		}
	}

	static char ReadUnicodeEscape(TextReader tr)
	{
		int acc = 0;
		for (int i = 0; i < 4; i ++) {
			int cp = Next(tr);
			if (cp >= '0' && cp <= '9') {
				cp -= '0';
			} else if (cp >= 'A' && cp <= 'F') {
				cp -= 'A' - 10;
			} else if (cp >= 'a' && cp <= 'f') {
				cp -= 'a' - 10;
			} else {
				throw Unexpected(cp);
			}
			acc = (acc << 4) + cp;
		}
		return (char)acc;
	}

	static IDictionary<string, object> ReadObject(TextReader tr)
	{
		IDictionary<string, object> r =
			new SortedDictionary<string, object>(
				StringComparer.Ordinal);
		int cp = NextNonWS(tr, ' ');
		if (cp == '}') {
			return r;
		}
		for (;;) {
			if (cp != '"') {
				throw Unexpected(cp);
			}
			string name = ReadString(tr);
			cp = NextNonWS(tr, ' ');
			if (cp != ':') {
				throw Unexpected(cp);
			}
			if (r.ContainsKey(name)) {
				throw new Exception(string.Format(
					"duplicate key '{0}' in object",
					name));
			}
			object val;
			cp = NextNonWS(tr, ' ');
			cp = ReadValue(tr, cp, out val);
			r[name] = val;
			cp = NextNonWS(tr, cp);
			if (cp == '}') {
				return r;
			}
			if (cp != ',') {
				throw Unexpected(cp);
			}
			cp = NextNonWS(tr, ' ');
		}
	}

	static object[] ReadArray(TextReader tr)
	{
		List<object> r = new List<object>();
		int cp = NextNonWS(tr, ' ');
		if (cp == ']') {
			return r.ToArray();
		}
		for (;;) {
			object val;
			cp = ReadValue(tr, cp, out val);
			r.Add(val);
			cp = NextNonWS(tr, cp);
			if (cp == ']') {
				return r.ToArray();
			}
			if (cp != ',') {
				throw Unexpected(cp);
			}
			cp = NextNonWS(tr, ' ');
		}
	}

	static int ReadNumber(TextReader tr, StringBuilder sb)
	{
		int cp;
		for (;;) {
			cp = tr.Read();
			switch (cp) {
			case '0': case '1': case '2': case '3': case '4':
			case '5': case '6': case '7': case '8': case '9':
			case '.': case '-': case '+': case 'e': case 'E':
				sb.Append((char)cp);
				break;
			default:
				return cp;
			}
		}
	}

	static void CheckKeyword(TextReader tr, string str)
	{
		int n = str.Length;
		for (int i = 1; i < n; i ++) {
			int cp = Next(tr);
			if (cp != (int)str[i]) {
				throw Unexpected(cp);
			}
		}
	}

	static bool IsWS(int cp)
	{
		return cp == 9 || cp == 10 || cp == 13 || cp == 32;
	}

	static int Next(TextReader tr)
	{
		int cp = tr.Read();
		if (cp < 0) {
			throw new EndOfStreamException();
		}
		return cp;
	}

	static int NextNonWS(TextReader tr, int cp)
	{
		while (IsWS(cp)) {
			cp = Next(tr);
		}
		return cp;
	}

	static Exception Unexpected(int cp)
	{
		return new Exception(string.Format(
			"Unexpected character U+{0:X4}", cp));
	}
}
