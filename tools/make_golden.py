#!/usr/bin/env python3
"""Build the hackvertor.sh test fixtures.

Two fixtures are produced, both as tab separated files of

    <tag> \t <argspec> \t <input-hex> \t <expected-hex>

so that the bash test runner never has to worry about quoting, newlines or
binary bytes.

1. tests/golden.tsv  - 200 vectors for the eight unbescape backed tags, taken
   verbatim from research/probe-out.txt.  That file is the output of running the
   REAL unbescape 1.1.6.RELEASE jar (the exact version and functions Hackvertor
   calls) through a JRE 8 / Nashorn probe, so these are ground truth rather than
   hand-derived expectations.

2. tests/vectors.tsv - vectors for the remaining tags.  Expectations come from
   the Hackvertor test suite (src/test/java/burp/*.java) wherever it asserts a
   concrete value, and from the Java implementations in Convertors.java
   otherwise.  Each vector carries a note naming its source.

Regenerate with:  python3 tools/make_golden.py
"""

from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# 1. golden.tsv - jar verified unbescape output
# ---------------------------------------------------------------------------

PROBE_COLUMNS = {
    "1_html4_named_dec_L3": "html_entities",
    "2_html5_named_dec_L3": "html5_entities",
    "3_html_hex_L4": "hex_entities",
    "4_html_dec_L4": "dec_entities",
    "5_js_xhexa_L4": "hex_escapes",
    "6_js_uhexa_L4": "unicode_escapes",
    "7_css_compact_L4": "css_escapes",
    "8_css_sixdigit_L4": "css_escapes6",
}

# probe.js inputs, in the order it declares them
PROBE_INPUTS = {
    "empty": "",
    "test": "test",
    "A": "A",
    "z": "z",
    "script-tag": "<script>",
    "hello-world": "Hello World",
    "a-eq-b": "a=b",
    "sq-q": "'q'",
    "dq-q": '"q"',
    "backslash": "back\\slash",
    "tab": "tab\tchar",
    "nl": "nl\nchar",
    "amp": "&amp;",
    "eacute": "\u00e9",
    "euro": "\u20ac",
    "emoji": "\U0001f600",
    "pct": "100%",
    "plus-slash-eq": "+/=",
    # the "EXTRA" probes
    "div": "<div>",
    "ABC": "ABC",
    "yuml-ff": "\u00ff",
    "A-macron-100": "\u0100",
    "ls-2028": "\u2028",
    "sol": "/",
}


def unescape_probe(text: str) -> str:
    """Undo the escaping applied by probe.js: \\\\ -> \\, \\uXXXX -> character."""
    out = []
    i = 0
    while i < len(text):
        char = text[i]
        if char == "\\":
            nxt = text[i + 1] if i + 1 < len(text) else ""
            if nxt == "u":
                out.append(chr(int(text[i + 2:i + 6], 16)))
                i += 6
                continue
            if nxt == "\\":
                out.append("\\")
                i += 2
                continue
            raise SystemExit(f"unexpected escape in probe output: {text!r}")
        out.append(char)
        i += 1
    return "".join(out)


def build_golden() -> list[str]:
    probe = ROOT / "research" / "probe-out.txt"
    if not probe.exists():
        raise SystemExit(f"{probe} is missing (the jar probe output)")
    rows: list[str] = []
    for line in probe.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("==="):
            continue
        parts = line.split("|")
        if parts[0] == "X":
            _, column, input_id, expected = parts
        else:
            column, input_id, expected = parts
        tag = PROBE_COLUMNS[column]
        if input_id not in PROBE_INPUTS:
            raise SystemExit(f"unknown probe input id: {input_id}")
        source = PROBE_INPUTS[input_id]
        rows.append(tsv(tag, "", source, unescape_probe(expected),
                        f"unbescape 1.1.6 jar: {column}"))
    return rows


# ---------------------------------------------------------------------------
# 2. vectors.tsv - Hackvertor's own test suite + Convertors.java semantics
# ---------------------------------------------------------------------------

JWT_PAYLOAD = (
    '{\n'
    '  "sub": "1234567890",\n'
    '  "name": "John Doe",\n'
    '  "admin": true,\n'
    '  "iat": 1516239022\n'
    '}'
)

PHP_NON_ALPHA_LOOKUP = ["\u00c0", "\u00c1", "\u00c2", "\u00c3", "\u00c4",
                        "\u00c6", "\u00c8", "\u00c9", "\u00ca", "\u00cb"]


def php_non_alpha_reference(source: str) -> str:
    """Independent transcription of Convertors.php_non_alpha() (Java).

    Used as the expected value for the php_non_alpha tag: the bash port and this
    python port are written from the same Java source, so agreeing outputs make a
    transcription error very unlikely.
    """
    out = [
        "$_[]++;$_[]=$_._;",
        "$_____=$_[(++$__[])][(++$__[])+(++$__[])+(++$__[])];",
        "$_=$_[$_[+_]];",
        "$___=$__=$_[++$__[]];",
        "$____=$_=$_[+_];",
        "$_++;$_++;$_++;",
        "$_=$____.++$___.$___.++$_.$__.++$___;",
        "$__=$_;",
        "$_=$_____;",
        "$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;",
        "$___=+_;",
        "$___.=$__;",
        "$___=++$_^$___[+_];$À=+_;$Á=$Â=$Ã=$Ä=$Æ=$È=$É=$Ê=$Ë=++$Á[];",
        "$Â++;",
        "$Ã++;$Ã++;",
        "$Ä++;$Ä++;$Ä++;",
        "$Æ++;$Æ++;$Æ++;$Æ++;",
        "$È++;$È++;$È++;$È++;$È++;",
        "$É++;$É++;$É++;$É++;$É++;$É++;",
        "$Ê++;$Ê++;$Ê++;$Ê++;$Ê++;$Ê++;$Ê++;",
        "$Ë++;$Ë++;$Ë++;$Ë++;$Ë++;$Ë++;$Ë++;",
        '$__(\'$_="\'',
    ]
    for char in source:
        digits = format(ord(char), "o")
        variables = ["$" + PHP_NON_ALPHA_LOOKUP[int(digit)] for digit in digits]
        out.append(".$___." + ".".join(variables))
    out.append(".'")
    out.append("\"');$__($_);")
    return "<?php " + "".join(out) + "?>"

TAG_VECTORS: list[tuple[str, str, str, str, str]] = [
    # (tag, argspec, input, expected, note)

    # --- base encodings (ConvertorTests / ConvertorTestsBasic / all-tags UI test)
    ("base32", "", "test", "ORSXG5A=", "HackvertorAllTagsUiTest"),
    ("base32", "", "Hello", "JBSWY3DP", "ConvertorTests.testBase32Encoding"),
    ("base64", "", "test", "dGVzdA==", "ConvertorTests.testBase64Encoding"),
    ("base64", "", " ", "IA==", "ConvertorTests.convertSpaceInTag"),
    ("base64url", "", "Hello World!", "SGVsbG8gV29ybGQh", "ConvertorTests.testBase64UrlEncoding"),
    ("base64url", "", "test>>data", "dGVzdD4-ZGF0YQ", "HackvertorAllTagsUiTest"),

    # --- hex family (ascii2hex: lowercase, even length, separator between chars)
    ("hex", "''", "ABC", "414243", "ConvertorTests.testHexEncoding (no separator)"),
    ("hex", "", "test", "74 65 73 74", "HackvertorAllTagsUiTest (UI default separator ' ')"),
    ("hex", "' '", "abcd", "61 62 63 64", "ConvertorTestsBasic.testSpaceInAttribute"),
    ("hex", "'  '", "abcd", "61  62  63  64", "ConvertorTestsBasic.testSpaceInAttribute"),
    ("hex", "':'", "test", "74:65:73:74", "Convertors.ascii2hex(separator)"),
    ("sql_hex", "", "test", "0x74657374", "HackvertorAllTagsUiTest"),

    # --- html entities (Java assertions with spaces and quotes)
    ("html_entities", "", "<script>alert('XSS')</script>",
     "&lt;script&gt;alert&#40;&#39;XSS&#39;&#41;&lt;&#47;script&gt;",
     "ConvertorTests.testHtmlEntities"),
    ("html5_entities", "", "<div>", "&lt;div&gt;", "HackvertorAllTagsUiTest"),
    ("hex_entities", "", "ABC", "&#x41;&#x42;&#x43;", "ConvertorTests.testHexEntities"),
    ("dec_entities", "", "ABC", "&#65;&#66;&#67;", "ConvertorTests.testDecEntities"),

    # --- escapes (unbescape level 4)
    ("hex_escapes", "", "test", "\\x74\\x65\\x73\\x74", "HackvertorAllTagsUiTest"),
    ("unicode_escapes", "", "test", "\\u0074\\u0065\\u0073\\u0074", "HackvertorAllTagsUiTest"),
    ("css_escapes", "", "test", "\\74\\65\\73\\74", "HackvertorAllTagsUiTest"),
    ("css_escapes6", "", "test", "\\000074\\000065\\000073\\000074", "HackvertorAllTagsUiTest"),
    # hand written in Convertors.octal_escapes, so lowercase/uppercase is moot
    ("octal_escapes", "", "test", "\\164\\145\\163\\164", "HackvertorAllTagsUiTest"),
    ("octal_escapes", "", " ", "\\40", "Convertors.octal_escapes"),

    # --- URL encoding
    ("burp_urlencode", "", "Hello World", "Hello+World", "HackvertorAllTagsUiTest"),
    ("burp_urlencode", "", "hello ~ // ##", "hello+~+//+%23%23",
     "Burp Encoder 'URL-encode key characters' (empirical report)"),
    ("burp_urlencode", "", "a/b?c=d&e=f", "a/b%3Fc%3Dd%26e%3Df",
     "Burp key characters: '/' literal, query characters encoded"),
    ("burp_urlencode", "", "100%", "100%25", "Burp key characters"),
    ("burp_urlencode", "", "<script>", "%3Cscript%3E", "Burp key characters"),
    ("burp_urlencode", "", "\u00e9", "%C3%A9", "non ASCII is UTF-8 percent encoded"),
    ("urlencode", "", "hello world!", "hello+world%21", "HackvertorAllTagsUiTest"),
    ("urlencode", "", "Hello World!", "Hello+World%21", "ConvertorTests.testUrlEncode"),
    ("url_encode", "", "Hello World!", "Hello+World%21", "alias for urlencode"),
    ("urlencode", "", "a+b", "a%2Bb", "JDK 17 URLEncoder"),
    ("urlencode", "", "~!*'()", "%7E%21*%27%28%29", "JDK 17 URLEncoder safe set"),
    ("urlencode", "", "a/b?c=d&e=f", "a%2Fb%3Fc%3Dd%26e%3Df", "JDK 17 URLEncoder"),
    ("urlencode", "", "test@example.com", "test%40example.com", "JDK 17 URLEncoder"),
    ("urlencode", "", "100%", "100%25", "JDK 17 URLEncoder"),
    ("urlencode", "", "<script>", "%3Cscript%3E", "JDK 17 URLEncoder"),
    ("urlencode", "", "line1\nline2", "line1%0Aline2", "JDK 17 URLEncoder"),
    ("urlencode", "", "~-_.*", "%7E-_.*", "Java URLEncoder safe set: only -_.* and alnum are literal"),
    ("urlencode_not_plus", "", "Hello World", "Hello%20World", "HackvertorAllTagsUiTest"),
    ("urlencode_not_plus", "", "hello world!", "hello%20world%21", "JDK 17 URLEncoder + '+' replacement"),
    ("urlencode_not_plus", "", "a+b", "a%2Bb", "only space derived '+' is rewritten"),
    ("urlencode_all", "", "ABC", "%41%42%43", "ConvertorTests.testUrlEncodeAll"),
    ("urlencode_all", "", "test", "%74%65%73%74", "HackvertorAllTagsUiTest"),
    ("urlencode_all", "", "hello world!", "%68%65%6C%6C%6F%20%77%6F%72%6C%64%21", "Convertors.urlencode_all"),
    ("urlencode_all", "", "a+b", "%61%2B%62", "Convertors.urlencode_all"),
    ("urlencode_all", "", "line1\nline2", "%6C%69%6E%65%31%0A%6C%69%6E%65%32", "Convertors.urlencode_all"),
    ("urlencode_all", "", "\u00e9", "%C3%A9", "Convertors.urlencode_all (UTF-8 bytes)"),
    ("urlencode_all", "", "\u20ac", "%E2%82%AC", "Convertors.urlencode_all (UTF-8 bytes)"),
    ("urlencode_all", "", "\U0001f600", "%F0%9F%98%80",
     "DEVIATION: Hackvertor's charAt() quirk emits %3F%3F for astral characters"),

    # --- URL decoding (Hackvertor's decode_url returns the input when URLDecoder throws)
    ("d_url", "", "a%20b", "a b", "Convertors.decode_url"),
    ("d_url", "", "%", "%", "Convertors.decode_url returns the input on an invalid escape"),
    ("d_burp_url", "", "a+b", "a b", "Burp urlDecode decodes '+' (permissive)"),

    # --- PHP / SQL
    ("php_chr", "", "test", "chr(116).chr(101).chr(115).chr(116)", "HackvertorAllTagsUiTest"),
    ("php_chr", "", "A", "chr(65)", "Convertors.php_chr"),
    ("php_non_alpha", "", "test", php_non_alpha_reference("test"),
     "convertors.php_non_alpha reference port"),
    ("php_non_alpha", "", "id", php_non_alpha_reference("id"),
     "convertors.php_non_alpha reference port"),

    # --- quoted printable (commons-codec 1.15, execution verified)
    ("quoted_printable", "", "test=", "test=3D", "HackvertorAllTagsUiTest"),
    ("quoted_printable", "", "abc", "abc", "printable ASCII is untouched"),
    ("quoted_printable", "", "Hello World", "Hello World", "commons-codec 1.15: SPACE stays literal"),
    ("quoted_printable", "", "a=b", "a=3Db", "commons-codec 1.15"),
    ("quoted_printable", "", "line1\nline2", "line1=0Aline2", "commons-codec 1.15: LF is escaped"),
    ("quoted_printable", "", "\r\n", "=0D=0A", "commons-codec 1.15: CR and LF are escaped"),
    ("quoted_printable", "", "\u00e9", "=C3=A9", "commons-codec 1.15: UTF-8 bytes"),
    ("quoted_printable", "", "caf\u00e9 = na\u00efve", "caf=C3=A9 =3D na=C3=AFve", "commons-codec 1.15"),
    ("quoted_printable", "", "a" * 100, "a" * 100, "commons-codec 1.15: output is never wrapped"),

    # --- JWT (JWTTest.java asserts full tokens)
    ("jwt", "'HS256','a-string-secret-at-least-256-bits-long'", JWT_PAYLOAD,
     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
     "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0."
     "KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30",
     "JWTTest.testJWTWithHS256"),
    ("jwt", "'HS256',''", JWT_PAYLOAD,
     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
     "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0."
     "7TNtfdcRCraA6JxwuKlByAryTktb653DD-Ve951DHSY",
     "JWTTest.testJWTWithBlankSecret"),
    ("jwt", "'INVALID','secret'", '{"sub":"test"}', "Unsupported algorithm",
     "JWTTest.testJWTWithInvalidAlgorithm"),
    ("jwt", "'HS256','secret'", "not valid json", "Unable to create token",
     "JWTTest.testJWTWithMalformedJSON"),
    ("jwt", "'NONE',''", '{"sub":"user789"}',
     "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyNzg5In0.",
     "JWTTest.testJWTWithNoneAlgorithm (trailing dot, no signature)"),

    # --- decoders (Hackvertor decode tags)
    ("d_base32", "", "JBSWY3DP", "Hello", "ConvertorTests.testBase32Decoding"),
    ("d_base64", "", "SGVsbG8gV29ybGQ=", "Hello World", "ConvertorTests.testBase64Decoding"),
    ("d_base64url", "", "SGVsbG8gV29ybGQh", "Hello World!", "ConvertorTests.testBase64UrlDecoding"),
    ("d_hex", "", "414243", "ABC", "ConvertorTests.testHex2Ascii"),
    ("d_hex", "", "41 42", "AB", "Convertors.hex2ascii, space separated"),
    ("d_hex", "", "41:42", "AB", "Convertors.hex2ascii scans for pairs, so ':' works too"),
    ("d_hex", "", "0x4142", "AB", "0x form"),
    ("d_sql_hex", "", "0x53454c454354", "SELECT", "d_sql_hex with the 0x prefix"),
    ("d_sql_hex", "", "53454c454354", "SELECT", "d_sql_hex without the 0x prefix"),
    ("d_html_entities", "", "&lt;script&gt;", "<script>", "ConvertorTests.testHtmlEntitiesDecoding"),
    ("d_url", "", "Hello+World%21", "Hello World!", "ConvertorTests.testUrlDecoding"),
    ("d_burp_url", "", "Hello%20World", "Hello World", "HackvertorAllTagsUiTest"),
    ("d_quoted_printable", "", "test=3D", "test=", "HackvertorAllTagsUiTest"),
    ("d_unicode_escapes", "", "\\u0074\\u0065\\u0073\\u0074", "test", "HackvertorAllTagsUiTest"),
    ("d_css_escapes", "", "\\74\\65\\73\\74", "test", "HackvertorAllTagsUiTest"),
    ("d_octal_escapes", "", "\\164\\145\\163\\164", "test", "HackvertorAllTagsUiTest"),
    ("d_jwt_get_header", "",
     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.x",
     '{"alg":"HS256","typ":"JWT"}', "HackvertorAllTagsUiTest"),
    ("d_jwt_get_payload", "",
     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
     "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
     "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
     '{"sub":"1234567890","name":"John Doe","iat":1516239022}',
     "HackvertorAllTagsUiTest"),
]


def tsv(tag: str, argspec: str, source: str, expected: str, note: str) -> str:
    return "\t".join(
        [tag, argspec, source.encode("utf-8").hex(), expected.encode("utf-8").hex(), note]
    )


def build_vectors() -> list[str]:
    return [tsv(*row) for row in TAG_VECTORS]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify fixtures are current")
    args = parser.parse_args()

    fixtures = {
        ROOT / "tests" / "golden.tsv": build_golden(),
        ROOT / "tests" / "vectors.tsv": build_vectors(),
    }
    stale = False
    for path, rows in fixtures.items():
        content = "\n".join(rows) + "\n"
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                print(f"stale: {path}")
                stale = True
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
        print(f"wrote {path.relative_to(ROOT)} ({len(rows)} vectors)")
    if stale:
        raise SystemExit("fixtures are stale - run tools/make_golden.py")


if __name__ == "__main__":
    main()
