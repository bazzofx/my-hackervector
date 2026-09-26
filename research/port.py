#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Source-faithful Python port of unbescape 1.1.6.RELEASE escaping, written from the
actual sources jar (research/unbescape-src). Used to VALIDATE the pseudo-code
description against the real jar (run through Nashorn) - not shipped.

Mirrors:
  org/unbescape/html/HtmlEscapeUtil.java  (String overload)
  org/unbescape/html/HtmlEscapeSymbols.java
  org/unbescape/css/CssStringEscapeUtil.java
  org/unbescape/javascript/JavaScriptEscapeUtil.java
"""
import os, re, sys, json

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "unbescape-src", "org", "unbescape")

# ---------------------------------------------------------------- Java-ish utils

def utf16_units(s):
    """Java String -> list of UTF-16 code units."""
    out = []
    for ch in s:
        cp = ord(ch)
        if cp <= 0xFFFF:
            out.append(cp)
        else:
            cp -= 0x10000
            out.append(0xD800 + (cp >> 10))
            out.append(0xDC00 + (cp & 0x3FF))
    return out

def units_to_str(u):
    return "".join(chr(x) for x in u)

def is_high_surrogate(c):
    return 0xD800 <= c <= 0xDBFF

def is_low_surrogate(c):
    return 0xDC00 <= c <= 0xDFFF

def char_count(cp):
    return 2 if cp > 0xFFFF else 1

def code_point_at(units, i):
    c1 = units[i]
    if is_high_surrogate(c1) and i + 1 < len(units):
        c2 = units[i + 1]
        if is_low_surrogate(c2):
            return 0x10000 + ((c1 - 0xD800) << 10) + (c2 - 0xDC00)
    return c1

def java_to_hex_string(cp):
    """Integer.toHexString: lowercase, no leading zeros."""
    return format(cp, "x")

# ------------------------------------------------- HTML symbol tables (parsed)

MAX_ASCII_CHAR = 0x7F
NCRS_BY_CODEPOINT_LEN = 0x2fff

def parse_initializer(fname, prefix):
    """Parse addReference(...) calls in original source order."""
    path = os.path.join(SRC, "html", fname)
    txt = open(path, encoding="latin-1").read()
    refs = []
    one = re.compile(r"%s\.addReference\(\s*('(?:\\.|[^'\\])*'|\d+|0x[0-9A-Fa-f]+)\s*,\s*(\"[^\"]*\")\)\s*;" % prefix)
    two = re.compile(r"%s\.addReference\(\s*(\d+|0x[0-9A-Fa-f]+)\s*,\s*(\d+|0x[0-9A-Fa-f]+)\s*,\s*(\"[^\"]*\")\)\s*;" % prefix)
    for m in one.finditer(txt):
        cp = parse_cp(m.group(1))
        refs.append(([cp], m.group(2)[1:-1]))
    for m in two.finditer(txt):
        refs.append(([parse_cp(m.group(1)), parse_cp(m.group(2))], m.group(3)[1:-1]))
    levels = parse_escape_levels(txt)
    return refs, levels

def parse_cp(tok):
    tok = tok.strip()
    if tok.startswith("'"):
        inner = tok[1:-1]
        out = []
        i = 0
        while i < len(inner):
            if inner[i] == "\\":
                if inner[i + 1] == "u":
                    out.append(int(inner[i + 2:i + 6], 16))
                    i += 6
                else:
                    mapping = {"0": 0x00, "t": 0x09, "n": 0x0A, "b": 0x08,
                               "f": 0x0C, "r": 0x0D, "\\": 0x5C, "'": 0x27, '"': 0x22}
                    out.append(mapping.get(inner[i + 1], ord(inner[i + 1])))
                    i += 2
            else:
                out.append(ord(inner[i]))
                i += 1
        assert len(out) == 1, "multi-char literal: %r" % tok
        return out[0]
    if tok.startswith("0x") or tok.startswith("0X"):
        return int(tok, 16)
    return int(tok)

def parse_escape_levels(txt):
    """Rebuild the escapeLevels byte[] exactly as the initializer does."""
    levels = [3] * (0x7F + 2)
    if "escapeLevels['\\''] = 1;" in txt or "escapeLevels['\\''] = 1" in txt:
        levels[0x27] = 1
    if "escapeLevels['\"'] = 0;" in txt:
        levels[0x22] = 0
    if "escapeLevels['<'] = 0;" in txt:
        levels[0x3C] = 0
    if "escapeLevels['>'] = 0;" in txt:
        levels[0x3E] = 0
    if "escapeLevels['&'] = 0;" in txt:
        levels[0x26] = 0
    if "escapeLevels[0x7f + 1] = 2;" in txt:
        levels[0x80] = 2
    if "escapeLevels['\\''] = 1;" in txt:  # apostrophe line present in both inits
        pass
    assert "Arrays.fill(escapeLevels, (byte)3);" in txt, "unexpected escapeLevels init"
    for c in range(ord('A'), ord('Z') + 1):
        levels[c] = 4
    for c in range(ord('a'), ord('z') + 1):
        levels[c] = 4
    for c in range(ord('0'), ord('9') + 1):
        levels[c] = 4
    return levels

def build_symbols(fname, prefix):
    refs, levels = parse_initializer(fname, prefix)
    ncrs = {}         # codepoint -> ncr text (first one in original order wins)
    overflow = {}     # codepoint >= 0x2fff -> ncr text (last in sorted order wins)
    single = [(cps[0], ncr) for cps, ncr in refs if len(cps) == 1]
    # Replicate HtmlEscapeSymbols: sort alphabetically (replicating compare()), then
    # for each sorted NCR assign to its codepoint keeping the EARLIEST original position.
    order = sorted(range(len(refs)), key=lambda k: SortKey(refs[k][1]))
    assigned = {}
    for k in order:
        cps, ncr = refs[k]
        if len(cps) != 1:
            continue
        cp = cps[0]
        if cp <= 0:
            continue
        if cp < NCRS_BY_CODEPOINT_LEN:
            cur = assigned.get(cp)
            if cur is None or k < cur[0]:
                assigned[cp] = (k, ncr)
        else:
            overflow[cp] = ncr   # sorted-order last write wins
    for cp, (k, ncr) in assigned.items():
        ncrs[cp] = ncr
    return ncrs, overflow, levels, refs

class SortKey:
    """Wraps the Java comparator (a<b) implemented via compare(ncr, text, 0, len(text))."""
    def __init__(self, s):
        self.s = s
    def __lt__(self, other):
        return java_compare(self.s, other.s, 0, len(other.s)) < 0

def java_compare(ncr, text, start, end):
    """Port of HtmlEscapeSymbols.compare(char[] ncr, String/char[] text, start, end)."""
    text_len = end - start
    max_common = min(len(ncr), text_len)
    i = 1
    while i < max_common:
        tc = text[start + i]
        if ncr[i] < tc:
            return 1 if tc == ';' else -1
        elif ncr[i] > tc:
            return -1 if ncr[i] == ';' else 1
        i += 1
    if len(ncr) > i:
        return -1 if ncr[i] == ';' else 1
    if text_len > i:
        if text[start + i] == ';':
            return 1
        return -((text_len - i) + 10)
    return 0

HTML4 = build_symbols("Html4EscapeSymbolsInitializer.java", "html4References")
HTML5 = build_symbols("Html5EscapeSymbolsInitializer.java", "html5References")

def html_escape(text, use_html5, use_ncrs, use_hexa, level):
    ncrs, overflow, levels, refs = HTML5 if use_html5 else HTML4
    units = utf16_units(text)
    out = []
    read_offset = 0
    i = 0
    n = len(units)
    while i < n:
        c = units[i]
        if c <= MAX_ASCII_CHAR and level < levels[c]:
            i += 1
            continue
        if c > MAX_ASCII_CHAR and level < levels[MAX_ASCII_CHAR + 1]:
            i += 1
            continue
        codepoint = code_point_at(units, i)
        if i - read_offset > 0:
            out.append(units_to_str(units[read_offset:i]))
        if char_count(codepoint) > 1:
            i += 1
        read_offset = i + 1
        done = False
        if use_ncrs:
            if codepoint < NCRS_BY_CODEPOINT_LEN:
                idx = ncrs.get(codepoint)
                if idx is not None:
                    out.append(idx)
                    done = True
            else:
                idx = overflow.get(codepoint)
                if idx is not None:
                    out.append(idx)
                    done = True
        if not done:
            if use_hexa:
                out.append("&#x" + java_to_hex_string(codepoint) + ";")
            else:
                out.append("&#" + str(codepoint) + ";")
        i += 1
    if n - read_offset > 0:
        out.append(units_to_str(units[read_offset:n]))
    return "".join(out)

# ------------------------------------------------------------------------ CSS

CSS_ESCAPE_LEVELS_LEN = 0x9F + 2
CSS_BACKSLASH_CHARS_LEN = ord('~') + 1

def build_css():
    levels = [3] * CSS_ESCAPE_LEVELS_LEN
    for c in range(0x80, CSS_ESCAPE_LEVELS_LEN):
        levels[c] = 2
    for c in range(ord('A'), ord('Z') + 1):
        levels[c] = 4
    for c in range(ord('a'), ord('z') + 1):
        levels[c] = 4
    for c in range(ord('0'), ord('9') + 1):
        levels[c] = 4
    for c in (0x22, 0x27, 0x5C, 0x2F, 0x26, 0x3B):
        levels[c] = 1
    for c in range(0x00, 0x20):
        levels[c] = 1
    for c in range(0x7F, 0xA0):
        levels[c] = 1
    bs = [0] * CSS_BACKSLASH_CHARS_LEN
    for c in [0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,
              0x3B,0x3C,0x3D,0x3E,0x3F,0x40,0x5B,0x5C,0x5D,0x5E,0x5F,0x60,0x7B,0x7C,0x7D,0x7E]:
        bs[c] = c
    return levels, bs

CSS_LEVELS, CSS_BS = build_css()
HEXA_UPPER = "0123456789ABCDEF"

def css_to_compact_hexa(codepoint, nxt, level):
    need_ws = ((level < 4 and ((ord('0') <= nxt <= ord('9')) or (ord('A') <= nxt <= ord('F')) or (ord('a') <= nxt <= ord('f'))))
               or (level < 3 and nxt == 0x20))
    if codepoint == 0:
        return "0 " if need_ws else "0"
    div = 20
    ndigits = None
    while ndigits is None and div >= 0:
        if ((codepoint >> div) % 0x10) > 0:
            ndigits = (div // 4) + (2 if need_ws else 1)
        div -= 4
    res = [None] * ndigits
    div = 0
    idx = (ndigits - 2) if need_ws else (ndigits - 1)
    while idx >= 0:
        res[idx] = HEXA_UPPER[(codepoint >> div) % 0x10]
        div += 4
        idx -= 1
    if need_ws:
        res[-1] = " "
    return "".join(res)

def css_to_six_digit_hexa(codepoint, nxt, level):
    need_ws = (level < 3 and nxt == 0x20)
    res = [HEXA_UPPER[(codepoint >> 20) % 0x10], HEXA_UPPER[(codepoint >> 16) % 0x10],
           HEXA_UPPER[(codepoint >> 12) % 0x10], HEXA_UPPER[(codepoint >> 8) % 0x10],
           HEXA_UPPER[(codepoint >> 4) % 0x10], HEXA_UPPER[codepoint % 0x10]]
    if need_ws:
        res.append(" ")
    return "".join(res)

def css_escape_string(text, use_backslash, use_compact, level):
    units = utf16_units(text)
    n = len(units)
    out = []
    read_offset = 0
    i = 0
    while i < n:
        codepoint = code_point_at(units, i)
        if codepoint <= (CSS_ESCAPE_LEVELS_LEN - 2) and level < CSS_LEVELS[codepoint]:
            i += 1
            continue
        if codepoint > (CSS_ESCAPE_LEVELS_LEN - 2) and level < CSS_LEVELS[CSS_ESCAPE_LEVELS_LEN - 1]:
            i += char_count(codepoint)
            continue
        if i - read_offset > 0:
            out.append(units_to_str(units[read_offset:i]))
        inc = char_count(codepoint)
        i += inc - 1
        read_offset = i + 1
        if use_backslash and codepoint < CSS_BACKSLASH_CHARS_LEN:
            sec = CSS_BS[codepoint]
            if sec != 0:
                out.append("\\" + chr(sec))
                i += 1
                continue
        nxt = units[i + 1] if (i + 1 < n) else 0
        if use_compact:
            out.append("\\" + css_to_compact_hexa(codepoint, nxt, level))
        else:
            out.append("\\" + css_to_six_digit_hexa(codepoint, nxt, level))
        i += 1
    if n - read_offset > 0:
        out.append(units_to_str(units[read_offset:n]))
    return "".join(out)

# --------------------------------------------------------------- JavaScript

JS_ESCAPE_LEVELS_LEN = 0x9F + 2
JS_SEC_CHARS_LEN = 0x5C + 1

def build_js():
    levels = [3] * JS_ESCAPE_LEVELS_LEN
    for c in range(0x80, JS_ESCAPE_LEVELS_LEN):
        levels[c] = 2
    for c in range(ord('A'), ord('Z') + 1):
        levels[c] = 4
    for c in range(ord('a'), ord('z') + 1):
        levels[c] = 4
    for c in range(ord('0'), ord('9') + 1):
        levels[c] = 4
    for c in (0x00, 0x08, 0x09, 0x0A, 0x0C, 0x0D, 0x22, 0x27, 0x5C, 0x2F, 0x26):
        levels[c] = 1
    for c in range(0x01, 0x20):
        levels[c] = 1
    for c in range(0x7F, 0xA0):
        levels[c] = 1
    sec = ["*"] * JS_SEC_CHARS_LEN
    sec[0x00] = '0'; sec[0x08] = 'b'; sec[0x09] = 't'; sec[0x0A] = 'n'
    sec[0x0C] = 'f'; sec[0x0D] = 'r'; sec[0x22] = '"'; sec[0x27] = "'"
    sec[0x5C] = "\\"; sec[0x2F] = '/'
    return levels, sec

JS_LEVELS, JS_SEC = build_js()

def js_to_xhexa(cp):
    return HEXA_UPPER[(cp >> 4) % 0x10] + HEXA_UPPER[cp % 0x10]

def js_to_uhexa(cp):
    return (HEXA_UPPER[(cp >> 12) % 0x10] + HEXA_UPPER[(cp >> 8) % 0x10]
            + HEXA_UPPER[(cp >> 4) % 0x10] + HEXA_UPPER[cp % 0x10])

def js_escape(text, use_secs, use_xhexa, level):
    units = utf16_units(text)
    n = len(units)
    out = []
    read_offset = 0
    i = 0
    while i < n:
        codepoint = code_point_at(units, i)
        if codepoint <= (JS_ESCAPE_LEVELS_LEN - 2) and level < JS_LEVELS[codepoint]:
            i += 1
            continue
        if codepoint == 0x2F and level < 3 and (i == 0 or units[i - 1] != ord('<')):
            i += 1
            continue
        if (codepoint > (JS_ESCAPE_LEVELS_LEN - 2) and level < JS_LEVELS[JS_ESCAPE_LEVELS_LEN - 1]
                and codepoint not in (0x2028, 0x2029)):
            i += char_count(codepoint)
            continue
        if i - read_offset > 0:
            out.append(units_to_str(units[read_offset:i]))
        if char_count(codepoint) > 1:
            i += 1
        read_offset = i + 1
        if use_secs and codepoint < JS_SEC_CHARS_LEN:
            sec = JS_SEC[codepoint]
            if sec != "*":
                out.append("\\" + sec)
                i += 1
                continue
        if use_xhexa and codepoint <= 0xFF:
            out.append("\\x" + js_to_xhexa(codepoint))
            i += 1
            continue
        if char_count(codepoint) > 1:
            hi = 0xD800 + ((codepoint - 0x10000) >> 10)
            lo = 0xDC00 + ((codepoint - 0x10000) & 0x3FF)
            out.append("\\u" + js_to_uhexa(hi) + "\\u" + js_to_uhexa(lo))
            i += 1
            continue
        out.append("\\u" + js_to_uhexa(codepoint))
        i += 1
    if n - read_offset > 0:
        out.append(units_to_str(units[read_offset:n]))
    return "".join(out)

# ------------------------------------------------------------------ 8 functions

def f1(s): return html_escape(s, False, True, False, 3)
def f2(s): return html_escape(s, True,  True, False, 3)
def f3(s): return html_escape(s, False, False, True, 4)
def f4(s): return html_escape(s, False, False, False, 4)
def f5(s): return js_escape(s, False, True, 4)
def f6(s): return js_escape(s, False, False, 4)
def f7(s): return css_escape_string(s, True, True, 4)
def f8(s): return css_escape_string(s, True, False, 4)

FUNCS = {
    "1_html4_named_dec_L3": f1,
    "2_html5_named_dec_L3": f2,
    "3_html_hex_L4": f3,
    "4_html_dec_L4": f4,
    "5_js_xhexa_L4": f5,
    "6_js_uhexa_L4": f6,
    "7_css_compact_L4": f7,
    "8_css_sixdigit_L4": f8,
}

INPUTS = [
    ("empty", ""),
    ("test", "test"),
    ("A", "A"),
    ("z", "z"),
    ("script-tag", "<script>"),
    ("hello-world", "Hello World"),
    ("a-eq-b", "a=b"),
    ("sq-q", "'q'"),
    ("dq-q", '"q"'),
    ("backslash", "back\\slash"),
    ("tab", "tab\tchar"),
    ("nl", "nl\nchar"),
    ("amp", "&amp;"),
    ("eacute", "\u00e9"),
    ("euro", "\u20ac"),
    ("emoji", "\U0001F600"),
    ("pct", "100%"),
    ("plus-slash-eq", "+/="),
]

if __name__ == "__main__":
    # report reference-table sizes
    print("# HTML4 refs:", len(HTML4[3]), " HTML5 refs:", len(HTML5[3]), file=sys.stderr)
    print("# HTML4 codepoints with NCR:", len(HTML4[0]), " HTML5:", len(HTML5[0]),
          " HTML5 overflow:", len(HTML5[1]), file=sys.stderr)
    if len(sys.argv) > 1 and sys.argv[1] == "--compare":
        # compare against jjs ground truth file
        truth = {}
        for line in open(os.path.join(HERE, "probe-out.txt"), encoding="utf-8"):
            line = line.rstrip("\n")
            if line.startswith("X|") or not line or line.startswith("==="):
                continue
            fn, inp, val = line.split("|", 2)
            if fn.startswith("X"):
                continue
            truth[(fn, inp)] = val
        bad = 0
        total = 0
        for fn, f in FUNCS.items():
            for name, s in INPUTS:
                total += 1
                got = f(s)
                # ground truth file uses \\ for a single literal backslash
                got_disp = got.replace("\\", "\\\\")
                want = truth.get((fn, name))
                if want is None:
                    print("MISSING truth:", fn, name)
                    bad += 1
                elif got_disp != want:
                    bad += 1
                    print("MISMATCH", fn, name)
                    print("   want:", want)
                    print("   got :", got_disp)
        print("compared %d cases, %d mismatches" % (total, bad), file=sys.stderr)
    else:
        for name, s in INPUTS:
            for fn, f in FUNCS.items():
                print("%s|%s|%s" % (fn, name, f(s).replace("\\", "\\\\")))
