// Nashorn probe against the REAL unbescape 1.1.6.RELEASE jar.
// All output is pure ASCII (\uXXXX escapes) to avoid console encoding issues.

var HtmlEscape = Java.type("org.unbescape.html.HtmlEscape");
var HtmlEscapeType = Java.type("org.unbescape.html.HtmlEscapeType");
var HtmlEscapeLevel = Java.type("org.unbescape.html.HtmlEscapeLevel");
var JavaScriptEscape = Java.type("org.unbescape.javascript.JavaScriptEscape");
var JavaScriptEscapeType = Java.type("org.unbescape.javascript.JavaScriptEscapeType");
var JavaScriptEscapeLevel = Java.type("org.unbescape.javascript.JavaScriptEscapeLevel");
var CssEscape = Java.type("org.unbescape.css.CssEscape");
var CssStringEscapeType = Java.type("org.unbescape.css.CssStringEscapeType");
var CssStringEscapeLevel = Java.type("org.unbescape.css.CssStringEscapeLevel");

var inputs = [
  ["empty", ""],
  ["test", "test"],
  ["A", "A"],
  ["z", "z"],
  ["script-tag", "<script>"],
  ["hello-world", "Hello World"],
  ["a-eq-b", "a=b"],
  ["sq-q", "'q'"],
  ["dq-q", "\"q\""],
  ["backslash", "back\\slash"],
  ["tab", "tab\tchar"],
  ["nl", "nl\nchar"],
  ["amp", "&amp;"],
  ["eacute", "\u00e9"],
  ["euro", "\u20ac"],
  ["emoji", "\ud83d\ude00"],
  ["pct", "100%"],
  ["plus-slash-eq", "+/="]
];

var fns = {
  "1_html4_named_dec_L3": function (s) {
    return HtmlEscape.escapeHtml(s, HtmlEscapeType.HTML4_NAMED_REFERENCES_DEFAULT_TO_DECIMAL, HtmlEscapeLevel.LEVEL_3_ALL_NON_ALPHANUMERIC);
  },
  "2_html5_named_dec_L3": function (s) {
    return HtmlEscape.escapeHtml(s, HtmlEscapeType.HTML5_NAMED_REFERENCES_DEFAULT_TO_DECIMAL, HtmlEscapeLevel.LEVEL_3_ALL_NON_ALPHANUMERIC);
  },
  "3_html_hex_L4": function (s) {
    return HtmlEscape.escapeHtml(s, HtmlEscapeType.HEXADECIMAL_REFERENCES, HtmlEscapeLevel.LEVEL_4_ALL_CHARACTERS);
  },
  "4_html_dec_L4": function (s) {
    return HtmlEscape.escapeHtml(s, HtmlEscapeType.DECIMAL_REFERENCES, HtmlEscapeLevel.LEVEL_4_ALL_CHARACTERS);
  },
  "5_js_xhexa_L4": function (s) {
    return JavaScriptEscape.escapeJavaScript(s, JavaScriptEscapeType.XHEXA_DEFAULT_TO_UHEXA, JavaScriptEscapeLevel.LEVEL_4_ALL_CHARACTERS);
  },
  "6_js_uhexa_L4": function (s) {
    return JavaScriptEscape.escapeJavaScript(s, JavaScriptEscapeType.UHEXA, JavaScriptEscapeLevel.LEVEL_4_ALL_CHARACTERS);
  },
  "7_css_compact_L4": function (s) {
    return CssEscape.escapeCssString(s, CssStringEscapeType.BACKSLASH_ESCAPES_DEFAULT_TO_COMPACT_HEXA, CssStringEscapeLevel.LEVEL_4_ALL_CHARACTERS);
  },
  "8_css_sixdigit_L4": function (s) {
    return CssEscape.escapeCssString(s, CssStringEscapeType.BACKSLASH_ESCAPES_DEFAULT_TO_SIX_DIGIT_HEXA, CssStringEscapeLevel.LEVEL_4_ALL_CHARACTERS);
  }
};

// extra probes for the report (ground-truth cross-checks)
var extra = [
  ["<div>", "div"],
  ["ABC", "ABC"],
  ["test", "test"],
  ["\u00ff", "yuml-ff"],
  ["\u0100", "A-macron-100"],
  ["\u2028", "ls-2028"],
  ["/", "sol"]
];

function esc(s) {
  var t = String(s);
  var out = "";
  for (var i = 0; i < t.length; i++) {
    var c = t.charCodeAt(i);
    if (c >= 0x20 && c < 0x7f && c !== 0x5c) {
      out += String.fromCharCode(c);
    } else if (c === 0x5c) {
      out += "\\\\";
    } else {
      out += "\\u" + ("0000" + c.toString(16)).slice(-4);
    }
  }
  return out;
}

for (var fname in fns) {
  for (var k = 0; k < inputs.length; k++) {
    var r = fns[fname](inputs[k][1]);
    print(fname + "|" + inputs[k][0] + "|" + esc(r));
  }
}

print("=== EXTRA ===");
for (var e = 0; e < extra.length; e++) {
  for (var fn2 in fns) {
    print("X|" + fn2 + "|" + extra[e][1] + "|" + esc(fns[fn2](extra[e][0])));
  }
}
