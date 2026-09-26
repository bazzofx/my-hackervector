// Extra edge-case probes: CSS hexa trailing-space rules across levels, NUL, etc.
var CssEscape = Java.type("org.unbescape.css.CssEscape");
var T = Java.type("org.unbescape.css.CssStringEscapeType");
var L = Java.type("org.unbescape.css.CssStringEscapeLevel");

function esc(s) {
  var t = String(s), out = "";
  for (var i = 0; i < t.length; i++) {
    var c = t.charCodeAt(i);
    if (c >= 0x20 && c < 0x7f) { out += String.fromCharCode(c); }
    else { out += "\\u" + ("0000" + c.toString(16)).slice(-4); }
  }
  return out;
}
function show(label, v) { print("P|" + label + "|" + esc(v)); }

var lv = [L.LEVEL_1_BASIC_ESCAPE_SET, L.LEVEL_2_ALL_NON_ASCII_PLUS_BASIC_ESCAPE_SET,
          L.LEVEL_3_ALL_NON_ALPHANUMERIC, L.LEVEL_4_ALL_CHARACTERS];
var lvn = ["L1", "L2", "L3", "L4"];

// trailing-space disambiguation: compact hexa followed by a hex digit / space
for (var i = 0; i < 4; i++) {
  show("csscompact_" + lvn[i] + "_z1", CssEscape.escapeCssString("z1", T.BACKSLASH_ESCAPES_DEFAULT_TO_COMPACT_HEXA, lv[i]));
  show("csscompact_" + lvn[i] + "_z_space", CssEscape.escapeCssString("z ", T.BACKSLASH_ESCAPES_DEFAULT_TO_COMPACT_HEXA, lv[i]));
  show("css6_" + lvn[i] + "_z1", CssEscape.escapeCssString("z1", T.BACKSLASH_ESCAPES_DEFAULT_TO_SIX_DIGIT_HEXA, lv[i]));
  show("css6_" + lvn[i] + "_z_space", CssEscape.escapeCssString("z ", T.BACKSLASH_ESCAPES_DEFAULT_TO_SIX_DIGIT_HEXA, lv[i]));
}

// NUL and control chars at L4
show("csscompact_L4_NUL", CssEscape.escapeCssString("\u0000", T.BACKSLASH_ESCAPES_DEFAULT_TO_COMPACT_HEXA, L.LEVEL_4_ALL_CHARACTERS));
show("css6_L4_NUL", CssEscape.escapeCssString("\u0000", T.BACKSLASH_ESCAPES_DEFAULT_TO_SIX_DIGIT_HEXA, L.LEVEL_4_ALL_CHARACTERS));
show("csscompact_L4_NUL_z", CssEscape.escapeCssString("\u0000z", T.BACKSLASH_ESCAPES_DEFAULT_TO_COMPACT_HEXA, L.LEVEL_4_ALL_CHARACTERS));
show("csscompact_L4_del", CssEscape.escapeCssString("\u007f", T.BACKSLASH_ESCAPES_DEFAULT_TO_COMPACT_HEXA, L.LEVEL_4_ALL_CHARACTERS));
show("csscompact_L4_colon", CssEscape.escapeCssString(":", T.BACKSLASH_ESCAPES_DEFAULT_TO_COMPACT_HEXA, L.LEVEL_4_ALL_CHARACTERS));
show("csscompact_L4_10FFFF", CssEscape.escapeCssString("\udbff\udfff", T.BACKSLASH_ESCAPES_DEFAULT_TO_COMPACT_HEXA, L.LEVEL_4_ALL_CHARACTERS));
show("css6_L4_10FFFF", CssEscape.escapeCssString("\udbff\udfff", T.BACKSLASH_ESCAPES_DEFAULT_TO_SIX_DIGIT_HEXA, L.LEVEL_4_ALL_CHARACTERS));

// JS: / handling and 0x100 boundary
var JE = Java.type("org.unbescape.javascript.JavaScriptEscape");
var JT = Java.type("org.unbescape.javascript.JavaScriptEscapeType");
var JL = Java.type("org.unbescape.javascript.JavaScriptEscapeLevel");
var lvj = [JL.LEVEL_1_BASIC_ESCAPE_SET, JL.LEVEL_2_ALL_NON_ASCII_PLUS_BASIC_ESCAPE_SET,
           JL.LEVEL_3_ALL_NON_ALPHANUMERIC, JL.LEVEL_4_ALL_CHARACTERS];
for (var j = 0; j < 4; j++) {
  show("jsx_" + lvn[j] + "_ff", JE.escapeJavaScript("\u00ff", JT.XHEXA_DEFAULT_TO_UHEXA, lvj[j]));
  show("jsx_" + lvn[j] + "_100", JE.escapeJavaScript("\u0100", JT.XHEXA_DEFAULT_TO_UHEXA, lvj[j]));
  show("jsx_" + lvn[j] + "_slash", JE.escapeJavaScript("/", JT.XHEXA_DEFAULT_TO_UHEXA, lvj[j]));
  show("jsx_" + lvn[j] + "_ltslash", JE.escapeJavaScript("</", JT.XHEXA_DEFAULT_TO_UHEXA, lvj[j]));
}
show("jsu_L4_1f600", JE.escapeJavaScript("\ud83d\ude00", JT.UHEXA, JL.LEVEL_4_ALL_CHARACTERS));
show("jsx_L4_1f600", JE.escapeJavaScript("\ud83d\ude00", JT.XHEXA_DEFAULT_TO_UHEXA, JL.LEVEL_4_ALL_CHARACTERS));

// HTML: which chars keep NCR at level 3 vs 4, and 0x2fff boundary
var HE = Java.type("org.unbescape.html.HtmlEscape");
var HT = Java.type("org.unbescape.html.HtmlEscapeType");
var HL = Java.type("org.unbescape.html.HtmlEscapeLevel");
show("html4_L3_tilde", HE.escapeHtml("~", HT.HTML4_NAMED_REFERENCES_DEFAULT_TO_DECIMAL, HL.LEVEL_3_ALL_NON_ALPHANUMERIC));
show("html4_L3_del", HE.escapeHtml("\u007f", HT.HTML4_NAMED_REFERENCES_DEFAULT_TO_DECIMAL, HL.LEVEL_3_ALL_NON_ALPHANUMERIC));
show("html4_L3_nbsp", HE.escapeHtml("\u00a0", HT.HTML4_NAMED_REFERENCES_DEFAULT_TO_DECIMAL, HL.LEVEL_3_ALL_NON_ALPHANUMERIC));
show("html5_L3_diams", HE.escapeHtml("\u2666", HT.HTML5_NAMED_REFERENCES_DEFAULT_TO_DECIMAL, HL.LEVEL_3_ALL_NON_ALPHANUMERIC));
show("html5_L3_2fff", HE.escapeHtml("\u2fff", HT.HTML5_NAMED_REFERENCES_DEFAULT_TO_DECIMAL, HL.LEVEL_3_ALL_NON_ALPHANUMERIC));
show("html5_L3_2713", HE.escapeHtml("\u2713", HT.HTML5_NAMED_REFERENCES_DEFAULT_TO_DECIMAL, HL.LEVEL_3_ALL_NON_ALPHANUMERIC));
show("html5_L3_1f600", HE.escapeHtml("\ud83d\ude00", HT.HTML5_NAMED_REFERENCES_DEFAULT_TO_DECIMAL, HL.LEVEL_3_ALL_NON_ALPHANUMERIC));
show("html5_L3_024", HE.escapeHtml("\u00f8", HT.HTML5_NAMED_REFERENCES_DEFAULT_TO_DECIMAL, HL.LEVEL_3_ALL_NON_ALPHANUMERIC));
show("html5_L3_space", HE.escapeHtml(" ", HT.HTML5_NAMED_REFERENCES_DEFAULT_TO_DECIMAL, HL.LEVEL_3_ALL_NON_ALPHANUMERIC));
show("html4_L4_A", HE.escapeHtml("A", HT.HTML4_NAMED_REFERENCES_DEFAULT_TO_DECIMAL, HL.LEVEL_4_ALL_CHARACTERS));
show("html5_L4_A", HE.escapeHtml("A", HT.HTML5_NAMED_REFERENCES_DEFAULT_TO_DECIMAL, HL.LEVEL_4_ALL_CHARACTERS));
