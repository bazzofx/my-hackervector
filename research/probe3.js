// Unambiguous probe: non-ASCII rendered as {U+XXXX}, backslash as {BS}
var CssEscape = Java.type("org.unbescape.css.CssEscape");
var T = Java.type("org.unbescape.css.CssStringEscapeType");
var L = Java.type("org.unbescape.css.CssStringEscapeLevel");
var JE = Java.type("org.unbescape.javascript.JavaScriptEscape");
var JT = Java.type("org.unbescape.javascript.JavaScriptEscapeType");
var JL = Java.type("org.unbescape.javascript.JavaScriptEscapeLevel");
var HE = Java.type("org.unbescape.html.HtmlEscape");
var HT = Java.type("org.unbescape.html.HtmlEscapeType");
var HL = Java.type("org.unbescape.html.HtmlEscapeLevel");

function esc(s) {
  var t = String(s), out = "";
  for (var i = 0; i < t.length; i++) {
    var c = t.charCodeAt(i);
    if (c === 0x5C) { out += "{BS}"; }
    else if (c === 0x20) { out += "{SP}"; }
    else if (c > 0x20 && c < 0x7f) { out += String.fromCharCode(c); }
    else { out += "{U+" + ("0000" + c.toString(16).toUpperCase()).slice(-4) + "}"; }
  }
  return out;
}
function show(label, v) { print("Q|" + label + "|" + esc(v)); }

show("css_compact_L2_eacute1", CssEscape.escapeCssString("\u00e9" + "1", T.BACKSLASH_ESCAPES_DEFAULT_TO_COMPACT_HEXA, L.LEVEL_2_ALL_NON_ASCII_PLUS_BASIC_ESCAPE_SET));
show("css_compact_L3_eacute1", CssEscape.escapeCssString("\u00e9" + "1", T.BACKSLASH_ESCAPES_DEFAULT_TO_COMPACT_HEXA, L.LEVEL_3_ALL_NON_ALPHANUMERIC));
show("css_compact_L4_eacute1", CssEscape.escapeCssString("\u00e9" + "1", T.BACKSLASH_ESCAPES_DEFAULT_TO_COMPACT_HEXA, L.LEVEL_4_ALL_CHARACTERS));
show("css_6digit_L2_eacute1", CssEscape.escapeCssString("\u00e9" + "1", T.BACKSLASH_ESCAPES_DEFAULT_TO_SIX_DIGIT_HEXA, L.LEVEL_2_ALL_NON_ASCII_PLUS_BASIC_ESCAPE_SET));
show("css_6digit_L3_eacute1", CssEscape.escapeCssString("\u00e9" + "1", T.BACKSLASH_ESCAPES_DEFAULT_TO_SIX_DIGIT_HEXA, L.LEVEL_3_ALL_NON_ALPHANUMERIC));
show("css_6digit_L4_eacute1", CssEscape.escapeCssString("\u00e9" + "1", T.BACKSLASH_ESCAPES_DEFAULT_TO_SIX_DIGIT_HEXA, L.LEVEL_4_ALL_CHARACTERS));
show("css_compact_L2_eacuteSP", CssEscape.escapeCssString("\u00e9" + " ", T.BACKSLASH_ESCAPES_DEFAULT_TO_COMPACT_HEXA, L.LEVEL_2_ALL_NON_ASCII_PLUS_BASIC_ESCAPE_SET));
show("css_6digit_L2_eacuteSP", CssEscape.escapeCssString("\u00e9" + " ", T.BACKSLASH_ESCAPES_DEFAULT_TO_SIX_DIGIT_HEXA, L.LEVEL_2_ALL_NON_ASCII_PLUS_BASIC_ESCAPE_SET));
show("css_compact_L1_eacute1", CssEscape.escapeCssString("\u00e9" + "1", T.BACKSLASH_ESCAPES_DEFAULT_TO_COMPACT_HEXA, L.LEVEL_1_BASIC_ESCAPE_SET));

// which ASCII chars get a BACKSLASH escape in CSS at L4
var s = "";
for (var c = 0x20; c <= 0x7e; c++) { s += String.fromCharCode(c); }
show("css_compact_L4_allprintable", CssEscape.escapeCssString(s, T.BACKSLASH_ESCAPES_DEFAULT_TO_COMPACT_HEXA, L.LEVEL_4_ALL_CHARACTERS));
show("css_6digit_L4_allprintable", CssEscape.escapeCssString(s, T.BACKSLASH_ESCAPES_DEFAULT_TO_SIX_DIGIT_HEXA, L.LEVEL_4_ALL_CHARACTERS));
show("js_xhexa_L4_allprintable", JE.escapeJavaScript(s, JT.XHEXA_DEFAULT_TO_UHEXA, JL.LEVEL_4_ALL_CHARACTERS));
show("js_uhexa_L4_allprintable", JE.escapeJavaScript(s, JT.UHEXA, JL.LEVEL_4_ALL_CHARACTERS));
show("html4_L3_allprintable", HE.escapeHtml(s, HT.HTML4_NAMED_REFERENCES_DEFAULT_TO_DECIMAL, HL.LEVEL_3_ALL_NON_ALPHANUMERIC));
show("html5_L3_allprintable", HE.escapeHtml(s, HT.HTML5_NAMED_REFERENCES_DEFAULT_TO_DECIMAL, HL.LEVEL_3_ALL_NON_ALPHANUMERIC));
