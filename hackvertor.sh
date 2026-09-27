#!/usr/bin/env bash
#===============================================================================
# hackvertor.sh - stand-alone command line encoder inspired by the Hackvertor
#                 Burp Suite extension <https://github.com/portswigger/hackvertor>
#
# The encoding tags implemented here are ports of Hackvertor's Convertors.java
# (burp.hv.Convertors) so that a conversion can be reproduced from a shell:
#
#     hackvertor.sh -base64 "admin' OR 1=1--"
#     cat content.txt | hackvertor.sh -urlencode_not_plus
#     hackvertor.sh -base64 -hex 'alert(1)'          # hex first, then base64
#     hackvertor.sh '<@base64><@hex>alert(1)</@hex></@base64>'
#
# Only bash (4.3+) plus a handful of POSIX tools (od, tr, awk) are required.
# openssl is used only for JWT HS384/HS512 (HS256 has a pure-bash fallback).
#
# ---------------------------------------------------------------------------
# IMPORTANT IMPLEMENTATION NOTES
# ---------------------------------------------------------------------------
# *  LC_ALL is forced to C: all string handling below is deliberately
#    byte oriented (the script does its own UTF-8 decoding) so that results do
#    not depend on the machine's locale.
# *  Output is assembled in an "escape buffer": literal text is appended
#    verbatim and raw bytes are appended as \NNN octal escapes.  Nothing that
#    goes through _hv_put may contain a backslash; use _hv_putb 92 (or
#    _hv_bslash) instead.  _hv_result renders the buffer.
#===============================================================================

set -u
export LC_ALL=C

HV_PROG=${HV_PROG:-hackvertor}
HV_VERSION='1.0.0'
HV_URL='https://github.com/portswigger/hackvertor'

# --- options / state ---------------------------------------------------------
HV_QUIET=0
HV_KEEP_NL=0        # keep the trailing newline of stdin input
HV_FINAL_NL=1       # append a newline to the final result
HV_EVAL=-1          # -1 = auto (evaluate <@tag>..</@tag> when present)
HV_ALG=''           # --alg for jwt
HV_SECRET=''        # --secret for jwt
HV_DEBUG=0
HV_UI_DEFAULTS=0    # 1 while running CLI tag flags (-hex defaults to the UI's " ")
HV_TAGS=()          # "name<TAB>argspec" list, in the order given
HV_POS=()           # positional content
HV_INPUT=''
HV_RESULT=''

# --- output buffers ---------------------------------------------------------
_HV_BUF=''          # escape buffer (text verbatim, raw bytes as \NNN)
_HV_PLAIN=1         # 1 while _HV_BUF is pure text without backslashes

# --- input state ------------------------------------------------------------
declare -A HV_HTML4_NAMES=() HV_HTML5_NAMES=()

HV_BYTES=()         # input as byte values 0..255
HV_NBYTES=0
CP=()               # codepoints
CP_BIDX=()          # index into HV_BYTES where the codepoint starts
CP_BLEN=()          # length in bytes of the codepoint
HV_NCP=0
JV=()               # "Java value sequence" - see _hv_build_java_seq
HV_NJV=0

#===============================================================================
# section 1 - small helpers
#===============================================================================

_hv_err()  { printf '%s: %s\n' "$HV_PROG" "$*" >&2; }
_hv_warn() { [ "$HV_QUIET" = 1 ] || printf '%s: warning: %s\n' "$HV_PROG" "$*" >&2; }
_hv_die()  { _hv_err "$*"; exit 2; }

# append literal text (must not contain a backslash)
_hv_put() {
  case $1 in
    '') return 0 ;;
    *\\*)
      _HV_PLAIN=0
      local _s=$1 _i
      for (( _i=0; _i<${#_s}; _i++ )); do
        if [ "${_s:_i:1}" = '\' ]; then _HV_BUF+='\134'; else _HV_BUF+="${_s:_i:1}"; fi
      done
      ;;
    *) _HV_BUF+="$1" ;;
  esac
}

# append a raw byte.  The octal escape is looked up in a table built once, so
# this stays fork free - it is the hottest function in the script.
_HV_OCTLUT=()
_HV_OCTLUT_READY=0
_hv_init_octlut() {
  local i
  for (( i=0; i<256; i++ )); do
    printf -v "_HV_OCTLUT[$i]" '\\%03o' "$i"
  done
  _HV_OCTLUT_READY=1
}

_hv_putb() {
  [ "$_HV_OCTLUT_READY" = 1 ] || _hv_init_octlut
  _HV_PLAIN=0
  _HV_BUF+="${_HV_OCTLUT[$1]}"
}

_hv_bslash() { _hv_putb 92; }

# append the original bytes of codepoint number $1 (pass-through)
_hv_put_orig() {
  local k=$1 j
  for (( j=0; j<${CP_BLEN[k]}; j++ )); do
    _hv_putb "${HV_BYTES[${CP_BIDX[k]}+j]}"
  done
}

_hv_reset_buf() { _HV_BUF=''; _HV_PLAIN=1; }

# render the escape buffer (no trailing newline is added here)
_hv_result() {
  if [ "$_HV_PLAIN" = 1 ]; then printf '%s' "$_HV_BUF"; else printf '%b' "$_HV_BUF"; fi
}

# write the buffer straight to stdout (byte exact, unlike $( ))
_hv_write_result() {
  if [ "$_HV_PLAIN" = 1 ]; then printf '%s' "$_HV_BUF"; else printf '%b' "$_HV_BUF"; fi
}

_hv_have() { command -v "$1" >/dev/null 2>&1; }

# byte value of a single character (LC_ALL=C, so this is a byte, not a codepoint).
# The two characters printf's "'c" form cannot handle are special cased.
_hv_ord() {
  case $1 in
    "'") printf '%s' 39 ;;
    '\') printf '%s' 92 ;;
    *) printf '%d' "'$1" ;;
  esac
}

# emit one byte, copying a character from the input verbatim
_hv_put_char() {
  case $1 in
    "'") _hv_putb 39 ;;
    '\') _hv_putb 92 ;;
    *) printf -v _hv_cc '%d' "'$1"; _hv_putb "$_hv_cc" ;;
  esac
}

#===============================================================================
# section 2 - input decoding (byte oriented UTF-8)
#===============================================================================

# set HV_BYTES from a string
_hv_to_bytes() {
  local t
  t=$(printf '%s' "$1" | od -An -tu1 -v | tr -s ' \n' ' ')
  HV_BYTES=()
  if [ -n "$t" ]; then read -r -a HV_BYTES <<< "$t"; fi
  HV_NBYTES=${#HV_BYTES[@]}
}

# decode HV_BYTES into CP/CP_BIDX/CP_BLEN; invalid bytes fall back to Latin-1
_hv_decode_utf8() {
  CP=(); CP_BIDX=(); CP_BLEN=()
  local i=0 n=$HV_NBYTES b len cp
  while [ "$i" -lt "$n" ]; do
    b=${HV_BYTES[i]}
    len=1; cp=$b
    if (( b < 0x80 )); then
      len=1; cp=$b
    elif (( (b & 0xE0) == 0xC0 )) && (( i+1 < n )) && (( (HV_BYTES[i+1] & 0xC0) == 0x80 )); then
      cp=$(( ((b & 0x1F) << 6) | (HV_BYTES[i+1] & 0x3F) )); len=2
    elif (( (b & 0xF0) == 0xE0 )) && (( i+2 < n )) && (( (HV_BYTES[i+1] & 0xC0) == 0x80 )) \
         && (( (HV_BYTES[i+2] & 0xC0) == 0x80 )); then
      cp=$(( ((b & 0x0F) << 12) | ((HV_BYTES[i+1] & 0x3F) << 6) | (HV_BYTES[i+2] & 0x3F) )); len=3
    elif (( (b & 0xF8) == 0xF0 )) && (( i+3 < n )) && (( (HV_BYTES[i+1] & 0xC0) == 0x80 )) \
         && (( (HV_BYTES[i+2] & 0xC0) == 0x80 )) && (( (HV_BYTES[i+3] & 0xC0) == 0x80 )); then
      cp=$(( ((b & 0x07) << 18) | ((HV_BYTES[i+1] & 0x3F) << 12) | \
              ((HV_BYTES[i+2] & 0x3F) << 6) | (HV_BYTES[i+3] & 0x3F) )); len=4
    fi
    # reject overlong encodings / surrogates such as C0 80, ED A0 80
    if (( len == 2 && cp < 0x80 )) || (( len == 3 && cp < 0x800 )) || \
       (( len == 4 && cp < 0x10000 )) || (( cp >= 0xD800 && cp <= 0xDFFF )); then
      len=1; cp=$b
    fi
    CP+=("$cp"); CP_BIDX+=("$i"); CP_BLEN+=("$len")
    i=$(( i + len ))
  done
  HV_NCP=${#CP[@]}
}

# Java's Convertors iterate UTF-16 indices while calling Character.codePointAt(i),
# so a supplementary character yields two values: the full codepoint, then the
# trailing (low) surrogate.  _hv_build_java_seq reproduces that quirk.
_hv_build_java_seq() {
  JV=()
  local k cp
  for (( k=0; k<HV_NCP; k++ )); do
    cp=${CP[k]}
    JV+=("$cp")
    if (( cp > 0xFFFF )); then
      JV+=("$(( 0xDC00 + ((cp - 0x10000) & 0x3FF) ))")
    fi
  done
  HV_NJV=${#JV[@]}
}

_hv_emit_cp_utf8() {
  local cp=$1
  if (( cp < 0x80 )); then
    _hv_putb "$cp"
  elif (( cp < 0x800 )); then
    _hv_putb "$(( 0xC0 | (cp >> 6) ))"
    _hv_putb "$(( 0x80 | (cp & 0x3F) ))"
  elif (( cp < 0x10000 )); then
    _hv_putb "$(( 0xE0 | (cp >> 12) ))"
    _hv_putb "$(( 0x80 | ((cp >> 6) & 0x3F) ))"
    _hv_putb "$(( 0x80 | (cp & 0x3F) ))"
  else
    _hv_putb "$(( 0xF0 | (cp >> 18) ))"
    _hv_putb "$(( 0x80 | ((cp >> 12) & 0x3F) ))"
    _hv_putb "$(( 0x80 | ((cp >> 6) & 0x3F) ))"
    _hv_putb "$(( 0x80 | (cp & 0x3F) ))"
  fi
}

# load input for the next conversion step
HV_INSTR=''                     # the current step's input, as a string
_hv_load_input() {
  HV_INSTR=$1
  _hv_to_bytes "$1"
  _hv_decode_utf8
  _hv_build_java_seq
}

# the input of the current step (used by the byte/string oriented encoders)
_hv_input_string() { printf '%s' "$HV_INSTR"; }

#===============================================================================
# section 3 - base encodings (pure bash, no external base64/base32 needed)
#===============================================================================

read -r -a _HV_B64TBL <<< "$(printf '%s ' {A..Z} {a..z} {0..9} '+' '/')"
read -r -a _HV_B32TBL <<< "$(printf '%s ' {A..Z} {2..7})"

# $1 = space separated byte values, $2 = 1 for url safe alphabet
_hv_b64_of_bytes() {
  local -a b=()
  local s=$1 i n out='' b0 b1 b2 rem
  if [ -n "$s" ]; then read -r -a b <<< "$s"; fi
  n=${#b[@]}
  for (( i=0; i<n; i+=3 )); do
    b0=${b[i]}; b1=0; b2=0
    rem=$(( n - i ))
    (( rem > 1 )) && b1=${b[i+1]}
    (( rem > 2 )) && b2=${b[i+2]}
    out+=${_HV_B64TBL[ b0 >> 2 ]}
    out+=${_HV_B64TBL[ ((b0 & 3) << 4) | (b1 >> 4) ]}
    if (( rem > 1 )); then out+=${_HV_B64TBL[ ((b1 & 15) << 2) | (b2 >> 6) ]}; else out+='='; fi
    if (( rem > 2 )); then out+=${_HV_B64TBL[ b2 & 63 ]}; else out+='='; fi
  done
  if [ "${2:-0}" = 1 ]; then
    out=${out//+/-}
    out=${out//\//_}
    while [ "${out: -1}" = '=' ]; do out=${out%?}; done
  fi
  HV_B64OUT=$out
}

# $1 = space separated byte values
_hv_b32_of_bytes() {
  local -a b=()
  local s=$1 i n acc=0 nbits=0 out=''
  if [ -n "$s" ]; then read -r -a b <<< "$s"; fi
  n=${#b[@]}
  for (( i=0; i<n; i++ )); do
    acc=$(( (acc << 8) | b[i] ))
    nbits=$(( nbits + 8 ))
    while (( nbits >= 5 )); do
      nbits=$(( nbits - 5 ))
      out+=${_HV_B32TBL[ (acc >> nbits) & 31 ]}
    done
    acc=$(( acc & ((1 << nbits) - 1) ))
  done
  if (( nbits > 0 )); then
    out+=${_HV_B32TBL[ (acc << (5 - nbits)) & 31 ]}
  fi
  while (( ${#out} % 8 != 0 )); do out+='='; done
  HV_B32OUT=$out
}

#===============================================================================
# section 4 - the encoders (ports of burp.hv.Convertors)
#===============================================================================

#--- base32 / base64 ----------------------------------------------------------
_enc_base32() { _hv_b32_of_bytes "${HV_BYTES[*]}"; _hv_put "$HV_B32OUT"; }
_enc_base64() { _hv_b64_of_bytes "${HV_BYTES[*]}" 0; _hv_put "$HV_B64OUT"; }
_enc_base64url() { _hv_b64_of_bytes "${HV_BYTES[*]}" 1; _hv_put "$HV_B64OUT"; }

#--- HTML entities ------------------------------------------------------------
# Convertors.java:
#   html_entities  = HtmlEscape.escapeHtml(str, HTML4_NAMED_REFERENCES_DEFAULT_TO_DECIMAL,
#                                          LEVEL_3_ALL_NON_ALPHANUMERIC)
#   html5_entities = same with HTML5_NAMED_REFERENCES_DEFAULT_TO_DECIMAL
# LEVEL_3 keeps ASCII alphanumerics and escapes everything else, preferring a
# named reference and falling back to a decimal reference.
_hv_is_ascii_alnum() {
  local c=$1
  (( (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) ))
}

_hv_html4_name() {
  if [ -n "${HV_HTML4_NAMES[$1]:-}" ]; then HV_NAME=${HV_HTML4_NAMES[$1]}; return 0; fi
  return 1
}

_hv_html5_name() {
  if [ -n "${HV_HTML5_NAMES[$1]:-}" ]; then HV_NAME=${HV_HTML5_NAMES[$1]}; return 0; fi
  return 1
}

_enc_html_entities()  { _enc_entities_named _hv_html4_name; }
_enc_html5_entities() { _enc_entities_named _hv_html5_name; }

_enc_entities_named() {
  local lk=$1 k cp
  _hv_load_html_tables "$lk"
  for (( k=0; k<HV_NCP; k++ )); do
    cp=${CP[k]}
    if _hv_is_ascii_alnum "$cp"; then
      _hv_put_orig "$k"
    elif "$lk" "$cp"; then
      _hv_put "&${HV_NAME};"
    else
      _hv_put "&#${cp};"
    fi
  done
}

# the generated tables are only materialised when an entity tag is used
_HV_T4_LOADED=0
_HV_T5_LOADED=0
_hv_load_html_tables() {
  case $1 in
    _hv_html4_name)
      if [ "$_HV_T4_LOADED" = 0 ]; then _hv_gen_load_html4; _HV_T4_LOADED=1; fi ;;
    _hv_html5_name)
      if [ "$_HV_T5_LOADED" = 0 ]; then _hv_gen_load_html5; _HV_T5_LOADED=1; fi ;;
  esac
}

# >>> BEGIN GENERATED ENTITY TABLES (produced by tools/gen_tables.py) >>>
# --- generated by tools/gen_tables.py from unbescape 1.1.6.RELEASE ---
# Do not edit by hand; run: python3 tools/gen_tables.py --output lib/entity_tables.sh
# HTML 4.01 named references: 252
_hv_gen_load_html4() {
  HV_HTML4_NAMES=(
    [34]="quot"
    [38]="amp"
    [60]="lt"
    [62]="gt"
    [160]="nbsp"
    [161]="iexcl"
    [162]="cent"
    [163]="pound"
    [164]="curren"
    [165]="yen"
    [166]="brvbar"
    [167]="sect"
    [168]="uml"
    [169]="copy"
    [170]="ordf"
    [171]="laquo"
    [172]="not"
    [173]="shy"
    [174]="reg"
    [175]="macr"
    [176]="deg"
    [177]="plusmn"
    [178]="sup2"
    [179]="sup3"
    [180]="acute"
    [181]="micro"
    [182]="para"
    [183]="middot"
    [184]="cedil"
    [185]="sup1"
    [186]="ordm"
    [187]="raquo"
    [188]="frac14"
    [189]="frac12"
    [190]="frac34"
    [191]="iquest"
    [192]="Agrave"
    [193]="Aacute"
    [194]="Acirc"
    [195]="Atilde"
    [196]="Auml"
    [197]="Aring"
    [198]="AElig"
    [199]="Ccedil"
    [200]="Egrave"
    [201]="Eacute"
    [202]="Ecirc"
    [203]="Euml"
    [204]="Igrave"
    [205]="Iacute"
    [206]="Icirc"
    [207]="Iuml"
    [208]="ETH"
    [209]="Ntilde"
    [210]="Ograve"
    [211]="Oacute"
    [212]="Ocirc"
    [213]="Otilde"
    [214]="Ouml"
    [215]="times"
    [216]="Oslash"
    [217]="Ugrave"
    [218]="Uacute"
    [219]="Ucirc"
    [220]="Uuml"
    [221]="Yacute"
    [222]="THORN"
    [223]="szlig"
    [224]="agrave"
    [225]="aacute"
    [226]="acirc"
    [227]="atilde"
    [228]="auml"
    [229]="aring"
    [230]="aelig"
    [231]="ccedil"
    [232]="egrave"
    [233]="eacute"
    [234]="ecirc"
    [235]="euml"
    [236]="igrave"
    [237]="iacute"
    [238]="icirc"
    [239]="iuml"
    [240]="eth"
    [241]="ntilde"
    [242]="ograve"
    [243]="oacute"
    [244]="ocirc"
    [245]="otilde"
    [246]="ouml"
    [247]="divide"
    [248]="oslash"
    [249]="ugrave"
    [250]="uacute"
    [251]="ucirc"
    [252]="uuml"
    [253]="yacute"
    [254]="thorn"
    [255]="yuml"
    [338]="OElig"
    [339]="oelig"
    [352]="Scaron"
    [353]="scaron"
    [376]="Yuml"
    [402]="fnof"
    [710]="circ"
    [732]="tilde"
    [913]="Alpha"
    [914]="Beta"
    [915]="Gamma"
    [916]="Delta"
    [917]="Epsilon"
    [918]="Zeta"
    [919]="Eta"
    [920]="Theta"
    [921]="Iota"
    [922]="Kappa"
    [923]="Lambda"
    [924]="Mu"
    [925]="Nu"
    [926]="Xi"
    [927]="Omicron"
    [928]="Pi"
    [929]="Rho"
    [931]="Sigma"
    [932]="Tau"
    [933]="Upsilon"
    [934]="Phi"
    [935]="Chi"
    [936]="Psi"
    [937]="Omega"
    [945]="alpha"
    [946]="beta"
    [947]="gamma"
    [948]="delta"
    [949]="epsilon"
    [950]="zeta"
    [951]="eta"
    [952]="theta"
    [953]="iota"
    [954]="kappa"
    [955]="lambda"
    [956]="mu"
    [957]="nu"
    [958]="xi"
    [959]="omicron"
    [960]="pi"
    [961]="rho"
    [962]="sigmaf"
    [963]="sigma"
    [964]="tau"
    [965]="upsilon"
    [966]="phi"
    [967]="chi"
    [968]="psi"
    [969]="omega"
    [977]="thetasym"
    [978]="upsih"
    [982]="piv"
    [8194]="ensp"
    [8195]="emsp"
    [8201]="thinsp"
    [8204]="zwnj"
    [8205]="zwj"
    [8206]="lrm"
    [8207]="rlm"
    [8211]="ndash"
    [8212]="mdash"
    [8216]="lsquo"
    [8217]="rsquo"
    [8218]="sbquo"
    [8220]="ldquo"
    [8221]="rdquo"
    [8222]="bdquo"
    [8224]="dagger"
    [8225]="Dagger"
    [8226]="bull"
    [8230]="hellip"
    [8240]="permil"
    [8242]="prime"
    [8243]="Prime"
    [8249]="lsaquo"
    [8250]="rsaquo"
    [8254]="oline"
    [8260]="frasl"
    [8364]="euro"
    [8465]="image"
    [8472]="weierp"
    [8476]="real"
    [8482]="trade"
    [8501]="alefsym"
    [8592]="larr"
    [8593]="uarr"
    [8594]="rarr"
    [8595]="darr"
    [8596]="harr"
    [8629]="crarr"
    [8656]="lArr"
    [8657]="uArr"
    [8658]="rArr"
    [8659]="dArr"
    [8660]="hArr"
    [8704]="forall"
    [8706]="part"
    [8707]="exist"
    [8709]="empty"
    [8711]="nabla"
    [8712]="isin"
    [8713]="notin"
    [8715]="ni"
    [8719]="prod"
    [8721]="sum"
    [8722]="minus"
    [8727]="lowast"
    [8730]="radic"
    [8733]="prop"
    [8734]="infin"
    [8736]="ang"
    [8743]="and"
    [8744]="or"
    [8745]="cap"
    [8746]="cup"
    [8747]="int"
    [8756]="there4"
    [8764]="sim"
    [8773]="cong"
    [8776]="asymp"
    [8800]="ne"
    [8801]="equiv"
    [8804]="le"
    [8805]="ge"
    [8834]="sub"
    [8835]="sup"
    [8836]="nsub"
    [8838]="sube"
    [8839]="supe"
    [8853]="oplus"
    [8855]="otimes"
    [8869]="perp"
    [8901]="sdot"
    [8968]="lceil"
    [8969]="rceil"
    [8970]="lfloor"
    [8971]="rfloor"
    [9001]="lang"
    [9002]="rang"
    [9674]="loz"
    [9824]="spades"
    [9827]="clubs"
    [9829]="hearts"
    [9830]="diams"
  )
}
# HTML5 named references (distinct codepoints): 1446
_hv_gen_load_html5() {
  HV_HTML5_NAMES=(
    [9]="Tab"
    [10]="NewLine"
    [33]="excl"
    [34]="quot"
    [35]="num"
    [36]="dollar"
    [37]="percnt"
    [38]="amp"
    [39]="apos"
    [40]="lpar"
    [41]="rpar"
    [42]="ast"
    [43]="plus"
    [44]="comma"
    [46]="period"
    [47]="sol"
    [58]="colon"
    [59]="semi"
    [60]="lt"
    [61]="equals"
    [62]="gt"
    [63]="quest"
    [64]="commat"
    [91]="lbrack"
    [92]="bsol"
    [93]="rbrack"
    [94]="Hat"
    [95]="lowbar"
    [96]="grave"
    [123]="lbrace"
    [124]="verbar"
    [125]="rbrace"
    [160]="nbsp"
    [161]="iexcl"
    [162]="cent"
    [163]="pound"
    [164]="curren"
    [165]="yen"
    [166]="brvbar"
    [167]="sect"
    [168]="uml"
    [169]="copy"
    [170]="ordf"
    [171]="laquo"
    [172]="not"
    [173]="shy"
    [174]="reg"
    [175]="macr"
    [176]="deg"
    [177]="plusmn"
    [178]="sup2"
    [179]="sup3"
    [180]="acute"
    [181]="micro"
    [182]="para"
    [183]="middot"
    [184]="cedil"
    [185]="sup1"
    [186]="ordm"
    [187]="raquo"
    [188]="frac14"
    [189]="frac12"
    [190]="frac34"
    [191]="iquest"
    [192]="Agrave"
    [193]="Aacute"
    [194]="Acirc"
    [195]="Atilde"
    [196]="Auml"
    [197]="Aring"
    [198]="AElig"
    [199]="Ccedil"
    [200]="Egrave"
    [201]="Eacute"
    [202]="Ecirc"
    [203]="Euml"
    [204]="Igrave"
    [205]="Iacute"
    [206]="Icirc"
    [207]="Iuml"
    [208]="ETH"
    [209]="Ntilde"
    [210]="Ograve"
    [211]="Oacute"
    [212]="Ocirc"
    [213]="Otilde"
    [214]="Ouml"
    [215]="times"
    [216]="Oslash"
    [217]="Ugrave"
    [218]="Uacute"
    [219]="Ucirc"
    [220]="Uuml"
    [221]="Yacute"
    [222]="THORN"
    [223]="szlig"
    [224]="agrave"
    [225]="aacute"
    [226]="acirc"
    [227]="atilde"
    [228]="auml"
    [229]="aring"
    [230]="aelig"
    [231]="ccedil"
    [232]="egrave"
    [233]="eacute"
    [234]="ecirc"
    [235]="euml"
    [236]="igrave"
    [237]="iacute"
    [238]="icirc"
    [239]="iuml"
    [240]="eth"
    [241]="ntilde"
    [242]="ograve"
    [243]="oacute"
    [244]="ocirc"
    [245]="otilde"
    [246]="ouml"
    [247]="divide"
    [248]="oslash"
    [249]="ugrave"
    [250]="uacute"
    [251]="ucirc"
    [252]="uuml"
    [253]="yacute"
    [254]="thorn"
    [255]="yuml"
    [256]="Amacr"
    [257]="amacr"
    [258]="Abreve"
    [259]="abreve"
    [260]="Aogon"
    [261]="aogon"
    [262]="Cacute"
    [263]="cacute"
    [264]="Ccirc"
    [265]="ccirc"
    [266]="Cdot"
    [267]="cdot"
    [268]="Ccaron"
    [269]="ccaron"
    [270]="Dcaron"
    [271]="dcaron"
    [272]="Dstrok"
    [273]="dstrok"
    [274]="Emacr"
    [275]="emacr"
    [278]="Edot"
    [279]="edot"
    [280]="Eogon"
    [281]="eogon"
    [282]="Ecaron"
    [283]="ecaron"
    [284]="Gcirc"
    [285]="gcirc"
    [286]="Gbreve"
    [287]="gbreve"
    [288]="Gdot"
    [289]="gdot"
    [290]="Gcedil"
    [292]="Hcirc"
    [293]="hcirc"
    [294]="Hstrok"
    [295]="hstrok"
    [296]="Itilde"
    [297]="itilde"
    [298]="Imacr"
    [299]="imacr"
    [302]="Iogon"
    [303]="iogon"
    [304]="Idot"
    [305]="imath"
    [306]="IJlig"
    [307]="ijlig"
    [308]="Jcirc"
    [309]="jcirc"
    [310]="Kcedil"
    [311]="kcedil"
    [312]="kgreen"
    [313]="Lacute"
    [314]="lacute"
    [315]="Lcedil"
    [316]="lcedil"
    [317]="Lcaron"
    [318]="lcaron"
    [319]="Lmidot"
    [320]="lmidot"
    [321]="Lstrok"
    [322]="lstrok"
    [323]="Nacute"
    [324]="nacute"
    [325]="Ncedil"
    [326]="ncedil"
    [327]="Ncaron"
    [328]="ncaron"
    [329]="napos"
    [330]="ENG"
    [331]="eng"
    [332]="Omacr"
    [333]="omacr"
    [336]="Odblac"
    [337]="odblac"
    [338]="OElig"
    [339]="oelig"
    [340]="Racute"
    [341]="racute"
    [342]="Rcedil"
    [343]="rcedil"
    [344]="Rcaron"
    [345]="rcaron"
    [346]="Sacute"
    [347]="sacute"
    [348]="Scirc"
    [349]="scirc"
    [350]="Scedil"
    [351]="scedil"
    [352]="Scaron"
    [353]="scaron"
    [354]="Tcedil"
    [355]="tcedil"
    [356]="Tcaron"
    [357]="tcaron"
    [358]="Tstrok"
    [359]="tstrok"
    [360]="Utilde"
    [361]="utilde"
    [362]="Umacr"
    [363]="umacr"
    [364]="Ubreve"
    [365]="ubreve"
    [366]="Uring"
    [367]="uring"
    [368]="Udblac"
    [369]="udblac"
    [370]="Uogon"
    [371]="uogon"
    [372]="Wcirc"
    [373]="wcirc"
    [374]="Ycirc"
    [375]="ycirc"
    [376]="Yuml"
    [377]="Zacute"
    [378]="zacute"
    [379]="Zdot"
    [380]="zdot"
    [381]="Zcaron"
    [382]="zcaron"
    [402]="fnof"
    [437]="imped"
    [501]="gacute"
    [567]="jmath"
    [710]="circ"
    [711]="caron"
    [728]="breve"
    [729]="dot"
    [730]="ring"
    [731]="ogon"
    [732]="tilde"
    [733]="dblac"
    [785]="DownBreve"
    [913]="Alpha"
    [914]="Beta"
    [915]="Gamma"
    [916]="Delta"
    [917]="Epsilon"
    [918]="Zeta"
    [919]="Eta"
    [920]="Theta"
    [921]="Iota"
    [922]="Kappa"
    [923]="Lambda"
    [924]="Mu"
    [925]="Nu"
    [926]="Xi"
    [927]="Omicron"
    [928]="Pi"
    [929]="Rho"
    [931]="Sigma"
    [932]="Tau"
    [933]="Upsilon"
    [934]="Phi"
    [935]="Chi"
    [936]="Psi"
    [937]="Omega"
    [945]="alpha"
    [946]="beta"
    [947]="gamma"
    [948]="delta"
    [949]="epsilon"
    [950]="zeta"
    [951]="eta"
    [952]="theta"
    [953]="iota"
    [954]="kappa"
    [955]="lambda"
    [956]="mu"
    [957]="nu"
    [958]="xi"
    [959]="omicron"
    [960]="pi"
    [961]="rho"
    [962]="sigmaf"
    [963]="sigma"
    [964]="tau"
    [965]="upsilon"
    [966]="phi"
    [967]="chi"
    [968]="psi"
    [969]="omega"
    [977]="thetasym"
    [978]="upsih"
    [981]="phiv"
    [982]="piv"
    [988]="Gammad"
    [989]="digamma"
    [1008]="kappav"
    [1009]="rhov"
    [1013]="epsiv"
    [1014]="backepsilon"
    [1025]="IOcy"
    [1026]="DJcy"
    [1027]="GJcy"
    [1028]="Jukcy"
    [1029]="DScy"
    [1030]="Iukcy"
    [1031]="YIcy"
    [1032]="Jsercy"
    [1033]="LJcy"
    [1034]="NJcy"
    [1035]="TSHcy"
    [1036]="KJcy"
    [1038]="Ubrcy"
    [1039]="DZcy"
    [1040]="Acy"
    [1041]="Bcy"
    [1042]="Vcy"
    [1043]="Gcy"
    [1044]="Dcy"
    [1045]="IEcy"
    [1046]="ZHcy"
    [1047]="Zcy"
    [1048]="Icy"
    [1049]="Jcy"
    [1050]="Kcy"
    [1051]="Lcy"
    [1052]="Mcy"
    [1053]="Ncy"
    [1054]="Ocy"
    [1055]="Pcy"
    [1056]="Rcy"
    [1057]="Scy"
    [1058]="Tcy"
    [1059]="Ucy"
    [1060]="Fcy"
    [1061]="KHcy"
    [1062]="TScy"
    [1063]="CHcy"
    [1064]="SHcy"
    [1065]="SHCHcy"
    [1066]="HARDcy"
    [1067]="Ycy"
    [1068]="SOFTcy"
    [1069]="Ecy"
    [1070]="YUcy"
    [1071]="YAcy"
    [1072]="acy"
    [1073]="bcy"
    [1074]="vcy"
    [1075]="gcy"
    [1076]="dcy"
    [1077]="iecy"
    [1078]="zhcy"
    [1079]="zcy"
    [1080]="icy"
    [1081]="jcy"
    [1082]="kcy"
    [1083]="lcy"
    [1084]="mcy"
    [1085]="ncy"
    [1086]="ocy"
    [1087]="pcy"
    [1088]="rcy"
    [1089]="scy"
    [1090]="tcy"
    [1091]="ucy"
    [1092]="fcy"
    [1093]="khcy"
    [1094]="tscy"
    [1095]="chcy"
    [1096]="shcy"
    [1097]="shchcy"
    [1098]="hardcy"
    [1099]="ycy"
    [1100]="softcy"
    [1101]="ecy"
    [1102]="yucy"
    [1103]="yacy"
    [1105]="iocy"
    [1106]="djcy"
    [1107]="gjcy"
    [1108]="jukcy"
    [1109]="dscy"
    [1110]="iukcy"
    [1111]="yicy"
    [1112]="jsercy"
    [1113]="ljcy"
    [1114]="njcy"
    [1115]="tshcy"
    [1116]="kjcy"
    [1118]="ubrcy"
    [1119]="dzcy"
    [8194]="ensp"
    [8195]="emsp"
    [8196]="emsp13"
    [8197]="emsp14"
    [8199]="numsp"
    [8200]="puncsp"
    [8201]="thinsp"
    [8202]="hairsp"
    [8203]="NegativeMediumSpace"
    [8204]="zwnj"
    [8205]="zwj"
    [8206]="lrm"
    [8207]="rlm"
    [8208]="dash"
    [8211]="ndash"
    [8212]="mdash"
    [8213]="horbar"
    [8214]="Verbar"
    [8216]="lsquo"
    [8217]="rsquo"
    [8218]="sbquo"
    [8220]="ldquo"
    [8221]="rdquo"
    [8222]="bdquo"
    [8224]="dagger"
    [8225]="Dagger"
    [8226]="bull"
    [8229]="nldr"
    [8230]="hellip"
    [8240]="permil"
    [8241]="pertenk"
    [8242]="prime"
    [8243]="Prime"
    [8244]="tprime"
    [8245]="backprime"
    [8249]="lsaquo"
    [8250]="rsaquo"
    [8254]="oline"
    [8257]="caret"
    [8259]="hybull"
    [8260]="frasl"
    [8271]="bsemi"
    [8279]="qprime"
    [8287]="MediumSpace"
    [8288]="NoBreak"
    [8289]="af"
    [8290]="it"
    [8291]="ic"
    [8364]="euro"
    [8411]="tdot"
    [8412]="DotDot"
    [8450]="complexes"
    [8453]="incare"
    [8458]="gscr"
    [8459]="hamilt"
    [8460]="Hfr"
    [8461]="quaternions"
    [8462]="planckh"
    [8463]="hbar"
    [8464]="imagline"
    [8465]="image"
    [8466]="lagran"
    [8467]="ell"
    [8469]="naturals"
    [8470]="numero"
    [8471]="copysr"
    [8472]="weierp"
    [8473]="primes"
    [8474]="rationals"
    [8475]="realine"
    [8476]="real"
    [8477]="reals"
    [8478]="rx"
    [8482]="trade"
    [8484]="integers"
    [8487]="mho"
    [8488]="zeetrf"
    [8489]="iiota"
    [8492]="bernou"
    [8493]="Cayleys"
    [8495]="escr"
    [8496]="expectation"
    [8497]="Fouriertrf"
    [8499]="phmmat"
    [8500]="order"
    [8501]="alefsym"
    [8502]="beth"
    [8503]="gimel"
    [8504]="daleth"
    [8517]="CapitalDifferentialD"
    [8518]="dd"
    [8519]="ee"
    [8520]="ii"
    [8531]="frac13"
    [8532]="frac23"
    [8533]="frac15"
    [8534]="frac25"
    [8535]="frac35"
    [8536]="frac45"
    [8537]="frac16"
    [8538]="frac56"
    [8539]="frac18"
    [8540]="frac38"
    [8541]="frac58"
    [8542]="frac78"
    [8592]="larr"
    [8593]="uarr"
    [8594]="rarr"
    [8595]="darr"
    [8596]="harr"
    [8597]="updownarrow"
    [8598]="nwarr"
    [8599]="nearr"
    [8600]="searr"
    [8601]="swarr"
    [8602]="nlarr"
    [8603]="nrarr"
    [8605]="rarrw"
    [8606]="twoheadleftarrow"
    [8607]="Uarr"
    [8608]="twoheadrightarrow"
    [8609]="Darr"
    [8610]="larrtl"
    [8611]="rarrtl"
    [8612]="mapstoleft"
    [8613]="mapstoup"
    [8614]="map"
    [8615]="mapstodown"
    [8617]="hookleftarrow"
    [8618]="hookrightarrow"
    [8619]="larrlp"
    [8620]="looparrowright"
    [8621]="harrw"
    [8622]="nharr"
    [8624]="lsh"
    [8625]="rsh"
    [8626]="ldsh"
    [8627]="rdsh"
    [8629]="crarr"
    [8630]="cularr"
    [8631]="curarr"
    [8634]="circlearrowleft"
    [8635]="circlearrowright"
    [8636]="leftharpoonup"
    [8637]="leftharpoondown"
    [8638]="uharr"
    [8639]="uharl"
    [8640]="rharu"
    [8641]="rhard"
    [8642]="dharr"
    [8643]="dharl"
    [8644]="rightleftarrows"
    [8645]="udarr"
    [8646]="leftrightarrows"
    [8647]="leftleftarrows"
    [8648]="upuparrows"
    [8649]="rightrightarrows"
    [8650]="ddarr"
    [8651]="leftrightharpoons"
    [8652]="rightleftharpoons"
    [8653]="nLeftarrow"
    [8654]="nLeftrightarrow"
    [8655]="nRightarrow"
    [8656]="lArr"
    [8657]="uArr"
    [8658]="rArr"
    [8659]="dArr"
    [8660]="hArr"
    [8661]="vArr"
    [8662]="nwArr"
    [8663]="neArr"
    [8664]="seArr"
    [8665]="swArr"
    [8666]="lAarr"
    [8667]="rAarr"
    [8669]="zigrarr"
    [8676]="larrb"
    [8677]="rarrb"
    [8693]="duarr"
    [8701]="loarr"
    [8702]="roarr"
    [8703]="hoarr"
    [8704]="forall"
    [8705]="comp"
    [8706]="part"
    [8707]="exist"
    [8708]="nexist"
    [8709]="empty"
    [8711]="nabla"
    [8712]="isin"
    [8713]="notin"
    [8715]="ni"
    [8716]="notni"
    [8719]="prod"
    [8720]="coprod"
    [8721]="sum"
    [8722]="minus"
    [8723]="mnplus"
    [8724]="dotplus"
    [8726]="setminus"
    [8727]="lowast"
    [8728]="compfn"
    [8730]="radic"
    [8733]="prop"
    [8734]="infin"
    [8735]="angrt"
    [8736]="ang"
    [8737]="angmsd"
    [8738]="angsph"
    [8739]="mid"
    [8740]="nmid"
    [8741]="par"
    [8742]="npar"
    [8743]="and"
    [8744]="or"
    [8745]="cap"
    [8746]="cup"
    [8747]="int"
    [8748]="Int"
    [8749]="iiint"
    [8750]="conint"
    [8751]="Conint"
    [8752]="Cconint"
    [8753]="cwint"
    [8754]="cwconint"
    [8755]="awconint"
    [8756]="there4"
    [8757]="becaus"
    [8758]="ratio"
    [8759]="Colon"
    [8760]="dotminus"
    [8762]="mDDot"
    [8763]="homtht"
    [8764]="sim"
    [8765]="backsim"
    [8766]="ac"
    [8767]="acd"
    [8768]="wr"
    [8769]="nsim"
    [8770]="eqsim"
    [8771]="sime"
    [8772]="nsime"
    [8773]="cong"
    [8774]="simne"
    [8775]="ncong"
    [8776]="asymp"
    [8777]="nap"
    [8778]="ape"
    [8779]="apid"
    [8780]="backcong"
    [8781]="asympeq"
    [8782]="bump"
    [8783]="bumpe"
    [8784]="doteq"
    [8785]="doteqdot"
    [8786]="efDot"
    [8787]="erDot"
    [8788]="colone"
    [8789]="ecolon"
    [8790]="ecir"
    [8791]="circeq"
    [8793]="wedgeq"
    [8794]="veeeq"
    [8796]="triangleq"
    [8799]="equest"
    [8800]="ne"
    [8801]="equiv"
    [8802]="nequiv"
    [8804]="le"
    [8805]="ge"
    [8806]="lE"
    [8807]="gE"
    [8808]="lnE"
    [8809]="gnE"
    [8810]="ll"
    [8811]="gg"
    [8812]="between"
    [8813]="NotCupCap"
    [8814]="nless"
    [8815]="ngt"
    [8816]="nle"
    [8817]="nge"
    [8818]="lesssim"
    [8819]="gsim"
    [8820]="nlsim"
    [8821]="ngsim"
    [8822]="lessgtr"
    [8823]="gl"
    [8824]="ntlg"
    [8825]="ntgl"
    [8826]="pr"
    [8827]="sc"
    [8828]="prcue"
    [8829]="sccue"
    [8830]="precsim"
    [8831]="scsim"
    [8832]="npr"
    [8833]="nsc"
    [8834]="sub"
    [8835]="sup"
    [8836]="nsub"
    [8837]="nsup"
    [8838]="sube"
    [8839]="supe"
    [8840]="nsube"
    [8841]="nsupe"
    [8842]="subne"
    [8843]="supne"
    [8845]="cupdot"
    [8846]="uplus"
    [8847]="sqsub"
    [8848]="sqsup"
    [8849]="sqsube"
    [8850]="sqsupe"
    [8851]="sqcap"
    [8852]="sqcup"
    [8853]="oplus"
    [8854]="ominus"
    [8855]="otimes"
    [8856]="osol"
    [8857]="odot"
    [8858]="circledcirc"
    [8859]="circledast"
    [8861]="circleddash"
    [8862]="boxplus"
    [8863]="boxminus"
    [8864]="boxtimes"
    [8865]="dotsquare"
    [8866]="vdash"
    [8867]="dashv"
    [8868]="top"
    [8869]="perp"
    [8871]="models"
    [8872]="vDash"
    [8873]="Vdash"
    [8874]="Vvdash"
    [8875]="VDash"
    [8876]="nvdash"
    [8877]="nvDash"
    [8878]="nVdash"
    [8879]="nVDash"
    [8880]="prurel"
    [8882]="vartriangleleft"
    [8883]="vartriangleright"
    [8884]="ltrie"
    [8885]="rtrie"
    [8886]="origof"
    [8887]="imof"
    [8888]="multimap"
    [8889]="hercon"
    [8890]="intcal"
    [8891]="veebar"
    [8893]="barvee"
    [8894]="angrtvb"
    [8895]="lrtri"
    [8896]="bigwedge"
    [8897]="bigvee"
    [8898]="bigcap"
    [8899]="bigcup"
    [8900]="diam"
    [8901]="sdot"
    [8902]="sstarf"
    [8903]="divideontimes"
    [8904]="bowtie"
    [8905]="ltimes"
    [8906]="rtimes"
    [8907]="leftthreetimes"
    [8908]="rightthreetimes"
    [8909]="backsimeq"
    [8910]="curlyvee"
    [8911]="curlywedge"
    [8912]="Sub"
    [8913]="Sup"
    [8914]="Cap"
    [8915]="Cup"
    [8916]="fork"
    [8917]="epar"
    [8918]="lessdot"
    [8919]="gtdot"
    [8920]="Ll"
    [8921]="ggg"
    [8922]="leg"
    [8923]="gel"
    [8926]="cuepr"
    [8927]="cuesc"
    [8928]="nprcue"
    [8929]="nsccue"
    [8930]="nsqsube"
    [8931]="nsqsupe"
    [8934]="lnsim"
    [8935]="gnsim"
    [8936]="precnsim"
    [8937]="scnsim"
    [8938]="nltri"
    [8939]="nrtri"
    [8940]="nltrie"
    [8941]="nrtrie"
    [8942]="vellip"
    [8943]="ctdot"
    [8944]="utdot"
    [8945]="dtdot"
    [8946]="disin"
    [8947]="isinsv"
    [8948]="isins"
    [8949]="isindot"
    [8950]="notinvc"
    [8951]="notinvb"
    [8953]="isinE"
    [8954]="nisd"
    [8955]="xnis"
    [8956]="nis"
    [8957]="notnivc"
    [8958]="notnivb"
    [8965]="barwed"
    [8966]="doublebarwedge"
    [8968]="lceil"
    [8969]="rceil"
    [8970]="lfloor"
    [8971]="rfloor"
    [8972]="drcrop"
    [8973]="dlcrop"
    [8974]="urcrop"
    [8975]="ulcrop"
    [8976]="bnot"
    [8978]="profline"
    [8979]="profsurf"
    [8981]="telrec"
    [8982]="target"
    [8988]="ulcorn"
    [8989]="urcorn"
    [8990]="dlcorn"
    [8991]="drcorn"
    [8994]="frown"
    [8995]="smile"
    [9005]="cylcty"
    [9006]="profalar"
    [9014]="topbot"
    [9021]="ovbar"
    [9023]="solbar"
    [9084]="angzarr"
    [9136]="lmoust"
    [9137]="rmoust"
    [9140]="tbrk"
    [9141]="bbrk"
    [9142]="bbrktbrk"
    [9180]="OverParenthesis"
    [9181]="UnderParenthesis"
    [9182]="OverBrace"
    [9183]="UnderBrace"
    [9186]="trpezium"
    [9191]="elinters"
    [9251]="blank"
    [9416]="circledS"
    [9472]="boxh"
    [9474]="boxv"
    [9484]="boxdr"
    [9488]="boxdl"
    [9492]="boxur"
    [9496]="boxul"
    [9500]="boxvr"
    [9508]="boxvl"
    [9516]="boxhd"
    [9524]="boxhu"
    [9532]="boxvh"
    [9552]="boxH"
    [9553]="boxV"
    [9554]="boxdR"
    [9555]="boxDr"
    [9556]="boxDR"
    [9557]="boxdL"
    [9558]="boxDl"
    [9559]="boxDL"
    [9560]="boxuR"
    [9561]="boxUr"
    [9562]="boxUR"
    [9563]="boxuL"
    [9564]="boxUl"
    [9565]="boxUL"
    [9566]="boxvR"
    [9567]="boxVr"
    [9568]="boxVR"
    [9569]="boxvL"
    [9570]="boxVl"
    [9571]="boxVL"
    [9572]="boxHd"
    [9573]="boxhD"
    [9574]="boxHD"
    [9575]="boxHu"
    [9576]="boxhU"
    [9577]="boxHU"
    [9578]="boxvH"
    [9579]="boxVh"
    [9580]="boxVH"
    [9600]="uhblk"
    [9604]="lhblk"
    [9608]="block"
    [9617]="blk14"
    [9618]="blk12"
    [9619]="blk34"
    [9633]="squ"
    [9642]="blacksquare"
    [9643]="EmptyVerySmallSquare"
    [9645]="rect"
    [9646]="marker"
    [9649]="fltns"
    [9651]="bigtriangleup"
    [9652]="blacktriangle"
    [9653]="triangle"
    [9656]="blacktriangleright"
    [9657]="rtri"
    [9661]="bigtriangledown"
    [9662]="blacktriangledown"
    [9663]="dtri"
    [9666]="blacktriangleleft"
    [9667]="ltri"
    [9674]="loz"
    [9675]="cir"
    [9708]="tridot"
    [9711]="bigcirc"
    [9720]="ultri"
    [9721]="urtri"
    [9722]="lltri"
    [9723]="EmptySmallSquare"
    [9724]="FilledSmallSquare"
    [9733]="bigstar"
    [9734]="star"
    [9742]="phone"
    [9792]="female"
    [9794]="male"
    [9824]="spades"
    [9827]="clubs"
    [9829]="hearts"
    [9830]="diams"
    [9834]="sung"
    [9837]="flat"
    [9838]="natur"
    [9839]="sharp"
    [10003]="check"
    [10007]="cross"
    [10016]="malt"
    [10038]="sext"
    [10072]="VerticalSeparator"
    [10098]="lbbrk"
    [10099]="rbbrk"
    [10184]="bsolhsub"
    [10185]="suphsol"
    [10214]="lobrk"
    [10215]="robrk"
    [10216]="lang"
    [10217]="rang"
    [10218]="Lang"
    [10219]="Rang"
    [10220]="loang"
    [10221]="roang"
    [10229]="longleftarrow"
    [10230]="longrightarrow"
    [10231]="longleftrightarrow"
    [10232]="xlArr"
    [10233]="xrArr"
    [10234]="xhArr"
    [10236]="longmapsto"
    [10239]="dzigrarr"
    [10498]="nvlArr"
    [10499]="nvrArr"
    [10500]="nvHarr"
    [10501]="Map"
    [10508]="lbarr"
    [10509]="bkarow"
    [10510]="lBarr"
    [10511]="dbkarow"
    [10512]="drbkarow"
    [10513]="DDotrahd"
    [10514]="UpArrowBar"
    [10515]="DownArrowBar"
    [10518]="Rarrtl"
    [10521]="latail"
    [10522]="ratail"
    [10523]="lAtail"
    [10524]="rAtail"
    [10525]="larrfs"
    [10526]="rarrfs"
    [10527]="larrbfs"
    [10528]="rarrbfs"
    [10531]="nwarhk"
    [10532]="nearhk"
    [10533]="hksearow"
    [10534]="hkswarow"
    [10535]="nwnear"
    [10536]="nesear"
    [10537]="seswar"
    [10538]="swnwar"
    [10547]="rarrc"
    [10549]="cudarrr"
    [10550]="ldca"
    [10551]="rdca"
    [10552]="cudarrl"
    [10553]="larrpl"
    [10556]="curarrm"
    [10557]="cularrp"
    [10565]="rarrpl"
    [10568]="harrcir"
    [10569]="Uarrocir"
    [10570]="lurdshar"
    [10571]="ldrushar"
    [10574]="LeftRightVector"
    [10575]="RightUpDownVector"
    [10576]="DownLeftRightVector"
    [10577]="LeftUpDownVector"
    [10578]="LeftVectorBar"
    [10579]="RightVectorBar"
    [10580]="RightUpVectorBar"
    [10581]="RightDownVectorBar"
    [10582]="DownLeftVectorBar"
    [10583]="DownRightVectorBar"
    [10584]="LeftUpVectorBar"
    [10585]="LeftDownVectorBar"
    [10586]="LeftTeeVector"
    [10587]="RightTeeVector"
    [10588]="RightUpTeeVector"
    [10589]="RightDownTeeVector"
    [10590]="DownLeftTeeVector"
    [10591]="DownRightTeeVector"
    [10592]="LeftUpTeeVector"
    [10593]="LeftDownTeeVector"
    [10594]="lHar"
    [10595]="uHar"
    [10596]="rHar"
    [10597]="dHar"
    [10598]="luruhar"
    [10599]="ldrdhar"
    [10600]="ruluhar"
    [10601]="rdldhar"
    [10602]="lharul"
    [10603]="llhard"
    [10604]="rharul"
    [10605]="lrhard"
    [10606]="udhar"
    [10607]="duhar"
    [10608]="RoundImplies"
    [10609]="erarr"
    [10610]="simrarr"
    [10611]="larrsim"
    [10612]="rarrsim"
    [10613]="rarrap"
    [10614]="ltlarr"
    [10616]="gtrarr"
    [10617]="subrarr"
    [10619]="suplarr"
    [10620]="lfisht"
    [10621]="rfisht"
    [10622]="ufisht"
    [10623]="dfisht"
    [10629]="lopar"
    [10630]="ropar"
    [10635]="lbrke"
    [10636]="rbrke"
    [10637]="lbrkslu"
    [10638]="rbrksld"
    [10639]="lbrksld"
    [10640]="rbrkslu"
    [10641]="langd"
    [10642]="rangd"
    [10643]="lparlt"
    [10644]="rpargt"
    [10645]="gtlPar"
    [10646]="ltrPar"
    [10650]="vzigzag"
    [10652]="vangrt"
    [10653]="angrtvbd"
    [10660]="ange"
    [10661]="range"
    [10662]="dwangle"
    [10663]="uwangle"
    [10664]="angmsdaa"
    [10665]="angmsdab"
    [10666]="angmsdac"
    [10667]="angmsdad"
    [10668]="angmsdae"
    [10669]="angmsdaf"
    [10670]="angmsdag"
    [10671]="angmsdah"
    [10672]="bemptyv"
    [10673]="demptyv"
    [10674]="cemptyv"
    [10675]="raemptyv"
    [10676]="laemptyv"
    [10677]="ohbar"
    [10678]="omid"
    [10679]="opar"
    [10681]="operp"
    [10683]="olcross"
    [10684]="odsold"
    [10686]="olcir"
    [10687]="ofcir"
    [10688]="olt"
    [10689]="ogt"
    [10690]="cirscir"
    [10691]="cirE"
    [10692]="solb"
    [10693]="bsolb"
    [10697]="boxbox"
    [10701]="trisb"
    [10702]="rtriltri"
    [10703]="LeftTriangleBar"
    [10704]="RightTriangleBar"
    [10716]="iinfin"
    [10717]="infintie"
    [10718]="nvinfin"
    [10723]="eparsl"
    [10724]="smeparsl"
    [10725]="eqvparsl"
    [10731]="blacklozenge"
    [10740]="RuleDelayed"
    [10742]="dsol"
    [10752]="bigodot"
    [10753]="bigoplus"
    [10754]="bigotimes"
    [10756]="biguplus"
    [10758]="bigsqcup"
    [10764]="iiiint"
    [10765]="fpartint"
    [10768]="cirfnint"
    [10769]="awint"
    [10770]="rppolint"
    [10771]="scpolint"
    [10772]="npolint"
    [10773]="pointint"
    [10774]="quatint"
    [10775]="intlarhk"
    [10786]="pluscir"
    [10787]="plusacir"
    [10788]="simplus"
    [10789]="plusdu"
    [10790]="plussim"
    [10791]="plustwo"
    [10793]="mcomma"
    [10794]="minusdu"
    [10797]="loplus"
    [10798]="roplus"
    [10799]="Cross"
    [10800]="timesd"
    [10801]="timesbar"
    [10803]="smashp"
    [10804]="lotimes"
    [10805]="rotimes"
    [10806]="otimesas"
    [10807]="Otimes"
    [10808]="odiv"
    [10809]="triplus"
    [10810]="triminus"
    [10811]="tritime"
    [10812]="intprod"
    [10815]="amalg"
    [10816]="capdot"
    [10818]="ncup"
    [10819]="ncap"
    [10820]="capand"
    [10821]="cupor"
    [10822]="cupcap"
    [10823]="capcup"
    [10824]="cupbrcap"
    [10825]="capbrcup"
    [10826]="cupcup"
    [10827]="capcap"
    [10828]="ccups"
    [10829]="ccaps"
    [10832]="ccupssm"
    [10835]="And"
    [10836]="Or"
    [10837]="andand"
    [10838]="oror"
    [10839]="orslope"
    [10840]="andslope"
    [10842]="andv"
    [10843]="orv"
    [10844]="andd"
    [10845]="ord"
    [10847]="wedbar"
    [10854]="sdote"
    [10858]="simdot"
    [10861]="congdot"
    [10862]="easter"
    [10863]="apacir"
    [10864]="apE"
    [10865]="eplus"
    [10866]="pluse"
    [10867]="Esim"
    [10868]="Colone"
    [10869]="Equal"
    [10871]="ddotseq"
    [10872]="equivDD"
    [10873]="ltcir"
    [10874]="gtcir"
    [10875]="ltquest"
    [10876]="gtquest"
    [10877]="leqslant"
    [10878]="geqslant"
    [10879]="lesdot"
    [10880]="gesdot"
    [10881]="lesdoto"
    [10882]="gesdoto"
    [10883]="lesdotor"
    [10884]="gesdotol"
    [10885]="lap"
    [10886]="gap"
    [10887]="lne"
    [10888]="gne"
    [10889]="lnap"
    [10890]="gnap"
    [10891]="lEg"
    [10892]="gEl"
    [10893]="lsime"
    [10894]="gsime"
    [10895]="lsimg"
    [10896]="gsiml"
    [10897]="lgE"
    [10898]="glE"
    [10899]="lesges"
    [10900]="gesles"
    [10901]="els"
    [10902]="egs"
    [10903]="elsdot"
    [10904]="egsdot"
    [10905]="el"
    [10906]="eg"
    [10909]="siml"
    [10910]="simg"
    [10911]="simlE"
    [10912]="simgE"
    [10913]="LessLess"
    [10914]="GreaterGreater"
    [10916]="glj"
    [10917]="gla"
    [10918]="ltcc"
    [10919]="gtcc"
    [10920]="lescc"
    [10921]="gescc"
    [10922]="smt"
    [10923]="lat"
    [10924]="smte"
    [10925]="late"
    [10926]="bumpE"
    [10927]="pre"
    [10928]="sce"
    [10931]="prE"
    [10932]="scE"
    [10933]="precneqq"
    [10934]="scnE"
    [10935]="prap"
    [10936]="scap"
    [10937]="precnapprox"
    [10938]="scnap"
    [10939]="Pr"
    [10940]="Sc"
    [10941]="subdot"
    [10942]="supdot"
    [10943]="subplus"
    [10944]="supplus"
    [10945]="submult"
    [10946]="supmult"
    [10947]="subedot"
    [10948]="supedot"
    [10949]="subE"
    [10950]="supE"
    [10951]="subsim"
    [10952]="supsim"
    [10955]="subnE"
    [10956]="supnE"
    [10959]="csub"
    [10960]="csup"
    [10961]="csube"
    [10962]="csupe"
    [10963]="subsup"
    [10964]="supsub"
    [10965]="subsub"
    [10966]="supsup"
    [10967]="suphsub"
    [10968]="supdsub"
    [10969]="forkv"
    [10970]="topfork"
    [10971]="mlcp"
    [10980]="Dashv"
    [10982]="Vdashl"
    [10983]="Barv"
    [10984]="vBar"
    [10985]="vBarv"
    [10987]="Vbar"
    [10988]="Not"
    [10989]="bNot"
    [10990]="rnmid"
    [10991]="cirmid"
    [10992]="midcir"
    [10993]="topcir"
    [10994]="nhpar"
    [10995]="parsim"
    [11005]="parsl"
    [64256]="fflig"
    [64257]="filig"
    [64258]="fllig"
    [64259]="ffilig"
    [64260]="ffllig"
    [119964]="Ascr"
    [119966]="Cscr"
    [119967]="Dscr"
    [119970]="Gscr"
    [119973]="Jscr"
    [119974]="Kscr"
    [119977]="Nscr"
    [119978]="Oscr"
    [119979]="Pscr"
    [119980]="Qscr"
    [119982]="Sscr"
    [119983]="Tscr"
    [119984]="Uscr"
    [119985]="Vscr"
    [119986]="Wscr"
    [119987]="Xscr"
    [119988]="Yscr"
    [119989]="Zscr"
    [119990]="ascr"
    [119991]="bscr"
    [119992]="cscr"
    [119993]="dscr"
    [119995]="fscr"
    [119997]="hscr"
    [119998]="iscr"
    [119999]="jscr"
    [120000]="kscr"
    [120001]="lscr"
    [120002]="mscr"
    [120003]="nscr"
    [120005]="pscr"
    [120006]="qscr"
    [120007]="rscr"
    [120008]="sscr"
    [120009]="tscr"
    [120010]="uscr"
    [120011]="vscr"
    [120012]="wscr"
    [120013]="xscr"
    [120014]="yscr"
    [120015]="zscr"
    [120068]="Afr"
    [120069]="Bfr"
    [120071]="Dfr"
    [120072]="Efr"
    [120073]="Ffr"
    [120074]="Gfr"
    [120077]="Jfr"
    [120078]="Kfr"
    [120079]="Lfr"
    [120080]="Mfr"
    [120081]="Nfr"
    [120082]="Ofr"
    [120083]="Pfr"
    [120084]="Qfr"
    [120086]="Sfr"
    [120087]="Tfr"
    [120088]="Ufr"
    [120089]="Vfr"
    [120090]="Wfr"
    [120091]="Xfr"
    [120092]="Yfr"
    [120094]="afr"
    [120095]="bfr"
    [120096]="cfr"
    [120097]="dfr"
    [120098]="efr"
    [120099]="ffr"
    [120100]="gfr"
    [120101]="hfr"
    [120102]="ifr"
    [120103]="jfr"
    [120104]="kfr"
    [120105]="lfr"
    [120106]="mfr"
    [120107]="nfr"
    [120108]="ofr"
    [120109]="pfr"
    [120110]="qfr"
    [120111]="rfr"
    [120112]="sfr"
    [120113]="tfr"
    [120114]="ufr"
    [120115]="vfr"
    [120116]="wfr"
    [120117]="xfr"
    [120118]="yfr"
    [120119]="zfr"
    [120120]="Aopf"
    [120121]="Bopf"
    [120123]="Dopf"
    [120124]="Eopf"
    [120125]="Fopf"
    [120126]="Gopf"
    [120128]="Iopf"
    [120129]="Jopf"
    [120130]="Kopf"
    [120131]="Lopf"
    [120132]="Mopf"
    [120134]="Oopf"
    [120138]="Sopf"
    [120139]="Topf"
    [120140]="Uopf"
    [120141]="Vopf"
    [120142]="Wopf"
    [120143]="Xopf"
    [120144]="Yopf"
    [120146]="aopf"
    [120147]="bopf"
    [120148]="copf"
    [120149]="dopf"
    [120150]="eopf"
    [120151]="fopf"
    [120152]="gopf"
    [120153]="hopf"
    [120154]="iopf"
    [120155]="jopf"
    [120156]="kopf"
    [120157]="lopf"
    [120158]="mopf"
    [120159]="nopf"
    [120160]="oopf"
    [120161]="popf"
    [120162]="qopf"
    [120163]="ropf"
    [120164]="sopf"
    [120165]="topf"
    [120166]="uopf"
    [120167]="vopf"
    [120168]="wopf"
    [120169]="xopf"
    [120170]="yopf"
    [120171]="zopf"
  )
}
# <<< END GENERATED ENTITY TABLES <<<

#--- hex ----------------------------------------------------------------------
# Convertors.ascii2hex(): Integer.toHexString(Character.codePointAt(i)), padded
# to an even number of digits, separator inserted between characters only.
_hv_hexval() {
  local h
  printf -v h '%x' "$1"
  if (( ${#h} % 2 != 0 )); then h="0$h"; fi
  printf '%s' "$h"
}

_enc_hex() {
  local sep=$1 k h
  for (( k=0; k<HV_NJV; k++ )); do
    if (( k > 0 )) && [ -n "$sep" ]; then _hv_put "$sep"; fi
    printf -v h '%x' "${JV[k]}"
    if (( ${#h} % 2 != 0 )); then h="0$h"; fi
    _hv_put "$h"
  done
}

_enc_sql_hex() { _hv_put '0x'; _enc_hex ''; }

#--- entity / escape formats (unbescape ports) --------------------------------
# LEVEL_4_ALL_CHARACTERS: every character is escaped.
_enc_dec_entities() {
  local k
  for (( k=0; k<HV_NCP; k++ )); do _hv_put "&#${CP[k]};"; done
}

_enc_hex_entities() {
  local k h
  for (( k=0; k<HV_NCP; k++ )); do
    printf -v h '%x' "${CP[k]}"
    _hv_put "&#x${h};"
  done
}

# JavaScriptEscape UHEXA: \uHHHH with UPPERCASE hex digits, surrogate pairs for
# supplementary characters (unbescape never emits \u{...})
_enc_unicode_escapes() {
  local k cp h
  for (( k=0; k<HV_NCP; k++ )); do
    cp=${CP[k]}
    if (( cp <= 0xFFFF )); then
      printf -v h '%04X' "$cp"
      _hv_bslash; _hv_put "u${h}"
    else
      local v=$(( cp - 0x10000 ))
      printf -v h '%04X' "$(( 0xD800 + (v >> 10) ))"
      _hv_bslash; _hv_put "u${h}"
      printf -v h '%04X' "$(( 0xDC00 + (v & 0x3FF) ))"
      _hv_bslash; _hv_put "u${h}"
    fi
  done
}

# JavaScriptEscape XHEXA_DEFAULT_TO_UHEXA: \xHH (uppercase) up to 0xFF, \uHHHH above
_enc_hex_escapes() {
  local k cp h
  for (( k=0; k<HV_NCP; k++ )); do
    cp=${CP[k]}
    if (( cp <= 0xFF )); then
      printf -v h '%02X' "$cp"
      _hv_bslash; _hv_put "x${h}"
    elif (( cp <= 0xFFFF )); then
      printf -v h '%04X' "$cp"
      _hv_bslash; _hv_put "u${h}"
    else
      local v=$(( cp - 0x10000 ))
      printf -v h '%04X' "$(( 0xD800 + (v >> 10) ))"
      _hv_bslash; _hv_put "u${h}"
      printf -v h '%04X' "$(( 0xDC00 + (v & 0x3FF) ))"
      _hv_bslash; _hv_put "u${h}"
    fi
  done
}

# Convertors.octal_escapes(): "\" + Integer.toOctalString(codePointAt(i))
_enc_octal_escapes() {
  local k o
  for (( k=0; k<HV_NJV; k++ )); do
    printf -v o '%o' "${JV[k]}"
    _hv_bslash; _hv_put "$o"
  done
}

# CssStringEscapeUtil: characters in this set are emitted as a two character
# backslash escape (\< , \& , \" ...) instead of a hex escape.  ':' (0x3A) is
# deliberately not part of the set.
_hv_css_backslash_set() {
  local c=$1
  (( (c >= 0x20 && c <= 0x2F) || (c >= 0x3B && c <= 0x40) \
     || (c >= 0x5B && c <= 0x60) || (c >= 0x7B && c <= 0x7E) ))
}

# CssEscape BACKSLASH_ESCAPES_DEFAULT_TO_COMPACT_HEXA (LEVEL_4: never a trailing
# space, because every hex digit and space is escaped as well)
_enc_css_escapes() {
  local k cp h
  for (( k=0; k<HV_NCP; k++ )); do
    cp=${CP[k]}
    if (( cp < 0x7F )) && _hv_css_backslash_set "$cp"; then
      _hv_bslash; _hv_putb "$cp"
    else
      printf -v h '%X' "$cp"
      _hv_bslash; _hv_put "$h"
    fi
  done
}

# CssEscape BACKSLASH_ESCAPES_DEFAULT_TO_SIX_DIGIT_HEXA
_enc_css_escapes6() {
  local k cp h
  for (( k=0; k<HV_NCP; k++ )); do
    cp=${CP[k]}
    if (( cp < 0x7F )) && _hv_css_backslash_set "$cp"; then
      _hv_bslash; _hv_putb "$cp"
    else
      printf -v h '%06X' "$cp"
      _hv_bslash; _hv_put "$h"
    fi
  done
}

#--- PHP / SQL ---------------------------------------------------------------
_enc_php_chr() {
  local k out=''
  for (( k=0; k<HV_NJV; k++ )); do
    if (( k > 0 )); then out+='.'; fi
    out+="chr(${JV[k]})"
  done
  _hv_put "$out"
}

# Literal port of Convertors.php_non_alpha(): fixed decoder prologue, then the
# payload split into octal digits addressed through $_[n] style variables.
_enc_php_non_alpha() {
  local out=''
  out+='$_[]++;$_[]=$_._;'
  out+='$_____=$_[(++$__[])][(++$__[])+(++$__[])+(++$__[])];'
  out+='$_=$_[$_[+_]];'
  out+='$___=$__=$_[++$__[]];'
  out+='$____=$_=$_[+_];'
  out+='$_++;$_++;$_++;'
  out+='$_=$____.++$___.$___.++$_.$__.++$___;'
  out+='$__=$_;'
  out+='$_=$_____;'
  out+='$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;'
  out+='$___=+_;'
  out+='$___.=$__;'
  out+='$___=++$_^$___[+_];$À=+_;$Á=$Â=$Ã=$Ä=$Æ=$È=$É=$Ê=$Ë=++$Á[];'
  out+='$Â++;'
  out+='$Ã++;$Ã++;'
  out+='$Ä++;$Ä++;$Ä++;'
  out+='$Æ++;$Æ++;$Æ++;$Æ++;'
  out+='$È++;$È++;$È++;$È++;$È++;'
  out+='$É++;$É++;$É++;$É++;$É++;$É++;'
  out+='$Ê++;$Ê++;$Ê++;$Ê++;$Ê++;$Ê++;$Ê++;'
  out+='$Ë++;$Ë++;$Ë++;$Ë++;$Ë++;$Ë++;$Ë++;'
  out+=$'$__(\'$_="\''
  local lookup=('À' 'Á' 'Â' 'Ã' 'Ä' 'Æ' 'È' 'É' 'Ê' 'Ë')
  local k o j d vars
  for (( k=0; k<HV_NJV; k++ )); do
    printf -v o '%o' "${JV[k]}"
    vars=''
    for (( j=0; j<${#o}; j++ )); do
      d=${o:j:1}
      if [ -n "$vars" ]; then vars+='.'; fi
      vars+='$'"${lookup[d]}"
    done
    out+='.$___.'"$vars"
  done
  out+=".'"
  out+=$'"\');$__($_);'
  _hv_put "<?php ${out}?>"
}

#--- URL encoding ------------------------------------------------------------
# Java URLEncoder.encode(str, UTF_8) (verified against JDK 17): alphanumerics
# plus ".-*_" are literal, space becomes "+", everything else is %XX (uppercase)
# of the UTF-8 bytes.
#
# Burp's IExtensionHelpers.urlEncode() encodes the "key characters" of a URL
# instead: alphanumerics plus "-_.~/" stay literal and the characters that are
# structural or unsafe in a URL ("#", "&", "%", "?", "=", "+", ...) are percent
# encoded.  Burp publishes no character list, so this rule is best effort based
# on the Burp Encoder behaviour documented in README.md.
_hv_urlencode_core() { # $1 input string, $2 java|burp
  local s=$1 mode=$2 i c b out='' lit
  local -a bytes=()
  _hv_to_bytes "$s"
  bytes=("${HV_BYTES[@]}")
  local n=$HV_NBYTES
  i=0
  while [ "$i" -lt "$n" ]; do
    b=${bytes[i]}
    lit=0
    if (( (b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122) \
          || b == 46 || b == 45 || b == 95 )); then
      lit=1
    elif [ "$mode" = 'java' ]; then
      (( b == 42 )) && lit=1
    elif [ "$mode" = 'burp' ]; then
      (( b == 126 || b == 47 )) && lit=1
    fi
    if [ "$lit" = 1 ]; then
      out+="${s:i:1}"        # the byte itself, straight from the input
    elif (( b == 32 )); then
      out+='+'
    else
      printf -v c '%02X' "$b"
      out+="%${c}"
    fi
    i=$(( i + 1 ))
  done
  HV_URLENC=$out
}

_enc_urlencode() { _hv_urlencode_core "$(_hv_input_string)" java; _hv_put "$HV_URLENC"; }
_enc_urlencode_not_plus() {
  _hv_urlencode_core "$(_hv_input_string)" java
  _hv_put "${HV_URLENC//+/%20}"
}
_enc_burp_urlencode() { _hv_urlencode_core "$(_hv_input_string)" burp; _hv_put "$HV_URLENC"; }

# Convertors.urlencode_all(): %XX for every codepoint <= 0x7F, UTF-8 %XX above.
_enc_urlencode_all() {
  local k cp h j out='' ub
  for (( k=0; k<HV_NCP; k++ )); do
    cp=${CP[k]}
    if (( cp <= 0x7F )); then
      printf -v h '%02X' "$cp"
      out+="%${h}"
    else
      _hv_cp_utf8_into "$cp"
      for j in "${_HV_UB[@]}"; do
        printf -v h '%02X' "$j"
        out+="%${h}"
      done
    fi
  done
  _hv_put "$out"
}

# the UTF-8 bytes of a codepoint, as an array (no subshell)
_HV_UB=()
_hv_cp_utf8_into() {
  local cp=$1
  if (( cp < 0x80 )); then
    _HV_UB=("$cp")
  elif (( cp < 0x800 )); then
    _HV_UB=("$(( 0xC0 | (cp >> 6) ))" "$(( 0x80 | (cp & 0x3F) ))")
  elif (( cp < 0x10000 )); then
    _HV_UB=("$(( 0xE0 | (cp >> 12) ))" "$(( 0x80 | ((cp >> 6) & 0x3F) ))" \
            "$(( 0x80 | (cp & 0x3F) ))")
  else
    _HV_UB=("$(( 0xF0 | (cp >> 18) ))" "$(( 0x80 | ((cp >> 12) & 0x3F) ))" \
            "$(( 0x80 | ((cp >> 6) & 0x3F) ))" "$(( 0x80 | (cp & 0x3F) ))")
  fi
}

# print the UTF-8 bytes of a codepoint as a space separated list
_hv_cp_utf8_bytes() {
  local cp=$1
  if (( cp < 0x80 )); then
    printf '%s' "$cp"
  elif (( cp < 0x800 )); then
    printf '%s %s' "$(( 0xC0 | (cp >> 6) ))" "$(( 0x80 | (cp & 0x3F) ))"
  elif (( cp < 0x10000 )); then
    printf '%s %s %s' "$(( 0xE0 | (cp >> 12) ))" "$(( 0x80 | ((cp >> 6) & 0x3F) ))" \
      "$(( 0x80 | (cp & 0x3F) ))"
  else
    printf '%s %s %s %s' "$(( 0xF0 | (cp >> 18) ))" "$(( 0x80 | ((cp >> 12) & 0x3F) ))" \
      "$(( 0x80 | ((cp >> 6) & 0x3F) ))" "$(( 0x80 | (cp & 0x3F) ))"
  fi
}

#--- quoted printable --------------------------------------------------------
# commons-codec 1.15 QuotedPrintableCodec (verified by executing the 1.15 jar):
# the default charset is UTF-8, TAB and SPACE stay literal, printable ASCII
# 33..126 except '=' stays literal, everything else becomes =XX (uppercase), and
# there is never any line wrapping because strict mode is off.
_enc_quoted_printable() {
  local i b h
  for (( i=0; i<HV_NBYTES; i++ )); do
    b=${HV_BYTES[i]}
    if (( b == 9 || b == 32 || (b >= 33 && b <= 60) || (b >= 62 && b <= 126) )); then
      _hv_putb "$b"
    else
      printf -v h '%02X' "$b"
      _hv_put "=${h}"
    fi
  done
}

#--- JWT ---------------------------------------------------------------------
# Convertors.jwt(payload, algo, secret)
_enc_jwt() {
  local algo=$1 secret=$2 payload
  algo=${algo^^}
  case $algo in
    HS256|HS384|HS512) ;;
    NONE) ;;
    *) _hv_put 'Unsupported algorithm'; return 0 ;;
  esac

  payload=$(_hv_input_string)
  payload=$(_hv_json_compact "$payload")
  if [ -z "$payload" ] || [ "${payload:0:1}" != '{' ] || [ "${payload: -1}" != '}' ]; then
    _hv_put 'Unable to create token'; return 0
  fi

  local header="{\"alg\":\"${algo}\",\"typ\":\"JWT\"}"
  local h64 p64
  _hv_b64url_of_string "$header"; h64=$HV_B64OUT
  _hv_b64url_of_string "$payload"; p64=$HV_B64OUT
  local message="${h64}.${p64}"

  if [ "$algo" = 'NONE' ]; then
    _hv_put "${message}."
    return 0
  fi

  local sig
  if _hv_jwt_sign "$algo" "$secret" "$message"; then
    sig=$HV_JWTSIG
  else
    _hv_put 'Unable to create token'; return 0
  fi
  _hv_put "${message}.${sig}"
}

_hv_b64url_of_string() {
  local -a b=()
  local t
  t=$(printf '%s' "$1" | od -An -tu1 -v | tr -s ' \n' ' ')
  if [ -n "$t" ]; then read -r -a b <<< "$t"; fi
  _hv_b64_of_bytes "${b[*]}" 1
}

# sets HV_JWTSIG (base64url of the raw HMAC) - returns 1 when unsupported
_hv_jwt_sign() {
  local algo=$1 secret=$2 message=$3 hex
  case $algo in
    HS256)
      if _hv_hmac_sha256_hex "$secret" "$message"; then hex=$HV_HASHHEX
      elif _hv_have openssl; then hex=$(_hv_openssl_hmac sha256 "$secret" "$message") || return 1
      else return 1; fi
      ;;
    HS384|HS512)
      _hv_have openssl || return 1
      local which=sha384
      [ "$algo" = 'HS512' ] && which=sha512
      hex=$(_hv_openssl_hmac "$which" "$secret" "$message") || return 1
      ;;
    *) return 1 ;;
  esac
  [ -n "$hex" ] || return 1
  local raw='' i
  for (( i=0; i<${#hex}; i+=2 )); do raw+="$(( 16#${hex:i:2} )) "; done
  _hv_b64_of_bytes "$raw" 1
  HV_JWTSIG=$HV_B64OUT
  return 0
}

_hv_openssl_hmac() {
  local which=$1 secret=$2 message=$3 keyarg out
  if [ -z "$secret" ]; then
    # Hackvertor substitutes a single NUL byte for an empty secret
    out=$(printf '%s' "$message" | openssl dgst "-$which" -mac HMAC -macopt hexkey:00 2>/dev/null) || return 1
  else
    out=$(printf '%s' "$message" | openssl dgst "-$which" -hmac "$secret" 2>/dev/null) || return 1
  fi
  # "SHA2-256(stdin)= <hex>" (OpenSSL) or "<hex> *stdin" (-r)
  out=${out##* }
  case $out in *[!0-9a-fA-F]*|'') return 1 ;; esac
  printf '%s' "$out"
}

# collapse insignificant whitespace outside string literals (org.json
# re-serialises the payload, which keeps the original member order)
_hv_json_compact() {
  local s=$1 out='' i c n instr=0 esc=0
  n=${#s}
  for (( i=0; i<n; i++ )); do
    c=${s:i:1}
    if [ "$instr" = 1 ]; then
      out+="$c"
      if [ "$esc" = 1 ]; then esc=0
      elif [ "$c" = '\' ]; then esc=1
      elif [ "$c" = '"' ]; then instr=0
      fi
    else
      case $c in
        ' '|$'\t'|$'\n'|$'\r') ;;
        '"') instr=1; out+="$c" ;;
        *) out+="$c" ;;
      esac
    fi
  done
  printf '%s' "$out"
}

#===============================================================================
# section 5 - hashing (pure bash SHA-256, openssl for 384/512)
#===============================================================================

_HV_K256=(
  0x428a2f98 0x71374491 0xb5c0fbcf 0xe9b5dba5 0x3956c25b 0x59f111f1 0x923f82a4 0xab1c5ed5
  0xd807aa98 0x12835b01 0x243185be 0x550c7dc3 0x72be5d74 0x80deb1fe 0x9bdc06a7 0xc19bf174
  0xe49b69c1 0xefbe4786 0x0fc19dc6 0x240ca1cc 0x2de92c6f 0x4a7484aa 0x5cb0a9dc 0x76f988da
  0x983e5152 0xa831c66d 0xb00327c8 0xbf597fc7 0xc6e00bf3 0xd5a79147 0x06ca6351 0x14292967
  0x27b70a85 0x2e1b2138 0x4d2c6dfc 0x53380d13 0x650a7354 0x766a0abb 0x81c2c92e 0x92722c85
  0xa2bfe8a1 0xa81a664b 0xc24b8b70 0xc76c51a3 0xd192e819 0xd6990624 0xf40e3585 0x106aa070
  0x19a4c116 0x1e376c08 0x2748774c 0x34b0bcb5 0x391c0cb3 0x4ed8aa4a 0x5b9cca4f 0x682e6ff3
  0x748f82ee 0x78a5636f 0x84c87814 0x8cc70208 0x90befffa 0xa4506ceb 0xbef9a3f7 0xc67178f2
)

# rotations are inlined in the round body on purpose: a helper call would fork a
# subshell per operation and make hashing unusably slow.
_hv_rotr32() { printf '%s' "$(( (( $1 >> $2 ) | ( $1 << (32 - $2) )) & 0xFFFFFFFF ))"; }

# $1 = space separated byte values; sets HV_HASHHEX
_hv_sha256_of_bytes() {
  local -a m=()
  local s=$1 i n h0 h1 h2 h3 h4 h5 h6 h7 a b c d e f g h
  local s0 s1 ch maj t1 t2 x y

  if [ -n "$s" ]; then read -r -a m <<< "$s"; fi
  n=${#m[@]}

  m+=("128")
  while (( (${#m[@]} + 8) % 64 != 0 )); do m+=(0); done
  local bitlen=$(( n * 8 ))
  for (( i=7; i>=0; i-- )); do m+=( $(( (bitlen >> (i * 8)) & 255 )) ); done

  h0=0x6a09e667; h1=0xbb67ae85; h2=0x3c6ef372; h3=0xa54ff53a
  h4=0x510e527f; h5=0x9b05688c; h6=0x1f83d9ab; h7=0x5be0cd19

  local chunks=$(( ${#m[@]} / 64 )) chunk idx base
  for (( chunk=0; chunk<chunks; chunk++ )); do
    base=$(( chunk * 64 ))
    for (( i=0; i<64; i++ )); do
      if (( i < 16 )); then
        idx=$(( base + i * 4 ))
        _HV_W[i]=$(( ((m[idx] << 24) | (m[idx+1] << 16) | (m[idx+2] << 8) | m[idx+3]) & 0xFFFFFFFF ))
      else
        x=${_HV_W[i-15]}
        s0=$(( ( ((x >> 7) | (x << 25)) ^ ((x >> 18) | (x << 14)) ^ (x >> 3) ) & 0xFFFFFFFF ))
        y=${_HV_W[i-2]}
        s1=$(( ( ((y >> 17) | (y << 15)) ^ ((y >> 19) | (y << 13)) ^ (y >> 10) ) & 0xFFFFFFFF ))
        _HV_W[i]=$(( (${_HV_W[i-16]} + s0 + ${_HV_W[i-7]} + s1) & 0xFFFFFFFF ))
      fi
    done
    a=$h0; b=$h1; c=$h2; d=$h3; e=$h4; f=$h5; g=$h6; h=$h7
    for (( i=0; i<64; i++ )); do
      s1=$(( ( ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7)) ) & 0xFFFFFFFF ))
      ch=$(( (e & f) ^ ((~e & 0xFFFFFFFF) & g) ))
      t1=$(( (h + s1 + ch + ${_HV_K256[i]} + ${_HV_W[i]}) & 0xFFFFFFFF ))
      s0=$(( ( ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10)) ) & 0xFFFFFFFF ))
      maj=$(( (a & b) ^ (a & c) ^ (b & c) ))
      t2=$(( (s0 + maj) & 0xFFFFFFFF ))
      h=$g; g=$f; f=$e
      e=$(( (d + t1) & 0xFFFFFFFF ))
      d=$c; c=$b; b=$a
      a=$(( (t1 + t2) & 0xFFFFFFFF ))
    done
    h0=$(( (h0 + a) & 0xFFFFFFFF )); h1=$(( (h1 + b) & 0xFFFFFFFF ))
    h2=$(( (h2 + c) & 0xFFFFFFFF )); h3=$(( (h3 + d) & 0xFFFFFFFF ))
    h4=$(( (h4 + e) & 0xFFFFFFFF )); h5=$(( (h5 + f) & 0xFFFFFFFF ))
    h6=$(( (h6 + g) & 0xFFFFFFFF )); h7=$(( (h7 + h) & 0xFFFFFFFF ))
  done
  printf -v HV_HASHHEX '%08x%08x%08x%08x%08x%08x%08x%08x' \
    "$h0" "$h1" "$h2" "$h3" "$h4" "$h5" "$h6" "$h7"
}
_HV_W=()

# $1 = key, $2 = message; sets HV_HASHHEX
_hv_hmac_sha256_hex() {
  local key=$1 msg=$2
  local -a kb=() ib=() ob=() mb=()
  local t i
  t=$(printf '%s' "$key" | od -An -tu1 -v | tr -s ' \n' ' ')
  if [ -n "$t" ]; then read -r -a kb <<< "$t"; fi
  if [ "${#kb[@]}" -eq 0 ]; then kb=(0); fi   # Hackvertor: one NUL byte
  if [ "${#kb[@]}" -gt 64 ]; then
    _hv_sha256_of_bytes "${kb[*]}"
    local hex=$HV_HASHHEX
    kb=()
    for (( i=0; i<${#hex}; i+=2 )); do kb+=( $(( 16#${hex:i:2} )) ); done
  fi
  for (( i=0; i<64; i++ )); do
    if (( i < ${#kb[@]} )); then
      ib+=($(( kb[i] ^ 0x36 ))); ob+=($(( kb[i] ^ 0x5C )))
    else
      ib+=($(( 0x36 ))); ob+=($(( 0x5C )))
    fi
  done
  t=$(printf '%s' "$msg" | od -An -tu1 -v | tr -s ' \n' ' ')
  if [ -n "$t" ]; then read -r -a mb <<< "$t"; fi
  _hv_sha256_of_bytes "$(printf '%s ' "${ib[@]}"; printf '%s' "${mb[*]:-}")"
  local inner=$HV_HASHHEX
  local -a innerb=()
  for (( i=0; i<${#inner}; i+=2 )); do innerb+=( $(( 16#${inner:i:2} )) ); done
  _hv_sha256_of_bytes "$(printf '%s ' "${ob[@]}"; printf '%s' "${innerb[*]}")"
}

#===============================================================================
# section 6 - decoders (d_* tags)
#===============================================================================

declare -A _HV_B64REV=() _HV_B32REV=()
_HV_REV_READY=0
_hv_rev_init() {
  [ "$_HV_REV_READY" = 1 ] && return 0
  local i
  for (( i=0; i<64; i++ )); do _HV_B64REV["${_HV_B64TBL[i]}"]=$i; done
  _HV_B64REV['-']=62; _HV_B64REV['_']=63
  for (( i=0; i<32; i++ )); do _HV_B32REV["${_HV_B32TBL[i]}"]=$i; done
  _HV_REV_READY=1
}

_dec_base64() {
  local s=$1 c v i acc=0 bits=0
  _hv_rev_init
  s=${s//[$' \t\r\n']/}
  for (( i=0; i<${#s}; i++ )); do
    c=${s:i:1}
    [ "$c" = '=' ] && continue
    v=${_HV_B64REV[$c]:-}
    [ -z "$v" ] && continue
    acc=$(( (acc << 6) | v )); bits=$(( bits + 6 ))
    if (( bits >= 8 )); then
      bits=$(( bits - 8 ))
      _hv_putb $(( (acc >> bits) & 0xFF ))
    fi
  done
}

_dec_base32() {
  local s=$1 c v i acc=0 bits=0
  _hv_rev_init
  s=${s//[$' \t\r\n']/}
  s=${s^^}
  for (( i=0; i<${#s}; i++ )); do
    c=${s:i:1}
    [ "$c" = '=' ] && continue
    v=${_HV_B32REV[$c]:-}
    [ -z "$v" ] && continue
    acc=$(( (acc << 5) | v )); bits=$(( bits + 5 ))
    if (( bits >= 8 )); then
      bits=$(( bits - 8 ))
      _hv_putb $(( (acc >> bits) & 0xFF ))
    fi
  done
}

_hv_hexdecode() {
  local s=$1 i hi lo
  s=${s//[$' \t\r\n']/}
  for (( i=0; i+1<${#s}; i+=2 )); do
    hi=${s:i:1}; lo=${s:i+1:1}
    case $hi in [0-9a-fA-F]) ;; *) continue ;; esac
    case $lo in [0-9a-fA-F]) ;; *) continue ;; esac
    _hv_putb $(( 16#$hi$lo ))
  done
}

_dec_hex() {
  local s=$1
  s=${s#0x}; s=${s#0X}
  s=${s//[ ,\-]/}
  _hv_hexdecode "$s"
}

_dec_url() { # $1 text, $2 strict: 1 = return the input unchanged if malformed
  local s=$1 strict=${2:-0} i=0 n c h
  n=${#s}
  if [ "$strict" = 1 ]; then
    # Convertors.decode_url() catches the URLDecoder exception and returns the
    # input unchanged, so a malformed '%' escape means "no decoding at all"
    local j
    for (( j=0; j<n; j++ )); do
      if [ "${s:j:1}" = '%' ]; then
        case ${s:j+1:2} in
          [0-9a-fA-F][0-9a-fA-F]) ;;
          *) printf '%s' "$s"; return 0 ;;
        esac
      fi
    done
  fi
  while [ "$i" -lt "$n" ]; do
    c=${s:i:1}
    if [ "$c" = '%' ] && (( i + 2 < n )); then
      h=${s:i+1:2}
      case $h in
        [0-9a-fA-F][0-9a-fA-F]) _hv_putb $(( 16#$h )); i=$(( i + 3 )); continue ;;
      esac
    fi
    if [ "$c" = '+' ]; then _hv_putb 32; else _hv_put_char "$c"; fi
    i=$(( i + 1 ))
  done
}

# convertors.html_entities / html5: named + numeric references
_hv_entity_decode_tables() {
  declare -gA _HV_NAME2CP=()
  local k
  _hv_gen_load_html4
  for k in "${!HV_HTML4_NAMES[@]}"; do _HV_NAME2CP["${HV_HTML4_NAMES[$k]}"]=$k; done
  _hv_gen_load_html5
  for k in "${!HV_HTML5_NAMES[@]}"; do _HV_NAME2CP["${HV_HTML5_NAMES[$k]}"]=$k; done
}
_HV_NAMES_READY=0
_dec_entities() {
  local s=$1 i n c h cp ent rest
  if [ "$_HV_NAMES_READY" = 0 ]; then _hv_entity_decode_tables; _HV_NAMES_READY=1; fi
  n=${#s}
  i=0
  while [ "$i" -lt "$n" ]; do
    c=${s:i:1}
    if [ "$c" != '&' ]; then
      _hv_put_char "$c"
      i=$(( i + 1 )); continue
    fi
    rest=${s:i+1}
    ent=${rest%%;*}
    if [ "$ent" = "$rest" ]; then         # no terminating ';'
      _hv_put '&'
      i=$(( i + 1 )); continue
    fi
    case $ent in
      '#x'*|'#X'*)
        cp=$(( 16#${ent:2} )) 2>/dev/null || cp=-1
        ;;
      '#'*)
        cp=${ent:1}
        case $cp in *[!0-9]*|'') cp=-1 ;; esac
        ;;
      *)
        if [ -n "${_HV_NAME2CP[$ent]:-}" ]; then cp=${_HV_NAME2CP[$ent]}
        elif [ "$ent" = 'apos' ]; then cp=39
        else cp=-1; fi
        ;;
    esac
    if [ "$cp" -ge 0 ] 2>/dev/null; then
      _hv_emit_cp_utf8 "$cp"
      i=$(( i + ${#ent} + 2 ))
    else
      _hv_put '&'
      i=$(( i + 1 ))
    fi
  done
}

_dec_quoted_printable() {
  local s=$1 i c h
  s=${s//$'=\r\n'/}
  s=${s//$'=\n'/}
  i=0
  while [ "$i" -lt "${#s}" ]; do
    c=${s:i:1}
    if [ "$c" = '=' ] && (( i + 2 < ${#s} )); then
      h=${s:i+1:2}
      case $h in
        [0-9a-fA-F][0-9a-fA-F]) _hv_putb $(( 16#$h )); i=$(( i + 3 )); continue ;;
      esac
    fi
    _hv_put_char "$c"
    i=$(( i + 1 ))
  done
}

# \uXXXX / \xHH / \NNN / \HHHHHH escapes
_hv_decode_escapes() { # $1 text, $2 mode: js | css | octal
  local s=$1 mode=$2 i c cp hex n
  n=${#s}
  i=0
  while [ "$i" -lt "$n" ]; do
    c=${s:i:1}
    if [ "$c" != '\' ]; then
      _hv_put_char "$c"
      i=$(( i + 1 )); continue
    fi
    local nxt=${s:i+1:1}
    if [ "$nxt" = '\' ]; then
      _hv_putb 92; i=$(( i + 2 )); continue
    fi
    if [ "$nxt" = 'x' ]; then
      hex=${s:i+2:2}
      case $hex in
        [0-9a-fA-F][0-9a-fA-F]) _hv_emit_cp_utf8 $(( 16#$hex )); i=$(( i + 4 )); continue ;;
      esac
    fi
    if [ "$nxt" = 'u' ]; then
      local brace=0
      if [ "${s:i+2:1}" = '{' ]; then brace=1; fi
      local j=$(( i + 2 + brace )) acc=0 cnt=0 ch
      while [ "$j" -lt "$n" ]; do
        ch=${s:j:1}
        if [ "$brace" = 1 ] && [ "$ch" = '}' ]; then break; fi
        case $ch in
          [0-9a-fA-F]) ;;
          *) break ;;
        esac
        if [ "$brace" = 0 ] && [ "$cnt" -ge 4 ]; then break; fi
        acc=$(( (acc << 4) | 16#$ch )); cnt=$(( cnt + 1 )); j=$(( j + 1 ))
      done
      if [ "$cnt" -gt 0 ]; then
        _hv_emit_cp_utf8 "$acc"
        i=$(( j + brace ))
        continue
      fi
    fi
    # numeric escape: octal (\NNN) or hexadecimal (CSS, 1..6 digits)
    local j=$(( i + 1 )) acc=0 cnt=0 ch max
    if [ "$mode" = 'css' ]; then max=6; else max=3; fi
    while [ "$j" -lt "$n" ] && [ "$cnt" -lt "$max" ]; do
      ch=${s:j:1}
      if [ "$mode" = 'css' ]; then
        case $ch in [0-9a-fA-F]) ;; *) break ;; esac
        acc=$(( (acc << 4) | 16#$ch ))
      else
        case $ch in [0-7]) ;; *) break ;; esac
        acc=$(( (acc << 3) | ch ))
      fi
      cnt=$(( cnt + 1 )); j=$(( j + 1 ))
    done
    if [ "$cnt" -gt 0 ]; then
      _hv_emit_cp_utf8 "$acc"
      i=$j
      continue
    fi
    _hv_putb 92
    i=$(( i + 1 ))
  done
}

_dec_unicode_escapes() { _hv_decode_escapes "$1" js; }
_dec_css_escapes()     { _hv_decode_escapes "$1" css; }
_dec_octal_escapes()   { _hv_decode_escapes "$1" octal; }

_dec_php_chr() {
  local s=$1 i
  while [[ $s =~ chr\(([0-9]+)\) ]]; do
    _hv_emit_cp_utf8 "${BASH_REMATCH[1]}"
    s=${s#*"${BASH_REMATCH[0]}"}
  done
  for (( i=0; i<${#s}; i++ )); do
    case ${s:i:1} in
      '.') ;;
      *) _hv_put_char "${s:i:1}" ;;
    esac
  done
}

_dec_jwt_part() { # $1 token, $2 0=header 1=payload
  local token=$1 idx=$2 rest part
  case $token in *.*.*) ;; *) _hv_put 'Invalid token'; return 0 ;; esac
  rest=${token#*.}
  if [ "$idx" = 0 ]; then part=${token%%.*}; else part=${rest%%.*}; fi
  _dec_base64 "$part"
}

#===============================================================================
# section 7 - tag registry, dispatch and CLI
#===============================================================================

_hv_alias() {
  case $1 in
    url_encode) echo urlencode ;;
    url_encode_all) echo urlencode_all ;;
    url_encode_not_plus) echo urlencode_not_plus ;;
    url_encode_burp|burp_url_encode) echo burp_urlencode ;;
    base64_url) echo base64url ;;
    base32url|base32_url) echo base32 ;;
    hex_escape) echo hex_escapes ;;
    *) echo "$1" ;;
  esac
}

_hv_tool_exists() {
  case $1 in
    base32|base64|base64url|html_entities|html5_entities|hex|hex_entities|hex_escapes \
    |octal_escapes|dec_entities|unicode_escapes|css_escapes|css_escapes6|burp_urlencode \
    |urlencode|urlencode_not_plus|urlencode_all|php_non_alpha|php_chr|sql_hex|jwt \
    |quoted_printable \
    |d_base32|d_base64|d_base64url|d_hex|d_html_entities|d_html5_entities|d_url|d_burp_url \
    |d_quoted_printable|d_unicode_escapes|d_css_escapes|d_octal_escapes|d_php_chr|d_sql_hex \
    |d_jwt_get_payload|d_jwt_get_header) return 0 ;;
    *) return 1 ;;
  esac
}

# run one tool; reads HV_CURRENT, writes HV_RESULT
_hv_dispatch() {
  local name=$1
  local a0 a1
  a0=${HV_TAGARGS[0]-}
  a1=${HV_TAGARGS[1]-}

  _hv_load_input "$HV_CURRENT"
  _hv_reset_buf

  case $name in
    base32)              _enc_base32 ;;
    base64)              _enc_base64 ;;
    base64url)           _enc_base64url ;;
    html_entities)       _enc_html_entities ;;
    html5_entities)      _enc_html5_entities ;;
    hex)
      if [ "$HV_ARGS_GIVEN" = 1 ]; then
        _enc_hex "$a0"
      elif [ "$HV_UI_DEFAULTS" = 1 ]; then
        _enc_hex ' '              # the Hackvertor UI inserts a space separator
      else
        _enc_hex ''               # a bare <@hex> tag has no separator
      fi
      ;;
    hex_entities)        _enc_hex_entities ;;
    hex_escapes)         _enc_hex_escapes ;;
    octal_escapes)       _enc_octal_escapes ;;
    dec_entities)        _enc_dec_entities ;;
    unicode_escapes)     _enc_unicode_escapes ;;
    css_escapes)         _enc_css_escapes ;;
    css_escapes6)        _enc_css_escapes6 ;;
    burp_urlencode)      _enc_burp_urlencode ;;
    urlencode)           _enc_urlencode ;;
    urlencode_not_plus)  _enc_urlencode_not_plus ;;
    urlencode_all)       _enc_urlencode_all ;;
    php_non_alpha)       _enc_php_non_alpha ;;
    php_chr)             _enc_php_chr ;;
    sql_hex)             _enc_sql_hex ;;
    quoted_printable)    _enc_quoted_printable ;;
    jwt)
      [ -z "$a0" ] && a0=${HV_ALG:-HS256}
      if [ "$HV_ARGS_GIVEN" = 1 ] && [ "${#HV_TAGARGS[@]}" -ge 2 ]; then
        a1=${HV_TAGARGS[1]}
      else
        a1=${HV_SECRET:-secret}
      fi
      if [ -n "$HV_ALG" ] && [ "${#HV_TAGARGS[@]}" -lt 1 ]; then a0=$HV_ALG; fi
      if [ -n "$HV_SECRET" ] && [ "${#HV_TAGARGS[@]}" -lt 2 ]; then a1=$HV_SECRET; fi
      _enc_jwt "$a0" "$a1" ;;
    d_base32)            _dec_base32 "$HV_CURRENT" ;;
    d_base64)            _dec_base64 "$HV_CURRENT" ;;
    d_base64url)         _dec_base64 "$HV_CURRENT" ;;
    d_hex)               _dec_hex "$HV_CURRENT" ;;
    d_sql_hex)           { local s=$HV_CURRENT; s=${s#0x}; s=${s#0X}; _hv_hexdecode "$s"; } ;;
    d_html_entities)     _dec_entities "$HV_CURRENT" ;;
    d_html5_entities)    _dec_entities "$HV_CURRENT" ;;
    d_url)               _dec_url "$HV_CURRENT" 1 ;;
    d_burp_url)          _dec_url "$HV_CURRENT" 0 ;;
    d_quoted_printable)  _dec_quoted_printable "$HV_CURRENT" ;;
    d_unicode_escapes)   _dec_unicode_escapes "$HV_CURRENT" ;;
    d_css_escapes)       _dec_css_escapes "$HV_CURRENT" ;;
    d_octal_escapes)     _dec_octal_escapes "$HV_CURRENT" ;;
    d_php_chr)           _dec_php_chr "$HV_CURRENT" ;;
    d_jwt_get_header)    _dec_jwt_part "$HV_CURRENT" 0 ;;
    d_jwt_get_payload)   _dec_jwt_part "$HV_CURRENT" 1 ;;
    *) _hv_die "internal error: unknown tool '$name'" ;;
  esac

  if [ "$_HV_PLAIN" = 1 ]; then HV_RESULT=$_HV_BUF; else HV_RESULT=$(_hv_result); fi
}

# split a Hackvertor style argument list: -hex(' ')  -jwt('HS256','secret')
HV_TAGARGS=()
HV_ARGS_GIVEN=0
_hv_unescape_arg() {
  local s=$1 out='' i c d
  for (( i=0; i<${#s}; i++ )); do
    c=${s:i:1}
    if [ "$c" = '\' ] && (( i + 1 < ${#s} )); then
      d=${s:i+1:1}
      case $d in
        n) out+=$'\n' ;;
        t) out+=$'\t' ;;
        r) out+=$'\r' ;;
        *) out+="$d" ;;
      esac
      i=$(( i + 1 ))
    else
      out+="$c"
    fi
  done
  printf '%s' "$out"
}

_hv_split_args() { # $1 arg spec, $2 1 = the spec was written out, even if empty
  HV_TAGARGS=()
  local s=$1 explicit=${2:-0} i c cur='' q='' n
  n=${#s}
  if [ -z "$s" ]; then
    # "-hex=" and "<@hex()>" pass one empty argument, "-hex" and "<@hex>" none
    if [ "$explicit" = 1 ]; then HV_TAGARGS=(''); HV_ARGS_GIVEN=1; else HV_ARGS_GIVEN=0; fi
    return 0
  fi
  HV_ARGS_GIVEN=1
  for (( i=0; i<n; i++ )); do
    c=${s:i:1}
    if [ -n "$q" ]; then
      if [ "$c" = "$q" ]; then q=''
      elif [ "$c" = '\' ] && (( i + 1 < n )); then cur+="$c${s:i+1:1}"; i=$(( i + 1 ))
      else cur+="$c"; fi
    else
      case $c in
        "'"|'"') q=$c ;;
        ',') HV_TAGARGS+=("$(_hv_unescape_arg "$cur")"); cur='' ;;
        *) cur+="$c" ;;
      esac
    fi
  done
  HV_TAGARGS+=("$(_hv_unescape_arg "$cur")")
}

#--- embedded <@tag>...</@tag> evaluation -------------------------------------
# Innermost-first, exactly like Hackvertor: the first closing tag is matched
# with the nearest preceding opening tag, that expression is converted, and the
# loop repeats until no closing tag is left.
_hv_eval_tags() {
  local text=$1 guard=0
  local before after tail tagname head openpart opening
  local name argstr argsgiven content tool
  while [[ $text == *'</@'* ]]; do
    guard=$(( guard + 1 ))
    if (( guard > 5000 )); then _hv_warn 'tag evaluation aborted (too many tags)'; break; fi
    before=${text%%'</@'*}          # everything before the first closing tag
    after=${text#*'</@'}            # after "</@"
    tagname=${after%%>*}
    tail=${after#*>}                # after the closing '>'
    if [[ $before != *'<@'* ]]; then
      _hv_warn "unmatched closing tag </@${tagname}>"
      break
    fi
    openpart=${before##*'<@'}       # "tagname(args)>content"
    opening=${before%'<@'*}         # text in front of the opening tag
    if [[ $openpart != *'>'* ]]; then
      _hv_warn "tag <@${tagname}> is missing '>'"
      break
    fi
    head=${openpart%%>*}
    content=${openpart#*>}
    name=$head
    argstr=''
    argsgiven=0
    if [[ $head == *'('* ]]; then
      name=${head%%(*}
      argstr=${head#*\(}
      argstr=${argstr%%)*}
      argsgiven=1
    fi
    if [ "$name" != "$tagname" ]; then
      _hv_warn "mismatched tags: <@${name} ...> closed by </@${tagname}>"
      break
    fi
    tool=$(_hv_alias "$name")
    if ! _hv_tool_exists "$tool"; then
      _hv_warn "unknown tag <@${name}>"
      break
    fi
    HV_UI_DEFAULTS=0            # bare <@hex> behaves like the Hackvertor tag
    _hv_split_args "$argstr" "$argsgiven"
    HV_CURRENT=$content
    _hv_dispatch "$tool"
    text="${opening}${HV_RESULT}${tail}"
  done
  printf '%s' "$text"
}

#===============================================================================
# section 8 - usage
#===============================================================================

usage() {
  cat <<EOF
${HV_PROG} ${HV_VERSION} - Hackvertor style encoding from the command line

USAGE
  ${HV_PROG} -TAG [CONTENT]
  ${HV_PROG} -TAG < file
  cat file | ${HV_PROG} -TAG
  ${HV_PROG} '<@base64><@hex>alert(1)</@hex></@base64>'

EXAMPLES
  ${HV_PROG} -base64 'admin'"'"' OR 1=1--'
  ${HV_PROG} -urlencode_all "Hello World"
  ${HV_PROG} -hex=\\t 'AB'                 # tab separated hex
  ${HV_PROG} -jwt='HS256,s3cr3t' '{"sub":"1234567890","name":"John Doe"}'
  cat content.txt | ${HV_PROG} -base64
  ${HV_PROG} -base64 -hex 'alert(1)'        # hex first, then base64

OPTIONS
  -h, --help              this help
  -V, --version           version
  -l, --list              list the available tags
  -N, --no-newline        do not append a newline to the result
  -K, --keep-newline      keep the trailing newline of piped input
  -q, --quiet             suppress warnings
      --eval              always evaluate <@tag>...</@tag> in the content
      --no-eval           never evaluate embedded tags
      --alg ALGO          JWT algorithm for -jwt (default HS256)
      --secret SECRET     JWT secret for -jwt (default "secret")
      --debug             trace every pipeline step on stderr
      --                  end of options

TAG FLAGS
  Every Hackvertor tag is available as -name.  Arguments use Hackvertor
  syntax and are comma separated:

      -hex=\\t          -hex=(,)        -jwt=HS512,secret
      -jwt('HS256','secret')             (quote the whole flag in the shell)

  Encode  $(printf '%s ' base32 base64 base64url html_entities html5_entities hex hex_entities hex_escapes octal_escapes dec_entities unicode_escapes css_escapes css_escapes6)
  URL     $(printf '%s ' burp_urlencode urlencode urlencode_not_plus urlencode_all)
  Code    $(printf '%s ' php_non_alpha php_chr sql_hex jwt quoted_printable)
  Decode  $(printf '%s ' d_base32 d_base64 d_base64url d_hex d_sql_hex d_html_entities d_html5_entities d_url d_quoted_printable d_unicode_escapes d_css_escapes d_octal_escapes d_php_chr d_jwt_get_header d_jwt_get_payload)

  Multiple flags are applied left to right: the first flag is the innermost
  conversion, exactly like nested <@tag> elements in Hackvertor.
EOF
}

list_tags() {
  cat <<'EOF'
Encode tags (Hackvertor ports)
  base32              RFC 4648 base32, padded with '='
  base64              standard base64 of the UTF-8 bytes
  base64url           base64 with -_ alphabet and no padding
  html_entities       HTML 4.01 named references, decimal for the rest
  html5_entities      HTML5 named references, decimal for the rest
  hex                 hex codepoints, separator arg (default one space)
  hex_entities        &#xH; for every character
  hex_escapes         \xHH (0-0xFF) and \uHHHH above
  octal_escapes       \NNN octal escapes
  dec_entities        &#N; for every character
  unicode_escapes     \uHHHH escapes, surrogate pairs when needed
  css_escapes         CSS \HH compact escapes
  css_escapes6        CSS \HHHHHH six digit escapes
  burp_urlencode      Burp IExtensionHelpers.urlEncode, space becomes +
  urlencode           Java URLEncoder.encode, space becomes +
  urlencode_not_plus  URLEncoder with space as %20
  urlencode_all       %XX for every character
  php_non_alpha       PHP without alphanumeric characters
  php_chr             chr(N).chr(N) chain
  sql_hex             0x hex literals
  jwt                 JSON Web Token (algo and secret arguments)
  quoted_printable    quoted printable, =XX for non printable bytes
Decode tags
  d_base32 d_base64 d_base64url d_hex d_sql_hex d_html_entities
  d_html5_entities d_url d_burp_url d_quoted_printable d_unicode_escapes
  d_css_escapes d_octal_escapes d_php_chr d_jwt_get_header d_jwt_get_payload
EOF
}

#===============================================================================
# section 9 - main
#===============================================================================

_hv_parse_tag_flag() {
  local tok=$1 name argstr='' rest given=0
  name=${tok#-}
  name=${name#-}
  case $name in
    *'('*)
      rest=${name#*\(}
      name=${name%%(*}
      case $rest in
        *')') argstr=${rest%\)}; given=1 ;;
        *) _hv_die "malformed tag flag '$tok' (missing closing ')')" ;;
      esac
      ;;
    *'='*)
      argstr=${name#*=}
      name=${name%%=*}
      given=1
      ;;
  esac
  name=$(_hv_alias "$name")
  if ! _hv_tool_exists "$name"; then
    _hv_err "unknown tag '$name'"
    _hv_err "run '$HV_PROG --list' to see the available tags"
    exit 2
  fi
  HV_TAGS+=("${name}"$'\t'"${argstr}"$'\t'"${given}")
}

main() {
  local arg
  while [ $# -gt 0 ]; do
    arg=$1
    case $arg in
      --) shift
          while [ $# -gt 0 ]; do HV_POS+=("$1"); shift; done
          break ;;
      -h|--help) usage; exit 0 ;;
      -V|--version) printf '%s %s\n' "$HV_PROG" "$HV_VERSION"; exit 0 ;;
      -l|--list) list_tags; exit 0 ;;
      -N|--no-newline) HV_FINAL_NL=0; shift ;;
      -K|--keep-newline) HV_KEEP_NL=1; shift ;;
      -q|--quiet) HV_QUIET=1; shift ;;
      --eval) HV_EVAL=1; shift ;;
      --no-eval) HV_EVAL=0; shift ;;
      --debug) HV_DEBUG=1; shift ;;
      --alg) [ $# -ge 2 ] || _hv_die '--alg needs a value'; HV_ALG=$2; shift 2 ;;
      --alg=*) HV_ALG=${arg#*=}; shift ;;
      --secret) [ $# -ge 2 ] || _hv_die '--secret needs a value'; HV_SECRET=$2; shift 2 ;;
      --secret=*) HV_SECRET=${arg#*=}; shift ;;
      -?*) _hv_parse_tag_flag "$arg"; shift ;;
      *) HV_POS+=("$arg"); shift ;;
    esac
  done

  # ---- gather the input
  if [ "${#HV_POS[@]}" -gt 0 ]; then
    HV_CURRENT="${HV_POS[*]}"
  else
    if [ -t 0 ]; then _hv_die 'no content given (see --help)'; fi
    IFS= read -r -d '' HV_CURRENT <&0 || true
  fi

  # a trailing newline from a pipe is almost always accidental
  if [ "$HV_KEEP_NL" = 0 ]; then
    case $HV_CURRENT in
      *$'\r'$'\n') HV_CURRENT=${HV_CURRENT%$'\n'}; HV_CURRENT=${HV_CURRENT%$'\r'} ;;
      *$'\n') HV_CURRENT=${HV_CURRENT%$'\n'} ;;
    esac
  fi

  # ---- embedded <@tag> evaluation
  if [ "$HV_EVAL" = 1 ] || { [ "$HV_EVAL" = -1 ] && [[ $HV_CURRENT == *'<@'*'</@'* ]]; }; then
    HV_CURRENT=$(_hv_eval_tags "$HV_CURRENT")
  fi

  if [ "${#HV_TAGS[@]}" -eq 0 ]; then
    # nothing to convert: pass the (possibly evaluated) content through
    printf '%s' "$HV_CURRENT"
    [ "$HV_FINAL_NL" = 1 ] && printf '\n'
    return 0
  fi

  local i spec name argstr given last
  HV_UI_DEFAULTS=1        # -hex without arguments uses the Burp UI's " " default
  last=$(( ${#HV_TAGS[@]} - 1 ))
  if [ "$HV_DEBUG" = 1 ]; then
    printf '%s: input => %s\n' "$HV_PROG" "$HV_CURRENT" >&2
  fi
  for (( i=0; i<${#HV_TAGS[@]}; i++ )); do
    spec=${HV_TAGS[i]}
    name=${spec%%$'\t'*}
    spec=${spec#*$'\t'}
    argstr=${spec%%$'\t'*}
    given=${spec#*$'\t'}
    _hv_split_args "$argstr" "$given"
    _hv_dispatch "$name"
    if [ "$HV_DEBUG" = 1 ]; then
      # a trace on stderr only: stdout stays byte exact
      printf '%s: step %d/%d %s%s => %s\n' \
        "$HV_PROG" "$(( i + 1 ))" "${#HV_TAGS[@]}" "$name" \
        "${given:+(${argstr})}" "$HV_RESULT" >&2
    fi
    if [ "$i" -eq "$last" ]; then
      _hv_write_result
      [ "$HV_FINAL_NL" = 1 ] && printf '\n'
    else
      HV_CURRENT=$HV_RESULT
    fi
  done
  return 0
}

main "$@"
