#!/usr/bin/env bash
# Prints "-flag | input | output" for every flag, straight from the tool, so the
# README examples are copied from real output rather than written by hand.
cd "$(dirname "$0")/.." || exit 1
HV=./hackvertor.sh
show() { # $1 label, $2 input, rest = flags
  local label=$1 in=$2 out
  shift 2
  out=$("$HV" "$@" "$in" 2>&1)
  printf '%-24s | %-22s | %s\n' "$label" "$in" "$out"
}
raw() { # $1 label, rest = full argument list (input included)
  local label=$1 out
  shift
  out=$("$HV" "$@" 2>&1)
  printf '%-24s | %-22s | %s\n' "$label" "${1:-}" "$out"
}

echo "=== encoders ==="
show base32          'test'                        -base32
show base64          'test'                        -base64
show base64url       'test>>data'                  -base64url
show html_entities   '<script>alert(1)</script>'   -html_entities
show html_entities   'SELECT * FROM t'             -html_entities
show html5_entities  '<div>©'                      -html5_entities
show hex             'AB'                          -hex
show 'hex (no sep)'  'AB'                          -hex=
show 'hex (colon)'   'AB'                          -hex=:
show hex_entities    'SELECT'                      -hex_entities
show hex_escapes     'test'                        -hex_escapes
show hex_escapes     'aé'                          -hex_escapes
show octal_escapes   'test'                        -octal_escapes
show dec_entities    'SELECT'                      -dec_entities
show unicode_escapes 'test'                        -unicode_escapes
show css_escapes     '<b>'                         -css_escapes
show css_escapes6    'test'                        -css_escapes6
show burp_urlencode  'a/b?c=d&e=f'                 -burp_urlencode
show urlencode       'hello world!'                -urlencode
show urlencode_not_plus 'hello world!'             -urlencode_not_plus
show urlencode_all   'SELECT'                      -urlencode_all
show php_chr         'id'                          -php_chr
show sql_hex         'SELECT'                      -sql_hex
show jwt             '{"sub":"1"}'                 -jwt
show quoted_printable 'a=b é'                      -quoted_printable
echo 'php_non_alpha (first 60 and last 24 chars):'
pna=$($HV -php_non_alpha 'id')
printf '  %s ... %s\n' "${pna:0:60}" "${pna: -24}"

echo
echo "=== decoders ==="
show d_base32           'ORSXG5A='        -d_base32
show d_base64           'dGVzdA=='        -d_base64
show d_base64url        'dGVzdD4-ZGF0YQ'  -d_base64url
show d_hex              '41 42'           -d_hex
show d_hex              '0x4142'          -d_hex
show d_html_entities    '&lt;b&gt;'       -d_html_entities
show d_html5_entities   '&sol;&verbar;'   -d_html5_entities
show d_url              'Hello+World%21'  -d_url
show d_burp_url         'a%2Fb%20c'       -d_burp_url
show d_quoted_printable 'a=3Db'           -d_quoted_printable
show d_unicode_escapes  '\u0074\u0065\x73\x74' -d_unicode_escapes
show d_css_escapes      '\74\65\73\74'    -d_css_escapes
show d_octal_escapes    '\164\145\163\164' -d_octal_escapes
show d_php_chr          'chr(105).chr(100)' -d_php_chr
show d_sql_hex          '0x53454c454354'  -d_sql_hex

JWT='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
show d_jwt_get_header   "$JWT" -d_jwt_get_header
show d_jwt_get_payload  "$JWT" -d_jwt_get_payload

echo
echo "=== aliases ==="
for a in url_encode url_encode_all url_encode_not_plus url_encode_burp burp_url_encode base64_url base32url base32_url hex_escape; do
  printf '%-24s -> %s\n' "$a" "$($HV -"$a" 'test' 2>&1)"
done

echo
echo "=== cli options ==="
printf '%-24s -> %s\n' '--debug (stderr trace)' "$($HV --debug -hex= -base64 test 2>&1 >/dev/null | tr '\n' ';')"
printf '%-24s -> %s\n' '--list (first line)' "$($HV --list | head -1)"
printf '%-24s -> %s\n' 'tag form' "$($HV '<@base64><@hex>test</@hex></@base64>')"
printf '%-24s -> %s\n' 'stdin' "$(printf 'test' | $HV -base64)"
