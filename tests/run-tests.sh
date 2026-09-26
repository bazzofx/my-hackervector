#!/usr/bin/env bash
#===============================================================================
# tests/run-tests.sh - test suite for hackvertor.sh
#
#   bash tests/run-tests.sh            run everything
#   bash tests/run-tests.sh -v         also print the passing case names
#
# Two fixture files drive most of the suite; both are tab separated
#       tag <TAB> argspec <TAB> input-hex <TAB> expected-hex <TAB> note
#
#   tests/golden.tsv   200 vectors produced by running the REAL unbescape
#                      1.1.6.RELEASE jar (see research/probe-out.txt)
#   tests/vectors.tsv  vectors taken from the Hackvertor Java test suite and
#                      from Convertors.java
#
# Everything is compared byte for byte through temporary files, so binary
# output, newlines and high bytes are all covered.
#===============================================================================

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
HV="$HERE/../hackvertor.sh"
VERBOSE=0
[ "${1:-}" = '-v' ] && VERBOSE=1

if [ ! -f "$HV" ]; then
  echo "cannot find hackvertor.sh next to $HERE" >&2
  exit 1
fi

TMP=$(mktemp -d 2>/dev/null) || TMP=$(mktemp -d -t hvXXXXXX) || exit 1
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
declare -a FAILURES=()

#-------------------------------------------------------------------------------
# helpers
#-------------------------------------------------------------------------------

hex_to_file() { # $1 = hex, $2 = file
  local hex=$1 file=$2 i n out=''
  n=${#hex}
  : > "$file"
  for (( i=0; i<n; i+=2 )); do
    out+="\\$(printf '%03o' "$(( 16#${hex:i:2} ))")"
  done
  [ -n "$out" ] && printf '%b' "$out" >> "$file"
  return 0
}

file_to_hex() { # $1 = file
  od -An -tx1 -v "$1" | tr -d ' \n'
}

# readable rendering: printable ASCII as is, everything else as \xNN
readable() { # $1 = hex
  local hex=$1 i byte ch out=''
  for (( i=0; i<${#hex}; i+=2 )); do
    byte=$(( 16#${hex:i:2} ))
    if (( byte >= 0x20 && byte < 0x7F )); then
      printf -v ch '%b' "\\$(printf '%03o' "$byte")"
      out+="$ch"
    else
      printf -v ch '\\x%02x' "$byte"
      out+="$ch"
    fi
  done
  printf '%s' "$out"
}

pass() {
  PASS=$(( PASS + 1 ))
  if [ "$VERBOSE" = 1 ]; then
    printf 'ok   %s\n' "$1"
  else
    printf '.'
    (( PASS % 60 == 0 )) && printf '\n'
  fi
  return 0
}

fail() { # $1 desc, $2 expected hex, $3 actual hex, $4 extra info
  FAIL=$(( FAIL + 1 ))
  FAILURES+=("$1")
  printf '\nFAIL %s\n' "$1"
  printf '  expected: %s\n' "$(readable "$2")"
  printf '  actual  : %s\n' "$(readable "$3")"
  if [ -n "${4:-}" ]; then printf '  note    : %s\n' "$4"; fi
  return 0
}

# run the tool on a hex encoded stdin, byte exact.  -K keeps the input byte for
# byte, which is what the fixture vectors need.
run_hex() { # $1 = input hex, rest = arguments
  local inhex=$1
  shift
  hex_to_file "$inhex" "$TMP/in"
  bash "$HV" -K -N "$@" < "$TMP/in" > "$TMP/out" 2> "$TMP/err"
  return $?
}

# like run_hex but without -K, so the default trailing newline handling applies
run_hex_raw() { # $1 = input hex, rest = arguments
  local inhex=$1
  shift
  hex_to_file "$inhex" "$TMP/in"
  bash "$HV" -N "$@" < "$TMP/in" > "$TMP/out" 2> "$TMP/err"
  return $?
}

check_hex_with() { # $1 runner, $2 desc, $3 expected hex, $4 input hex, rest = args
  local runner=$1 desc=$2 exphex=$3 inhex=$4
  shift 4
  local rc=0
  "$runner" "$inhex" "$@" || rc=$?
  if [ "$rc" -ne 0 ]; then
    fail "$desc" "$exphex" "$(file_to_hex "$TMP/out")" "exit code $rc: $(cat "$TMP/err")"
    return 0
  fi
  local acthex
  acthex=$(file_to_hex "$TMP/out")
  if [ "$acthex" = "$exphex" ]; then pass "$desc"; else fail "$desc" "$exphex" "$acthex"; fi
  return 0
}

check_hex() { # $1 desc, $2 expected hex, $3 input hex, rest = args
  local desc=$1 exphex=$2 inhex=$3
  shift 3
  check_hex_with run_hex "$desc" "$exphex" "$inhex" "$@"
}

# run and compare text output (trailing newlines are not significant here)
check_text() { # $1 desc, $2 expected text, rest = args (stdin = /dev/null)
  local desc=$1 expected=$2
  shift 2
  local actual rc=0
  actual=$(bash "$HV" "$@" < /dev/null 2>"$TMP/err") || rc=$?
  if [ "$rc" -ne 0 ]; then
    fail "$desc" "$(printf '%s' "$expected" | od -An -tx1 | tr -d ' \n')" "" "exit code $rc: $(cat "$TMP/err")"
    return 0
  fi
  if [ "$actual" = "$expected" ]; then
    pass "$desc"
  else
    fail "$desc" "$(printf '%s' "$expected" | od -An -tx1 | tr -d ' \n')" \
         "$(printf '%s' "$actual" | od -An -tx1 | tr -d ' \n')"
  fi
  return 0
}

#-------------------------------------------------------------------------------
# 1. fixture driven cases
#-------------------------------------------------------------------------------

run_fixture() { # $1 = tsv file
  local file=$1 line rest tag argspec inhex exphex note flag desc
  # split by hand: bash read collapses runs of tab (IFS whitespace), which would
  # silently drop empty fields such as an empty argspec
  while IFS= read -r line || [ -n "$line" ]; do
    [ -z "$line" ] && continue
    tag=${line%%$'\t'*}; rest=${line#*$'\t'}
    argspec=${rest%%$'\t'*}; rest=${rest#*$'\t'}
    inhex=${rest%%$'\t'*}; rest=${rest#*$'\t'}
    exphex=${rest%%$'\t'*}; note=${rest#*$'\t'}
    if [ -n "$argspec" ]; then flag="-${tag}(${argspec})"; else flag="-${tag}"; fi
    desc="${tag}${argspec:+(${argspec})} '$(readable "$inhex")'  [${note:-fixture}]"
    check_hex "$desc" "$exphex" "$inhex" "$flag"
  done < "$file"
}

printf '== fixtures ==\n'
run_fixture "$HERE/golden.tsv"
run_fixture "$HERE/vectors.tsv"

#-------------------------------------------------------------------------------
# 2. command line behaviour
#-------------------------------------------------------------------------------

printf '\n== command line ==\n'

check_text '-base64 with a content argument' 'dGVzdA==' -base64 'test'
check_text '-base64 with quoted spaces' 'SGVsbG8gV29ybGQ=' -base64 'Hello World'
check_text 'unquoted content is joined with spaces' 'SGVsbG8gV29ybGQ=' -base64 Hello World
check_text 'long form --base64' 'dGVzdA==' --base64 'test'
check_text '-- separator protects a leading dash' 'LXRlc3Q=' -base64 -- '-test'

# stdin (run_hex_raw leaves the default trailing newline handling in place)
check_hex_with run_hex_raw 'stdin without a trailing newline' '6447567a64413d3d' '74657374' -base64
check_hex_with run_hex_raw 'stdin trailing newline is stripped' '6447567a64413d3d' '746573740a' -base64
check_hex_with run_hex_raw 'stdin CRLF is stripped' '6447567a64413d3d' '746573740d0a' -base64
check_hex_with run_hex_raw '-K keeps the trailing newline' '6447567a64413d3d0a' '746573740a' -base64 -K
check_hex 'two input newlines keep both' '6447567a64413d3d0a0a' '746573740a0a' -base64 -K
check_hex_with run_hex_raw '-N omits the final newline' '6447567a64413d3d' '74657374' -base64 -N
check_hex_with run_hex_raw 'empty input' '' '' -base64
check_hex_with run_hex_raw 'no tag flag passes the content through' '74657374' '74657374'

# pipelines: flags are applied in the order given, so the first flag is the
# innermost conversion - equivalently, the tags are written in reverse order
check_text 'first flag is applied first' 'NjE2MjYz' -hex='' -base64 'abc'
check_text 'last flag is the outermost conversion' '5957786c636e516f4d536b3d' -base64 -hex='' 'alert(1)'
check_text 'flag pipeline equals the nested tag form' 'NzQ2NTczNzQ=' -hex='' -base64 'test'
check_text 'nested tag form for comparison' 'NzQ2NTczNzQ=' '<@base64><@hex>test</@hex></@base64>'

# tag flag argument syntaxes
check_text "Hackvertor style -hex(':')" '74:65:73:74' -hex=':' 'test'
check_text "= form -hex=:" '74:65:73:74' -hex=: 'test'
check_text "-hex('') has no separator" '74657374' "-hex('')" 'test'
check_text 'default -hex separator is one space' '74 65 73 74' -hex 'test'
check_text '-jwt= form matches the Hackvertor style form' \
  "$(bash "$HV" "-jwt('HS256','secret')" '{"a":1}' < /dev/null)" -jwt=HS256,secret '{"a":1}'

# embedded <@tag> evaluation
check_text 'embedded tags are evaluated' 'NzQ2NTczNzQ=' '<@base64><@hex>test</@hex></@base64>'
check_text 'embedded tags with arguments' 'NzQ2NTczNzQ=' "<@base64><@hex('')>test</@hex></@base64>"
check_text 'embedded tags mixed with text' 'YQ== and Yg==' \
  '<@base64>a</@base64> and <@base64>b</@base64>'
check_text '--no-eval leaves tags alone' '<@base64>test</@base64>' --no-eval '<@base64>test</@base64>'
check_text 'flags apply after embedded tags' 'NzQ2NTczNzQ=' -base64 '<@hex>test</@hex>'

# decoders that produce raw bytes
check_hex 'decoder output keeps binary bytes' '0a' '43673d3d' -d_base64
check_hex 'decoder round trip' '74657374' '4f5253584735413d' -d_base32

# exit codes and listings
bash "$HV" --help > /dev/null 2>&1
[ $? -eq 0 ] && pass '--help exits 0' || fail '--help exits 0' '00' ''

bash "$HV" --list > "$TMP/list" 2>&1
if [ $? -eq 0 ]; then pass '--list exits 0'; else fail '--list exits 0' '00' ''; fi

MISSING=''
for tag in base32 base64 base64url html_entities html5_entities hex hex_entities \
           hex_escapes octal_escapes dec_entities unicode_escapes css_escapes \
           css_escapes6 burp_urlencode urlencode urlencode_not_plus urlencode_all \
           php_non_alpha php_chr sql_hex jwt quoted_printable; do
  if ! grep -q "^  ${tag} " "$TMP/list"; then MISSING="$MISSING $tag"; fi
done
if [ -z "$MISSING" ]; then
  pass 'every requested tag is listed by --list'
else
  fail 'every requested tag is listed by --list' '' '' "missing:$MISSING"
fi

bash "$HV" -definitely_not_a_tag 'x' > /dev/null 2>"$TMP/err"
if [ $? -eq 2 ]; then pass 'unknown tag exits 2'; else fail 'unknown tag exits 2' '02' ''; fi

bash "$HV" -base64 < /dev/null > /dev/null 2>&1
[ $? -eq 0 ] && pass 'empty stdin is not an error' || fail 'empty stdin is not an error' '00' ''

#-------------------------------------------------------------------------------
# summary
#-------------------------------------------------------------------------------

printf '\n== summary ==\n'
printf 'passed: %d\nfailed: %d\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  printf '\nfailing cases:\n'
  for f in "${FAILURES[@]}"; do printf '  - %s\n' "$f"; done
  exit 1
fi
printf 'all tests passed\n'
exit 0
