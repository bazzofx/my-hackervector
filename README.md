# hackvertor.sh

A stand-alone command-line port of the encoding tags from the [Hackvertor](https://github.com/portswigger/hackvertor) Burp Suite extension.

```sh
hackvertor.sh -base64 "admin' OR 1=1--"
```

```sh
cat content.txt | hackvertor.sh -base64
```

```sh
hackvertor.sh '<@base64><@hex>alert(1)</@hex></@base64>'
```

```sh
hackvertor.sh -dec_entities SELECT
```

Everything is implemented in one Bash script (`hackvertor.sh`, ~3,200 lines, ~84 KB).

No Python, Perl, Node, or `base64` binary is required at runtime. The only requirements are:

- Bash 4.3+
- `od`
- `tr`

`openssl` is used only for JWT HS384/HS512. HS256 has a pure-Bash fallback.

---

## 1. Usage

```sh
hackvertor.sh -TAG [CONTENT]

hackvertor.sh -TAG < file

cat file | hackvertor.sh -TAG

hackvertor.sh '<@base64><@hex>alert(1)'
```

| Option | Meaning |
|---|---|
| `-h`, `--help` | Show help |
| `-V`, `--version` | Show version (`hackvertor 1.0.0`) |
| `-l`, `--list` | List every tag flag |
| `-N`, `--no-newline` | Do not append a newline to the result |
| `-K`, `--keep-newline` | Keep the trailing newline of piped input |
| `-q`, `--quiet` | Suppress warnings |
| `--eval` | Always evaluate embedded `<@tag>...</@tag>` |
| `--no-eval` | Never evaluate embedded tags |
| `--alg ALGO`, `--alg=ALGO` | JWT algorithm for `-jwt`: `HS256`, `HS384`, `HS512`, `NONE` |
| `--secret SECRET`, `--secret=SECRET` | JWT secret for `-jwt` |
| `--debug` | Trace every pipeline step on stderr |
| `--` | End of options; everything after it is content |

Exit codes: `0` on success, `2` for a usage error or an unknown tag.

Make it executable once, then call it however you like:

```sh
chmod +x hackvertor.sh
./hackvertor.sh -base64 "test"

# or put it on PATH and drop the .sh
install -m 0755 hackvertor.sh ~/.local/bin/hackvertor
hackvertor -dec_entities SELECT
```

`--debug` writes its trace to **stderr only**, so stdout stays byte exact and piped output is unaffected:

```sh
hackvertor.sh --debug -hex= -base64 test
```

```text
hackvertor: input => test
hackvertor: step 1/2 hex() => 74657374
hackvertor: step 2/2 base64() => NzQ2NTczNzQ=
NzQ2NTczNzQ=
```

Tag flags accept Hackvertor-style arguments, either quoted as one shell word or after an `=`:

```sh
hackvertor.sh "-hex(':')" 'test'
# 74:65:73:74

hackvertor.sh -hex=: 'test'
# 74:65:73:74

hackvertor.sh -hex= 'test'
# 74657374

hackvertor.sh -hex 'test'
# 74 65 73 74

hackvertor.sh -jwt=HS512,s3cr3t '{"sub":"1"}'
```

Every tag flag accepts four spellings:

| Spelling | `-hex` on `AB` | Notes |
|---|---|---|
| `-hex 'AB'` | `41 42` | the separator the Hackvertor UI button inserts |
| `--hex 'AB'` | `41 42` | long form works for every flag |
| `-hex= 'AB'` | `4142` | explicitly empty separator |
| `-hex=: 'AB'` | `41:42` | custom separator |
| `"-hex(':')" 'AB'` | `41:42` | Hackvertor style; quote the whole flag |

Arguments are comma separated, may be quoted with `'` or `"`, and understand Java-style escapes (`\t`, `\n`, `\r`):

```sh
hackvertor.sh -hex=\\t 'AB'
# 41<TAB>42
```

Only **`-hex`** (optional separator) and **`-jwt`** (`algo`, `secret`) take arguments. Arguments on any other flag are ignored, so `-base64=zzz test` still gives `dGVzdA==`.

### Pipelines

Flags are applied **in the order given**, so the first flag is the innermost conversion and the last flag is the outermost.

This is the same as writing the tags in reverse order:

```sh
hackvertor.sh -hex= -base64 'test'
# base64(hex("test"))

hackvertor.sh '<@base64><@hex>test</@hex></@base64>'
# identical: NzQ2NTczNzQ=

hackvertor.sh -base64 -hex= 'alert(1)'
# the other way round: hex(base64("alert(1)")) = 5957786c636e516f4d536b3d
```

### Trailing newlines

When the content comes from stdin, exactly one trailing newline (LF or CRLF) is removed first.

This means:

```sh
cat file | hackvertor.sh -base64
```

normally means "encode the file's content" rather than "encode the file's final newline".

Use `-K` to keep the input bytes exactly as they are.

A result is always terminated with one newline unless `-N` is specified.

### Embedded tags

If the content contains `<@tag>...</@tag>`, the tags are evaluated innermost-first, exactly like Hackvertor.

Use `--no-eval` to disable this behaviour.

```sh
hackvertor.sh '<@base64><@hex>alert(1)</@hex></@base64>'
# NjE2YzY1NzI3NDI4MzEyOQ==

hackvertor.sh -base64 '<@hex>test</@hex>'
# NzQ2NTczNzQ=

hackvertor.sh '<@dec_entities>SELECT</@dec_entities>'
# &#83;&#69;&#76;&#69;&#67;&#84;
```

Bare tags follow Hackvertor's own defaults.

For example, a bare `<@hex>` has **no separator**, matching:

```text
<@hex>ABC</@hex>
```

→

```text
414243
```

A bare command-line `-hex` uses the separator inserted by the Hackvertor UI button:

```text
74 65 73 74
```

---

# 2. Implemented Tags

## Encode

| Tag | Output for `test` | Semantics |
|---|---|---|
| `base32` | `ORSXG5A=` | RFC 4648 base32, padded |
| `base64` | `dGVzdA==` | Standard base64 of the UTF-8 bytes |
| `base64url` | `dGVzdA` | Base64 with `-_`, padding removed |
| `html_entities` | `test` | HTML 4.01 named references, decimal fallback |
| `html5_entities` | `test` | HTML5 named references, decimal fallback |
| `hex` | `74 65 73 74` | Hex codepoints, separator argument; default is one space |
| `hex_entities` | `&#x74;&#x65;&#x73;&#x74;` | `&#xH;` for every character, **lowercase** hex |
| `hex_escapes` | `\x74\x65\x73\x74` | `\xHH` up to `0xFF`, then `\uHHHH`, **uppercase** |
| `octal_escapes` | `\164\145\163\164` | `\NNN` for every codepoint |
| `dec_entities` | `&#116;&#101;&#115;&#116;` | `&#N;` for every character |
| `unicode_escapes` | `\u0074\u0065\u0073\u0074` | `\uHHHH`, surrogate pairs, **uppercase** |
| `css_escapes` | `\74\65\73\74` | CSS `\HH` compact format, **uppercase** |
| `css_escapes6` | `\000074\000065\000073\000074` | CSS `\HHHHHH`, **uppercase** |
| `burp_urlencode` | `test` | Burp `urlEncode`, key characters, space → `+` |
| `urlencode` (`url_encode`) | `test` | Java `URLEncoder`, space → `+` |
| `urlencode_not_plus` | `test` | `URLEncoder` with space → `%20` |
| `urlencode_all` | `%74%65%73%74` | `%XX` for every character, uppercase |
| `php_non_alpha` | `<?php $_[]++;...$Ä.'"');$__($_);?>` | PHP payload with no alphanumerics |
| `php_chr` | `chr(116).chr(101).chr(115).chr(116)` | `chr(N)` chain |
| `sql_hex` | `0x74657374` | `0x` + hex |
| `jwt` | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...` | JWT, arguments `algo,secret`; default `HS256,secret` |
| `quoted_printable` | `test` | Quoted printable, `=XX` uppercase |

Outputs above are for the input `test`. `php_non_alpha` is abbreviated: the real
output is a full `<?php` payload whose prologue decodes the string, for example
`-php_non_alpha 'id'` starts with
`<?php $_[]++;$_[]=$_._;$_____=$_[(++$__[])][(++$__[])+(++$__[])+(++$__[])];`.

### Flags that take arguments

| Flag | Argument | Example | Output |
|---|---|---|---|
| `hex` | separator (default one space) | `"-hex('')" 'AB'` | `4142` |
| `hex` | | `-hex=: 'AB'` | `41:42` |
| `hex` | | `-hex 'AB'` | `41 42` |
| `jwt` | `algo` | `-jwt --alg NONE '{"sub":"1"}'` | `eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.` |
| `jwt` | `algo,secret` | `-jwt=HS256,secret '{"sub":"1"}'` | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.8qZF8vbN3UpcanXFc-mPXJkOPN01-bRch8XX3rToP1U` |
| `jwt` | empty secret | `-jwt=HS256,'' '{"sub":"1"}'` | HMAC keyed with a single NUL byte, as Hackvertor does |

Supported JWT algorithms: `HS256`, `HS384`, `HS512`, `NONE` (unsigned, output
ends with a dot). Anything else returns `Unsupported algorithm`, and a payload
that is not a JSON object returns `Unable to create token` — the same strings
Hackvertor uses.

### Entity tags: named or numeric?

`html_entities` and `html5_entities` use unbescape's
`LEVEL_3_ALL_NON_ALPHANUMERIC`, so **letters and digits pass through untouched**
and only non-alphanumerics are escaped, preferring a *named* reference:

```sh
hackvertor.sh -html_entities S
# S                     (nothing to escape)

hackvertor.sh -html_entities 'SELECT * FROM t'
# SELECT&#32;&#42;&#32;FROM&#32;t    (space and * escaped, letters kept)

hackvertor.sh -html_entities '©'
# &#169;                (HTML4 has no name for it)

hackvertor.sh -html5_entities '©'
# &copy;
```

For **numeric** references on every character — `S` → `&#83;` — use
`dec_entities` (decimal) or `hex_entities` (hex):

```sh
hackvertor.sh -dec_entities S
# &#83;

hackvertor.sh -dec_entities SELECT
# &#83;&#69;&#76;&#69;&#67;&#84;

hackvertor.sh -hex_entities SELECT
# &#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;
```

## Decode

| Tag | Example | Output |
|---|---|---|
| `d_base32` | `-d_base32 'ORSXG5A='` | `test` |
| `d_base64` | `-d_base64 'dGVzdA=='` | `test` |
| `d_base64url` | `-d_base64url 'dGVzdD4-ZGF0YQ'` | `test>>data` |
| `d_hex` | `-d_hex '41 42'` | `AB` |
| `d_sql_hex` | `-d_sql_hex '0x53454c454354'` | `SELECT` |
| `d_html_entities` | `-d_html_entities '&lt;b&gt;'` | `<b>` |
| `d_html5_entities` | `-d_html5_entities '&copy;&euro;'` | `©€` |
| `d_url` | `-d_url 'Hello+World%21'` | `Hello World!` |
| `d_burp_url` | `-d_burp_url 'a%2Fb%20c'` | `a/b c` |
| `d_quoted_printable` | `-d_quoted_printable 'a=3Db'` | `a=b` |
| `d_unicode_escapes` | `-d_unicode_escapes '\u0074\u0065\x73\x74'` | `test` |
| `d_css_escapes` | `-d_css_escapes '\74\65\73\74'` | `test` |
| `d_octal_escapes` | `-d_octal_escapes '\164\145\163\164'` | `test` |
| `d_php_chr` | `-d_php_chr 'chr(105).chr(100)'` | `id` |
| `d_jwt_get_header` | `-d_jwt_get_header '<token>'` | `{"alg":"HS256","typ":"JWT"}` |
| `d_jwt_get_payload` | `-d_jwt_get_payload '<token>'` | `{"sub":"1234567890","name":"John Doe","iat":1516239022}` |

Notes:

- `d_hex` accepts plain hex, space/colon separated hex and the `0x` form.
- `d_sql_hex` accepts the `0x` form with or without the prefix.
- `d_url` decodes `+` to a space and, like Hackvertor, returns the input
  unchanged when a `%` escape is malformed. `d_burp_url` is permissive instead.
- `d_unicode_escapes` also understands `\xHH` and `\u{...}`.
- `d_jwt_get_header` / `d_jwt_get_payload` print `Invalid token` for a token
  without three dot separated parts.

## Aliases

| Alias | Same as |
|---|---|
| `url_encode` | `urlencode` |
| `url_encode_all` | `urlencode_all` |
| `url_encode_not_plus` | `urlencode_not_plus` |
| `url_encode_burp`, `burp_url_encode` | `burp_urlencode` |
| `base64_url` | `base64url` |
| `base32url`, `base32_url` | `base32` |
| `hex_escape` | `hex_escapes` |

---

# 3. How Faithful Is It?

The ports were written against Hackvertor's `Convertors.java` and then checked against the **real Java libraries**, rather than relying on assumptions.

| Area | Reference used | Result |
|---|---|---|
| `html_entities`, `html5_entities`, `hex_entities`, `dec_entities`, `hex_escapes`, `unicode_escapes`, `css_escapes`, `css_escapes6` | **unbescape 1.1.6.RELEASE JAR**, executed through a JRE 8/Nashorn probe (`research/probe.js`, output in `research/probe-out.txt`) | 200/200 vectors byte-identical (`tests/golden.tsv`) |
| HTML named-reference tables | Parsed directly from unbescape's `Html4EscapeSymbolsInitializer` / `Html5EscapeSymbolsInitializer` sources (`tools/ref/`) | 252 HTML4 names, 1,446 HTML5 codepoints, first-declared name wins, identical to unbescape |
| `quoted_printable` | **commons-codec 1.15 JAR** executed directly; Hackvertor pins 1.15 | Matches UTF-8, TAB/SPACE literal, `=` → `=3D`, CR/LF escaped, never wrapped, uppercase hex |
| `urlencode`, `urlencode_not_plus`, `urlencode_all` | JDK 17 `URLEncoder` | Matches, including the `-_.*` literal set and `%7E` for `~` |
| JWT | `JWTTest.java` full-token assertions | HS256/HS384/HS512/NONE and the error strings match |
| base32/base64/hex/php/sql/etc. | Hackvertor's own JUnit suite (`ConvertorTests`, `ConvertorTestsBasic`, `HackvertorAllTagsUiTest`) | Matching vectors in `tests/vectors.tsv` |

## Deliberate Deviations

### 1. `urlencode_all` and astral characters

For astral characters such as 😀, Hackvertor calls `str.charAt(i)` on a UTF-16 code unit and therefore emits:

```text
%3F%3F
```

This port instead emits the correct UTF-8 representation:

```text
%F0%9F%98%80
```

BMP characters are identical.

### 2. `d_url` and invalid UTF-8

For invalid UTF-8 such as:

```text
%FF
```

Java's `URLDecoder` substitutes U+FFFD.

This port emits the raw byte instead.

Invalid `%` escapes are handled like Hackvertor, which returns the input unchanged.

### 3. `burp_urlencode`

`burp_urlencode` is the one tag whose exact Java behaviour cannot be reproduced from public information.

PortSwigger does not publish a complete character list for the legacy `IExtensionHelpers.urlEncode`.

This port therefore implements the documented "key characters" behaviour:

- Alphanumerics remain literal
- `-_.~/` remain literal
- Spaces become `+`
- Everything else is percent encoded

This reproduces the known ground truth:

```text
burp_urlencode("Hello World")
```

→

```text
Hello+World
```

It also reproduces the observed Burp Encoder output:

```text
hello ~ // ##

→

hello+~+//+%23%23
```

If strict Java `URLEncoder` behaviour is required instead, use:

```sh
hackvertor.sh -urlencode
```

### 4. JWT

`jwt` re-serialises the payload compactly while preserving member order.

This matches the behaviour of `org.json` for the vectors asserted by Hackvertor's tests.

The implementation uses UTF-8 where the JVM would otherwise use the platform charset.

---

# 4. Building and Testing

Regenerate the entity tables:

```sh
python3 tools/gen_tables.py --output lib/entity_tables.sh
```

Splice them into the single-file deliverable:

```sh
python3 tools/build.py
```

Rebuild the test fixtures:

```sh
python3 tools/make_golden.py
```

Run the test suite:

```sh
bash tests/run-tests.sh
```

Add `-v` to print every test case name:

```sh
bash tests/run-tests.sh -v
```

`tests/run-tests.sh` compares results byte-for-byte through temporary files, so binary results, embedded newlines, and high bytes are all covered.

There are approximately **325 test cases**.

---

# 5. Project Layout

| Path | Purpose |
|---|---|
| `hackvertor.sh` | The tool; single-file, self-contained |
| `hackvertor` | Convenience wrapper so it can be called as `hackvertor` |
| `hackvertor.cmd` | Windows convenience wrapper (locates Git Bash) |
| `tests/run-tests.sh` | Test suite |
| `tests/golden.tsv` | Golden test fixtures (produced from real unbescape JAR output) |
| `tests/vectors.tsv` | Hackvertor test vectors |
| `tools/gen_tables.py` | Entity table generator |
| `tools/build.py` | Single-file build script |
| `tools/make_golden.py` | Test fixture generator |
| `tools/flag-examples.sh` | Prints a verified example for every flag |
| `tools/ref/` | Vendored unbescape 1.1.6 initialiser sources + Apache-2.0 licence |
| `research/` | Evidence from the Nashorn probe against the real unbescape JAR, raw output, and source-faithful Python implementation |
| `original-example/` | Vendored Hackvertor checkout used as the source for the ports |
| `.gitignore`, `.gitattributes` | Ignore rules; LF pinning so the shell scripts cannot be checked out as CRLF |

The following are **investigation artefacts** and are not required by the tool itself:

```text
research/
_research/
encoder-behavior-report.md
fetch.js
tools/probe.sh
```

---

## Requirements

Runtime requirements are intentionally minimal:

```text
Bash 4.3+
od
tr
```

Optional:

```text
openssl
```

`openssl` is only required for JWT HS384/HS512. HS256 includes a pure-Bash fallback.

---

## License

See the project source and vendored dependency licences for applicable licensing information.

Hackvertor is a project by PortSwigger. This project is a standalone command-line implementation inspired by and based on Hackvertor's encoding tag behaviour.

[Hackvertor](https://github.com/portswigger/hackvertor)
