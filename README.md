# hackvertor.sh

A stand-alone command line port of the encoding tags from the
[Hackvertor](https://github.com/portswigger/hackvertor) Burp Suite extension.

```sh
hackvertor.sh -base64 "admin' OR 1=1--"
cat content.txt | hackvertor.sh -base64
hackvertor.sh '<@base64><@hex>alert(1)</@hex></@base64>'
```

Everything is implemented in one bash script (`hackvertor.sh`, ~3200 lines,
~84 KB). No Python, Perl, Node or base64 binary is needed at run time; the only
requirements are bash 4.3+ and the POSIX tools `od` and `tr`. `openssl` is used
only for JWT HS384/HS512 (HS256 has a pure-bash fallback).

---

## 1. Usage

```
hackvertor.sh -TAG [CONTENT]
hackvertor.sh -TAG < file
cat file | hackvertor.sh -TAG
hackvertor.sh '<@base64><@hex>alert(1)</@hex></@base64>'
```

| Option | Meaning |
| --- | --- |
| `-h`, `--help` | help |
| `-V`, `--version` | version |
| `-l`, `--list` | list every tag |
| `-N`, `--no-newline` | do not append a newline to the result |
| `-K`, `--keep-newline` | keep the trailing newline of piped input |
| `-q`, `--quiet` | suppress warnings |
| `--eval`, `--no-eval` | force / disable evaluation of embedded `<@tag>` |
| `--alg`, `--secret` | JWT algorithm / secret for `-jwt` |
| `--` | end of options |

Tag flags accept Hackvertor style arguments, either quoted as one shell word or
after an `=`:

```sh
hackvertor.sh "-hex(':')" 'test'      # 74:65:73:74
hackvertor.sh -hex=: 'test'           # 74:65:73:74
hackvertor.sh -hex= 'test'            # 74657374   (empty separator)
hackvertor.sh -hex 'test'             # 74 65 73 74  (UI default separator)
hackvertor.sh -jwt=HS512,s3cr3t '{"sub":"1"}'
```

### Pipelines

Flags are applied **in the order given**, so the first flag is the innermost
conversion and the last flag is the outermost. This is the same thing as
writing the tags in reverse order:

```sh
hackvertor.sh -hex= -base64 'test'                     # base64(hex("test"))
hackvertor.sh '<@base64><@hex>test</@hex></@base64>'   # identical
```

### Trailing newlines

When the content comes from stdin, exactly one trailing newline (LF or CRLF) is
removed first, because `cat file | hackvertor.sh -base64` almost always means
"encode the file's content" and not "encode the file's final newline". Use `-K`
to keep the bytes exactly as they are. A result is always terminated with one
newline unless `-N` is given.

### Embedded tags

If the content contains `<@tag>...</@tag>`, the tags are evaluated
innermost-first, exactly like Hackvertor (`--no-eval` disables this):

```sh
hackvertor.sh '<@base64><@hex>alert(1)</@hex></@base64>'   # NjE2YzY1NzI3NDI4MzEyOQ==
hackvertor.sh -base64 '<@hex>test</@hex>'                  # NzQ2NTczNzQ=
```

Bare tags follow Hackvertor's own defaults (a bare `<@hex>` has *no* separator,
matching `<@hex>ABC</@hex>` → `414243`), while a bare *command line* `-hex`
uses the separator the Hackvertor UI button inserts (a single space).

---

## 2. Implemented tags

### Encode (the set requested)

| Tag | Output for `test` | Semantics |
| --- | --- | --- |
| `base32` | `ORSXG5A=` | RFC 4648 base32, padded |
| `base64` | `dGVzdA==` | standard base64 of the UTF-8 bytes |
| `base64url` | `dGVzdA` | base64 with `-_`, padding removed |
| `html_entities` | `test` | HTML 4.01 named refs, decimal fallback |
| `html5_entities` | `test` | HTML5 named refs, decimal fallback |
| `hex` | `74 65 73 74` | hex codepoints, separator argument (default one space) |
| `hex_entities` | `&#x74;&#x65;&#x73;&#x74;` | `&#xH;` for every character, **lowercase** hex |
| `hex_escapes` | `\x74\x65\x73\x74` | `\xHH` up to 0xFF then `\uHHHH`, **uppercase** |
| `octal_escapes` | `\164\145\163\164` | `\NNN` for every codepoint |
| `dec_entities` | `&#116;&#101;&#115;&#116;` | `&#N;` for every character |
| `unicode_escapes` | `\u0074\u0065\u0073\u0074` | `\uHHHH`, surrogate pairs, **uppercase** |
| `css_escapes` | `\74\65\73\74` | CSS `\HH` compact, **uppercase** |
| `css_escapes6` | `\000074\000065\000073\000074` | CSS `\HHHHHH`, **uppercase** |
| `burp_urlencode` | `test` | Burp `urlEncode` (key characters), space → `+` |
| `urlencode` (`url_encode`) | `test` | Java `URLEncoder`, space → `+` |
| `urlencode_not_plus` | `test` | `URLEncoder` with space → `%20` |
| `urlencode_all` | `%74%65%73%74` | `%XX` for every character, uppercase |
| `php_non_alpha` | `<?php $_[]++...?>` | PHP payload with no alphanumerics |
| `php_chr` | `chr(116).chr(101).chr(115).chr(116)` | `chr(N)` chain |
| `sql_hex` | `0x74657374` | `0x` + hex |
| `jwt` | `eyJ...` | JWT, args `algo,secret` (default `HS256,secret`) |
| `quoted_printable` | `test` | quoted printable, `=XX` uppercase |

### Decode (bonus)

`d_base32`, `d_base64`, `d_base64url`, `d_hex`, `d_sql_hex`,
`d_html_entities`, `d_html5_entities`, `d_url`, `d_burp_url`,
`d_quoted_printable`, `d_unicode_escapes`, `d_css_escapes`,
`d_octal_escapes`, `d_php_chr`, `d_jwt_get_header`, `d_jwt_get_payload`.

---

## 3. How faithful is it?

The ports were written against Hackvertor's `Convertors.java` and then checked
against **the real Java libraries**, not against guesses:

| Area | Reference used | Result |
| --- | --- | --- |
| `html_entities`, `html5_entities`, `hex_entities`, `dec_entities`, `hex_escapes`, `unicode_escapes`, `css_escapes`, `css_escapes6` | **unbescape 1.1.6.RELEASE jar, executed** through a JRE 8/Nashorn probe (`research/probe.js`, output in `research/probe-out.txt`) | 200/200 vectors byte-identical (`tests/golden.tsv`) |
| HTML named-reference tables | parsed straight out of unbescape's own `Html4EscapeSymbolsInitializer` / `Html5EscapeSymbolsInitializer` sources (`tools/ref/`) | 252 HTML4 names, 1446 HTML5 codepoints, first-declared name wins, identical to unbescape |
| `quoted_printable` | **commons-codec 1.15 jar executed** (Hackvertor pins 1.15) | matches: UTF-8, TAB/SPACE literal, `=`→`=3D`, CR/LF escaped, never wrapped, uppercase hex |
| `urlencode`, `urlencode_not_plus`, `urlencode_all` | JDK 17 `URLEncoder` | matches, including the `-_.*` literal set and `%7E` for `~` |
| JWT | `JWTTest.java` full-token assertions | HS256/HS384/HS512/NONE and the error strings match |
| base32/base64/hex/php/sql/etc. | Hackvertor's own JUnit suite (`ConvertorTests`, `ConvertorTestsBasic`, `HackvertorAllTagsUiTest`) | matching vectors in `tests/vectors.tsv` |

### Deliberate deviations

1. `urlencode_all` on **astral** characters (e.g. 😀). Hackvertor calls
   `str.charAt(i)` on a UTF-16 code unit there, so it emits `%3F%3F`. This port
   emits the correct UTF-8 `%F0%9F%98%80`. (BMP characters are identical.)
2. `d_url` with invalid UTF-8 (e.g. `%FF`): Java's `URLDecoder` substitutes
   U+FFFD, this port emits the raw byte. Invalid `%` escapes *are* handled like
   Hackvertor, which returns the input unchanged.
3. `burp_urlencode` is the one tag whose exact Java behaviour cannot be
   reproduced from public information: PortSwigger publishes no character list
   for the legacy `IExtensionHelpers.urlEncode`. This port implements the
   documented "key characters" behaviour (alphanumerics plus `-_.~/` literal,
   space → `+`, everything else percent encoded), which reproduces the known
   ground truth `burp_urlencode("Hello World") == "Hello+World"` and the
   observed Burp Encoder output `hello ~ // ##` → `hello+~+//+%23%23`. If you
   need the strict Java `URLEncoder` behaviour instead, use `-urlencode`.
4. `jwt` re-serialises the payload compactly while preserving member order
   (org.json does the same for the vectors Hackvertor's tests assert), and it
   uses UTF-8 where the JVM would use the platform charset.

---

## 4. Building and testing

```sh
# regenerate the entity tables from the vendored unbescape initialisers
python3 tools/gen_tables.py --output lib/entity_tables.sh

# splice them into the single-file deliverable (idempotent)
python3 tools/build.py

# rebuild the test fixtures (jar output + Hackvertor test-suite vectors)
python3 tools/make_golden.py

# run the suite
bash tests/run-tests.sh          # add -v to print every case name
```

`tests/run-tests.sh` compares byte for byte through temporary files, so binary
results, embedded newlines and high bytes are all covered: ~320 cases.

### Layout

| Path | Purpose |
| --- | --- |
| `hackvertor.sh` | the tool (single file, self-contained) |
| `hackvertor`, `hackvertor.cmd` | convenience wrappers so it can be called as `hackvertor` |
| `tests/run-tests.sh`, `tests/golden.tsv`, `tests/vectors.tsv` | test suite and fixtures |
| `tools/gen_tables.py`, `tools/build.py`, `tools/make_golden.py` | generators |
| `tools/ref/` | vendored unbescape 1.1.6 initialiser sources + Apache-2.0 licence |
| `research/` | evidence: the Nashorn probe against the real unbescape jar, its raw output, a source-faithful Python port that was diffed against the jar |
| `original-example/` | the vendored Hackvertor checkout the ports were written from |

`research/`, `_research/`, `encoder-behavior-report.md`, `fetch.js` and
`tools/probe.sh` are investigation artefacts, not part of the tool.
#   m y - h a c k e r v e c t o r  
 