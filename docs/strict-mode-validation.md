# Strict-mode validation and security review

Date: 2026-11-17. Base: `9ce1c071` (`vlm_master`).

Implementation and testing used a separate temporary clone. The existing
`~/src/asn1c` build and its source files were left untouched while that build
was active. On 2026-11-18, after confirming its original build processes had
exited, signed implementation commit `6cac70d9` was integrated into the main
`vlm_master` checkout. The compiler library and local executable were rebuilt
using the checkout's existing configuration, and the focused CLI regression
passed there. The pre-existing untracked `conf99104.file` was left untouched.
The original build's overall exit status was not captured by this chat.

## Executed checks

| Check | Result |
| --- | --- |
| `autoreconf -iv`, configure with static libraries, single-job compiler build | Passed |
| C default and strict generated-code fixture: every codec family, independent PER bytes, Unicode, XER syntax, streaming, DER, padding and unknown additions | Passed, including canonical PER relay; no sanitizer findings |
| Same C fixture under AddressSanitizer and UndefinedBehaviorSanitizer | Passed, including canonical PER relay; no sanitizer findings |
| Fast CLI test through Automake, including `-fbless-SIZE`, conflicts, duplicate/malformed switches, short-option operands and `--` | Passed, 1/1 |
| Main-checkout compiler library/executable rebuild and focused CLI regression after integration (2026-11-18) | Passed |
| Rust runtime `cargo test --offline` | Passed, 270 tests |
| Rust runtime `cargo test --offline --all-features` | Passed, 270 tests |
| Rust runtime Clippy, all targets/features, pedantic/nursery, warnings denied | Passed |
| Generated Rust test through Automake: default/strict scalar codecs, XER output, malformed data, feature propagation, unsupported PER strings, same strict Clippy settings | Passed, 1/1 driver; 7 integration tests |
| Shared C application/constraint/enum/CHOICE sources with each of BER, CER, UPER, APER, OER, XER, JER and CBOR selected individually, `-std=c11 -Werror -fsyntax-only` | Passed, 8/8 configurations |
| Shell syntax and `git diff --check` | Passed |

The sanitizer invocation uses:

```sh
top_srcdir=. top_builddir=. \
CFLAGS='-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer' \
ASAN_OPTIONS='detect_leaks=0:halt_on_error=1' \
UBSAN_OPTIONS='halt_on_error=1' \
bash tests/tests-asn1c-smoke/check-strict-mode.sh
```

LeakSanitizer was not run. Compiler bootstrap reported the existing six
shift/reduce and six reduce/reduce parser conflicts. Generated test schemas
exercise legacy T61String, VideotexString, GraphicString and GeneralString;
the compiler warns that their support is incomplete. These warnings are not
evidence of full repertoire validation. The entire existing `make check`
suite was not rerun for this patch; the focused tests above are the patch's
validation evidence.

## Security reasoning and independent review

A Terra reviewer independently examined policy propagation, direct versus
generic codec boundaries, streaming ownership, canonical verification and
extension handling. The supervising agent reviewed and integrated the fixes;
review findings were not accepted as proof without checking the owning code
and executing relevant regressions. Luna was unavailable in this session.

The main invariants checked are:

* Codecs validate complete decoded roots, preserving partial streaming values
  and ordinary failure ownership. Strict DER uses an explicit one-shot
  contract, freeing/resetting incomplete or failed values.
* Invalid encoder inputs fail before publishing any callback bytes.
* Abstract SIZE remains independent from PER-visible length metadata. Strict
  string subtypes retain their base repertoire/alignment checks.
* ENUMERATED membership examines the full native `long`; a narrow C enum
  cannot hide out-of-range high bits. Unknown PER markers remain bounded,
  follow every locally known extension ordinal, and relay losslessly.
* Decoder-produced skipped extensible CHOICE arms remain valid for input;
  unselected application CHOICE values are not thereby enabled for output.
* DER comparison is bounded by the consumed prefix and does not allocate a
  second encoded value. Opaque contents remain an explicit validation limit.
* Rust validation charges its extra character scans against the existing work
  budget. Exact-budget and one-below-budget tests cover both feature profiles.

The C fixture deterministically mutates short inputs across all format
families. Existing Rust character-string mutation tests run in both profiles
with valid per-repertoire seeds. These are bounded regression/fuzz-style
checks, not a long-running coverage-guided fuzz campaign or a conformance proof.
See [the policy contract](strict-mode.md) for API and support limits.
