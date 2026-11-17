# Issue #611 and PR #612 review

Review date: 2026-11-17.

## Attribution and scope

The original diagnosis, unsigned-span implementation, and initial regression
coverage are by Javier ([@mr-j0nes](https://github.com/mr-j0nes)) in
[PR #612](https://github.com/mouse07410/asn1c/pull/612), fixing
[issue #611](https://github.com/mouse07410/asn1c/issues/611).
The author's commit is retained. Maintainer follow-up adds documentation,
stronger regression coverage, and watchdog lifecycle hardening. The supervising agent retained integration and acceptance responsibility;
Terra independently reviewed security and Rust relevance, and Luna implemented
bounded documentation, test, watchdog, and emitter-refactoring changes.
The supervisor reviewed their output and performed additional validation.

The review covers the compiler's PER width calculation, its alphabet and
empty-range paths, the new parser helpers, generated C and Rust behavior,
and every Copilot review thread available on the PR. It does not establish
that the entire compiler or runtime is free of vulnerabilities.

## Defect and security assessment

The old calculation forms `1 + right - left` in a signed compiler integer.
Even `1 + INTMAX_MAX` is undefined behavior. With no `__int128`, a full signed
64-bit interval can produce zero range bits rather than 64. The signed
`cover *= 2` loop can also overflow before reaching a wide interval's count.
The consequences include compiler failure under UBSan and incorrect emitted
PER metadata, potentially corrupting wire encodings or decoding behavior.
This review did not demonstrate remote code execution or a new runtime
memory-corruption exploit.

The replacement casts both endpoints to the matching unsigned type **before**
subtracting. For ordered signed endpoints the mathematical span fits that
unsigned type; modular subtraction recovers it even across zero. The span's
bit length equals `ceil(log2(right - left + 1))` without constructing the
possibly unrepresentable count. Unsigned wrap is intentional, defined C
behavior; it is not signed-overflow undefined behavior. A singleton needs zero
bits, and a reversed interval returns zero defensively. The fixer continues to
reject reversed user ranges before code generation.

The alphabet path retains its character-count semantics and uses the bit
length of `count - 1` only when the count is positive. Empty intervals still
have zero bits. The effective-width condition is equivalent to the former
loop for valid intervals: use the range width when at most 16 bits and the
upper bound is below 65536, otherwise use -1. Existing safeguards against
emitting unsupported C bound literals remain in effect.

No new consequential vulnerability was identified in these reviewed paths.
The new arithmetic allocates no memory, dereferences no user pointers, and
runs for at most the compiler integer's bit width. New tests exhaust all
4,225 endpoint pairs in [-32, 32], both sides of every unsigned power-of-two
boundary, and full configured-width signed extrema. No new fuzz harness is
needed for this bounded arithmetic; this review did not run extended fuzzing.

## Copilot comments and follow-up

All four original Copilot threads had been resolved by the author at reviewed
head `1a6534e38e910d35743291f8e273340d9558da95`:

1. **Oversized or empty deadlines:** verified unset-only defaulting, decimal
   syntax checks, and a four-digit length guard before numeric comparison.
   Invalid empty, zero, leading-zero, oversized, and out-of-range values are
   tested and rejected with status 2.
2. **Signal cleanup:** verified the author's active command/timer tracking and
   exit/signal cleanup. Follow-up defers signal exits until both PIDs are
   recorded, tracks and reaps timer sleep children, and makes fake compilers
   reap their children. External HUP, INT, and TERM probes with a one-hour
   configured deadline confirm prompt exit, compiler reaping, and removal of
   temporary files.
3. **Effective-width simplification:** verified removal of the intermediate
   sentinel 17; regressions assert both range_bits and effective_bits for full
   64-bit, positive 63-bit, singleton, 16-bit, 17-bit, and crossing-65536 ranges.
4. **Dedicated arithmetic test helper:** retained the author's extraction,
   corrected indentation and documentation placement, and broadened coverage.
   The applicable user function-size bound is 200 lines; Copilot's separate
   50-line claim is not treated as an overriding user requirement.

The watchdog is for a direct, trusted compiler process. It is not a sandbox
or process-tree supervisor. Shell PID liveness checks and signals cannot be
atomic: PID reuse and an exit exactly at a deadline remain best-effort races,
as in the existing reversed-range watchdog. Deadline markers remain
failure-authoritative even when TERM is caught and the compiler exits zero.
A prompt-exit self-test has scheduling headroom rather than a one-second
false-timeout window.

## Rust relevance

Rust uses the shared parser/fixer but does not use the C PER metadata emitter.
The generator validates and formats i64 bounds without calculating this
signed count. The runtime widens bounds to i128 before subtraction and
calculates widths in u128; its UPER and APER offset arithmetic also widens.
No matching Rust production arithmetic change was necessary.

The C emitter now delegates width calculation and courtesy-comment emission
to documented static helpers. This preserves output and keeps each modified
unit below 200 lines and a source-level McCabe complexity of 20 (counting
short-circuit operators and ternaries, before macro expansion).

The existing generated constraint-range regression covers full signed i64
extrema and neighbours, narrow ranges, malformed constraints, and (on a
128-bit compiler build) rejection of bounds outside Rust's i64 support.
It now also generates `INTEGER (0..9223372036854775807)`, rejects -1, and
round-trips 0, 1, MAX-1, and MAX through both codecs, asserting 63 UPER bits.
The original C fix remains credited to PR #612's author.

## Validation and limitations

Validation details are recorded here for reproducibility. Configure's default
sanitizers instrument runtime tests; the separate no-128 compiler build
explicitly supplies `CFLAGS='-O1 -g -fsanitize=address,undefined
-fno-sanitize-recover=all'` so compiler arithmetic itself is instrumented.

- On base `e34d2aad`, the explicitly instrumented no-128 compiler reproduces
  issue #611: full64 generation terminates at `asn1c_C.c` with UBSan reporting
  signed overflow in `1 + 9223372036854775807`.
- The fixed compiler passes the expanded boundary script with ASan/UBSan
  instrumentation on the no-128 build, including the final emitter refactor.
  Parser unit tests pass (1/1) in that build.
- Direct ASan/UBSan parser arithmetic tests pass with both 64-bit and 128-bit
  compiler integers. Native parser unit tests also pass (1/1).
- Generated C full64 codecs pass 14 UPER/APER round trips over MIN, MIN+1, -1,
  0, 1, MAX-1, and MAX, under both default and explicit wide-type generation.
  The default full64 representation is `INTEGER_t` in the no-128 build.
- HUP, INT, and TERM interruption probes pass with exit statuses 129, 130,
  and 143 respectively and no surviving direct compiler process.
- All 269 Rust runtime tests pass with all features enabled.
- Generated Rust constraint-range checks pass on both compiler integer widths:
  three conformance tests and seven malformed/unsupported-option rejection
  cases, plus five out-of-i64 backend rejection cases on the 128-bit build.
  The no-128 build skips those five backend-only cases, since its parser
  cannot represent those bounds.
- Focused Rust runtime tests `integer_thresholds_round_trip` and
  `supports_bounded_integer_shapes` pass. Runtime strict Clippy passes with
  exactly `cargo clippy --all-targets --all-features -- -W clippy::pedantic
  -W clippy::nursery -D warnings`. The generated Rust regression also invokes
  these strict Clippy settings for its generated crate.

The initial broad no-128 compiler-suite run exposed a pre-existing parsing
reference mismatch (notably fixture 90's signed/unsigned C representation).
The normalized generated fixture-90 output is identical on the base and PR
revisions. This is not reported as a clean no-128 full-suite result.
An interim boundary-test run during follow-up editing failed; the missing
self-test helper reference and nonzero-status capture were corrected before
acceptance and the finished script was rerun.

Generated full64 C still has pre-existing signed-minimum literal warnings
under Clang; promoting them to errors with `-Werror` prevents compilation.
This PR does not change literal emission. The existing policy of falling back
to unconstrained C metadata for unrepresentable compiler-width bounds is
unchanged; the helper's 128-bit tests do not claim a 128-bit C runtime.
