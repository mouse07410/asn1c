# CBOR standards review

Reviewed on 2026-11-12 against the IETF Datatracker. This is an ASN.1-to-CBOR
mapping, with a bounded Rust subset, rather than a general CBOR object model.
The [working-group document list](https://datatracker.ietf.org/wg/cbor/documents/)
can lag individual document revisions; the revisions below were checked directly.
Internet-Drafts are work in progress, and this review does not turn their
requirements into published RFC requirements.

## Applicable binary format requirements

[RFC 8949 / STD 94](https://datatracker.ietf.org/doc/html/rfc8949) remains the
base binary format. The current
[serialization draft, revision 12](https://datatracker.ietf.org/doc/html/draft-ietf-cbor-serialization-12)
was published October 30, 2026. Section 4 defines preferred-plus serialization:
shortest arguments and exact floating-point widths, definite containers,
normalized NaN, and minimal bignums. It permits implementations to support
explicit subsets of types and ranges.

Changes made by this review:

- C REAL and NativeReal decode binary16, binary32 and binary64. Encoding chooses
  the shortest exact width, preserving negative zero and subnormals; NaNs use
  `f9 7e 00`. Explicit `cbor_encode_float64` remains available for fixed-width use.
- C INTEGER uses major type 1 throughout its full range down to `-2^64`.
  Smaller negative values use tag 3 without leading zero magnitude octets.
  C bignum decoding accepts leading zeros and empty magnitudes.
- Rust bounded INTEGER decoding accepts tags 2 and 3 when the resulting value
  fits the supported signed range and schema constraints. Leading zeros and
  empty magnitudes are accepted; larger values fail without narrowing.
- Both runtimes reject `f8 00` through `f8 1f`, which are malformed simple
  values under RFC 8949 section 3.3; these are not merely nonminimal encodings.
- Both runtimes' unknown-item scanners accept indefinite arrays, maps and chunked strings
  under RFC 8949 section 3.2. Chunks must have the correct definite string type,
  each text chunk must independently be UTF-8, and a map cannot end after a key.
  C nesting is capped at 128 even with stack checks disabled. Caller stack
  limits can impose a smaller bound. Rust retains its existing 64-level bound.

Typed ASN.1 strings, maps and arrays still use definite lengths. Encoders use
schema/list order for maps and collections. This is not a claim of RFC 8949
core deterministic encoding or the draft's deterministic serialization, which
requires bytewise lexicographic sorting of encoded map keys. Decoders accept
nonminimal integer/length heads. The Rust generator still has no CBOR REAL
mapping or arbitrary-precision CBOR INTEGER API; runtime changes do not expand
its accepted schema families.

## Other RFCs and current drafts

| IETF specification | Applicability to this repository |
| --- | --- |
| [RFC 8742, CBOR Sequences](https://datatracker.ietf.org/doc/html/rfc8742) | A sequence concatenates independent CBOR items. Prefix decoders report consumed bytes, allowing callers to iterate. ASN.1 SEQUENCE remains a map; it is not a CBOR Sequence. No new framing is added. |
| [RFC 8746, typed arrays](https://datatracker.ietf.org/doc/html/rfc8746) | Optional tag-specific packed numeric arrays; ASN.1 collections retain their existing ordinary array mapping. No typed-array semantic API is provided. |
| [RFC 8943, dates](https://datatracker.ietf.org/doc/html/rfc8943) and [RFC 9581, time/duration/period](https://datatracker.ietf.org/doc/html/rfc9581) | Application-specific tagged representations. Existing ASN.1 time mappings are retained; no automatic date conversion or validation of these tag semantics is claimed. |
| [RFC 9090, object identifiers](https://datatracker.ietf.org/doc/html/rfc9090) | Tags 111 and 110 describe OID and relative-OID byte strings. Generic tag emission is available in C. Existing untagged ASN.1 byte-string encoding is retained; tag presence alone does not establish semantic validation. |
| [RFC 9164, network addresses](https://datatracker.ietf.org/doc/html/rfc9164) | Address/prefix-specific tags and structures are application data. No automatic interpretation as ASN.1 OCTET STRING is introduced. |
| [RFC 9277, stable storage](https://datatracker.ietf.org/doc/html/rfc9277) | File magic and media-type conventions belong to application framing. The codec emits individual items without adding a file header. |
| [RFC 8610, CDDL](https://datatracker.ietf.org/doc/html/rfc8610), [RFC 9165](https://datatracker.ietf.org/doc/html/rfc9165), [RFC 9682](https://datatracker.ietf.org/doc/html/rfc9682), [RFC 9741](https://datatracker.ietf.org/doc/html/rfc9741) | CDDL syntax and control operators do not change the binary format. This compiler consumes ASN.1; no CDDL parser is claimed. |
| [CDDL modules draft, revision 07](https://datatracker.ietf.org/doc/html/draft-ietf-cbor-cddl-modules-07) | CDDL module structure is outside the ASN.1 parser and binary codec. |
| [Diagnostic notation draft, revision 29](https://datatracker.ietf.org/doc/html/draft-ietf-cbor-edn-literals-29) | Published October 31, 2026; specifies textual diagnostic notation. The binary codec does not expose a diagnostic-notation parser/printer. |

Expired/parked drafts listed by the working group, including Packed CBOR and
Common Deterministic Encoding, do not create new normative requirements here.
Related individual drafts such as dCBOR define additional profiles; no dCBOR,
Packed CBOR or diagnostic-notation conformance is claimed.

## Security and compatibility

Tag-transparent decoding is an existing application policy, not validation of
registered tag semantics. Except for INTEGER's bignum handling, callers must
validate tag/content combinations when their protocol needs them. Raw structural
scanning also does not detect duplicate generic map keys; typed record decoders
retain their own duplicate-key checks.

Malformed simple-value rejection closes a parser disagreement on unknown
fields. Bounded scanner traversal prevents stack exhaustion through the public
no-context helper, including sanitizer builds. Length arithmetic is checked
before pointer advancement; indefinite string validation allocates no joined
payload. Rust bignum conversion checks work limits, overflow and schema bounds.
The new accepted numeric encodings broaden interoperability. Shorter REAL and
negative INTEGER encodings change emitted bytes without changing their values;
applications comparing historical bytes or hashes must account for that change.

Regression coverage includes RFC float vectors, integer representation boundaries,
empty/padded bignums, malformed simple values, truncated input, chunk rules,
map parity and nesting limits. The scanner test also exercises all 65,536
two-byte inputs to check returned bounds; this is a bounded exhaustive check,
not a claim of an extended fuzzing campaign.

## Optional sanitizer fuzz target

From the repository root, with a Clang installation that includes libFuzzer:

```sh
clang -g -O1 -fsanitize=fuzzer,address,undefined \
  -DASN_DISABLE_STACK_OVERFLOW_CHECK -I. -Iskeletons \
  tests/tests-skeletons/fuzz-CBOR-support.c skeletons/cbor_support.c \
  -lm -o /tmp/asn1c-cbor-fuzzer
/tmp/asn1c-cbor-fuzzer -max_total_time=30 -max_len=8192
```

This exercises arbitrary structural items and exact float encode/decode round
trips, including zero sign and NaN handling. The explicit scanner depth bound
is tested with compiler stack checks disabled. Extend the duration and supply
a persistent corpus directory for longer campaigns.

## Validation for this review

- All 69 C skeleton checks passed in the configured ASan/UBSan build; the
  normal, C89 and strict skeleton libraries built successfully.
- Compiler `check-parsing.sh` passed.
- All 269 Rust runtime tests and strict Clippy passed with all targets/features
  and the pedantic/nursery groups enabled as errors.
- Generated CBOR primitive, SEQUENCE, string, SEQUENCE-with-strings and CHOICE
  fixtures passed C interoperability execution, Rust tests and exact strict
  Clippy checks, using the existing backend script's CBOR blocks.
- Independent ASan/UBSan checking covered all 65,536 binary16 patterns.
- The final standalone ASan/UBSan/libFuzzer run completed 18,815,018 inputs in
  31 seconds without a failure; this is a short smoke campaign.

The generated C primitive interoperability fixture emits two warnings about
its existing spelling of the minimum signed 64-bit integer literal. Those
warnings remain unresolved by this CBOR runtime change. Whole-crate Rust
format checking also reports pre-existing differences in untouched `src/lib.rs`;
the edited CBOR module passes its targeted format check. The full repository
suite was not run.
