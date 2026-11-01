# Generated Rust compiler tests

`check-rust-backend.sh` exercises the first generated Rust slice in a temporary
directory. Its generated conformance cases cover BOOLEAN, NULL, bounded and
singleton INTEGER, and a full `i64`-range INTEGER with UPER. It checks CER
encodings for BOOLEAN, NULL, and bounded signed `i64` INTEGER against fixed
vectors; selected `Count`, `Singleton`, and `SignBounds` values are also
compared with a separately generated C encoder. Rust-produced CER TLVs are
passed to the generated C decoder for semantic checks, and the
`cer_strict_decode_interop` case decodes live C-generated CER vectors with
the generated Rust `decode_cer` and checks hostile rejections. The Rust crate
builds offline with its copied runtime.

The BER/DER extension adds generated `decode_ber` and `encode_der` methods for
the same primitive types when `-gen-BER` is selected. Tests check canonical DER
bytes against independent vectors and C-produced primitive TLVs, BER prefix
consumption, noncanonical but accepted BER forms, malformed input, and bounds.
The harness also generates a BER-only crate to check codec selection.

The APER/OER primitive extension adds opt-in paired encode/decode methods for
the same direct BOOLEAN, NULL, and bounded INTEGER subset. The harness builds
each codec alone and together, runs generated Rust vectors and malformed-input
checks, and compares selected APER/OER bytes with a separately generated C
fixture. Runtime tests cover additional alignment and integer-width edges.

The opt-in JER slice checks compact BOOLEAN, NULL, bounded INTEGER, and
nonextensible ENUMERATED tokens. ENUMERATED values map to their ASN.1 names as
JSON strings; decoding accepts JSON whitespace and requires one complete,
known string. Tests reject unknown names, escapes, trailing JSON values, and
input/output/work limit violations. Generated C code independently encodes
fixed primitive tokens and decodes Rust-generated JSON files for comparison.
Direct fixed-size OCTET STRING and BIT STRING assignments support JER
hexadecimal strings, alone or with UPER. Direct bounded OCTET STRING
assignments use the same quoted uppercase hexadecimal form; bounded BIT STRING
assignments use the C-compatible `value`/`length` JSON object. Tests compare
fixed and bounded string values with generated C in both directions, accept
lowercase hex input, and reject malformed tokens, wrong sizes, nonzero padding,
unsupported forms, and exhausted limits.

The UPER-only SEQUENCE slice packs required and OPTIONAL direct BOOLEAN, NULL,
bounded INTEGER, fixed string, and inline nested SEQUENCE fields, plus literal
BOOLEAN and bounded INTEGER DEFAULT fields (including inside nested records),
with one bit cursor and one cumulative resource budget.
Tests cover declaration-order OPTIONAL/DEFAULT presence bits, omitted and
present defaults, an OPTIONAL interleaved bitmap crossing an octet, cross-byte
packing, zero-width fields and whole-value filler, full `i64` bounds, truncation,
and exact work/input/output ceilings. The C fixture checks both C encoding of
Rust vectors and C decoding of a Rust-compatible present-default vector.
Default UPER/CER selection rejects SEQUENCE until CER support exists; unsupported
DEFAULT forms, nested constructed DEFAULTs, extensions, excessive nesting or
aggregate field-work, generated-name collisions, and top-level tagged types fail
before publication. Required and OPTIONAL inline records each write their own
presence bitmap immediately before payload. Private record helpers share the
top-level cursor, budget, and final filler. The automatic component tags in
`SequenceDefaults.asn1` are covered by live C encode/decode parity vectors.
The fixed-size string fixture covers standalone OCTET STRING and BIT STRING,
zero-sized values, bit packing inside a mixed SEQUENCE, malformed lengths and
pad bits, truncation, and whole-operation budgets. It also checks that the
default UPER/CER selection rejects strings without CER support.
The bounded OCTET STRING fixture adds one direct nonextensible contiguous
`SIZE(l..u)` range with `0 <= l < u < 65536`, encoded by UPER for standalone
values and SEQUENCE fields. Direct assignments also support opt-in JER and
compare quoted hex with C vectors. UPER vectors cover standalone lengths,
OPTIONAL and required fields in a shared SEQUENCE cursor, spare length codes,
truncation, resource ceilings, and generated C comparisons. Extensible sizes
and disjoint size unions still fail before output publication.
The bounded BIT STRING fixture carries its exact logical bit length alongside
the packed octets. It checks non-octet standalone vectors, required and OPTIONAL
SEQUENCE fields, spare codes, truncation, zero padding, resource limits, and
generated C comparisons. Extensible ranges, disjoint unions, upper bounds at
65536, and variable `NamedBitList` forms fail before publication.
Direct ENUMERATED tests cover numeric index ordering, spare indexes,
singleton framing, budgets, extension rejection, and live C comparisons.

The harness covers codec selection as well as wire behavior. The default Rust
mask contains UPER and CER; `-gen-UPER` retains both, `-no-gen-UPER` selects
CER-only output, and `-no-gen-CER` leaves UPER enabled. `-gen-BER` adds BER/DER
methods and `-no-gen-BER` omits them. APER/OER/JER are opt-in and can be selected
independently. CER-only generation is
also checked with explicit `-gen-CER -no-gen-UPER`; `-no-gen-BER` leaves CER
selected. Disabling all supported codecs and requesting
unsupported XER shapes are rejected before output publication. The generated
dual-codec and CER-only APIs are checked to contain `decode_cer`, and the
`-no-gen-CER` output is checked to omit it.

C remains a comparison implementation rather than a protocol oracle. Fixed
vectors and Rust-side malformed-input checks provide independent checks. The
exact supported scope and unimplemented families are listed in
[`coverage.json`](coverage.json); the harness does not claim codec-wide or
type-wide parity.

If Cargo or `rustc` is unavailable, Automake marks the test skipped with status
77.

Negative compiler cases cover unsupported types, constraints, selectors, and
name collisions before output publication. Destination checks cover unrelated
files, interior symlinks, traversal entries, oversized ownership manifests,
and deterministic regeneration. Runtime-name overlaps are positive compilation
cases. `LIB`, `Core`, and `Asn1cRuntime` modules are checked for safe filenames
and pass an offline Cargo check.

The harness is registered in the normal test suite. It can also be run from a
configured build tree with:

```sh
make -C tests/tests-rust-compiler check
```

Inline nonextensible ENUMERATED SEQUENCE members support UPER as required or
OPTIONAL fields. Their indices follow numeric value order, and singleton values
consume no payload bits. Tests compare presence and payload vectors with C,
and reject truncation and spare indices.

Rust supports unqualified ANY at top level with UPER, APER, OER, JER, and CBOR,
and as required or OPTIONAL UPER SEQUENCE fields. Values are represented as
opaque octets, including fragmented PER length determinants. The payload is
not interpreted as an ASN.1 value; callers supply its transfer syntax. Other
codecs and selector-driven ANY remain unsupported.

Unconstrained BIT STRING and OCTET STRING with CONTAINING support UPER
at top level or as required/OPTIONAL SEQUENCE fields when the contained type
is a same-module direct BOOLEAN or a bounded, non-singleton INTEGER. Inline forms are promoted to local type assignments.
Generated wrappers hold the typed inner value. Decoding validates the outer
length, inner range and OCTET STRING padding with a single operation budget.
SIZE combinations, singleton integers, constructed contents, and other
encodings are rejected before output publication.
A narrow UPER, APER, and OER information-object OPEN TYPE subset supports a two-field
required SEQUENCE with a bounded INTEGER selector and a local nonextensible
object set of direct BOOLEAN or bounded INTEGER rows. The generated enum is
checked against its selector, and malformed inner lengths, values and padding
are rejected. APER requires selector bounds 0..255 and selected INTEGER range
spans at most 255. Other object-set and codec forms are rejected.

Direct BOOLEAN, NULL, bounded signed INTEGER, and opaque ANY support opt-in
CBOR. Definite byte strings represent ANY. Decoding accepts semantic tags and
nonminimal definite heads, but rejects INTEGER bignum tags, indefinite strings,
invalid or truncated data, and exhausted resource budgets. C interoperability
tests cover primitive boundaries and opaque byte-string lengths.

`CborSequence.asn1` exercises flat CBOR SEQUENCE maps with required and
OPTIONAL primitive fields, OPTIONAL ANY, and a bounded INTEGER DEFAULT. Rust
and generated C compare the same declaration-order wire vector. Rust decoding
also checks unordered keys, omitted OPTIONAL/default fields, unknown definite
nested values, duplicate and missing keys, malformed values, and resource
limits. CBOR nested SEQUENCE, SET, SEQUENCE CONTAINING, and
extension groups remain gated before Rust output is published.

`CborStrings.asn1` covers fixed and bounded BIT/OCTET STRING values, zero
lengths, exact bit length, unused-bit padding, malformed heads, SIZE checks,
and resource limits. Generated C and Rust compare the same byte-string vectors.
`CborSequenceStrings.asn1` puts those strings in required and OPTIONAL fields
of a CBOR SEQUENCE map, with generated C/Rust wire parity and malformed-field
checks.

`CborChoice.asn1` covers the bounded direct CHOICE subset. Each alternative
uses the same one-entry text-key map as generated C. Tests cover BOOLEAN,
NULL, bounded INTEGER, and opaque ANY alternatives, plus unknown, duplicate,
multiple, malformed, truncated, and over-limit inputs.

`CborContaining.asn1` checks top-level local BOOLEAN and bounded INTEGER
contents. The Rust wrapper places a complete inner CBOR primitive inside the
ordinary C BIT/OCTET CBOR byte string. Decoding rejects non-octet BIT contents,
extra inner bytes, out-of-range integers, malformed inner types, and limits.
Generated C confirms the raw outer wire vectors; C constraint validation can
also parse the inner value with `ATS_CBOR`.

`OpenSelected.asn1` also exercises CBOR for the existing two-field
IOC-selected OPEN TYPE shape. The parent map contains the selector and direct
selected CBOR primitive. Generated Rust accepts either key order, rejects
missing, duplicate, or out-of-range fields, skips unique unknown fields, and requires the selected
primitive to consume its complete map value. Generated C confirms wire parity.

The opt-in BASIC-XER encoder-only slice supports flat SET and SEQUENCE records with
untagged or AUTOMATIC TAGS fields: direct BOOLEAN, bounded INTEGER,
unconstrained IA5String, and REAL DEFAULT
0.5 fields. REAL values must be finite, with magnitude at most 1,000,000 and
nonzero magnitude at least 1e-15, and their formatted decimal must round-trip.
BOOLEAN, INTEGER, and REAL DEFAULT fields use `Option`, with `None` emitting the default;
OPTIONAL fields are omitted when absent. Select XER alone with `-gen-XER
-no-gen-UPER -no-gen-CER`. Other REAL defaults and shapes, mixed codecs, canonical XER,
and XER decoding are not supported. Output and work limits apply to the whole
XML value; IA5 text accepts tab, line feed, carriage return, and ASCII 0x20–0x7f.
Other IA5 controls and their XER control elements are unsupported. Carriage
return is emitted as `&#xD;` to preserve it through XML line-ending normalization.
