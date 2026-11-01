# Rust conversion: first stage

This directory defines the first stage of converting asn1c to Rust: generate Rust
types and codecs backed by a Rust implementation of the runtime currently in
`skeletons/`, and migrate the relevant codec tests. The compiler frontend remains
in C during this stage. The implemented Rust runtime covers selected UPER,
APER, OER, CER, BER, DER, and JER operations for BOOLEAN, NULL, and bounded INTEGER values;
the remaining runtime and codec coverage is an incremental conversion target.

The user authorized backend implementation on 2026-10-11. The selected mode is
`--rust`; codec coverage is incremental and uses safe Rust with `std`. The
current generated-code slice supports UPER encode/decode, CER encode/strict
decode, and opt-in APER/OER/JER encode/decode or BER decode/DER encode for BOOLEAN, NULL, and bounded
nonextensible INTEGER. Other types and codecs remain conversion targets.
An explicit UPER-only selection also supports SEQUENCE assignments with
required and OPTIONAL direct primitive or inline nested fields, BOOLEAN and
bounded INTEGER DEFAULT fields, and one cumulative resource budget. Direct
nonextensible fixed-size OCTET STRING and BIT STRING assignments and fields
are also supported with that selection.
Direct OCTET STRING assignments and SEQUENCE fields with one contiguous,
nonextensible `SIZE(l..u)` range (`0 <= l < u < 65536`) also support UPER
encode/decode. Direct bounded OCTET STRING assignments additionally support
opt-in JER encode/decode as quoted uppercase hexadecimal; that JER selection
can stand alone or accompany UPER. Extensible, unbounded, disjoint, and larger
ranges remain unsupported.
The same UPER-only subset supports nonextensible BIT STRING ranges with an
explicit packed value and exact bit length. Direct fixed and bounded BIT STRING
assignments also support opt-in JER with `-gen-JER`; bounded values preserve
their exact bit length in C's `{"value":"HEX","length":N}` object form.
`NamedBitList` forms remain unsupported, and JER for SEQUENCE string fields is
not available.
Direct nonextensible fixed-size OCTET STRING assignments additionally support
opt-in JER encode/decode with `-gen-JER`.
The same selection supports direct nonextensible ENUMERATED assignments;
JER is also available for those assignments when selected explicitly.
Direct nonextensible ENUMERATED values and fixed or bounded OCTET STRING and
BIT STRING assignments also support BER prefix decoding, DER encoding, and
CER encoding and strict decoding. This is a limited direct-type slice;
empty or flat SEQUENCE records with an untagged outer type and distinct
effective direct-field tags for BOOLEAN, NULL, bounded INTEGER, ENUMERATED,
and bounded BIT/OCTET STRING also support BER/DER/CER. Resolved
context-specific IMPLICIT and AUTOMATIC member tags are supported within the
C tag-number range. Root tags, EXPLICIT tag stacks, aliases, open types,
and broader constructed records do not yet have BER/DER/CER parity. See the
[parity design](ber-der-cer-design.md).
The same direct-field subset supports flat SET with an untagged outer type under a BER/CER-only
codec selection (`-no-gen-UPER`); BER decoding accepts any member order while
DER and CER encoding sort by effective tag class and number.

Start with the [architecture decision](architecture.md) and
[implementation plan](stage-one-plan.md). Supporting designs describe the
[runtime](runtime.md), [code generator](code-generation.md), and
[test migration](testing.md).

The baseline inspected for this plan is commit
`5a0ccf24ede9b176e8fd76861bf4855ed95f5105` on `vlm_master`.
Implementation must recheck that baseline against subsequent changes, especially
security fixes, schema semantics, and the test inventory.

Sol supervises implementation and accepts integration; three Luna agents own
bounded coding assignments. The plan specifies their dependencies, file
ownership, handoff requirements, and acceptance gates. No implementation agents
should treat a proposed interface in these documents as an existing API.

The implemented runtime API is documented in its
[crate README](../../rust/asn1c-runtime/README.md); see also the
[first implementation](implementation.md). The broader designs below
include proposed interfaces and features beyond this first runtime slice.
