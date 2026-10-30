# SET extension addition groups

This follow-up extends the transparent extension addition group handling from
[issue #583](issues-583-extension-groups.md) to `SET`. Issue #583 was reported
by Ruud Schramp (@Schramp); this SET implementation and its additional tests
were completed by the asn1c maintainers with Codex/Luna assistance.

## Encoding model

The bracketed members of a `SET` extension addition group are independent
members of the enclosing `SET`. BER, DER, CER, and XER do not encode a
synthetic group wrapper. The generated C value still stores each group behind
its existing nested pointer, and the synthetic group descriptor is a `SET`
with its own presence bitmap and mandatory-member mask. Parent metadata marks
the pointer with `ATF_EXTENSION_GROUP`; the parent tag-to-member map routes
each leaf tag to that group pointer, while the child map resolves the leaf
inside the group.

DER and CER collect group leaves together with ordinary `SET` members before
canonical ordering. CER orders each leaf by its static minimum effective tag,
including the minimum alternative tag for an untagged `CHOICE`, then encodes
the `SET` with indefinite length. A present group must contain every mandatory
leaf. An absent group is valid, and absent optional or defaulted leaves do not
produce BER-family components.

Canonical XER emits the root members sorted by their minimum effective tag,
then emits extension additions in textual declaration order. It includes
`DEFAULT` values when their enclosing group is present, but an absent group
does not materialize its internal defaults. The regression schema uses
a root `CHOICE` whose selected alternative has a higher tag than its static
minimum; this distinguishes CER's static ordering from ordering by the selected
wire tag. Its root `[20]` member also makes CER's tag order differ from XER's
root-first order.

The compiler does not reorder extension declarations. Under its interpretation
of X.680 clauses 27.3 and 29.8, it checks each current component's minimum
effective tag against the maximum effective tag exposed by preceding
components. For an untagged `CHOICE`, the minimum and maximum cover all
alternatives, so overlapping or out-of-order tag ranges are rejected. This
extension-order check is distinct from canonical XER root ordering, which uses
the minimum effective tag of a root `CHOICE`.

X.680 clause 25.1 allows a root component type list after an extension end
marker. The fixer restores such trailing roots to the root region before
assigning tags. The `31-set-of` compiler golden output now keeps its
`anything [2]` root component ahead of the extension additions instead of
treating it as an extension addition and retagging it. The extension tag-range
check follows the interpretation of clauses 27.3 and 29.8 described above.

UPER supports extensible `SET` values with individual extension additions.
Root components use canonical tag order, including roots after a second
extension marker; additions use declaration order and unknown additions are
skipped on decode. Regenerate C descriptors with the matching runtime: v2
metadata records the root and addition maps; addition storage must be
pointer-backed so absence is representable. A legacy extensible descriptor
fails closed, and the runtime reads appended metadata only for the v2 or v3 sentinel.

UPER, APER, and OER support SET extension addition groups. Each group uses
one extension bitmap bit and one open type; its body uses SEQUENCE declaration
order, with its own OPTIONAL and DEFAULT preamble. The canonical root order is
unchanged. A present group restores its missing DEFAULT values on decode; an
absent group remains absent. An allocated group with no encoded optional or
default values is omitted. Unknown groups are skipped as open types.

Group-bearing descriptors use v3 metadata to associate each synthetic SET
with a SEQUENCE wire layout. The C group structure and its SET descriptor
remain in use for BER, DER, CER, XER, and freeing. Regenerate group-bearing C
descriptors with the matching runtime; v2 and legacy group descriptors are
rejected by these binary codecs. JER represents group leaves as members of the
enclosing JSON object, as required by [X.697] clauses 27.3 and 29. The repository
has not defined a CBOR mapping for SET extension groups; grouped SET CBOR
encoding and decoding fail rather than emitting or accepting synthetic group
wrappers. JER unknown extension values use a bounded container skipper that,
like the existing JER skipper, does not fully validate JSON syntax. JER NAME
overrides containing control characters, quotes, or backslashes are rejected
for group-bearing SET encoding because escaped key matching is not implemented.
SET JER rejects table-selected open-type leaves pending dedicated support.
The parser has no version-prefix production for extension group notation.

The packed and octet encodings follow [x691] clauses 19.9 and 21 and [x696]
clauses 16.5.2–16.5.3 and 18. Regression coverage is in
[`600-set-codec-extension-groups-OK.asn1`](../tests/tests-asn1c-compiler/600-set-codec-extension-groups-OK.asn1).
It exercises independent UPER, APER, and OER wire vectors, trailing roots,
defaults, empty groups, older decoders, invalid metadata, and OER input splits.
[`601-set-jer-groups-OK.asn1`](../tests/tests-asn1c-compiler/601-set-jer-groups-OK.asn1)
covers flat JER output, input splits, group DEFAULT values, duplicate and
unknown keys, invalid metadata, and unsupported CBOR and open-type dispatch.

The tag-order validation follows [x680]. The encoding rules follow [x690]
(clauses 8.11 for BER SET, 9.3 for CER SET, and 10.3 for DER SET) and [x693]
(clause 9.6 for canonical XER).

[x697]: https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.697-202102-I%21%21PDF-E&lang=e&type=items
[x691]: https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.691-202102-I%21%21PDF-E&lang=e&type=items
[x680]: https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.680-202102-I!!PDF-E&lang=e&type=items
[x690]: https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-202102-I!!PDF-E&lang=e&type=items
[x693]: https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.693-202102-I!!PDF-E&lang=e&type=items

## Validation and resource bounds

The CER encoder checks the parent and child descriptor element counts before
traversing group children, validates group structure and presence-map bounds,
and checks member widths and offsets before reading values. The shared SET
member view used by BER and XER validates the complete storage width of inline
primitive and constructed members; unknown custom inline layouts fail closed,
while pointer-backed custom types use a validated pointer slot. Required
values are checked from stored fields rather than a decoder-populated presence
bitmap. Each CER leaf is charged to the existing work limit and retained in the
bounded scratch budget until canonical ordering is known. Group depth is
charged to the encoder's recursion limit.
Recursive SET XER decoding checks the caller's stack limit before descending
into a nested member; the regression uses a 128-level document with a
deliberately small bound. The repository's ASan build intentionally disables
the pointer-difference stack probe, so that build verifies clean decoding and
freeing while a non-ASan run verifies `RC_FAIL` at the configured bound.

The generated C structure layout for a synthetic group changes because its
descriptor is now a `SET` with a presence bitmap and mandatory mask. Regenerate
generated C and use it with the matching runtime and skeleton headers. Do not
mix descriptors and runtime versions.

The acceptance regression is
[`585-set-extension-groups-OK.asn1`](../tests/tests-asn1c-compiler/585-set-extension-groups-OK.asn1).
Compiler negative cases reject out-of-order extension leaf tags and duplicate
component names across the root and group. The focused C test checks flat
BER/DER/CER/XER behavior, canonical ordering, optional/default values,
mandatory group validation, malformed encodings and descriptors, and decoder
input splits. Malformed descriptor cases include invalid parent presence-map
offsets and inline native-integer offsets that leave less than a `long` of
storage, for both the parent `rootValue` and required group leaf `first`.

The final configured sanitizer run passed the focused C regression 1/1. The
full generated-C suite passed 75/75; normal, C89, and strict runtime suites
passed 59/59; all seven compiler scripts passed, with the parser and fixer
unit tests passing 1/1 and 2/2 earlier. A normal-build run also verified that
the recursive XER case returns `RC_FAIL` at the configured stack bound; the
ASan build disables the pointer-difference stack probe by design.
The final dependency audit added explicit source dependencies for the core
free-callback providers; a minimal SET PDU build with all codecs disabled
compiled, linked, and ran with 44 C sources.

An LLVM 22 libFuzzer build with ASan, UBSan, unsigned-overflow checks, and
LeakSanitizer enabled ran the BER, CER, and XER decoders for 1,201,498 inputs
in 16 seconds, with a 512-byte maximum input and no finding. To avoid a prior
libFuzzer RSS-monitor thread leak, the run used
`-rss_limit_mb=0 -purge_allocator_interval=-1`; LeakSanitizer remained enabled.
This bounded smoke run is not an exhaustive security proof.

An independent normal converter encoded a simple SET as DER
`31 0c 80 01 01 81 01 ff 82 01 03 84 01 02` and CER
`31 80 80 01 01 81 01 ff 82 01 03 84 01 02 00 00`. Strict CER decoding
followed by DER encoding produced byte-identical DER. The aggregate test
results are also linked from the [issues #582–#584 review](issues-582-584-review.md#validation).

During implementation review, regression cases caught draft-only errors before
acceptance: DER could pass the group owner address where a leaf value was
required; skipping an unknown nested XER element could affect routing of a
later known leaf; and a child XER decoder could report consumption beyond its
input. Tests also caught grouped `DEFAULT` leakage when the group was absent
and confusion between an absent first optional leaf and a populated group with
a later required leaf. These were corrected in the reviewed implementation;
they are not reported as defects in a released version.

OER individual-addition regression coverage is in
[`599-set-oer-individual-additions-OK.asn1`](../tests/tests-asn1c-compiler/599-set-oer-individual-additions-OK.asn1).
It checks an independently constructed wire vector, trailing roots, default values,
unknown additions, input splits, malformed bitmaps, and descriptor rejection.
The OER decoder accepts empty or all-zero extension maps for compatibility with
the existing SEQUENCE decoder, although X.696 requires the extension bit to be
clear when no additions are present. The encoder emits that conforming form.

[x696]: https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.696-202102-I%21%21PDF-E&lang=e&type=items
