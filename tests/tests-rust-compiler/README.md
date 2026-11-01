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

The first BER/DER/CER structured primitive expansion covers direct
nonextensible ENUMERATED values and fixed or bounded OCTET STRING and BIT STRING
types with finite SIZE constraints below 65536. ENUMERATED methods encode the
declared signed numeric value and reject decoded values absent from the root.
String decoders enforce the generated SIZE constraints, including exact logical
BIT STRING width when the packed storage byte count is unchanged. The harness
checks mixed UPER/BER/CER output, DER and CER vectors against live generated C,
prefix consumption, wrong sizes, malformed input, and named BIT STRING
rejection.

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
Default UPER/CER selection rejects SEQUENCE shapes outside the direct
BOOLEAN/NULL/bounded-INTEGER BER/CER subset; unsupported
DEFAULT forms, nested constructed DEFAULTs, extensions, excessive nesting or
aggregate field-work, generated-name collisions, and tagged roots under mixed
codec selection fail before publication. Required and OPTIONAL inline records each write their own
presence bitmap immediately before payload. Private record helpers share the
top-level cursor, budget, and final filler. The automatic component tags in
`SequenceDefaults.asn1` are covered by live C encode/decode parity vectors.
The second BER/CER SEQUENCE slice supports empty records and flat, untagged
records with unique BOOLEAN, NULL, and bounded INTEGER universal tags. Required,
OPTIONAL, BOOLEAN DEFAULT, and INTEGER DEFAULT members preserve declaration
order; DER omits default literals, BER decoding substitutes omitted defaults,
and CER decoding verifies the complete canonical record against the same
operation budget. Tests include fixed C encoder parity vectors, empty CER
framing, unknown/duplicate/reordered fields, truncation, range violations, and
resource ceilings. The initial untagged slice rejected tagged, automatic-tagged,
nested, duplicate-tag, unbounded, and unsupported DEFAULT shapes before crate
publication. The fixture also builds all three codec families together with
UPER and runs strict Clippy.
The third BER/CER SEQUENCE slice adds direct inline ENUMERATED and finite fixed
or bounded OCTET STRING and BIT STRING fields. New members may be required or
OPTIONAL; enum wire values use their declared ASN.1 numbers. Records remain flat,
nonextensible, and limited to six unique effective tags. At this stage members
use universal tags. New kinds do
not accept DEFAULT, named bits, CONTAINING, aliases, or unsupported size ranges.
Mixed UPER/BER/CER tests and BER-only/CER-only builds check selector-sensitive
emitters. C comparisons cover DER length edges at 125/126 and 127/128 OCTET
bytes, CER OCTET thresholds at 1000/1001, and CER BIT content thresholds at
999/1000 payload octets. BER constructed OCTET/BIT fields, strict CER rejection
of noncanonical fragments, unknown enum values, and cumulative record budgets
are also covered.
The fourth BER/CER slice adds flat SET records with unique direct
BOOLEAN, bounded INTEGER, fixed or bounded BIT/OCTET STRING, NULL, and inline
nonextensible ENUMERATED members. SET members remain in declaration order in
the Rust struct; DER and CER encode them in ascending universal-tag order. BER
decoding accepts arbitrary child order, while strict CER rejects noncanonical
ordering by re-encoding the record under the same resource context. Required,
OPTIONAL, and literal BOOLEAN/INTEGER DEFAULT fields are covered, as are empty
SET framing, string fragmentation, malformed fields, codec selectors, and
negative shape gates. The generated C parity schema exercises nonempty SET
cases. It excludes the Rust empty SET fixture because the current C generator
emits an empty C enum for that type, which strict C compilation rejects; empty
SET vectors are tested with the generated Rust wrapper and runtime.

The fifth BER/CER slice supports fixed resolved context-specific IMPLICIT tags
on the same flat SEQUENCE and SET fields. The generator reads the tags from the
fixed AST, including AUTOMATIC TAGS, and validates tag class, mode, range, and
uniqueness before publishing output. The C-compatible maximum is
`0x3fffffff`. SEQUENCE retains declaration order and can still combine UPER
with BER/CER; SET remains BER/CER-only and sorts by effective class and number.
Required, OPTIONAL, and supported BOOLEAN/INTEGER DEFAULT behavior is preserved.
Tests cover tags 30, 31, 127, 128, and the maximum; malformed/nonminimal high
tags; BER prefix consumption and arbitrary SET ordering; strict CER canonical
re-encoding; tagged constructed strings; resource limits; and selector-only
strict Clippy. C parity checks DER/CER encoding and decoding for tags 31/128,
AUTOMATIC TAGS, mixed universal/context SET order, BER redundant-tag aliases,
and CER-fragmented tagged OCTET/BIT STRING values. The C parity schema omits the
empty SET because current C code generation produces an empty enum that fails
strict C compilation; the empty SET case is checked through the Rust wrapper.

The tagged-root SEQUENCE slice accepts one context-specific IMPLICIT tag on a
flat top-level SEQUENCE with direct supported fields, and only when BER/CER are
the selected codecs. It keeps one `RecordContext` across the root wrapper,
fields, and strict CER re-encoding. Tests cover tags 0, 3, 30, 31, 127, and
`0x3fffffff`; definite and indefinite BER; canonical DER/CER bytes; prefix
consumption; malformed root forms and EOC; nonminimal BER aliases rejected by
strict CER; input/output/work limits; and rejection of mixed codecs, aliases,
extensions, nested members, EXPLICIT tags, and non-context-specific classes.
Empty records and OPTIONAL/DEFAULT fields retain their normal presence behavior.
The parser rejects stacked-root syntax before Rust generation.
The generated C fixture checks DER/CER parity for `[3] IMPLICIT SEQUENCE`,
tags 31 and `0x3fffffff`, BER/CER decoding, indefinite BER, and the nonminimal
root alias.

The tagged-root SET slice accepts one context-specific IMPLICIT tag on a flat
top-level SET for BER/CER-only selection. DER and CER retain SET field sorting
by effective class and number, while BER accepts arbitrary field order. Tests
cover reverse-declaration C vectors, mixed universal/context-specific child
tags, root tags 0, 30, 31, 127, and `0x3fffffff`, empty SETs, OPTIONAL/DEFAULT
fields, prefix use, resource ceilings, primitive/mismatched roots, malformed
EOC, and isolated strict CER rejection of indefinite reversed fields and
nonminimal root aliases. Explicit/other-class roots, aliases, extensions,
nested children, stacked tags, and mixed codec masks fail before publication.
BER-only, CER-only, and combined generator masks pass strict Clippy. C parity
uses a separate nonempty schema because generated empty C SET types do not
compile portably.

The sixth BER/CER slice supports one resolved context-specific EXPLICIT wrapper
on each supported direct SEQUENCE or SET field, alongside universal and
IMPLICIT fields. Generated readers require the wrapper to contain exactly one
matching universal child; generated CER decoders re-encode with the same shared
budget and compare the consumed prefix. SET output sorts by the effective
outer class and tag number; SEQUENCE output preserves declaration order.
Coverage includes tags 0, 30, 31, 127, and 128; EXPLICIT and IMPLICIT module
defaults; AUTOMATIC TAGS; DEFAULT omission; definite and indefinite BER
wrappers; constructed BER/CER string children; truncation, malformed wrappers,
resource limits, SET reordering, and strict selector-only Clippy builds. C
fixtures compare DER/CER encoding and decoding for explicit scalar SEQUENCE/SET
members, inline EXPLICIT ENUMERATED members, and fragmented OCTET/BIT STRING
values.

The next BER/CER composition stage supports one nonrecursive inline SEQUENCE
child inside a top-level SEQUENCE or BER/CER-only SET. The child may be required
or OPTIONAL and may contain zero to six unique-tag direct primitive fields,
including OPTIONAL IMPLICIT/EXPLICIT fields and bounded strings. Child
extensions, references, imports, recursion, nested SET/CHOICE/OF/ANY,
constructed DEFAULTs, tag collisions, ambiguous OPTIONAL dispatch, and
unsupported codec combinations fail before publication. Natural, IMPLICIT, and
EXPLICIT child tags, nested optional leaves, empty-child framing, and 1001-octet
CER string fragmentation are covered by fixed generated-C DER/CER vectors. The
mixed-codec SEQUENCE also round-trips through UPER, while the SET fixture remains
BER/CER-only.
Tests cover absent and present children, prefix consumption, malformed/truncated
child boundaries, nested CER EOCs, canonical SET order, resource exhaustion,
and strict Clippy. A BER EXPLICIT
wrapper may use a different definite/indefinite form from its nested SEQUENCE;
the Rust BER decoder accepts well-framed combinations, and strict CER rejects
them after canonical re-encoding. The current C decoder rejects those mixed
forms, so this case is documented as a C/Rust BER behavior divergence.
Empty nested child records are tested in a separate BER/CER-only fixture;
combining an empty nested child with UPER is gated before publication.
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
is a same-module direct BOOLEAN or a bounded, non-singleton INTEGER. Inline
forms are promoted to local type assignments.
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

The BigInteger BER/CER slice accepts exactly an untagged, unconstrained
top-level INTEGER when BER/CER are the only selected codecs. Its generated
wrapper owns a private normalized signed-byte `BigInteger`, constructs from
fallible signed big-endian bytes, and exposes borrowed bytes plus an optional
`i64` conversion. BER selection emits DER encoding and prefix BER decoding;
CER selection emits CER encoding and strict prefix CER decoding. All paths
share the caller's input, output, and work limits. Bounded `i64` INTEGER APIs
remain unchanged. Tags, aliases, fields, imports, explicit bounds such as
`MIN..MAX`, extensibility, and mixed codec selections fail before output.

`big_integer_conformance.rs` and `c_big_integer.c` compare exact encodings for
zero, signed byte boundaries, both `i64` boundaries, `2^64`, `-2^65`, and a
129-octet content. The C reference is generated with `-fwide-types`; native C
integer layouts are outside this comparison. Tests also cover BER redundant
sign and universal high-tag aliases, strict CER rejection, malformed and
truncated input, prefix consumption, input mutation, and resource limits.
Wide C BER accepts empty INTEGER content, while Rust deliberately
rejects empty content; this is a documented implementation divergence.

Direct untagged unconstrained BIT STRING and OCTET STRING roots are supported
only when BER and/or CER are selected without other codecs. The generated
wrappers take ownership of their buffers and expose borrowed views; they do
not implement infallible `Clone`. BIT values use validated packed storage:
`bit_len` records the significant bits and unused low bits in the last octet
must be zero. DER is emitted with BER prefix decoding when BER is selected;
CER encoding and strict CER prefix decoding are available when CER is selected.
Named bits, CONTAINING, explicit SIZE constraints, tags, aliases, fields,
imports, and mixed or non-BER/CER selections fail before output publication.

`UnconstrainedStrings.asn1`, `unconstrained_strings_conformance.rs`, and
`c_unconstrained_strings.c` compare empty values, the 999/1000/1001 CER
fragmentation boundary, multi-fragment values, and non-byte-aligned BIT
STRINGs. Rust also checks constructed BER nesting, aliases, malformed and
truncated input, prefix consumption, mutation safety, and resource limits.
The C decoder accepts a constructed BER BIT STRING whose non-final fragment
has unused bits; Rust rejects it according to the X.690 rule. C DER masks
invalid in-memory BIT padding, while Rust rejects invalid padding at value
construction, so malformed-value DER behavior is intentionally not claimed
to match.

Direct untagged unconstrained OBJECT IDENTIFIER and RELATIVE-OID roots are
supported when BER and/or CER are selected without other codecs. Generated
wrappers keep private canonical base-128 content and expose borrowed content
bytes. Their fallible content constructors normalize redundant leading `80`
groups while preserving arbitrarily wide subidentifiers; empty content and
unterminated continuation groups are rejected. The first combined OBJECT
IDENTIFIER subidentifier remains encoded content rather than a `u64` arc.
Wrappers do not derive infallible `Clone`. Tags, constraints, aliases, imports,
fields, and mixed or non-BER/CER codec selections fail before publication.

`OidValues.asn1`, `oid_conformance.rs`, and `c_oid.c` compare DER/CER bytes and
BER/CER decoded content for first-arc combinations, values beyond `u64`, and
127/128/1001-byte content lengths. Tests also cover redundant base-128 groups,
high-tag aliases, malformed and truncated input, prefix consumption, input
mutations, and resource limits. C BER accepts empty and unterminated OID
content and preserves nonminimal content; Rust rejects invalid empty or
unterminated values and normalizes BER aliases. Strict CER rejects these
noncanonical forms.

The direct IA5String BER/CER slice accepts only an untagged, unconstrained
top-level `IA5String` with BER/CER-only selection. Its wrapper owns private raw
bytes, exposes a borrowed view, and does not derive infallible `Clone`. BER and
DER preserve arbitrary content bytes; CER encode and strict CER decode require
every byte to be at most `0x7f`, including the valid NUL, ESC, and DEL values.
The separate restricted-string stage below uses a generic runtime value while
leaving this source-compatible IA5 API unchanged.

`Ia5Values.asn1`, `ia5_conformance.rs`, and `c_ia5.c` compare empty content,
127/128 and 999/1000/1001/2001-byte CER boundaries, constructed BER with OCTET STRING
fragments, high-tag aliases, prefix consumption, malformed EOCs, truncation,
mutations, and limits. The vectors also confirm that C and Rust BER/DER retain
`0x80`, while C and Rust CER reject it. Constructed empty BER normalizes to an
empty byte vector in Rust and re-encodes as primitive `16 00`; C BER also
decodes it, but its null-buffer representation cannot be passed directly to
the C CER encoder without first providing valid in-memory storage.

`RestrictedStrings.asn1`, `restricted_strings_conformance.rs`, and
`c_restricted_strings.c` cover direct untagged unconstrained ObjectDescriptor,
UTF8String, NumericString, PrintableString, TeletexString/T61String,
VideotexString, GraphicString, VisibleString/ISO646String, GeneralString,
UniversalString, and BMPString roots under BER/CER-only selection. T61 and
Teletex, and ISO646 and Visible, keep separate generated type names even when
their universal tags and runtime validation are shared. Wrappers own private
raw bytes without infallible `Clone`; each generated wrapper fixes its runtime
kind and tag. DER and BER preserve raw content, while CER applies the matching
C descriptor constraint after reassembly. UTF8 validation follows the C
descriptor's minimal one- through six-byte form, including its accepted
surrogates and values above U+10FFFF. BMP and UniversalString CER checks enforce
two- and four-byte alignment while matching C's acceptance of surrogate and
out-of-range code units. Character-string content uses universal OCTET STRING
tag-4 children for constructed BER and CER fragments.

The live vectors cover all tags, empty values, 127/128 and 999/1000/1001-byte
boundaries, aligned BMP/UniversalString boundaries, UTF8 legacy forms and a
sequence split across a CER fragment, nested definite/indefinite BER, malformed
children and EOCs, prefix consumption, repertoire failures, truncation, and
limits. Aliases, tags, constraints, fields, imports, CHARACTER STRING, and
mixed or non-BER/CER codec selection fail before output publication.

`UtcTimeValues.asn1`, `utc_time_conformance.rs`, and `c_utc_time.c` compare raw
BER/DER preservation and canonical CER normalization for the direct untagged
`UTCTime` root. Coverage includes omitted seconds, all four allowed input
lengths, positive and negative offsets, leap years, the 1950/2049 pivot,
constructed BER tag-4 fragments, wire identifier aliases, malformed time text, exact prefix
consumption, and resource limits. Rust uses checked Gregorian arithmetic and
accepts `691231235959Z`; C's `time_t == -1` sentinel rejects that instant on
this path, so the vector records an intentional compatibility divergence.
ASN.1 aliases, fields, imports, tags, constraints, and mixed or non-BER/CER
codec selections fail before publication.

`GeneralizedTimeValues.asn1`, `generalized_time_conformance.rs`, and
`c_generalized_time.c` compare only explicitly zoned valid DER/CER vectors.
BER preserves arbitrary raw content, including constructed tag-4 fragments;
DER and CER normalize valid UTC/offset spellings, optional clock fields, and
fractions to canonical tag-24 content. Valid-content constructed and high-tag
aliases decode under BER and fail strict CER. The C fixture separately records
four adapter differences without claiming wire parity: zoneless DER uses the
process timezone, DER may normalize an invalid calendar date, DER truncates
fractions beyond nine digits, and C rejects the valid epoch-minus-one instant
through its `time_t == -1` sentinel. Tagged, constrained, aliased, imported,
member, mixed-codec, and UPER-only GeneralizedTime schemas fail before output
publication.

The initial `SEQUENCE OF` and `SET OF` generator gate accepts only direct,
untagged, unconstrained roots with one untagged BOOLEAN, NULL, or finite
nonextensible bounded-`i64` INTEGER element under BER/CER-only selection.
Generated wrappers own typed vectors and expose borrowed slices. NULL uses a
count-backed runtime representation and a Rust `Vec<()>` view. Collection
decoders preserve BER prefix consumption; strict CER re-encodes under the same
limits context. SET OF DER/CER output sorts complete child TLVs, while
SEQUENCE OF preserves declaration order. The runtime caps element count at
1,000,000 and accounts for work and aggregate scratch.

`OfCollections.asn1`, `of_collections_conformance.rs`, and
`c_of_collections.c` compare empty, singleton, repeated, and multi-element
BOOLEAN, NULL, and bounded INTEGER collections. Coverage includes definite and
indefinite BER, canonical DER/CER bytes, SET OF ordering and duplicates,
nonminimal scalar/root aliases, malformed EOCs and children, suffix prefixes,
truncations, input mutations, and resource limits. C BER accepts zero-length
and multi-octet BOOLEAN content in these collection fixtures. Generated Rust
BER decodes them to Boolean values, while strict CER rejects the noncanonical
forms in both implementations.
The C BER decoder may leave bounded INTEGER range checking to a later
constraint check; generated Rust rejects an out-of-range collection element
during decode. This timing difference is tested separately from canonical
wire parity.

The direct primitive CHOICE gate accepts an untagged, nonextensible top-level
CHOICE containing one to three alternatives with unique intrinsic tags:
unconstrained BOOLEAN, unconstrained NULL, or finite bounded-i64 INTEGER.
Generated Rust exposes a typed enum and emits exactly the selected primitive
TLV without an outer CHOICE wrapper. BER prefix decoding dispatches by
universal tag; strict CER re-encodes the selected value under the same limits
context and compares the consumed prefix.

`PrimitiveChoice.asn1`, `choice_conformance.rs`, and `c_primitive_choice.c`
compare exact C and Rust DER/CER bytes and decoded alternatives. They cover
high-tag and long-length aliases, BER-compatible empty and multi-octet
BOOLEAN values, redundant INTEGER sign bytes, strict CER rejection, suffix
consumption, malformed identifiers, bounds, and resource limits. BOOLEAN-only,
NULL-only, INTEGER-only, and BOOLEAN/NULL pair schemas are also compiled with
BER-only and CER-only selection.
Tagged, constrained, aliased, imported, nested, optional/default, extended,
duplicate-tag, sanitized-name-collision, and mixed-codec CHOICE schemas fail
before an output crate is published.
Root SIZE constraints, root or element tags, aliases, imports, fields, nested
types, extensions, unsupported constraints, and mixed or non-BER/CER codecs
fail before output publication.

One nonempty inline SET child is supported inside an untagged top-level
SEQUENCE or BER/CER SET root. Child SET output sorts by effective tag,
independently of a containing SET's field order, while BER decoding accepts
unordered child and parent members. Natural, context-specific IMPLICIT, and one
EXPLICIT child wrappers are covered, including all six primitive leaf kinds
and optional child absence. Nested SETs, multiple constructed children, empty
SET children, DEFAULT/extension fields, aliases/imports, tagged roots, and mixed codec
selection fail before output publication. A nested SET selects a shared nested
record context even when an OPTIONAL child is absent.

`NestedSetChildren.asn1`, `nested_set_children_conformance.rs`, and
`c_nested_set_child.c` compare C and Rust DER/CER bytes and decoded values.
They cover canonical child and parent tag order, BER acceptance and strict CER
rejection of isolated order reversals, explicit-wrapper framing, prefixes,
malformed boundaries, and resource limits. Rust BER accepts two validly framed
mixed definite/indefinite EXPLICIT wrapper combinations that the C BER adapter
rejects; the fixture records this implementation divergence separately from
canonical wire parity. Empty inline SET children remain excluded because the
current C generator produces invalid C output for that schema.
