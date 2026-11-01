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

One natural unconstrained INTEGER field is also supported in an untagged flat
SEQUENCE or SET under BER/CER-only selection. It may be required or OPTIONAL
beside the supported scalar siblings. Generated fields own the non-Clone
`BigInteger` value, and every record operation selects aggregate-scratch
accounting even when the OPTIONAL INTEGER is absent. Tags, aliases, imports,
constraints, DEFAULT, extensions, nesting, multiple unbounded INTEGER fields,
IA5/OID coexistence, and mixed codecs fail before output publication.

`BigIntegerRecord.asn1`, `big_integer_record_conformance.rs`, and
`c_big_integer_record.c` compare DER/CER and BER/CER decoding for signed
boundaries, `i64` limits, `2^64`, `-2^65`, and 127/128/129/1000/1001-octet
contents. They also cover OPTIONAL omission/presence in both record kinds,
required fields, SET
tag order, prefix consumption, redundant signs, aliases, truncation, mutations,
malformed content, and resource limits. The C reference uses `-fwide-types`;
other INTEGER layouts are not part of the comparison.

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

One natural, unconstrained OBJECT IDENTIFIER and one RELATIVE-OID member are
supported in an untagged flat SEQUENCE or SET under BER/CER-only selection.
Each field may be required or OPTIONAL alongside the existing supported scalar
fields. Generated fields own the existing canonical-content wrappers without
infallible `Clone`, and every record operation uses aggregate-scratch accounting
even when an OPTIONAL OID is absent. IA5 coexistence, tags, constraints, aliases,
imports, DEFAULT, nested records, duplicate OID kinds, and mixed codecs fail
before output publication.

`OidRecord.asn1`, `oid_record_conformance.rs`, and `c_oid_record.c` compare exact
DER/CER records and decoded values for both OID kinds, SET ordering, optional
SEQUENCE and SET presence/absence, large base-128 arcs, and 127/128/1001-byte
content. They cover BER
normalization and C preservation of redundant groups, C BER acceptance of empty
and unterminated content, strict CER rejection under canonical record framing,
prefix suffixes, truncation, single-byte mutations, malformed content, and
input/output/work limits.

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

One direct natural, unconstrained `IA5String` member is also supported in a flat
untagged SEQUENCE or SET under BER/CER-only selection. The member may be required
or OPTIONAL and can have scalar siblings; generated records retain private
`Ia5String` ownership without deriving `Clone`. All record encode/decode methods
use aggregate-scratch accounting, including operations where an OPTIONAL IA5
member is absent. Aliases, imports, tags, constraints, DEFAULT, nested members,
multiple IA5 fields, and mixed or non-BER/CER codec selection fail before output
publication.

`Ia5Record.asn1`, `ia5_record_conformance.rs`, and `c_ia5_record.c` compare
record DER/CER bytes and decoded values for empty, 127/128, 999/1000/1001, and
multi-fragment content. They cover required SET and OPTIONAL SEQUENCE fields,
constructed BER OCTET STRING fragments, unordered SET BER, strict CER order and
framing checks, raw high-byte BER/DER preservation with CER rejection, suffix
consumption, malformed and truncated input, and resource limits. The generated
OPTIONAL-absent path is exercised while selecting aggregate-scratch context.

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
limits. Aliases, tags, constraints, imports, CHARACTER STRING, and mixed or
non-BER/CER codec selection fail before output publication. Flat record members
are covered by the separate restricted-string record gate below.

The restricted-string record gate composes one direct natural non-IA5
`CharacterStringKind` member into a flat untagged SEQUENCE or SET with scalar
siblings. Required and OPTIONAL fields are covered, including OPTIONAL absence
in both record kinds. Teletex/T61 and Visible/ISO646 descriptors retain their
distinct generated kinds despite shared universal tags. Every encode/decode
operation selects aggregate-scratch accounting even when an OPTIONAL string is
absent; strict CER re-encoding uses that same record context.
Bounded OCTET STRING and BIT STRING siblings remain available through their
existing explicit and implicit tags. A combined generated/C vector verifies
these fields share record limits with the restricted string.

`RestrictedStringsField.asn1` smoke-tests a one-field SEQUENCE. The broader
`RestrictedStringRecord.asn1`, `restricted_string_record_conformance.rs`, and
`c_restricted_string_record.c` compare all supported non-IA5 kinds in both
directions. They cover primitive and fragmented CER vectors, UTF8 999/1000/1001
and multi-fragment content, aligned BMP/Universal boundaries, optional SET
presence and omission, BER constructed tag-4 fragments, prefix consumption,
invalid CER repertoire/alignment, malformed children, and input/output limits.
Aliases, fields, imports, tags, constraints, DEFAULT, extensions, nesting,
CHOICE, IA5/OID/BigInteger coexistence, and mixed or non-BER/CER codecs fail
before output publication.

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

One inline primitive CHOICE child is supported in an untagged top-level
SEQUENCE, or as a one-tag EXPLICIT child in an untagged SET. Natural CHOICE is
also supported in SEQUENCE and top-level SET. In SET, DER ordering uses the
selected arm's intrinsic tag, while CER ordering uses the lowest tag among all
declared arms; this keeps field ordering valid for each encoding rule. The
child has one to three uniquely tagged
BOOLEAN, NULL, or finite bounded-`i64` INTEGER alternatives; it may be required
or OPTIONAL. The generated enum represents the selected arm, and the parent
record keeps one logical presence slot. Natural arm tags are checked against
every sibling tag, so a later alternative cannot be mistaken for a second
field. Parent record encoding and decoding share one BER/CER operation
context; strict CER re-encodes and compares the consumed prefix with that same
context.

`InlineChoiceChildren.asn1`, `inline_choice_conformance.rs`, and
`c_inline_choice.c` compare exact C and Rust DER/CER bytes and decoded values
for natural, EXPLICIT, required, and OPTIONAL alternatives in SEQUENCE and SET.
They cover all supported arms, SET tag sorting, C-compatible empty and
multi-octet BOOLEAN BER forms, a high-tag alias, suffix consumption, duplicate
logical alternatives, missing required choice, malformed EXPLICIT wrappers,
and input/output limits. Ten negative schema fixtures exercise aliases,
imports, IMPLICIT tagging, arm/sibling tag collisions, extensions,
nested/multiple choices, and generated-name collisions. Mixed UPER/BER/CER and
UPER-only selection fail before output publication. Combined, BER-only, and
CER-only generated crates run strict Clippy.
The single-arm `InlineChoiceBooleanOnly.asn1` and two-arm
`InlineChoicePair.asn1` forms also compile under combined and codec-only
selection with the same strict lint settings.

`NaturalChoiceSet.asn1`, `natural_choice_set_conformance.rs`, and
`c_natural_choice_set.c` compare exact C and Rust SET encodings for each
selected alternative and the absent OPTIONAL state. They verify BER accepts
unordered members and a high-tag alias, while strict CER rejects both, and
check canonical CER prefix consumption. A sibling tag colliding with any
natural CHOICE arm fails before output publication.

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

One same-module bounded `INTEGER` assignment may be referenced by one direct
required or OPTIONAL member in a flat untagged SEQUENCE or SET. The target
must have one finite contiguous range fitting `i64`; the generated public
newtype validates construction and is written through the parent's shared
record context. The field may be natural, context-specific IMPLICIT, or one
EXPLICIT tag. Existing scalar siblings include BOOLEAN, NULL, bounded INTEGER,
ENUMERATED, and finite bounded BIT/OCTET STRING fields, within the existing
six-field cap. BER/CER selection is required.

`NamedIntegerRecord.asn1`, `named_integer_record_conformance.rs`, and
`c_named_integer_record.c` compare required and OPTIONAL newtypes, natural,
IMPLICIT, and EXPLICIT tags, BIT STRING siblings, SET sorting, BER alias
handling, range checking, prefix consumption, and resource limits. C verifies
out-of-range BER values separately through `asn_check_constraints`. References
outside the later qualified alias/import slices, unbounded/union/extended/MIN..MAX targets, extra member constraints,
tagged target/root, nested, multiple-reference, duplicate-tag, DEFAULT, and
unsupported target schemas fail before output publication. BER-only,
CER-only, mixed-codec, and UPER-only selector behavior is checked; generated
combined and codec-only crates run strict Clippy.

One same-module untagged named SEQUENCE assignment may be used as the single
required or OPTIONAL child of an untagged flat SEQUENCE or SET. The target may
be empty or contain up to six direct BOOLEAN, NULL, bounded `i64` INTEGER,
ENUMERATED, and finite bounded BIT/OCTET STRING leaves. Child fields support
the existing natural, context-specific IMPLICIT, and one EXPLICIT tagging
forms. Parent scalar siblings retain BOOLEAN and bounded INTEGER DEFAULT
support; child DEFAULT is rejected. The generated public child type is
encoded and decoded through private field callbacks with the parent's one
nested `RecordContext`, including when an OPTIONAL child is absent.

`NamedSequenceRecord.asn1`, `named_sequence_record_conformance.rs`, and
`c_named_sequence_record.c` compare exact DER/CER bytes and values for natural,
IMPLICIT, and EXPLICIT children under both SEQUENCE and SET parents. The
five-leaf target covers an inline ENUMERATED plus tagged bounded OCTET STRING
and bounded BIT STRING. Tests cover SET ordering, reversed BER members,
OPTIONAL presence/absence, parent DEFAULT omission and nondefault values,
high-tag aliases, malformed and mixed EXPLICIT frames, prefix suffixes,
truncations, byte mutations, bounded child values, and a pinned shared-work
limit. The C decoder rejects one validly framed mixed definite/indefinite
EXPLICIT stack that generated Rust BER accepts; strict CER rejects that stack.
Alias, import, recursive/nested, constrained/defaulted, extension,
effective-tag collision, tagged-root/target, and non-SEQUENCE target fixtures
fail before output publication. The legacy multiple-reference fixture remains
negative because its natural child tags collide. Mixed and UPER-only selection
is also rejected.

`NamedSequenceEmpty.asn1`, `named_sequence_empty_conformance.rs`, and
`c_named_sequence_empty.c` cover required and OPTIONAL empty children and
parent BOOLEAN/INTEGER DEFAULT values. They compare present and absent DER/CER
framing, verify explicit BER DEFAULT decoding and strict CER rejection, and
compile the empty target under the exact strict Clippy settings. The main
named-child crate runs generated tests and strict Clippy under combined,
BER-only, and CER-only selection.

### Same-module named SET child

`NamedSetRecord.asn1`, `named_set_child_conformance.rs`, and
`c_named_set_child.c` exercise one same-module named SET child with natural,
context-specific IMPLICIT, and EXPLICIT tags under flat SEQUENCE and SET roots.
The target has required bounded INTEGER and BOOLEAN leaves with unique tags;
parent roots include required and OPTIONAL children and a literal BOOLEAN
DEFAULT. Empty named SET targets are rejected because generated C emits an
invalid empty enum and tag map.

Tests compare C and Rust DER/CER encodings and decoded values, exercise natural
and tagged child order independently from parent SET order, accept BER
permutations, and require strict CER to reject them. Malformed EOCs, duplicate
and unknown child tags, a wrong EXPLICIT inner type, out-of-range child values,
prefix suffixes, truncations, mutations, input/output limits, and a pinned
shared-work threshold are covered. No-publication negatives cover empty,
aliased, imported, parameterized, recursive, tagged, constrained, extended,
nested, colliding, CHOICE, and collection targets, plus mixed or UPER-only
selection. An unreferenced top-level SET remains free of unused private
nested callbacks under strict Clippy.

### Two same-module named record children

`NamedRecordPair.asn1`, `named_record_pair_conformance.rs`, and
`c_named_record_pair.c` cover one or two direct named SEQUENCE/SET children
inside flat SEQUENCE and SET parents. They compare the approved C DER/CER
vectors for required and OPTIONAL children, all OPTIONAL presence combinations,
same-target distinct IMPLICIT and EXPLICIT tags, parent SET order, and a
multi-member named SET whose own order is independent of its parent. The
SEQUENCE pair also retains a scalar BOOLEAN DEFAULT sibling. A separate pair
includes an empty named SEQUENCE target, and the multi-member parent checks
the DEFAULT both omitted and emitted. Owned OCTET/BIT STRING children check
retained values, BER padding normalization, and strict CER padding rejection.
Tests check strict CER canonicality, BER
permutations, suffix consumption, every proper DER/CER prefix, malformed EOCs
and wrappers, duplicate and unknown child tags, target bounds, limits, and
deterministic byte mutations. The generated
module is checked for both nested writer/reader paths and strict Clippy runs
under combined, BER-only, and CER-only selection.

The schema gates accept the aggregate twelve-member work boundary and the
six-field parent boundary; thirteen aggregate members, seven parent fields,
three named children, mixed inline/named construction, mixed named scalar and
record references, and duplicate effective tags fail without publishing output.
The runtime suite separately exercises second-child failure/retry cleanup in
writers and readers, shared work accounting, active nesting depth, and exact
aggregate writer scratch limits.

### Direct imported bounded INTEGER field

`ImportedIntegerBase.asn1`, `ImportedIntegerClient.asn1`,
`imported_bounded_integer_conformance.rs`, and
`c_imported_bounded_integer.c` cover one directly imported bounded INTEGER
field in flat SEQUENCE and SET parents. Rust and generated C compare natural,
OPTIONAL, IMPLICIT, and EXPLICIT fields, including both OPTIONAL states,
parent SET ordering, and BOOLEAN DEFAULT omission/emission. Tests cover target
range endpoints and out-of-range values, strict CER canonicality, BER/CER
prefix consumption and truncations, malformed tags/wrappers/EOCs, duplicate
and unknown members, deterministic mutations, and exact input/output/work
limits. The C fixture records C's decode-then-constraint-check timing for an
out-of-range value separately from Rust's generated decoder rejection.

Import-resolution fixtures verify omitted, `EXPORTS ALL`, and explicit export
lists; the same `Small` spelling in different source modules; both source file
orders; and a Rust reserved-word module path. Unsupported aliases, re-exports,
transitive targets, constructed targets outside the qualified record slice,
parameters, member constraints, unused
unsupported imports, unused non-exported targets, import/module identifiers
and options, local raw-symbol collisions, and duplicate normalized/raw module
names must fail without publishing output. Positive generation and strict
Clippy runs cover combined, BER-only, and CER-only selection; mixed and
UPER-only selections fail before publication. The existing
`NamedIntegerImported.asn1` smoke case now exercises a direct imported target.
Supported unused imports compile and retain both modules' direct codecs.
Each unsupported fixture is parsed first,
so syntax errors cannot accidentally satisfy the no-publication checks.

### Direct imported named record children and type names

`ImportedRecord*.asn1`, `imported_record_conformance.rs`, and
`imported_record_legacy_conformance.rs` cover direct imported SEQUENCE and
nonempty SET children. The eight Rust tests compare fixed C vectors for
natural local/imported pairs, repeated IMPLICIT/EXPLICIT references, OPTIONAL
states, empty SEQUENCE targets, owned OCTET/BIT STRING leaves, scalar DEFAULT
siblings, independent SET ordering, prefix/truncation behavior, malformed
second children, and deterministic mutations. Local and imported equivalents
must have identical exact encode/decode work thresholds; one-short input and
output budgets fail. Both source orders and individual BER/CER selections pass
exact strict Clippy. Unused imported SETs emit no unused child callbacks.
`ImportedRecordWork12Base/Client.asn1` and
`imported_record_work12_conformance.rs` accept exactly twelve aggregate fields
across an imported SEQUENCE child and a local SET child, with pinned work and
prefix checks. The combined `ImportedRecordNegativeWork13.asn1` is parse-valid
and rejects the first excess field with both modules supplied.

`imported_record_composition.c`, `imported_record_owned_defaults.c`, and
`imported_record_legacy.c` check seventeen DER/CER value pairs through C encoders
and decoders, including correctly framed indefinite reversed SET order,
defaults, independent target bounds, owned leaves, and exact prefixes. The
harness runs all three normally and under ASan/UBSan. Twenty-three parse-valid
negative schemas and unsupported codec selections must reject without an
output path. Invalid unused imported targets are included. Former imported
SEQUENCE/SET rejection fixtures now also receive positive compilation checks;
imported references inside inline nested SET leaves remain rejected.

`TypeNameConformance.asn1` and `type_name_conformance.rs` verify qualified
`Foo-Bar`/local `FooBar` coexistence, reserved names, nested names, and unchanged
module/field/ENUMERATED naming. Three parse-valid normalized-name collisions
must fail before publication. The naming correction emits `FooBar` instead
of `Foo_Bar`, preserves existing interior capitals, and uses `Asn1Self` for
reserved `Self`; it introduces no lint allowances or compatibility aliases.

### Transparent local bounded INTEGER aliases

`check-rust-aliases.sh` qualifies one same-module transparent hop such as
`Small ::= Base` with `Base ::= INTEGER (0..5)`. The generated `pub type`
preserves type identity, checked constructors, accessors, and selected codec
methods. Forward declarations and multiple aliases of one base compile.
Record fields and decoder constructors retain their declared alias names;
tag/range decisions and shared operation budgets use the direct base.

The driver reuses the eight named INTEGER record tests with the alias schema
and adds four identity/range/default/resource tests. It checks signed and
singleton bounds, natural/IMPLICIT/EXPLICIT fields, OPTIONAL presence, SET
ordering, strict CER rejection, prefixes, malformed data, and exact shared
limits. Combined, BER-only, and CER-only crates pass exact strict Clippy.
Twenty-one parse-valid negative fixtures reject unsupported metadata, chains,
cycles, imports, constraints, tags, parameters, and normalized collisions before
publication. Twelve unsupported codec selections also reject unused aliases.

`c_named_integer_record.c` and `c_alias_integer_identity.c` check 24 DER/CER
value pairs with generated C encoding, BER decoding, and strict CER decoding.
Both run normally and under ASan/UBSan when available. The identity fixture
also verifies eight encodings of noncanonical C TRUE representations (`0xff`
and `7`) with DEFAULT TRUE siblings. This caught the C DEFAULT comparison bug:
BOOLEAN must compare truth values rather than its stored integer to `1`.
Canonical omission and explicit DEFAULT rejection now agree with fixed vectors.

`check-rust-bitsets.sh` qualifies the approved private BOOLEAN representation
with every strict Clippy lint enabled. `BoolStorage` and its import modules
cover four/six scalar BOOLEANs, keyword accessors, REQUIRED/OPTIONAL/DEFAULT,
inline/named/imported children, owned OCTET siblings, exact limits, truncations,
and deterministic malformed mutations. The independent C harness compares
DER/CER bytes, decoded values, prefixes, and strict canonicality, normally and
under ASan/UBSan when the toolchain supports them. The five value pairs cover
ten canonical encodings in each direction and explicit DEFAULT FALSE rejection.

`BoolAuto` exhausts all 16 packed values with three OPTIONAL states and two
interleaved INTEGER states across UPER, CBOR, BER, and CER. `BoolXer` retains
DEFAULT `Option<bool>` semantics, OPTIONAL tuple transparency, heterogeneous
owned String tuples, invalid controls, and exact output limits. `Bool64` checks every
UPER bit position, all-zero/all-one values, setter byte boundaries, truncation,
and exact input/output/work limits. `BoolDefaultsOnly` checks sixteen independent
presence/payload vectors. `WideMixed` compares 64 required/default/optional
BOOLEAN fields with an independent UPER oracle. `WideOptional` checks a
four-required/sixty-OPTIONAL constructor from outside the generated module,
including presence/setters at both ends of its tuple. `BoolAny` checks packed BOOLEAN neighbors
with absent, empty, and nonempty opaque ANY values. `BoolOwned` checks moved
OCTET/BIT buffers and invalid sibling validation; `BoolLongName` checks maximum field-name output
width and strict lint. Individual BER/CER selections, reverse import order, and
external rejection of private-byte access are also checked. Existing smaller
record struct literals remain in the full backend regression driver.
