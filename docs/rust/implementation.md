# Rust implementation

This document records the implemented slices of the
[stage-one plan](stage-one-plan.md). The full conversion remains incomplete.
The existing C parser and semantic fixer feed a separate Rust output backend.
The matching runtime uses `std`, forbids unsafe Rust, and has no dependencies.

## Compiler mode and output

`--rust` selects the complete Rust output mode. It generates a Cargo package
with typed Rust bindings and a local copy of the Rust runtime. The current
defaults are UPER and CER. `-gen-APER` and `-gen-OER` add paired primitive
encoders and decoders; `-gen-BER` adds BER decoding and DER encoding.
`-gen-CBOR` adds direct BOOLEAN, NULL, bounded INTEGER, opaque ANY, fixed or
bounded BIT/OCTET STRING, and flat SEQUENCE map codecs for these direct field
types. A bounded direct CHOICE subset uses one-pair text-key maps. SEQUENCE
supports required, OPTIONAL, and literal BOOLEAN or bounded
INTEGER DEFAULT fields in this mode. Top-level local primitive CONTAINING
uses complete inner CBOR bytes inside an outer BIT/OCTET byte string. The narrow
IOC-selected OPEN TYPE record also supports direct selected CBOR map values.
-gen-JER adds compact JSON encoding and complete-input decoding for top-level
BOOLEAN, NULL, bounded INTEGER, direct ANY, direct nonextensible ENUMERATED, direct
fixed-size or bounded nonextensible OCTET STRING, and direct fixed-size or
bounded nonextensible BIT STRING assignments. JER for these strings is
available by itself or together with UPER. An explicit request for an unavailable
codec or unsupported ASN.1 form fails before publishing output; the C
compiler's default codec set does not select Rust codecs.

```sh
asn1c --rust -D generated schema.asn1
cargo check --offline --manifest-path generated/Cargo.toml
```

To generate only CER encoding and decoding, disable UPER explicitly:

```sh
asn1c --rust -no-gen-UPER -D generated schema.asn1
cargo check --offline --manifest-path generated/Cargo.toml
```

For fixed-size OCTET STRING or BIT STRING, bounded-size OCTET STRING or
BIT STRING, or a SEQUENCE with required and OPTIONAL direct or inline nested
BOOLEAN, NULL, finite bounded INTEGER, inline nonextensible ENUMERATED,
fixed-size string, and bounded-size OCTET STRING or BIT STRING fields,
plus BOOLEAN and bounded INTEGER DEFAULT
fields, select UPER alone:

```sh
asn1c --rust -no-gen-CER -D generated schema.asn1
cargo check --offline --manifest-path generated/Cargo.toml
```

For a source checkout, select its matching assets explicitly when necessary:

```sh
./asn1c/asn1c --rust -S skeletons -D generated schema.asn1
```

The output contains `Cargo.toml`, `src/lib.rs`, one Rust source file per ASN.1
module, and `runtime/` with a Cargo path dependency. The generated package is
named `asn1c-generated`. Module names are normalized for Rust and namespace
collisions are diagnosed. Type names use CamelCase: `Foo-Bar` becomes `FooBar`,
existing interior capitals are preserved, and reserved `Self` becomes
`Asn1Self`. Module and field snake case and ENUMERATED variant naming are
unchanged. This corrects older generated public type names such as `Foo_Bar`;
regenerated callers must use the corrected spelling. Normalized top-level,
keyword, and nested-name collisions fail before publication. The default
output directory is `asn1c-rust`.

An ownership manifest records generated files. Output is staged before
publication. Regeneration accepts an empty directory or a prior generated
directory containing only owned files; unrelated files, build artifacts, and
symlinks cause a failure that preserves the prior directory. Generate into a
fresh directory after adding application code or running Cargo there.

## Implemented boundary

| Feature | First slice |
| --- | --- |
| Top-level BOOLEAN | UPER encoding and prefix decoding |
| Top-level NULL | UPER complete zero-width encoding and prefix decoding |
| Direct bounded INTEGER | Nonextensible finite signed i64 range; UPER codecs |
| Top-level BOOLEAN, NULL, bounded INTEGER | CER encoding; INTEGER bounds are finite, nonextensible, and fit `i64` |
| Runtime limits | Input bytes, output bytes, and cumulative field work for composed UPER values |
| SEQUENCE | Required and OPTIONAL direct primitives, inline nonextensible ENUMERATED, or inline nested records; BOOLEAN and bounded INTEGER DEFAULT fields; UPER-only shared cursor and presence bitmap |
| Fixed OCTET STRING and BIT STRING | Direct nonextensible SIZE(N), 0 <= N < 65536; UPER, standalone or SEQUENCE field |
| Bounded OCTET STRING | One nonextensible SIZE(l..u), 0 <= l < u < 65536; UPER direct/SEQUENCE |
| Bounded BIT STRING | One nonextensible SIZE(l..u), 0 <= l < u < 65536; UPER direct/SEQUENCE; NamedBitList excluded |
| Direct fixed OCTET STRING | Opt-in JER hexadecimal string encode/decode; JER alone or with UPER |
| Direct bounded OCTET STRING | Opt-in JER quoted uppercase-hex encode/decode with complete-input and size-range checks; JER alone or with UPER |
| Direct fixed BIT STRING | Opt-in JER packed hexadecimal string; JER alone or with UPER |
| Direct bounded BIT STRING | One nonextensible SIZE(l..u), 0 <= l < u < 65536; JER `value`/`length` object, JER alone or with UPER |
| Direct ENUMERATED | Nonextensible root values fitting i64, up to 64 items; UPER or opt-in JER encode/decode; BER/DER and CER when selected |
| Primitive CONTAINING | UPER top-level and required/OPTIONAL SEQUENCE fields; unconstrained BIT/OCTET STRING containing a same-module direct BOOLEAN or non-singleton bounded INTEGER; validates inner range, length, and octet padding |
| Top-level primitive CONTAINING under CBOR | Unconstrained BIT/OCTET STRING containing a same-module direct BOOLEAN or non-singleton bounded INTEGER; complete inner CBOR value, octet-aligned BIT contents, and C-compatible outer byte string |
| Direct ANY and required/OPTIONAL ANY SEQUENCE fields | Opaque octets under UPER with C-compatible length framing and shared cursor budgets |
| Direct ANY | Opt-in APER/OER octet framing, JER hexadecimal strings, and CBOR byte strings; C interoperability vectors and malformed-input checks |
| Direct BOOLEAN, NULL, bounded INTEGER | Opt-in CBOR prefix encode/decode, including semantic tags and nonminimal heads; bignum tags are rejected |
| Direct fixed/bounded BIT or OCTET STRING | Opt-in CBOR definite byte-string encode/decode with SIZE checks; BIT STRING includes an unused-bit count octet and validates zero padding |
| Flat SEQUENCE of CBOR primitives, strings, or ANY | Opt-in definite text-key map; declaration-order encoding, unordered prefix decoding, required/OPTIONAL/DEFAULT fields, duplicate-key checks and unknown definite-item skip |
| Direct CHOICE of BOOLEAN, NULL, bounded INTEGER or ANY | CBOR-only one-entry text-key map with at most eight alternatives; unknown, duplicate or multiple keys fail |
| IOC-selected OPEN TYPE under CBOR | Narrow existing two-field required SEQUENCE and local object-set rows; direct BOOLEAN or bounded INTEGER selected value in a text-key map; selector agreement and complete selected value checked; unique unknown keys skipped and duplicate keys rejected |
| Top-level BOOLEAN, NULL, bounded INTEGER | Strict CER decoding; canonical short-form TLV only |
| Top-level BOOLEAN, NULL, bounded INTEGER | Opt-in BER prefix decoding and DER encoding with `-gen-BER` |
| Direct unconstrained INTEGER | BER prefix decoding, DER encoding, CER encoding, and strict CER decoding under BER/CER-only selection; private arbitrary-precision signed-byte value, untagged root, finite operation limits |
| Direct unconstrained OBJECT IDENTIFIER and RELATIVE-OID | BER prefix decoding, DER encoding, CER encoding, and strict CER decoding under BER/CER-only selection; untagged roots, private canonical base-128 content, arbitrarily large subidentifiers and finite operation limits |
| Direct unconstrained IA5String | BER prefix decoding and DER encoding preserve raw bytes; CER encoding and strict CER decoding enforce the 7-bit repertoire and canonical tag-22 primitive or universal OCTET STRING fragment forms; untagged BER/CER-only root with owned bytes and finite limits |
| Other direct restricted character strings | Untagged, unconstrained BER/CER-only roots for ObjectDescriptor, UTF8String, NumericString, PrintableString, TeletexString/T61String, VideotexString, GraphicString, VisibleString/ISO646String, GeneralString, UniversalString, and BMPString; BER/DER preserve raw bytes, CER applies C-specific repertoire or alignment checks and canonical tag-4 fragmentation; private owned bytes and finite limits |
| Direct UTCTime | Untagged, unconstrained BER/CER-only root; BER prefix decoding preserves raw primitive or constructed content, DER preserves raw bytes, CER normalizes valid calendar/zone forms to `YYMMDDhhmmssZ`, and strict CER compares the canonical tag-23 prefix; private owned bytes and finite limits |
| Direct GeneralizedTime | Untagged, unconstrained BER/CER-only root; BER preserves raw primitive or constructed content, DER/CER normalize valid explicitly zoned time to `YYYYMMDDhhmmss[.fraction]Z` with up to nine fractional digits, and strict CER compares the tag-24 prefix; private owned bytes and finite limits; host-local and permissive C DER cases remain outside the qualified subset |
| Direct SEQUENCE OF and SET OF primitive elements | Untagged, unconstrained BER/CER-only roots with one direct BOOLEAN, NULL, or finite bounded `i64` INTEGER element; BER prefix decoding accepts order and duplicates, DER/CER encode with SET OF full-child TLV ordering, strict CER compares the canonical prefix, and a hard count plus finite work/scratch/output budgets bound collection handling |
| Direct primitive CHOICE | Untagged, nonextensible BER/CER-only root with one through three unique intrinsic BOOLEAN, NULL, or finite bounded `i64` INTEGER alternatives; BER prefix decoding dispatches by tag, DER/CER emits the selected primitive TLV without an outer wrapper, and strict CER compares the canonical consumed prefix under one work budget |
| Direct ENUMERATED | BER prefix decoding, DER encoding, CER encoding and strict CER decoding when selected |
| Direct fixed/bounded OCTET STRING and BIT STRING | BER prefix decoding, DER encoding, CER encoding and strict CER decoding when selected; finite nonextensible SIZE below 65536 |
| Direct unconstrained OCTET STRING and BIT STRING | BER prefix decoding, DER encoding, CER encoding, and strict CER decoding under BER/CER-only selection; untagged roots, owned values, complete-input and work limits; BIT STRING stores validated packed bytes and exact bit length |
| Flat SEQUENCE with untagged outer type | BER prefix decoding, DER encoding, CER encoding and strict CER decoding for empty records or up to six direct BOOLEAN, NULL, bounded i64 INTEGER, nonextensible ENUMERATED, and finite bounded BIT/OCTET STRING fields with distinct effective tags; untagged, resolved context-specific IMPLICIT or one EXPLICIT wrapper, or AUTOMATIC members; required, OPTIONAL, and literal BOOLEAN/INTEGER DEFAULT; one shared record budget |
| Flat SEQUENCE with one context-specific IMPLICIT root tag | BER prefix decoding, DER encoding, CER encoding, and strict CER decoding for the direct flat field slice above, with BER/CER-only codec selection and a root tag number through `0x3fff_ffff` |
| Flat SET with untagged outer type | BER prefix decoding in any member order, effective-tag-ordered DER/CER encoding, and strict CER decoding for the same six direct field kinds; empty, required, OPTIONAL, and literal BOOLEAN/INTEGER DEFAULT records; resolved IMPLICIT/EXPLICIT/AUTOMATIC member tags; BER/CER-only codec selection |
| Flat SET with one context-specific IMPLICIT root tag | The direct flat SET slice above with BER/CER-only codec selection, unordered BER member decoding, effective-tag-ordered DER/CER output, strict CER decoding, and a root tag number through `0x3fff_ffff` |
| One inline SEQUENCE child in an untagged SEQUENCE or SET | BER prefix decoding, DER encoding, CER encoding, and strict CER decoding; nonrecursive child with up to six direct supported primitive leaves, required/OPTIONAL members, and natural, resolved context-specific IMPLICIT or one EXPLICIT child tag; one shared record and scratch budget; SET and empty child require BER/CER-only selection |
| One inline SET child in an untagged SEQUENCE or SET | BER prefix decoding accepts arbitrary child field order; DER/CER and strict CER sort and compare effective child tags independently of any parent SET sort; nonrecursive, nonempty child with up to six direct supported primitive leaves, required/OPTIONAL members, natural/IMPLICIT/one EXPLICIT child tag, and one shared record budget; BER/CER-only selection |
| One inline primitive CHOICE child in an untagged SEQUENCE or SET | BER prefix decoding, DER/CER encoding, and strict CER comparison for one nonextensible BOOLEAN/NULL/bounded `i64` INTEGER CHOICE with required/OPTIONAL presence; natural or context EXPLICIT under either parent; natural SET orders by the selected arm tag for DER and the minimum declared arm tag for CER; all alternatives share one logical presence slot and parent work budget; BER/CER-only selection |
| One natural IA5String field in a flat untagged SEQUENCE or SET | BER prefix decoding accepts primitive and constructed tag-22 content; DER preserves raw bytes; CER validates 7-bit content and uses tag-4 fragments above 1000 octets; required/OPTIONAL presence, scalar siblings, shared aggregate scratch, strict CER comparison, and BER/CER-only selection |
| One natural non-IA5 restricted character-string field in a flat untagged SEQUENCE or SET | Required/OPTIONAL field with existing scalar siblings, including finite bounded BIT/OCTET STRING members; exact `CharacterStringKind` retained for Teletex/T61 and Visible/ISO646 aliases; BER/DER preserve bytes; CER validates the C-compatible repertoire or alignment after reassembly and fragments with tag 4; aggregate scratch is selected even when absent; BER/CER-only |
| Natural OBJECT IDENTIFIER and RELATIVE-OID fields in a flat untagged SEQUENCE or SET | BER prefix decoding normalizes base-128 content with one shared work and aggregate scratch budget; DER/CER emit primitive tag-6/tag-13 child TLVs; at most one of each kind with required/OPTIONAL presence, scalar siblings, strict CER comparison, and BER/CER-only selection |
| One natural unconstrained INTEGER field in a flat untagged SEQUENCE or SET | `BigInteger` owned value without i64 narrowing; BER sign normalization, primitive DER/CER tag-2 output, strict CER comparison, one aggregate record budget, required/OPTIONAL presence, scalar siblings, and BER/CER-only selection |
| One same-module named bounded INTEGER field in a flat untagged SEQUENCE or SET | Checked generated newtype with one finite contiguous `i64` range; natural, resolved context IMPLICIT, or one EXPLICIT tag; required/OPTIONAL; supported scalar siblings including finite bounded BIT/OCTET; shared record context and BER/CER-only selection |
| One directly imported bounded INTEGER field in a flat untagged SEQUENCE or SET | Required/OPTIONAL, natural/IMPLICIT/one EXPLICIT member tag, and supported scalar/default siblings; one explicitly named import from a distinct supplied module with no imports; direct finite contiguous `i64` target; module ownership, exports, paths, and all declared imports are validated; shared parent context; BER/CER-only selection |
| One or two local or directly imported named SEQUENCE/SET children in a flat untagged SEQUENCE or SET | Required/OPTIONAL nonrecursive untagged targets with existing direct-leaf restrictions; natural, context-specific IMPLICIT, or one EXPLICIT member tag; distinct effective tags permit a repeated target; up to six parent fields and twelve total parent/target members; parent scalar DEFAULT behavior retained; one declared import group/symbol from a distinct supplied source without imports, qualified paths and validated exports/ownership/leaves, including unused targets; independently sorted SET levels, shared nested context, strict CER comparison; BER/CER-only selection |
| Top-level BOOLEAN, NULL, bounded INTEGER | Opt-in APER and OER encode/decode; each call begins at an octet boundary |
| Top-level BOOLEAN, NULL, bounded INTEGER | Opt-in JER encode/decode of one complete JSON primitive with -gen-JER |
| Direct fixed OCTET/BIT STRING | Opt-in JER uppercase-hex encoding, case-insensitive complete-input decoding, exact packed size and zero-padding checks, and resource limits |
| Direct bounded BIT STRING | Opt-in JER minified `{"value":"HEX","length":N}` encoding and complete-input decoding with range, padding, and resource-limit checks |
| Direct ENUMERATED | Opt-in JER quoted-name encode/decode; complete input, JSON whitespace, unknown-name and resource-limit checks |
| Flat SET and SEQUENCE | XER-only basic encoder for direct BOOLEAN, bounded INTEGER, unconstrained IA5String and REAL DEFAULT 0.5 fields; OPTIONAL and supported DEFAULT fields use `Option` |
| XER and CBOR/JER outside the listed slices | Planned; unavailable in Rust mode |
| SET, collections, or CHOICE outside the listed slices; extensible, other unbounded SIZE forms, or disjoint string constraints; named-bit strings, extensible ENUMERATED, aliases, imports outside the listed direct INTEGER/named-record slices, other top-level tagged types, and multi-tag member stacks | Planned; rejected in this slice |
| Encoding controls, other information-object forms, parameterized types | Planned; rejected in this slice |
| IOC-selected OPEN TYPE | UPER, APER, OER, CBOR; one local nonextensible set, bounded INTEGER selector, BOOLEAN or bounded INTEGER rows, and a two-field required SEQUENCE; APER selector 0..255 and row spans <=255 |
| Other CONTAINING and OPEN TYPE forms | Unsupported; rejected before output publication |
| ANY in SEQUENCE outside UPER/CBOR, and ANY under BER/DER, CER, or XER | Require codec-specific opaque-value semantics; rejected before output publication |

### Direct imported bounded INTEGER field

One directly imported bounded INTEGER assignment may supply one required or
OPTIONAL field in a flat untagged SEQUENCE or SET. The schema uses one
explicitly named import from a distinct supplied module with no imports. The
target must be a direct named finite contiguous `i64` INTEGER assignment and
must be exported: omitted EXPORTS and EXPORTS ALL export all assignments, and
an explicit export list must include the target. The source module name must
be unique in the fixed module list and must produce a Rust module.

The generated field type uses a fully qualified source-module path. Its scalar
read and write helper receives the parent's record context, preserving target
range checks and shared resource accounting. Natural, resolved context-specific
IMPLICIT, and one EXPLICIT member tag are supported with existing scalar
siblings and literal BOOLEAN/INTEGER DEFAULT siblings. Every declared import
is validated even when unused. Aliases, re-exports, parameters, extra imports,
member constraints, assigned module identifiers, import successor/descendant
options, and unsupported module paths
fail before output publication. Differential tests compare C and Rust
DER/CER bytes and values across SEQUENCE/SET parents, OPTIONAL states, tags,
defaults, limits, malformed values, suffixes, source orders, same-spelled
target names, export rules, and no-publication negatives. Imports outside the
qualified direct INTEGER/named-record slices remain unsupported.

For CBOR SEQUENCE, an omitted literal DEFAULT decodes to the default value.
The Rust record does not retain whether that field appeared on the wire, so
encoding that record includes the value explicitly. Generated C emits a DEFAULT
member when its pointer is populated and omits it when absent.

The XER slice is selected with `-gen-XER -no-gen-UPER -no-gen-CER` and does
not provide decoding or canonical XER. Untagged and AUTOMATIC TAGS records
are supported; explicitly tagged fields are rejected. It emits absent BOOLEAN, INTEGER and
REAL DEFAULT fields, omits absent OPTIONAL fields, and rejects unsupported
shapes and mixed codec selections before publication. REAL accepts only DEFAULT
0.5 and finite values of magnitude at most 1,000,000, with nonzero magnitude
at least 1e-15; values whose formatted decimal cannot round-trip are rejected.
IA5 accepts tab, line feed, carriage return, and ASCII 0x20–0x7f; other IA5
control characters and their XER control elements are unsupported. Carriage
returns use XML character references to survive line-ending normalization.
Output and work limits apply to the complete XML value.

BOOLEAN and INTEGER wrappers expose constructors, value getters, and the
methods selected during generation. UPER methods encode and prefix-decode the
supported primitives. CER adds `encode_cer` and strict `decode_cer` methods for
BOOLEAN, NULL, and bounded INTEGER. APER and OER add matching encode/decode
methods for the same subset when explicitly selected. NULL is a unit struct.
JER emits `true`, `false`, `null`, or minimal signed decimal text. Its decoder
accepts surrounding JSON whitespace and `-0`, rejects a second value and
malformed JSON numbers, and reports consumption of the entire input. It is
not a streaming decoder. Applications should use a JSON number parser that
preserves the full signed 64-bit range when consuming its output.
The C NULL decoder accepts some malformed tokens beginning with `n`; the Rust
decoder requires the complete `null` literal. C's JER INTEGER parser uses
native `long` and may have a narrower range on 32-bit targets.
INTEGER construction checks the
declared range. Codecs return typed errors for malformed values, invalid
constraints, exceeded limits, or allocation failure.
Generated SEQUENCE structs expose required and DEFAULT fields directly and
represent OPTIONAL fields as `Option<T>`. Inline nonextensible ENUMERATED
fields use their declared numeric values and encode declaration-order PER
ranks; unknown values and spare ranks are rejected. Inline nested SEQUENCE fields use
deterministic public Rust record types. Nested record types and aggregate field
work are bounded during generation; cycles and generated-name collisions are
rejected. Constructed DEFAULTs, extensions, aliases, and imports outside the
qualified direct INTEGER/named-record slices remain unsupported. DEFAULT is
supported only for literal BOOLEAN and in-range finite
bounded INTEGER values. Each record writes or reads its own OPTIONAL and
DEFAULT presence bitmap immediately before that record's payload. Encoding
omits a DEFAULT payload when the field equals its literal; decoding substitutes
the literal when absent and accepts a present value equal to the default.
UPER ignores direct component tags, including `AUTOMATIC TAGS`; tagged
top-level types remain unsupported. Fields pack without per-field padding.
Private `encode_uper_fields` and `decode_uper_fields` helpers pass one cursor
through all records; only the public top-level methods create the cursor and
finish the complete value. One budget covers the whole operation. Each field
charges its wire bits plus eight work units, including presence bits, NULL, and
singleton INTEGER fields.
The entire decode slice counts toward the input-byte limit. Only a complete
zero-width SEQUENCE uses one zero filler byte; a zero-width field inside a
nonzero value adds none.
Fixed OCTET STRING values use exactly N octets; fixed BIT STRING values use
ceil(N/8) octets with unused low bits zero in the Rust API. The two string
forms contribute N*8 and N wire bits, respectively, with no length determinant
or per-field alignment. Constructors and cursor writes reject invalid lengths
and nonzero unused BIT STRING bits. This subset excludes PER fragmentation.
For a bounded OCTET STRING or BIT STRING with `SIZE(l..u)`, UPER writes the
constrained length offset in `ceil(log2(u-l+1))` bits, followed immediately by
the content octets or meaningful bits. Both share the unaligned cursor; no
field alignment is inserted. `BitStringValue` preserves the exact logical bit
length and validates zero unused low bits in its storage. The runtime validates
spare length codes, input bounds, work, and output limits before allocating or
committing reader state. Generated wrappers validate `l <= value.len() <= u`
for octets and the corresponding bit length for BIT STRING. These forms use
UPER for SEQUENCE fields. Direct OCTET STRING assignments also support
`-gen-JER` for fixed and bounded sizes; both emit C-compatible quoted uppercase
hexadecimal and decode one complete token with a range check. `NamedBitList`
forms are rejected because they use separate canonicalization rules. With
`-gen-JER`, fixed OCTET STRING and BIT STRING assignments use the C-compatible
quoted hexadecimal form. BIT STRING values
include their packed octets and require zero unused low bits. Bounded BIT STRING
assignments use the C-compatible minified object with `value` before `length`;
the decoder validates the declared range, exact packed-octet count, and zero
padding. Encoding uses uppercase hex; decoding accepts uppercase or lowercase
digits and surrounding JSON whitespace, then requires complete input. JER is
available without UPER or alongside UPER for these direct assignments.
Direct ENUMERATED values are Rust enum variants. Their UPER indexes follow
ascending ASN.1 numeric value order, including when declaration order differs.
Unused root indexes fail decoding; a singleton uses zero meaningful bits and
the complete-value filler. With -gen-JER, root alternatives encode as the
same quoted ASN.1 identifiers used by C, independent of numeric value order.
The JER decoder accepts one complete quoted known name with JSON whitespace
around it and rejects escapes, unknown names, trailing data, and over-limit
input or lookup work. Extension markers and named-number constraints are
outside this ENUMERATED subset.

CER and DER methods emit complete TLV byte strings. `Encoded.bit_len` is the encoded
byte length multiplied by eight. Primitive BOOLEAN, NULL and bounded INTEGER
`decode_cer` requires the exact universal tag, short-form definite length,
and canonical content. Direct ENUMERATED and string CER decoding compares the
BER-decoded value's CER re-encoding with the consumed prefix. CER string
encoding fragments content over 1000 octets. Trailing bytes are left unconsumed.
The C `ATS_CER` decoder is likewise strict. BER decoding accepts definite
long-form lengths and any nonzero BOOLEAN content octet as true. Rust and C
also treat zero-length BOOLEAN content as false and multi-octet content as true
when any octet is nonzero; these are C-compatible malformed-input extensions,
not valid X.690 BOOLEAN encodings. The Rust BER INTEGER decoder accepts
redundant sign-extension octets as a compatibility extension, while DER and
CER output remain minimal. The wire-form distinctions follow
[ITU-T X.690 (2021)](https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-202102-I%21%21PDF-E&lang=e&type=items),
clauses 8.1.3, 8.2, and 8.3.

The flat BER/DER/CER SEQUENCE slice keeps fields in declaration order and
rejects duplicates, unknown tags, and missing required fields. BER accepts a
definite or indefinite outer length and reports the exact consumed prefix.
DER uses a definite outer length; CER uses an indefinite outer length with
end-of-contents. Both omit literal DEFAULT values. Strict CER decoding
re-encodes through the same operation context before comparing the consumed
prefix, so parsing, output, and comparison share the work limit. Constructed
BER BIT/OCTET STRING fields are flattened under that limit, and `max_output_bytes`
also caps cumulative retained decoded string bytes. The generator rejects
deeper nested, colliding-effective-tag, extensible, or unsupported field forms.
A direct flat SEQUENCE or SET with one resolved context-specific IMPLICIT root
tag is supported under BER/CER-only selection; other root tags are rejected.

The flat SET slice uses the same six direct field kinds and record context.
BER accepts members in any order, rejects duplicates and unknown tags, and
reports the exact prefix. DER/CER emits fields by ascending effective tag class
and number; strict CER rejects a reordered input or an encoded DEFAULT. SET generation
requires selecting BER and/or CER without UPER, CBOR, JER, or XER.

The qualified record slice accepts resolved context-specific IMPLICIT member
tags, including AUTOMATIC TAGS, and one context-specific EXPLICIT wrapper on
each supported direct member. The wrapper contains exactly one intrinsic
universal value. High tag numbers use checked identifiers up to `0x3fff_ffff`,
the C runtime's packed-tag limit on this target. BER accepts C-compatible
nonminimal high-tag aliases; strict CER rejects them. Constructed tagged
strings retain universal fragment tags. Two fields of the same primitive
kind are permitted when their effective class/number pairs differ. Tagged
flat SEQUENCE and SET roots replace their universal outer identifier with one
resolved context-specific IMPLICIT tag under BER/CER-only selection. BER accepts
C-compatible nonminimal root identifiers, and strict CER requires the shortest
form and canonical indefinite framing. Tagged SET roots retain unordered BER
member decoding and effective-tag-sorted DER/CER output. Other root tags,
multi-tag stacks, references, imports, and broader nested records remain
outside this slice.

The nested record slice permits one nonrecursive inline SEQUENCE child in an
untagged SEQUENCE or BER/CER-only SET. Child leaves use the supported direct
primitive types and required or OPTIONAL presence. The child may keep its
natural SEQUENCE tag, replace it with a resolved context-specific IMPLICIT tag,
or be enclosed by one resolved context-specific EXPLICIT wrapper. Parent and
child use one `RecordContext`; nested operations opt into a fixed aggregate
scratch cap without changing flat record limits. BER accepts independently
definite or indefinite constructed layers when their lengths and EOCs match;
strict CER requires the canonical indefinite form. The C decoder currently
rejects some valid mixed EXPLICIT layer forms, as recorded in the
[parity design](ber-der-cer-design.md).
An empty inline child is supported under BER/CER-only selection. Mixed UPER
with BER/CER currently requires a nonempty child because the generated empty
UPER helper does not pass the required strict Clippy checks; that selection is
rejected before output publication.

One or two local or directly imported named SEQUENCE/SET assignments may be
direct required or OPTIONAL children of a flat untagged SEQUENCE or SET. Targets are
nonrecursive and obey the existing direct primitive-leaf rules; named
SEQUENCE targets may be empty, while named SETs must remain nonempty. Natural,
one resolved context-specific IMPLICIT, or one
EXPLICIT wrapper may identify each child. Reusing a target is supported when
the fields have distinct effective tags. The parent retains its six-field cap,
and the parent plus both targets share a twelve-member schema-work cap. Parent
scalar siblings and literal BOOLEAN/bounded INTEGER DEFAULT values keep their
existing behavior. Imported targets use one explicitly declared symbol from a
supplied distinct source module with no imports. Exports, direct assignment
ownership, unique module identity, and all child leaves are validated even
when the import is unused. Qualified type paths and crate-visible field
callbacks permit cross-module calls under the same parent context. Source SET
helper discovery scans the complete fixed module tree; unreferenced SETs emit
no child callbacks. One nested `RecordContext` tracks both children and the
parent, and each child SET sorts its fields independently of a parent SET.
Empty named SETs remain unsupported because the generated C target does not
compile them. Aliases, broader imports, parameters, constrained/tagged/recursive
targets, extensions, nested members, more than two children, mixed inline and
named constructed children, effective-tag collisions, and mixed codecs fail
before output publication.

`Encoded` carries output bytes and meaningful bit length. `Decoded<T>` carries
the value and consumed bits and bytes. Prefix decoding may leave a suffix;
input limits cover the entire supplied slice. For C compatibility, unused
padding bits are accepted. NULL and singleton INTEGER complete encodings use
one zero byte with zero meaningful bits; empty input requests more data and a
nonzero filler byte is rejected.

The defaults are 1 MiB input, 1 MiB output, and 8 MiBits of work per primitive
operation. CER encoding applies the output and work limits before allocation;
input limits apply to decoder input. Applications can supply smaller or larger
finite limits. The [runtime README](../../rust/asn1c-runtime/README.md)
documents the API.

## Validation and next work

The runtime tests cover independent vectors, signed and full-i64 endpoints,
singleton ranges, spare codes, truncation, padding, consumption, and limits.
A deterministic mutation test exhausts every first-byte pattern of a small
constrained INTEGER and flips each meaningful bit in bounded OCTET and BIT
STRING golden vectors. The compiler integration harness builds generated Cargo
packages offline and checks CLI failures, schema gates, output ownership,
repeat generation. Rust CI checks runtime formatting,
unit tests, Clippy, generated codecs, and installed runtime packaging.

The Rust runtime suite includes composable UPER cursors,
fixed strings, APER/OER range transitions, JER primitives, malformed-input,
and limit cases.
The generated Rust harness includes primitive, string, ENUMERATED, and flat
SEQUENCE tests, including C comparisons for selected UPER/CER/APER/OER/JER vectors,
C decoding of Rust output, codec selection, and negative-schema checks.
Runtime and generated crates pass pedantic and nursery Clippy with warnings
denied. `make dist` includes the APER, OER, JER, CBOR, XER, and UPER cursor modules and their
test fixtures; `make install-data` installs the runtime modules. Hosted Rust CI has not yet run
for this extension. No minimum Rust compiler version is claimed.

These are first-slice gates. The [test migration plan](testing.md) remains the
stage-wide target; unsupported DEFAULT forms, other SET shapes, and open types still need
schema and codec support. XER and CBOR/JER for types outside the listed slices remain unimplemented.
The CER encoder is also only a first slice and does not establish whole-runtime
parity.

The [OPEN TYPE boundary and plan](open-type-plan.md) describes the current selector-driven subset and future work.
