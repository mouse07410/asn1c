# Binary codec support and dispatch

Source-audited through 2026-11-01 against generated descriptors, the generic
dispatcher, and CER regression cases. This records available operations, not
blanket support for every ASN.1 type or proof of canonical conformance.

| Selector | C encoder | C decoder |
| --- | --- | --- |
| `ATS_BER` | DER encoder; valid BER output | `ber_decode` |
| `ATS_DER` | `der_encode` | `ber_decode` |
| `ATS_CER` | `cer_encode` | `cer_decode` (strict) |
| Basic/canonical OER | `oer_encode` | `oer_decode` |
| Basic/canonical UPER | UPER encoder | `uper_decode_complete` |
| Basic/canonical APER | APER encoder | `aper_decode_complete` |
| `ATS_CBOR` | `cbor_encode` | `cbor_decode` |

The table follows [asn_application.c](../skeletons/asn_application.c), its
`ASN_DISABLE_*_SUPPORT` guards, and each type's operation descriptor where
applicable. CER is a direct descriptor walker rather than an operation-table
slot, so its support depends on the descriptor kinds and canonical value forms
handled by that walker.

## CER encoding and decoding

[ber_decoder.h](../skeletons/ber_decoder.h) advertises decoding BER, DER, and
CER. The implementation handles indefinite-length constructed values,
end-of-contents markers, and segmented strings. `ATS_BER` and `ATS_DER` input
use this permissive decoder.

[cer_decoder.h](../skeletons/cer_decoder.h) provides strict `cer_decode()`,
which `asn_decode(ATS_CER, ...)` and the converter's `-icer` selector use. It
runs `ber_decode()`, re-encodes the value with `cer_encode()`, and requires the
re-encoding to be byte-identical to the consumed input prefix. Noncanonical
input is rejected: long-form lengths where short form applies, definite-length
constructed values, BOOLEAN TRUE other than `FF`, non-minimal INTEGER, unsorted
`SET OF`, unsegmented strings over 1000 octets, and similar forms. Coverage
matches the descriptor kinds supported by the CER encoder.

Invalid arguments return `RC_FAIL` with `EINVAL`. A BER result other than
`RC_OK` (`RC_WMORE` or `RC_FAIL`) is returned with zero bytes consumed. A
re-encoding mismatch returns `RC_FAIL` with `EBADF`. On failure, a structure
allocated by the decoder is freed and caller-provided storage is reset.
Trailing bytes after the first TLV are not consumed. The decoder is compiled
only when neither `ASN_DISABLE_BER_SUPPORT` nor `ASN_DISABLE_CER_SUPPORT` is
defined; otherwise a stub returns `RC_FAIL` with `ENOENT`. `-icer` requires
CER generation, is rejected under `-no-gen-CER`, and buffers the whole input
because it is not restartable.

For scalar descriptors with explicit or named tags, CER input with indefinite
constructed wrappers ending in a definite primitive is supported. Tested BER
compatibility also includes a definite constructed child. A nested scalar
wrapper chain that mixes definite and indefinite lengths among its constructed
layers can still be rejected by the pre-existing `ber_check_tags` limitation.
This is a BER-family input limitation; it does not restrict CER encoder
output.

Opaque `ANY` input retains the existing BER decoder's permissive byte-container
behavior, including empty or multiple-TLV explicit containers. This is runtime
compatibility, not a claim that such containers encode one standards-conforming
open-type value. Legacy definite containers also preserve an exact `00 00`
pair as opaque bytes; that pair does not close a definite frame. Malformed
tag-zero headers and missing required EOCs are rejected. Length bounds,
nesting, and EOC checks still apply. Typed string
wrappers continue to require exactly one child value. The
[regression-fix design](cer-encoder-plan.md#follow-up-design-for-the-three-generated-c-test-failures)
documents this distinction and the character-string fragment-tag correction.

The C runtime provides `cer_encode()` and `asn_encode(ATS_CER, ...)`, and the
generated converter accepts `-ocer`. The C target enables CER encoding by
default alongside BER support. `-no-gen-CER` disables CER encoding and
strict decoding support; it need not remove the CER skeleton source from the shared BER-family
dependency closure. `-no-gen-BER` also disables the shared BER-family
dependencies. The encoder walks generated type descriptors; support is limited
to descriptor kinds and canonical value forms that the walker implements. It
does not add a CER operation-table slot or change that ABI.

The current descriptor set covers BOOLEAN, NULL, raw and native
INTEGER/ENUMERATED, raw REAL, native REAL stored as `float` or `double`,
OBJECT IDENTIFIER and RELATIVE-OID with minimal complete base-128 arcs,
BIT STRING, OCTET STRING, UTCTime, and GeneralizedTime. Built-in character
strings are supported when their primitive operation matches a recognized
runtime encoder: UTF8String, NumericString, PrintableString, IA5String,
VisibleString/ISO646String, ObjectDescriptor,
GeneralString, GraphicString, VideotexString, TeletexString/T61String,
UniversalString, and BMPString. SEQUENCE, SET, CHOICE, SEQUENCE OF, and SET OF
are supported through generated descriptors. Generated member metadata
supplies tags and defaults; the encoder omits default-valued members. `SET`
fields are ordered by their minimum effective tag, including the minimum
alternative tag for a CHOICE.
`SET OF` elements are ordered by their final CER encodings, comparing shorter
encodings as if zero octets were appended for comparison only. Long supported
strings use 1000-content-octet fragments; BIT STRING fragments reserve one
content octet for the unused-bit count, leaving at most 999 payload octets.
The fragment tag is universal 3 for BIT STRING and universal 4 for OCTET
STRING and restricted character strings. Character-string outer tags retain
their descriptor-specific values.
Named BIT STRING values remove trailing zero bits; ordinary BIT STRING values
preserve them. Member and explicit/implicit tag metadata is applied at each
descriptor boundary.

Typed open-type members are encoded when the parent selector resolves a
concrete type. Opaque `ANY` and unresolved standalone open types are rejected;
the encoder does not pass through arbitrary stored bytes. REAL encoding is
limited to zero, special values, and minimal binary base-2 forms whose exponent
uses at most eight octets; decimal and noncanonical raw forms are rejected.
Unknown or custom primitive operations are also rejected. UTCTime values are
validated and normalized to UTC seconds with `Z`, for output years 1950
through 2049. GeneralizedTime accepts adapter-parsable hour-, minute-, and
second-precision forms with an explicit `Z` or signed numeric offset; output
is normalized to seconds with `Z`. Fractional seconds accept a comma or period
on input, are limited to nine digits, and use a period in output with trailing
zeroes removed. Fractional hours or minutes, missing zones, and excess
fractional precision are rejected. Calendar and zone fields are validated,
and normalization must stay within the four-digit year range 0001–9999.

Primitive content capture uses a shallow descriptor copy with one resolved
intrinsic tag; the CER walker applies the original descriptor and member
wrappers afterward. CER tag-chain bounds therefore apply to those effective
wrappers, independent of the primitive content adapter's tag limit.

Resource ceilings default to 64 MiB encoded output, 128 MiB aggregate active
scratch storage, 1,000,000 collection elements, 4,000,000 descriptor/value
visits, and recursion depth 30. Descriptor tag chains are also capped at 30 by
default. Both depth and tag-chain limits use `ASN_STACK_OVERFLOW_LIMIT`; the
existing optional codec-context stack limit also applies to recursive
traversal. An additional explicit member tag counts as another tag-chain layer,
while a replacement tag does not. Excess tag chains return `EOVERFLOW` before
the tag array is read. The four CER ceilings are configurable through
`ASN_CER_MAX_ENCODED_SIZE`, `ASN_CER_MAX_SCRATCH_SIZE`, `ASN_CER_MAX_ELEMENTS`,
and `ASN_CER_MAX_WORK_ITEMS`. Invalid values or malformed descriptor/count
metadata return `EBADF`; exceeding configured element-count, tag-chain, depth,
output, scratch, or work limits returns `EOVERFLOW`. Unsupported forms return
`ENOENT`, a short direct buffer
returns `ENOSPC`, and allocation or callback failures are reported as `ENOMEM`
or `EIO`.

The Rust backend emits CER encoding and strict decoding for top-level BOOLEAN,
NULL, finite nonextensible INTEGER ranges fitting `i64`, direct nonextensible
ENUMERATED roots fitting `i64`, and direct fixed or bounded BIT STRING and
OCTET STRING values with finite `SIZE` constraints. The string path includes
the 1000-content-octet CER fragmentation rule; strict decoding re-encodes and
compares the consumed prefix. With `-gen-BER`, these direct types also receive
BER prefix decoding and DER encoding. BER accepts constructed BIT/OCTET STRING
forms within bounded nesting. Flat SEQUENCE records with an untagged outer type also support
required, OPTIONAL, and literal BOOLEAN/INTEGER DEFAULT fields when every
field is a direct BOOLEAN, NULL, finite bounded INTEGER, nonextensible
ENUMERATED, or finite bounded BIT/OCTET STRING with a distinct effective tag;
empty records are supported. Other constructed records remain
outside the Rust BER/DER/CER slice.
An untagged, unconstrained top-level INTEGER also has a separate
arbitrary-precision signed-byte Rust representation when only BER and/or CER
are selected. It supports BER prefix decoding, DER encoding, CER encoding,
and strict CER decoding under finite input, output, work, and scratch limits.
The C comparison uses `-fwide-types`; the default native C INTEGER storage on
the probed host did not represent values beyond `i64`. Rust deliberately
rejects an empty BER INTEGER content that the wide C decoder accepts.
Untagged, unconstrained top-level BIT STRING and OCTET STRING values also
support the same BER/DER/CER operations under BER/CER-only selection. The
generated wrappers own a validated BIT STRING value or OCTET STRING bytes.
CER fragmentation starts above 1000 content octets; for BIT STRING the
unused-bit count occupies one content octet. BER accepts constructed forms,
including nested definite and indefinite lengths, while strict CER compares
the canonical re-encoding. Rust rejects a non-final BER BIT STRING fragment
with unused bits that the C BER decoder accepts; this malformed form violates
X.690 section 8.6.4.
Direct untagged, unconstrained OBJECT IDENTIFIER and RELATIVE-OID roots also
support BER prefix decoding, DER and CER encoding, and strict CER decoding
under BER/CER-only selection. Their Rust values retain canonical base-128
content bytes, including subidentifiers larger than machine integers. BER
normalizes redundant leading base-128 groups. Rust rejects empty or
unterminated content that C BER may retain; strict CER requires the minimal
primitive encoding. These roots use finite input, output, work, and aggregate
scratch limits. Tagged, constrained, aliased, imported, and member OID forms
remain outside the Rust slice.
Direct untagged, unconstrained IA5String roots support BER prefix decoding,
DER encoding, CER encoding, and strict CER decoding under BER/CER-only
selection. BER and DER preserve arbitrary content bytes as the C codecs do;
CER checks the IA5 7-bit repertoire. Constructed BER uses universal OCTET
STRING fragments under the IA5 outer tag, and canonical CER fragments content
above 1000 octets. An empty constructed BER value normalizes to empty Rust
bytes and can be encoded as canonical `16 00`; the C BER decoder leaves a null
buffer for that form, so its later constraint check or CER encode fails.
The other direct restricted character-string roots with universal tags 7, 12,
18 through 21, 25 through 28, and 30 use the same raw BER/DER and canonical
CER entry points under BER/CER-only selection. TeletexString/T61String and
VisibleString/ISO646String retain distinct generated names for their shared
tags. CER applies the C descriptor's Numeric, Printable, Visible, UTF8,
BMP, or Universal check; ObjectDescriptor, Teletex, Videotex, Graphic, and
General have no effective C character validator. The UTF8 check accepts
minimal legacy five- and six-byte forms, surrogate values, and values above
the Unicode scalar range, as the C descriptor does. Fragmentation is bytewise
and may split a UTF8 sequence between tag-4 children; validation follows
reassembly. The C compatibility target does not establish X.690 escape-state
canonicality for the permissive legacy types. Tagged, constrained, aliased,
imported, and other member character strings remain outside the Rust slice.
Direct untagged, unconstrained UTCTime roots support BER prefix decoding, DER
encoding, CER encoding, and strict CER decoding under BER/CER-only selection.
BER accepts raw and constructed tag-23 content with universal tag-4 children;
DER preserves the raw bytes. CER accepts valid 1950 through 2049 Gregorian
times in the C-supported seconds-optional, Z-or-numeric-zone syntax, converts
the zone to UTC, and emits primitive `YYMMDDhhmmssZ`. Strict CER rejects
noncanonical text or framing. Checked calendar arithmetic accepts the valid
1969-12-31 23:59:59 UTC instant that C rejects through a `time_t == -1`
sentinel. Tagged, constrained, aliased, imported, and member UTCTime forms
remain outside this Rust slice.
Direct untagged, unconstrained GeneralizedTime roots also support BER prefix
decoding and DER/CER encoding with strict CER prefix decoding under BER/CER-only
selection. BER preserves arbitrary raw tag-24 content and constructed tag-4
fragments. DER and CER normalize valid explicitly zoned forms to primitive
`YYYYMMDDhhmmss[.fraction]Z`, with up to nine fractional digits and trailing
zeros removed. This qualified gate rejects zoneless DER input, invalid dates,
and longer fractions that the C DER adapter may interpret using the host
timezone, normalize, or truncate. The C `time_t == -1` sentinel also rejects
one valid epoch-edge instant that checked Rust arithmetic accepts. Tagged,
constrained, aliased, imported, and member GeneralizedTime forms remain gated.
Direct untagged, unconstrained SEQUENCE OF and SET OF roots with one direct
BOOLEAN, NULL, or finite bounded `i64` INTEGER element also have BER prefix
decoding, DER/CER encoding, and strict CER prefix decoding under BER/CER-only
selection. BER accepts definite and indefinite roots, duplicates, and any
SET OF order. DER uses a definite root; CER uses an indefinite root and EOC.
SEQUENCE OF preserves member order, while SET OF sorts complete canonical
child TLVs by padded octet order. The runtime caps element count, work,
decoded storage, sorting scratch, and output. Bounded INTEGER element range
checks occur during Rust decoding; C BER may defer the subtype constraint
check. BER BOOLEAN elements accept C-compatible empty or multi-octet content;
strict CER requires one canonical content octet. Root SIZE constraints,
tags, aliases, imports, nested elements, and
broader C collection forms remain outside this qualified slice.
Direct untagged, nonextensible CHOICE roots with one through three unique
BOOLEAN, NULL, or finite bounded `i64` INTEGER alternatives also support BER
prefix decoding, DER/CER encoding, and strict CER prefix decoding under
BER/CER-only selection. The selected alternative is the complete wire value;
there is no CHOICE wrapper. BER accepts C-compatible primitive aliases and
BOOLEAN content forms, while strict CER requires the canonical selected TLV.
Rust checks bounded INTEGER ranges during decoding, whereas C BER may defer
the subtype check. Tagged, referenced, extensible, nested, and broader C
CHOICE forms remain outside this qualified slice.
Flat SET records with an untagged outer type and the same six direct field kinds are
available when only BER and/or CER are selected. BER accepts members in any
order; DER/CER emits them by ascending effective tag class and number, and strict CER rejects
a reordered input. The SET path uses the same bounded record context.
Resolved context-specific IMPLICIT and AUTOMATIC member tags and one
context-specific EXPLICIT wrapper per direct field are supported through the
C tag-number limit; high-tag BER aliases are accepted, while strict CER
requires the shortest identifier. EXPLICIT wrappers contain one intrinsic
universal child; tagged constructed strings use universal identifiers for
their fragments. One nonrecursive inline SEQUENCE child is supported inside
an untagged SEQUENCE or BER/CER-only SET, with up to six direct supported
primitive leaves and required/OPTIONAL presence. Child record tags may be
natural, resolved context-specific IMPLICIT, or one EXPLICIT wrapper. Parent
and child share one record context and an opt-in fixed aggregate scratch cap.
One nonrecursive inline SET child with the same direct leaves and tag modes is
also supported under BER/CER-only selection in an untagged SEQUENCE or SET.
Its BER fields may arrive in any order; DER/CER sorts the child fields by
effective tag independently of any parent SET sort. Empty inline SET children
remain gated because the unmodified C generator does not compile that schema.
Both child kinds share the parent record budget and exact nested boundary checks.
One natural, unconstrained IA5String member is also supported in an untagged
flat SEQUENCE or SET under BER/CER-only selection, with required or OPTIONAL
presence and the existing supported scalar siblings. BER accepts primitive or
constructed tag-22 content with universal tag-4 fragments; DER preserves raw
bytes; CER checks the 7-bit repertoire and fragments content above 1000
octets. Generated operations select aggregate scratch accounting even when
the OPTIONAL member is absent. The aggregate cap counts record-owned output
and retained decoded storage; caller-owned spare input capacity is excluded.
Tagged or constrained IA5 fields, nested records, multiple IA5 fields, and
mixed-codec record forms remain gated.
One inline primitive CHOICE child with unique BOOLEAN, NULL, or bounded `i64`
INTEGER alternatives is supported under BER/CER-only selection. An untagged
SEQUENCE parent accepts a natural or one context-specific EXPLICIT CHOICE;
an untagged SET parent accepts natural or one EXPLICIT CHOICE. Required and OPTIONAL
presence share one logical field slot across all alternatives. BER reads the
selected primitive with the parent's budget; strict CER compares the canonical
parent prefix. For a natural CHOICE in SET, DER orders by the selected arm tag
and CER by the lowest declared arm tag. The writer tracks that ordering key
separately from the selected wire tag used to detect duplicates.
One resolved context-specific IMPLICIT tag on a direct flat SEQUENCE or SET
root is also supported under BER/CER-only selection, with a tag number through
`0x3fff_ffff`. BER accepts a C-compatible nonminimal high-tag alias; strict
CER requires the shortest identifier and an indefinite constructed root.
SET retains unordered BER member decoding and effective-tag-ordered DER/CER
output. Other root tags, multi-tag stacks, aliases, and broader C forms remain
outside this slice.

Rust codec defaults include UPER and CER; `-no-gen-UPER` selects CER-only
generation. See [the Rust implementation matrix](rust/implementation.md#implemented-boundary)
and [parity design](rust/ber-der-cer-design.md) for the remaining C-supported
types and schema forms.

CER is a constrained form of BER. The primary
[X.690 (2015) text, sections 9.1, 9.2, 9.3, and 11.6][x690]
specifies indefinite lengths for constructed encodings, segmented string
forms, tag ordering for `SET` components, and ordering of complete `SET OF`
encodings. String fragments use the 1000-content-octet boundary. CER encoding
implements these rules for its supported descriptors, and strict CER decoding
rejects input that does not match them.

## Other binary families

### OPTIONAL, CONTAINING, ANY, and OPEN TYPE

C constructed codecs use generated presence metadata for `OPTIONAL` members.
For `BIT STRING (CONTAINING Type)` and
`OCTET STRING (CONTAINING Type)`, the
syntax-aware constraint checker decodes the embedded value, checks its own
constraints, and requires a complete encoding. The OCTET STRING checker
accepts only zero padding after the last PER bit; non-PER encodings must
consume every octet. The [CONTAINING smoke test](../tests/tests-asn1c-smoke/check-CONTAINING.sh)
covers valid and invalid UPER and APER encodings, including spare values,
padding, and trailing data. Random filling of OCTET STRING CONTAINING values
does not yet construct a valid embedded value.
Inline contained types receive generated descriptors that preserve their
constraints and codec metadata. PDU-only generation includes descriptors
referenced solely through `CONTAINING`. Parameterized types are supported when
the actual contained type is supplied as an argument or when the contained
type refers to a bound formal type. The
[inline regression](../tests/tests-c-compiler/check-src/check-603.-gen-UPER.c)
covers bounded INTEGER and constructed contained types under UPER, APER,
OER, and BER. Syntax-aware constraint checking limits nested calls to 64,
so recursive contained values fail safely at that depth.

`ANY` remains an opaque encoded-value container with codec-specific behavior;
the BER compatibility boundary is described above. C BER/DER, OER, CBOR,
XER and JER adapters preserve the public signed-size `ANY_t` layout. Their
regressions cover complete values, malformed input, and split BER and JER
input. IOC-selected `OPEN TYPE`
uses its selected concrete descriptor. The
[JER OPEN TYPE regression](../tests/tests-c-compiler/check-src/check-602.-findirect-choice.-fcompound-names.-gen-JER.c)
covers a selected value with an `OPTIONAL` field, truncation, and malformed
input. C SET APER and OER defer root open-type decoding until their selectors
are available, including when a root open member precedes its selector in
canonical wire order. APER and OER SET also support open types in extension
additions, including selectors carried in later additions. Extension additions
use a nested open-type envelope; OER retains the encoded value across partial
input until its selector is available. UPER SET also supports direct root and
extension-addition open values with deferred selector resolution and nested
addition envelopes. Unknown UPER selectors fail because its selected-value
runtime has no opaque fallback. The
[generated SET IOC regression](../tests/tests-asn1c-smoke/check-SET-open-type.sh)
covers open roots and additions with selectors in later canonical or extension
order. Direct SET OPEN TYPE members also support JER with the selector before
or after the value; duplicate keys and mismatched selectors are rejected. For
such SETs, incomplete JER objects return `RC_WMORE` with zero bytes consumed,
so callers must retain and replay the complete object. OPEN TYPE leaves inside
SET extension groups remain unsupported in JER. OER rejects selected values
that leave trailing bytes inside their open-type envelopes. Constructed storage validation permits pointer-recursive
layouts and rejects graphs beyond 64 nested levels, 1024 distinct cached types,
or 16384 descriptor visits.

BMPString and UniversalString JER encoders emit valid JSON strings: quotes,
backslashes, and C0 controls are escaped, and invalid Unicode scalar values or
misaligned storage lengths fail encoding. SEQUENCE extension-addition groups
are represented as flat sibling fields in the outer JER object. Their fields
are encoded and decoded in declaration order; a present group must include its
required children. Unknown extension values are skipped only after strict JSON
value parsing, including nested arrays, objects, and escaped strings. The flat
group path rejects duplicate and out-of-order known fields. OPEN TYPE leaves
inside SEQUENCE extension groups remain unsupported by this path.

Direct SET XER OPEN TYPE members support selector-first decoding once every
other sibling has appeared. This conservative rule also rejects a present
open value when an unrelated OPTIONAL sibling is absent. The encoder rejects
canonical order that would put the open member before a sibling. Partial open
XML members return `RC_WMORE` with zero member bytes consumed; callers retain
and replay those bytes. Open leaves inside SET extension groups and a
self-closing outer open-member element remain unsupported.

Direct SET BER/DER OPEN TYPE support covers one explicitly tagged open member
with an unambiguous tag route. BER waits for a complete SET TLV, returning
`RC_WMORE` with zero bytes consumed until the caller can replay it. Two-pass
decoding permits the selector before or after the open value; DER sorts the
selected field canonically. A present open value requires every non-open
sibling to be present before selector invocation, so an omitted unrelated
OPTIONAL or DEFAULT sibling is conservatively rejected. Untagged, colliding,
multiple, and extension-group open members remain unsupported in this path.

The Rust backend supports `OPTIONAL` fields in its documented UPER and CBOR
flat SEQUENCE subsets. UPER includes inline nonextensible ENUMERATED, opaque
`ANY`, and primitive `CONTAINING` values. Direct `ANY` supports UPER, APER,
OER, JER, and CBOR. Opt-in CBOR adds direct BOOLEAN, NULL, bounded INTEGER,
fixed/bounded BIT and OCTET STRING, flat SEQUENCE maps, narrow CHOICE maps,
IOC-selected OPEN TYPE, and top-level typed primitive CONTAINING values.
Rust CBOR SET/collections, nested constructed fields, wider selected object
sets, and indefinite items remain unsupported.
UPER `CONTAINING` supports unconstrained BIT/OCTET STRING containing a local
direct BOOLEAN or non-singleton bounded INTEGER, at top level or as a required
or OPTIONAL SEQUENCE field. A narrow UPER, APER, OER, and CBOR IOC-selected
`OPEN TYPE` subset supports one local nonextensible object set with bounded
INTEGER selectors and primitive BOOLEAN or bounded INTEGER rows in a two-field
required SEQUENCE. APER requires selector bounds 0..255 and selected INTEGER
range spans at most 255. Other forms are rejected before output publication. See the
[Rust implementation boundary](rust/implementation.md#implemented-boundary).

### C SET support in OER and APER

The C `SET` operation table has OER and APER encoders and decoders for
nonextensible `SET` types and individual extension additions in both codecs.
Root members and their optionality bits follow
canonical tag order. An untagged `CHOICE` is placed by its lowest root
alternative tag, even when another alternative is selected or an extension
alternative has a lower tag. The OER decoder supports input split across
calls and frees its retained presence map when an incomplete value is freed.
The APER codec uses child APER operations, including aligned member
encodings. Both codecs support root table-selected open types. An open
component can precede its selector in
canonical SET order; decoding that form requires deferred component resolution.
The shared OER open-type decoder now releases incomplete or failed CHOICE
wrappers through their descriptor, with a focused malformed-input regression.
Generated C UPER descriptors now carry versioned root and addition maps.
UPER and APER encode and decode individual SET extension additions, including
roots after a second extension marker, and skip unknown additions during
decoding. APER uses aligned open types for additions. Version 3 descriptors
also encode and decode SET extension groups as SEQUENCE open types in UPER,
APER, and OER. Empty or DEFAULT-only groups are omitted, and unknown groups
are skipped. Legacy group descriptors fail closed in these codecs. OER
streams roots, the extension bitmap, and known or unknown open types across
input chunks. It restores omitted DEFAULT additions and rejects malformed
bitmap padding and open types with trailing child bytes. Its decoder accepts
an empty or all-zero extension map when the extension bit is set, matching the
existing C SEQUENCE decoder's permissive behavior; the encoder sets that bit
only when at least one addition is present.

The focused generated C regressions are
[check-593](../tests/tests-c-compiler/check-src/check-593.-gen-UPER.c),
[check-594](../tests/tests-c-compiler/check-src/check-594.-gen-OER.c), and
[check-595](../tests/tests-asn1c-compiler/595-set-aper-OK.asn1).
They exercise canonical ordering, presence/default handling, streaming OER,
single-flavor generated dependencies, malformed input and metadata, and
unsupported extensions. The runtime APER tests also cover alignment and
truncated input. The root ordering follows [X.691 section 21][x691], while
OER SET ordering follows [X.696 section 18][x696].
The additional [check-596](../tests/tests-c-compiler/check-src/check-596.-gen-UPER.c)
and [check-597](../tests/tests-c-compiler/check-src/check-597.-gen-UPER.c)
cover versioned metadata, known and unknown UPER additions, and truncation.
[Check-598](../tests/tests-c-compiler/check-src/check-598.-gen-APER.c)
covers APER additions, trailing-root order, DEFAULT restoration, unknown
additions, truncation, and malformed metadata.
[Check-599](../tests/tests-c-compiler/check-src/check-599.-gen-OER.c)
covers OER additions, independent wire vectors, trailing-root and extensible
CHOICE ordering, DEFAULT restoration, unknown additions, every input split,
malformed bitmaps, and strict open-type payload consumption.
[Check-600](../tests/tests-c-compiler/check-src/check-600.-gen-UPER.-gen-APER.-gen-OER.c)
covers grouped additions with independent UPER, APER, and OER vectors, empty
groups, DEFAULT restoration, older-schema skipping, malformed v3 metadata,
and OER streaming and payload validation.
[Check-601](../tests/tests-c-compiler/check-src/check-601.-fcompound-names.-gen-JER.-gen-CBOR.c)
covers flat SET group members in JER, split input, defaults, renamed and
duplicate keys, and malformed metadata. CBOR now flattens SET extension-group
leaves into the same name-keyed map as JER: a group leaf appears beside direct
SET members, and an absent group contributes no map entries. This is a
repository-specific CBOR mapping. Duplicate names across direct and grouped
members fail before encoding or decoder allocation; group OPEN TYPE leaves
remain unsupported.
[Check-608](../tests/tests-c-compiler/check-src/check-608.-fcompound-names.-gen-JER.c)
covers flat SEQUENCE group output, round trips at every input split, missing
required group children, duplicate and out-of-order keys, unknown JSON values,
malformed storage offsets, and callback failures.

SET constraint checking visits each present member, including OPTIONAL members,
and rejects absent mandatory pointers. CER permits an absent OPTIONAL ANY
member in SEQUENCE or SET, producing the usual empty component encoding when
no other members are present. A present opaque ANY remains unsupported in CER.
SET CBOR decoding rejects missing required members and duplicate map keys,
including duplicate unknown keys. Direct IOC-selected CBOR SET open members
are resolved against their selector regardless of map-key order. An absent
OPTIONAL open member is accepted; malformed selections, wrappers, and repeated
keys fail. Open leaves inside SET extension groups remain unsupported in CBOR
and UPER. Opaque selector callbacks require every other flat SET member to be
present, so a present open value with an absent unrelated OPTIONAL sibling is
rejected. CBOR selection from another deferred open member is unsupported.

SEQUENCE CBOR uses the same direct member-name map: the encoder writes members
in declaration order, while the decoder accepts any key order. Decoding rejects
missing required members and repeated known or unknown keys. A direct
IOC-selected OPEN TYPE may precede its selector in the map; the decoder stages
the value until the parent is complete and preserves a preallocated parent on
failure. Omitted pointer-backed and inline generated DEFAULT values are
restored in staged storage. Opaque selector callbacks require every other
sibling to be present, so a present open value with an absent unrelated
OPTIONAL sibling is rejected.
SEQUENCE extension groups remain unsupported in CBOR.
CBOR map text keys and skipped text items are checked for valid UTF-8.

C CBOR CHOICE uses a one-entry text-key map. The encoder validates its active
arm before output. The decoder checks the key, complete child item and active
arm in staged storage, preserving a preallocated CHOICE on failure. Unknown or
malformed keys and incomplete child values fail.

CBOR `SEQUENCE OF` and `SET OF` use definite arrays in list order. The C
encoder rejects null element holes and inconsistent list counts before writing
the array header. The decoder bounds the declared count by available input,
checks each child consumes a nonempty item, and stages the whole array so a
failure preserves a preallocated caller value. The shared CBOR item skipper
also rejects malformed UTF-8 text inside nested unknown values.
The UTF8String adapter validates text and compatible byte-string input as
UTF-8 and preserves preallocated values when a malformed length is rejected.

CBOR BIT STRING and OCTET STRING remain byte strings; a CONTAINING constraint
does not introduce another CBOR wrapper. The C CBOR codec carries the contained
bytes; `asn_check_constraints` with CBOR syntax checks that those bytes form a
complete value of the contained type. BIT STRING uses an initial unused-bit
count octet and rejects nonzero padding. Byte-string decoders reject truncated
or overflowing lengths without replacing an existing value. INTEGER decoding
preserves existing values on failure and converts negative major-one values
below `INT64_MIN` into BER bytes without host-endian dependence. Unknown-item
skipping checks nested lengths and accumulated byte counts before advancing.

The generic binary selectors map to their implemented codec families.
Basic/canonical OER and PER decode selectors share
the same family entrypoint. The DER decode selector shares the permissive BER
decoder and is not a strict canonicality check; the CER selector is strict.

CBOR uses a separate repository mapping for ASN.1 values. It is not an ASN.1
encoding rule. Claims of complete deterministic encoding require checking more
than shortest integer/length forms, including floating-point choices and map
ordering under [RFC 8949 section 4.2](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2).
This change does not establish blanket deterministic-CBOR conformance.

The generated converter accepts `-iber` and `-ider` as permissive BER-family
input selectors and `-icer` as the strict CER input selector. Output supports `-oder` and `-ocer` for their respective
encoding rules.

## PER flavor selection (UPER and APER)

`-no-gen-UPER` and `-no-gen-APER` each omit every skeleton file of the disabled
flavor (`uper_*`/`*_uper.c` or `aper_*`/`*_aper.c`) and define
`ASN_DISABLE_UPER_SUPPORT` or `ASN_DISABLE_APER_SUPPORT`. Code needed by both
flavors must therefore live in a module that both the `CODEC-UPER` and
`CODEC-APER` sections of `skeletons/file-dependencies` emit, normally
`per_support.[ch]`. One example is the checked range helpers
`per_{long,imax,umax}_range_{rebase,unrebase}()`. An APER file that calls a
`uper_support` function, or the reverse, compiles when both flavors are
generated but breaks single-flavor projects. The 2026-10-20 fix moved the range
helpers out of `uper_support.[ch]` for this reason.

[check-PER-single-flavor.sh](../tests/tests-asn1c-smoke/check-PER-single-flavor.sh)
runs this check quickly. It builds APER-only and UPER-only converters and asserts
that no file of the disabled flavor is emitted. It round-trips constrained
INTEGERs, checks that the bytes match a combined build, and fails on the
pre-fix tree. The slower per-type smoke tests also run each `-no-gen-*` variant.
The skeleton archives are `check_LTLIBRARIES`, so after moving skeleton symbols
between files you must rebuild them with `make -C skeletons check`. Otherwise
stale objects cause duplicate-symbol link errors in `tests/tests-skeletons`.

## Verification

The PER INTEGER security regressions are covered by
[`check-PER-INTEGER-security.c`](../tests/tests-skeletons/check-PER-INTEGER-security.c).
For native unsigned INTEGERs, both PER constraint-bound slots contain unsigned
bit patterns even though the legacy structure declares them as `intmax_t`.
Code must interpret both slots as `uintmax_t`, validate the bounds and offset,
and only then add or subtract. The checked unsigned helpers in `per_support`
also reject null output pointers and reversed bounds without changing output.
APER range alignment uses a checked maximum offset rather than an inclusive
signed range size, which can overflow at full-width bounds.

For semi-constrained `INTEGER (0..MAX)`, decoding preserves the positive byte
buffer directly, including values wider than `uintmax_t`. NativeInteger
conversion remains responsible for rejecting values too wide for native
storage. This restores zero-bound decoding; it does not add arbitrary-precision
arithmetic for nonzero lower bounds or expand the existing encoder limits.
The single-flavor smoke test also generates native uint64 fields whose lower
or upper bounds exceed `INTMAX_MAX`, and round-trips them in APER-only,
UPER-only and combined builds.

The regression executable runs under the configured skeleton sanitizers and
exhausts all 256 one-octet inputs for a seven-bit range near `UINTMAX_MAX`.
It also checks truncated determinants/payloads, negative unsigned values,
malformed API arguments and full signed-range encoding. The four codec entry
points are split into documented helpers; Clang control-flow graphs give a
maximum cyclomatic complexity of 19 for these codec functions, below the
project limit of 20. Each function is also shorter than 200 lines.

The 2026-10-12 fragment-tag and opaque-ANY compatibility correction passes the
complete generated C suite (71/71) under the configured ASan/UBSan test flags.
Freshly rebuilt normal, strict, and C89 skeleton archives pass the linked
skeleton suite (52/52). The updated generated CER converter check passes all
three codec-enable/disable configurations, and the generated Rust harness
passes its 10 conformance tests and C UPER/CER interoperability checks. The
main build and regenerated manuals also pass their checks. See the
[follow-up design](cer-encoder-plan.md#follow-up-design-for-the-three-generated-c-test-failures)
for the exact compatibility boundary and new negative vectors.

The following records the earlier CER implementation qualification:

The corrected tag-capture encoder passes the linked skeleton suite (52/52) and
the fresh Rust harness (10 generated conformance checks). The Rust harness
includes fresh C UPER/CER reference comparisons, C decoding of generated Rust
UPER/CER bytes, codec-selection, and negative-schema checks. The unchanged C
compiler suite passes 7/7. A fresh ASan/UBSan fuzz run processed 660,325
mutations in 16 seconds without a sanitizer failure, and independent seed bytes
passed. This is a short fuzz run, not a long campaign.

The generated CER converter script passes for all three C codec-disable
variants, including direct generated multi-wrapper vectors and CER re-decoding.
All 28 generated smoke tests and the installed-toolchain qualification also
pass. Source-distribution qualification passed with all 13 required assets
present. The randomized driver is wired to feed BER-decoded corpus values to
generic `ATS_CER` encoding. At that time `ATS_CER` input used the permissive
BER decoder; it now uses strict `cer_decode()`.

Strict CER decoding is covered by
[check-CER-decode.c](../tests/tests-skeletons/check-CER-decode.c), updated
`check-CER.c` and `check-binary-dispatch.c` skeleton tests, and strict and
disabled-build cases in
[check-CER.sh](../tests/tests-asn1c-smoke/check-CER.sh).

[x690]: https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-201508-S%21%21PDF-E&lang=e&type=items
[x691]: https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.691-202102-I%21%21PDF-E&lang=e&type=items
[x696]: https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.696-202102-I%21%21PDF-E&lang=e&type=items
