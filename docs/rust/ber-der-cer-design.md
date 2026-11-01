# Rust BER, DER, and CER parity design

Status: approved architecture and staged plan with qualified slices already
implemented. Full C parity has not been reached. The compatibility target is
the C backend in this repository, qualified by the decisions below. The Rust
runtime currently supplies BER prefix decoding and DER and CER encoding, plus
strict CER prefix decoding, for BOOLEAN, NULL, finite bounded `i64` INTEGER,
unconstrained arbitrary-precision INTEGER, direct finite ENUMERATED, direct
unconstrained OBJECT IDENTIFIER and RELATIVE-OID, and fixed, bounded, or direct
unconstrained BIT/OCTET STRING values, direct untagged restricted character
strings, direct UTCTime, direct qualified GeneralizedTime, direct primitive
collections, and direct primitive CHOICE. See
`rust/asn1c-runtime/README.md` and
`libasn1compiler/asn1c_rust.c`. The generator rejects many schemas supported by
C, including imports, references, most root tags, and multi-tag stacks. These
rejections remain until the corresponding generated representation and codecs
are implemented.

The implemented SEQUENCE slice handles empty or flat records with an untagged
outer type and up to six distinct effective direct-field tags for BOOLEAN,
NULL, bounded INTEGER, ENUMERATED, and finite bounded BIT/OCTET STRING fields.
Required and OPTIONAL members and literal BOOLEAN/INTEGER DEFAULT members
share one operation budget. Resolved context-specific IMPLICIT and AUTOMATIC
member tags and one context-specific EXPLICIT wrapper per direct member are
supported. One nonrecursive inline SEQUENCE or nonempty SET child and one
primitive CHOICE child in the qualified parent/tag combinations are also
supported below; broader nested records and members remain in the parity
matrix.
BER/CER-only untagged flat records additionally qualify one natural IA5String
member or up to one natural OBJECT IDENTIFIER and one natural RELATIVE-OID
member, with the resource and schema gates described below.

The flat SET slice uses the same six direct field kinds under BER/CER-only
selection. Its BER reader accepts arbitrary member order;
the DER/CER writer emits ascending effective tags. Direct untagged,
unconstrained SEQUENCE OF and SET OF roots with one BOOLEAN, NULL, or bounded
`i64` INTEGER element are also implemented. Broader SET and collection shapes,
broader nested records, and multi-tag stacks remain future stages.

A BER/CER-only flat SEQUENCE or SET may use one resolved context-specific
IMPLICIT root tag in the C representable range. This replaces the outer
constructed identifier while retaining the member encodings. Other root tags
and tagged roots combined with nested fields remain gated.

## Architecture and interfaces

Use a shared, safe Rust TLV engine for identifiers, lengths, tag stacks and
constructed contents. It must check arithmetic and buffer boundaries before
advancing or allocating. It must handle high tag numbers, definite and
constructed indefinite lengths, and matching end-of-contents markers. Nested
parsing must not treat an end-of-contents marker as an ordinary value or
allow it to escape its enclosing indefinite value. Primitive indefinite
lengths are invalid. Tag handling needs explicit and implicit wrappers,
including CHOICE and open types, and must preserve the expected constructed
bit for the selected type.

Generated types should supply schema-specific descriptor information and
codec operations over a shared runtime context. Descriptors need the resolved
tag set, member and alternative metadata, defaults, constraints, extension
information, and open-type selection where applicable. Recursive ASN.1 types
need finite-size Rust representations and bounded traversal. Constraint checks
must be performed at the appropriate generated type boundary. Unsupported
schemas and codec combinations must fail before publishing generated output.

The existing generated `encode_der`, `decode_ber`, `encode_cer`, and
`decode_cer` entry points, `Encoded`, and `Decoded<T>` are the starting
interface. Prefix decoding reports the exact consumed bytes and bits; it must
not consume a suffix. DER and CER encoders produce complete octet-aligned
values. Preserve the existing primitive API and its limits semantics unless a
separately reviewed compatibility change is required. A streaming interface
is a separate unresolved decision, below. Type-specific handling must not
silently reinterpret a malformed or unsupported value as another type.

### Resolved field tags

The implemented tagged-field stage uses the fixed AST's resolved tag for each direct field.
An untagged field keeps its universal identifier. A context-specific IMPLICIT
tag replaces only the outer field identifier; the primitive content rules and
the universal identifiers of constructed BIT/OCTET STRING fragments remain
unchanged. Automatic tags are read from the fixed member metadata instead of
being recomputed from declaration position. A single resolved context-specific
EXPLICIT wrapper is supported for the same direct field kinds. References and
longer tag chains remain gated until the generator can represent and validate
the full chain.

The runtime keeps field kind separate from effective identifier class and
number. Readers match the full class/number pair, then validate the field's
primitive or constructed form against its declared kind. SEQUENCE preserves
declaration order, while SET canonical output sorts effective tags by class
and number. Tagged identifiers use checked high-tag parsing and minimal
encoding; BER may accept nonminimal identifiers that the C decoder accepts,
and strict CER rejects them by re-encoding. The tagged-field generator
gate limits tag numbers to the C target's representable range and rejects
duplicate effective tags before publishing output. The existing untagged
record API remains source compatible.

### IMPLICIT flat SEQUENCE and SET roots (qualified slice)

The tagged-root stage accepts a direct flat SEQUENCE or SET assignment with one
resolved context-specific IMPLICIT root tag from 0 through `0x3fff_ffff`,
selected only for BER and/or CER. It reuses the existing direct-field and
effective-tag validation. The runtime reader validates the constructed root
identifier before entering a bounded record; the writer charges identifier
growth and body movement to the same record context. DER emits a definite
outer length, while CER emits an indefinite outer length and matching EOC.
Strict CER compares the consumed prefix with a tagged-root re-encoding through
the same context. BER may accept a nonminimal high-tag alias compatible with
the C decoder, but strict CER rejects it. Tagged SET decoding keeps unordered
BER member dispatch; DER and CER sort members by effective class and number.

The generator keeps top-level aliases, references, imports, nested members,
multi-tag stacks, other tag classes and modes, and mixed codec selections
outside this gate. The untagged flat record API remains source compatible.

### EXPLICIT field wrappers (qualified slice)

The current tag stage accepts one resolved context-specific EXPLICIT tag
on each supported flat direct field. The effective outer tag determines
record dispatch and SET order; an intrinsic universal child retains the
declared field kind. DER wraps one complete child TLV in a constructed,
definite-length outer TLV. CER uses a constructed, indefinite-length outer
TLV and a matching EOC, with the child encoded under CER rules. Both layers
must charge the same record context, including child storage, wrapper bytes,
work, and depth.

BER decoding must accept a definite or indefinite EXPLICIT wrapper only when
it contains exactly one complete child of the expected intrinsic type. It
must reject missing or extra children, cross-boundary lengths, a primitive
outer identifier, and unmatched EOCs. Constructed BIT/OCTET STRING children
may have their own nested EOCs; wrapper traversal must match each level.
Strict CER comparison rejects a definite wrapper or noncanonical child. The
generator continues rejecting references, multi-tag chains, other
classes, broader nested records, and unsupported codec combinations until their
representation and tests are complete.

### Inline nested SEQUENCE (qualified slice)

The current record stage accepts one nonrecursive inline SEQUENCE member
inside a SEQUENCE or SET. It allows required and OPTIONAL members and the
existing direct primitive leaf kinds; constructed DEFAULT, extensions,
references, imports, CHOICE, and collections remain gated. It validates the
entire inline tree before generation, including effective-tag collisions,
optional dispatch ambiguity, field and node counts, and nesting depth.
An empty child is qualified only for BER/CER-only selection until the existing
UPER empty-child helpers pass strict Clippy; mixed UPER/BER/CER generation for
that shape fails before publication.

Nested readers and writers must borrow one `RecordContext`. A child reader
receives an input span bounded by its parent and must consume that span
exactly, including the matching EOC for an indefinite value. A child writer
must account for its retained output along with parent output and wrappers;
if it buffers a child, its simultaneous scratch storage needs an explicit
limit. That scratch count includes decoded string capacity charges during
strict CER re-encoding; charges remain spent if a nested callback fails, since
the callback may have captured a decoded value. Keep the internal aggregate
scratch ceiling separate from `max_output_bytes`, which still caps complete
output and retained decoded payloads individually. The generated child methods
must not call their own public entry points with fresh limits. DER uses
definite child lengths, while CER uses an indefinite child and EOC; an
EXPLICIT field adds another wrapper layer.

Use an opt-in nested operation context at the root so scratch accounting starts
before the first parent field and continues after the child callback, including
when an OPTIONAL child is absent. Reject nested callbacks on a flat context.
This preserves the existing flat record resource contract for callers that
configure output limits above the new internal scratch ceiling.

The acceptance tests include generated C/Rust vectors for natural, IMPLICIT, and
EXPLICIT child tags, absent and present children, nested CER EOCs, SET order,
string fragmentation, and DER length transitions. Reject truncated and extra
EOCs, child lengths crossing a parent boundary, duplicate or unknown fields,
trailing child bytes, and cumulative resource exhaustion. Check exact prefix
consumption and strict CER comparison at each outer boundary.

### Inline nested SET (qualified slice)

Extend the existing one-child, nonrecursive inline record gate to a SET child
within an untagged top-level SEQUENCE or SET under BER/CER-only selection.
Reject mixed UPER selection before publication, including a SEQUENCE parent;
UPER encoding of a SET child is a separate gate. Reject an empty inline SET
child before publication in this parity gate: the current unmodified C
generator does not compile that schema, so no C differential can qualify it.
Retain the same six direct leaf
kinds, required/OPTIONAL presence, distinct effective tags, and one nested
child cap. Exclude child DEFAULT values, extensions, aliases, references,
imports, recursive or multiple children, and wider tag stacks until their
representation and shared-budget behavior are designed and tested.

Represent the child record kind explicitly in the runtime field descriptor.
The natural child identifier is universal constructed tag 17; a resolved
context-specific IMPLICIT tag replaces that identifier, while one EXPLICIT
context-specific wrapper contains the intrinsic tag-17 child. Reuse the nested
`RecordContext` so parent and child parsing, writing, canonical comparison,
retained decoded buffers, and temporary child output share one work and scratch
budget. A nested SET reader dispatches leaf fields by effective tag in any BER
order; its DER/CER writer sorts by effective tag class and number. Parent SET
ordering still uses the outer effective tag of the child field. SET OF's
complete-TLV ordering rule does not apply to SET fields.
Generalize the current SEQUENCE-only `new_nested_writer`, `new_nested`,
`write_nested_sequence`, `read_nested_sequence`, `intrinsic_tag`, nested tag
application, and EXPLICIT-framing scanners before exposing SET callbacks.
`SetWriter` relies on generated field order, so the child generator must emit
its own sorted members independently of any parent SET sort. Preserve
transactional parent rollback on nested failure.

The C reference emits `30 08 31 06 80 01 02 81 01 ff` for an untagged
SEQUENCE containing a SET child with `[0] IMPLICIT INTEGER 2` and `[1]
IMPLICIT BOOLEAN TRUE`. Its CER form is
`30 80 31 80 80 01 02 81 01 ff 00 00 00 00`. Replacing the child tag with
`[3] IMPLICIT` changes `31` to `a3`; wrapping it with `[3] EXPLICIT` adds an
outer `a3` and retains the inner `31`. C BER accepts reversed child fields;
strict CER rejects that order and rejects the definite DER form. Acceptance
must compare these natural, IMPLICIT, and EXPLICIT vectors in both directions,
including parent SET ordering, absent OPTIONAL children, nested EOC matching,
exact prefix consumption, malformed framing/duplicates, and resource limits.
For a parent SET declared with `[4] IMPLICIT BOOLEAN` before `[3] EXPLICIT`
SET, C DER instead emits the child first:
`31 0d a3 08 31 06 80 01 02 81 01 ff 84 01 ff`; C CER emits
`31 80 a3 80 31 80 80 01 02 81 01 ff 00 00 00 00 84 01 ff 00 00`.
The parent and child sorts are independent.
For EXPLICIT child wrappers that mix definite and indefinite constructed
lengths, the existing C BER tag scanner rejects both layer orders. Follow the
current nested SEQUENCE compatibility decision: a well-framed Rust BER parser
may accept them, while strict CER rejects both by canonical comparison.
The generator must reject excluded schemas before publishing output.

Strict CER decoding uses BER decoding followed by canonical CER encoding and
comparison with exactly the consumed prefix. This matches the architecture of
`skeletons/cer_decoder.c`. A mismatch fails; resource exhaustion during either
pass is an error, not acceptance. The decoded value is published only after
comparison succeeds. DER and CER encoders share primitive validation where
appropriate, but differ in constructed lengths and string fragmentation.
SET ordering uses the rules for component tags; SET OF ordering compares the
complete canonical encodings. Defaults are omitted where required. CER strings
must use the specified fragmentation, including the BIT STRING unused-bits
octet; verify boundaries independently against X.690 and C.

## Resource policy

One operation owns one cumulative context. Check the entire supplied input
slice against `max_input_bytes`, as the current primitive API does; check the
complete output against `max_output_bytes`. Charge parsing, encoding,
comparison, element visits, sorting and both passes of strict CER decoding to
a shared work budget. Zero-length elements must still cost work. Define and
expose finite depth, element and aggregate scratch limits before generated
recursive codecs are enabled. Bound allocations and temporary sorted values,
including retained capacities and fragmentation overhead; use checked
arithmetic for all lengths, offsets, bit counts and budget charges. Never
allocate directly from an unvalidated wire length. Limits and accounting must
cover all recursive and open-type calls rather than resetting per child.

The current `Limits` struct has only input, output and work fields. Adding
public fields would break existing struct literals, so the extension mechanism
and defaults need an API review. C CER currently defaults to a 64 MiB encoded
size, 128 MiB aggregate scratch, 1,000,000 elements and 4,000,000 work items;
it also bounds recursive traversal and tag chains using
`ASN_STACK_OVERFLOW_LIMIT` (30 in `skeletons/asn_internal.h`). These are C
implementation ceilings, not the current Rust defaults or a promise to copy
their accounting units. Stage the change by first specifying a separate
extended policy and conversion from existing `Limits`, then adding opt-in
entry points or a compatible builder after API review, and finally applying
one shared context throughout recursive generated codecs. Existing entry
points must retain documented defaults and behavior unless a deliberate
breaking change is approved. Existing primitive resource behavior must
remain tested. When configured limits are reached, return a resource error
without panicking or exposing partially decoded values. Document whether a
streaming operation's input budget applies to aggregate supplied chunks or
consumed bytes; do not assume the existing whole-slice rule answers that.

## Parity matrix and acceptance

Each row requires generated C and Rust interoperability for all relevant tag,
constraint and nesting combinations, not merely a runtime helper. For each
supported value, compare DER and CER output byte-for-byte with C, decode C BER
and CER in Rust and Rust output in C, and check exact prefix consumption.
Use independent X.690 examples as well: a shared C/Rust defect must not be
mistaken for standard conformance. C output/acceptance divergences and their
resolution must be recorded. Unsupported cases must produce diagnostics until
all applicable gates pass.

| Coverage | Required cases |
| --- | --- |
| TLV and tags | All classes; low and high tag numbers; explicit, implicit and automatic tags; nested tag stacks; short and long lengths; constructed indefinite lengths and EOC; length, tag and offset overflow; truncation at every byte. |
| Scalars | BOOLEAN, NULL, INTEGER including unbounded and native representations, ENUMERATED including extensions, REAL and native REAL, OBJECT IDENTIFIER and RELATIVE-OID; values and constraints supported by C. |
| Strings and time | BIT STRING and OCTET STRING, all C-supported character strings, UTCTime and GeneralizedTime; empty and large values, unused bits, character/time validity, BER constructed forms and CER fragmentation boundaries. |
| Records | SEQUENCE and SET; optional and default members, nested records, extensions and extension groups; field order, unknown extension behavior, canonical SET order and default omission. |
| Alternatives and collections | CHOICE, SEQUENCE OF and SET OF; empty and nested values, selected tags, SET OF ordering on complete encodings, equal encodings and limits. |
| Schema composition | Defined types and aliases, imports, multiple modules, recursive types, explicit/implicit/automatic tagging, applicable constraints and generated names. |
| Open content | ANY and supported open types, selector-dependent types, unknown and invalid selections, tagging, extensions and applicable CONTAINING forms. |
| API and failures | Codec option combinations, complete and prefix input, invalid values and constraints, exact resource boundaries, malformed inputs, deterministic errors and no panic; streaming behavior once decided. |

Test DER minimal identifiers, lengths and primitive values; CER canonical
lengths, BOOLEAN, integers, ordering, omitted defaults and fragmented strings;
BER permissive encodings accepted by C where compatibility is selected.
Exercise string lengths around 999, 1000 and 1001 content octets, plus BIT
STRING's unused-bits overhead and multi-fragment cases. Test valid and invalid
nested indefinite forms, missing or extra EOCs, duplicate or missing members,
ambiguous alternatives, spare bits, lengths near `usize` limits and large
nesting. Differential fuzzing and regression corpora must include malformed
and truncated data, not only round trips. Run the Rust runtime and generated
project tests with all targets and features under the repository's exact
strict Clippy settings, plus the relevant C and generator suites.

## Incremental delivery gates

1. Establish C feature inventory and a reusable differential harness; settle
   observable error, prefix and compatibility contracts. Keep existing tests
   and primitive APIs passing.
2. Implement checked TLV and tag machinery and primitive families in bounded
   increments. Enable a generator case only after positive, negative, resource
   and cross-language tests cover that case.
3. Add references, imports, tag resolution and recursive representations with
   fail-closed diagnostics for still unsupported shapes.
4. Add records, alternatives and collections, including defaults, extensions
   and canonical ordering. Verify nested combinations and resource accounting.
5. Add open content, remaining primitive types and constraints, and CER string
   fragmentation. Cover C-specific behavior and independent standard vectors.
6. Resolve streaming and complete the matrix with differential fuzzing,
   regression suites, documentation and strict lint checks. Declare full
   parity only when every applicable row has evidence and documented decisions.

A stage is complete only when the supported subset is documented, generator
selection flags expose exactly the implemented operations, adversarial cases
fail safely, and checks pass. The matrix is a target, not evidence that C
implements every conceivable ASN.1 feature.

### Arbitrary INTEGER representation (qualified initial gate)

The first arbitrary INTEGER stage covers an untagged top-level,
unconstrained `INTEGER` under BER/CER-only selection. It introduces a
separate Rust type that privately stores a nonempty, minimal, big-endian signed
two's-complement byte sequence. Fallible constructors normalize sign padding;
borrowed canonical bytes and fallible `i64` conversion provide access without
a third-party bigint dependency. Existing bounded `i64` types and APIs remain
unchanged. This representation is mathematically unbounded, but each operation
is subject to the caller's finite input, output, work, and scratch limits.
The runtime value and generated wrapper move ownership and expose borrowed
inspection; they do not require an infallible `Clone` for large payloads.
The runtime surface is `BigInteger::try_from_signed_bytes`,
`as_signed_bytes`, and `try_to_i64`, plus separate
`encode_big_integer_der`/`encode_big_integer_cer` and
`decode_big_integer_ber`/`decode_big_integer_cer` functions. Conversion
overflow uses its own small error type or an explicit `Option`; it must not
silently truncate or change the existing runtime `Error` variants.

The BER reader accepts redundant sign extension as a C compatibility
extension and C-compatible nonminimal universal high-tag INTEGER identifiers,
normalizes the value, and preserves exact prefix consumption. Strict CER rejects
such identifier aliases by canonical comparison. The reader rejects an
empty INTEGER content. A local C probe showed that the wide C
`INTEGER_t` BER decoder accepts empty content, while strict CER rejects it;
mapping that malformed input to a valid Rust value would hide the defect. DER
and CER emit minimal primitive contents, and strict CER re-encodes and compares
through one operation budget. Input lengths and available bytes must be checked
before allocation, with bounded retained capacity and checked work for sign
trimming, copying, output, and comparison.

The C comparison for arbitrary values uses generated `-fwide-types`
descriptors: on the probed host, default unconstrained INTEGER generation used
native `long` storage and rejected values outside its width. Native width
variants, bounded ranges beyond `i64`, record fields, aliases, tags,
extensions, and constraint timing require separate gates. Tests cover both
signs across the `i64` boundary, 127/128 length transitions, malformed
lengths, truncation, nonminimal BER padding, strict CER rejection, exact
limits, and C wide-type interoperability.

### Unconstrained direct BIT and OCTET STRING (qualified direct gate)

An untagged top-level `BIT STRING` or `OCTET STRING` without a constraint,
named bits, or `CONTAINING` may use the existing standalone BER, DER, and CER
runtime codecs under BER/CER-only selection. The generated OCTET STRING wrapper
owns a `Vec<u8>`; the BIT STRING wrapper owns a validated `BitStringValue`.
Constructors consume those values without an additional copy. The codecs
check complete input, output, decoded storage, work, and exact prefix
consumption using the existing standalone runtime limits. This gate does not
derive an infallible `Clone` for potentially large owned values. It does not
change bounded string APIs or record member representations. Other codec
selections, tags, references, fields, and explicit `SIZE(0..MAX)` remain
outside this gate until their constraints and composition are qualified.

Check C and Rust at empty, 999/1000/1001 content-octet boundaries, with
multiple CER fragments and non-byte-aligned final BIT STRING fragments. Test
constructed BER strings with definite and indefinite nesting, fragment tag
aliases, padding normalization, malformed EOCs, lengths, unused-bit counts,
truncations, and resource ceilings. A local C probe accepts a non-final BIT
STRING fragment with unused bits, while the Rust BER reader rejects it.
[X.690 section 8.6.4](https://www.itu.int/rec/T-REC-X.690/en) requires every
segment except possibly the last to contain a
multiple of eight bits. Retain this deliberate malformed-input difference and
test it. Strict CER rejects the noncanonical C input as well. The existing
standalone string codecs bound retained and canonical buffers individually by
`max_output_bytes`; aggregate simultaneous scratch policy remains a separate
resource-design decision rather than a claim of complete C resource parity.
Another C probe found that its DER encoder masks nonzero unused low bits from
an invalid in-memory BIT STRING, while its CER encoder rejects that value.
The Rust `BitStringValue` constructor rejects it before either encoder runs;
valid masked values encode identically. BER decoding of nonzero wire padding
still normalizes it before strict CER comparison.

### Direct OBJECT IDENTIFIER and RELATIVE-OID (qualified initial gate)

The initial scalar gate covers untagged, unconstrained, top-level OBJECT IDENTIFIER
and RELATIVE-OID under BER/CER-only selection. Use distinct public Rust value
types with private, nonempty, canonical base-128 content octets. This preserves
subidentifiers larger than machine integers, which the C raw storage and CER
encoder accept. The first OBJECT IDENTIFIER subidentifier combines its first
two arcs; the public bytes are encoded content, not a numeric arc list.
These rules follow [X.690 sections 8.19 and 8.20](https://www.itu.int/rec/T-REC-X.690/en)
and [X.680 sections 32 and 33](https://www.itu.int/rec/T-REC-X.680/en).
Fallible constructors normalize redundant leading `80` groups in each
subidentifier and reject empty or unterminated content. Borrowed accessors
return canonical content; do not derive an infallible `Clone` for large values.
The runtime types should be `ObjectIdentifier` and `RelativeOid`, each with
`try_from_content(&[u8], &Limits)` and `as_content()`. Distinct
`encode_object_identifier_{der,cer}` and
`decode_object_identifier_{ber,cer}` functions, and the corresponding
`relative_oid` functions, keep the universal tags explicit.

BER decoding accepts C-compatible nonminimal high-tag aliases and redundant
base-128 leading groups, then normalizes the value and reports exact prefix
consumption. Strict CER re-encodes and compares through one cumulative input,
retained-output, scratch, and work budget; it rejects every nonminimal form.
The C BER decoder also accepts empty and unterminated contents and preserves
nonminimal contents for its DER encoder. Rust deliberately rejects empty and
unterminated values because they cannot represent valid OIDs. This difference
must be tested and documented. Primitive constructed forms are invalid.

The generator must reject tags, aliases, imports, constraints, fields, and
other codec selections before publishing output. Compare C and Rust vectors
for low and high combined first subidentifiers, relative arcs, values beyond
`u32` and `u64`, and 127/128 content-length transitions. Test truncated
base-128 runs, `80` at every subidentifier boundary, high-tag aliases,
malformed lengths and EOCs, suffix consumption, exact resource ceilings, and
mutations. Keep numeric-arc conversion optional and explicitly fallible if it
is added later.

### Direct IA5String (qualified initial gate)

The initial restricted-string gate covers only a direct untagged, unconstrained,
top-level IA5String with BER/CER-only codec selection. It does not enable
other character strings, references, members, imports, root tags, explicit
constraints, or mixed codec selections. The public runtime `Ia5String` owns
private bytes, has a fallible `try_from_bytes(&[u8], &Limits)` constructor and
a borrowed `as_bytes()` accessor, and does not derive infallible `Clone`.
Keep the bytes raw at construction: the C BER decoder accepts an octet above
`7f`, and its DER encoder reproduces it. The C CER encoder applies the IA5
constraint and rejects such a value; strict CER decoding rejects the same
wire form. Rust BER and DER should preserve this codec timing. Rust CER must
validate every byte is at most `7f` before encoding or publishing a decoded
value. The full 7-bit repertoire, including `00`, ESC, and `7f`, is accepted
by the C constraint. Empty `16 00` is a valid C BER and CER wire value even
though a manually constructed C zero-length value with a null buffer fails
its in-memory CER constraint check.
The C BER decoder also accepts a constructed empty IA5String but leaves a
null data pointer, so a subsequent C constraint check or CER encode fails.
Rust may normalize that BER value to empty owned bytes and encode canonical
`16 00`; document this cross-operation storage divergence.

The BER reader expects universal tag 22 and flattens primitive or constructed
definite and indefinite forms through universal OCTET STRING tag 4 children;
character-tag children are rejected. It must validate each parent boundary,
matching EOC, depth, output growth, and whole-input budget. DER emits a
primitive tag 22 with minimal definite length. CER is primitive through 1000
content octets; above 1000 it emits an indefinite constructed tag 22 with
1000-octet universal tag 4 fragments, a final shorter fragment, and EOC.
Fragmentation is bytewise, so later UTF8String support must validate after
reassembly rather than per fragment. Strict CER decodes BER, validates IA5,
re-encodes and compares the exact consumed prefix through one cumulative
input, retained value, output, work, and scratch budget. The selected-method
generator gate and tests must cover empty, invalid high-bit, 999/1000/1001
and larger lengths, nested BER forms, fragment tags, high-tag aliases,
truncation, suffixes, mutations, exact limits, and live C vectors.

### Remaining direct restricted character strings (qualified initial gate)

Extend only direct untagged, unconstrained, top-level restricted string roots
under BER/CER-only selection. The intrinsic universal tags are
ObjectDescriptor 7, UTF8String 12, NumericString 18, PrintableString 19,
TeletexString/T61String 20, VideotexString 21, GraphicString 25,
VisibleString/ISO646String 26, GeneralString 27, UniversalString 28, and
BMPString 30. The aliases at tags 20 and 26 retain distinct generated type
names but share runtime encoding rules. IA5String tag 22 remains supported by
its existing source-compatible public API. `CHARACTER STRING` tag 29, time
types, defined types, tags, fields, imports, constraints, and other codec
selections remain gated.

Add a `CharacterStringKind` enum and private-byte `CharacterString` value with
fallible `try_from_bytes(kind, bytes, limits)`, borrowed `as_bytes()`, and
read-only `kind()`. Do not derive infallible `Clone`. Generic DER/CER encoders
take the value's stored kind; BER/CER decoders take an expected kind and
report exact prefix consumption. Keep the `Ia5String` API unchanged while
sharing the checked tag-parameterized framing engine. A generated wrapper
fixes its kind in its constructor and decoder, so callers cannot pair a type
with another type's tag or CER validator.

Construction, BER decoding, and DER encoding preserve raw bytes as the C
callbacks do. CER encoding and strict CER decoding apply the corresponding C
descriptor's general constraint to complete reassembled content:

| Kind | C-compatible CER content check |
| --- | --- |
| NumericString | Every byte is space or ASCII digit. |
| PrintableString | Every byte belongs to letters, digits, space, or `'()+,-./:=?`. |
| VisibleString and ISO646String | Every byte is from `20` through `7e`. |
| BMPString | Content length is divisible by two; C accepts surrogate values. |
| UniversalString | Content length is divisible by four; C accepts out-of-range scalar values. |
| UTF8String | C's minimal 1- through 6-byte sequence check: valid starts and continuations, complete sequences and shortest length. It accepts surrogate values, values above `10ffff`, and minimal legacy 5- and 6-byte encodings. Do not use Rust `str::from_utf8` as the validator. |
| ObjectDescriptor, TeletexString/T61String, VideotexString, GraphicString, GeneralString | No effective C character constraint; arbitrary bytes pass. |

These policies target the C codec's observable behavior. C acceptance of
legacy UTF8 forms and arbitrary escape-based character content does not prove
X.690 character repertoire or escape-state canonicality. Record these as
qualified C-compatibility decisions rather than broad standards claims.
Universal tag 4 primitive children form constructed BER strings. CER keeps
the type's own outer tag, is primitive through 1000 content octets, then uses
an indefinite constructed outer value with 1000-octet universal tag 4
fragments and EOC. Fragmentation is bytewise: a UTF8 sequence may cross a
fragment boundary, so validate only after reassembly. Strict CER compares
the exact consumed prefix with canonical output under one cumulative input,
retained value, output, work, and aggregate scratch budget.

The acceptance set includes each AST kind and shared-tag alias, valid and
invalid C constraint cases, minimal legacy UTF8 forms and invalid UTF8
sequences, UTF8 split across CER fragments, BMP/Universal alignment, empty
values, 127/128 and 999/1000/1001 length transitions, nested definite and
indefinite BER, high-tag aliases, wrong fragment tags and EOCs, suffixes,
truncation at every boundary, mutations, exact limits, and live C vectors.
All excluded schema shapes must fail before output publication.

### Direct UTCTime (qualified initial gate)

Support only direct, untagged, unconstrained top-level `UTCTime` with universal
tag 23 under BER/CER-only selection. Keep `GeneralizedTime`, aliases, imports,
fields, tags, constraints, and other codec combinations gated. The public
`UtcTime` value owns private raw bytes through a fallible, limit-checked
constructor and exposes a borrowed byte accessor. It has no infallible clone.
BER prefix decoding returns exact consumption and accepts primitive or nested
constructed tag-23 values with universal tag-4 primitive fragments, following
the C OCTET STRING decoder. BER accepts raw content without checking the time
syntax. DER emission preserves those bytes in primitive definite tag 23,
matching the C DER callback, even when the contents are not a valid time.

CER encoding validates and normalizes complete content as the C CER adapter
does: `YYMMDDhhmm[ss]` followed by `Z` or a numeric `+/-hhmm` offset;
Gregorian dates and clock components must be valid; the year pivot is 50
(1950 through 2049); absent seconds become `00`; the zone converts to UTC;
and the normalized year must remain in the 1950 through 2049 window. Encode
the result as primitive definite tag 23 with exactly `YYMMDDhhmmssZ` content.
Strict CER prefix decoding parses BER, normalizes, reencodes, and compares the
exact consumed prefix. No CER fragmentation is needed because normalized
content is always 13 bytes. Bound input, retained content, canonical output,
temporary scratch, and cumulative work with the shared operation limits.
Calendar conversion must use checked Gregorian arithmetic rather than a
process-local timezone or machine `time_t`.

The C time conversion routine uses `time_t == -1` as an error sentinel and
therefore rejects the valid instant 1969-12-31 23:59:59 UTC in some paths.
Rust accepts that instant under checked calendar arithmetic. Record this as
an intentional standards-correct C divergence; do not propagate a sentinel
bug into the Rust value model. The acceptance gate includes each allowed
length, leap years and invalid dates, the 1950/2049 pivot and zone-crossing
limits, positive and negative offsets, the epoch sentinel case, arbitrary
BER bytes, constructed BER, malformed TLV/EOC/fragments, high-tag aliases,
suffixes, truncation, mutations, exact resource limits, C differential
vectors, strict Clippy, and fail-before-publication generator negatives.

### Direct GeneralizedTime (qualified initial gate)

Support only direct, untagged, unconstrained top-level `GeneralizedTime`
with universal tag 24 under BER/CER-only selection. BER prefix decoding keeps
arbitrary raw content bytes, including nested constructed tag-24 forms with
universal tag-4 fragments. A private owned value has a fallible bounded
constructor and borrowed byte accessor, without infallible clone.

Unlike UTCTime, the C DER adapter canonicalizes GeneralizedTime. For this
initial deterministic gate, DER and CER encoding require an explicit `Z`,
`+hh`, `-hh`, `+hhmm`, or `-hhmm` zone. Accept a four-digit year from 0001
through 9999, valid Gregorian date and clock, optional complete minute and
second pairs, and a one-through-nine-digit fraction only after seconds.
Accept `.` or `,` in source text. Normalize the zone with checked calendar
arithmetic and emit primitive tag 24 with
`YYYYMMDDhhmmss[.fraction]Z`, dropping an all-zero fraction and trailing
fractional zeros. Reject conversion outside the four-digit year window.
Strict CER prefix decoding compares the canonical encoding against exactly
the consumed BER prefix under one input, retained value, output, scratch,
and cumulative work budget. The canonical content is at most 25 octets, so
CER string fragmentation does not apply.

This is a qualified interoperability subset, not complete C DER behavior:
the C adapter interprets zoneless text through the process timezone, may
normalize invalid dates and clock fields, and may truncate fractions longer
than nine digits. These behaviors depend on platform state or silently lose
information; the initial Rust DER gate rejects them. C also rejects the
valid instant 1969-12-31 23:59:59 UTC through its `time_t == -1` sentinel;
Rust accepts it. The nine-digit limit is the C CER adapter's effective
precision limit, not a general X.690 bound. Tests must separate C-compatible
valid zoned vectors from these documented divergences and cover raw BER,
constructed/tag aliases, optional fields, both zone signs and widths,
fractions and trimming, leap/year edges, invalid text, malformed TLV,
prefixes, limits, mutations, and negative generator shapes.

### Direct SEQUENCE OF and SET OF primitive elements (qualified initial gate)

Add direct, untagged, unconstrained top-level SEQUENCE OF and SET OF with
exactly one direct untagged BOOLEAN, NULL, or finite nonextensible bounded
`i64` INTEGER element under BER/CER-only selection. Reject root SIZE and
element tags/references, nested types, extensions, defaults, imports,
parameterization, mixed codecs, and unconstrained INTEGER before publishing
output. The generated collection owns typed values. A separate runtime
collection walker is required: the six-distinct-field record reader and
writer cannot represent repeated members.

Use public root and element kind descriptors, a typed owned decoded-value
enum, and a typed borrowed-input enum for encoding; use a NULL count variant
internally to avoid a zero-sized vector's `usize::MAX` capacity. Generated
wrappers may expose `Vec<()>` after enforcing the count cap. Keep existing
`Limits` struct literals
source-compatible. Bound count independently, including `Vec<()>` or a NULL
count that has no byte allocation; cap it at 1,000,000 before any loop or
reserve. Charge each element visit, TLV parse/encode, validation, sorting,
canonical re-encode, and comparison to one cumulative work budget. Count
retained decoded vector, sort metadata, temporary sort buffers, and final output
capacities against a fixed aggregate scratch cap; also cap retained decoded
vector bytes by `max_output_bytes`. Use checked arithmetic
and fallible allocation. A fixed 11-byte canonical child encoding suffices
for the three approved element kinds. Sorting SET OF may use a bounded
fixed-width radix pass over zero-padded complete child TLVs, so sort work
is linear and can be precharged before allocation; this ordering must not
be replaced by numeric or field-tag order.

BER accepts definite and indefinite constructed roots, repeated child tags,
arbitrary SET OF order and duplicates, zero-length or multi-octet BOOLEAN
contents as C BER does, and redundant INTEGER sign octets. Strict CER still
requires the canonical one-octet BOOLEAN form. Decode one
prefix with exact consumption while enforcing
child bounds and matching EOCs. DER SEQUENCE OF preserves element order and
uses a definite tag-16 root; DER SET OF sorts complete canonical child TLVs
under a definite tag-17 root. CER uses indefinite tag-16/tag-17 roots and EOC;
SET OF sorts complete canonical CER child TLVs under X.690 section 11.6's
zero-padded octet comparison. Strict CER decodes under the same context,
re-encodes, and compares only the consumed prefix. This initial Rust value
model checks bounded INTEGER element ranges at decode; C BER may leave a
decoded out-of-range value for a later constraint check, so record the
timing difference as a qualified compatibility limitation.

Acceptance includes empty, singleton, duplicate, reversed, and repeated NULL
collections; DER/CER root and SET OF ordering vectors; BER definite and
indefinite forms, nonminimal aliases, malformed children/EOCs, suffixes,
truncation, mutations, and exact count/input/output/work/scratch boundaries.
Compare canonical Rust/C output and both decode directions for supported
values. Every excluded schema shape must fail before crate publication.

### Direct CHOICE of primitive alternatives (qualified initial gate)

Add one direct, untagged, nonextensible top-level CHOICE with one through
three uniquely tagged alternatives selected from BOOLEAN, NULL, and finite
nonextensible bounded `i64` INTEGER, under BER/CER-only selection. Reject
root or member tags, duplicate intrinsic tags, aliases/imports, constraints
outside the approved integer range, optional/default members, extensions,
recursive or constructed alternatives, parameterization, and generated
variant-name collisions before output publication. The generated Rust enum
contains only selected arm values, so it has no invalid unselected state.

An untagged CHOICE has no outer TLV: DER and CER emit exactly the selected
primitive alternative TLV. BER reads one complete identifier with precharged
work, dispatches by universal class and tag number 1, 5, or 2, then parses
the selected primitive through the same operation context. Reuse the
collection scalar parser rather than calling a public scalar decoder that
would reset budgets. BER accepts C-compatible high-tag and long-length
aliases, empty or multi-octet BOOLEAN content, and redundant INTEGER sign
octets. NULL must have empty primitive content. Strict CER reencodes the
selected value under the same work/output budget and compares exactly the
consumed prefix; the trailing suffix is untouched. Bounded INTEGER range
checks occur immediately in Rust, while C BER can defer subtype constraint
checking, so this timing difference remains a qualified limitation.

Use a public selected-value enum and an alternative descriptor slice with
at most one instance of each universal tag. Validate descriptor count,
uniqueness, and integer bounds before scanning input or allocating output.
The primitive output is at most 11 octets; decoded values need no heap
allocation. Apply whole-input, output, and cumulative work limits, including
identifier/length parsing, selected content scanning, canonical encode, and
strict comparison. Acceptance includes all three arms, no outer wrapper,
high-tag aliases, noncanonical BOOLEAN and INTEGER BER, unknown/wrong-class
or constructed tags, malformed lengths/content, suffixes, truncation at
every byte, mutations, exact resource limits, live C vectors in both
directions, and negative schema gates. IMPLICIT or EXPLICIT CHOICE tagging
remains a separate design stage because it changes dispatch or adds a wrapper.

### One inline primitive CHOICE child (qualified slice)

Compose the direct primitive CHOICE value model into one untagged SEQUENCE
or SET parent with a natural or one context-specific EXPLICIT child tag. Select only
BER and/or CER. The child has one through three unique intrinsic BOOLEAN,
NULL, or finite nonextensible bounded `i64` INTEGER alternatives, and is
required or OPTIONAL. Reject an IMPLICIT CHOICE child: the C parser/fixer
requires EXPLICIT tagging because CHOICE has no single intrinsic outer tag.
The initial inline gate qualified EXPLICIT CHOICE in SET; the following
natural SET gate supplies its separate DER and CER ordering. References,
extensions, nested alternatives, multiple CHOICE children, and other codec
selections remain gated.

Use one logical presence slot for the CHOICE even though a natural child may
match several alternative tags. A second alternative in one parent must be a
duplicate field, not another value. Validate every alternative tag against
other possible parent field tags and verify exact parent declaration order for
SEQUENCE. An EXPLICIT wrapper contains exactly one selected intrinsic TLV;
DER uses a definite wrapper and CER an indefinite wrapper with one EOC. The
selected scalar parser and writer must borrow the parent's operation context:
calling a public direct-CHOICE codec would reset work/output budgets. Count
wrapper bytes, identifier/length scans, child visits, canonical re-encoding,
comparison, and retained capacity against that shared context. Preserve
transactional parent rollback on malformed input or callback failure.

For a SEQUENCE with selected INTEGER 2 then `[4] IMPLICIT BOOLEAN TRUE`, C DER
emits `30 06 02 01 02 84 01 ff` and C CER emits
`30 80 02 01 02 84 01 ff 00 00`. With `[3] EXPLICIT CHOICE`, C DER emits
`30 08 a3 03 02 01 02 84 01 ff` and C CER emits
`30 80 a3 80 02 01 02 00 00 84 01 ff 00 00`. In a SET whose `[4]`
IMPLICIT BOOLEAN is declared before `[3] EXPLICIT CHOICE`, C DER emits
`31 08 a3 03 02 01 02 84 01 ff`; C CER emits
`31 80 a3 80 02 01 02 00 00 84 01 ff 00 00`. C BER accepts these values;
strict CER accepts the CER prefixes and rejects the DER forms.
For an OPTIONAL `[3] EXPLICIT CHOICE` in a SET with `[4] IMPLICIT BOOLEAN
TRUE`, C DER omits the absent field as `31 03 84 01 ff` and emits selected
NULL as `31 07 a3 02 05 00 84 01 ff`; the CER forms use an indefinite SET
and, when present, an indefinite `a3` wrapper.

The later natural-CHOICE-in-SET gate must implement two ordering keys. X.690
section 9.3 uses the minimum possible alternative tag for CER SET ordering;
section 10.3 makes DER SET ordering depend on the selected component tag. C
exhibits this difference: with an OCTET STRING tag 4 and a natural CHOICE
selected as NULL tag 5, DER places the OCTET STRING first, while CER places the
CHOICE first because its minimum alternative is BOOLEAN tag 1. A single
statically sorted writer for both rules would be incorrect.

Acceptance includes required/OPTIONAL presence, every selected arm, natural
and EXPLICIT tags, parent SET ordering, high-tag BER aliases, malformed and
multiple wrapper children, duplicate CHOICE alternatives on input, unknown
tags, truncated lengths/EOCs, suffix preservation, strict CER comparison,
exact resource limits, live C vectors in both directions, and fail-closed
negative schema gates.

### Natural primitive CHOICE in SET (qualified slice)

Extend the one-inline-CHOICE gate to an untagged SET parent whose child has
natural tagging. Keep one through three unique intrinsic primitive arms, one
logical presence slot, the existing six-field record limit, and BER/CER codec
selection. All sibling effective tags must be distinct from every possible
CHOICE arm, including arms not selected in a particular value. Reject aliases,
extensions, nested arms, and unsupported forms before generating any files.

DER orders a natural CHOICE field by the tag of its selected arm. CER orders
that field by the minimum tag among all its declared alternatives, regardless
of which arm was selected. The writer must track the wire tag separately from
the SET ordering key. Duplicate detection uses the wire tag and the CHOICE's
single logical presence slot; ordering checks use the rule-specific key. The
CHOICE scalar append must pass both keys through the same transactional field
preparation and commit path as ordinary fields, preserving work, output,
retained-storage, and rollback behavior. Generated SET encoders can select one
of at most three fixed emission orders for DER; CER uses one fixed order based
on the minimum arm tag. OPTIONAL absence omits the field from either order.
This bounded approach needs no encode-to-sort scratch allocation.

The BER SET reader maps every arm tag to one logical slot, accepts arbitrary
field order, and rejects a second arm even if its tag differs. Strict CER
decoding re-encodes the selected value using the same context and compares
only the consumed prefix. With `[4] IMPLICIT OCTET STRING (SIZE(1))` equal to
`aa` and an OPTIONAL natural CHOICE of BOOLEAN, NULL, and bounded INTEGER,
live C output for a selected NULL is DER `31 05 04 01 aa 05 00` and CER
`31 80 05 00 04 01 aa 00 00`. The absent forms are DER
`31 03 04 01 aa` and CER `31 80 04 01 aa 00 00`. C BER accepts the reversed
NULL order in CER framing, while strict CER rejects it. Acceptance must cover
all arms, absence, sibling tags on either side of the selected and minimum
tags, collisions with unselected arms, duplicate distinct arms, exact limits,
transactional writer failures, suffixes, truncation, C vectors, and negative
schema gates.

### IA5String fields in flat records (qualified slice)

This record-field gate adds a direct, unconstrained IA5String member to
an untagged, nonrecursive top-level SEQUENCE or SET under BER/CER-only
selection. Begin with natural tag 22 and required/OPTIONAL presence. Keep
IMPLICIT/EXPLICIT member tags, DEFAULT, references, constraints, nested
records, multiple semantic string fields, and mixed codecs gated until each
form has checked metadata and C differential tests. The public generated
value uses the direct `Ia5String` byte wrapper so BER and DER can preserve
arbitrary content bytes, including bytes outside the CER repertoire.

Extend the shared record field kind, writer, and reader with tag-22 IA5
semantics. BER accepts primitive and constructed definite or indefinite
content; constructed fragments retain universal OCTET STRING tag 4. Reuse
the bounded TLV fragment walker and move its decoded buffer into the wrapper
without copying. DER emits the primitive tag-22 value. CER validates the
7-bit repertoire before committing output and uses a primitive value through
1000 content octets or constructed tag-22 framing with 1000-octet tag-4
fragments beyond that point. The parent's `RecordContext` covers all parsing,
encoding, canonical comparison, and retained storage. Opt IA5-containing
record operations into aggregate scratch accounting even when the optional
member is absent, while preserving the existing flat scalar-record contract.
The aggregate record cap counts operation-owned output and temporary buffers
plus retained decoded `Vec` capacity. It does not count unused reserve capacity
in a caller-owned IA5 value supplied to a record encoder; actual content and
output length remain bounded. This differs from the direct IA5 root encoder's
conservative input-capacity accounting. Strict CER re-encoding counts the
decoded value once as retained storage and adds the canonical output.

Acceptance includes empty, ASCII boundary, invalid CER byte, lengths 999,
1000, 1001, and 2001, definite/indefinite constructed BER, wrong fragment
tags, SET reversal, duplicate fields, suffixes, every truncation boundary,
exact work/output/scratch limits, and fail-closed negative schemas. Live C
vectors for SEQUENCE with IA5String `A` are DER `30 03 16 01 41` and CER
`30 80 16 01 41 00 00`; SET with that member and `[4] IMPLICIT BOOLEAN
TRUE` is DER `31 06 16 01 41 84 01 ff` and CER
`31 80 16 01 41 84 01 ff 00 00`.

### OID fields in flat records (qualified slice)

Extend the flat BER/CER-only untagged SEQUENCE and SET gate to at most one
natural direct OBJECT IDENTIFIER and one natural direct RELATIVE-OID field,
each required or OPTIONAL, with the existing scalar siblings and six-field
limit. Reject coexistence with IA5String, nested records, CHOICE, references,
imports, constraints, DEFAULT, extension metadata, member/root tags, and
other codec selections before publication. This bounded combination allows
both universal tags 6 and 13 in either declaration order without ambiguous
dispatch.

Use the existing private canonical-content OID wrappers as field values.
The record writer emits primitive definite tag-6 and tag-13 TLVs for DER and
CER, retaining the shared record work/output/scratch accounting. The BER
reader rejects constructed or indefinite primitive forms and normalizes
redundant leading base-128 groups within the same operation context before
moving each decoded allocation into its wrapper. It checks input and work
before allocation, retains actual Vec capacity, and uses the same context
for strict CER re-encoding and consumed-prefix comparison. Generated roots
select aggregate scratch accounting even if an OPTIONAL OID field is absent;
nested callbacks remain disabled. Ordinary record encoding excludes unused
caller-owned input reserve capacity, as in the IA5 record gate.

The repaired C encoder emits SEQUENCE with OID content `2a 81 00` and relative
content `81 00` as DER `30 09 06 03 2a 81 00 0d 02 81 00` and CER
`30 80 06 03 2a 81 00 0d 02 81 00 00 00`; SET uses the same field order
with outer tag `31`, even when declared relative first. BER accepts reversed
SET members and nonminimal tag aliases; strict CER rejects both. C BER also
accepts empty or unterminated OID content and retains redundant base-128
groups, while the current direct Rust OID codec rejects the first two and
normalizes the last. Preserve and document that qualified divergence until
the broader BER compatibility policy is settled. Acceptance includes both
presence states, large arcs and length boundaries, malformed identifiers,
duplicate and unknown fields, suffixes, all truncations, exact limits,
canonical SET ordering, C vectors, and negative schema gates.

### Unconstrained INTEGER fields in flat records (next qualified gate)

Add at most one natural, direct unconstrained INTEGER member to an untagged
flat SEQUENCE or SET under BER/CER-only selection. The member may be required
or OPTIONAL and may coexist with already-qualified scalar siblings, while
the six-field cap remains. Keep bounded `i64` INTEGER members and their API
unchanged. Reject member/root tags, DEFAULT, references/imports, constraints,
extensions, nested records, CHOICE, IA5/OID coexistence, and mixed codecs
before publication. The generator selects the existing `BigInteger` owned
value only for the unconstrained member; C differential tests for values
outside `i64` must use `-fwide-types` because default C generation can select
native `long` storage.

Add natural `write_big_integer` and `read_big_integer` methods to record
writers/readers while retaining universal `FieldKind::Integer` dispatch.
DER/CER emit one primitive definite tag-2 TLV containing the wrapper's
minimal signed bytes. BER rejects constructed and empty content and
normalizes redundant leading `00` or `ff` sign octets. Share the record
context's input, work, output, and aggregate retained-capacity counters;
factor the existing direct normalizer so scan and copy passes can charge the
caller's budget without making a new scalar budget. Generated methods select
aggregate scratch accounting even when the OPTIONAL field is absent; strict
CER re-encoding uses the same context and compares only the consumed prefix.
The record encoder excludes unused reserve capacity of caller-owned input,
as in the IA5/OID gates.

Live C wide-type output for positive `2^63` content
`00 80 00 00 00 00 00 00 00` in SEQUENCE is DER
`30 0b 02 09 00 80 00 00 00 00 00 00 00` and CER
`30 80 02 09 00 80 00 00 00 00 00 00 00 00 00`.
For a SET containing BOOLEAN TRUE and that INTEGER, C DER is
`31 0e 01 01 ff 02 09 00 80 00 00 00 00 00 00 00`; CER uses
indefinite root framing and the same child order. C BER accepts empty
INTEGER content, while the direct Rust `BigInteger` codec rejects it; this
qualified divergence must be documented. Acceptance includes sign boundaries,
large values and length boundaries, redundant sign normalization, optional
SET presence and ordering, malformed/constructed fields, tag aliases,
suffixes, every truncation, exact resource limits, C vectors, and negative
schema gates.

## Decisions still required

* **Streaming:** C BER decoders preserve state and can return `RC_WMORE`;
  Rust currently accepts a complete slice and reports a decoded prefix. Decide
  whether full parity requires resumable state and precisely specify chunk
  ownership, consumption, rollback, resource accounting and failure cleanup.
  A prefix-only implementation must not be described as streaming parity.
* **C compatibility versus standard rules:** the Rust README records that C
  accepts redundant INTEGER sign octets even though this extends the X.690
  wire rule. Establish whether BER defaults to C-compatible acceptance or a
  separately selectable strict mode, and enumerate any other observed
  divergences. CER canonical validation must remain strict. Do not assume C is
  a conformance oracle for every malformed value.
  Live checks against the sanitized C skeleton library show BER accepts empty
  indefinite constructed OCTET STRING (`24 80 00 00`) and BIT STRING
  (`23 80 00 00`), accepts the nonminimal high-tag encoding `1F 04` for the
  OCTET STRING universal tag, and masks nonzero unused tail bits (for example,
  `03 02 03 A7` decodes to payload `A0` with three unused bits). These cases
  need explicit differential tests and a compatibility decision; strict CER
  must reject their noncanonical encodings by byte comparison.
  A generated C probe for an EXPLICIT inline SEQUENCE child accepted wholly
  definite and wholly indefinite wrapper stacks, but rejected stacks where
  the EXPLICIT wrapper and its inner SEQUENCE used different length forms.
  This held with either definite or indefinite parent SEQUENCE length. X.690
  sections 8.1.3.2(b) and 8.14 permit each constructed layer to choose its
  length form independently. The nested Rust BER reader should accept a
  well-framed mixed stack and record this C decoder divergence in its tests;
  strict CER rejects it because CER requires indefinite constructed layers.
  See [ITU-T X.690 (02/2021)](https://www.itu.int/rec/T-REC-X.690/en).
* **Constraint timing and generated invariants:** C BER decoding generally
  decodes first and leaves constraint checking to `asn_check_constraints`,
  whereas Rust's bounded `decode_integer_ber` checks the range during decode.
  Decide whether generated BER decoding must return an unconstrained wire
  value followed by an explicit validation step, provide a separate permissive
  representation or API, or deliberately retain stricter behavior. Generated
  constructors currently enforce invariants, so accepting an out-of-range
  value cannot simply bypass those invariants. Test C decode success separately
  from subsequent constraint failure, as required by `docs/rust/testing.md`,
  and document any intentional compatibility difference.
* **Limits and remaining representations:** agree how to extend `Limits`
  without breaking public struct literals, select finite defaults and an
  aggregate scratch policy, and define unknown extension and opaque open-type
  representations. The initial arbitrary INTEGER representation above does not
  settle native-width or constrained-wide INTEGER behavior. Document cases
  where Rust's bounded operation intentionally differs from C's limits.
