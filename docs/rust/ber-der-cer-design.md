# Rust BER, DER, and CER parity design

Status: approved architecture and staged plan with qualified slices already
implemented. Full C parity has not been reached. The compatibility target is
the C backend in this repository, qualified by the decisions below. The Rust
runtime currently supplies BER prefix decoding and DER and CER encoding, plus
strict CER prefix decoding, for BOOLEAN, NULL, finite bounded `i64` INTEGER,
direct finite ENUMERATED, and fixed or bounded BIT/OCTET STRING values. See
`rust/asn1c-runtime/README.md` and
`libasn1compiler/asn1c_rust.c`. The generator rejects many schemas supported by
C, including imports, references, root tags, and multi-tag stacks. These
rejections remain until the corresponding generated representation and codecs
are implemented.

The implemented SEQUENCE slice handles empty or flat records with an untagged
outer type and up to six distinct effective direct-field tags for BOOLEAN,
NULL, bounded INTEGER, ENUMERATED, and finite bounded BIT/OCTET STRING fields.
Required and OPTIONAL members and literal BOOLEAN/INTEGER DEFAULT members
share one operation budget. Resolved context-specific IMPLICIT and AUTOMATIC
member tags and one context-specific EXPLICIT wrapper per direct member are
supported. One nonrecursive inline SEQUENCE child is also qualified below;
broader nested records and primitive members remain in the parity matrix.

The flat SET slice uses the same six direct field kinds under BER/CER-only
selection. Its BER reader accepts arbitrary member order;
the DER/CER writer emits ascending effective tags. Broader SET shapes,
collections, broader nested records, and multi-tag stacks remain future stages.

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
* **Limits and representations:** agree how to extend `Limits` without
  breaking public struct literals, select finite defaults, and define arbitrary
  integer, unknown extension and opaque open-type representations. Document
  cases where Rust's bounded operation intentionally differs from C's limits.
