# Rust Runtime Architecture Proposal

Date: 2026-10-11

Baseline: commit 5a0ccf24ede9b176e8fd76861bf4855ed95f5105.

Status: architecture target with an implemented first runtime slice in
[rust/asn1c-runtime](../../rust/asn1c-runtime/README.md). That slice supports
UPER, CER, and BER/DER BOOLEAN, NULL, and bounded i64 INTEGER operations. Its
UPER cursor also composes fixed-size OCTET STRING and BIT STRING fields. The
generic runtime
shape and remaining codec families described below are conversion targets.

## Accepted target constraints

- Use the Rust standard library and safe Rust. Do not use unsafe blocks or a C
  runtime FFI in the Rust implementation.
- At the end of stage one, cover every current C-supported codec, type,
  direction, mode, and feature. Document C limitations accurately; a limitation
  does not count as Rust parity coverage.
- Preserve the complete, prefix, and callback behavior supported by each C API.
  A common prefix/session API and resumable PER sessions are proposed
  improvements, not parity gates for this stage.
- The codec order below is a proposed delivery sequence, not a release schedule.
  The user has not selected a different order.

The Rust crate layout, exact public API, third-party dependency policy, generated
value API, and compatibility switches remain design choices. The proposal below
recommends defaults while identifying the tradeoffs.

## What the C runtime currently provides

The skeletons are shared codec implementations driven by compiler-emitted
descriptors; the directory README describes this split
([skeletons/README:1-4](../../skeletons/README#L1)).
The central operation table has type operations, lifecycle helpers, and
per-codec function pointers. A type descriptor carries tags, encoding
constraints, member tables, and type-specific data; a member carries its type,
tag, optional/default metadata, constraints, and optional open-type selector
([skeletons/constr_TYPE.h:194-299](../../skeletons/constr_TYPE.h#L194)).

Generated metadata is more than a list of fields. It includes tag-to-member
maps, root/extension boundaries, optional-member maps, CHOICE selection maps,
and IO-set selector hooks. The C generator emits these tables in
libasn1compiler/asn1c_C.c, including SEQUENCE specifics at lines 704-736 and
CHOICE specifics at lines 1650-1681. Rust should preserve their meaning while
replacing C offsets, pointer flags, and raw function-pointer layouts with safe
generated field access and typed metadata.

The current C value model covers the following families. These are proposed
Rust value mappings, not a claim that each C type has every codec operation.
The C operation tables and skeleton library source list are the sources of
truth for the current type/syntax intersections
([skeletons/Makefile.am:38-274](../../skeletons/Makefile.am#L38)).

| ASN.1 family | Proposed Rust representation |
| --- | --- |
| BOOLEAN, NULL | bool and unit value |
| INTEGER | Signed, arbitrary-width integer bytes with checked conversions |
| NativeInteger | Generated signed/unsigned fixed-width integer |
| ENUMERATED | Generated enum; extensible values retain the unknown ordinal |
| NativeEnumerated | Generated integer enum plus an explicit unknown ordinal |
| REAL | Exact runtime Real value; do not reduce the model to f64 |
| NativeReal | Generated f32 or f64 value, matching selected C storage |
| BIT STRING | Byte storage plus an explicit bit length |
| OCTET STRING | Owned bytes |
| OBJECT IDENTIFIER, RELATIVE-OID | Typed arc sequence with checked arc conversion |
| UTCTime, GeneralizedTime | Typed time value retaining validated text form |
| ANY | Opaque encoded value bytes with an explicit transfer-syntax context |
| OPEN TYPE | Generated selected-value enum; preserve opaque unknown payloads |
| Character strings | Type-tagged validated text or bytes, as required by the type |
| SEQUENCE, SET | Generated record with typed fields |
| CHOICE | Generated enum with one active alternative |
| SEQUENCE OF, SET OF | Ordered Vec of typed elements |

The character-string family includes BMPString, GeneralString, GraphicString,
IA5String, ISO646String, NumericString, ObjectDescriptor, PrintableString,
T61String, TeletexString, UTF8String, UniversalString, VideotexString, and
VisibleString. C stores OCTET STRING and many string types as byte buffers and
uses type-specific specifics or handlers for interpretation. Rust must retain
the ASN.1 string type and validate its repertoire; treating every member as a
plain String would lose raw-byte and legacy-string cases. See
skeletons/OCTET_STRING.h:14-18 and type-specific files such as
skeletons/UTF8String.c and skeletons/PrintableString.c.

INTEGER currently has a byte-buffer representation, whereas the compiler may
select fixed-width native storage for some integer types
([skeletons/INTEGER.h](../../skeletons/INTEGER.h),
libasn1compiler/asn1c_C.c:121-135). Keep both paths explicit in generated
Rust metadata. OBJECT IDENTIFIER arcs are uint32_t in the current C header
([skeletons/OBJECT_IDENTIFIER.h:16-20](../../skeletons/OBJECT_IDENTIFIER.h#L16)).
REAL is represented by the C primitive byte-buffer type, while NativeReal uses
a fixed machine float and may have limited precision. A plain f64 mapping is
not sufficient for REAL compatibility
([skeletons/REAL.h:34-50](../../skeletons/REAL.h#L34),
[skeletons/NativeReal.h:5-22](../../skeletons/NativeReal.h#L5)).

The transfer-syntax selector lists BER, DER, CER, basic and canonical OER,
basic and canonical UPER and APER, basic and canonical XER, JER and minified
JER, and CBOR. Random fill and plaintext printing are utility operations
rather than transfer syntaxes
([skeletons/asn_application.h:23-75](../../skeletons/asn_application.h#L23)).
The source tree provides shared support modules and type-specific handlers, but
not every type has a handler for every syntax. C dispatch reports a missing
operation as unsupported. Rust must track the exact type-by-syntax matrix
instead of inferring complete coverage from a family-level filename.

| Codec family | Current modes | Main C source anchors |
| --- | --- | --- |
| BER / DER | BER decode; DER encode; Rust primitive slice | ber_decoder.c, der_encoder.c |
| CER | Strict C decode and encode; Rust strict primitive encode/decode slice | cer_decoder.c, cer_encoder.c |
| PER | UPER / APER, each basic and canonical | per_*.c, uper_*.c, aper_*.c |
| OER | Basic and canonical | oer_*.c |
| XER | Basic and canonical | xer_*.c |
| JER | Regular and minified | jer_*.c |
| CBOR | CBOR | cbor_*.c |

The dispatcher routes `ATS_CER` input to strict `cer_decode`, which decodes
with `ber_decode`, re-encodes with the descriptor-driven CER encoder, and
rejects input that is not byte-identical to the canonical encoding. `ATS_BER`
and `ATS_DER` input remain permissive. The current Rust runtime implements CER
encoding and strict decoding only for BOOLEAN, NULL, and finite nonextensible
INTEGER ranges that fit `i64` (`decode_boolean_cer`, `decode_null_cer`,
`decode_integer_cer`). These accept only the exact universal tag, a short-form
definite length, and canonical content, and enforce `Limits`.
See [the binary audit](../binary-codec-support.md).

The C encoder already exposes a byte callback, while decoder entry points accept
input slices and return RC_OK, RC_WMORE, or RC_FAIL. Its codec context limits
stack use and carries a few validation flags, but has no shared heap or input
budget ([skeletons/asn_codecs.h:14-51](../../skeletons/asn_codecs.h#L14),
[skeletons/asn_codecs.h:88-104](../../skeletons/asn_codecs.h#L88)).
Input and output semantics are not uniform across the public APIs. Record
whether each C entry point is complete-message, prefix, callback, or
restartable, together with its consumption units and partial-state contract.
uper_decoder.c calls its PER codec non-restartable and reports the failure
position when more input is needed
([skeletons/uper_decoder.c:155-174](../../skeletons/uper_decoder.c#L155)).
Parity means preserving those contracts with bounded behavior. A persistent
session API for every codec, including resumable PER, may be prototyped as a
later improvement; codec coverage does not require it.

The C constraint contract is a per-type callback, with a general
asn_check_constraints entry point
([skeletons/constraints.h:17-54](../../skeletons/constraints.h#L17)).
The Rust design should keep schema constraints in generated metadata, apply
them during codec operations where required, and provide a separate complete
value validation entry point. Do not turn an unknown constraint into success
without a reviewed compatibility decision; the C helper named
asn_generic_unknown_constraint currently returns success
([skeletons/constraints.c:17-28](../../skeletons/constraints.c#L17)).

## Recommended runtime shape

Separate the runtime into safe, syntax-focused modules with shared descriptor,
value, constraint, error, and resource-budget layers:

- A schema layer contains immutable generated type and member descriptors.
  It records tags, constraints, defaults, optionality, extension positions,
  string subtypes, and open-type selectors.
- A value layer exposes generated typed records, enums, and borrowed views.
  Codec code uses generated safe field accessors rather than C byte offsets.
- Shared primitive helpers handle checked lengths, integer conversion,
  bit access, tags, length determinants, string validation, and OID arcs.
- Each codec module owns its parse/encode state. Shared helpers may be reused
  only when their wire behavior is identical and the distinction remains clear.
- The constraint layer validates both values and codec-specific metadata.
- The error and budget layers are shared by nested decoders so recursion cannot
  reset resource accounting.

Generated values should default to schema-specific typed structs and enums, as
described in architecture.md. Resolve recursive ownership during M0 rather than
freezing an arena here. Ordinary owned structs are ergonomic, but recursive Box
fields complicate fallible allocation and stack-safe destruction. A flat arena
with typed views and builders makes those properties easier to control, but
costs API ergonomics and may require copying for ordinary structs. Prototype
both approaches with deep recursion, budgeted allocation, and destruction, then
record the selected model and residual OOM limits.

The exact public I/O API is also open. Preserve complete-message, prefix, and
callback contracts supported by C. A common result should distinguish
incomplete input from malformed input, unsupported type/syntax combinations,
constraint failures, limit exhaustion, allocation failure, and I/O failure.
Include byte offsets and bit offsets for PER diagnostics and a generated member
path when available. Define trailing-data behavior per top-level API.

A persistent decoder session can accept additional slices without requiring
callers to concatenate a full message; an encoder session can target a bounded
sink. These are API improvement options. If adopted, finish must turn an
incomplete value into a truncation error, and output failures must be typed.

Safe Rust prevents memory unsafety but does not by itself prevent allocation
failure, process abort, deep-recursion overflow, or denial of service. Before
growing any input-derived vector, use fallible reserve operations and check
arithmetic. Charge one shared budget before allocation or nested decode work.
At minimum, define configurable limits for input bytes, output bytes, total
decoded bytes, element count, nesting depth, open-type payload bytes, and
temporary canonical-ordering storage. Decoder depth and value destruction must
have a tested bound. An arena can make destruction iterative, while owned
recursive structs need an explicit strategy.

Canonical SET OF output can require encoding and sorting elements before they
are emitted. The C implementation has explicit sorting paths for DER and
canonical PER in skeletons/constr_SET_OF.c. Any proposed chunked-output API
must document and budget this scratch storage; it must not promise constant
memory when canonical ordering requires staging.

Extensibility must be represented deliberately. The C PER ENUMERATED decoder
can preserve an unknown extension index, while SEQUENCE PER decoders skip
overflow additions unknown to their schema
(skeletons/NativeEnumerated_uper.c:47-64 and
skeletons/constr_SEQUENCE_uper.c:224-274). APER has corresponding paths.
Rust should preserve unknown extension indices and payloads wherever the wire
form permits, and make any intentional discard an explicit compatibility
policy. Generated known open types should use their IO-set selector; unknown
open types should remain opaque and round-trip when enough wire context is
available. Apply resource limits before retaining payloads.

The existing C PER SET implementation documents a root-only limitation in its
SET codec. This is evidence for a current C boundary, not a reason to infer
that all extensible SET schemas are supported
([skeletons/constr_SET_uper.c:84-85](../../skeletons/constr_SET_uper.c#L84)).
Every such boundary must be recorded in the stage-one coverage manifest.

## Delivery slices

These are implementation waves, not dated releases. Every wave should leave
the runtime buildable and should add its tests and support matrix entries.

1. Foundation, Rust backend, and harness: define generated descriptors and
   value access, common errors and limits, fixture format, C/Rust differential
   harness, and a ledger of existing I/O contracts. Prototype session APIs
   separately.
2. First vertical slice: constrained UPER primitives, including the exact
   length, extension, and canonical checks needed by the selected schemas.
3. APER plus constructed and recursive types, including optional/default
   members, CHOICE, SET, OF collections, extensions, open types, and limits.
4. Remaining BER/DER and OER families, including the supported BER behavior
   and permissive BER decoding; expand the existing C and Rust CER codec
   matrices before making wider claims.
5. XER, JER, and CBOR. These may proceed in parallel after shared value,
   descriptor, error, and I/O interfaces stabilize.
6. Parity qualification: close the type/syntax/direction matrix and qualify
   existing API semantics, limits, unknown values, malformed input, and
   generated-schema behavior. Treat persistent sessions as optional work.

If a schema feature cannot be implemented in a slice, code generation must
report it explicitly or runtime dispatch must return a typed unsupported-feature
error. Never silently encode, decode, or validate through a different type or
codec path. A schema can be excluded from the stage-one compatibility gate only
with source evidence that the C baseline also lacks that support and an
explicitly reviewed disposition. Any uncovered C-supported feature keeps the
stage-one gate incomplete unless a maintainer explicitly changes the scope.

## Acceptance gates

The following checks define completion; they are test plans, not tests run for
this documentation change.

- Maintain a checked-in type-family by codec by mode matrix. Derive C support
  from operation tables and source handlers. Mark each Rust cell complete,
  baseline-unsupported with evidence, or pending. At the stage-one gate, every
  C-supported cell must be complete; no cell may be left empty.
- For each supported decode cell, test Rust against C-produced fixtures; for
  paired encode cells, test C decoding of Rust output. Compare output bytes
  only for matched canonical and deterministic modes. Record fixture IDs,
  schemas, baseline and Rust revisions, codec mode, and generation command.
- Cover every primitive and constructed family, generated tags, constraints,
  optional and default values, recursion, extension additions, unknown enum
  values, open types, and all identified C-supported syntax intersections.
- For each C API, check complete or prefix behavior, truncation, consumption,
  and partial-state rules against the recorded contract. Exercise every split
  boundary only where that C API supports prefix or incremental input.
- If a persistent feed/session API is adopted, split valid and malformed input
  at every byte boundary and at PER bit boundaries. Compare results, offsets,
  and errors with complete decode; finish on proper prefixes.
- Exercise callback failures, short writes, trailing data, and length/count
  boundaries. For any chunked-output API, qualify bounded output and document
  scratch storage such as canonical SET OF ordering.
- Check every configured limit immediately below, at, and above its boundary,
  including nested collections and extension payloads. Verify allocation
  failures return errors, no panic occurs for malformed bytes, and deep values
  can be destroyed without overflowing the stack.
- Run differential fuzzing against the C baseline for supported intersections,
  plus Rust-only fuzzing for malformed inputs, state transitions, and budget
  accounting. Keep intentional policy differences separately documented.
- Re-run generated compiler tests for representative C output and add generated
  Rust fixtures for equivalent schemas. The repository's existing skeleton
  and generated compiler suites are listed in tests/tests-skeletons/Makefile.am
  and tests/tests-c-compiler/README.

## Source map

- Skeleton model: skeletons/README; skeletons/constr_TYPE.h;
  skeletons/constr_SEQUENCE.h; skeletons/constr_CHOICE.h;
  skeletons/constr_SET_OF.h.
- Codec selection and public results: skeletons/asn_application.h;
  skeletons/asn_application.c; skeletons/asn_codecs.h.
- Generated metadata: libasn1compiler/asn1c_C.c.
- Constraint callback contract: skeletons/constraints.h and constraints.c.
- Type storage and codecs: primitive headers and implementations under
  skeletons/, with the built source inventory in skeletons/Makefile.am.
- Existing regression coverage: tests/tests-skeletons/Makefile.am,
  tests/tests-c-compiler/Makefile.am, and tests/tests-c-compiler/README.
