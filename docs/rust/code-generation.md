# Rust code generation architecture

**Status:** Implementation in progress; primitive UPER, APER, OER, CER, and BER/DER slices present
**Date:** 2026-10-11
**Baseline:** `5a0ccf24ede9b176e8fd76861bf4855ed95f5105`
**Scope:** An opt-in Rust target that reuses the C parser and fixer, emits a
standalone Cargo crate with a safe Rust runtime, and adds codec support in
reviewed increments.

## Decision summary

Keep parsing, module assembly, standard-module loading, and semantic fixing in
the existing C front end. After `asn1f_process()` succeeds, select a backend
that lowers the fixed ASN.1 tree. Preserve C as the default target and keep its
current output and option behavior. Add Rust as an opt-in target; its generator
must produce Rust files and Cargo metadata through a Rust-specific writer and
runtime rather than reuse the C source emitter or C skeleton dependency list.

The target includes the current C codec families over time: BER decoding,
strict CER decoding, DER/CER encoding, UPER, APER, OER, XER, JER, and CBOR. Rust keeps the C target's
codec defaults independent. `--rust` selects the Rust backend as a whole;
it emits the currently qualified Rust codecs by default, beginning with UPER
and CER encoding and strict decoding for a primitive subset. An explicit codec request
that Rust cannot satisfy must fail before output is published. As codecs are
qualified, add them to the Rust default until it covers the C defaults.

The generated crate includes a copy of the matching runtime sources under its
own directory and refers to it with a Cargo path dependency. Both runtime and
generated code forbid unsafe code. This restriction does not automatically
cover third-party crates; audit their safety and licenses separately. Start
without runtime dependencies if the first slice can meet its requirements;
review any later bigint, XML, JSON, or CBOR dependency. Claim offline builds
only when every dependency is included or vendored. A future shared-runtime
option must validate a compatible runtime version and API.

## C codec dispatch and converter inventory

The C compiler defaults to its current codec family set in
[`asn1c/asn1c.c`](../../asn1c/asn1c.c#L176). Its `-gen-*` parser supports BER,
CER, XER, JER, CBOR, OER, UPER, and APER; DER remains the BER family's encoder
rule ([`asn1c/asn1c.c`](../../asn1c/asn1c.c#L266)). CER encoding is selected by
`-gen-CER` and can be disabled with `-no-gen-CER`. CER shares BER-family
runtime dependencies. A generated type's operation table has separate decoder
and encoder pointers for BER/DER, OER, UPER, APER, and CBOR, guarded by build
feature macros and generation flags
([`constr_TYPE.h`](../../skeletons/constr_TYPE.h#L200),
[`asn1c_C.c`](../../libasn1compiler/asn1c_C.c#L3019)). Thus, codec coverage
must be measured by type, direction, syntax variant, and feature, not by the
presence of a family name alone.

| C selector or syntax | Current dispatch and meaning |
| --- | --- |
| `-gen-BER`, `ATS_BER` / `ATS_DER` | BER decoder and DER encoder paths. |
| `-gen-CER`, `ATS_CER` | Descriptor-driven CER encoder; strict `cer_decode` for CER input. |
| `ATS_BASIC_OER` / `ATS_CANONICAL_OER` | Both labels call the same OER encoder or decoder. |
| UPER basic / canonical | Both labels call the same UPER encoder or complete decoder. |
| APER basic / canonical | Both labels call the same APER encoder or complete decoder. |
| `ATS_CBOR` | Calls the CBOR encoder or decoder when its feature is built. |

These shared branches are in the generic transfer-syntax dispatcher at
[`asn_application.c`](../../skeletons/asn_application.c#L285),
[`asn_application.c`](../../skeletons/asn_application.c#L343),
[`asn_application.c`](../../skeletons/asn_application.c#L473), and
[`asn_application.c`](../../skeletons/asn_application.c#L563).

The C runtime provides `cer_encode()` and generic `asn_encode(ATS_CER, ...)`;
the generated converter accepts `-ocer`. For input, `ATS_CER` and `-icer`
route to strict `cer_decode()`, which decodes with `ber_decode()`, re-encodes
with `cer_encode()`, and rejects input that is not byte-identical (`EBADF`).
`-icer` requires CER generation and buffers the whole input.
`ASN_DISABLE_CER_SUPPORT` disables the CER encoder and strict decoder; the
decoder stub then fails with `ENOENT`. `ATS_BER` and `ATS_DER` stay permissive.

The Rust backend adds `encode_cer` and strict `decode_cer` methods for BOOLEAN,
NULL, finite nonextensible INTEGER ranges fitting `i64`, direct nonextensible
ENUMERATED roots fitting `i64`, and direct fixed or bounded BIT/OCTET STRING
values with supported finite `SIZE` constraints. `-gen-BER` adds `decode_ber`
and `encode_der` for those types. Its `--rust` defaults to UPER and CER.
Empty or flat SEQUENCE records with an untagged outer type and distinct
effective direct-field tags for BOOLEAN, NULL, bounded INTEGER,
nonextensible ENUMERATED, and finite bounded BIT/OCTET STRING fields also have
BER/DER/CER methods. Resolved context-specific IMPLICIT and AUTOMATIC member
tags are supported. Flat SET records with the same untagged outer type and
distinct effective direct tags are available under a BER/CER-only selection. Other constructed
records and many C-supported BER-family forms remain outside the implemented
slice; see [the implementation matrix](implementation.md).

The example converter's baseline inputs are BER, OER, PER/UPER, APER, XER,
JER, and CBOR; outputs are DER, OER, PER/UPER, APER, XER, JER, CBOR, text,
and null. The converter provides `ber` and `der` input aliases that invoke
the BER decoder pointer and a `cer` alias for strict CER, then call
`asn_decode()`
([`converter-example.c`](../../skeletons/converter-example.c#L155),
[`converter-example.c`](../../skeletons/converter-example.c#L174),
[`converter-example.c`](../../skeletons/converter-example.c#L827)). Its OER,
PER, and APER output labels select canonical syntax values. The CER input
selector uses strict `cer_decode()` and is not restartable.

## Existing pipeline and backend coupling

The command-line driver parses all input modules, merges them, establishes
standard namespaces, and runs the fixer before invoking
`asn1_compile_with_target()`. This is the shared frontend boundary: Rust
consumes the resolved tree, including references, specializations, tags,
constraints,
extension markers, imports, and information-object metadata. See the driver
flow at [`asn1c/asn1c.c`](../../asn1c/asn1c.c#L947), tree fixing at
[`asn1c/asn1c.c`](../../asn1c/asn1c.c#L1003), and backend dispatch at
[`asn1c/asn1c.c`](../../asn1c/asn1c.c#L1025).

The old target-language table is not a decoupled backend interface.
[`asn1c_lang.h`](../../libasn1compiler/asn1c_lang.h#L6) stores one callback per
expression kind, and [`asn1c_lang.c`](../../libasn1compiler/asn1c_lang.c#L7)
accepts only C. The new public dispatch in
[`asn1compiler.c`](../../libasn1compiler/asn1compiler.c#L42) selects the
standalone Rust backend before entering the existing C-only pipeline. C
visitors still write to
[`asn1c_out.h`](../../libasn1compiler/asn1c_out.h#L14)'s C-oriented include,
declaration, table, and code streams. The C visitors in
[`asn1c_C.c`](../../libasn1compiler/asn1c_C.c#L152) call C type naming,
descriptor, and skeleton helpers directly.

The writer is also C-specific.
[`asn1c_save.c`](../../libasn1compiler/asn1c_save.c#L620) creates one `.c` and
one `.h` per generated top-level type, writes C preambles and include guards,
and emits C support files and Makefile fragments.
[`asn1c_fdeps.c`](../../libasn1compiler/asn1c_fdeps.c#L76) reads a tagged
dependency format. Its entries in
[`file-dependencies`](../../skeletons/file-dependencies#L1) name C `.c` and
`.h` skeleton files. Rust can share language-neutral traversal metadata; it
needs a separate output model, naming pass, dependency plan, and serializer.

Information-object table processing has reusable semantic inputs, but its
current lowering is C output:
[`asn1c_ioc.c`](../../libasn1compiler/asn1c_ioc.c#L77) resolves a table and
[`asn1c_ioc.c`](../../libasn1compiler/asn1c_ioc.c#L418) emits values through
the C output stream. Encoding controls are applied before backend generation
by [`asn1c_encoding.c`](../../libasn1compiler/asn1c_encoding.c#L185), while
custom XER/JER operation generation is in the C visitor. Extract shared
semantic helpers where they are coupled to C output; then apply each encoding
control only in Rust codecs that implement its behavior.

## Integration points and current implementation

1. `asn1p_parse_file()`, module merging, standard namespace setup, and
   `asn1f_process()` remain in `asn1c/asn1c.c`. The Rust backend receives the
   fixed tree; it does not parse ASN.1 or run a second fixer.
2. The CLI parses `--rust` in bounded option helpers, validates target-specific
   flags before generation, resolves the runtime, and calls
   `asn1_compile_with_target()`. The C target remains the default. Functions
   changed for this work are kept within the repository's size and complexity
   limits, including extracted helpers for prior oversized callables.
3. `asn1compiler.h` now defines the target options structure. The public
   `asn1_compile()` API is a compatibility wrapper selecting C; the new
   `asn1_compile_with_target()` dispatches to Rust or the unchanged C pipeline.
4. Existing C callback registration, C naming, streams, skeleton copying,
   Makefile output, and generated files remain on the C path.
5. The Rust lowering and writer now live in
   `libasn1compiler/asn1c_rust.c` and `asn1c_rust.h`, registered in
   `libasn1compiler/Makefile.am`. It validates the fixed tree before staging
   output. The current gate accepts top-level BOOLEAN, NULL, and bounded,
   nonextensible INTEGER whose complete range fits `i64`, plus SEQUENCE with
   required and OPTIONAL direct or inline nested fields and literal BOOLEAN or
   bounded INTEGER DEFAULT fields under UPER selection. A stricter flat,
   unique-effective-tag direct-field gate enables BER/DER/CER SEQUENCE methods,
   including resolved context-specific IMPLICIT and AUTOMATIC member tags.
6. Runtime sources now live under `rust/asn1c-runtime/` and are included in
   Automake distribution and package-data installation. The CLI resolves the
   runtime separately from `-S`, which still selects C skeletons and standard
   ASN.1 modules.
7. Rust has a bounded identifier sanitizer and collision checker. Diagnostics
   retain source module/type names and line numbers. The SEQUENCE gate checks
   direct field shapes, recursive depth and aggregate field-work limits,
   generated nested-type name collisions, presence markers, and DEFAULT literal
   types and ranges.
8. The generated-crate harness lives under
   `tests/tests-rust-compiler/`. It invokes the built compiler and checks the
   staged Cargo project. The first runtime has no third-party dependencies;
   future offline builds require all dependencies to be local or vendored.
   Existing parser/fixer tests remain shared; C output tests remain the
   regression gate for the default target.

The backend contract remains deliberately small: accept the fixed tree and
resolved target options; validate supported codecs, schema features, names,
and output paths; then stage the complete crate or return a diagnostic. Do not
generalize the existing `OUT()` macros or C stream enum into a universal
text-emission system. The first supported tree is validated before the writer
creates any files.

## Generated crate layout

The current writer creates one crate at the requested destination directory:

```text
Cargo.toml                  # package = "asn1c-generated", edition 2021
src/lib.rs                  # declares each generated module
src/<module>.rs             # one normalized file per ASN.1 module
runtime/Cargo.toml          # package = "asn1c-runtime"
runtime/src/lib.rs
.asn1c-rust-files            # exact generated-file ownership manifest
```

The writer copies `Cargo.toml`, `README.md`, `LICENSE`, and `src/lib.rs` from
the runtime and records them in the local path dependency `runtime`. Generated
code imports the runtime as `asn1c_runtime`. The crate root declares one Rust
module per ASN.1 module. The first sanitizer bounds identifiers to 80 bytes,
prefixes Rust keywords and reserved module filenames, and rejects collisions
after normalization. Imports and repeated type names remain unsupported in
this initial slice.

The writer stages the complete crate before publication. A destination must
be empty or contain a valid generator ownership manifest and exactly the files
it lists. Existing unowned files, symlinks, malformed manifests, Cargo build
artifacts, and `Cargo.lock` cause refusal; the generator preserves them. A
valid prior generated crate is replaced as a unit after staging succeeds.
Failure cleanup keeps the old crate or publishes the complete new crate.

The local runtime copy isolates generated crates from a globally installed
runtime update. Start with no runtime dependencies if the first slice can meet
its requirements. If later codecs need external crates, review each dependency
and include its source plus local Cargo configuration before claiming offline
builds. Preserve dependency license notices. Record the generator/runtime
version pairing. A future shared-runtime option must validate a compatible
runtime version and API; Rust ABI compatibility is not a requirement.

## Initial ASN.1-to-Rust type model

The mapping below is the API proposal, not a claim about implemented Rust
support. Use public safe value types and runtime wrappers where Rust's built-in
types cannot represent every valid ASN.1 value or preserve enough data for
encoding. Start with correctness and a stable public API; avoid target-machine
integer-width heuristics.

| ASN.1 form | Proposed Rust representation | Notes |
| --- | --- | --- |
| BOOLEAN | generated public newtype over `bool` | The codec validates the encoded form. |
| NULL | generated unit struct | The codec still validates the encoded NULL form. |
| INTEGER | bounded `i64` newtype or runtime `Integer` | Use schema bounds; arbitrary precision otherwise. |
| ENUMERATED | generated enum | Extensible types need an unknown numeric variant. |
| REAL | runtime `Real` | Must preserve special values and source precision; `f64` alone is insufficient. |
| BIT STRING | runtime `BitString` | Store bytes and bit length; validate unused bits and size. |
| OCTET STRING | `Vec<u8>` or constrained newtype | Preserve byte values and enforce size constraints. |
| UTF8String | `String` or constrained newtype | Validate ASN.1 size and alphabet constraints. |
| Other character strings | runtime `AsnString` newtype | Preserve ASN.1 repertoire and encoding semantics. |
| OBJECT IDENTIFIER | runtime `ObjectIdentifier` | Use checked arcs; do not assume every arc fits a machine integer. |
| RELATIVE-OID | runtime `RelativeOid` | Same checked-arithmetic requirement as OID arcs. |
| UTCTime, GeneralizedTime | runtime time wrapper or validated text newtype | Canonical rules need explicit APIs. |
| SEQUENCE, SET | generated `struct` | UPER SEQUENCE fields use values and `Option<T>`; inline nested records share a cursor and put their presence bitmap before each record payload. The BER/DER/CER slice handles flat records with an untagged outer type and up to six distinct effective direct-field tags for BOOLEAN, NULL, bounded INTEGER, ENUMERATED, and BIT/OCTET STRING fields, including supported BOOLEAN/INTEGER defaults. Resolved IMPLICIT/AUTOMATIC context-specific member tags are accepted; SET needs a BER/CER-only mask and emits members by effective class/number order. |
| CHOICE | generated `enum` | Include an unknown extension variant when the type is extensible. |
| SEQUENCE OF, SET OF | `Vec<T>` newtype | Retain SET OF ordering rules in codec logic. |
| Type reference | module-qualified reference | Use public newtypes for aliases that add constraints or API identity. |
| ANY / open type | runtime `OpenType` or generated typed enum | Preserve unknowns; use IOC metadata when resolved. |

The generated Rust slice supports top-level BOOLEAN as a public newtype over
`bool`, NULL as a public unit struct, and a bounded, nonextensible INTEGER as
a public newtype over `i64`. These types have UPER encode/decode and CER
encode/strict decode methods. INTEGER must have one effective finite PER
range fitting `i64`; `new(value)` returns `Result` and checks that range.
The BOOLEAN constructor is infallible. Direct nonextensible ENUMERATED and
fixed or bounded BIT/OCTET STRING types also have BER/DER/CER methods when
selected. Reject aliases, imports, tags, constructed types outside the
documented UPER, CBOR, and BER/DER/CER record slices, and unsupported constraints before creating
output. UPER-only selection supports direct and SEQUENCE-member ENUMERATED
and strings within the documented size bounds.
Direct fixed-size OCTET STRING assignments also accept the JER codec alone or
with UPER. Their generated methods call the runtime's fixed-size hexadecimal
JER helpers. Supported flat SEQUENCE BIT/OCTET STRING fields also have
BER/DER/CER methods; JER methods for those fields remain unavailable.
Bounded variable-size strings are supported as direct assignments; unbounded
or disjoint strings, named-bit lists, and extensible ENUMERATED remain future
increments.

Use a safe, `std`-only runtime crate at `rust/asn1c-runtime/`, package name
`asn1c-runtime`, import name `asn1c_runtime`, and Cargo edition 2021. Make no
MSRV claim beyond the Rust toolchain actually tested. Its initial public API is
`Limits { max_input_bytes, max_output_bytes, max_work_bits }`, `Error`,
`Encoded { bytes: Vec<u8>, bit_len: usize }`, and
`Decoded<T> { value, consumed_bits, consumed_bytes }`; `Decoded::map` transforms
a decoded value without changing consumption. `Encoded.bit_len` records
meaningful UPER bits; CER reports all encoded TLV octets as bits. The runtime
also exposes `encode_boolean_cer`, `encode_null_cer`, and
`encode_integer_cer`, plus strict `decode_boolean_cer`, `decode_null_cer`, and
`decode_integer_cer`; these accept only the exact universal tag, a short-form
length, and canonical content. The direct ENUMERATED and BIT/OCTET STRING
functions extend that API, including canonical CER string fragments over 1000
content octets. All prefix decoders leave trailing bytes unconsumed. For NULL
and any zero-width UPER complete encoding, return
`bytes == [0]` and `bit_len == 0`.

The primitive functions have these signatures:

```rust
encode_boolean(value: bool, limits: &Limits) -> Result<Encoded, Error>
decode_boolean(input: &[u8], limits: &Limits) -> Result<Decoded<bool>, Error>
encode_null(limits: &Limits) -> Result<Encoded, Error>
decode_null(input: &[u8], limits: &Limits) -> Result<Decoded<()>, Error>
validate_integer(value: i64, lower: i64, upper: i64) -> Result<(), Error>
encode_integer(value: i64, lower: i64, upper: i64, limits: &Limits)
    -> Result<Encoded, Error>
decode_integer(input: &[u8], lower: i64, upper: i64, limits: &Limits)
    -> Result<Decoded<i64>, Error>
```

Generated inherent `encode_uper` and `decode_uper` methods delegate to these
functions. Complete-value decoding may leave a suffix and reports both bit and
byte consumption. Preserve the current C PER decoder's acceptance of nonzero
low-order padding bits; do not turn that behavior into strict padding
validation in the initial slice.

The runtime uses bounded `Limits` for input bytes, output bytes, and work bits.
Defaults are 1 MiB for each byte limit and 8 MiBits for work. Every generated
encode/decode path receives these limits. Callers can tighten them. Check
arithmetic and limits before advancing,
accumulating, allocating, or sorting. Input-driven allocation must be fallible,
and malformed input must return typed errors without input-driven panics. Safe
Rust cannot guarantee that every process-level allocation failure avoids
aborting; document residual limits and review recursion, cloning, formatting,
and teardown behavior.

## Semantic lowering requirements

- **Modules, imports, aliases:** Resolve references from the fixed tree and emit
  module-qualified Rust paths. Respect exports/imports and avoid `use` name
  collisions. Preserve ASN.1 alias identity with a newtype when the alias adds
  constraints, tags, or public meaning; otherwise use a documented type alias.
- **Recursion:** Build a reference graph and identify recursive strongly
  connected components. Add `Box<T>` only on required by-value recursive edges;
  `Vec<T>` and other indirections do not need another box. Handle recursive
  aliases and cycles across imported modules explicitly.
- **Tags:** Keep universal/application/context/private class, tag number, and
  implicit/explicit mode as encoding metadata. Do not create a Rust wrapper
  solely because a type has a tag. The codec must consume effective tags after
  fixing, including module tagging defaults and nested explicit tags.
- **Constraints:** Lower the fixed constraint tree into checked runtime
  predicates for ranges, unions/intersections, SIZE, permitted alphabets,
  component constraints, and collection sizes as each form is supported.
  Provide `validate()` and checked constructors where practical. Codecs must
  enforce constraints at their specified encoding/decoding boundaries; an
  unchecked construction API must not bypass decoder validation.
- **Extensibility:** Preserve extensible ENUMERATED and CHOICE values and
  unknown SEQUENCE/SET extension additions when the selected codec can identify
  and retain them. A single untyped byte vector is not enough for every codec:
  BER needs complete unknown TLVs, while PER/OER and text encodings have
  different extension payload boundaries. Define codec-aware unknown-field
  storage before claiming round-trip support. Preserve current successful
  skip/relay behavior where supported, and offer strict rejection. Do not
  promise relay after a decoder skips bytes or across transfer syntaxes without
  a semantic value.
- **Information object classes:** Lower object sets and component-relation
  constraints into typed dispatch metadata. Generate a safe typed enum for
  known table rows plus an opaque unknown form where the codec permits it.
  Do not emit C descriptors or reproduce the C IOC output stream. Validate
  duplicate keys and unresolved references before writing.
- **Open types:** Distinguish a raw open type from a statically resolved table
  alternative. Resolve selector-to-payload relationships from the fixed tree;
  preserve unknown alternatives only when the chosen codec can retain enough
  wire information to re-encode them. Defer unsupported dynamic cases with a
  location-aware error instead of substituting an unrelated Rust type.
- **Encoding controls:** Use the shared parser representation and control
  application pass. Implement XER/JER rename and representation directives in
  their codecs, with duplicate generated-name checks. Reject a requested codec
  when a recognized control has no implementation for that codec.
- **Parameterized types:** Reuse the fixer's resolved specializations. Emit
  generic Rust types only if parameter substitution and constraints can be
  expressed without changing ASN.1 semantics; otherwise emit each resolved
  specialization with deterministic names and diagnostics for unsupported
  unresolved parameters.

Complete-message and prefix decoding must report distinct consumption
semantics. Report PER consumption in bits and other consumption in the relevant
byte or text unit. Full resumable PER sessions are optional unless the C
coverage ledger identifies a supported behavior that requires them. If a
streaming API is added, incomplete and malformed input must remain distinct,
nested decoders must share one budget, and resumed work must remain bounded.

## CLI behavior and diagnostics

The CLI has one major selector, `--rust`, for the complete Rust path: generated
types, codecs, runtime assets, writer, and Cargo project. Omitting it keeps the
C target and its defaults. Exact `--rust` parsing is extracted from the short
option parser; the option is recognized only before `--`. It cannot be used as
the operand of `-D` or `-S`. Existing `-gen-*` spellings remain unchanged.

Rust defaults independently to its qualified codecs. `--rust` alone selects
UPER and CER. `-gen-BER` opts into BER decoding and DER encoding; there is no
separate `-gen-DER` flag. `-gen-APER`, `-gen-OER`, `-gen-JER`, `-gen-CBOR`, and
`-gen-XER` select their documented subsets. `-no-gen-UPER` selects CER-only
output unless another codec was explicitly selected, while `-no-gen-CER`
omits CER methods. Disabling every supported codec or selecting an unsupported
ASN.1 form fails before output is published. The CLI keeps the C defaults
unchanged. See [the implementation matrix](implementation.md) for each exact
type/codec intersection.

Validate all flags and the complete schema before creating output files. An
unsupported CLI combination is an `EX_USAGE` diagnostic; an unsupported
ASN.1 feature produces a module/type/source-line diagnostic. Do not silently
ignore a C-specific option or emit a Rust
`compile_error!` placeholder in generated output. Keep the existing exit-status
categories documented in [`asn1c/asn1c.c`](../../asn1c/asn1c.c#L148).

The current Rust option handling is:

| Option family | Rust handling |
| --- | --- |
| `-D` | Selects the output directory; Rust defaults to `asn1c-rust`. |
| `-gen-*`, `-no-gen-*` | UPER and CER are default; APER/OER/BER/JER are opt-in for qualified slices; BER/DER/CER records require the documented flat, unique-tag shape, and SET needs UPER disabled. |
| C storage/layout/output flags | Fail as incompatible with `--rust`. |
| `-S` | Selects standard modules and resolves the matching runtime assets. |
| `-P`, `-R`, C helper/example flags | Fail as incompatible with `--rust`. |
| parser/fixer options | Apply before backend selection where supported. |
| `-E`, `-F`, `-X` | Fail because they select inspection or printing output. |

Where a shared option affects only C code generation, reject it rather than
treating it as a harmless no-op. The CLI tests cover the default C target,
`--rust` alone, unsupported codec requests, C-only options, unsupported schema
features, and refusal before any files are written.

## Build, packaging, and tests

Automake distributes and installs the Rust runtime sources. The CLI resolves
the source runtime alongside `-S`, or the installed runtime beneath the
configured data directory. The compiler integration harness uses the built
CLI and a local temporary output directory. The first runtime has no
third-party crates, and the generated copy passes an offline Cargo test.
Review later dependencies and vendor all sources before claiming offline builds.

For each feature increment, test three layers:

1. **Runtime unit tests:** valid and malformed primitive encodings, exact
   boundary lengths, truncated inputs, overflow arithmetic, constraint
   failures, shared budget exhaustion, recursion limits, and unknown extension
   policy. Maintain fuzz targets and a regression corpus for decoder inputs.
2. **Generated-crate tests:** compile representative ASN.1 modules, exercise
   public type construction and validation, run each requested codec, and
   confirm a Cargo build; require offline execution when all dependencies are
   local or vendored. Include imports, alias chains,
   recursive types, tags, extensible forms, IOC/open types, and encoding
   controls as those features enter the capability matrix.
3. **Interoperability tests:** for supported schema/codec intersections,
   compare Rust encode/decode behavior with existing C-generated codecs and
   checked reference vectors. Test both directions, malformed input, and
   semantic values. Do not use agreement with the C implementation alone as
   evidence of standards correctness; include normative vectors and boundary
   cases.

Rust integration scripts are in `tests/tests-rust-compiler/` and are registered
in Automake's `TESTS`. Dedicated Rust CI exercises them; Cargo remains optional
for C-only builds. Record vector provenance and semantic differences in
fixtures. The M0 ledger maps each relevant C schema/test to its Rust
counterpart, codec, direction, variant, constraints, extension policy, and
result. Exclusions require evidence that the C behavior is unsupported or has
a source-backed limit.

## Implementation supervision and ownership

Sol owns architecture, shared interfaces, assignments, CLI/dispatch, build and
CI wiring, integration, review, and release claims. Runtime, generator, and
test work use exclusive paths after their interfaces are frozen. Agents do not
edit shared headers, CLI, manifests, build files, CI, or the coverage ledger in
parallel. Shared-file proposals go to Sol for serial integration. Each handoff
names the supported matrix, dependencies, owned paths, reference rules and
fixtures, required negative cases, commands, and evidence. See the detailed
[stage-one plan](stage-one-plan.md) for the assignment template and owners.

Keep `--rust` opt-in and C behavior on the existing path. `--rust` alone
currently selects UPER and CER for the qualified primitive slice.
Explicitly requested codecs and unsupported schema features fail before
publishing a crate. Do not expose a user-facing type-only crate as a fallback.
The initial UPER and CER slices do not complete the broader parity milestones.

## Milestones and completion gates

1. **M0, baseline and contracts:** Build a coverage ledger for existing C
   codec/type/direction/variant behavior and applicable tests. Freeze integer,
   bit-string, error, cursor, constraint, tag, codec-context, unknown-extension,
   resource-budget, and generator/writer contracts. Freeze prefix-consumption
   semantics; prototype resumable streaming only if the coverage ledger needs
   it. Use Cargo edition 2021. Select dependencies and finite default limits
   with evidence; make no MSRV claim beyond tested
   toolchains.
2. **M1, foundation and harness:** The target flag, capability diagnostics,
   name/path validation, staged Cargo output, local runtime packaging, and
   generated-crate harness are implemented. Complete negative, regeneration,
   install, and platform qualification as part of the stage gates.
3. **M2, first UPER slice:** The current slice supports NULL, BOOLEAN, and
   bounded nonextensible INTEGER whose effective range fits `i64`. Extend it
   with nonextensible ENUMERATED, bounded OCTET STRING, and BIT STRING only
   when bounds and malformed-input behavior are safely covered. Include a
   small SEQUENCE only after field traversal is reviewed. Test bit consumption,
   truncation, bound edges, invalid application values, and small budgets.
   Compare Rust/C in both directions, use independent vectors, and provide
   generated API documentation and a usage example.
4. **M3, APER and semantic foundations:** Port APER alignment, length
   fragmentation, and open-type helpers separately from UPER. Expand PER to
   strings, time, REAL, arbitrary INTEGERs, constructed types, tags, defaults,
   extensions, and recursion. Complete imports, aliases, parameterized
   specializations, constraints, PDU dependencies, IOC tables, and open types
   in bounded feature assignments.
5. **M4, BER/DER and OER:** Expand Rust BER decoding, DER encoding, BER TLV and
   length handling, constructed strings, canonical ordering, and OER
   encode/decode. Expand Rust CER encoding and strict decoding beyond the
   current slice as each supported type matrix is qualified. Keep the
   permissive C BER decoder distinct from the strict C CER decoder.
6. **M5, XER/JER/CBOR:** Add bounded tokenization, escaping, names, supported
   encoding controls, exact integer handling, object-member policy, and the
   repository's CBOR mapping. Keep canonical output and permissive decoding
   expectations explicit. Reject duplicate/unknown/trailing JER BIT STRING
   members according to current runtime policy. Disable XML external entities
   if an XML dependency is selected.
7. **M6, qualification and packaging:** Map every applicable existing C test
   and supported behavior cell. Investigate every gap and record source-backed
   exclusions. Test feature combinations, strict/compatible extension policy,
   Rust toolchains, platforms, packaging, VPATH, output paths with spaces,
   prefix consumption, any supported streaming mode, budgets, teardown, fuzz
   regressions, and generated projects from installed and distribution
   artifacts. Add a Rust converter/example for
   interoperability workflows. Test Linux and macOS, and a 32-bit target when
   an executable runner is available. Keep utility APIs idiomatic; do not clone
   each C helper signature. Useful display support and Rust-native randomized
   test values may accompany the codecs.

Milestones are ordered by dependency, and all codec families remain in scope.
A codec-feature pair is qualified only when its runtime, generator, errors,
generated-crate tests, policy tests, and interoperability evidence pass. The
Every C-supported behavior cell needs a Rust counterpart. Exclusions are
allowed only for C-unsupported behavior or a source-backed C limitation.

## Open implementation questions

- Should finite default limits change as codec and constructed-type support
  grows, and what tests would justify an adjustment?
- Which Rust toolchains can CI test, and what licensing checks are required
  for the runtime and generated projects?
- Which dependencies, if any, are needed for bigint, XML, JSON, or CBOR support,
  and how will their code and licenses be vendored for offline builds?
- What exact internal representation should `Real` use to preserve values
  across BER/OER/PER and textual codecs without reducing values to `f64`?
- Which constrained aliases are public newtypes versus aliases, and what is the
  supported source-compatibility policy when generated APIs change?
- What manifest/version format should govern overwriting output from an older
  generator, and what recovery behavior is required after a disk error?
- Which reference-vector sources and Rust fuzzing toolchain are available in
  project CI?

## Source map

The baseline records the code-generation audit starting point. File anchors
above refer to the checked-out source tree and may need refreshing on another
revision. The fixed expression model and
its fields for constraints, tags, markers, encoding controls, modules, and
object tables are in [`asn1p_expr.h`](../../libasn1parser/asn1p_expr.h#L116) and
[`asn1p_module.h`](../../libasn1parser/asn1p_module.h#L46). The callback table
and C implementation list are in [`asn1c_lang.h`](../../libasn1compiler/asn1c_lang.h#L6)
and [`asn1c_C.h`](../../libasn1compiler/asn1c_C.h#L20). Build integration is
currently listed in
[`Makefile.am`](../../libasn1compiler/Makefile.am#L10),
[`asn1c/Makefile.am`](../../asn1c/Makefile.am#L4), and
[`skeletons/Makefile.am`](../../skeletons/Makefile.am#L4).
