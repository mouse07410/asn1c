# Rust BER/DER/CER checkpoint (2026-11-01)

The current implementation is a qualified subset, not C codec parity. The
support matrix in [implementation.md](implementation.md) and the detailed
[design](ber-der-cer-design.md) are the scope and behavior references.

## Implemented in this checkpoint

- One or two direct local or imported named SEQUENCE/SET children of a flat
  untagged SEQUENCE or SET, required or OPTIONAL, with supported primitive
  child leaves. Empty SEQUENCE children remain supported.
- Natural, context-specific IMPLICIT, and EXPLICIT child tags; separate child
  and parent SET ordering; shared nested resource accounting; strict CER
  canonical comparison; BER definite and indefinite decoding.
- Generated Rust conformance and C differential fixtures, negative schema
  publication gates, and BER-only/CER-only strict Clippy checks.
- Repeated references to one target with distinct effective tags; six parent
  fields and twelve aggregate schema fields; failure/retry, shared scratch,
  work, and depth boundary regressions across sequential child callbacks.
- One directly imported finite bounded INTEGER field in an untagged flat
  SEQUENCE or SET, with required/OPTIONAL presence, natural/IMPLICIT/EXPLICIT
  tags, scalar DEFAULT siblings, qualified source paths, validated exports
  and module ownership, and shared parent resource accounting. All declared
  imports are checked, including unused imports.
- Direct imported record targets use the same import ownership/export rules,
  full child-leaf validation even when unused, qualified type paths, and
  crate-visible callbacks under the parent context. SET helper discovery
  scans all fixed modules and emits no dead callbacks for unused SET targets.
- Dashed Rust type names now use CamelCase, preserving existing interior
  capitals; `Foo-Bar` becomes `FooBar` and reserved `Self` becomes `Asn1Self`.
  Normalized type/nested/keyword collisions fail before publication. Module,
  field, and ENUMERATED naming behavior is unchanged.
- The latest C fix, `976d86eb`, preserves PER alphabets for built-in string
  aliases. It is already included after the earlier `30591ead` checkpoint;
  its compiler regression C609 passes.

## Validation at checkpoint

Runtime tests pass (263 tests), as does exact strict Clippy for all runtime
targets and features. Focused two-child validation passes nine generated
Rust tests, BER-only/CER-only strict Clippy, the schema boundary crates, and
C differential checks under ASan/UBSan. Imported INTEGER validation passes ten
Rust test functions, exact strict Clippy for both source orders and codec
selections, 28 canonical C vectors in each direction, 20 syntax-valid negative
schemas, and C differential checks under ASan/UBSan. Local/imported resource
controls verify identical exact work budgets. The full backend harness passes
(`make -C tests/tests-rust-compiler check TESTS=check-rust-backend.sh`, one
suite, zero failures). A separately checked negative schema rejects mixed
named scalar/record references without publishing output. `make dist` passes
and includes the checkpoint note, two-child and imported INTEGER/record fixtures,
and type-name regression fixtures.

Imported record validation passes seven Rust functions in both source orders,
both individual codec selections under exact strict Clippy, 32 canonical C
vectors in each direction, 22 syntax-valid negative schemas, and three C
fixtures under ASan/UBSan. Type-name validation adds two Rust tests and three
parse-valid no-publication collisions. The combined source-order, unused-import,
malformed-second-child, owned-leaf, truncation, mutation, and exact-budget checks
pass against the rebuilt main compiler.

## Resume from here

1. Complete isolated implementation of the approved transparent same-module
   one-hop bounded INTEGER alias design in `ber-der-cer-design.md`.
   A scratch C/AST probe is checking the acceptance evidence.
   Review declared versus inherited constraints, fixed target ownership,
   alias-before-target order, wire tags, cycles, range checks, and shared
   parent limits before enabling any broader graph. No alias support has
   been added in this checkpoint. Keep the tested imported-record baseline
   separate from alias implementation until those checks pass.
2. Resolve the pending generated BOOLEAN representation decision. Strict
   Clippy rejects structs with more than three BOOLEAN fields through
   `struct_excessive_bools`. No lint suppression has been added. The user
   was asked to choose public fields with a specific schema lint exception
   or a bitset with accessors while retaining every lint.

Remaining broad gaps include broader imported and recursive reference graphs,
constructed CHOICE and collections, OPEN TYPE and containing forms, REAL,
general tagging and constraints, and resumable streaming. Do not describe
the current Rust codecs as fully on par with C.
