# Rust BER/DER/CER checkpoint (2026-11-01)

The current implementation is a qualified subset, not C codec parity. The
support matrix in [implementation.md](implementation.md) and the detailed
[design](ber-der-cer-design.md) are the scope and behavior references.

## Implemented in this checkpoint

- One or two direct same-module named SEQUENCE/SET children of a flat
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
- The latest C fix, `976d86eb`, preserves PER alphabets for built-in string
  aliases. It is already included after the earlier `30591ead` checkpoint;
  its compiler regression C609 passes.

## Validation at checkpoint

Runtime tests pass (263 tests), as does exact strict Clippy for all runtime
targets and features. Focused two-child validation passes nine generated
Rust tests, BER-only/CER-only strict Clippy, the schema boundary crates, and
C differential checks under ASan/UBSan. Imported INTEGER validation passes ten
Rust test functions, exact strict Clippy for both source orders and codec
selections, 28 canonical C vectors in each direction, 21 syntax-valid negative
schemas, and C differential checks under ASan/UBSan. Local/imported resource
controls verify identical exact work budgets. The full backend harness passes
(`make -C tests/tests-rust-compiler check TESTS=check-rust-backend.sh`, one
suite, zero failures). A separately checked negative schema rejects mixed
named scalar/record references without publishing output. `make dist` passes
and includes the checkpoint note, two-child fixtures, and imported INTEGER fixtures.

## Resume from here

1. Integrate the imported named-record child gate designed in
   [ber-der-cer-design.md](ber-der-cer-design.md). Preserve scalar import
   restrictions and validate all child leaves even for unused imports. Share
   one parent operation context through crate-visible field callbacks. Review
   SET helper discovery across modules, both source orders, owned leaves,
   independent SET sorting, and exact local/imported budget equivalence.
2. Resolve the pending generated BOOLEAN representation decision. Strict
   Clippy rejects structs with more than three BOOLEAN fields through
   `struct_excessive_bools`. No lint suppression has been added. The user
   was asked to choose public fields with a specific schema lint exception
   or a bitset with accessors while retaining every lint.

Remaining broad gaps include broader imported and recursive reference graphs,
constructed CHOICE and collections, OPEN TYPE and containing forms, REAL,
general tagging and constraints, and resumable streaming. Do not describe
the current Rust codecs as fully on par with C.
