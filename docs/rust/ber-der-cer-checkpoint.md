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
- The latest C fix, `976d86eb`, preserves PER alphabets for built-in string
  aliases. It is already included after the earlier `30591ead` checkpoint;
  its compiler regression C609 passes.

## Validation at checkpoint

Runtime tests pass (263 tests), as does exact strict Clippy for all runtime
targets and features. Focused two-child validation passes nine generated
Rust tests, BER-only/CER-only strict Clippy, the schema boundary crates, and
C differential checks under ASan/UBSan. The full backend harness passes
(`make -C tests/tests-rust-compiler check TESTS=check-rust-backend.sh`, one
suite, zero failures). A separately checked negative schema rejects mixed
named scalar/record references without publishing output. `make dist` passes
and includes the checkpoint note and all two-child fixtures.

## Resume from here

1. Implement the imported bounded INTEGER gate designed in
   [ber-der-cer-design.md](ber-der-cer-design.md). A live C probe confirmed
   natural, IMPLICIT, and EXPLICIT member tags. Resolve imports by module
   identity, explicit declaration, direct target ownership, and exports.
   Preserve shared parent resource accounting and preflight publication.
2. Resolve the pending generated BOOLEAN representation decision. Strict
   Clippy rejects structs with more than three BOOLEAN fields through
   `struct_excessive_bools`. No lint suppression has been added. The user
   was asked to choose public fields with a specific schema lint exception
   or a bitset with accessors while retaining every lint.

Remaining broad gaps include imported and recursive reference graphs,
constructed CHOICE and collections, OPEN TYPE and containing forms, REAL,
general tagging and constraints, and resumable streaming. Do not describe
the current Rust codecs as fully on par with C.
