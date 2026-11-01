# Rust BER/DER/CER checkpoint (2026-11-01)

The current implementation is a qualified subset, not C codec parity. The
support matrix in [implementation.md](implementation.md) and the detailed
[design](ber-der-cer-design.md) are the scope and behavior references.

## Implemented in this checkpoint

- A direct same-module named SET child of a flat untagged SEQUENCE or SET,
  required or OPTIONAL, with supported primitive child leaves.
- Natural, context-specific IMPLICIT, and EXPLICIT child tags; separate child
  and parent SET ordering; shared nested resource accounting; strict CER
  canonical comparison; BER definite and indefinite decoding.
- Generated Rust conformance and C differential fixtures, negative schema
  publication gates, and BER-only/CER-only strict Clippy checks.
- A former negative fixture for a named SET inside a SEQUENCE is now a positive
  generation check. The generated source assertion checks the actual child
  method call.

## Validation at checkpoint

`make -C tests/tests-rust-compiler check TESTS=check-rust-backend.sh` passes
(one suite, zero failures). The harness includes generated Rust tests,
generated C differential fixtures, and exact `cargo clippy --all-targets
--all-features -- -W clippy::pedantic -W clippy::nursery -D warnings` checks.
`make dist` passes and includes this note and the named SET fixtures.

## Resume from here

1. Implement the two-named-child gate designed in
   [ber-der-cer-design.md](ber-der-cer-design.md). The generator currently
   accepts one named record reference; field emission and nested callbacks
   already iterate over all fields. Preserve the one-child cases while
   validating both target assignments and distinct effective tags before
   publishing a crate.
2. Add generated Rust and C differential tests for two children, optional
   absence, same-target distinct tags, parent and child SET ordering, shared
   limits, malformed input, and no-publication negative schemas.
3. Then address cross-module imports. A live C probe confirmed that a direct
   imported bounded INTEGER in a flat record works with natural, IMPLICIT,
   and EXPLICIT tags; an explicit EXPORTS list must include the symbol.
   Resolve imports by module identity and declared symbol, not by name alone.

Remaining broad gaps include imported and recursive reference graphs,
constructed CHOICE and collections, OPEN TYPE and containing forms, REAL,
general tagging and constraints, and resumable streaming. Do not describe
the current Rust codecs as fully on par with C.
