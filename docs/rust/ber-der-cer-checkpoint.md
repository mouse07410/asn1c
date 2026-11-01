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
- Transparent one-hop same-module bounded INTEGER aliases, including forward
  declarations, standalone public codecs, and named record fields. Rust aliases
  preserve base type identity and checked construction; range/tag readers use
  the direct base and record callbacks retain the parent's resource context.
  Unsupported metadata, chains, imports, and codec selections reject before
  publication, including unused aliases.
- C BOOLEAN DEFAULT comparison now uses truth values. TRUE represented by
  `0xff` or `7` omits canonically, and strict CER rejects an explicit default.
  Numeric storage selection and non-BOOLEAN DEFAULT output remain unchanged.
- Exact twelve-field imported/local aggregate acceptance and the first
  excessive thirteen-field rejection, with both modules supplied. Generated
  C and Rust share fixed DER/CER vectors, prefix checks, and work boundaries.

## Validation at checkpoint

Runtime tests pass (263 tests), as does exact strict Clippy for all runtime
targets and features. Focused two-child validation passes nine generated
Rust tests, BER-only/CER-only strict Clippy, the schema boundary crates, and
C differential checks under ASan/UBSan. Imported INTEGER validation passes ten
Rust test functions, exact strict Clippy for both source orders and codec
selections, 28 canonical C vectors in each direction, 20 syntax-valid negative
schemas, and C differential checks under ASan/UBSan. Local/imported resource
controls verify identical exact work budgets. The full compiler harness passes
(`make -C tests/tests-rust-compiler -j2 check`, both backend and alias drivers,
two suites, zero failures). A separately checked negative schema rejects mixed
named scalar/record references without publishing output. `make dist` passes
and includes the checkpoint note, two-child and imported INTEGER/record fixtures,
type-name regression fixtures, transparent aliases, and exact imported-field boundaries.
Archive verification compares every changed/new file with its current source bytes.

Imported record validation passes eight Rust functions in both source orders,
both individual codec selections under exact strict Clippy, 34 canonical C
vectors in each direction, 23 syntax-valid negative schemas, and three C
fixtures under ASan/UBSan. Type-name validation adds two Rust tests and three
parse-valid no-publication collisions. The combined source-order, unused-import,
malformed-second-child, owned-leaf, truncation, mutation, and exact-budget checks
pass against the rebuilt main compiler.

Transparent alias qualification passes twelve generated Rust tests (eight
reused record tests plus four identity/range/default/limit tests), combined and
individual BER/CER exact strict Clippy, 21 parse-valid schema rejections, and
12 unsupported codec selections. C comparison passes 24 DER/CER value pairs
and eight extra DEFAULT TRUE encodings, normally and under ASan/UBSan. The
pre-fix C compiler fails both raw TRUE omission and explicit DEFAULT strict-CER
rejection; the corrected compiler passes. Non-BOOLEAN DEFAULT source output
is identical after excluding output-directory strings. Existing C compiler
regressions C148/C609 and all INTEGER storage regressions pass, including
issue #591 DEFAULT callbacks in all five storage modes. The coverage inventory
now counts all 277 standalone Rust test functions referenced by the drivers;
repeated codec/source-order runs and reused alias tests do not inflate that count.

## Resume from here

1. Implement the user's approved BOOLEAN representation decision (2026-11-01):
   use a bitset with getters/setters for records that exceed Clippy's BOOLEAN
   field limit, and keep every lint enabled. The decision is settled; the
   representation implementation follows this checkpoint. Preserve OPTIONAL
   and DEFAULT semantics, public construction, naming safety, shared limits,
   and all currently qualified parent/child and codec combinations.
2. Extend the reference/type graph beyond the qualified one-hop local INTEGER
   alias and direct imported INTEGER/record slices. Sol reviews the next graph
   boundary before implementation; keep exact ownership, declared constraints,
   cycle detection, unused declarations, wire identity, and shared limits checked.

Remaining broad gaps include broader imported and recursive reference graphs,
constructed CHOICE and collections, OPEN TYPE and containing forms, REAL,
general tagging and constraints, and resumable streaming. Do not describe
the current Rust codecs as fully on par with C.
