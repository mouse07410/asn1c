# Rust conversion: first stage

This directory defines the first stage of converting asn1c to Rust: generate Rust
types and codecs backed by a Rust implementation of the runtime currently in
`skeletons/`, and migrate the relevant codec tests. The compiler frontend remains
in C during this stage. The implemented Rust runtime covers selected UPER,
APER, OER, CER, BER, and DER operations for BOOLEAN, NULL, and bounded INTEGER values;
the remaining runtime and codec coverage is an incremental conversion target.

The user authorized backend implementation on 2026-10-11. The selected mode is
`--rust`; codec coverage is incremental and uses safe Rust with `std`. The
current generated-code slice supports UPER encode/decode, CER encode/strict
decode, and opt-in APER/OER encode/decode or BER decode/DER encode for BOOLEAN, NULL, and bounded
nonextensible INTEGER. Other types and codecs remain conversion targets.
An explicit UPER-only selection also supports flat SEQUENCE assignments with
required direct primitive fields and one cumulative resource budget.

Start with the [architecture decision](architecture.md) and
[implementation plan](stage-one-plan.md). Supporting designs describe the
[runtime](runtime.md), [code generator](code-generation.md), and
[test migration](testing.md).

The baseline inspected for this plan is commit
`5a0ccf24ede9b176e8fd76861bf4855ed95f5105` on `vlm_master`.
Implementation must recheck that baseline against subsequent changes, especially
security fixes, schema semantics, and the test inventory.

Sol supervises implementation and accepts integration; three Luna agents own
bounded coding assignments. The plan specifies their dependencies, file
ownership, handoff requirements, and acceptance gates. No implementation agents
should treat a proposed interface in these documents as an existing API.

The implemented runtime API is documented in its
[crate README](../../rust/asn1c-runtime/README.md); see also the
[first implementation](implementation.md). The broader designs below
include proposed interfaces and features beyond this first runtime slice.
