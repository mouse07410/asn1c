# Generated Rust compiler tests

`check-rust-backend.sh` exercises the first generated Rust slice in a temporary
directory. Its generated conformance cases cover BOOLEAN, NULL, bounded and
singleton INTEGER, and a full `i64`-range INTEGER with UPER. It checks CER
encodings for BOOLEAN, NULL, and bounded signed `i64` INTEGER against fixed
vectors; selected `Count`, `Singleton`, and `SignBounds` values are also
compared with a separately generated C encoder. Rust-produced CER TLVs are
passed to the generated C decoder for semantic checks, and the
`cer_strict_decode_interop` case decodes live C-generated CER vectors with
the generated Rust `decode_cer` and checks hostile rejections. The Rust crate
builds offline with its copied runtime.

The BER/DER extension adds generated `decode_ber` and `encode_der` methods for
the same primitive types when `-gen-BER` is selected. Tests check canonical DER
bytes against independent vectors and C-produced primitive TLVs, BER prefix
consumption, noncanonical but accepted BER forms, malformed input, and bounds.
The harness also generates a BER-only crate to check codec selection.

The APER/OER primitive extension adds opt-in paired encode/decode methods for
the same direct BOOLEAN, NULL, and bounded INTEGER subset. The harness builds
each codec alone and together, runs generated Rust vectors and malformed-input
checks, and compares selected APER/OER bytes with a separately generated C
fixture. Runtime tests cover additional alignment and integer-width edges.

The UPER-only SEQUENCE slice packs required direct BOOLEAN, NULL, and bounded
INTEGER fields with one bit cursor and one cumulative resource budget. Tests
cover cross-byte packing, zero-width fields and whole-value filler, full `i64`
bounds, spare codes, truncation, and exact work/input/output ceilings. Default
UPER/CER selection rejects SEQUENCE until CER support exists; optional and
nested fields are also rejected before publishing output.
The fixed-size string fixture covers standalone OCTET STRING and BIT STRING,
zero-sized values, bit packing inside a mixed SEQUENCE, malformed lengths and
pad bits, truncation, and whole-operation budgets. It also checks that the
default UPER/CER selection rejects strings without CER support.
Direct ENUMERATED tests cover numeric index ordering, spare indexes,
singleton framing, budgets, extension rejection, and live C comparisons.

The harness covers codec selection as well as wire behavior. The default Rust
mask contains UPER and CER; `-gen-UPER` retains both, `-no-gen-UPER` selects
CER-only output, and `-no-gen-CER` leaves UPER enabled. `-gen-BER` adds BER/DER
methods and `-no-gen-BER` omits them. APER/OER are opt-in and can be selected
independently. CER-only generation is
also checked with explicit `-gen-CER -no-gen-UPER`; `-no-gen-BER` leaves CER
selected. Disabling all supported codecs and requesting
unsupported XER/JER/CBOR codecs are rejected before output publication. The generated
dual-codec and CER-only APIs are checked to contain `decode_cer`, and the
`-no-gen-CER` output is checked to omit it.

C remains a comparison implementation rather than a protocol oracle. Fixed
vectors and Rust-side malformed-input checks provide independent checks. The
exact supported scope and unimplemented families are listed in
[`coverage.json`](coverage.json); the harness does not claim codec-wide or
type-wide parity.

If Cargo or `rustc` is unavailable, Automake marks the test skipped with status
77.

Negative compiler cases cover unsupported types, constraints, selectors, and
name collisions before output publication. Destination checks cover unrelated
files, interior symlinks, traversal entries, oversized ownership manifests,
and deterministic regeneration. Runtime-name overlaps are positive compilation
cases. `LIB`, `Core`, and `Asn1cRuntime` modules are checked for safe filenames
and pass an offline Cargo check.

The harness is registered in the normal test suite. It can also be run from a
configured build tree with:

```sh
make -C tests/tests-rust-compiler check
```
