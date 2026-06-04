# Oversized INTEGER constraint / `-finteger-native-type` tests

These tests cover robust INTEGER constraint handling for bounds that exceed
signed `long`/`intmax_t`, fixed-width native storage for ordinary constraints,
and the `-finteger-native-type=int32|uint32|int64|uint64|auto` code-generation
option.

## Running

After building asn1c in-tree:

```sh
./run.sh                       # uses ../../asn1c/asn1c and ../../skeletons
./run.sh /path/to/asn1c /path/to/skeletons
```

The script exercises four areas:

1. **Command-line option parsing** — `auto`, `int32`, `uint32`, `int64`,
   `uint64` are accepted; `bogus` is rejected with a non-zero exit. (`long`
   is still accepted as a deprecated, undocumented alias for `auto`.)
2. **Generated storage selection** — the storage type emitted for `T1..T8`
   under each mode (see table below).
3. **`asn1c_bigint` unit tests** — decimal parsing, fit tests, canonical
   INTEGER content-octet generation, comparison and range arithmetic.
4. **Runtime + generated-code tests** — the `asn_cval_t` comparison/range
   helpers, the `asn_ulong2INTEGER()` fix, constraint enforcement (accept /
   reject at and beyond each bound, including `UINT64_MAX` vs `-1` and
   oversized `INTEGER_t` bounds), and UPER round-trips for `T5`/`T6`.

## Expected generated storage (`oversized-integers.asn1`)

| Type | range | `auto` | `int32` | `uint32` | `int64` | `uint64` |
|------|-------|--------|---------|----------|---------|----------|
| T1 | 0..255 | long | int32_t | uint32_t | int64_t | uint64_t |
| T2 | -2^31..2^31-1 | long | int32_t | INTEGER_t | int64_t | INTEGER_t |
| T3 | 0..2^32-1 | unsigned long | INTEGER_t | uint32_t | int64_t | uint64_t |
| T4 | 0..2^63-1 | INTEGER_t | INTEGER_t | INTEGER_t | int64_t | uint64_t |
| T5 | 0..2^64-1 | INTEGER_t | INTEGER_t | INTEGER_t | INTEGER_t | uint64_t |
| T6 | 2^64-6..2^64-1 | INTEGER_t | INTEGER_t | INTEGER_t | INTEGER_t | uint64_t |
| T7 | 0..2^64 | INTEGER_t | INTEGER_t | INTEGER_t | INTEGER_t | INTEGER_t |
| T8 | -2^64..2^64 | INTEGER_t | INTEGER_t | INTEGER_t | INTEGER_t | INTEGER_t |

`auto` (the default) **preserves the traditional storage decision** —
`long`/`unsigned long` for ranges that fit the conservative 32-bit native
window, `INTEGER_t` otherwise — so default-generated code is unchanged.
Fixed-width `int32_t`/`uint32_t`/`int64_t`/`uint64_t` storage is produced
**only** by the explicit modes. Oversized constraints (e.g. `0..2^64-1`)
remain correct under `auto` via `INTEGER_t` plus `asn_cval_t` bounds, and the
unsigned wraparound / `UINT64_MAX`-vs-`-1` distinction is preserved
regardless of storage.

## Notes / known limitations

- Fixed-width `int32_t`/`uint32_t`/`int64_t`/`uint64_t` storage is backed by
  the width-aware `NativeInteger` codec (`field_width`/`field_unsigned` in
  `asn_INTEGER_specifics_t`); the legacy `field_width == 0` path (ENUMERATED
  and any descriptor that doesn't set it) is byte-for-byte unchanged.
- PER/OER bound *descriptors* (`asn_per_constraint_t`) still store bounds as
  `intmax_t`; an additive `asn_integer_constraint_t` (asn_cval_t-based) and
  `asn_cval_compute_range()` are provided in `asn_constraint_value.h` as the
  foundation for migrating those descriptors. Range *width* (`range_bits`) is
  already computed correctly (e.g. `T6` encodes in 3 bits).
