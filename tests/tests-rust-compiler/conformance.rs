//! Generated-crate conformance and hostile-input tests for the first Rust slice.
//!
//! These integration tests use independent UPER bit vectors, live API round
//! trips, explicit resource limits, and bounded deterministic mutations.

use asn1c_generated::first_slice::{
    Count, Decoded, Empty, Error as AsnError, Flag, Limits as AsnLimits, Ok as AsnOk,
    Result as AsnResult, SignBounds, Singleton, Wide,
};
use asn1c_runtime::{Error, Limits, Resource};
use std::path::Path;

/// Check the bytes and meaningful bit count returned by a generated encoder.
///
/// # Parameters
/// `actual` is the generated encoding, `bytes` is the independent golden byte
/// slice, `bit_len` is the golden bit count, and `case` names the vector.
///
/// # Returns
/// No value; any difference panics and fails the calling integration test.
///
/// # Errors and panics
/// Panics on a byte or bit-count mismatch. The generated encoder is expected
/// to return a typed error before this helper is called when it cannot encode.
///
/// # Source, history, and example
/// Original source: new asn1c generated-Rust integration test. Version/date:
/// 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: added
/// with the primitive codecs. Example: `check_encoding(&encoded, &[0x80], 1, "UPER TRUE")`.
fn check_encoding(actual: &asn1c_runtime::Encoded, bytes: &[u8], bit_len: usize, case: &str) {
    assert_eq!(actual.bytes, bytes, "{case} bytes");
    assert_eq!(actual.bit_len, bit_len, "{case} bit count");
}

/// Save generated Rust bytes for a separately compiled C decoder.
///
/// # Parameters
/// `filename` is a fixed interop-vector name; `bytes` are the generated output.
///
/// # Returns
/// No value. Writes the vector under `ASN1C_RUST_VECTORS` for the harness.
///
/// # Errors and panics
/// Panics if the harness omitted its output directory or the vector cannot be
/// written. Those conditions indicate an invalid test environment.
///
/// # Source, history, and example
/// Original source: new asn1c generated-Rust interoperability test. Version/date:
/// 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: initial
/// bidirectional C/Rust wire exchange. Example: `write_rust_vector("null.bin", &[0])`.
fn write_rust_vector(filename: &str, bytes: &[u8]) {
    let directory =
        std::env::var_os("ASN1C_RUST_VECTORS").expect("harness must configure ASN1C_RUST_VECTORS");
    let path = Path::new(&directory).join(filename);
    std::fs::write(&path, bytes)
        .unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
}

/// Read a complete vector emitted by the separate generated C encoder.
///
/// # Parameters
/// `filename` is a fixed vector name under the directory in `ASN1C_C_VECTORS`.
///
/// # Returns
/// The exact complete encoding emitted by the C fixture.
///
/// # Errors and panics
/// Panics if the harness omitted its directory or the file cannot be read.
///
/// # Source, history, and example
/// Original source: new asn1c generated-Rust interoperability test. Version/date:
/// 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: initial
/// bidirectional C/Rust wire exchange. Example: `read_c_vector("bool_true.bin")`.
fn read_c_vector(filename: &str) -> Vec<u8> {
    let directory =
        std::env::var_os("ASN1C_C_VECTORS").expect("harness must configure ASN1C_C_VECTORS");
    let path = Path::new(&directory).join(filename);
    std::fs::read(&path).unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

/// Check one generated CER vector against an independent vector and live C output.
///
/// # Parameters
/// `filename` is shared between the C and Rust vector directories; `actual` is
/// Rust output and `expected` is the independent complete CER encoding.
///
/// # Returns
/// No value. The exact bytes are also saved for generic C `ATS_CER` decoding.
///
/// # Errors and panics
/// Panics if Rust, the C encoder, or the independent expected bytes differ, or
/// if either test vector directory is missing or unwritable.
///
/// # Source, history, and example
/// Original source: new asn1c CER interoperability fixture. Version/date:
/// 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: added
/// for independent and bidirectional CER checks. Example: check `02 02 00 80`.
fn check_cer_vector(filename: &str, actual: &asn1c_runtime::Encoded, expected: &[u8]) {
    check_encoding(actual, expected, expected.len() * 8, filename);
    write_rust_vector(filename, &actual.bytes);
    assert_eq!(read_c_vector(filename), expected, "C CER bytes: {filename}");
}

/// Check BOOLEAN values against fixed UPER vectors and prefix consumption.
///
/// # Parameters and returns
/// No parameters or return value. Exercises generated `Flag` encode/decode.
///
/// # Errors and panics
/// Panics if encoding, decoding, semantic values, or consumption differs.
///
/// # Source, history, and example
/// Original source: generated type contract plus X.691 UPER BOOLEAN bit order.
/// Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
/// History: initial Rust compiler integration. Example: TRUE is `0x80` in one bit.
#[test]
fn boolean_golden_vectors_and_prefix() {
    let limits = Limits::default();
    for (value, octet, filename) in [
        (false, 0x00, "bool_false.bin"),
        (true, 0x80, "bool_true.bin"),
    ] {
        let encoded = Flag::new(value).encode_uper(&limits).unwrap();
        check_encoding(&encoded, &[octet], 1, "BOOLEAN");
        write_rust_vector(filename, &encoded.bytes);

        let decoded = Flag::decode_uper(&[octet, 0x5a], &limits).unwrap();
        assert_eq!(decoded.value.value(), value);
        assert_eq!(decoded.consumed_bits, 1);
        assert_eq!(decoded.consumed_bytes, 1);
    }
}

/// Check zero-width NULL complete encoding and malformed filler handling.
///
/// # Parameters and returns
/// No parameters or return value. Exercises generated unit type `Empty`.
///
/// # Errors and panics
/// Panics if complete-value bytes, consumption, or malformed-input rejection
/// differs from the runtime contract.
///
/// # Source, history, and example
/// Original source: generated type contract and `uper_decode_complete` behavior.
/// Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
/// History: initial Rust compiler integration. Example: NULL encodes as `[0]`, zero bits.
#[test]
fn null_complete_encoding() {
    let limits = Limits::default();
    let encoded = Empty.encode_uper(&limits).unwrap();
    check_encoding(&encoded, &[0x00], 0, "NULL");
    write_rust_vector("null.bin", &encoded.bytes);

    let decoded = Empty::decode_uper(&[0x00, 0x7f], &limits).unwrap();
    assert_eq!(decoded.consumed_bits, 0);
    assert_eq!(decoded.consumed_bytes, 1);
    assert!(Empty::decode_uper(&[], &limits).is_err());
    assert!(Empty::decode_uper(&[0x01], &limits).is_err());
}

/// Check generated CER encoders against independent canonical TLV vectors.
///
/// # Parameters and returns
/// No parameters or return value. Exercises BOOLEAN, NULL, and signed i64 CER.
///
/// # Errors and panics
/// Panics if generated encoding, minimal INTEGER sign handling, or complete
/// octet bit counts differ from the expected vectors.
///
/// # Source, history, and example
/// Original source: X.690 CER primitive encoding rules. Version/date:
/// 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: added
/// for the Rust CER encoder slice. Example: 128 encodes as `02 02 00 80`.
#[test]
fn cer_primitive_golden_vectors() {
    let limits = Limits::default();
    check_cer_vector(
        "cer_bool_false.bin",
        &Flag::new(false).encode_cer(&limits).unwrap(),
        &[0x01, 0x01, 0x00],
    );
    check_cer_vector(
        "cer_bool_true.bin",
        &Flag::new(true).encode_cer(&limits).unwrap(),
        &[0x01, 0x01, 0xff],
    );
    check_cer_vector(
        "cer_null.bin",
        &Empty.encode_cer(&limits).unwrap(),
        &[0x05, 0x00],
    );

    let vectors: &[(i64, &[u8])] = &[
        (127, &[0x02, 0x01, 0x7f]),
        (128, &[0x02, 0x02, 0x00, 0x80]),
        (-128, &[0x02, 0x01, 0x80]),
        (-129, &[0x02, 0x02, 0xff, 0x7f]),
        (i64::MIN, &[0x02, 0x08, 0x80, 0, 0, 0, 0, 0, 0, 0]),
        (
            i64::MAX,
            &[0x02, 0x08, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ),
    ];
    for (value, expected) in vectors {
        let encoded = Wide::new(*value).unwrap().encode_cer(&limits).unwrap();
        check_encoding(&encoded, expected, expected.len() * 8, "CER INTEGER");
    }

    let sign_vectors: &[(i64, &[u8], &str)] = &[
        (127, &[0x02, 0x01, 0x7f], "cer_sign_127.bin"),
        (128, &[0x02, 0x02, 0x00, 0x80], "cer_sign_128.bin"),
        (-128, &[0x02, 0x01, 0x80], "cer_sign_minus_128.bin"),
        (-129, &[0x02, 0x02, 0xff, 0x7f], "cer_sign_minus_129.bin"),
    ];
    for (value, expected, filename) in sign_vectors {
        let encoded = SignBounds::new(*value)
            .unwrap()
            .encode_cer(&limits)
            .unwrap();
        check_cer_vector(filename, &encoded, expected);
    }

    for (value, expected, filename) in [
        (-10, &[0x02, 0x01, 0xf6][..], "cer_count_min.bin"),
        (10, &[0x02, 0x01, 0x0a][..], "cer_count_max.bin"),
    ] {
        let encoded = Count::new(value).unwrap().encode_cer(&limits).unwrap();
        check_cer_vector(filename, &encoded, expected);
    }
    let singleton = Singleton::new(5).unwrap().encode_cer(&limits).unwrap();
    check_cer_vector("cer_singleton.bin", &singleton, &[0x02, 0x01, 0x05]);
}

/// Check canonical DER output and BER decoding against shared C vectors.
///
/// # Parameters and returns
/// No parameters or return value. Exercises all three generated BER/DER types.
///
/// # Errors and panics
/// Panics if DER bytes, BER values, prefix consumption, or malformed-input
/// handling differs from the runtime contract.
///
/// # Source, history, and example
/// Original source: X.690 DER encoding and BER primitive decoding contracts.
/// Version/date: 0.1.0, 2026-10-30. Responsible party: asn1c maintainers.
/// History: added with opt-in generated BER/DER methods. Example: BOOLEAN TRUE
/// uses the canonical DER bytes `01 01 FF`.
#[test]
fn ber_der_primitive_vectors_and_prefixes() {
    let limits = Limits::default();
    check_cer_vector(
        "cer_bool_false.bin",
        &Flag::new(false).encode_der(&limits).unwrap(),
        &[0x01, 0x01, 0x00],
    );
    check_cer_vector(
        "cer_bool_true.bin",
        &Flag::new(true).encode_der(&limits).unwrap(),
        &[0x01, 0x01, 0xff],
    );
    check_cer_vector(
        "cer_null.bin",
        &Empty.encode_der(&limits).unwrap(),
        &[0x05, 0x00],
    );
    check_cer_vector(
        "cer_count_min.bin",
        &Count::new(-10).unwrap().encode_der(&limits).unwrap(),
        &[0x02, 0x01, 0xf6],
    );
    check_cer_vector(
        "cer_count_max.bin",
        &Count::new(10).unwrap().encode_der(&limits).unwrap(),
        &[0x02, 0x01, 0x0a],
    );
    check_cer_vector(
        "cer_singleton.bin",
        &Singleton::new(5).unwrap().encode_der(&limits).unwrap(),
        &[0x02, 0x01, 0x05],
    );
    for (value, expected, filename) in [
        (127, &[0x02, 0x01, 0x7f][..], "cer_sign_127.bin"),
        (128, &[0x02, 0x02, 0x00, 0x80][..], "cer_sign_128.bin"),
        (-128, &[0x02, 0x01, 0x80][..], "cer_sign_minus_128.bin"),
        (-129, &[0x02, 0x02, 0xff, 0x7f][..], "cer_sign_minus_129.bin"),
    ] {
        let encoded = SignBounds::new(value).unwrap().encode_der(&limits).unwrap();
        check_cer_vector(filename, &encoded, expected);
    }

    let mut boolean_prefix = read_c_vector("cer_bool_true.bin");
    boolean_prefix.push(0x5a);
    let decoded = Flag::decode_ber(&boolean_prefix, &limits).unwrap();
    assert!(decoded.value.value());
    assert_eq!(decoded.consumed_bytes, 3);
    assert_eq!(decoded.consumed_bits, 24);
    assert!(Flag::decode_ber(&[0x01, 0x01, 0x01], &limits)
        .unwrap()
        .value
        .value());
    let multi_octet_boolean = Flag::decode_ber(&[0x01, 0x02, 0x00, 0xff], &limits).unwrap();
    assert!(multi_octet_boolean.value.value());
    assert_eq!(multi_octet_boolean.consumed_bytes, 4);
    assert_eq!(multi_octet_boolean.consumed_bits, 32);
    assert_eq!(
        multi_octet_boolean.value.encode_der(&limits).unwrap().bytes,
        [0x01, 0x01, 0xff]
    );
    assert!(Flag::decode_cer(&[0x01, 0x02, 0x00, 0xff], &limits).is_err());
    let empty_boolean = Flag::decode_ber(&[0x01, 0x00], &limits).unwrap();
    assert!(!empty_boolean.value.value());
    assert_eq!(empty_boolean.consumed_bytes, 2);
    assert_eq!(empty_boolean.consumed_bits, 16);
    assert_eq!(
        empty_boolean.value.encode_der(&limits).unwrap().bytes,
        [0x01, 0x01, 0x00]
    );
    assert!(Flag::decode_cer(&[0x01, 0x00], &limits).is_err());
    assert!(Flag::decode_ber(&[0x01, 0x01], &limits).is_err());

    let null_decoded = Empty::decode_ber(&read_c_vector("cer_null.bin"), &limits).unwrap();
    assert_eq!(null_decoded.consumed_bytes, 2);
    assert!(Empty::decode_ber(&[0x05, 0x01, 0x00], &limits).is_err());

    let count_decoded = Count::decode_ber(&read_c_vector("cer_count_max.bin"), &limits).unwrap();
    assert_eq!(count_decoded.value.value(), 10);
    assert_eq!(count_decoded.consumed_bytes, 3);
    let redundant_count = Count::decode_ber(&[0x02, 0x02, 0x00, 0x0a], &limits).unwrap();
    assert_eq!(redundant_count.value.value(), 10);
    assert!(Count::decode_ber(&[0x02, 0x01, 0x0b], &limits).is_err());
    let singleton = Singleton::decode_ber(&read_c_vector("cer_singleton.bin"), &limits).unwrap();
    assert_eq!(singleton.value.value(), 5);
    let sign_bounds = SignBounds::decode_ber(
        &read_c_vector("cer_sign_minus_129.bin"),
        &limits,
    )
    .unwrap();
    assert_eq!(sign_bounds.value.value(), -129);
}

/// Decode live C CER vectors with generated strict decoders and reject noncanonical TLVs.
///
/// # Parameters and returns
/// No parameters or return value. Exercises generated `decode_cer` methods.
///
/// # Errors and panics
/// Panics if a canonical C vector does not decode to its value with full-TLV
/// consumption, or if a noncanonical, truncated, or out-of-range TLV decodes.
///
/// # Source, history, and example
/// Original source: X.690 CER primitive rules and the strict C `cer_decode`
/// contract. Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c
/// maintainers. History: added with the Rust CER decoder slice. Example:
/// `01 01 01` is rejected because CER TRUE must be `FF`.
#[test]
fn cer_strict_decode_interop() {
    let limits = Limits::default();
    for (filename, value) in [("cer_bool_false.bin", false), ("cer_bool_true.bin", true)] {
        let bytes = read_c_vector(filename);
        let decoded = Flag::decode_cer(&bytes, &limits).unwrap();
        assert_eq!(decoded.value.value(), value, "{filename}");
        assert_eq!(decoded.consumed_bytes, bytes.len());
        assert_eq!(decoded.consumed_bits, bytes.len() * 8);
    }
    let null_bytes = read_c_vector("cer_null.bin");
    assert_eq!(Empty::decode_cer(&null_bytes, &limits).unwrap().consumed_bytes, 2);

    for (filename, value) in [("cer_count_min.bin", -10), ("cer_count_max.bin", 10)] {
        let bytes = read_c_vector(filename);
        let decoded = Count::decode_cer(&bytes, &limits).unwrap();
        assert_eq!(decoded.value.value(), value, "{filename}");
        assert_eq!(decoded.consumed_bytes, bytes.len());
    }
    for (filename, value) in [
        ("cer_sign_127.bin", 127),
        ("cer_sign_128.bin", 128),
        ("cer_sign_minus_128.bin", -128),
        ("cer_sign_minus_129.bin", -129),
    ] {
        let bytes = read_c_vector(filename);
        assert_eq!(
            SignBounds::decode_cer(&bytes, &limits).unwrap().value.value(),
            value,
            "{filename}"
        );
    }
    let singleton = read_c_vector("cer_singleton.bin");
    assert_eq!(Singleton::decode_cer(&singleton, &limits).unwrap().value.value(), 5);

    // Full-range i64 boundaries round-trip through the generated encoder.
    for value in [i64::MIN, -1, 0, 1, i64::MAX] {
        let encoded = Wide::new(value).unwrap().encode_cer(&limits).unwrap();
        let decoded = Wide::decode_cer(&encoded.bytes, &limits).unwrap();
        assert_eq!(decoded.value.value(), value);
        assert_eq!(decoded.consumed_bytes, encoded.bytes.len());
    }

    // Trailing bytes are not consumed, matching C `cer_decode`.
    let prefixed = Flag::decode_cer(&[0x01, 0x01, 0xff, 0x05, 0x00], &limits).unwrap();
    assert!(prefixed.value.value());
    assert_eq!(prefixed.consumed_bytes, 3);

    for hostile in [
        &[0x01, 0x01, 0x01][..],
        &[0x01, 0x81, 0x01, 0xff][..],
        &[0x01, 0x80, 0xff, 0x00, 0x00][..],
        &[0x21, 0x01, 0xff][..],
        &[0x01, 0x02, 0xff, 0xff][..],
        &[0x01, 0x01][..],
        &[][..],
    ] {
        assert!(Flag::decode_cer(hostile, &limits).is_err(), "{hostile:02x?}");
    }
    assert!(Empty::decode_cer(&[0x05, 0x01, 0x00], &limits).is_err());
    assert!(Empty::decode_cer(&[0x05, 0x81, 0x00], &limits).is_err());
    for hostile in [
        &[0x02, 0x00][..],
        &[0x02, 0x02, 0x00, 0x05][..],
        &[0x02, 0x02, 0xff, 0xf6][..],
        &[0x02, 0x01, 0x0b][..],
        &[0x02, 0x01, 0xf5][..],
        &[0x0a, 0x01, 0x00][..],
    ] {
        assert!(Count::decode_cer(hostile, &limits).is_err(), "{hostile:02x?}");
    }
    assert!(Singleton::decode_cer(&[0x02, 0x01, 0x06], &limits).is_err());
    assert!(Wide::decode_cer(&[0x02, 0x09, 0, 0x80, 0, 0, 0, 0, 0, 0, 0], &limits).is_err());

    let tight = Limits {
        max_input_bytes: 2,
        ..Limits::default()
    };
    assert!(matches!(
        Flag::decode_cer(&[0x01, 0x01, 0xff], &tight),
        Err(Error::LimitExceeded {
            resource: Resource::InputBytes,
            ..
        })
    ));
}

/// Ensure generated ASN.1 names can overlap Rust and runtime API names safely.
///
/// # Parameters and returns
/// No parameters or return value. Exercises names `Limits`, `Error`, `Decoded`,
/// `Result`, and `Ok` against emitted method and runtime names.
///
/// # Errors and panics
/// Panics if these generated types shadow Rust/runtime paths or fail their
/// basic UPER round trips.
///
/// # Source, history, and example
/// Original source: generated Rust name-collision regression. Version/date:
/// 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: added
/// for the initial Rust compiler slice. Example: `Decoded::new(1)` encodes.
#[test]
fn generated_runtime_name_collisions_are_safe() {
    let runtime_limits = Limits::default();
    let generated_limits = AsnLimits::new(true);
    assert!(generated_limits.value());

    let generated_error = AsnError;
    let encoded_null = generated_error.encode_uper(&runtime_limits).unwrap();
    assert_eq!(encoded_null.bytes, [0x00]);

    let encoded_integer = Decoded::new(1)
        .unwrap()
        .encode_uper(&runtime_limits)
        .unwrap();
    check_encoding(&encoded_integer, &[0x80], 1, "Decoded name collision");
    assert_eq!(
        Decoded::decode_uper(&encoded_integer.bytes, &runtime_limits)
            .unwrap()
            .value
            .value(),
        1
    );

    let generated_result = AsnResult::new(true);
    let encoded_result = generated_result.encode_uper(&runtime_limits).unwrap();
    check_encoding(&encoded_result, &[0x80], 1, "Result name collision");
    assert!(
        AsnResult::decode_uper(&encoded_result.bytes, &runtime_limits)
            .unwrap()
            .value
            .value()
    );

    let generated_ok = AsnOk::new(false);
    let encoded_ok = generated_ok.encode_uper(&runtime_limits).unwrap();
    check_encoding(&encoded_ok, &[0x00], 1, "Ok name collision");
    assert!(!AsnOk::decode_uper(&encoded_ok.bytes, &runtime_limits)
        .unwrap()
        .value
        .value());
}

/// Check bounded signed INTEGER vectors, spare codes, and constructor bounds.
///
/// # Parameters and returns
/// No parameters or return value. Exercises generated `Count` for `-10..10`.
///
/// # Errors and panics
/// Panics if a golden vector, prefix-consumption value, range check, or spare
/// code rejection differs from the fixed UPER expectations.
///
/// # Source, history, and example
/// Original source: generated type contract and X.691 constrained whole number.
/// Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
/// History: initial Rust compiler integration. Example: -1 has offset 9, encoded `0x48`.
#[test]
fn bounded_integer_golden_vectors_and_errors() {
    let limits = Limits::default();
    for (value, octet, filename) in [
        (-10, 0x00, "count_min.bin"),
        (-1, 0x48, "count_minus_one.bin"),
        (0, 0x50, "count_zero.bin"),
        (10, 0xa0, "count_max.bin"),
    ] {
        let encoded = Count::new(value).unwrap().encode_uper(&limits).unwrap();
        check_encoding(&encoded, &[octet], 5, "Count");
        write_rust_vector(filename, &encoded.bytes);

        let decoded = Count::decode_uper(&[octet, 0xab], &limits).unwrap();
        assert_eq!(decoded.value.value(), value);
        assert_eq!(decoded.consumed_bits, 5);
        assert_eq!(decoded.consumed_bytes, 1);
    }

    assert!(Count::new(-11).is_err());
    assert!(Count::new(11).is_err());
    assert!(Count::decode_uper(&[], &limits).is_err());
    assert!(Count::decode_uper(&[0xa8], &limits).is_err());

    // Match the C decoder policy: low unused bits in a final octet are ignored.
    let padded = Count::decode_uper(&[0x51], &limits).unwrap();
    assert_eq!(padded.value.value(), 0);
}

/// Check a singleton INTEGER's complete zero-width representation.
///
/// # Parameters and returns
/// No parameters or return value. Exercises generated `Singleton` at value 5.
///
/// # Errors and panics
/// Panics if the value is not represented by one zero complete byte and no
/// meaningful bits, or if empty input is accepted as a complete value.
///
/// # Source, history, and example
/// Original source: generated type contract and X.691 constrained whole number.
/// Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
/// History: initial Rust compiler integration. Example: range `5..5` encodes as `[0]`.
#[test]
fn singleton_integer_complete_encoding() {
    let limits = Limits::default();
    let encoded = Singleton::new(5).unwrap().encode_uper(&limits).unwrap();
    check_encoding(&encoded, &[0x00], 0, "Singleton");
    write_rust_vector("singleton.bin", &encoded.bytes);

    let decoded = Singleton::decode_uper(&[0x00], &limits).unwrap();
    assert_eq!(decoded.value.value(), 5);
    assert_eq!(decoded.consumed_bits, 0);
    assert_eq!(decoded.consumed_bytes, 1);
    assert!(Singleton::decode_uper(&[], &limits).is_err());
    assert!(Singleton::decode_uper(&[0x01], &limits).is_err());
}

/// Decode bytes written by the live C encoder through generated Rust types.
///
/// # Parameters and returns
/// No parameters or return value. Reads every shared BOOLEAN, NULL, bounded
/// INTEGER, and singleton vector from `ASN1C_C_VECTORS`.
///
/// # Errors and panics
/// Panics if the C fixture did not write a vector, if Rust rejects it, or if
/// Rust's bytes or decoded semantic value differ.
///
/// # Source, history, and example
/// Original source: new asn1c bidirectional interoperability test. Version/date:
/// 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: initial
/// live C-to-Rust decode coverage. Example: decode C's `count_minus_one.bin` as -1.
#[test]
fn c_encoder_vectors_decode_in_rust() {
    let limits = Limits::default();
    for (value, filename) in [(false, "bool_false.bin"), (true, "bool_true.bin")] {
        let c_bytes = read_c_vector(filename);
        assert_eq!(
            Flag::new(value).encode_uper(&limits).unwrap().bytes,
            c_bytes
        );
        assert_eq!(
            Flag::decode_uper(&c_bytes, &limits).unwrap().value.value(),
            value
        );
    }

    let c_null = read_c_vector("null.bin");
    assert_eq!(Empty.encode_uper(&limits).unwrap().bytes, c_null);
    assert_eq!(
        Empty::decode_uper(&c_null, &limits).unwrap().consumed_bytes,
        1
    );

    for (value, filename) in [
        (-10, "count_min.bin"),
        (-1, "count_minus_one.bin"),
        (0, "count_zero.bin"),
        (10, "count_max.bin"),
    ] {
        let c_bytes = read_c_vector(filename);
        assert_eq!(
            Count::new(value)
                .unwrap()
                .encode_uper(&limits)
                .unwrap()
                .bytes,
            c_bytes
        );
        assert_eq!(
            Count::decode_uper(&c_bytes, &limits).unwrap().value.value(),
            value
        );
    }

    let c_singleton = read_c_vector("singleton.bin");
    assert_eq!(
        Singleton::new(5)
            .unwrap()
            .encode_uper(&limits)
            .unwrap()
            .bytes,
        c_singleton
    );
    assert_eq!(
        Singleton::decode_uper(&c_singleton, &limits)
            .unwrap()
            .value
            .value(),
        5
    );
}

/// Check all edge encodings of the full signed i64 constraint range.
///
/// # Parameters and returns
/// No parameters or return value. Exercises generated `Wide` without a C parity
/// claim because the current C accumulator does not cover this width.
///
/// # Errors and panics
/// Panics if a fixed 64-bit vector, decoded semantic value, or bit count differs.
///
/// # Source, history, and example
/// Original source: generated type contract and the full inclusive i64 range.
/// Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
/// History: initial Rust compiler integration. Example: `i64::MIN` encodes as eight zero bytes.
#[test]
fn full_i64_range_golden_vectors() {
    let limits = Limits::default();
    for (value, bytes) in [
        (i64::MIN, [0x00; 8]),
        (-1, [0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        (i64::MAX, [0xff; 8]),
    ] {
        let encoded = Wide::new(value).unwrap().encode_uper(&limits).unwrap();
        check_encoding(&encoded, &bytes, 64, "Wide");

        let decoded = Wide::decode_uper(&bytes, &limits).unwrap();
        assert_eq!(decoded.value.value(), value);
        assert_eq!(decoded.consumed_bits, 64);
        assert_eq!(decoded.consumed_bytes, 8);
    }
}

/// Check configured input, output, and meaningful-work ceilings.
///
/// # Parameters and returns
/// No parameters or return value. Uses one generated BOOLEAN and the public
/// runtime `Limits` fields to exercise each resource independently.
///
/// # Errors and panics
/// Panics if a request above a configured limit succeeds or an exact-limit
/// request fails.
///
/// # Source, history, and example
/// Original source: runtime resource contract. Version/date: 0.1.0, 2026-10-11.
/// Responsible party: asn1c maintainers. History: initial Rust compiler test.
/// Example: set `max_work_bits: 0` and require a one-bit BOOLEAN encode to fail.
#[test]
fn resource_limits_are_enforced() {
    let defaults = Limits::default();
    let no_input = Limits {
        max_input_bytes: 0,
        ..defaults
    };
    let input_error = Flag::decode_uper(&[0x80], &no_input).unwrap_err();
    assert!(matches!(
        input_error,
        Error::LimitExceeded {
            resource: Resource::InputBytes,
            ..
        }
    ));

    let no_output = Limits {
        max_output_bytes: 0,
        ..defaults
    };
    let output_error = Flag::new(true).encode_uper(&no_output).unwrap_err();
    assert!(matches!(
        output_error,
        Error::LimitExceeded {
            resource: Resource::OutputBytes,
            ..
        }
    ));

    let no_work = Limits {
        max_work_bits: 0,
        ..defaults
    };
    let work_error = Flag::new(true).encode_uper(&no_work).unwrap_err();
    assert!(matches!(
        work_error,
        Error::LimitExceeded {
            resource: Resource::WorkBits,
            ..
        }
    ));

    let one_bit = Limits {
        max_input_bytes: 1,
        max_output_bytes: 1,
        max_work_bits: 1,
    };
    assert_eq!(Flag::new(true).encode_uper(&one_bit).unwrap().bytes, [0x80]);
    assert!(Flag::decode_uper(&[0x80, 0x00], &one_bit).is_err());

    let wide = Wide::new(i64::MAX).unwrap();
    let seven_output_bytes = Limits {
        max_output_bytes: 7,
        ..defaults
    };
    let output_error = wide.encode_uper(&seven_output_bytes).unwrap_err();
    assert!(matches!(
        output_error,
        Error::LimitExceeded {
            resource: Resource::OutputBytes,
            ..
        }
    ));

    let sixty_three_work_bits = Limits {
        max_work_bits: 63,
        ..defaults
    };
    let work_error = wide.encode_uper(&sixty_three_work_bits).unwrap_err();
    assert!(matches!(
        work_error,
        Error::LimitExceeded {
            resource: Resource::WorkBits,
            ..
        }
    ));
}

/// Exercise deterministic byte mutations and every truncated i64 prefix.
///
/// # Parameters and returns
/// No parameters or return value. Iterates bounded one-byte mutations and all
/// prefixes of one full-width INTEGER vector.
///
/// # Errors and panics
/// Panics if a decoder panics for any tested byte string. Ordinary decode
/// errors are expected and accepted.
///
/// # Source, history, and example
/// Original source: generated Rust parser-safety test plan. Version/date:
/// 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: added
/// with bounded primitive decoders. Example: decode every single-octet prefix.
#[test]
fn deterministic_mutations_never_panic() {
    let limits = Limits::default();
    for octet in u8::MIN..=u8::MAX {
        let one_byte = [octet];
        assert!(std::panic::catch_unwind(|| {
            let _ = Flag::decode_uper(&one_byte, &limits);
            let _ = Count::decode_uper(&one_byte, &limits);
            let _ = Empty::decode_uper(&one_byte, &limits);
        })
        .is_ok());
    }

    let complete = [0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    for prefix_len in 0..=complete.len() {
        assert!(std::panic::catch_unwind(|| {
            let _ = Wide::decode_uper(&complete[..prefix_len], &limits);
        })
        .is_ok());
    }
}
