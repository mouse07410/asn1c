//! Generated BIT STRING JER conformance and live C interoperability tests.

use asn1c_generated::octet_jer::{BoundedBits, ThreeBits};
use asn1c_runtime::{BitStringValue, Limits};
use std::{env, fs, path::PathBuf};

/// Read one named vector from an integration-test directory.
///
/// # Parameters and returns
/// `variable` names the environment variable containing the directory; `name`
/// is the vector filename. Returns the complete file bytes.
///
/// # Errors
/// Panics with a descriptive message if the variable or file is missing.
///
/// # Source, version, history, and example
/// Original source: Rust/C JER integration fixture. Version/date: 2026-10-30.
/// Responsible party: asn1c maintainers. History: added BIT STRING JER
/// interoperability. Example: `read_vector("ASN1C_C_BIT_JER_VECTORS", "x.json")`.
fn read_vector(variable: &str, name: &str) -> Vec<u8> {
    let directory = env::var_os(variable).expect("JER vector directory is configured");
    fs::read(PathBuf::from(directory).join(name)).expect("read JER vector")
}

/// Save one Rust-generated vector for the independent C decoder.
///
/// # Parameters and returns
/// `name` is the output filename; `bytes` is the complete JSON value. This
/// function returns no value.
///
/// # Errors
/// Panics if the configured directory cannot be created or written.
///
/// # Source, version, history, and example
/// Original source: Rust/C JER integration fixture. Version/date: 2026-10-30.
/// Responsible party: asn1c maintainers. History: added BIT STRING JER
/// interoperability. Example: `write_vector("bits.json", token)`.
fn write_vector(name: &str, bytes: &[u8]) {
    let directory =
        env::var_os("ASN1C_RUST_BIT_JER_VECTORS").expect("Rust JER vector directory is configured");
    let directory = PathBuf::from(directory);
    fs::create_dir_all(&directory).expect("create Rust JER vector directory");
    fs::write(directory.join(name), bytes).expect("write Rust JER vector");
}

/// Compare fixed-size BIT STRING JER with C and reject malformed input.
///
/// # Parameters and returns
/// No parameters or return value.
///
/// # Errors
/// Panics only when an encode, decode, or validation assertion fails.
///
/// # Source, version, history, and example
/// Original source: fixed-size `BIT_STRING_encode_jer` vectors. Version/date:
/// 2026-10-30. Responsible party: asn1c maintainers. History: initial BIT
/// STRING JER tests. Example: SIZE(3) payload `0xA0` emits `"A0"`.
#[test]
fn fixed_bit_string_matches_c_hex_vector() {
    let value = ThreeBits::new(vec![0xa0]).expect("valid three-bit value");
    let encoded = value.encode_jer(&Limits::default()).expect("encode JER");
    assert_eq!(encoded.bytes, b"\"A0\"");

    let c_value = read_vector("ASN1C_C_BIT_JER_VECTORS", "jer_three_bits.json");
    let decoded = ThreeBits::decode_jer(&c_value, &Limits::default()).expect("decode C token");
    assert_eq!(decoded.value, value);
    write_vector("jer_three_bits.json", &encoded.bytes);

    for malformed in [b"\"A\"".as_slice(), b"\"A1\"", b"\"GG\"", b"\"A0\"x"] {
        assert!(ThreeBits::decode_jer(malformed, &Limits::default()).is_err());
    }
    assert!(ThreeBits::new(vec![0xa1]).is_err());
}

/// Compare bounded BIT STRING JER object shape and logical length with C.
///
/// # Parameters and returns
/// No parameters or return value.
///
/// # Errors
/// Panics only when an encode, decode, or validation assertion fails.
///
/// # Source, version, history, and example
/// Original source: variable-size `BIT_STRING_encode_jer` vectors. Version/date:
/// 2026-10-30. Responsible party: asn1c maintainers. History: initial bounded
/// BIT STRING JER tests. Example: width five and `0xA8` emits the C object.
#[test]
fn bounded_bit_string_matches_c_object_vector() {
    let packed = BitStringValue::new(vec![0xa8], 5).expect("valid packed bits");
    let value = BoundedBits::new(packed).expect("valid bounded value");
    let encoded = value.encode_jer(&Limits::default()).expect("encode JER");
    assert_eq!(encoded.bytes, b"{\"value\":\"A8\",\"length\":5}");

    let c_value = read_vector("ASN1C_C_BIT_JER_VECTORS", "jer_bounded_bits.json");
    let decoded = BoundedBits::decode_jer(&c_value, &Limits::default()).expect("decode C object");
    assert_eq!(decoded.value, value);
    write_vector("jer_bounded_bits.json", &encoded.bytes);

    for malformed in [
        b"{}".as_slice(),
        b"{\"length\":5,\"value\":\"A8\"}",
        b"{\"value\":\"A8\",\"length\":0}",
        b"{\"value\":\"A1\",\"length\":5}",
        b"{\"value\":\"A8\",\"length\":05}",
    ] {
        assert!(BoundedBits::decode_jer(malformed, &Limits::default()).is_err());
    }
}
