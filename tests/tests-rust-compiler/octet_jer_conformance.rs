//! Generated fixed-size OCTET STRING JER tests and C interoperability vectors.

use asn1c_generated::octet_jer::{EmptyHexOctets, MixedHexOctets};
use asn1c_runtime::{Error, Limits, Resource};
use std::fs;
use std::path::Path;

/// Store a generated JSON vector for the independent C JER decoder.
///
/// Parameters: directory is the vector folder; name is a fixed test filename;
/// bytes is the complete JSON token. Returns no value. Errors: filesystem
/// failures panic so the test reports missing or unwritable output. Original
/// source: Rust/C JER integration fixture. Version/date: 2026-10-30.
/// Responsible party: asn1c maintainers. History: added OCTET STRING JER
/// parity. Example: `store_vector(path, "jer_octets.json", b"\"00AF\"")`.
fn store_vector(directory: &Path, name: &str, bytes: &[u8]) {
    fs::create_dir_all(directory).expect("create JER vector directory");
    fs::write(directory.join(name), bytes).expect("write Rust JER vector");
}

/// Compare the generated JER encoding against one exact JSON token.
///
/// Parameters: actual is generated output; expected is the fixed token.
/// Returns no value. Errors: assertions panic when bytes or bit length differ.
/// Original source: C OCTET STRING JER hexadecimal mapping. Version/date:
/// 2026-10-30. Responsible party: asn1c maintainers. History: generated JER
/// parity. Example: `assert_token(&encoded, b"\"00AF\"")`.
fn assert_token(actual: &asn1c_runtime::Encoded, expected: &[u8]) {
    assert_eq!(actual.bytes, expected);
    assert_eq!(actual.bit_len, expected.len() * 8);
}

/// Encode, decode, and exchange empty and mixed byte strings with C.
///
/// Parameters: none. Returns no value; assertions check generated APIs and
/// cross-language wire vectors. Errors: codec errors propagate through test
/// assertions; filesystem errors panic. Original source: JER OCTET STRING
/// rule in `OCTET_STRING_jer.c`. Version/date: 2026-10-30. Responsible party:
/// asn1c maintainers. History: added fixed-size OCTET STRING JER coverage.
/// Example: SIZE(3) `[00, AF, FF]` encodes as the JSON string `"00AFFF"`.
#[test]
fn fixed_octets_round_trip_and_exchange_with_c() {
    let limits = Limits::default();
    let empty = EmptyHexOctets::new(vec![]).expect("empty fixed-size value");
    let mixed = MixedHexOctets::new(vec![0x00, 0xaf, 0xff]).expect("mixed fixed-size value");
    let empty_encoded = empty
        .encode_jer(&limits)
        .expect("encode empty OCTET STRING");
    let mixed_encoded = mixed
        .encode_jer(&limits)
        .expect("encode mixed OCTET STRING");
    assert_token(&empty_encoded, b"\"\"");
    assert_token(&mixed_encoded, b"\"00AFFF\"");

    let empty_decoded = EmptyHexOctets::decode_jer(&empty_encoded.bytes, &limits)
        .expect("decode empty OCTET STRING");
    let mixed_lowercase = MixedHexOctets::decode_jer(b" \t\"00aFfF\"\r\n", &limits)
        .expect("decode lowercase hexadecimal and surrounding JSON whitespace");
    assert_eq!(empty_decoded.value, empty);
    assert_eq!(mixed_lowercase.value, mixed);
    assert_eq!(mixed_lowercase.consumed_bytes, 12);
    assert_eq!(mixed_lowercase.consumed_bits, 96);

    let c_vectors =
        std::env::var_os("ASN1C_C_JER_VECTORS").expect("C JER vector directory is configured");
    let c_directory = Path::new(&c_vectors);
    let c_empty =
        fs::read(c_directory.join("jer_empty_octets.json")).expect("read C empty JER vector");
    assert_eq!(c_empty, b"\"\"");
    assert_eq!(
        EmptyHexOctets::decode_jer(&c_empty, &limits).unwrap().value,
        empty
    );
    let c_mixed =
        fs::read(c_directory.join("jer_mixed_octets.json")).expect("read C mixed JER vector");
    assert_eq!(c_mixed, b"\"00AFFF\"");
    assert_eq!(
        MixedHexOctets::decode_jer(&c_mixed, &limits).unwrap().value,
        mixed
    );

    let rust_vectors = std::env::var_os("ASN1C_RUST_JER_VECTORS")
        .expect("Rust JER vector directory is configured");
    let rust_directory = Path::new(&rust_vectors);
    store_vector(
        rust_directory,
        "jer_empty_octets.json",
        &empty_encoded.bytes,
    );
    store_vector(
        rust_directory,
        "jer_mixed_octets.json",
        &mixed_encoded.bytes,
    );
}

/// Reject malformed tokens, wrong fixed sizes, and resource exhaustion.
///
/// Parameters: none. Returns no value; assertions inspect typed errors.
/// Errors: malformed tokens are expected and checked explicitly. Original
/// source: fixed OCTET STRING JER validation and runtime limits. Version/date:
/// 2026-10-30. Responsible party: asn1c maintainers. History: malformed-input
/// and limit coverage. Example: a seven-byte output ceiling rejects `"00AFFF"`.
#[test]
fn malformed_values_and_limits_are_rejected() {
    let limits = Limits::default();
    assert!(matches!(
        MixedHexOctets::new(vec![0]),
        Err(Error::InvalidEncoding { .. })
    ));
    for input in [
        b"00AFFF".as_slice(),
        b"\"00AFG1\"",
        b"\"00AF\"",
        b"\"00AFFF\"false",
    ] {
        assert!(matches!(
            MixedHexOctets::decode_jer(input, &limits),
            Err(Error::InvalidEncoding { .. })
        ));
    }

    let value = MixedHexOctets::new(vec![0x00, 0xaf, 0xff]).expect("valid value");
    let output_limited = Limits {
        max_output_bytes: 7,
        ..limits
    };
    assert!(matches!(
        value.encode_jer(&output_limited),
        Err(Error::LimitExceeded {
            resource: Resource::OutputBytes,
            ..
        })
    ));
    let input_limited = Limits {
        max_input_bytes: 7,
        ..limits
    };
    assert!(matches!(
        MixedHexOctets::decode_jer(b"\"00AFFF\"", &input_limited),
        Err(Error::LimitExceeded {
            resource: Resource::InputBytes,
            ..
        })
    ));
    let work_limited = Limits {
        max_work_bits: 63,
        ..limits
    };
    assert!(matches!(
        value.encode_jer(&work_limited),
        Err(Error::LimitExceeded {
            resource: Resource::WorkBits,
            ..
        })
    ));
}
