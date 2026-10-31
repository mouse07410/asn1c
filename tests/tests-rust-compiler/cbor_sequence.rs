//! Generated Rust CBOR SEQUENCE map conformance and malformed-input checks.
use asn1c_generated::cbor_sequence::Packet;
use asn1c_runtime::Limits;

/// Build a representative record with OPTIONAL ANY and BOOLEAN values.
/// Source: `CborSequence.asn1`. Version: 2026-10-30. Inputs: none.
/// Returns: a valid Packet. Errors: none. Responsible: asn1c maintainers.
/// History: constructed CBOR slice. Example: `sample().encode_cbor(&limits)`.
fn sample() -> Packet {
    Packet {
        flag: true,
        empty: (),
        amount: -2,
        maybe: Some(false),
        opaque: Some(vec![0, 0xa5]),
        usual: 2,
    }
}

/// Compare the generated encoder with the C CBOR declaration-order vector.
/// Source: C `SEQUENCE_encode_cbor`. Version: 2026-10-30. Inputs: none.
/// Returns: unit. Errors: assertion panic. Responsible: asn1c maintainers.
/// History: map interop. Example: `cargo test sequence_vector`.
#[test]
fn sequence_vector() {
    let limits = Limits::default();
    let expected = [
        0xa6, 0x64, b'f', b'l', b'a', b'g', 0xf5, 0x65, b'e', b'm', b'p', b't', b'y', 0xf6,
        0x66, b'a', b'm', b'o', b'u', b'n', b't', 0x21, 0x65, b'm', b'a', b'y', b'b', b'e', 0xf4,
        0x66, b'o', b'p', b'a', b'q', b'u', b'e', 0x42, 0, 0xa5, 0x65, b'u', b's', b'u', b'a',
        b'l', 2,
    ];
    let encoded = sample().encode_cbor(&limits).unwrap();
    assert_eq!(encoded.bytes, expected);
    let decoded = Packet::decode_cbor(&expected, &limits).unwrap();
    assert_eq!(decoded.value, sample());
    assert_eq!(decoded.consumed_bytes, expected.len());
    let mut suffix = expected.to_vec();
    suffix.push(0xff);
    assert_eq!(Packet::decode_cbor(&suffix, &limits).unwrap().consumed_bytes, expected.len());
}

/// Check unordered keys, omitted OPTIONAL/default members, and unknown values.
/// Source: C `SEQUENCE_decode_cbor`. Version: 2026-10-30. Inputs: none.
/// Returns: unit. Errors: assertion panic. Responsible: asn1c maintainers.
/// History: map decoder parity. Example: `cargo test unordered_and_omitted`.
#[test]
fn unordered_and_omitted() {
    let limits = Limits::default();
    let input = [
        0xc0, 0xa4, 0x66, b'a', b'm', b'o', b'u', b'n', b't', 0x21, 0x65, b'x', b't', b'r',
        b'a', b'!', 0x82, 1, 2, 0x65, b'e', b'm', b'p', b't', b'y', 0xf6, 0x64, b'f', b'l',
        b'a', b'g', 0xf5,
    ];
    let decoded = Packet::decode_cbor(&input, &limits).unwrap();
    assert_eq!(decoded.consumed_bytes, input.len());
    assert_eq!(decoded.value.maybe, None);
    assert_eq!(decoded.value.opaque, None);
    assert_eq!(decoded.value.usual, 2);
    assert_eq!(decoded.value.amount, -2);
    assert!(decoded.value.flag);
}

/// Reject duplicate/missing keys, bad values, incomplete maps, and limits.
/// Source: C CBOR map and primitive codecs. Version: 2026-10-30.
/// Inputs: none. Returns: unit. Errors: assertion panic.
/// Responsible: asn1c maintainers. History: malformed record regression.
/// Example: `cargo test malformed_records`.
#[test]
fn malformed_records() {
    let limits = Limits::default();
    for wire in [
        &[][..],
        &[0xa0][..],
        &[0xa1, 0x64, b'f', b'l', b'a', b'g', 0xf5][..],
        &[0xa2, 0x64, b'f', b'l', b'a', b'g', 0xf5, 0x64, b'f', b'l', b'a', b'g', 0xf4][..],
        &[0xa1, 0x64, b'f', b'l', b'a', b'g', 0xf5, 0xff][..],
        &[0xa1, 0x64, b'f', b'l', b'a', b'g', 0x9f][..],
    ] {
        assert!(Packet::decode_cbor(wire, &limits).is_err(), "{wire:?}");
    }
    let mut bad = sample().encode_cbor(&limits).unwrap().bytes;
    bad[21] = 0x06;
    assert!(Packet::decode_cbor(&bad, &limits).is_err());
    let tiny = Limits {
        max_output_bytes: 1,
        ..limits
    };
    assert!(sample().encode_cbor(&tiny).is_err());
    let tiny = Limits {
        max_input_bytes: 2,
        ..limits
    };
    assert!(Packet::decode_cbor(&bad, &tiny).is_err());
}
