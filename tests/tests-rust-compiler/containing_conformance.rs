//! UPER primitive CONTAINING values and malformed contents.
use asn1c_generated::containing::{Bits, BoolBits, BoolOct, Oct, Packet};
use asn1c_runtime::Limits;

/// Compare C-compatible UPER vectors and reject malformed inner encodings.
/// Source: X.691 contents constraints. Version: 2026-10-30. Inputs: none.
/// Returns: nothing; assertion failures panic. Responsible: asn1c maintainers.
/// History: primitive CONTAINING support. Example: run with `cargo test`.
#[test]
fn vectors_and_validation() {
    let limits = Limits::default();
    assert_eq!(Oct(2).encode_uper(&limits).unwrap().bytes, [1, 0x80]);
    assert_eq!(Bits(2).encode_uper(&limits).unwrap().bytes, [2, 0x80]);
    assert_eq!(BoolOct(true).encode_uper(&limits).unwrap().bytes, [1, 0x80]);
    assert_eq!(
        BoolBits(true).encode_uper(&limits).unwrap().bytes,
        [1, 0x80]
    );
    assert_eq!(Oct::decode_uper(&[1, 0x80], &limits).unwrap().value, Oct(2));
    assert_eq!(
        Bits::decode_uper(&[2, 0x80], &limits).unwrap().value,
        Bits(2)
    );
    assert_eq!(
        Oct::decode_uper(&[0x80, 1, 0x80], &limits).unwrap().value,
        Oct(2)
    );

    assert_eq!(
        BoolOct::decode_uper(&[1, 0x80], &limits).unwrap().value,
        BoolOct(true)
    );
    assert_eq!(
        BoolBits::decode_uper(&[1, 0x80], &limits).unwrap().value,
        BoolBits(true)
    );
    for input in [
        &[][..],
        &[1][..],
        &[0][..],
        &[2, 0x80][..],
        &[1, 0xc0][..],
        &[1, 0x81][..],
    ] {
        assert!(Oct::decode_uper(input, &limits).is_err());
    }
    for input in [&[][..], &[2][..], &[1, 0x80][..], &[2, 0xc0][..]] {
        assert!(Bits::decode_uper(input, &limits).is_err());
    }
    assert!(Oct(3).encode_uper(&limits).is_err());
    let small = Limits {
        max_work_bits: 8,
        ..limits
    };
    assert!(Oct(2).encode_uper(&small).is_err());
    assert!(Oct::decode_uper(&[1, 0x80], &small).is_err());
    let small_output = Limits {
        max_output_bytes: 1,
        ..limits
    };
    assert!(Oct(2).encode_uper(&small_output).is_err());
    let small_input = Limits {
        max_input_bytes: 1,
        ..limits
    };
    assert!(Oct::decode_uper(&[1, 0x80], &small_input).is_err());
    for byte in 0_u8..=255 {
        let decoded = Oct::decode_uper(&[1, byte], &limits);
        assert_eq!(decoded.is_ok(), byte == 0 || byte == 0x40 || byte == 0x80);
    }
}

/// Exercise OPTIONAL and required CONTAINING fields at unaligned offsets.
/// Source: X.691 composed UPER. Version: 2026-10-30. Inputs: none.
/// Returns: nothing; assertion failures panic. Responsible: asn1c maintainers.
/// History: composable contents support. Example: run with `cargo test`.
#[test]
fn sequence_fields() {
    let limits = Limits::default();
    let packet = Packet {
        x: true,
        i: Some(2),
        b: true,
    };
    let encoded = packet.encode_uper(&limits).unwrap();
    assert_eq!(encoded.bytes, [0xc0, 0x60, 0x00, 0x60]);
    assert_eq!(encoded.bit_len, 27);
    assert_eq!(
        Packet::decode_uper(&encoded.bytes, &limits).unwrap().value,
        packet
    );
    let absent = Packet {
        x: false,
        i: None,
        b: false,
    };
    let encoded = absent.encode_uper(&limits).unwrap();
    assert_eq!(
        Packet::decode_uper(&encoded.bytes, &limits).unwrap().value,
        absent
    );
    assert!(Packet::decode_uper(&[0xc0, 0x70], &limits).is_err());
}
