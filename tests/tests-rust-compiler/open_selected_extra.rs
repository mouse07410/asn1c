//! APER/OER selected OPEN TYPE interoperability and malformed values.
use asn1c_generated::open_module::{Packet, PacketValue};
use asn1c_runtime::Limits;

/// Compare the selected primitive rows with generated C wire vectors.
/// Source: C OPEN TYPE APER/OER codecs. Version: 2026-10-30. Inputs: none.
/// Returns: nothing; panics on failure. Responsible: asn1c maintainers.
/// History: selected primitive codecs. Example: run with `cargo test`.
#[test]
fn vectors() {
    let limits = Limits::default();
    for (packet, aper, oer) in [
        (
            Packet {
                id: 1,
                value: PacketValue::Row1(true),
            },
            [1, 1, 0x80],
            [1, 1, 0xff],
        ),
        (
            Packet {
                id: 2,
                value: PacketValue::Row2(2),
            },
            [2, 1, 0x80],
            [2, 1, 2],
        ),
        (
            Packet {
                id: 3,
                value: PacketValue::Row3(5),
            },
            [3, 1, 0],
            [3, 1, 5],
        ),
    ] {
        assert_eq!(packet.encode_aper(&limits).unwrap().bytes, aper);
        assert_eq!(Packet::decode_aper(&aper, &limits).unwrap().value, packet);
        assert_eq!(packet.encode_oer(&limits).unwrap().bytes, oer);
        assert_eq!(Packet::decode_oer(&oer, &limits).unwrap().value, packet);
    }
}

/// Reject unknown selectors, bad envelopes, mismatched variants and limits.
/// Source: codec validation. Version: 2026-10-30. Inputs: none; returns nothing.
/// Panics on failure. Responsible: asn1c maintainers. History: malformed inputs.
/// Example: run with `cargo test`.
#[test]
fn invalid() {
    let limits = Limits::default();
    for input in [
        &[][..],
        &[1][..],
        &[1, 1][..],
        &[4, 1, 0][..],
        &[2, 0][..],
        &[2, 2, 0, 0][..],
        &[2, 1, 0xc0][..],
        &[2, 1, 0x81][..],
    ] {
        assert!(Packet::decode_aper(input, &limits).is_err());
    }
    for input in [
        &[][..],
        &[1][..],
        &[1, 1][..],
        &[4, 1, 0][..],
        &[2, 0][..],
        &[2, 2, 0, 0][..],
        &[2, 1, 3][..],
        &[3, 1, 6][..],
    ] {
        assert!(Packet::decode_oer(input, &limits).is_err());
    }
    let wrong = Packet {
        id: 1,
        value: PacketValue::Row2(2),
    };
    assert!(wrong.encode_aper(&limits).is_err());
    assert!(wrong.encode_oer(&limits).is_err());
    let small = Limits {
        max_work_bits: 24,
        ..limits
    };
    let valid = Packet {
        id: 1,
        value: PacketValue::Row1(true),
    };
    assert!(valid.encode_aper(&small).is_err());
    assert!(valid.encode_oer(&small).is_err());
    assert!(Packet::decode_aper(&[1, 1, 0x80], &small).is_err());
    assert!(Packet::decode_oer(&[1, 1, 0xff], &small).is_err());
}
