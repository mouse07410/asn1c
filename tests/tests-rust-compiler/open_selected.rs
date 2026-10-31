//! Selector-driven primitive OPEN TYPE UPER conformance and malformed inputs.
use asn1c_generated::open_module::{Packet, PacketValue};
use asn1c_runtime::Limits;

/// Compare selected BOOLEAN and INTEGER vectors and their decoded values.
/// Source: X.691 OPEN TYPE framing. Version: 2026-10-30. Inputs: none.
/// Returns: nothing; panics on assertion failure. Responsible: asn1c maintainers.
/// History: initial selected primitive slice. Example: run with `cargo test`.
#[test]
fn selected_vectors() {
    let limits = Limits::default();
    for (packet, wire) in [
        (
            Packet {
                id: 1,
                value: PacketValue::Row1(true),
            },
            [1, 1, 0x80],
        ),
        (
            Packet {
                id: 2,
                value: PacketValue::Row2(2),
            },
            [2, 1, 0x80],
        ),
        (
            Packet {
                id: 1,
                value: PacketValue::Row1(false),
            },
            [1, 1, 0],
        ),
        (
            Packet {
                id: 3,
                value: PacketValue::Row3(5),
            },
            [3, 1, 0],
        ),
    ] {
        let encoded = packet.encode_uper(&limits).unwrap();
        assert_eq!(encoded.bytes, wire);
        assert_eq!(encoded.bit_len, 24);
        assert_eq!(Packet::decode_uper(&wire, &limits).unwrap().value, packet);
    }
    assert_eq!(
        Packet::decode_uper(&[2, 0x80, 1, 0x80], &limits)
            .unwrap()
            .value,
        Packet {
            id: 2,
            value: PacketValue::Row2(2)
        }
    );
}

/// Reject inconsistent selectors, truncation, spare values and padding.
/// Source: X.691 OPEN TYPE envelope. Version: 2026-10-30. Inputs: none.
/// Returns: nothing; panics on assertion failure. Responsible: asn1c maintainers.
/// History: selected primitive hardening. Example: run with `cargo test`.
#[test]
fn malformed_values() {
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
        &[1, 1, 0x81][..],
    ] {
        assert!(Packet::decode_uper(input, &limits).is_err());
    }
    assert!(Packet {
        id: 1,
        value: PacketValue::Row2(2)
    }
    .encode_uper(&limits)
    .is_err());
    assert!(Packet {
        id: 2,
        value: PacketValue::Row2(3)
    }
    .encode_uper(&limits)
    .is_err());
    assert!(Packet {
        id: 3,
        value: PacketValue::Row3(6)
    }
    .encode_uper(&limits)
    .is_err());
    assert!(Packet::decode_uper(&[3, 1, 1], &limits).is_err());
    assert_eq!(
        Packet::decode_uper(&[3, 0x80, 1, 0], &limits)
            .unwrap()
            .value,
        Packet {
            id: 3,
            value: PacketValue::Row3(5)
        }
    );
    for byte in 0_u8..=255 {
        assert_eq!(
            Packet::decode_uper(&[2, 1, byte], &limits).is_ok(),
            byte == 0 || byte == 0x40 || byte == 0x80
        );
    }
    let small = Limits {
        max_work_bits: 16,
        ..limits
    };
    assert!(Packet::decode_uper(&[1, 1, 0x80], &small).is_err());
    assert!(Packet {
        id: 1,
        value: PacketValue::Row1(true)
    }
    .encode_uper(&small)
    .is_err());
}
