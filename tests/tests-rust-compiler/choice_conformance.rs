//! BER/DER/CER conformance for direct primitive CHOICE alternatives.

use asn1c_generated::primitive_choice::Value;
use asn1c_runtime::Limits;

/// Compare DER/CER output and both decoder modes against C-verified TLVs.
/// Source: generated C primitive CHOICE descriptor. Version/date: 2026-11-01.
/// Inputs: none. Returns: unit. Errors: assertion failures identify mismatches.
/// Responsible party: asn1c maintainers. History: initial direct CHOICE slice.
/// Example: `cargo test canonical_vectors`.
#[test]
fn canonical_vectors() {
    let limits = Limits::default();
    let cases = [
        (Value::Flag(true), vec![0x01, 0x01, 0xff]),
        (Value::Flag(false), vec![0x01, 0x01, 0x00]),
        (Value::Empty, vec![0x05, 0x00]),
        (Value::Count(-2), vec![0x02, 0x01, 0xfe]),
        (Value::Count(5), vec![0x02, 0x01, 0x05]),
    ];
    for (value, wire) in cases {
        assert_eq!(value.encode_der(&limits).unwrap().bytes, wire);
        assert_eq!(value.encode_cer(&limits).unwrap().bytes, wire);
        let ber = Value::decode_ber(&wire, &limits).unwrap();
        let cer = Value::decode_cer(&wire, &limits).unwrap();
        assert_eq!(ber.value, value);
        assert_eq!(cer.value, value);
        assert_eq!(ber.consumed_bytes, wire.len());
        assert_eq!(cer.consumed_bits, wire.len() * 8);
    }
    let suffixed = [0x01, 0x01, 0xff, 0xaa];
    let decoded = Value::decode_ber(&suffixed, &limits).unwrap();
    assert_eq!(decoded.value, Value::Flag(true));
    assert_eq!(decoded.consumed_bytes, 3);
    assert_eq!(decoded.consumed_bits, 24);
}

/// Accept BER identifier/content aliases and ensure strict CER rejects them.
/// Source: X.690 primitive dispatch and generated C BER behavior.
/// Version/date: 2026-11-01. Inputs: none. Returns: unit.
/// Errors: assertion failures indicate incorrect alias handling.
/// Responsible party: asn1c maintainers. History: CHOICE canonicality tests.
/// Example: `cargo test ber_aliases_and_cer_rejections`.
#[test]
fn ber_aliases_and_cer_rejections() {
    let limits = Limits::default();
    let cases = [
        (&[0x1f, 0x01, 0x01, 0xff][..], Value::Flag(true)),
        (&[0x1f, 0x05, 0x00][..], Value::Empty),
        (&[0x1f, 0x02, 0x01, 0x05][..], Value::Count(5)),
        (&[0x01, 0x81, 0x01, 0xff][..], Value::Flag(true)),
        (&[0x05, 0x81, 0x00][..], Value::Empty),
        (&[0x02, 0x02, 0x00, 0x05][..], Value::Count(5)),
        (&[0x01, 0x00][..], Value::Flag(false)),
        (&[0x01, 0x02, 0x00, 0xff][..], Value::Flag(true)),
    ];
    for (wire, expected) in cases {
        let decoded = Value::decode_ber(wire, &limits).unwrap();
        assert_eq!(decoded.value, expected, "{wire:02x?}");
        assert_eq!(decoded.consumed_bytes, wire.len());
        assert!(Value::decode_cer(wire, &limits).is_err(), "{wire:02x?}");
    }
    for wire in [
        &[0x01, 0x01, 0xff][..],
        &[0x05, 0x00][..],
        &[0x02, 0x01, 0x05][..],
    ] {
        assert!(Value::decode_cer(wire, &limits).is_ok());
    }
}

/// Reject unknown, malformed, out-of-range, and over-limit inputs.
/// Source: primitive CHOICE runtime contract. Version/date: 2026-11-01.
/// Inputs: none. Returns: unit. Errors: assertion failures identify acceptance.
/// Responsible party: asn1c maintainers. History: malformed CHOICE coverage.
/// Example: `cargo test malformed_and_limits`.
#[test]
fn malformed_and_limits() {
    let limits = Limits::default();
    for wire in [
        &[][..],
        &[0x03, 0x00][..],
        &[0x81, 0x01, 0xff][..],
        &[0x21, 0x01, 0xff][..],
        &[0x05, 0x01, 0x00][..],
        &[0x02, 0x01, 0x06][..],
        &[0x02, 0x02, 0x00][..],
        &[0x01, 0x80][..],
    ] {
        assert!(Value::decode_ber(wire, &limits).is_err(), "{wire:02x?}");
        assert!(Value::decode_cer(wire, &limits).is_err(), "{wire:02x?}");
    }
    assert!(Value::Count(6).encode_der(&limits).is_err());
    assert!(Value::Count(6).encode_cer(&limits).is_err());
    let tiny_input = Limits {
        max_input_bytes: 2,
        ..limits
    };
    assert!(Value::decode_ber(&[0x01, 0x01, 0xff], &tiny_input).is_err());
    let tiny_output = Limits {
        max_output_bytes: 2,
        ..limits
    };
    assert!(Value::Flag(true).encode_der(&tiny_output).is_err());
    let exact = Limits {
        max_output_bytes: 3,
        max_work_bits: 32,
        ..limits
    };
    assert!(Value::Flag(true).encode_der(&exact).is_ok());
    assert!(Value::decode_ber(&[0x01, 0x01, 0xff], &exact).is_ok());
    let no_work = Limits {
        max_work_bits: 0,
        ..limits
    };
    assert!(Value::decode_ber(&[0x05, 0x00], &no_work).is_err());
}

/// Exercise every truncation and representative one-octet mutations safely.
/// Source: primitive CHOICE malformed-input policy. Version/date: 2026-11-01.
/// Inputs: none. Returns: unit. Errors: assertion failures indicate bad prefix
/// accounting or mutation handling. Responsible party: asn1c maintainers.
/// History: direct CHOICE hardening. Example: `cargo test mutations_and_truncations`.
#[test]
fn mutations_and_truncations() {
    let limits = Limits::default();
    for wire in [
        &[0x01, 0x01, 0xff][..],
        &[0x05, 0x00][..],
        &[0x02, 0x01, 0x05][..],
    ] {
        for end in 0..wire.len() {
            assert!(Value::decode_ber(&wire[..end], &limits).is_err());
            assert!(Value::decode_cer(&wire[..end], &limits).is_err());
        }
        for index in 0..wire.len() {
            for replacement in [0x00, 0x01, 0xff] {
                let mut changed = wire.to_vec();
                changed[index] = replacement;
                for value in [
                    Value::decode_ber(&changed, &limits),
                    Value::decode_cer(&changed, &limits),
                ]
                .into_iter()
                .flatten()
                {
                    assert!(value.consumed_bytes <= changed.len());
                    assert_eq!(value.consumed_bits, value.consumed_bytes * 8);
                    assert!(value.value.encode_der(&limits).is_ok());
                }
            }
        }
    }
}
