use asn1c_generated::bool64::Flags;
use asn1c_runtime::{Error, Limits, Resource};

/// Check every packed BOOLEAN position against its UPER wire bit and accessors.
///
/// Inputs: no external inputs; the test constructs fixed 64-field records.
/// Returns: no value; assertions inspect every one-hot, zero, and all-one value.
/// Errors: codec errors fail the test; no malformed input is expected here.
/// Source: Bool64 ASN.1 fixture and UPER schema-order rules. Version/date:
/// 2026-11-01. Responsible party: asn1c maintainers. History: bitset gate test.
/// Example: field 8 must encode as the top bit of octet two.
#[test]
fn walking_one_and_extreme_encodings_preserve_all_positions() {
    let getters: [fn(&Flags) -> bool; 64] = [
        Flags::get_bit0,
        Flags::get_bit1,
        Flags::get_bit2,
        Flags::get_bit3,
        Flags::get_bit4,
        Flags::get_bit5,
        Flags::get_bit6,
        Flags::get_bit7,
        Flags::get_bit8,
        Flags::get_bit9,
        Flags::get_bit10,
        Flags::get_bit11,
        Flags::get_bit12,
        Flags::get_bit13,
        Flags::get_bit14,
        Flags::get_bit15,
        Flags::get_bit16,
        Flags::get_bit17,
        Flags::get_bit18,
        Flags::get_bit19,
        Flags::get_bit20,
        Flags::get_bit21,
        Flags::get_bit22,
        Flags::get_bit23,
        Flags::get_bit24,
        Flags::get_bit25,
        Flags::get_bit26,
        Flags::get_bit27,
        Flags::get_bit28,
        Flags::get_bit29,
        Flags::get_bit30,
        Flags::get_bit31,
        Flags::get_bit32,
        Flags::get_bit33,
        Flags::get_bit34,
        Flags::get_bit35,
        Flags::get_bit36,
        Flags::get_bit37,
        Flags::get_bit38,
        Flags::get_bit39,
        Flags::get_bit40,
        Flags::get_bit41,
        Flags::get_bit42,
        Flags::get_bit43,
        Flags::get_bit44,
        Flags::get_bit45,
        Flags::get_bit46,
        Flags::get_bit47,
        Flags::get_bit48,
        Flags::get_bit49,
        Flags::get_bit50,
        Flags::get_bit51,
        Flags::get_bit52,
        Flags::get_bit53,
        Flags::get_bit54,
        Flags::get_bit55,
        Flags::get_bit56,
        Flags::get_bit57,
        Flags::get_bit58,
        Flags::get_bit59,
        Flags::get_bit60,
        Flags::get_bit61,
        Flags::get_bit62,
        Flags::get_bit63,
    ];
    let limits = Limits::default();
    for (index, getter) in getters.iter().enumerate() {
        let mut fields = [false; 64];
        fields[index] = true;
        let value = Flags::new(fields, ());
        assert!(getter(&value));
        let encoded = value.encode_uper(&limits).unwrap();
        let mut expected = [0_u8; 8];
        expected[index / 8] = 0x80_u8 >> (index % 8);
        assert_eq!(encoded.bytes, expected);
        assert_eq!(encoded.bit_len, 64);
        let decoded = Flags::decode_uper(&encoded.bytes, &limits).unwrap();
        assert_eq!(decoded.consumed_bits, 64);
        assert_eq!(decoded.consumed_bytes, 8);
        assert_eq!(decoded.value, value);
    }

    for (fields, expected) in [([false; 64], [0_u8; 8]), ([true; 64], [0xFF_u8; 8])] {
        let value = Flags::new(fields, ());
        let encoded = value.encode_uper(&limits).unwrap();
        assert_eq!(encoded.bytes, expected);
        assert_eq!(encoded.bit_len, 64);
        assert_eq!(
            Flags::decode_uper(&encoded.bytes, &limits).unwrap().value,
            value
        );
    }
}

/// Check setters at boundaries between packed storage octets.
///
/// Inputs: no external inputs; the test selects fields 7, 8, 15, 16, and 63.
/// Returns: no value; assertions inspect getter values and exact UPER bytes.
/// Errors: codec errors fail the test; no malformed input is expected.
/// Source: generated bitset accessors. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: setter boundary coverage.
/// Example: clearing field 8 changes only the second encoded octet.
#[test]
fn setters_preserve_neighbors_across_byte_boundaries() {
    let positions = [7_usize, 8, 15, 16, 63];
    let setters: [fn(&mut Flags, bool); 5] = [
        Flags::set_bit7,
        Flags::set_bit8,
        Flags::set_bit15,
        Flags::set_bit16,
        Flags::set_bit63,
    ];
    let getters: [fn(&Flags) -> bool; 5] = [
        Flags::get_bit7,
        Flags::get_bit8,
        Flags::get_bit15,
        Flags::get_bit16,
        Flags::get_bit63,
    ];
    let limits = Limits::default();
    for ((position, setter), getter) in positions.into_iter().zip(setters).zip(getters) {
        let mut value = Flags::new([true; 64], ());
        setter(&mut value, false);
        assert!(!getter(&value));
        let mut expected = [0xFF_u8; 8];
        expected[position / 8] &= !(0x80_u8 >> (position % 8));
        let encoded = value.encode_uper(&limits).unwrap();
        assert_eq!(encoded.bytes, expected);
        assert_eq!(encoded.bit_len, 64);
        setter(&mut value, true);
        assert!(getter(&value));
        assert_eq!(value.encode_uper(&limits).unwrap().bytes, [0xFF_u8; 8]);
    }
}

/// Check every byte truncation and input, output, and cumulative-work limits.
///
/// Inputs: a valid 64-bit encoding and progressively smaller resource limits.
/// Returns: no value; assertions inspect typed decode and encode failures.
/// Errors: expected failures are `NeedMoreBits` or `LimitExceeded`.
/// Source: generated complete-value UPER methods and runtime limits.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: packed record boundary hardening. Example: a seven-byte prefix fails.
#[test]
fn truncations_and_resource_limits_fail_closed() {
    let limits = Limits::default();
    let value = Flags::new([true; 64], ());
    let encoded = value.encode_uper(&limits).unwrap();
    for prefix_bytes in 0..encoded.bytes.len() {
        let error = Flags::decode_uper(&encoded.bytes[..prefix_bytes], &limits).unwrap_err();
        assert!(matches!(
            error,
            Error::NeedMoreBits { required_bits, available_bits }
                if available_bits == prefix_bytes * 8 && required_bits == available_bits + 1
        ));
    }

    let input_limited = Limits {
        max_input_bytes: 7,
        ..limits
    };
    assert!(matches!(
        Flags::decode_uper(&encoded.bytes, &input_limited),
        Err(Error::LimitExceeded {
            resource: Resource::InputBytes,
            ..
        })
    ));
    let output_limited = Limits {
        max_output_bytes: 7,
        ..limits
    };
    assert!(matches!(
        value.encode_uper(&output_limited),
        Err(Error::LimitExceeded {
            resource: Resource::OutputBytes,
            ..
        })
    ));
    let work_limited = Limits {
        max_work_bits: 575,
        ..limits
    };
    assert!(matches!(
        value.encode_uper(&work_limited),
        Err(Error::LimitExceeded {
            resource: Resource::WorkBits,
            ..
        })
    ));
    assert!(matches!(
        Flags::decode_uper(&encoded.bytes, &work_limited),
        Err(Error::LimitExceeded {
            resource: Resource::WorkBits,
            ..
        })
    ));
    let exact_work = Limits {
        max_work_bits: 576,
        ..limits
    };
    assert_eq!(value.encode_uper(&exact_work).unwrap(), encoded);
    assert_eq!(
        Flags::decode_uper(&encoded.bytes, &exact_work)
            .unwrap()
            .value,
        value
    );
}
