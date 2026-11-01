use asn1c_generated::bool_defaults_only::Flags;
use asn1c_runtime::{Error, Limits, Resource};

/// Check all packed patterns against fixed UPER presence and payload vectors.
///
/// Inputs: sixteen four-BOOLEAN values with TRUE/FALSE defaults at fields one
/// and three. Returns: no value; exact byte, bit length, and decoded fields are
/// asserted. Errors: codec errors fail the test; vectors are valid.
/// Source: `BoolDefaultsOnly` schema and X.691 presence/payload order.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: default-only packed decoder regression. Example: absent defaults
/// omit their payload while required fields remain in schema order.
#[test]
fn all_patterns_match_presence_and_payload_golden_vectors() {
    let vectors: [([bool; 4], u8, usize); 16] = [
        ([false, false, false, false], 0x80, 5),
        ([false, false, false, true], 0x88, 5),
        ([false, false, true, false], 0xC8, 6),
        ([false, false, true, true], 0xCC, 6),
        ([false, true, false, false], 0x90, 5),
        ([false, true, false, true], 0x98, 5),
        ([false, true, true, false], 0xD8, 6),
        ([false, true, true, true], 0xDC, 6),
        ([true, false, false, false], 0x00, 4),
        ([true, false, false, true], 0x10, 4),
        ([true, false, true, false], 0x50, 5),
        ([true, false, true, true], 0x58, 5),
        ([true, true, false, false], 0x20, 4),
        ([true, true, false, true], 0x30, 4),
        ([true, true, true, false], 0x70, 5),
        ([true, true, true, true], 0x78, 5),
    ];
    let limits = Limits::default();
    for (fields, expected_byte, expected_bits) in vectors {
        let value = Flags::new(fields, ());
        let encoded = value.encode_uper(&limits).unwrap();
        assert_eq!(encoded.bytes, [expected_byte]);
        assert_eq!(encoded.bit_len, expected_bits);

        let present_defaults = usize::from(!fields[0]) + usize::from(fields[2]);
        let work = 9 * (4 + present_defaults);
        let exact_work = Limits {
            max_work_bits: work,
            ..limits
        };
        let decoded = Flags::decode_uper(&encoded.bytes, &limits).unwrap();
        assert_eq!(decoded.consumed_bits, expected_bits);
        assert_eq!(decoded.value, value);
        assert_eq!(
            Flags::decode_uper(&encoded.bytes, &exact_work).unwrap().value,
            value
        );

        let short_work = Limits {
            max_work_bits: work - 1,
            ..limits
        };
        assert!(matches!(
            Flags::decode_uper(&encoded.bytes, &short_work),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                ..
            })
        ));
    }
}

/// Check every truncated prefix and the input-byte ceiling.
///
/// Inputs: a valid fixed-vector encoding and an empty byte prefix.
/// Returns: no value; assertions inspect typed decode errors.
/// Errors: truncation yields `NeedMoreBits`; zero input budget yields a limit error.
/// Source: complete-value UPER decoder contract. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: DEFAULT input hardening.
/// Example: the two-bit presence map cannot be read from an empty prefix.
#[test]
fn truncated_prefix_and_input_limit_fail_closed() {
    let limits = Limits::default();
    let value = Flags::new([true, false, false, true], ());
    let encoded = value.encode_uper(&limits).unwrap();
    for prefix_length in 0..encoded.bytes.len() {
        assert!(matches!(
            Flags::decode_uper(&encoded.bytes[..prefix_length], &limits),
            Err(Error::NeedMoreBits { .. })
        ));
    }
    let no_input = Limits {
        max_input_bytes: 0,
        ..limits
    };
    assert!(matches!(
        Flags::decode_uper(&encoded.bytes, &no_input),
        Err(Error::LimitExceeded {
            resource: Resource::InputBytes,
            ..
        })
    ));
}
