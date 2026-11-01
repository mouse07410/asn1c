use asn1c_generated::wide_mixed::Flags;
use asn1c_runtime::{Error, Limits, Resource};

/// Build an independent schema-order UPER oracle for sixty packed values.
///
/// Inputs: packed values are in declaration order excluding four OPTIONAL
/// fields; options are ordered by declaration. Returns bytes and meaningful
/// bits. Errors: none. Source: `WideMixed` schema markers and X.691 ordering.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: mixed DEFAULT/OPTIONAL wide-record regression. Example: all
/// DEFAULT TRUE values and absent options omit their payloads.
fn expected_wire(
    packed: [bool; 60],
    options: [Option<bool>; 4],
) -> (Vec<u8>, usize) {
    let mut presence = Vec::new();
    let mut payload = Vec::new();
    let mut packed_index = 0;
    for field in 0..64 {
        if field % 16 == 2 {
            let option = options[field / 16];
            presence.push(option.is_some());
            if let Some(value) = option {
                payload.push(value);
            }
        } else {
            let value = packed[packed_index];
            packed_index += 1;
            if field % 2 == 0 {
                presence.push(!value);
                if !value {
                    payload.push(value);
                }
            } else {
                payload.push(value);
            }
        }
    }
    let bit_len = presence.len() + payload.len();
    let mut bytes = vec![0_u8; bit_len.div_ceil(8)];
    for (index, bit) in presence.into_iter().chain(payload).enumerate() {
        if bit {
            bytes[index / 8] |= 0x80 >> (index % 8);
        }
    }
    (bytes, bit_len)
}

/// Check all-absent markers and a mixed OPTIONAL/DEFAULT payload.
///
/// Inputs: constructor values cover all sixty packed and four OPTIONAL fields.
/// Returns: no value; canonical bytes, bit lengths, round trips, truncation,
/// and exact work limits are asserted. Errors: codec errors fail the test.
/// Source: `WideMixed` schema plus independent X.691 presence/payload oracle.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: compact wide marker regression. Example: defaults and options may
/// all be absent while required values remain in schema order.
#[test]
fn wide_markers_match_schema_order_oracle_and_limits() {
    let limits = Limits::default();
    let cases = [
        ([true; 60], [None; 4]),
        (
            std::array::from_fn(|index| index % 3 == 0),
            [Some(false), None, Some(true), Some(false)],
        ),
    ];
    for (packed, options) in cases {
        let value = Flags::new(packed, options.into());
        let (expected_bytes, expected_bits) = expected_wire(packed, options);
        let encoded = value.encode_uper(&limits).unwrap();
        assert_eq!(encoded.bytes, expected_bytes);
        assert_eq!(encoded.bit_len, expected_bits);
        let exact_work = Limits {
            max_work_bits: expected_bits * 9,
            ..limits
        };
        let decoded = Flags::decode_uper(&encoded.bytes, &exact_work).unwrap();
        assert_eq!(decoded.consumed_bits, expected_bits);
        assert_eq!(decoded.value, value);
        let short_work = Limits {
            max_work_bits: expected_bits * 9 - 1,
            ..limits
        };
        assert!(matches!(
            Flags::decode_uper(&encoded.bytes, &short_work),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                ..
            })
        ));
        for prefix_length in 0..encoded.bytes.len() {
            assert!(matches!(
                Flags::decode_uper(&encoded.bytes[..prefix_length], &limits),
                Err(Error::NeedMoreBits { .. })
            ));
        }
    }
}
