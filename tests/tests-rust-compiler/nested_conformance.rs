//! UPER interoperability checks for inline nested SEQUENCE records.

use asn1c_generated::sequence_nested::{NestedPacket, NestedPacketFixed, NestedPacketMaybe};
use asn1c_runtime::{Error, Limits, Resource};

/// Check one shared cursor across required and optional nested records.
///
/// Parameters: none. Returns: no value; assertions fail on mismatch.
/// Errors: malformed input returns a typed error; test failures panic.
/// Original source: X.691 nested SEQUENCE ordering and independent bit vector.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
/// History: first inline nested-record parity test. Example: nested default 3.
#[test]
fn nested_records_share_cursor_and_presence_order() {
    let limits = Limits::default();
    let value = NestedPacket {
        prefix: true,
        fixed: NestedPacketFixed {
            flag: false,
            count: 3,
            suffix: true,
        },
        maybe: Some(NestedPacketMaybe {
            number: 2,
            enabled: Some(true),
        }),
        tail: false,
    };
    let encoded = value.encode_uper(&limits).expect("encode nested packet");
    assert_eq!(encoded.bytes, [0xef, 0xa0]);
    assert_eq!(encoded.bit_len, 12);
    let decoded = NestedPacket::decode_uper(&encoded.bytes, &limits).expect("decode nested packet");
    assert_eq!(decoded.value, value);
    assert_eq!(decoded.consumed_bits, 12);
    assert_eq!(decoded.consumed_bytes, 2);
}

/// Check nested DEFAULT omission and an absent OPTIONAL constructed field.
///
/// Parameters: none. Returns: no value; assertions fail on mismatch.
/// Errors: malformed input returns a typed error; test failures panic.
/// Original source: X.691 DEFAULT omission and UPER presence bitmap rules.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
/// History: nested absent-default coverage. Example: default count 1.
#[test]
fn nested_default_and_optional_absence_round_trip() {
    let value = NestedPacket {
        prefix: false,
        fixed: NestedPacketFixed {
            flag: true,
            count: 1,
            suffix: false,
        },
        maybe: None,
        tail: true,
    };
    let encoded = value
        .encode_uper(&Limits::default())
        .expect("encode defaults");
    assert_eq!(encoded.bytes, [0x14]);
    assert_eq!(encoded.bit_len, 6);
    assert_eq!(
        NestedPacket::decode_uper(&encoded.bytes, &Limits::default())
            .expect("decode defaults")
            .value,
        value
    );
}

/// Reject an unused INTEGER index, truncation, and cumulative work overruns.
///
/// Parameters: none. Returns: no value; assertions fail on mismatch.
/// Errors: each hostile input must return the corresponding typed error.
/// Original source: UPER cursor malformed-input and operation budget contract.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
/// History: nested hostile-input checks. Example: encode spare index 3.
#[test]
fn nested_malformed_inputs_and_limits_fail_closed() {
    let value = NestedPacket {
        prefix: true,
        fixed: NestedPacketFixed {
            flag: false,
            count: 3,
            suffix: true,
        },
        maybe: Some(NestedPacketMaybe {
            number: 2,
            enabled: Some(true),
        }),
        tail: false,
    };
    let exact = Limits {
        max_work_bits: 92,
        ..Limits::default()
    };
    value.encode_uper(&exact).expect("exact nested work budget");
    NestedPacket::decode_uper(&[0xef, 0xa0], &exact).expect("exact decode budget");
    let too_small = Limits {
        max_work_bits: 91,
        ..exact
    };
    assert!(matches!(
        value.encode_uper(&too_small),
        Err(Error::LimitExceeded {
            resource: Resource::WorkBits,
            ..
        })
    ));
    assert!(matches!(
        NestedPacket::decode_uper(&[0xef, 0xa0], &too_small),
        Err(Error::LimitExceeded {
            resource: Resource::WorkBits,
            ..
        })
    ));
    assert!(matches!(
        NestedPacket::decode_uper(&[0xef], &Limits::default()),
        Err(Error::NeedMoreBits { .. })
    ));
    assert!(matches!(
        NestedPacket::decode_uper(&[0xef, 0xe0], &Limits::default()),
        Err(Error::InvalidEncoding { .. })
    ));
}
