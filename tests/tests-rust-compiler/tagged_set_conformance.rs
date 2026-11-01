//! Generated BER/DER/CER tests for SETs with resolved direct IMPLICIT tags.

use asn1c_generated::tagged_set::{AutomaticSet, EmptyTaggedSet, TaggedSetRecord};
use asn1c_runtime::{Error, Limits};

/// Check canonical effective-tag sorting across universal and context classes.
///
/// Parameters: none. Returns: no value; exact bytes and semantic fields are asserted.
/// Errors: malformed, noncanonical, or over-limit data returns typed errors.
/// Original source: X.690 SET tag ordering and resolved ASN.1 member tags.
/// Version/date: 2026-11-01. Author: asn1c maintainers. History: tagged SET slice.
/// Example: emitted universal tag 1 precedes context tags 2, 31, 127, and 128.
#[test]
fn tagged_set_writes_in_effective_class_and_number_order() {
    let value = TaggedSetRecord {
        largest: None,
        high: Some(true),
        marker: (),
        count: 3,
        flag: false,
        second: Some(false),
    };
    let der = [
        0x31, 0x12, 0x01, 0x01, 0x00, 0x82, 0x01, 0x03, 0x9f, 0x1f, 0x00, 0x9f, 0x7f, 0x01, 0x00,
        0x9f, 0x81, 0x00, 0x01, 0xff,
    ];
    let cer = [
        0x31, 0x80, 0x01, 0x01, 0x00, 0x82, 0x01, 0x03, 0x9f, 0x1f, 0x00, 0x9f, 0x7f, 0x01, 0x00,
        0x9f, 0x81, 0x00, 0x01, 0xff, 0x00, 0x00,
    ];
    let limits = Limits::default();

    assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(
        TaggedSetRecord::decode_ber(&der, &limits).unwrap().value,
        value
    );
    assert_eq!(
        TaggedSetRecord::decode_cer(&cer, &limits).unwrap().value,
        value
    );
}

/// Verify arbitrary BER SET order and strict canonical CER order checking.
///
/// Parameters: none. Returns: no value; decoded value and rejection are asserted.
/// Errors: noncanonical CER field order returns an encoding error.
/// Original source: X.690 unordered BER SET and CER canonical encoding.
/// Version/date: 2026-11-01. Author: asn1c maintainers. History: tagged SET.
/// Example: reversing the context-specific children is accepted only by BER.
#[test]
fn reordered_tagged_set_is_ber_valid_but_not_cer_canonical() {
    let value = TaggedSetRecord {
        largest: None,
        high: Some(true),
        marker: (),
        count: 3,
        flag: false,
        second: Some(false),
    };
    let ber = [
        0x31, 0x12, 0x9f, 0x81, 0x00, 0x01, 0xff, 0x9f, 0x7f, 0x01, 0x00, 0x9f, 0x1f, 0x00, 0x82,
        0x01, 0x03, 0x01, 0x01, 0x00,
    ];
    let cer = [
        0x31, 0x80, 0x9f, 0x81, 0x00, 0x01, 0xff, 0x9f, 0x7f, 0x01, 0x00, 0x9f, 0x1f, 0x00, 0x82,
        0x01, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00,
    ];
    let limits = Limits::default();

    assert_eq!(
        TaggedSetRecord::decode_ber(&ber, &limits).unwrap().value,
        value
    );
    assert!(matches!(
        TaggedSetRecord::decode_cer(&cer, &limits),
        Err(Error::InvalidEncoding { .. })
    ));
}

/// Check DEFAULT omission, empty framing, and AUTOMATIC TAGS resolution.
///
/// Parameters: none. Returns: no value; exact bytes and values are asserted.
/// Errors: unsupported runtime behavior fails this generated-code test.
/// Original source: ASN.1 DEFAULT and AUTOMATIC TAGS resolution.
/// Version/date: 2026-11-01. Author: asn1c maintainers. History: tagged SET.
/// Example: the empty CER SET uses indefinite framing and an EOC marker.
#[test]
fn defaults_empty_sets_and_automatic_tags_roundtrip() {
    let limits = Limits::default();
    let defaults = TaggedSetRecord {
        largest: None,
        high: None,
        marker: (),
        count: 1,
        flag: true,
        second: None,
    };
    assert_eq!(
        defaults.encode_der(&limits).unwrap().bytes,
        [0x31, 0x03, 0x9f, 0x1f, 0x00]
    );
    assert_eq!(
        defaults.encode_cer(&limits).unwrap().bytes,
        [0x31, 0x80, 0x9f, 0x1f, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        TaggedSetRecord::decode_ber(&[0x31, 0x03, 0x9f, 0x1f, 0x00], &limits)
            .unwrap()
            .value,
        defaults
    );
    let empty = EmptyTaggedSet {};
    assert_eq!(empty.encode_der(&limits).unwrap().bytes, [0x31, 0x00]);
    assert_eq!(
        empty.encode_cer(&limits).unwrap().bytes,
        [0x31, 0x80, 0x00, 0x00]
    );

    let automatic = AutomaticSet {
        flag: true,
        count: -1,
        empty: Some(()),
    };
    let encoded = automatic.encode_der(&limits).unwrap();
    assert_eq!(
        encoded.bytes,
        [0x31, 0x08, 0x80, 0x01, 0xff, 0x81, 0x01, 0xff, 0x82, 0x00]
    );
    assert_eq!(
        AutomaticSet::decode_ber(&encoded.bytes, &limits)
            .unwrap()
            .value,
        automatic
    );
}

/// Reject truncated tag forms, unknown tags, duplicate tags, and tag limits.
///
/// Parameters: none. Returns: no value; malformed inputs must fail closed.
/// Errors: decoders return typed errors for all invalid or incomplete records.
/// Original source: X.680 tags and bounded BER record parsing.
/// Version/date: 2026-11-01. Author: asn1c maintainers. History: hostile SET tests.
/// Example: two encodings of a known tag are rejected as duplicate SET fields.
#[test]
fn malformed_tagged_sets_fail_closed() {
    let limits = Limits::default();
    let duplicate = [0x31, 0x06, 0x9f, 0x1f, 0x00, 0x9f, 0x1f, 0x00];
    let unknown = [0x31, 0x03, 0x9f, 0x1e, 0x00];
    let invalid_integer = [0x31, 0x06, 0x9f, 0x1f, 0x00, 0x82, 0x01, 0x04];
    let constructed_boolean = [0x31, 0x08, 0x9f, 0x1f, 0x00, 0xbf, 0x81, 0x00, 0x01, 0xff];
    for wire in [
        duplicate.as_slice(),
        unknown.as_slice(),
        invalid_integer.as_slice(),
        constructed_boolean.as_slice(),
    ] {
        assert!(TaggedSetRecord::decode_ber(wire, &limits).is_err());
    }
    assert!(TaggedSetRecord::decode_ber(&[0x31, 0x80, 0x9f], &limits).is_err());
    assert!(
        TaggedSetRecord::decode_cer(&[0x31, 0x80, 0x9f, 0x80, 0x1f, 0x00, 0, 0], &limits).is_err()
    );
}
