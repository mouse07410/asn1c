//! Generated BER/DER/CER conformance tests for resolved IMPLICIT member tags.

use asn1c_generated::tagged_sequence::{
    AutomaticRecord, TaggedExtendedRecord, TaggedExtendedRecordState, TaggedOptionalRecord,
    TaggedRecord, TaggedStringRecord,
};
use asn1c_runtime::{BitStringValue, Error, Limits, Resource};

/// Check high-tag DER/CER vectors, UPER compatibility, and exact prefix use.
///
/// Parameters: none. Returns: no value; byte vectors and decoded fields are asserted.
/// Errors: malformed encodings and resource failures are returned by generated codecs.
/// Original source: X.680 resolved IMPLICIT tags and X.690 record framing.
/// Version/date: 2026-11-01. Author: asn1c maintainers. History: tagged fields.
/// Example: context tags 31 and 128 encode with high-tag-number identifiers.
#[test]
fn required_high_tags_roundtrip_across_selected_codecs() {
    let value = TaggedRecord {
        flag: true,
        count: 3,
    };
    let limits = Limits::default();
    let der = [
        0x30, 0x09, 0x9f, 0x1f, 0x01, 0xff, 0x9f, 0x81, 0x00, 0x01, 0x03,
    ];
    let cer = [
        0x30, 0x80, 0x9f, 0x1f, 0x01, 0xff, 0x9f, 0x81, 0x00, 0x01, 0x03, 0x00, 0x00,
    ];

    assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(
        TaggedRecord::decode_ber(&der, &limits).unwrap().value,
        value
    );
    assert_eq!(
        TaggedRecord::decode_cer(&cer, &limits).unwrap().value,
        value
    );
    for end in 0..der.len() {
        assert!(TaggedRecord::decode_ber(&der[..end], &limits).is_err());
    }
    let packed = value.encode_uper(&limits).unwrap();
    assert_eq!(
        TaggedRecord::decode_uper(&packed.bytes, &limits)
            .unwrap()
            .value,
        value
    );

    let mut with_suffix = der.to_vec();
    with_suffix.push(0xaa);
    let decoded = TaggedRecord::decode_ber(&with_suffix, &limits).unwrap();
    assert_eq!(decoded.value, value);
    assert_eq!(decoded.consumed_bytes, der.len());
    let mut cer_with_suffix = cer.to_vec();
    cer_with_suffix.push(0xaa);
    let decoded = TaggedRecord::decode_cer(&cer_with_suffix, &limits).unwrap();
    assert_eq!(decoded.value, value);
    assert_eq!(decoded.consumed_bytes, cer.len());
}

/// Exercise tag-number boundaries and the maximum tag representable by C.
///
/// Parameters: none. Returns: no value; all effective tags must roundtrip.
/// Errors: a codec failure for a supported resolved tag fails this test.
/// Original source: X.680 high-tag-number form and the C tag-number cap.
/// Version/date: 2026-11-01. Author: asn1c maintainers. History: high tags.
/// Example: tags 30, 31, 127, 128 and 0x3fffffff are checked together.
#[test]
fn context_tag_boundaries_and_maximum_roundtrip() {
    let value = TaggedOptionalRecord {
        first: Some(false),
        second: Some(false),
        third: Some(false),
        fourth: Some(false),
        largest: Some(false),
    };
    let wire = [
        0x30, 0x18, 0x9e, 0x01, 0x00, 0x9f, 0x1f, 0x01, 0x00, 0x9f, 0x7f, 0x01, 0x00, 0x9f, 0x81,
        0x00, 0x01, 0x00, 0x9f, 0x83, 0xff, 0xff, 0xff, 0x7f, 0x01, 0x00,
    ];
    let limits = Limits::default();

    assert_eq!(value.encode_der(&limits).unwrap().bytes, wire);
    assert_eq!(
        TaggedOptionalRecord::decode_ber(&wire, &limits)
            .unwrap()
            .value,
        value
    );
    assert!(matches!(
        TaggedOptionalRecord::decode_cer(&wire, &limits),
        Err(Error::InvalidEncoding { .. })
    ));
}

/// Check DEFAULT omission and OPTIONAL string/ENUMERATED values under IMPLICIT tags.
///
/// Parameters: none. Returns: no value; exact encodings and semantic values are checked.
/// Errors: invalid BIT STRING padding, enum values, or malformed lengths return errors.
/// Original source: X.690 DEFAULT and string rules with resolved member tags.
/// Version/date: 2026-11-01. Author: asn1c maintainers. History: tagged records.
/// Example: default count 1 is absent while tag 31 BOOLEAN remains required.
#[test]
fn mixed_tagged_fields_preserve_defaults_and_primitive_shapes() {
    let value = TaggedExtendedRecord {
        flag: true,
        repeated: Some(false),
        count: 1,
        bits: Some(BitStringValue::new(vec![0xa0], 3).unwrap()),
        octets: Some(b"AB".to_vec()),
        state: Some(TaggedExtendedRecordState::Active),
    };
    let der = [
        0x30, 0x12, 0x9f, 0x1f, 0x01, 0xff, 0x9e, 0x01, 0x00, 0x83, 0x02, 0x05, 0xa0, 0x84, 0x02,
        0x41, 0x42, 0x8a, 0x01, 0x03,
    ];
    let limits = Limits::default();

    assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(
        TaggedExtendedRecord::decode_ber(&der, &limits)
            .unwrap()
            .value,
        value
    );
    let permuted = [
        0x30, 0x12, 0x9e, 0x01, 0x00, 0x9f, 0x1f, 0x01, 0xff, 0x83, 0x02, 0x05, 0xa0, 0x84, 0x02,
        0x41, 0x42, 0x8a, 0x01, 0x03,
    ];
    assert!(matches!(
        TaggedExtendedRecord::decode_ber(&permuted, &limits),
        Err(Error::InvalidEncoding { .. } | Error::NeedMoreBytes { .. })
    ));
}

/// Reject truncated, unknown, duplicate, reordered, and nonminimal tagged children.
///
/// Parameters: none. Returns: no value; every malformed prefix must fail closed.
/// Errors: valid records are decoded; malformed records return typed errors.
/// Original source: X.690 high-tag identifiers and ordered SEQUENCE components.
/// Version/date: 2026-11-01. Author: asn1c maintainers. History: hostile-input tests.
/// Example: BER accepts a nonminimal tag alias while strict CER rejects it.
#[test]
fn malformed_and_truncated_high_tag_records_fail_closed() {
    let canonical = [
        0x30, 0x80, 0x9f, 0x1f, 0x01, 0xff, 0x9f, 0x81, 0x00, 0x01, 0x03, 0x00, 0x00,
    ];
    let limits = Limits::default();
    for end in 0..canonical.len() {
        assert!(TaggedRecord::decode_cer(&canonical[..end], &limits).is_err());
    }
    let invalid: [&[u8]; 4] = [
        &[
            0x30, 0x80, 0x9f, 0x20, 0x00, 0x9f, 0x81, 0x00, 0x01, 0x03, 0x00, 0x00,
        ],
        &[
            0x30, 0x80, 0x9f, 0x1f, 0x01, 0xff, 0x9f, 0x81, 0x00, 0x01, 0x04, 0x00, 0x00,
        ],
        &[
            0x30, 0x80, 0x9f, 0x1f, 0x00, 0x9f, 0x81, 0x00, 0x01, 0x03, 0x00, 0x00,
        ],
        &[
            0x30, 0x80, 0x9f, 0x1f, 0x01, 0xff, 0x9f, 0x81, 0x00, 0x01, 0x03, 0x00,
        ],
    ];
    for wire in invalid {
        assert!(TaggedRecord::decode_ber(wire, &limits).is_err());
        assert!(TaggedRecord::decode_cer(wire, &limits).is_err());
    }
    let nonminimal_flag = [
        0x30, 0x80, 0x9f, 0x80, 0x1f, 0x01, 0xff, 0x9f, 0x81, 0x00, 0x01, 0x03, 0, 0,
    ];
    let mut with_suffix = nonminimal_flag.to_vec();
    with_suffix.push(0xaa);
    let decoded = TaggedRecord::decode_ber(&with_suffix, &limits).unwrap();
    assert_eq!(
        decoded.value,
        TaggedRecord {
            flag: true,
            count: 3
        }
    );
    assert_eq!(decoded.consumed_bytes, nonminimal_flag.len());
    assert!(TaggedRecord::decode_cer(&nonminimal_flag, &limits).is_err());
    assert!(TaggedRecord::decode_ber(&[0x30, 0x80, 0x9f], &limits).is_err());
    assert!(TaggedRecord::decode_ber(
        &[0x30, 0x80, 0x9f, 0x1f, 0x01, 0xff, 0x9f, 0x1f, 0x01, 0x00, 0x00, 0x00],
        &limits
    )
    .is_err());
}

/// Decode BER-constructed implicit strings and reject them under strict CER.
///
/// Parameters: none. Returns: no value; flattened bytes and bit length are checked.
/// Errors: truncated fragments and noncanonical CER constructed forms are rejected.
/// Original source: X.690 BER constructed string handling and CER canonical form.
/// Version/date: 2026-11-01. Author: asn1c maintainers. History: implicit strings.
/// Example: context tag 4 contains universal OCTET STRING fragments.
#[test]
fn constructed_implicit_strings_are_ber_only() {
    let wire = [
        0x30, 0x80, 0x9f, 0x1f, 0x01, 0xff, 0xa3, 0x80, 0x03, 0x02, 0x00, 0x80, 0x03, 0x02, 0x07,
        0x80, 0x00, 0x00, 0xa4, 0x80, 0x04, 0x01, 0x41, 0x04, 0x01, 0x42, 0x00, 0x00, 0x00, 0x00,
    ];
    let decoded = TaggedExtendedRecord::decode_ber(&wire, &Limits::default()).unwrap();
    assert!(decoded.value.flag);
    assert_eq!(decoded.value.bits.unwrap().bit_len(), 9);
    assert_eq!(decoded.value.octets.unwrap(), b"AB");
    assert!(matches!(
        TaggedExtendedRecord::decode_cer(&wire, &Limits::default()),
        Err(Error::InvalidEncoding { .. })
    ));
}

/// Verify caller limits apply to tagged record input, output, and codec work.
///
/// Parameters: none. Returns: no value; each configured ceiling is asserted.
/// Errors: generated codecs report the specific exceeded resource.
/// Original source: shared BER record budget. Version/date: 2026-11-01.
/// Author: asn1c maintainers. History: tagged record resource coverage.
/// Example: a short output budget rejects DER before returning encoded bytes.
#[test]
fn tagged_record_obeys_shared_resource_limits() {
    let value = TaggedRecord {
        flag: true,
        count: 3,
    };
    let limits = Limits::default();
    let encoded = value.encode_der(&limits).unwrap();
    let short_input = Limits {
        max_input_bytes: encoded.bytes.len() - 1,
        ..limits
    };
    let short_output = Limits {
        max_output_bytes: encoded.bytes.len() - 1,
        ..limits
    };
    let no_work = Limits {
        max_work_bits: 0,
        ..limits
    };

    assert!(matches!(
        TaggedRecord::decode_ber(&encoded.bytes, &short_input),
        Err(Error::LimitExceeded {
            resource: Resource::InputBytes,
            ..
        })
    ));
    assert!(matches!(
        value.encode_der(&short_output),
        Err(Error::LimitExceeded {
            resource: Resource::OutputBytes,
            ..
        })
    ));
    assert!(matches!(
        TaggedRecord::decode_ber(&encoded.bytes, &no_work),
        Err(Error::LimitExceeded {
            resource: Resource::WorkBits,
            ..
        })
    ));
}

/// Exercise CER fragmentation for context-tagged OCTET and BIT STRING roots.
///
/// Parameters: none. Returns: no value; fragments and flattened values are checked.
/// Errors: string size, encoding, or decoding failures fail this boundary test.
/// Original source: X.690 CER fragmentation thresholds for constructed strings.
/// Version/date: 2026-11-01. Author: asn1c maintainers. History: tagged strings.
/// Example: 1001 octets and 1000 BIT STRING payload octets use constructed roots.
#[test]
fn tagged_cer_strings_fragment_at_the_canonical_boundaries() {
    let value = TaggedStringRecord {
        octets: vec![0x5a; 1001],
        bits: Some(BitStringValue::new(vec![0xa5; 1000], 8000).unwrap()),
    };
    let limits = Limits::default();
    let encoded = value.encode_cer(&limits).unwrap();
    assert_eq!(&encoded.bytes[2..6], &[0xbf, 0x1f, 0x80, 0x04]);
    assert_eq!(&encoded.bytes[1014..1018], &[0xbf, 0x81, 0x00, 0x80]);
    assert!(encoded.bytes.ends_with(&[0x00, 0x00]));
    assert_eq!(
        TaggedStringRecord::decode_cer(&encoded.bytes, &limits)
            .unwrap()
            .value,
        value
    );
}

/// Verify AUTOMATIC TAGS use fixed AST tags without changing UPER field values.
///
/// Parameters: none. Returns: no value; BER and UPER values are roundtripped.
/// Errors: codec failures fail the test.
/// Original source: ASN.1 automatic tagging resolution in the fixer.
/// Version/date: 2026-11-01. Author: asn1c maintainers. History: automatic fields.
/// Example: the first direct component uses resolved context-specific tag zero.
#[test]
fn automatic_member_tags_are_emitted_from_the_resolved_tree() {
    let value = AutomaticRecord {
        flag: true,
        count: -1,
        empty: Some(()),
        octets: Some(b"AB".to_vec()),
    };
    let limits = Limits::default();
    let encoded = value.encode_der(&limits).unwrap();
    assert_eq!(
        encoded.bytes,
        [0x30, 0x0c, 0x80, 0x01, 0xff, 0x81, 0x01, 0xff, 0x82, 0x00, 0x83, 0x02, 0x41, 0x42]
    );
    assert_eq!(
        AutomaticRecord::decode_ber(&encoded.bytes, &limits)
            .unwrap()
            .value,
        value
    );
    let packed = value.encode_uper(&limits).unwrap();
    assert_eq!(
        AutomaticRecord::decode_uper(&packed.bytes, &limits)
            .unwrap()
            .value,
        value
    );
}
