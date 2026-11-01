//! Generated BER/DER/CER tests for flat direct-field SEQUENCE values.

use asn1c_generated::sequence_ber_cer::{
    BitBoundaryRecord, DefaultRecord, EmptyRecord, EnumeratedRecord, ExtendedRecord,
    ExtendedRecordStateValue, FixedStringsRecord, OctetBoundaryRecord, OptionalBitRecord,
    OptionalFixedStringsRecord, OptionalOctetRecord, OptionalRecord, RequiredRecord,
};
use asn1c_runtime::{Error, Limits, Resource};

/// Compare DER and CER output with fixed X.690 vectors for required fields.
///
/// Parameters: none. Returns: no value; assertions compare exact wire bytes.
/// Errors: malformed decode input returns typed runtime errors.
/// Original source: X.690 primitive and constructed encoding rules.
/// Version/date: 2026-10-31. Responsible party: asn1c maintainers.
/// History: initial generated BER/CER SEQUENCE coverage.
/// Example: TRUE, NULL, and INTEGER 3 produce one ordered SEQUENCE TLV.
#[test]
fn required_record_uses_declaration_order_and_canonical_outer_framing() {
    let limits = Limits::default();
    let value = RequiredRecord {
        flag: true,
        empty: (),
        number: 3,
    };
    let der = [0x30, 0x08, 0x01, 0x01, 0xff, 0x05, 0x00, 0x02, 0x01, 0x03];
    let cer = [
        0x30, 0x80, 0x01, 0x01, 0xff, 0x05, 0x00, 0x02, 0x01, 0x03, 0x00, 0x00,
    ];

    assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(
        RequiredRecord::decode_ber(&der, &limits).unwrap().value,
        value
    );
    assert_eq!(
        RequiredRecord::decode_cer(&cer, &limits).unwrap().value,
        value
    );
    let up = value.encode_uper(&limits).unwrap();
    assert_eq!(
        RequiredRecord::decode_uper(&up.bytes, &limits)
            .unwrap()
            .value,
        value
    );
    let mut with_suffix = der.to_vec();
    with_suffix.push(0xaa);
    let decoded_prefix = RequiredRecord::decode_ber(&with_suffix, &limits).unwrap();
    assert_eq!(decoded_prefix.value, value);
    assert_eq!(decoded_prefix.consumed_bytes, der.len());
    assert_eq!(decoded_prefix.consumed_bits, der.len() * 8);
    let mut cer_with_suffix = cer.to_vec();
    cer_with_suffix.push(0xaa);
    let decoded_cer_prefix = RequiredRecord::decode_cer(&cer_with_suffix, &limits).unwrap();
    assert_eq!(decoded_cer_prefix.value, value);
    assert_eq!(decoded_cer_prefix.consumed_bytes, cer.len());
    assert!(matches!(
        RequiredRecord::decode_ber(&[0x30, 0x05, 0x01, 0x01, 0xff], &limits),
        Err(Error::InvalidEncoding { .. } | Error::NeedMoreBytes { .. })
    ));
    assert!(matches!(
        RequiredRecord::decode_ber(
            &[0x30, 0x08, 0x01, 0x01, 0xff, 0x05, 0x00, 0x02, 0x01, 0x04],
            &limits
        ),
        Err(Error::ValueOutOfRange { .. })
    ));
}

/// Check OPTIONAL omission and explicit values across all three universal tags.
///
/// Parameters: none. Returns: no value; assertions compare exact wire bytes.
/// Errors: invalid order or malformed values return typed errors.
/// Original source: X.690 ordered SEQUENCE component rules.
/// Version/date: 2026-10-31. Responsible party: asn1c maintainers.
/// History: OPTIONAL record conformance. Example: three absent fields yield an
/// empty DER SEQUENCE and an indefinite CER SEQUENCE.
#[test]
fn optional_record_roundtrips_absent_and_present_fields() {
    let limits = Limits::default();
    let absent = OptionalRecord {
        flag: None,
        empty: None,
        number: None,
    };
    let present = OptionalRecord {
        flag: Some(true),
        empty: Some(()),
        number: Some(-1),
    };
    let der_absent = [0x30, 0x00];
    let cer_absent = [0x30, 0x80, 0x00, 0x00];
    let der_present = [0x30, 0x08, 0x01, 0x01, 0xff, 0x05, 0x00, 0x02, 0x01, 0xff];
    let cer_present = [
        0x30, 0x80, 0x01, 0x01, 0xff, 0x05, 0x00, 0x02, 0x01, 0xff, 0x00, 0x00,
    ];

    assert_eq!(absent.encode_der(&limits).unwrap().bytes, der_absent);
    assert_eq!(absent.encode_cer(&limits).unwrap().bytes, cer_absent);
    assert_eq!(
        OptionalRecord::decode_ber(&der_absent, &limits)
            .unwrap()
            .value,
        absent
    );
    assert_eq!(
        OptionalRecord::decode_cer(&cer_absent, &limits)
            .unwrap()
            .value,
        absent
    );
    assert_eq!(present.encode_der(&limits).unwrap().bytes, der_present);
    assert_eq!(present.encode_cer(&limits).unwrap().bytes, cer_present);
    assert_eq!(
        OptionalRecord::decode_ber(&der_present, &limits)
            .unwrap()
            .value,
        present
    );
    assert_eq!(
        OptionalRecord::decode_cer(&cer_present, &limits)
            .unwrap()
            .value,
        present
    );
}

/// Check literal BOOLEAN and INTEGER DEFAULT omission and decode substitution.
///
/// Parameters: none. Returns: no value; assertions compare values and bytes.
/// Errors: CER rejects a valid BER value when its encoding is noncanonical.
/// Original source: X.690 DEFAULT component omission and CER canonicality.
/// Version/date: 2026-10-31. Responsible party: asn1c maintainers.
/// History: DEFAULT record conformance. Example: both declared defaults omit.
#[test]
fn default_record_omits_literals_and_cer_checks_canonical_form() {
    let limits = Limits::default();
    let defaults = DefaultRecord {
        flag: false,
        empty: (),
        number: 1,
    };
    let nondefaults = DefaultRecord {
        flag: true,
        empty: (),
        number: 2,
    };
    let der_defaults = [0x30, 0x02, 0x05, 0x00];
    let cer_defaults = [0x30, 0x80, 0x05, 0x00, 0x00, 0x00];
    let der_nondefaults = [0x30, 0x08, 0x01, 0x01, 0xff, 0x05, 0x00, 0x02, 0x01, 0x02];
    let cer_nondefaults = [
        0x30, 0x80, 0x01, 0x01, 0xff, 0x05, 0x00, 0x02, 0x01, 0x02, 0x00, 0x00,
    ];
    let explicit_defaults = [0x30, 0x08, 0x01, 0x01, 0x00, 0x05, 0x00, 0x02, 0x01, 0x01];

    assert_eq!(defaults.encode_der(&limits).unwrap().bytes, der_defaults);
    assert_eq!(defaults.encode_cer(&limits).unwrap().bytes, cer_defaults);
    assert_eq!(
        nondefaults.encode_der(&limits).unwrap().bytes,
        der_nondefaults
    );
    assert_eq!(
        nondefaults.encode_cer(&limits).unwrap().bytes,
        cer_nondefaults
    );
    assert_eq!(
        DefaultRecord::decode_ber(&der_defaults, &limits)
            .unwrap()
            .value,
        defaults
    );
    assert_eq!(
        DefaultRecord::decode_cer(&cer_defaults, &limits)
            .unwrap()
            .value,
        defaults
    );
    assert_eq!(
        DefaultRecord::decode_ber(&explicit_defaults, &limits)
            .unwrap()
            .value,
        DefaultRecord {
            flag: false,
            empty: (),
            number: 1
        }
    );
    assert!(matches!(
        DefaultRecord::decode_cer(
            &[0x30, 0x80, 0x01, 0x01, 0x00, 0x05, 0x00, 0x02, 0x01, 0x01, 0x00, 0x00],
            &limits
        ),
        Err(Error::InvalidEncoding { .. })
    ));
}

/// Verify empty records retain the distinct DER and CER constructed framing.
///
/// Parameters: none. Returns: no value; assertions compare exact wire bytes.
/// Errors: malformed records return typed runtime errors.
/// Original source: X.690 empty constructed values.
/// Version/date: 2026-10-31. Responsible party: asn1c maintainers.
/// History: empty record support. Example: empty CER is indefinite with EOC.
#[test]
fn empty_record_has_rule_specific_framing() {
    let limits = Limits::default();
    let value = EmptyRecord {};

    assert_eq!(value.encode_der(&limits).unwrap().bytes, [0x30, 0x00]);
    assert_eq!(
        value.encode_cer(&limits).unwrap().bytes,
        [0x30, 0x80, 0x00, 0x00]
    );
    assert_eq!(
        EmptyRecord::decode_ber(&[0x30, 0x00], &limits)
            .unwrap()
            .value,
        value
    );
    assert_eq!(
        EmptyRecord::decode_cer(&[0x30, 0x80, 0x00, 0x00], &limits)
            .unwrap()
            .value,
        value
    );
    let up = value.encode_uper(&limits).unwrap();
    assert_eq!(up.bit_len, 0);
    assert_eq!(
        EmptyRecord::decode_uper(&up.bytes, &limits).unwrap().value,
        value
    );
    assert!(matches!(
        EmptyRecord::decode_ber(&[0x30, 0x03, 0x01, 0x01, 0x00], &limits),
        Err(Error::InvalidEncoding { .. })
    ));
}

/// Reject reordered, duplicate, and unknown children plus truncation and limits.
///
/// Parameters: none. Returns: no value; assertions inspect typed failures.
/// Errors: malformed and over-budget inputs are expected to fail.
/// Original source: ordered SEQUENCE grammar and runtime resource limits.
/// Version/date: 2026-10-31. Responsible party: asn1c maintainers.
/// History: negative record coverage. Example: an INTEGER before BOOLEAN fails.
#[test]
fn malformed_and_over_budget_records_fail_closed() {
    let limits = Limits::default();
    let reordered = [0x30, 0x08, 0x02, 0x01, 0x01, 0x01, 0x01, 0xff, 0x05, 0x00];
    let duplicate = [
        0x30, 0x0b, 0x01, 0x01, 0xff, 0x01, 0x01, 0xff, 0x05, 0x00, 0x02, 0x01, 0x03,
    ];
    let unknown = [
        0x30, 0x0a, 0x01, 0x01, 0xff, 0x04, 0x00, 0x05, 0x00, 0x02, 0x01, 0x03,
    ];
    let trailing_unknown = [
        0x30, 0x0a, 0x01, 0x01, 0xff, 0x05, 0x00, 0x02, 0x01, 0x03, 0x04, 0x00,
    ];
    let truncated = [0x30, 0x08, 0x01, 0x01, 0xff, 0x05, 0x00, 0x02, 0x01];
    let value = RequiredRecord {
        flag: true,
        empty: (),
        number: 3,
    };
    let der = value.encode_der(&limits).unwrap();
    let short_input = Limits {
        max_input_bytes: der.bytes.len() - 1,
        ..limits
    };
    let short_output = Limits {
        max_output_bytes: der.bytes.len() - 1,
        ..limits
    };
    let no_work = Limits {
        max_work_bits: 0,
        ..limits
    };

    assert!(RequiredRecord::decode_ber(&reordered, &limits).is_err());
    assert!(RequiredRecord::decode_ber(&duplicate, &limits).is_err());
    assert!(RequiredRecord::decode_ber(&unknown, &limits).is_err());
    assert!(RequiredRecord::decode_ber(&trailing_unknown, &limits).is_err());
    assert!(RequiredRecord::decode_ber(&truncated, &limits).is_err());
    for end in 0..der.bytes.len() {
        assert!(RequiredRecord::decode_ber(&der.bytes[..end], &limits).is_err());
    }
    let canonical_cer = [
        0x30, 0x80, 0x01, 0x01, 0xff, 0x05, 0x00, 0x02, 0x01, 0x03, 0x00, 0x00,
    ];
    for end in 0..canonical_cer.len() {
        assert!(RequiredRecord::decode_cer(&canonical_cer[..end], &limits).is_err());
    }
    assert!(matches!(
        RequiredRecord::decode_ber(&der.bytes, &short_input),
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
        RequiredRecord::decode_ber(&der.bytes, &no_work),
        Err(Error::LimitExceeded {
            resource: Resource::WorkBits,
            ..
        })
    ));
}

/// Append a minimal DER length to a test-only expected vector.
///
/// Parameters: output receives bytes; length is the content byte count.
/// Returns no value. Lengths are small enough for one or two length octets.
/// Errors: no error is returned because the test bounds inputs explicitly.
/// Original source: X.690 definite-length form. Version/date: 2026-10-31.
/// Responsible party: asn1c maintainers. History: third-wave sequence tests.
/// Example: `append_length(&mut bytes, 128)` appends `81 80`.
fn append_length(output: &mut Vec<u8>, length: usize) {
    if length < 128 {
        output.push(u8::try_from(length).expect("short test length fits in u8"));
    } else if length <= 255 {
        output.extend_from_slice(&[
            0x81,
            u8::try_from(length).expect("one-octet test length fits in u8"),
        ]);
    } else {
        output.extend_from_slice(&[
            0x82,
            u8::try_from(length >> 8).expect("high test length octet fits in u8"),
            u8::try_from(length & 0xff).expect("low test length octet fits in u8"),
        ]);
    }
}

/// Construct a DER primitive TLV for an independent compact vector.
///
/// Parameters: tag is the one-octet universal tag; payload is borrowed data.
/// Returns the complete TLV. Errors: no error is returned for these test sizes.
/// Original source: X.690 DER primitive framing. Version/date: 2026-10-31.
/// Responsible party: asn1c maintainers. History: boundary-vector tests.
/// Example: `primitive_tlv(4, b"abc")` returns an OCTET STRING TLV.
fn primitive_tlv(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    append_length(&mut output, payload.len());
    output.extend_from_slice(payload);
    output
}

/// Build the expected DER or CER one-field OCTET STRING SEQUENCE bytes.
///
/// Parameters: payload is one bounded string; cer selects the record rule.
/// Returns one exact record TLV. Errors: test inputs are within fixture bounds.
/// Original source: X.690 record and string framing. Version/date: 2026-10-31.
/// Responsible party: asn1c maintainers. History: fragmentation boundaries.
/// Example: `expected_octets(&vec![0; 1001], true)` builds fragmented CER.
fn expected_octets(payload: &[u8], cer: bool) -> Vec<u8> {
    let mut children = Vec::new();
    if cer {
        children.extend_from_slice(&[0x30, 0x80]);
        if payload.len() > 1000 {
            children.extend_from_slice(&[0x24, 0x80]);
            for fragment in payload.chunks(1000) {
                children.extend_from_slice(&primitive_tlv(4, fragment));
            }
            children.extend_from_slice(&[0, 0]);
        } else {
            children.extend_from_slice(&primitive_tlv(4, payload));
        }
        children.extend_from_slice(&[0, 0]);
    } else {
        let child = primitive_tlv(4, payload);
        children.push(0x30);
        append_length(&mut children, child.len());
        children.extend_from_slice(&child);
    }
    children
}

/// Build expected CER BIT STRING framing around whole-byte test payloads.
///
/// Parameters: bytes is packed payload with no unused bits; cer selects CER.
/// Returns one complete record. Errors: fixture inputs are bounded to 1000 B.
/// Original source: X.690 BIT STRING CER fragmentation. Version/date: 2026-10-31.
/// Responsible party: asn1c maintainers. History: content-size threshold tests.
/// Example: `expected_bits(&vec![0xaa; 1000])` returns constructed CER.
fn expected_bits(bytes: &[u8]) -> Vec<u8> {
    let mut output = vec![0x30, 0x80];
    if bytes.len() + 1 > 1000 {
        output.extend_from_slice(&[0x23, 0x80]);
        for fragment in bytes.chunks(999) {
            let mut content = vec![0];
            content.extend_from_slice(fragment);
            output.extend_from_slice(&primitive_tlv(3, &content));
        }
        output.extend_from_slice(&[0, 0]);
    } else {
        let mut content = vec![0];
        content.extend_from_slice(bytes);
        output.extend_from_slice(&primitive_tlv(3, &content));
    }
    output.extend_from_slice(&[0, 0]);
    output
}

/// Test required and OPTIONAL enum/string fields across UPER, DER, and CER.
///
/// Parameters: none. Returns no value; exact wire and decoded values are checked.
/// Errors: invalid or unknown enum values return runtime errors.
/// Original source: X.690 primitive encodings and generated C parity vectors.
/// Version/date: 2026-10-31. Responsible party: asn1c maintainers.
/// History: direct ENUMERATED and bounded string record support.
/// Example: numeric enum value 3 maps to `ExtendedRecordStateValue::Active`.
#[test]
fn direct_enum_and_bounded_strings_roundtrip_in_mixed_codec_record() {
    let limits = Limits::default();
    let value = ExtendedRecord {
        state_value: Some(ExtendedRecordStateValue::Active),
        octets: vec![0x41, 0x42],
        bits: Some(asn1c_runtime::BitStringValue::new(vec![0xa0], 3).unwrap()),
        number: -2,
    };
    let der = [
        0x30, 0x0e, 0x0a, 0x01, 0x03, 0x04, 0x02, 0x41, 0x42, 0x03, 0x02, 0x05, 0xa0, 0x02, 0x01,
        0xfe,
    ];
    let cer = [
        0x30, 0x80, 0x0a, 0x01, 0x03, 0x04, 0x02, 0x41, 0x42, 0x03, 0x02, 0x05, 0xa0, 0x02, 0x01,
        0xfe, 0x00, 0x00,
    ];

    assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(
        ExtendedRecord::decode_ber(&der, &limits).unwrap().value,
        value
    );
    assert_eq!(
        ExtendedRecord::decode_cer(&cer, &limits).unwrap().value,
        value
    );
    let uper = value.encode_uper(&limits).unwrap();
    assert_eq!(
        ExtendedRecord::decode_uper(&uper.bytes, &limits)
            .unwrap()
            .value,
        value
    );

    let required = EnumeratedRecord {
        state: asn1c_generated::sequence_ber_cer::EnumeratedRecordState::Active,
    };
    assert_eq!(
        required.encode_der(&limits).unwrap().bytes,
        [0x30, 0x03, 0x0a, 0x01, 0x03]
    );
    assert!(EnumeratedRecord::decode_ber(&[0x30, 0x03, 0x0a, 0x01, 0x04], &limits).is_err());
    assert!(EnumeratedRecord::decode_cer(&[0x30, 0x80, 0x0a, 0x01, 0x04, 0, 0], &limits,).is_err());
}

/// Test fixed string storage, OPTIONAL empty values, and DER/CER size edges.
///
/// Parameters: none. Returns no value; exact wire bytes and roundtrips are checked.
/// Errors: invalid sizes and malformed inputs return runtime errors.
/// Original source: X.690 string length and bit-padding rules.
/// Version/date: 2026-10-31. Responsible party: asn1c maintainers.
/// History: fixed/bounded direct SEQUENCE string coverage.
/// Example: a five-bit fixed BIT STRING uses one padded octet.
#[test]
fn fixed_optional_and_fragmented_strings_use_canonical_boundaries() {
    let limits = Limits::default();
    let fixed = FixedStringsRecord {
        octets: vec![1, 2, 3],
        bits: vec![0xa8],
    };
    let fixed_der = [0x30, 0x09, 0x04, 0x03, 1, 2, 3, 0x03, 0x02, 0x03, 0xa8];
    assert_eq!(fixed.encode_der(&limits).unwrap().bytes, fixed_der);
    assert_eq!(
        FixedStringsRecord::decode_ber(&fixed_der, &limits)
            .unwrap()
            .value,
        fixed
    );

    let absent_octets = OptionalOctetRecord { octets: None };
    let present_octets = OptionalOctetRecord {
        octets: Some(vec![0x42]),
    };
    assert_eq!(absent_octets.encode_der(&limits).unwrap().bytes, [0x30, 0]);
    assert_eq!(
        present_octets.encode_der(&limits).unwrap().bytes,
        [0x30, 3, 4, 1, 0x42]
    );
    assert_eq!(
        OptionalOctetRecord::decode_ber(
            &present_octets.encode_der(&limits).unwrap().bytes,
            &limits,
        )
        .unwrap()
        .value,
        present_octets
    );
    let optional_bits = OptionalBitRecord {
        bits: Some(asn1c_runtime::BitStringValue::new(vec![0x80], 1).unwrap()),
    };
    assert_eq!(
        OptionalBitRecord::decode_cer(&optional_bits.encode_cer(&limits).unwrap().bytes, &limits,)
            .unwrap()
            .value,
        optional_bits
    );
    for length in [125, 126, 127, 128] {
        let payload = vec![0x5a; length];
        let value = OctetBoundaryRecord {
            octets: payload.clone(),
        };
        let encoded = value.encode_der(&limits).unwrap();
        assert_eq!(encoded.bytes, expected_octets(&payload, false));
        assert_eq!(
            OctetBoundaryRecord::decode_ber(&encoded.bytes, &limits)
                .unwrap()
                .value,
            value
        );
    }
    for length in [1000, 1001] {
        let payload = vec![0x5a; length];
        let value = OctetBoundaryRecord {
            octets: payload.clone(),
        };
        let encoded = value.encode_cer(&limits).unwrap();
        assert_eq!(encoded.bytes, expected_octets(&payload, true));
        assert_eq!(
            OctetBoundaryRecord::decode_cer(&encoded.bytes, &limits)
                .unwrap()
                .value,
            value
        );
    }
    for octets in [999, 1000] {
        let bytes = vec![0xa5; octets];
        let value = BitBoundaryRecord {
            bits: asn1c_runtime::BitStringValue::new(bytes.clone(), octets * 8).unwrap(),
        };
        let encoded = value.encode_cer(&limits).unwrap();
        assert_eq!(encoded.bytes, expected_bits(&bytes));
        assert_eq!(
            BitBoundaryRecord::decode_cer(&encoded.bytes, &limits)
                .unwrap()
                .value,
            value
        );
    }
}

/// Check omitted and present OPTIONAL fixed strings in a generated record.
///
/// Parameters: none. Returns no value; exact DER bytes and values are checked.
/// Errors: malformed record decoding returns runtime errors.
/// Original source: X.690 OPTIONAL component omission.
/// Version/date: 2026-10-31. Responsible party: asn1c maintainers.
/// History: fixed OPTIONAL strings added in third-wave record support.
/// Example: absent fields encode as an empty SEQUENCE.
#[test]
fn optional_fixed_string_fields_roundtrip() {
    let limits = Limits::default();
    let absent = OptionalFixedStringsRecord {
        octets: None,
        bits: None,
    };
    let present = OptionalFixedStringsRecord {
        octets: Some(vec![0x11, 0x22]),
        bits: Some(vec![0xa0]),
    };
    let der = [0x30, 0x08, 0x04, 0x02, 0x11, 0x22, 0x03, 0x02, 0x05, 0xa0];

    assert_eq!(absent.encode_der(&limits).unwrap().bytes, [0x30, 0]);
    assert_eq!(present.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(
        OptionalFixedStringsRecord::decode_ber(&der, &limits)
            .unwrap()
            .value,
        present
    );
}

/// Reject malformed, truncated, out-of-range, and over-budget string records.
///
/// Parameters: none. Returns no value; all invalid inputs must be rejected.
/// Errors: checks typed size/resource failures and generic malformed failures.
/// Original source: malformed BER/CER adversarial inputs.
/// Version/date: 2026-10-31. Responsible party: asn1c maintainers.
/// History: third-wave safety tests. Example: reject a BER string over SIZE.
#[test]
fn malformed_string_fields_and_limits_are_rejected() {
    let limits = Limits::default();
    assert!(OctetBoundaryRecord::decode_ber(&[0x30, 0x04, 0x04, 0x02, 1, 2], &limits).is_ok());
    assert!(OctetBoundaryRecord::decode_ber(&[0x30, 0x05, 0x04, 0x03, 1, 2], &limits).is_err());
    assert!(
        ExtendedRecord::decode_ber(&[0x30, 0x05, 0x0a, 0x01, 0x04, 0x04, 0], &limits,).is_err()
    );
    let value = OctetBoundaryRecord {
        octets: vec![0; 128],
    };
    let der = value.encode_der(&limits).unwrap();
    for end in 0..der.bytes.len() {
        assert!(OctetBoundaryRecord::decode_ber(&der.bytes[..end], &limits).is_err());
    }
    let short_input = Limits {
        max_input_bytes: der.bytes.len() - 1,
        ..limits
    };
    assert!(matches!(
        OctetBoundaryRecord::decode_ber(&der.bytes, &short_input),
        Err(Error::LimitExceeded {
            resource: Resource::InputBytes,
            ..
        })
    ));
    assert!(OctetBoundaryRecord {
        octets: vec![0; 1002]
    }
    .encode_der(&limits)
    .is_err());
    let dirty_fixed_bits = FixedStringsRecord {
        octets: vec![1, 2, 3],
        bits: vec![0xaf],
    };
    assert!(dirty_fixed_bits.encode_der(&limits).is_err());

    let constructed_octets = [
        0x30, 0x80, 0x24, 0x80, 0x04, 0x01, 0x41, 0, 0, 0x02, 0x01, 0, 0, 0,
    ];
    let decoded_ber = ExtendedRecord::decode_ber(&constructed_octets, &limits).unwrap();
    assert_eq!(decoded_ber.value.octets, [0x41]);
    assert!(ExtendedRecord::decode_cer(&constructed_octets, &limits).is_err());
    let constructed_bits = [
        0x30, 0x80, 0x04, 0x01, 0x41, 0x23, 0x80, 0x03, 0x02, 0, 0x80, 0x03, 0x02, 7, 0x80, 0, 0,
        0x02, 0x01, 0, 0, 0,
    ];
    let decoded_bits = ExtendedRecord::decode_ber(&constructed_bits, &limits).unwrap();
    assert_eq!(
        decoded_bits.value.bits,
        Some(asn1c_runtime::BitStringValue::new(vec![0x80, 0x80], 9).unwrap())
    );
    assert!(ExtendedRecord::decode_cer(&constructed_bits, &limits).is_err());

    let multiple_strings = ExtendedRecord {
        state_value: None,
        octets: vec![0x5a; 128],
        bits: Some(asn1c_runtime::BitStringValue::new(vec![0xa5; 2], 16).unwrap()),
        number: 0,
    };
    let encoded = multiple_strings.encode_der(&limits).unwrap();
    let tight_output = Limits {
        max_output_bytes: encoded.bytes.len() - 1,
        ..limits
    };
    assert!(matches!(
        multiple_strings.encode_der(&tight_output),
        Err(Error::LimitExceeded {
            resource: Resource::OutputBytes,
            ..
        })
    ));
    let tight_work = Limits {
        max_work_bits: encoded.bytes.len() * 8 - 1,
        ..limits
    };
    assert!(matches!(
        ExtendedRecord::decode_ber(&encoded.bytes, &tight_work),
        Err(Error::LimitExceeded {
            resource: Resource::WorkBits,
            ..
        })
    ));
    let tight_retained = Limits {
        max_output_bytes: 129,
        ..limits
    };
    assert!(matches!(
        ExtendedRecord::decode_ber(&encoded.bytes, &tight_retained),
        Err(Error::LimitExceeded {
            resource: Resource::OutputBytes,
            ..
        })
    ));
}
