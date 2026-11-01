//! Generated BER/DER/CER tests for flat direct-field SEQUENCE values.

use asn1c_generated::sequence_ber_cer::{
    DefaultRecord, EmptyRecord, OptionalRecord, RequiredRecord,
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
    let cer = [0x30, 0x80, 0x01, 0x01, 0xff, 0x05, 0x00, 0x02, 0x01, 0x03, 0x00, 0x00];

    assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(RequiredRecord::decode_ber(&der, &limits).unwrap().value, value);
    assert_eq!(RequiredRecord::decode_cer(&cer, &limits).unwrap().value, value);
    let up = value.encode_uper(&limits).unwrap();
    assert_eq!(RequiredRecord::decode_uper(&up.bytes, &limits).unwrap().value, value);
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
        RequiredRecord::decode_ber(&[0x30, 0x08, 0x01, 0x01, 0xff, 0x05, 0x00,
                                    0x02, 0x01, 0x04], &limits),
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
    let cer_present = [0x30, 0x80, 0x01, 0x01, 0xff, 0x05, 0x00,
                       0x02, 0x01, 0xff, 0x00, 0x00];

    assert_eq!(absent.encode_der(&limits).unwrap().bytes, der_absent);
    assert_eq!(absent.encode_cer(&limits).unwrap().bytes, cer_absent);
    assert_eq!(OptionalRecord::decode_ber(&der_absent, &limits).unwrap().value, absent);
    assert_eq!(OptionalRecord::decode_cer(&cer_absent, &limits).unwrap().value, absent);
    assert_eq!(present.encode_der(&limits).unwrap().bytes, der_present);
    assert_eq!(present.encode_cer(&limits).unwrap().bytes, cer_present);
    assert_eq!(OptionalRecord::decode_ber(&der_present, &limits).unwrap().value, present);
    assert_eq!(OptionalRecord::decode_cer(&cer_present, &limits).unwrap().value, present);
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
    let cer_nondefaults = [0x30, 0x80, 0x01, 0x01, 0xff, 0x05, 0x00,
                           0x02, 0x01, 0x02, 0x00, 0x00];
    let explicit_defaults = [0x30, 0x08, 0x01, 0x01, 0x00, 0x05, 0x00, 0x02, 0x01, 0x01];

    assert_eq!(defaults.encode_der(&limits).unwrap().bytes, der_defaults);
    assert_eq!(defaults.encode_cer(&limits).unwrap().bytes, cer_defaults);
    assert_eq!(nondefaults.encode_der(&limits).unwrap().bytes, der_nondefaults);
    assert_eq!(nondefaults.encode_cer(&limits).unwrap().bytes, cer_nondefaults);
    assert_eq!(DefaultRecord::decode_ber(&der_defaults, &limits).unwrap().value, defaults);
    assert_eq!(DefaultRecord::decode_cer(&cer_defaults, &limits).unwrap().value, defaults);
    assert_eq!(DefaultRecord::decode_ber(&explicit_defaults, &limits).unwrap().value,
               DefaultRecord { flag: false, empty: (), number: 1 });
    assert!(matches!(
        DefaultRecord::decode_cer(&[0x30, 0x80, 0x01, 0x01, 0x00, 0x05, 0x00,
                                    0x02, 0x01, 0x01, 0x00, 0x00], &limits),
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
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, [0x30, 0x80, 0x00, 0x00]);
    assert_eq!(EmptyRecord::decode_ber(&[0x30, 0x00], &limits).unwrap().value, value);
    assert_eq!(EmptyRecord::decode_cer(&[0x30, 0x80, 0x00, 0x00], &limits).unwrap().value, value);
    let up = value.encode_uper(&limits).unwrap();
    assert_eq!(up.bit_len, 0);
    assert_eq!(EmptyRecord::decode_uper(&up.bytes, &limits).unwrap().value, value);
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
    let duplicate = [0x30, 0x0b, 0x01, 0x01, 0xff, 0x01, 0x01, 0xff,
                     0x05, 0x00, 0x02, 0x01, 0x03];
    let unknown = [0x30, 0x0a, 0x01, 0x01, 0xff, 0x04, 0x00,
                   0x05, 0x00, 0x02, 0x01, 0x03];
    let trailing_unknown = [0x30, 0x0a, 0x01, 0x01, 0xff, 0x05, 0x00,
                            0x02, 0x01, 0x03, 0x04, 0x00];
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
        Err(Error::LimitExceeded { resource: Resource::InputBytes, .. })
    ));
    assert!(matches!(
        value.encode_der(&short_output),
        Err(Error::LimitExceeded { resource: Resource::OutputBytes, .. })
    ));
    assert!(matches!(
        RequiredRecord::decode_ber(&der.bytes, &no_work),
        Err(Error::LimitExceeded { resource: Resource::WorkBits, .. })
    ));
}
