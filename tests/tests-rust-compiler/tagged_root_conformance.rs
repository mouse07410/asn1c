//! Conformance tests for one context-specific IMPLICIT SEQUENCE root tag.

use asn1c_generated::tagged_root_sequence::{
    RootDefault, RootEmpty, RootOptional, RootTag0, RootTag127, RootTag3, RootTag30, RootTag31,
    RootTagMax,
};
use asn1c_runtime::{Error, Limits, Resource};

/// Check exact DER/CER encodings and BER/CER decoding at root-tag boundaries.
///
/// Parameters: none. Returns: no value; all fixed vectors and decoded values are asserted.
/// Errors: malformed roots and resource ceilings must produce runtime errors.
/// Source: X.680 IMPLICIT tagging and X.690 constructed BER/DER/CER framing.
/// Version/date: 2026-11-01. Author: asn1c maintainers. History: tagged root slice.
/// Example: tag 3 encodes value 2 as `a3 03 02 01 02` in DER.
#[test]
fn root_tag_boundaries_encode_decode_and_consume_prefixes() {
    macro_rules! check_root_tag {
        ($value:expr, $type:ty, $der:expr, $cer:expr) => {{
            let limits = Limits::default();
            let value = $value;
            let der: &[u8] = $der;
            let cer: &[u8] = $cer;
            assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
            assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
            assert_eq!(<$type>::decode_ber(&der, &limits).unwrap().value, value);
            assert_eq!(<$type>::decode_ber(&cer, &limits).unwrap().value, value);
            assert_eq!(<$type>::decode_cer(&cer, &limits).unwrap().value, value);
            assert!(<$type>::decode_cer(&der, &limits).is_err());
            let mut prefixed = der.to_vec();
            prefixed.push(0xaa);
            let decoded = <$type>::decode_ber(&prefixed, &limits).unwrap();
            assert_eq!(decoded.value, value);
            assert_eq!(decoded.consumed_bytes, der.len());
            assert_eq!(decoded.consumed_bits, decoded.consumed_bytes * 8);
        }};
    }

    check_root_tag!(
        RootTag0 { x: 2 },
        RootTag0,
        &[0xa0, 3, 2, 1, 2],
        &[0xa0, 0x80, 2, 1, 2, 0, 0]
    );
    check_root_tag!(
        RootTag3 { x: 2 },
        RootTag3,
        &[0xa3, 3, 2, 1, 2],
        &[0xa3, 0x80, 2, 1, 2, 0, 0]
    );
    check_root_tag!(
        RootTag30 { x: 2 },
        RootTag30,
        &[0xbe, 3, 2, 1, 2],
        &[0xbe, 0x80, 2, 1, 2, 0, 0]
    );
    check_root_tag!(
        RootTag31 { x: 2 },
        RootTag31,
        &[0xbf, 0x1f, 3, 2, 1, 2],
        &[0xbf, 0x1f, 0x80, 2, 1, 2, 0, 0]
    );
    check_root_tag!(
        RootTag127 { x: 2 },
        RootTag127,
        &[0xbf, 0x7f, 3, 2, 1, 2],
        &[0xbf, 0x7f, 0x80, 2, 1, 2, 0, 0]
    );
    check_root_tag!(
        RootTagMax { x: 2 },
        RootTagMax,
        &[0xbf, 0x83, 0xff, 0xff, 0xff, 0x7f, 3, 2, 1, 2],
        &[0xbf, 0x83, 0xff, 0xff, 0xff, 0x7f, 0x80, 2, 1, 2, 0, 0]
    );
}

/// Preserve empty, OPTIONAL, and DEFAULT fields under a tagged root wrapper.
///
/// Parameters: none. Returns: no value; exact wrappers and substituted values are asserted.
/// Errors: malformed or noncanonical framed records are returned by generated codecs.
/// Source: X.680 presence semantics and X.690 constructed framing. Version/date: 2026-11-01.
/// Author: asn1c maintainers. History: tagged root component coverage. Example: absent DEFAULT 2.
#[test]
fn empty_optional_and_default_root_records_roundtrip() {
    let limits = Limits::default();
    let empty_definite = [0xa4, 0x00];
    let empty_indefinite = [0xa4, 0x80, 0x00, 0x00];
    let optional_absent_der = [0xa5, 0x00];
    let optional_present_der = [0xa5, 0x03, 0x02, 0x01, 0x02];
    let default_omitted_der = [0xa6, 0x00];
    let default_present_der = [0xa6, 0x03, 0x02, 0x01, 0x03];

    assert_eq!(
        RootEmpty {}.encode_der(&limits).unwrap().bytes,
        empty_definite
    );
    assert_eq!(
        RootEmpty {}.encode_cer(&limits).unwrap().bytes,
        empty_indefinite
    );
    assert_eq!(
        RootEmpty::decode_ber(&empty_definite, &limits)
            .unwrap()
            .value,
        RootEmpty {}
    );
    assert_eq!(
        RootEmpty::decode_cer(&empty_indefinite, &limits)
            .unwrap()
            .value,
        RootEmpty {}
    );

    let absent = RootOptional { x: None };
    let present = RootOptional { x: Some(2) };
    assert_eq!(
        absent.encode_der(&limits).unwrap().bytes,
        optional_absent_der
    );
    assert_eq!(
        present.encode_der(&limits).unwrap().bytes,
        optional_present_der
    );
    assert_eq!(
        RootOptional::decode_ber(&optional_absent_der, &limits)
            .unwrap()
            .value,
        absent
    );
    assert_eq!(
        RootOptional::decode_ber(&optional_present_der, &limits)
            .unwrap()
            .value,
        present
    );

    let default = RootDefault { x: 2 };
    let nondefault = RootDefault { x: 3 };
    assert_eq!(
        default.encode_der(&limits).unwrap().bytes,
        default_omitted_der
    );
    assert_eq!(
        nondefault.encode_der(&limits).unwrap().bytes,
        default_present_der
    );
    assert_eq!(
        RootDefault::decode_ber(&default_omitted_der, &limits)
            .unwrap()
            .value,
        default
    );
    assert_eq!(
        RootDefault::decode_ber(&default_present_der, &limits)
            .unwrap()
            .value,
        nondefault
    );
}

/// Reject invalid root identifier forms and noncanonical CER aliases.
///
/// Parameters: none. Returns: no value; each malformed form must fail closed.
/// Errors: valid BER aliases remain accepted while strict CER rejects them.
/// Source: X.690 identifier and constructed-value rules. Version/date: 2026-11-01.
/// Author: asn1c maintainers. History: hostile tagged-root forms. Example: `bf 03` aliases tag 3.
#[test]
fn malformed_root_forms_and_nonminimal_aliases_are_checked() {
    let limits = Limits::default();
    let alias = [0xbf, 0x03, 0x03, 0x02, 0x01, 0x02];
    let decoded = RootTag3::decode_ber(&alias, &limits).unwrap();
    assert_eq!(decoded.value, RootTag3 { x: 2 });
    assert_eq!(decoded.consumed_bytes, alias.len());
    assert!(matches!(
        RootTag3::decode_cer(&alias, &limits),
        Err(Error::InvalidEncoding { .. })
    ));

    let invalid: [&[u8]; 8] = [
        &[0x83, 3, 2, 1, 2],
        &[0xa4, 3, 2, 1, 2],
        &[0xa3, 0x80, 2, 1, 2],
        &[0xa3, 0x80, 2, 1, 2, 0],
        &[0xa3, 3, 2, 1],
        &[0xa3, 4, 2, 1, 2],
        &[0xa3, 0x80, 0, 0, 2, 1, 2],
        &[0xa3, 0x80, 2, 1, 2, 0, 1],
    ];
    for wire in invalid {
        assert!(RootTag3::decode_ber(wire, &limits).is_err());
        assert!(RootTag3::decode_cer(wire, &limits).is_err());
    }
}

/// Apply the configured input, output, and work limits to the full root TLV.
///
/// Parameters: none. Returns: no value; low ceilings must be surfaced by the codecs.
/// Errors: each over-limit encode or decode returns its corresponding resource error.
/// Source: shared BER/CER `RecordContext`. Version/date: 2026-11-01.
/// Author: asn1c maintainers. History: tagged root resource checks. Example: cap output at 4 bytes.
#[test]
fn root_tag_operations_enforce_input_output_and_work_limits() {
    let value = RootTag3 { x: 2 };
    let wire = [0xa3, 3, 2, 1, 2];
    let too_small_input = Limits {
        max_input_bytes: wire.len() - 1,
        ..Limits::default()
    };
    let too_small_output = Limits {
        max_output_bytes: wire.len() - 1,
        ..Limits::default()
    };
    let too_small_work = Limits {
        max_work_bits: 0,
        ..Limits::default()
    };

    assert!(matches!(
        RootTag3::decode_ber(&wire, &too_small_input),
        Err(Error::LimitExceeded {
            resource: Resource::InputBytes,
            ..
        })
    ));
    assert!(matches!(
        value.encode_der(&too_small_output),
        Err(Error::LimitExceeded {
            resource: Resource::OutputBytes,
            ..
        })
    ));
    assert!(RootTag3::decode_ber(&wire, &too_small_work).is_err());
}
