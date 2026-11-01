//! Generated BER/DER/CER tests for explicit context-specific record fields.

use asn1c_generated::explicit_automatic_mode::ExplicitAutomaticRecord;
use asn1c_generated::explicit_implicit_mode::ExplicitImplicitRecord;
use asn1c_generated::explicit_sequence::{
    ExplicitDefaultTrue, ExplicitRecord, ExplicitRecordState, ExplicitStringRecord,
};
use asn1c_runtime::{BitStringValue, Error, Limits, Resource};

/// Verify the exact DER and CER wrappers for explicit scalar fields.
///
/// Parameters: none. Returns: no value; assertions compare complete vectors.
/// Errors: generated encoders and decoders report malformed values as errors.
/// Source: X.690 explicit component wrappers. Version/date: 2026-11-01.
/// Author: asn1c maintainers. History: EXPLICIT record conformance.
/// Example: context tag 30 contains one universal INTEGER child.
#[test]
fn explicit_sequence_emits_one_wrapper_per_field() {
    let limits = Limits::default();
    let value = ExplicitRecord {
        flag: true,
        count: 4,
        marker: Some(()),
        state: ExplicitRecordState::Two,
        extra: Some(false),
    };
    let der = [
        0x30, 0x1c, 0xa0, 0x03, 0x01, 0x01, 0xff, 0xbe, 0x03, 0x02, 0x01, 0x04, 0xbf, 0x1f, 0x02,
        0x05, 0x00, 0xbf, 0x7f, 0x03, 0x0a, 0x01, 0x02, 0xbf, 0x81, 0x00, 0x03, 0x01, 0x01, 0x00,
    ];
    let cer = [
        0x30, 0x80, 0xa0, 0x80, 0x01, 0x01, 0xff, 0, 0, 0xbe, 0x80, 0x02, 0x01, 0x04, 0, 0, 0xbf,
        0x1f, 0x80, 0x05, 0x00, 0, 0, 0xbf, 0x7f, 0x80, 0x0a, 0x01, 0x02, 0, 0, 0xbf, 0x81, 0x00,
        0x80, 0x01, 0x01, 0x00, 0, 0, 0, 0,
    ];

    assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(
        ExplicitRecord::decode_ber(&der, &limits).unwrap().value,
        value
    );
    assert_eq!(
        ExplicitRecord::decode_cer(&cer, &limits).unwrap().value,
        value
    );
    let packed = value.encode_uper(&limits).unwrap();
    assert_eq!(
        ExplicitRecord::decode_uper(&packed.bytes, &limits)
            .unwrap()
            .value,
        value
    );
}

/// Verify DEFAULT omission and resolved module tagging modes.
///
/// Parameters: none. Returns: no value; assertions compare values and bytes.
/// Errors: decoder failures are surfaced by the generated Result APIs.
/// Source: X.680 tagging defaults and X.690 record rules. Version/date:
/// 2026-11-01. Author: asn1c maintainers. History: EXPLICIT mode coverage.
/// Example: AUTOMATIC TAGS use the parser's resolved member tags.
#[test]
fn defaults_and_module_tagging_modes_use_fixed_tree_tags() {
    let limits = Limits::default();
    let defaults = ExplicitRecord {
        flag: false,
        count: 3,
        marker: None,
        state: ExplicitRecordState::Two,
        extra: None,
    };
    let der_defaults = [0x30, 0x06, 0xbf, 0x7f, 0x03, 0x0a, 0x01, 0x02];
    assert_eq!(defaults.encode_der(&limits).unwrap().bytes, der_defaults);
    assert_eq!(
        ExplicitRecord::decode_ber(&der_defaults, &limits)
            .unwrap()
            .value,
        defaults
    );

    let explicit_override = ExplicitImplicitRecord {
        flag: true,
        count: 4,
        plain: Some(false),
    };
    let override_der = [
        0x30, 0x0c, 0xbe, 0x03, 0x01, 0x01, 0xff, 0x9f, 0x1f, 0x01, 0x04, 0x01, 0x01, 0x00,
    ];
    assert_eq!(
        explicit_override.encode_der(&limits).unwrap().bytes,
        override_der
    );
    assert_eq!(
        ExplicitImplicitRecord::decode_ber(&override_der, &limits)
            .unwrap()
            .value,
        explicit_override
    );

    let automatic = ExplicitAutomaticRecord {
        flag: true,
        count: Some(4),
        marker: Some(()),
    };
    let automatic_der = [0x30, 0x08, 0x80, 0x01, 0xff, 0x81, 0x01, 0x04, 0x82, 0x00];
    assert_eq!(automatic.encode_der(&limits).unwrap().bytes, automatic_der);
    assert_eq!(
        ExplicitAutomaticRecord::decode_ber(&automatic_der, &limits)
            .unwrap()
            .value,
        automatic
    );
}

/// Check omission and emission of an explicit BOOLEAN DEFAULT TRUE.
///
/// Parameters: none. Returns: no value; DER/CER vectors are compared exactly.
/// Errors: generated decoder errors fail the test.
/// Source: X.680 DEFAULT and X.690 explicit-tag framing. Version/date:
/// 2026-11-01. Author: asn1c maintainers. History: explicit true-default test.
/// Example: FALSE is encoded under tag 30 while TRUE is omitted.
#[test]
fn explicit_true_default_is_omitted_and_nondefault_false_is_wrapped() {
    let limits = Limits::default();
    let default_value = ExplicitDefaultTrue { flag: true };
    let nondefault = ExplicitDefaultTrue { flag: false };
    let der_default = [0x30, 0x00];
    let cer_default = [0x30, 0x80, 0x00, 0x00];
    let der_nondefault = [0x30, 0x05, 0xbe, 0x03, 0x01, 0x01, 0x00];
    let cer_nondefault = [0x30, 0x80, 0xbe, 0x80, 0x01, 0x01, 0x00, 0, 0, 0, 0];

    assert_eq!(
        default_value.encode_der(&limits).unwrap().bytes,
        der_default
    );
    assert_eq!(
        default_value.encode_cer(&limits).unwrap().bytes,
        cer_default
    );
    assert_eq!(
        nondefault.encode_der(&limits).unwrap().bytes,
        der_nondefault
    );
    assert_eq!(
        nondefault.encode_cer(&limits).unwrap().bytes,
        cer_nondefault
    );
    assert_eq!(
        ExplicitDefaultTrue::decode_ber(&der_default, &limits)
            .unwrap()
            .value,
        default_value
    );
    assert_eq!(
        ExplicitDefaultTrue::decode_cer(&cer_nondefault, &limits)
            .unwrap()
            .value,
        nondefault
    );
}

/// Verify BER prefix decoding and reject malformed EXPLICIT wrappers.
///
/// Parameters: none. Returns: no value; assertions inspect prefix lengths.
/// Errors: invalid child count, child kind, truncation, or CER canonicality fail.
/// Source: X.690 constructed tagging. Version/date: 2026-11-01.
/// Author: asn1c maintainers. History: wrapper boundary regression.
/// Example: definite and indefinite wrappers each contain exactly one child.
#[test]
fn explicit_wrapper_boundaries_and_canonicality_are_checked() {
    let limits = Limits::default();
    let definite = [0x30, 0x05, 0xbe, 0x03, 0x01, 0x01, 0xff];
    let indefinite = [0x30, 0x80, 0xbe, 0x80, 0x01, 0x01, 0xff, 0, 0, 0, 0];
    let expected = ExplicitImplicitRecord {
        flag: true,
        count: 3,
        plain: None,
    };
    let with_suffix = [0x30, 0x05, 0xbe, 0x03, 0x01, 0x01, 0xff, 0xaa];
    let decoded = ExplicitImplicitRecord::decode_ber(&with_suffix, &limits).unwrap();
    assert_eq!(decoded.value, expected);
    assert_eq!(decoded.consumed_bytes, definite.len());
    assert_eq!(
        ExplicitImplicitRecord::decode_ber(&indefinite, &limits)
            .unwrap()
            .value,
        expected
    );
    assert!(ExplicitImplicitRecord::decode_cer(&definite, &limits).is_err());
    assert!(ExplicitImplicitRecord::decode_cer(&indefinite, &limits).is_ok());

    let wrong_child = [0x30, 0x04, 0xbe, 0x02, 0x05, 0x00];
    let primitive_wrapper = [0x30, 0x05, 0x9e, 0x03, 0x01, 0x01, 0xff];
    let multiple_children = [0x30, 0x07, 0xbe, 0x05, 0x01, 0x01, 0xff, 0x05, 0x00];
    let extra_child = [0x30, 0x08, 0xbe, 0x03, 0x01, 0x01, 0xff, 0x05, 0x00];
    let missing_wrapper_eoc = [0x30, 0x80, 0xbe, 0x80, 0x01, 0x01, 0xff, 0, 0];
    for malformed in [
        wrong_child.as_slice(),
        primitive_wrapper.as_slice(),
        multiple_children.as_slice(),
        extra_child.as_slice(),
        missing_wrapper_eoc.as_slice(),
    ] {
        assert!(ExplicitImplicitRecord::decode_ber(malformed, &limits).is_err());
    }
    for end in 0..definite.len() {
        assert!(ExplicitImplicitRecord::decode_ber(&definite[..end], &limits).is_err());
    }
    for end in 0..indefinite.len() {
        assert!(ExplicitImplicitRecord::decode_ber(&indefinite[..end], &limits).is_err());
    }
}

/// Verify explicit wrappers around CER-fragmented OCTET and BIT STRING roots.
///
/// Parameters: none. Returns: no value; assertions inspect canonical framing.
/// Errors: malformed fragments, bounds, and resource exhaustion return errors.
/// Source: X.690 CER string fragmentation. Version/date: 2026-11-01.
/// Author: asn1c maintainers. History: explicit string support.
/// Example: an explicit tag 31 contains a constructed CER OCTET STRING.
#[test]
fn explicit_strings_fragment_inside_their_outer_wrapper() {
    let limits = Limits::default();
    let value = ExplicitStringRecord {
        octets: vec![0x5a; 1001],
        bits: Some(BitStringValue::new(vec![0xa5; 1000], 8000).unwrap()),
    };
    let encoded = value.encode_cer(&limits).unwrap();
    assert_eq!(&encoded.bytes[..5], &[0x30, 0x80, 0xbf, 0x1f, 0x80]);
    assert!(encoded
        .bytes
        .windows(5)
        .any(|window| window == [0xbf, 0x81, 0x00, 0x80, 0x23]));
    assert_eq!(&encoded.bytes[encoded.bytes.len() - 4..], &[0, 0, 0, 0]);
    let decoded = ExplicitStringRecord::decode_cer(&encoded.bytes, &limits).unwrap();
    assert_eq!(decoded.value, value);
    assert_eq!(decoded.consumed_bytes, encoded.bytes.len());
    let mut with_suffix = encoded.bytes.clone();
    with_suffix.push(0xaa);
    assert_eq!(
        ExplicitStringRecord::decode_ber(&with_suffix, &limits)
            .unwrap()
            .consumed_bytes,
        encoded.bytes.len()
    );
    for end in 0..encoded.bytes.len() {
        assert!(ExplicitStringRecord::decode_cer(&encoded.bytes[..end], &limits).is_err());
    }
    let ber_constructed = [
        0x30, 0x80, 0xbf, 0x1f, 0x80, 0x24, 0x80, 0x04, 0x01, b'A', 0x04, 0x01, b'B', 0, 0, 0, 0,
        0, 0,
    ];
    let prefix = ExplicitStringRecord::decode_ber(&ber_constructed, &limits).unwrap();
    assert_eq!(prefix.value.octets, b"AB");
    assert_eq!(prefix.value.bits, None);
    assert_eq!(prefix.consumed_bytes, ber_constructed.len());
    assert!(ExplicitStringRecord::decode_cer(&ber_constructed, &limits).is_err());
    let tight = Limits {
        max_output_bytes: 8,
        ..limits
    };
    assert!(matches!(
        value.encode_cer(&tight),
        Err(Error::LimitExceeded {
            resource: Resource::OutputBytes,
            ..
        })
    ));
    let no_input = Limits {
        max_input_bytes: 1,
        ..limits
    };
    assert!(matches!(
        ExplicitStringRecord::decode_cer(&encoded.bytes, &no_input),
        Err(Error::LimitExceeded {
            resource: Resource::InputBytes,
            ..
        })
    ));
    let no_work = Limits {
        max_work_bits: 0,
        ..limits
    };
    assert!(matches!(
        ExplicitStringRecord::decode_cer(&encoded.bytes, &no_work),
        Err(Error::LimitExceeded {
            resource: Resource::WorkBits,
            ..
        })
    ));
}
