//! Conformance tests for a context-specific IMPLICIT SET root tag.

use asn1c_generated::tagged_root_set::{
    RootDefault, RootEmpty, RootMixed, RootOptional, RootTag0, RootTag127, RootTag30, RootTag31,
    RootTagMax, RootTagged,
};
use asn1c_runtime::{Error, Limits, Resource};

/// Verify SET sorting, unordered BER dispatch, and high root-tag boundaries.
///
/// Parameters: none. Returns: no value; fixed vectors and decoded values are asserted.
/// Errors: malformed or noncanonical records return runtime errors.
/// Source: X.680 SET tagging and X.690 BER/DER/CER framing. Version/date: 2026-11-01.
/// Author: asn1c maintainers. History: tagged SET root slice. Example: tag 3 wraps reordered fields.
#[test]
fn tagged_set_root_sorts_canonical_content_and_accepts_ber_order() {
    let limits = Limits::default();
    let value = RootTagged { y: true, x: 2 };
    let der = [0xa3, 6, 0x80, 1, 2, 0x81, 1, 0xff];
    let cer = [0xa3, 0x80, 0x80, 1, 2, 0x81, 1, 0xff, 0, 0];
    let reversed_ber = [0xa3, 6, 0x81, 1, 0xff, 0x80, 1, 2];
    let reversed_indefinite = [0xa3, 0x80, 0x81, 1, 0xff, 0x80, 1, 2, 0, 0];

    assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(RootTagged::decode_ber(&der, &limits).unwrap().value, value);
    assert_eq!(
        RootTagged::decode_ber(&reversed_ber, &limits)
            .unwrap()
            .value,
        value
    );
    assert_eq!(
        RootTagged::decode_ber(&reversed_indefinite, &limits)
            .unwrap()
            .value,
        value
    );
    assert_eq!(RootTagged::decode_cer(&cer, &limits).unwrap().value, value);
    assert!(RootTagged::decode_cer(&der, &limits).is_err());
    assert!(RootTagged::decode_cer(&reversed_ber, &limits).is_err());
    assert!(RootTagged::decode_cer(&reversed_indefinite, &limits).is_err());

    let mixed = RootMixed {
        y: true,
        a: 3,
        x: 2,
    };
    let mixed_definite = [0xa3, 9, 2, 1, 3, 0x80, 1, 2, 0x81, 1, 0xff];
    let mixed_indefinite = [0xa3, 0x80, 2, 1, 3, 0x80, 1, 2, 0x81, 1, 0xff, 0, 0];
    assert_eq!(mixed.encode_der(&limits).unwrap().bytes, mixed_definite);
    assert_eq!(mixed.encode_cer(&limits).unwrap().bytes, mixed_indefinite);
    assert_eq!(
        RootMixed::decode_ber(&mixed_definite, &limits)
            .unwrap()
            .value,
        mixed
    );
    assert_eq!(
        RootMixed::decode_cer(&mixed_indefinite, &limits)
            .unwrap()
            .value,
        mixed
    );

    macro_rules! check_root_tag {
        ($value:expr, $type:ty, $der:expr, $cer:expr) => {{
            let value = $value;
            let der: &[u8] = $der;
            let cer: &[u8] = $cer;
            assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
            assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
            assert_eq!(<$type>::decode_ber(der, &limits).unwrap().value, value);
            assert_eq!(<$type>::decode_cer(cer, &limits).unwrap().value, value);
            let mut suffixed = der.to_vec();
            suffixed.push(0xaa);
            let decoded = <$type>::decode_ber(&suffixed, &limits).unwrap();
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

/// Preserve empty, OPTIONAL, and DEFAULT SET fields beneath the tagged root.
///
/// Parameters: none. Returns: no value; exact framing and substituted values are checked.
/// Errors: malformed or noncanonical encodings are returned by generated codecs.
/// Source: X.680 SET presence and DEFAULT rules. Version/date: 2026-11-01.
/// Author: asn1c maintainers. History: tagged SET root components. Example: omitted DEFAULT 2.
#[test]
fn empty_optional_and_default_tagged_sets_roundtrip() {
    let limits = Limits::default();
    let empty_definite = [0xa4, 0];
    let empty_indefinite = [0xa4, 0x80, 0, 0];
    let optional_absent = [0xa5, 0];
    let optional_present = [0xa5, 3, 0x80, 1, 2];
    let default_omitted = [0xa6, 0];
    let default_present = [0xa6, 3, 0x80, 1, 3];

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
    assert_eq!(absent.encode_der(&limits).unwrap().bytes, optional_absent);
    assert_eq!(present.encode_der(&limits).unwrap().bytes, optional_present);
    assert_eq!(
        RootOptional::decode_ber(&optional_absent, &limits)
            .unwrap()
            .value,
        absent
    );
    assert_eq!(
        RootOptional::decode_ber(&optional_present, &limits)
            .unwrap()
            .value,
        present
    );

    let default = RootDefault { x: 2 };
    let nondefault = RootDefault { x: 3 };
    assert_eq!(default.encode_der(&limits).unwrap().bytes, default_omitted);
    assert_eq!(
        nondefault.encode_der(&limits).unwrap().bytes,
        default_present
    );
    assert_eq!(
        RootDefault::decode_ber(&default_omitted, &limits)
            .unwrap()
            .value,
        default
    );
    assert_eq!(
        RootDefault::decode_ber(&default_present, &limits)
            .unwrap()
            .value,
        nondefault
    );
}

/// Reject malformed SET roots and check nonminimal root-tag aliases.
///
/// Parameters: none. Returns: no value; BER aliases decode, strict CER rejects them.
/// Errors: invalid roots, children, EOCs, order, and lengths return runtime errors.
/// Source: X.690 SET dispatch and CER canonical re-encoding. Version/date: 2026-11-01.
/// Author: asn1c maintainers. History: hostile tagged SET inputs. Example: `bf 03` aliases tag 3.
#[test]
fn malformed_tagged_set_roots_and_nonminimal_aliases_are_checked() {
    let limits = Limits::default();
    let alias = [0xbf, 3, 6, 0x80, 1, 2, 0x81, 1, 0xff];
    let indefinite_alias = [0xbf, 3, 0x80, 0x80, 1, 2, 0x81, 1, 0xff, 0, 0];
    let high_tag_alias = [0xbf, 0x80, 0x1f, 0x80, 2, 1, 2, 0, 0];
    assert_eq!(
        RootTagged::decode_ber(&alias, &limits).unwrap().value,
        RootTagged { y: true, x: 2 }
    );
    assert!(RootTagged::decode_cer(&alias, &limits).is_err());
    assert_eq!(
        RootTagged::decode_ber(&indefinite_alias, &limits)
            .unwrap()
            .value,
        RootTagged { y: true, x: 2 }
    );
    assert!(RootTagged::decode_cer(&indefinite_alias, &limits).is_err());
    assert_eq!(
        RootTag31::decode_ber(&high_tag_alias, &limits)
            .unwrap()
            .value,
        RootTag31 { x: 2 }
    );
    assert!(RootTag31::decode_cer(&high_tag_alias, &limits).is_err());

    let invalid: [&[u8]; 9] = [
        &[0x83, 6, 0x80, 1, 2, 0x81, 1, 0xff],
        &[0xa4, 6, 0x80, 1, 2, 0x81, 1, 0xff],
        &[0xa3, 0x80, 0x80, 1, 2, 0x81, 1, 0xff],
        &[0xa3, 0x80, 0, 0, 0x80, 1, 2],
        &[0xa3, 6, 0x80, 1, 2, 0x81, 1],
        &[0xa3, 0x80, 0x81, 1, 0xff, 0x80, 1, 2, 0],
        &[0xa3, 0x80, 0x81, 1, 0xff, 0x80, 1, 2, 0, 1],
        &[0xa3, 0x80, 0x82, 1, 1, 0x80, 1, 2, 0x81, 1, 0xff, 0, 0],
        &[0xa3, 0x80, 0x80, 1, 2, 0x80, 1, 2, 0x81, 1, 0xff, 0, 0],
    ];
    for wire in invalid {
        assert!(RootTagged::decode_ber(wire, &limits).is_err());
        assert!(RootTagged::decode_cer(wire, &limits).is_err());
    }
}

/// Apply input, output, and work ceilings to complete tagged SET operations.
///
/// Parameters: none. Returns: no value; each over-limit operation is asserted.
/// Errors: input/output/work excess must surface as runtime errors.
/// Source: shared BER/CER `RecordContext`. Version/date: 2026-11-01.
/// Author: asn1c maintainers. History: tagged SET root limits. Example: cap input at 7 bytes.
#[test]
fn tagged_set_root_obeys_input_output_and_work_limits() {
    let value = RootTagged { y: true, x: 2 };
    let wire = [0xa3, 6, 0x80, 1, 2, 0x81, 1, 0xff];
    let small_input = Limits {
        max_input_bytes: 7,
        ..Limits::default()
    };
    let small_output = Limits {
        max_output_bytes: 7,
        ..Limits::default()
    };
    let no_work = Limits {
        max_work_bits: 0,
        ..Limits::default()
    };

    assert!(matches!(
        RootTagged::decode_ber(&wire, &small_input),
        Err(Error::LimitExceeded {
            resource: Resource::InputBytes,
            ..
        })
    ));
    assert!(matches!(
        value.encode_der(&small_output),
        Err(Error::LimitExceeded {
            resource: Resource::OutputBytes,
            ..
        })
    ));
    assert!(RootTagged::decode_ber(&wire, &no_work).is_err());
}
