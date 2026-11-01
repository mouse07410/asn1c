//! BER/DER/CER coverage for same-module named bounded INTEGER fields.

use asn1c_generated::named_integer_record::{
    Sequence, SequenceBits, SequenceExplicit, SequenceImplicit, SequenceOptional, Set, SetExplicit,
    SetImplicit, SetOptional, Small,
};
use asn1c_runtime::{BitStringValue, Limits};

/// Verify the public named newtype constructor enforces the target INTEGER range.
///
/// Inputs: none. Returns no value. Errors are assertion failures.
/// Source: generated `Small ::= INTEGER (0..5)`. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: named INTEGER field gate.
/// Example: `Small::new(2)` succeeds and `Small::new(6)` fails.
#[test]
fn named_integer_constructor_enforces_target_range() {
    assert_eq!(Small::new(2).unwrap().value(), 2);
    assert!(Small::new(-1).is_err());
    assert!(Small::new(6).is_err());
}

/// Compare natural SEQUENCE DER/CER bytes, decoded values, and prefix lengths.
///
/// Inputs: none. Returns no value. Errors are codec or assertion failures.
/// Source: live generated C vectors and X.690. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: natural named field parity.
/// Example: BOOLEAN, Small, and one OCTET STRING preserve declaration order.
#[test]
fn natural_sequence_matches_der_cer_and_prefix_vectors() {
    let limits = Limits::default();
    let value = Sequence {
        flag: true,
        value: Small::new(2).unwrap(),
        tail: vec![0xaa],
    };
    let der = [
        0x30, 0x09, 0x01, 0x01, 0xff, 0x02, 0x01, 0x02, 0x04, 0x01, 0xaa,
    ];
    let cer = [
        0x30, 0x80, 0x01, 0x01, 0xff, 0x02, 0x01, 0x02, 0x04, 0x01, 0xaa, 0, 0,
    ];
    assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(Sequence::decode_ber(&der, &limits).unwrap().value, value);
    assert_eq!(Sequence::decode_ber(&cer, &limits).unwrap().value, value);
    assert!(Sequence::decode_cer(&der, &limits).is_err());
    let mut suffixed = cer.to_vec();
    suffixed.push(0x5a);
    let decoded = Sequence::decode_cer(&suffixed, &limits).unwrap();
    assert_eq!(decoded.value, value);
    assert_eq!(decoded.consumed_bytes, cer.len());
    assert_eq!(decoded.consumed_bits, cer.len() * 8);
}

/// Keep an existing bounded BIT STRING sibling available beside the named field.
///
/// Inputs: none. Returns no value. Errors are codec or assertion failures.
/// Source: live C vector and the approved scalar-sibling gate.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: bounded BIT STRING coexistence. Example: five meaningful bits encode as `a0`.
#[test]
fn bounded_bit_string_sibling_uses_shared_record_codec() {
    let limits = Limits::default();
    let value = SequenceBits {
        value: Small::new(2).unwrap(),
        bits: BitStringValue::new(vec![0xa0], 5).unwrap(),
    };
    let der = [0x30, 0x07, 0x02, 0x01, 0x02, 0x03, 0x02, 0x03, 0xa0];
    let cer = [0x30, 0x80, 0x02, 0x01, 0x02, 0x03, 0x02, 0x03, 0xa0, 0, 0];
    assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(
        SequenceBits::decode_ber(&der, &limits).unwrap().value,
        value
    );
    assert_eq!(
        SequenceBits::decode_cer(&cer, &limits).unwrap().value,
        value
    );
}

/// Check OPTIONAL presence and one resolved IMPLICIT or EXPLICIT member tag.
///
/// Inputs: none. Returns no value. Errors are codec or assertion failures.
/// Source: live C vectors and X.680/X.690 tagging. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: named tag-mode coverage.
/// Example: context tag 3 replaces the INTEGER tag for IMPLICIT encoding.
#[test]
fn optional_implicit_and_explicit_sequence_fields_round_trip() {
    let limits = Limits::default();
    let absent = SequenceOptional {
        value: None,
        flag: true,
    };
    let absent_definite = [0x30, 0x03, 0x01, 0x01, 0xff];
    let absent_canonical = [0x30, 0x80, 0x01, 0x01, 0xff, 0, 0];
    assert_eq!(absent.encode_der(&limits).unwrap().bytes, absent_definite);
    assert_eq!(absent.encode_cer(&limits).unwrap().bytes, absent_canonical);
    assert_eq!(
        SequenceOptional::decode_cer(&absent_canonical, &limits)
            .unwrap()
            .value,
        absent
    );

    let present = SequenceOptional {
        value: Some(Small::new(2).unwrap()),
        flag: true,
    };
    let present_der = [0x30, 0x06, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff];
    assert_eq!(present.encode_der(&limits).unwrap().bytes, present_der);
    assert_eq!(
        SequenceOptional::decode_ber(&present_der, &limits)
            .unwrap()
            .value,
        present
    );

    let implicit = SequenceImplicit {
        value: Small::new(2).unwrap(),
        flag: true,
    };
    let implicit_definite = [0x30, 0x06, 0x83, 0x01, 0x02, 0x01, 0x01, 0xff];
    let implicit_canonical = [0x30, 0x80, 0x83, 0x01, 0x02, 0x01, 0x01, 0xff, 0, 0];
    assert_eq!(
        implicit.encode_der(&limits).unwrap().bytes,
        implicit_definite
    );
    assert_eq!(
        implicit.encode_cer(&limits).unwrap().bytes,
        implicit_canonical
    );
    assert_eq!(
        SequenceImplicit::decode_cer(&implicit_canonical, &limits)
            .unwrap()
            .value,
        implicit
    );

    let explicit = SequenceExplicit {
        value: Some(Small::new(2).unwrap()),
        flag: true,
    };
    let explicit_definite = [0x30, 0x08, 0xa3, 0x03, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff];
    let explicit_canonical = [
        0x30, 0x80, 0xa3, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x01, 0x01, 0xff, 0, 0,
    ];
    assert_eq!(
        explicit.encode_der(&limits).unwrap().bytes,
        explicit_definite
    );
    assert_eq!(
        explicit.encode_cer(&limits).unwrap().bytes,
        explicit_canonical
    );
    assert_eq!(
        SequenceExplicit::decode_cer(&explicit_canonical, &limits)
            .unwrap()
            .value,
        explicit
    );
}

/// Verify natural SET ordering, optional presence, and unordered BER input.
///
/// Inputs: none. Returns no value. Errors are codec or assertion failures.
/// Source: live generated C vectors and X.690 SET order. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: natural named SET parity.
/// Example: universal BOOLEAN/INTEGER/OCTET tags sort in numeric order.
#[test]
fn set_fields_sort_by_effective_tag_and_decode_unordered_ber() {
    let limits = Limits::default();
    let value = Set {
        flag: true,
        value: Small::new(2).unwrap(),
        tail: vec![0xaa],
    };
    let der = [
        0x31, 0x09, 0x01, 0x01, 0xff, 0x02, 0x01, 0x02, 0x04, 0x01, 0xaa,
    ];
    let cer = [
        0x31, 0x80, 0x01, 0x01, 0xff, 0x02, 0x01, 0x02, 0x04, 0x01, 0xaa, 0, 0,
    ];
    assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(Set::decode_ber(&der, &limits).unwrap().value, value);
    let reversed = [
        0x31, 0x80, 0x04, 0x01, 0xaa, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0, 0,
    ];
    assert_eq!(Set::decode_ber(&reversed, &limits).unwrap().value, value);
    assert!(Set::decode_cer(&reversed, &limits).is_err());

    let absent = SetOptional {
        tail: vec![0xaa],
        value: None,
        flag: true,
    };
    let absent_der = [0x31, 0x06, 0x01, 0x01, 0xff, 0x04, 0x01, 0xaa];
    assert_eq!(absent.encode_der(&limits).unwrap().bytes, absent_der);
    assert_eq!(
        SetOptional::decode_ber(&absent_der, &limits).unwrap().value,
        absent
    );
    let present = SetOptional {
        tail: vec![0xaa],
        value: Some(Small::new(2).unwrap()),
        flag: true,
    };
    let present_der = [
        0x31, 0x09, 0x01, 0x01, 0xff, 0x02, 0x01, 0x02, 0x04, 0x01, 0xaa,
    ];
    assert_eq!(present.encode_der(&limits).unwrap().bytes, present_der);
    assert_eq!(
        SetOptional::decode_ber(&present_der, &limits)
            .unwrap()
            .value,
        present
    );
}

/// Verify implicit and explicit named INTEGER SET field forms.
///
/// Inputs: none. Returns no value. Errors are codec or assertion failures.
/// Source: live generated C vectors and X.690 SET order. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: tagged named SET parity.
/// Example: context tag 3 sorts after the universal BOOLEAN field.
#[test]
fn tagged_set_fields_preserve_effective_tag_order() {
    let limits = Limits::default();
    let implicit = SetImplicit {
        value: Small::new(2).unwrap(),
        flag: true,
    };
    let implicit_der = [0x31, 0x06, 0x01, 0x01, 0xff, 0x83, 0x01, 0x02];
    let implicit_canonical = [0x31, 0x80, 0x01, 0x01, 0xff, 0x83, 0x01, 0x02, 0, 0];
    assert_eq!(implicit.encode_der(&limits).unwrap().bytes, implicit_der);
    assert_eq!(
        implicit.encode_cer(&limits).unwrap().bytes,
        implicit_canonical
    );
    assert_eq!(
        SetImplicit::decode_ber(&implicit_der, &limits)
            .unwrap()
            .value,
        implicit
    );
    assert_eq!(
        SetImplicit::decode_cer(&implicit_canonical, &limits)
            .unwrap()
            .value,
        implicit
    );

    let explicit = SetExplicit {
        value: Some(Small::new(2).unwrap()),
        flag: true,
    };
    let explicit_der = [0x31, 0x08, 0x01, 0x01, 0xff, 0xa3, 0x03, 0x02, 0x01, 0x02];
    let explicit_canonical = [
        0x31, 0x80, 0x01, 0x01, 0xff, 0xa3, 0x80, 0x02, 0x01, 0x02, 0, 0, 0, 0,
    ];
    assert_eq!(explicit.encode_der(&limits).unwrap().bytes, explicit_der);
    assert_eq!(
        explicit.encode_cer(&limits).unwrap().bytes,
        explicit_canonical
    );
    assert_eq!(
        SetExplicit::decode_ber(&explicit_der, &limits)
            .unwrap()
            .value,
        explicit
    );
    assert_eq!(
        SetExplicit::decode_cer(&explicit_canonical, &limits)
            .unwrap()
            .value,
        explicit
    );
    let explicit_absent = SetExplicit {
        value: None,
        flag: true,
    };
    let explicit_absent_canonical = [0x31, 0x80, 0x01, 0x01, 0xff, 0, 0];
    assert_eq!(
        explicit_absent.encode_cer(&limits).unwrap().bytes,
        explicit_absent_canonical
    );
    assert_eq!(
        SetExplicit::decode_cer(&explicit_absent_canonical, &limits)
            .unwrap()
            .value,
        explicit_absent
    );
}

/// Accept a nonminimal implicit high-tag alias in BER and reject it in CER.
///
/// Inputs: one valid tag-3 field encoded with a high-tag alias.
/// Returns no value. Errors are codec or assertion failures.
/// Source: X.690 identifier canonicality and live C behavior.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: named implicit INTEGER tag canonicality. Example: `9f 03` aliases `83`.
#[test]
fn implicit_high_tag_alias_is_ber_only() {
    let limits = Limits::default();
    let expected = SequenceImplicit {
        value: Small::new(2).unwrap(),
        flag: true,
    };
    let alias = [0x30, 0x80, 0x9f, 0x03, 0x01, 0x02, 0x01, 0x01, 0xff, 0, 0];
    assert_eq!(
        SequenceImplicit::decode_ber(&alias, &limits).unwrap().value,
        expected
    );
    assert!(SequenceImplicit::decode_cer(&alias, &limits).is_err());
    let constructed_implicit = [0x30, 0x06, 0xa3, 0x01, 0x02, 0x01, 0x01, 0xff];
    assert!(SequenceImplicit::decode_ber(&constructed_implicit, &limits).is_err());
}

/// Reject out-of-range values, malformed explicit children, and exhausted limits.
///
/// Inputs: fixed malformed BER/CER TLVs. Returns no value; failures are assertions.
/// Source: generated record decoders and runtime resource contract.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: hostile named INTEGER records. Example: integer 6 exceeds `0..=5`.
#[test]
fn malformed_values_and_resource_limits_fail_closed() {
    let limits = Limits::default();
    let invalid_range = [
        0x30, 0x09, 0x01, 0x01, 0xff, 0x02, 0x01, 0x06, 0x04, 0x01, 0xaa,
    ];
    assert!(Sequence::decode_ber(&invalid_range, &limits).is_err());
    let wrong_explicit_child = [0x30, 0x08, 0xa3, 0x03, 0x01, 0x01, 0xff, 0x01, 0x01, 0xff];
    assert!(SequenceExplicit::decode_ber(&wrong_explicit_child, &limits).is_err());
    let multiple_explicit_children = [
        0x30, 0x0b, 0xa3, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03, 0x01, 0x01, 0xff,
    ];
    assert!(SequenceExplicit::decode_ber(&multiple_explicit_children, &limits).is_err());

    let value = Sequence {
        flag: true,
        value: Small::new(2).unwrap(),
        tail: vec![0xaa],
    };
    let valid_wire = [
        0x30, 0x09, 0x01, 0x01, 0xff, 0x02, 0x01, 0x02, 0x04, 0x01, 0xaa,
    ];
    let input_limit = Limits {
        max_input_bytes: valid_wire.len() - 1,
        ..limits
    };
    assert!(Sequence::decode_ber(&valid_wire, &input_limit).is_err());
    let output_limit = Limits {
        max_output_bytes: 1,
        ..limits
    };
    assert!(value.encode_der(&output_limit).is_err());
    let der_budget_exact = Limits {
        max_work_bits: 112,
        ..limits
    };
    let der_budget_short = Limits {
        max_work_bits: 111,
        ..limits
    };
    assert!(value.encode_der(&der_budget_exact).is_ok());
    assert!(value.encode_der(&der_budget_short).is_err());
    let cer_budget_exact = Limits {
        max_work_bits: 128,
        ..limits
    };
    let cer_budget_short = Limits {
        max_work_bits: 127,
        ..limits
    };
    assert!(value.encode_cer(&cer_budget_exact).is_ok());
    assert!(value.encode_cer(&cer_budget_short).is_err());
    let exact_cer_decode = Limits {
        max_work_bits: 504,
        ..limits
    };
    let short_cer_decode = Limits {
        max_work_bits: 503,
        ..limits
    };
    let canonical = [
        0x30, 0x80, 0x01, 0x01, 0xff, 0x02, 0x01, 0x02, 0x04, 0x01, 0xaa, 0, 0,
    ];
    assert!(Sequence::decode_cer(&canonical, &exact_cer_decode).is_ok());
    assert!(Sequence::decode_cer(&canonical, &short_cer_decode).is_err());
    let work_limit = Limits {
        max_work_bits: 0,
        ..limits
    };
    assert!(Sequence::decode_ber(&invalid_range, &work_limit).is_err());
}
