//! DER selected-tag and CER minimum-tag ordering for natural CHOICE in SET.

use asn1c_generated::natural_choice_set::{Values, ValuesChoice, ValuesMarker};
use asn1c_runtime::Limits;

/// Compare all selected and absent values with live C DER/CER vectors.
/// Source: `NaturalChoiceSet.asn1` and `c_natural_choice_set.c`. Version/date:
/// 2026-11-01. Inputs: none. Returns: unit. Errors: byte/value mismatches fail.
/// Responsible party: asn1c maintainers. History: natural CHOICE SET stage.
/// Example: `cargo test selected_choice_uses_der_and_cer_order_keys`.
#[test]
fn selected_choice_uses_der_and_cer_order_keys() {
    let limits = Limits::default();
    let cases: [(Option<ValuesChoice>, &[u8], &[u8]); 4] = [
        (
            Some(ValuesChoice::Flag(true)),
            &[
                0x31, 0x0c, 0x01, 0x01, 0xff, 0x04, 0x01, 0xaa, 0x0a, 0x01, 0x01, 0x80, 0x01, 0xff,
            ],
            &[
                0x31, 0x80, 0x01, 0x01, 0xff, 0x04, 0x01, 0xaa, 0x0a, 0x01, 0x01, 0x80, 0x01, 0xff,
                0, 0,
            ],
        ),
        (
            Some(ValuesChoice::Nothing),
            &[
                0x31, 0x0b, 0x04, 0x01, 0xaa, 0x05, 0x00, 0x0a, 0x01, 0x01, 0x80, 0x01, 0xff,
            ],
            &[
                0x31, 0x80, 0x05, 0x00, 0x04, 0x01, 0xaa, 0x0a, 0x01, 0x01, 0x80, 0x01, 0xff, 0, 0,
            ],
        ),
        (
            Some(ValuesChoice::Count(2)),
            &[
                0x31, 0x0c, 0x02, 0x01, 0x02, 0x04, 0x01, 0xaa, 0x0a, 0x01, 0x01, 0x80, 0x01, 0xff,
            ],
            &[
                0x31, 0x80, 0x02, 0x01, 0x02, 0x04, 0x01, 0xaa, 0x0a, 0x01, 0x01, 0x80, 0x01, 0xff,
                0, 0,
            ],
        ),
        (
            None,
            &[
                0x31, 0x09, 0x04, 0x01, 0xaa, 0x0a, 0x01, 0x01, 0x80, 0x01, 0xff,
            ],
            &[
                0x31, 0x80, 0x04, 0x01, 0xaa, 0x0a, 0x01, 0x01, 0x80, 0x01, 0xff, 0, 0,
            ],
        ),
    ];
    for (choice, definite_wire, canonical_wire) in cases {
        let value = Values {
            choice,
            octets: vec![0xaa],
            marker: ValuesMarker::One,
            after: true,
        };
        assert_eq!(value.encode_der(&limits).unwrap().bytes, definite_wire);
        assert_eq!(value.encode_cer(&limits).unwrap().bytes, canonical_wire);
        assert_eq!(
            Values::decode_ber(definite_wire, &limits).unwrap().value,
            value
        );
        assert_eq!(
            Values::decode_ber(canonical_wire, &limits).unwrap().value,
            value
        );
        assert_eq!(
            Values::decode_cer(canonical_wire, &limits).unwrap().value,
            value
        );
        assert!(Values::decode_cer(definite_wire, &limits).is_err());
    }
}

/// Check BER permutations/aliases, strict CER, and exact suffix consumption.
/// Source: C probes in `c_natural_choice_set.c`. Version/date: 2026-11-01.
/// Inputs: none. Returns: unit. Errors: decoded values and prefixes are checked.
/// Responsible party: asn1c maintainers. History: SET logical-choice dispatch.
/// Example: BER accepts reversed fields while strict CER rejects the prefix.
#[test]
fn unordered_ber_choice_and_canonical_cer_prefix() {
    let limits = Limits::default();
    let expected = Values {
        choice: Some(ValuesChoice::Nothing),
        octets: vec![0xaa],
        marker: ValuesMarker::One,
        after: true,
    };
    let reversed = [
        0x31, 0x80, 0x04, 0x01, 0xaa, 0x05, 0x00, 0x0a, 0x01, 0x01, 0x80, 0x01, 0xff, 0, 0,
    ];
    let decoded = Values::decode_ber(&reversed, &limits).unwrap();
    assert_eq!(decoded.value, expected);
    assert_eq!(decoded.consumed_bytes, reversed.len());
    assert!(Values::decode_cer(&reversed, &limits).is_err());

    let alias = [
        0x31, 0x80, 0x04, 0x01, 0xaa, 0x1f, 0x05, 0x00, 0x0a, 0x01, 0x01, 0x80, 0x01, 0xff, 0, 0,
    ];
    let decoded = Values::decode_ber(&alias, &limits).unwrap();
    assert_eq!(decoded.value, expected);
    assert_eq!(decoded.consumed_bytes, alias.len());
    assert!(Values::decode_cer(&alias, &limits).is_err());

    let canonical = expected.encode_cer(&limits).unwrap().bytes;
    let mut suffixed = canonical.clone();
    suffixed.push(0xaa);
    let decoded = Values::decode_cer(&suffixed, &limits).unwrap();
    assert_eq!(decoded.value, expected);
    assert_eq!(decoded.consumed_bytes, canonical.len());
    assert_eq!(decoded.consumed_bits, canonical.len() * 8);
}

/// Reject duplicate logical alternatives, malformed frames, and exhausted limits.
/// Source: X.690 SET/CHOICE scanner and runtime limits. Version/date: 2026-11-01.
/// Inputs: none. Returns: unit. Errors: each malformed prefix must fail.
/// Responsible party: asn1c maintainers. History: natural CHOICE SET validation.
/// Example: a second distinct arm cannot fill the already selected CHOICE slot.
#[test]
fn duplicate_malformed_and_limit_inputs_fail() {
    let limits = Limits::default();
    let duplicate_arms = [
        0x31, 0x80, 0x01, 0x01, 0xff, 0x05, 0x00, 0x04, 0x01, 0xaa, 0x0a, 0x01, 0x01, 0x80, 0x01,
        0xff, 0, 0,
    ];
    assert!(Values::decode_ber(&duplicate_arms, &limits).is_err());
    assert!(Values::decode_cer(&duplicate_arms, &limits).is_err());
    for malformed in [
        &[0x31, 0x80, 0x04, 0x01, 0xaa, 0, 0][..],
        &[0x31, 0x80, 0x05, 0x00, 0x04, 0x01, 0xaa][..],
        &[0x31, 0x03, 0x04, 0x01, 0xaa][..],
        &[0x31, 0x80, 0x03, 0x01, 0x00, 0, 0][..],
    ] {
        assert!(Values::decode_ber(malformed, &limits).is_err());
        assert!(Values::decode_cer(malformed, &limits).is_err());
    }

    let canonical = Values {
        choice: Some(ValuesChoice::Nothing),
        octets: vec![0xaa],
        marker: ValuesMarker::One,
        after: true,
    }
    .encode_cer(&limits)
    .unwrap()
    .bytes;
    for end in 0..canonical.len() {
        assert!(Values::decode_ber(&canonical[..end], &limits).is_err());
    }
    let small_input = Limits {
        max_input_bytes: canonical.len() - 1,
        ..limits
    };
    assert!(Values::decode_ber(&canonical, &small_input).is_err());
    let small_output = Limits {
        max_output_bytes: canonical.len() - 1,
        ..limits
    };
    assert!(Values {
        choice: Some(ValuesChoice::Nothing),
        octets: vec![0xaa],
        marker: ValuesMarker::One,
        after: true,
    }
    .encode_cer(&small_output)
    .is_err());
    assert!(Values {
        choice: Some(ValuesChoice::Count(6)),
        octets: vec![0xaa],
        marker: ValuesMarker::One,
        after: true,
    }
    .encode_der(&limits)
    .is_err());
}
