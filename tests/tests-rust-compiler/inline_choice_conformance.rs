//! BER/DER/CER conformance for one inline primitive CHOICE in a record.

use asn1c_generated::inline_choice_children::{
    SequenceExplicit, SequenceExplicitChoice, SequenceNatural, SequenceNaturalChoice,
    SequenceOptional, SequenceOptionalChoice, SetExplicit, SetExplicitChoice, SetOptional,
    SetOptionalChoice,
};
use asn1c_runtime::Limits;

/// Compare natural CHOICE arms against their primitive C TLVs.
/// Source: generated `SequenceNatural` descriptor and X.690. Version/date:
/// 2026-11-01. Inputs: none. Returns: unit. Errors: assertions identify codec
/// mismatches. Responsible party: asn1c maintainers. History: inline CHOICE.
/// Example: `cargo test sequence_natural_choice_vectors`.
#[test]
fn sequence_natural_choice_vectors() {
    let limits = Limits::default();
    let cases = [
        (
            SequenceNatural {
                choice: SequenceNaturalChoice::Flag(true),
                after: true,
            },
            vec![0x30, 0x06, 0x01, 0x01, 0xff, 0x84, 0x01, 0xff],
            vec![0x30, 0x80, 0x01, 0x01, 0xff, 0x84, 0x01, 0xff, 0, 0],
        ),
        (
            SequenceNatural {
                choice: SequenceNaturalChoice::Nothing,
                after: true,
            },
            vec![0x30, 0x05, 0x05, 0x00, 0x84, 0x01, 0xff],
            vec![0x30, 0x80, 0x05, 0x00, 0x84, 0x01, 0xff, 0, 0],
        ),
        (
            SequenceNatural {
                choice: SequenceNaturalChoice::Count(2),
                after: true,
            },
            vec![0x30, 0x06, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff],
            vec![0x30, 0x80, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff, 0, 0],
        ),
    ];
    for (value, der, cer) in cases {
        assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
        assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
        let ber = SequenceNatural::decode_ber(&der, &limits).unwrap();
        let strict = SequenceNatural::decode_cer(&cer, &limits).unwrap();
        assert_eq!(ber.value, value);
        assert_eq!(strict.value, value);
        assert_eq!(ber.consumed_bytes, der.len());
        assert_eq!(strict.consumed_bits, cer.len() * 8);
        assert!(SequenceNatural::decode_cer(&der, &limits).is_err());
    }
}

/// Compare natural OPTIONAL CHOICE presence and omission.
/// Source: generated `SequenceOptional` descriptor and C vectors.
/// Version/date: 2026-11-01. Inputs: none. Returns: unit. Errors: assertions
/// identify incorrect presence or prefix handling. Responsible party: asn1c.
/// History: inline CHOICE. Example: `cargo test sequence_optional_choice`.
#[test]
fn sequence_optional_choice() {
    let limits = Limits::default();
    let absent = SequenceOptional {
        before: 1,
        choice: None,
        after: true,
    };
    let absent_definite = [0x30, 0x06, 0x80, 0x01, 0x01, 0x84, 0x01, 0xff];
    let absent_indefinite = [0x30, 0x80, 0x80, 0x01, 0x01, 0x84, 0x01, 0xff, 0, 0];
    assert_eq!(absent.encode_der(&limits).unwrap().bytes, absent_definite);
    assert_eq!(absent.encode_cer(&limits).unwrap().bytes, absent_indefinite);
    assert_eq!(
        SequenceOptional::decode_ber(&absent_definite, &limits)
            .unwrap()
            .value,
        absent
    );
    assert_eq!(
        SequenceOptional::decode_cer(&absent_indefinite, &limits)
            .unwrap()
            .value,
        absent
    );

    let present = SequenceOptional {
        before: 1,
        choice: Some(SequenceOptionalChoice::Count(2)),
        after: true,
    };
    let present_definite = [
        0x30, 0x09, 0x80, 0x01, 0x01, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff,
    ];
    let present_indefinite = [
        0x30, 0x80, 0x80, 0x01, 0x01, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff, 0, 0,
    ];
    assert_eq!(present.encode_der(&limits).unwrap().bytes, present_definite);
    assert_eq!(
        present.encode_cer(&limits).unwrap().bytes,
        present_indefinite
    );
    assert_eq!(
        SequenceOptional::decode_ber(&present_definite, &limits)
            .unwrap()
            .value,
        present
    );
    assert_eq!(
        SequenceOptional::decode_cer(&present_indefinite, &limits)
            .unwrap()
            .value,
        present
    );
}

/// Verify EXPLICIT wrappers and SET's effective-tag order.
/// Source: generated `SequenceExplicit`/`SetExplicit` descriptors and C probes.
/// Version/date: 2026-11-01. Inputs: none. Returns: unit. Errors: exact byte or
/// value mismatches fail. Responsible party: asn1c maintainers. History: inline.
/// Example: `cargo test explicit_choice_wrappers_and_set_order`.
#[test]
fn explicit_choice_wrappers_and_set_order() {
    let limits = Limits::default();
    let sequence = SequenceExplicit {
        choice: SequenceExplicitChoice::Count(2),
        after: true,
    };
    let sequence_definite = [0x30, 0x08, 0xa3, 0x03, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff];
    let sequence_indefinite = [
        0x30, 0x80, 0xa3, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x84, 0x01, 0xff, 0, 0,
    ];
    assert_eq!(
        sequence.encode_der(&limits).unwrap().bytes,
        sequence_definite
    );
    assert_eq!(
        sequence.encode_cer(&limits).unwrap().bytes,
        sequence_indefinite
    );
    assert_eq!(
        SequenceExplicit::decode_ber(&sequence_definite, &limits)
            .unwrap()
            .value,
        sequence
    );
    assert_eq!(
        SequenceExplicit::decode_cer(&sequence_indefinite, &limits)
            .unwrap()
            .value,
        sequence
    );

    let set = SetExplicit {
        after: true,
        choice: SetExplicitChoice::Count(2),
    };
    let set_der = [0x31, 0x08, 0xa3, 0x03, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff];
    let set_cer = [
        0x31, 0x80, 0xa3, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x84, 0x01, 0xff, 0, 0,
    ];
    assert_eq!(set.encode_der(&limits).unwrap().bytes, set_der);
    assert_eq!(set.encode_cer(&limits).unwrap().bytes, set_cer);
    assert_eq!(
        SetExplicit::decode_ber(&set_der, &limits).unwrap().value,
        set
    );
    assert_eq!(
        SetExplicit::decode_cer(&set_cer, &limits).unwrap().value,
        set
    );
}

/// Verify OPTIONAL EXPLICIT CHOICE in SET keeps one logical slot.
/// Source: generated C `SetOptional` descriptor and live vectors.
/// Version/date: 2026-11-01. Inputs: none. Returns: unit. Errors: assertion
/// failures identify wrapper and omission mismatches. Responsible party: asn1c.
/// History: inline CHOICE. Example: `cargo test optional_set_choice`.
#[test]
fn optional_set_choice() {
    let limits = Limits::default();
    let absent = SetOptional {
        after: true,
        choice: None,
    };
    let absent_definite = [0x31, 0x03, 0x84, 0x01, 0xff];
    let absent_indefinite = [0x31, 0x80, 0x84, 0x01, 0xff, 0, 0];
    assert_eq!(absent.encode_der(&limits).unwrap().bytes, absent_definite);
    assert_eq!(absent.encode_cer(&limits).unwrap().bytes, absent_indefinite);
    assert_eq!(
        SetOptional::decode_ber(&absent_definite, &limits)
            .unwrap()
            .value,
        absent
    );
    assert_eq!(
        SetOptional::decode_cer(&absent_indefinite, &limits)
            .unwrap()
            .value,
        absent
    );

    let present = SetOptional {
        after: true,
        choice: Some(SetOptionalChoice::Nothing),
    };
    let present_definite = [0x31, 0x07, 0xa3, 0x02, 0x05, 0x00, 0x84, 0x01, 0xff];
    let present_indefinite = [
        0x31, 0x80, 0xa3, 0x80, 0x05, 0x00, 0, 0, 0x84, 0x01, 0xff, 0, 0,
    ];
    assert_eq!(present.encode_der(&limits).unwrap().bytes, present_definite);
    assert_eq!(
        present.encode_cer(&limits).unwrap().bytes,
        present_indefinite
    );
    assert_eq!(
        SetOptional::decode_ber(&present_definite, &limits)
            .unwrap()
            .value,
        present
    );
    assert_eq!(
        SetOptional::decode_cer(&present_indefinite, &limits)
            .unwrap()
            .value,
        present
    );
}

/// Test valid BER aliases, suffixes, malformed wrappers, and operation limits.
/// Source: X.690 primitive CHOICE dispatch and shared record context.
/// Version/date: 2026-11-01. Inputs: none. Returns: unit. Errors: failed
/// assertions expose boundary regressions. Responsible party: asn1c maintainers.
/// History: inline CHOICE hardening. Example: `cargo test aliases_and_limits`.
#[test]
fn aliases_malformed_and_limits() {
    let limits = Limits::default();
    let alias = [0x30, 0x07, 0x1f, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff];
    let decoded = SequenceNatural::decode_ber(&alias, &limits).unwrap();
    assert_eq!(decoded.value.choice, SequenceNaturalChoice::Count(2));
    assert_eq!(decoded.consumed_bytes, alias.len());
    assert!(SequenceNatural::decode_cer(&alias, &limits).is_err());

    let suffix = [0x30, 0x06, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff, 0xaa];
    let decoded = SequenceNatural::decode_ber(&suffix, &limits).unwrap();
    assert_eq!(decoded.consumed_bytes, 8);
    assert_eq!(decoded.consumed_bits, 64);
    assert_eq!(decoded.value.choice, SequenceNaturalChoice::Count(2));
    let canonical_cer = [0x30, 0x80, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff, 0, 0, 0xaa];
    let strict = SequenceNatural::decode_cer(&canonical_cer, &limits).unwrap();
    assert_eq!(strict.consumed_bytes, 10);
    assert_eq!(strict.consumed_bits, 80);
    assert_eq!(strict.value.choice, SequenceNaturalChoice::Count(2));

    for wire in [
        &[0x30, 0x03, 0xa3, 0x01, 0x00][..],
        &[0x30, 0x08, 0xa3, 0x05, 0x02, 0x01, 0x02, 0x05, 0x00][..],
        &[0x30, 0x05, 0x03, 0x01, 0x00, 0x84, 0x01, 0xff][..],
        &[0x30, 0x06, 0x02, 0x01, 0x06, 0x84, 0x01, 0xff][..],
    ] {
        assert!(SequenceExplicit::decode_ber(wire, &limits).is_err());
        assert!(SequenceExplicit::decode_cer(wire, &limits).is_err());
    }
    let boolean_empty = [0x30, 0x05, 0x01, 0x00, 0x84, 0x01, 0xff];
    let decoded = SequenceNatural::decode_ber(&boolean_empty, &limits).unwrap();
    assert_eq!(decoded.value.choice, SequenceNaturalChoice::Flag(false));
    assert_eq!(decoded.consumed_bytes, boolean_empty.len());
    assert!(SequenceNatural::decode_cer(&boolean_empty, &limits).is_err());
    let boolean_multioctet = [0x30, 0x07, 0x01, 0x02, 0x00, 0xff, 0x84, 0x01, 0xff];
    let decoded = SequenceNatural::decode_ber(&boolean_multioctet, &limits).unwrap();
    assert_eq!(decoded.value.choice, SequenceNaturalChoice::Flag(true));
    assert!(SequenceNatural::decode_cer(&boolean_multioctet, &limits).is_err());

    let missing_choice = [0x30, 0x03, 0x84, 0x01, 0xff];
    let duplicate_choice = [
        0x30, 0x09, 0x01, 0x01, 0xff, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff,
    ];
    assert!(SequenceNatural::decode_ber(&missing_choice, &limits).is_err());
    assert!(SequenceNatural::decode_cer(&missing_choice, &limits).is_err());
    assert!(SequenceNatural::decode_ber(&duplicate_choice, &limits).is_err());
    assert!(SequenceNatural::decode_cer(&duplicate_choice, &limits).is_err());
    let tiny_input = Limits {
        max_input_bytes: 7,
        ..limits
    };
    assert!(SequenceNatural::decode_ber(&suffix, &tiny_input).is_err());
    let tiny_output = Limits {
        max_output_bytes: 7,
        ..limits
    };
    let value = SequenceNatural {
        choice: SequenceNaturalChoice::Count(2),
        after: true,
    };
    assert!(value.encode_der(&tiny_output).is_err());
}
