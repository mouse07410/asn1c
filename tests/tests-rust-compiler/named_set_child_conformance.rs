//! BER/DER/CER coverage for a same-module named SET child.

use asn1c_generated::named_set_record::{
    InnerSet, SequenceExplicit, SequenceImplicit, SequenceNatural, SequenceOptional, SetDefaults,
    SetExplicit, SetImplicit, SetNatural, SetOptional,
};
use asn1c_runtime::Limits;

/// Compare natural, IMPLICIT, and EXPLICIT child tags with generated C vectors.
/// Inputs: none. Returns no value. Errors are assertion failures or codec errors.
/// Source: design C vectors and X.690. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: named SET child gate.
/// Example: the natural child SET is encoded inside a SEQUENCE.
#[test]
fn sequence_child_tag_modes_match_c_der_cer_and_values() {
    let limits = Limits::default();
    let child = InnerSet {
        number: 2,
        flag: true,
    };
    let natural = SequenceNatural {
        child: child.clone(),
        after: true,
    };
    let natural_definite = [
        0x30, 0x0b, 0x31, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0x84, 0x01, 0xff,
    ];
    let natural_canonical = [
        0x30, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0x84, 0x01, 0xff, 0, 0,
    ];
    assert_eq!(natural.encode_der(&limits).unwrap().bytes, natural_definite);
    assert_eq!(
        natural.encode_cer(&limits).unwrap().bytes,
        natural_canonical
    );
    assert_eq!(
        SequenceNatural::decode_ber(&natural_definite, &limits)
            .unwrap()
            .value,
        natural
    );
    assert_eq!(
        SequenceNatural::decode_cer(&natural_canonical, &limits)
            .unwrap()
            .value,
        natural
    );

    let implicit = SequenceImplicit {
        child: child.clone(),
        after: true,
    };
    let implicit_definite = [
        0x30, 0x0b, 0xa3, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0x84, 0x01, 0xff,
    ];
    let implicit_canonical = [
        0x30, 0x80, 0xa3, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0x84, 0x01, 0xff, 0, 0,
    ];
    assert_eq!(
        implicit.encode_der(&limits).unwrap().bytes,
        implicit_definite
    );
    assert_eq!(
        implicit.encode_cer(&limits).unwrap().bytes,
        implicit_canonical
    );
    assert_eq!(
        SequenceImplicit::decode_ber(&implicit_definite, &limits)
            .unwrap()
            .value,
        implicit
    );
    assert_eq!(
        SequenceImplicit::decode_cer(&implicit_canonical, &limits)
            .unwrap()
            .value,
        implicit
    );

    let explicit = SequenceExplicit { child, after: true };
    let explicit_definite = [
        0x30, 0x0d, 0xa3, 0x08, 0x31, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0x84, 0x01, 0xff,
    ];
    let explicit_canonical = [
        0x30, 0x80, 0xa3, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0, 0, 0x84,
        0x01, 0xff, 0, 0,
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
        SequenceExplicit::decode_ber(&explicit_definite, &limits)
            .unwrap()
            .value,
        explicit
    );
    assert_eq!(
        SequenceExplicit::decode_cer(&explicit_canonical, &limits)
            .unwrap()
            .value,
        explicit
    );
    assert!(SequenceExplicit::decode_cer(&explicit_definite, &limits).is_err());
}

/// Verify OPTIONAL child omission and present-child decoding for both roots.
/// Inputs: none. Returns no value. Errors are assertion failures or codec errors.
/// Source: live C vectors. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: optional named SET child.
/// Example: the absent child leaves the required following BOOLEAN readable.
#[test]
fn optional_named_set_child_matches_absent_and_present_c_vectors() {
    let limits = Limits::default();
    let absent_sequence = SequenceOptional {
        child: None,
        after: true,
    };
    let absent_sequence_definite = [0x30, 0x03, 0x84, 0x01, 0xff];
    let absent_sequence_canonical = [0x30, 0x80, 0x84, 0x01, 0xff, 0, 0];
    assert_eq!(
        absent_sequence.encode_der(&limits).unwrap().bytes,
        absent_sequence_definite
    );
    assert_eq!(
        absent_sequence.encode_cer(&limits).unwrap().bytes,
        absent_sequence_canonical
    );
    assert_eq!(
        SequenceOptional::decode_ber(&absent_sequence_canonical, &limits)
            .unwrap()
            .value,
        absent_sequence
    );

    let child = InnerSet {
        number: 2,
        flag: true,
    };
    let present_sequence = SequenceOptional {
        child: Some(child.clone()),
        after: true,
    };
    let present_sequence_definite = [
        0x30, 0x0d, 0xa3, 0x08, 0x31, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0x84, 0x01, 0xff,
    ];
    let present_sequence_canonical = [
        0x30, 0x80, 0xa3, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0, 0, 0x84,
        0x01, 0xff, 0, 0,
    ];
    assert_eq!(
        present_sequence.encode_der(&limits).unwrap().bytes,
        present_sequence_definite
    );
    assert_eq!(
        present_sequence.encode_cer(&limits).unwrap().bytes,
        present_sequence_canonical
    );
    assert_eq!(
        SequenceOptional::decode_cer(&present_sequence_canonical, &limits)
            .unwrap()
            .value,
        present_sequence
    );

    let absent_set = SetOptional {
        child: None,
        after: true,
    };
    let absent_set_definite = [0x31, 0x03, 0x84, 0x01, 0xff];
    let absent_set_canonical = [0x31, 0x80, 0x84, 0x01, 0xff, 0, 0];
    assert_eq!(
        absent_set.encode_der(&limits).unwrap().bytes,
        absent_set_definite
    );
    assert_eq!(
        absent_set.encode_cer(&limits).unwrap().bytes,
        absent_set_canonical
    );
    assert_eq!(
        SetOptional::decode_cer(&absent_set_canonical, &limits)
            .unwrap()
            .value,
        absent_set
    );

    let present_set = SetOptional {
        child: Some(child),
        after: true,
    };
    let present_set_definite = [
        0x31, 0x0d, 0xa3, 0x08, 0x31, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0x84, 0x01, 0xff,
    ];
    let present_set_canonical = [
        0x31, 0x80, 0xa3, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0, 0, 0x84,
        0x01, 0xff, 0, 0,
    ];
    assert_eq!(
        present_set.encode_der(&limits).unwrap().bytes,
        present_set_definite
    );
    assert_eq!(
        present_set.encode_cer(&limits).unwrap().bytes,
        present_set_canonical
    );
    assert_eq!(
        SetOptional::decode_cer(&present_set_canonical, &limits)
            .unwrap()
            .value,
        present_set
    );
}

/// Ensure parent and child SET order are validated independently.
/// Inputs: none. Returns no value. Errors are assertion failures or codec errors.
/// Source: X.690 SET sorting and live C probes. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: nested SET ordering.
/// Example: BER accepts reversed child fields; strict CER rejects them.
#[test]
fn explicit_child_set_sorts_independently_from_parent_set() {
    let limits = Limits::default();
    let value = SetExplicit {
        child: InnerSet {
            number: 2,
            flag: true,
        },
        after: true,
    };
    let der = [
        0x31, 0x0d, 0xa3, 0x08, 0x31, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0x84, 0x01, 0xff,
    ];
    let cer = [
        0x31, 0x80, 0xa3, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0, 0, 0x84,
        0x01, 0xff, 0, 0,
    ];
    assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(SetExplicit::decode_ber(&der, &limits).unwrap().value, value);
    assert_eq!(SetExplicit::decode_cer(&cer, &limits).unwrap().value, value);

    let parent_reversed = [
        0x31, 0x80, 0x84, 0x01, 0xff, 0xa3, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff,
        0, 0, 0, 0, 0, 0,
    ];
    let decoded_parent = SetExplicit::decode_ber(&parent_reversed, &limits).unwrap();
    assert_eq!(decoded_parent.value, value);
    assert_eq!(decoded_parent.consumed_bytes, parent_reversed.len());
    assert!(SetExplicit::decode_cer(&parent_reversed, &limits).is_err());

    let child_reversed = [
        0x31, 0x80, 0xa3, 0x80, 0x31, 0x80, 0x81, 0x01, 0xff, 0x80, 0x01, 0x02, 0, 0, 0, 0, 0x84,
        0x01, 0xff, 0, 0,
    ];
    let decoded_child = SetExplicit::decode_ber(&child_reversed, &limits).unwrap();
    assert_eq!(decoded_child.value, value);
    assert!(SetExplicit::decode_cer(&child_reversed, &limits).is_err());
}

/// Bound malformed child framing, INTEGER range, prefix, and output handling.
/// Inputs: none. Returns no value. Errors are assertion failures or codec errors.
/// Source: generated C vectors and shared-context limits. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: nested SET hardening.
/// Example: truncating an EOC leaves the decoder in an error state.
#[test]
fn malformed_nested_set_frames_ranges_prefixes_and_limits_fail_safely() {
    let limits = Limits::default();
    let value = SequenceNatural {
        child: InnerSet {
            number: 2,
            flag: true,
        },
        after: true,
    };
    let canonical = value.encode_cer(&limits).unwrap().bytes;
    let suffixed = [canonical.as_slice(), &[0x5a]].concat();
    let decoded = SequenceNatural::decode_cer(&suffixed, &limits).unwrap();
    assert_eq!(decoded.value, value);
    assert_eq!(decoded.consumed_bytes, canonical.len());
    assert_eq!(decoded.consumed_bits, canonical.len() * 8);
    for end in 0..canonical.len() {
        assert!(SequenceNatural::decode_cer(&canonical[..end], &limits).is_err());
    }
    for index in 0..canonical.len() {
        for mask in [0x01, 0x80] {
            let mut mutated = canonical.clone();
            mutated[index] ^= mask;
            if let Ok(result) = SequenceNatural::decode_ber(&mutated, &limits) {
                assert!(result.consumed_bytes <= mutated.len());
                assert!(result.consumed_bits <= mutated.len() * 8);
            }
        }
    }

    let missing_child_eoc = [
        0x30, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0,
    ];
    let missing_parent_eoc = [
        0x30, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0,
    ];
    let extra_child_eoc = [
        0x30, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0, 0, 0x84, 0x01, 0xff,
        0, 0,
    ];
    let duplicate_child = [
        0x30, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x80, 0x01, 0x03, 0x81, 0x01, 0xff, 0, 0, 0x84,
        0x01, 0xff, 0, 0,
    ];
    let unknown_child = [
        0x30, 0x80, 0x31, 0x80, 0x82, 0x01, 0x01, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0,
        0x84, 0x01, 0xff, 0, 0,
    ];
    for wire in [
        missing_child_eoc.as_slice(),
        missing_parent_eoc.as_slice(),
        extra_child_eoc.as_slice(),
        duplicate_child.as_slice(),
        unknown_child.as_slice(),
    ] {
        assert!(SequenceNatural::decode_ber(wire, &limits).is_err());
    }
    let out_of_range = [
        0x30, 0x0b, 0x31, 0x06, 0x80, 0x01, 0x06, 0x81, 0x01, 0xff, 0x84, 0x01, 0xff,
    ];
    assert!(SequenceNatural::decode_ber(&out_of_range, &limits).is_err());

    let no_output = Limits {
        max_output_bytes: canonical.len() - 1,
        ..limits
    };
    assert!(value.encode_cer(&no_output).is_err());
    let no_input = Limits {
        max_input_bytes: canonical.len() - 1,
        ..limits
    };
    assert!(SequenceNatural::decode_cer(&canonical, &no_input).is_err());
    let exact_work = Limits {
        max_work_bits: 752,
        ..limits
    };
    let below_work = Limits {
        max_work_bits: 751,
        ..limits
    };
    assert!(SequenceNatural::decode_cer(&canonical, &exact_work).is_ok());
    assert!(SequenceNatural::decode_cer(&canonical, &below_work).is_err());
}

/// Verify natural and IMPLICIT named SET children in an outer SET root.
/// Inputs: none. Returns no value. Errors are assertion failures or codec errors.
/// Source: live C vectors and X.690 SET ordering. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: named SET parent variants.
/// Example: universal child tag 17 sorts before context tag 4.
#[test]
fn natural_and_implicit_children_sort_inside_set_roots() {
    let limits = Limits::default();
    let child = InnerSet {
        number: 2,
        flag: true,
    };
    let natural = SetNatural {
        child: child.clone(),
        after: true,
    };
    let natural_definite = [
        0x31, 0x0b, 0x31, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0x84, 0x01, 0xff,
    ];
    let natural_canonical = [
        0x31, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0x84, 0x01, 0xff, 0, 0,
    ];
    assert_eq!(natural.encode_der(&limits).unwrap().bytes, natural_definite);
    assert_eq!(
        natural.encode_cer(&limits).unwrap().bytes,
        natural_canonical
    );
    assert_eq!(
        SetNatural::decode_ber(&natural_definite, &limits)
            .unwrap()
            .value,
        natural
    );
    assert_eq!(
        SetNatural::decode_cer(&natural_canonical, &limits)
            .unwrap()
            .value,
        natural
    );

    let implicit = SetImplicit { child, after: true };
    let implicit_definite = [
        0x31, 0x0b, 0xa3, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0x84, 0x01, 0xff,
    ];
    let implicit_canonical = [
        0x31, 0x80, 0xa3, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0x84, 0x01, 0xff, 0, 0,
    ];
    assert_eq!(
        implicit.encode_der(&limits).unwrap().bytes,
        implicit_definite
    );
    assert_eq!(
        implicit.encode_cer(&limits).unwrap().bytes,
        implicit_canonical
    );
    assert_eq!(
        SetImplicit::decode_ber(&implicit_definite, &limits)
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
}

/// Verify EXPLICIT named SET children and parent DEFAULT omission.
/// Inputs: none. Returns no value. Errors are assertion failures or codec errors.
/// Source: live C vectors and X.690. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: SET wrapper and DEFAULT fields.
/// Example: a default FALSE sibling is omitted from canonical SET output.
#[test]
fn explicit_child_set_and_parent_default_match_c_vectors() {
    let limits = Limits::default();
    let explicit = SetExplicit {
        child: InnerSet {
            number: 2,
            flag: true,
        },
        after: true,
    };
    let explicit_definite = [
        0x31, 0x0d, 0xa3, 0x08, 0x31, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0x84, 0x01, 0xff,
    ];
    let explicit_canonical = [
        0x31, 0x80, 0xa3, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0, 0, 0x84,
        0x01, 0xff, 0, 0,
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
        SetExplicit::decode_ber(&explicit_definite, &limits)
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

    let default_value = SetDefaults {
        child: InnerSet {
            number: 2,
            flag: true,
        },
        enabled: false,
    };
    let default_definite = [
        0x31, 0x0a, 0xa3, 0x08, 0x31, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff,
    ];
    let default_canonical = [
        0x31, 0x80, 0xa3, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(
        default_value.encode_der(&limits).unwrap().bytes,
        default_definite
    );
    assert_eq!(
        default_value.encode_cer(&limits).unwrap().bytes,
        default_canonical
    );
    assert_eq!(
        SetDefaults::decode_ber(&default_definite, &limits)
            .unwrap()
            .value,
        default_value
    );
    assert_eq!(
        SetDefaults::decode_cer(&default_canonical, &limits)
            .unwrap()
            .value,
        default_value
    );
}
