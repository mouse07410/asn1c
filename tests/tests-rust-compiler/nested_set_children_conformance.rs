//! BER, DER, and CER checks for one direct inline SET child.

use asn1c_generated::nested_set_children::{
    SequenceExplicit, SequenceExplicitChild, SequenceImplicit, SequenceImplicitChild,
    SequenceLeaves, SequenceLeavesChild, SequenceLeavesChildState, SequenceNatural,
    SequenceNaturalChild, SequenceOptional, SequenceOptionalChild, SetExplicit, SetExplicitChild,
};
use asn1c_runtime::{Limits, Resource};

/// Compare natural, IMPLICIT, and EXPLICIT nested SET encodings with C vectors.
///
/// Parameters: none. Returns: no value; exact byte assertions report failures.
/// Errors: generated encoders/decoders return errors for malformed values.
/// Source: C-generated vectors and X.690 SET/SEQUENCE framing.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: inline SET child gate. Example: encode x=2 and y=TRUE.
#[test]
fn nested_set_tags_match_c_vectors() {
    let limits = Limits::default();
    let natural = SequenceNatural {
        child: SequenceNaturalChild { y: true, x: 2 },
    };
    let natural_definite = [0x30, 0x08, 0x31, 0x06, 0x80, 1, 2, 0x81, 1, 0xff];
    let natural_canonical = [
        0x30, 0x80, 0x31, 0x80, 0x80, 1, 2, 0x81, 1, 0xff, 0, 0, 0, 0,
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
        child: SequenceImplicitChild { y: true, x: 2 },
    };
    let implicit_definite = [0x30, 0x08, 0xa3, 0x06, 0x80, 1, 2, 0x81, 1, 0xff];
    let implicit_canonical = [
        0x30, 0x80, 0xa3, 0x80, 0x80, 1, 2, 0x81, 1, 0xff, 0, 0, 0, 0,
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

    let explicit = SequenceExplicit {
        child: SequenceExplicitChild { y: true, x: 2 },
    };
    let explicit_definite = [
        0x30, 0x0a, 0xa3, 0x08, 0x31, 0x06, 0x80, 1, 2, 0x81, 1, 0xff,
    ];
    let explicit_canonical = [
        0x30, 0x80, 0xa3, 0x80, 0x31, 0x80, 0x80, 1, 2, 0x81, 1, 0xff, 0, 0, 0, 0, 0, 0,
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
}

/// Check child SET ordering independently from its parent SET ordering.
///
/// Parameters: none. Returns: no value; assertions verify BER/CER behavior.
/// Errors: strict CER must reject reordered members; BER must accept them.
/// Source: C probe and X.690 SET ordering. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: nested SET gate.
/// Example: reverse y/x wire order while keeping canonical parent order.
#[test]
fn child_set_dispatch_is_unordered_and_cer_is_canonical() {
    let limits = Limits::default();
    let value = SequenceNatural {
        child: SequenceNaturalChild { y: true, x: 2 },
    };
    let reordered = [0x30, 0x08, 0x31, 0x06, 0x81, 1, 0xff, 0x80, 1, 2];
    let decoded = SequenceNatural::decode_ber(&reordered, &limits).unwrap();
    assert_eq!(decoded.value, value);
    assert_eq!(decoded.consumed_bytes, reordered.len());
    assert_eq!(decoded.consumed_bits, reordered.len() * 8);
    assert!(SequenceNatural::decode_cer(&reordered, &limits).is_err());
    let mut canonical_with_suffix = value.encode_cer(&limits).unwrap().bytes;
    canonical_with_suffix.push(0xee);
    let decoded = SequenceNatural::decode_cer(&canonical_with_suffix, &limits).unwrap();
    assert_eq!(decoded.value, value);
    assert_eq!(decoded.consumed_bytes, canonical_with_suffix.len() - 1);

    let root_set = SetExplicit {
        after: true,
        child: SetExplicitChild { y: true, x: 2 },
    };
    let root_definite = [
        0x31, 0x0d, 0xa3, 0x08, 0x31, 0x06, 0x80, 1, 2, 0x81, 1, 0xff, 0x84, 1, 0xff,
    ];
    let root_canonical = [
        0x31, 0x80, 0xa3, 0x80, 0x31, 0x80, 0x80, 1, 2, 0x81, 1, 0xff, 0, 0, 0, 0, 0x84, 1, 0xff,
        0, 0,
    ];
    assert_eq!(root_set.encode_der(&limits).unwrap().bytes, root_definite);
    assert_eq!(root_set.encode_cer(&limits).unwrap().bytes, root_canonical);
    assert_eq!(
        SetExplicit::decode_ber(&root_definite, &limits)
            .unwrap()
            .value,
        root_set
    );
    assert_eq!(
        SetExplicit::decode_cer(&root_canonical, &limits)
            .unwrap()
            .value,
        root_set
    );
    let parent_reordered = [
        0x31, 0x80, 0x84, 1, 0xff, 0xa3, 0x80, 0x31, 0x80, 0x80, 1, 2, 0x81, 1, 0xff, 0, 0, 0, 0,
        0, 0,
    ];
    assert_eq!(
        SetExplicit::decode_ber(&parent_reordered, &limits)
            .unwrap()
            .value,
        root_set
    );
    assert!(SetExplicit::decode_cer(&parent_reordered, &limits).is_err());
    let child_reordered = [
        0x31, 0x80, 0xa3, 0x80, 0x31, 0x80, 0x81, 1, 0xff, 0x80, 1, 2, 0, 0, 0, 0, 0x84, 1, 0xff,
        0, 0,
    ];
    assert_eq!(
        SetExplicit::decode_ber(&child_reordered, &limits)
            .unwrap()
            .value,
        root_set
    );
    assert!(SetExplicit::decode_cer(&child_reordered, &limits).is_err());

    let parent_definite_child_indefinite = [
        0x30, 0x0c, 0xa3, 0x0a, 0x31, 0x80, 0x80, 1, 2, 0x81, 1, 0xff, 0, 0,
    ];
    assert_eq!(
        SequenceExplicit::decode_ber(&parent_definite_child_indefinite, &limits)
            .unwrap()
            .value,
        SequenceExplicit {
            child: SequenceExplicitChild { y: true, x: 2 },
        }
    );
    assert!(SequenceExplicit::decode_cer(&parent_definite_child_indefinite, &limits).is_err());
    let parent_indefinite_child_definite = [
        0x30, 0x80, 0xa3, 0x80, 0x31, 0x06, 0x80, 1, 2, 0x81, 1, 0xff, 0, 0, 0, 0,
    ];
    assert_eq!(
        SequenceExplicit::decode_ber(&parent_indefinite_child_definite, &limits)
            .unwrap()
            .value,
        SequenceExplicit {
            child: SequenceExplicitChild { y: true, x: 2 },
        }
    );
    assert!(SequenceExplicit::decode_cer(&parent_indefinite_child_definite, &limits).is_err());
}

/// Exercise OPTIONAL absence, prefix boundaries, malformed framing, and limits.
///
/// Parameters: none. Returns: no value; assertions check exact decoding errors.
/// Errors: malformed and over-limit inputs are expected to return errors.
/// Source: X.690 nested-record framing and shared runtime limits.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: inline nested SET gate. Example: omit the optional child SET.
#[test]
fn optional_child_prefix_malformed_and_limits() {
    let limits = Limits::default();
    let absent = SequenceOptional { child: None };
    assert_eq!(absent.encode_der(&limits).unwrap().bytes, [0x30, 0x00]);
    assert_eq!(
        absent.encode_cer(&limits).unwrap().bytes,
        [0x30, 0x80, 0, 0]
    );
    assert_eq!(
        SequenceOptional::decode_ber(&[0x30, 0], &limits)
            .unwrap()
            .value,
        absent
    );
    assert_eq!(
        SequenceOptional::decode_cer(&[0x30, 0x80, 0, 0], &limits)
            .unwrap()
            .value,
        absent
    );

    let present = SequenceOptional {
        child: Some(SequenceOptionalChild { y: true, x: 2 }),
    };
    let definite = [
        0x30, 0x0a, 0xa3, 0x08, 0x31, 0x06, 0x80, 1, 2, 0x81, 1, 0xff,
    ];
    let mut suffixed = definite.to_vec();
    suffixed.push(0xee);
    let decoded = SequenceOptional::decode_ber(&suffixed, &limits).unwrap();
    assert_eq!(decoded.value, present);
    assert_eq!(decoded.consumed_bytes, definite.len());
    assert_eq!(decoded.consumed_bits, definite.len() * 8);
    assert!(SequenceOptional::decode_cer(&suffixed, &limits).is_err());
    for malformed in [
        &[0x30, 0x03, 0xa3, 1, 0][..],
        &[0x30, 0x04, 0xa3, 0x80, 0, 0][..],
        &[
            0x30, 0x09, 0xa3, 0x08, 0x31, 0x06, 0x80, 1, 2, 0x81, 1, 0xff,
        ][..],
    ] {
        assert!(SequenceOptional::decode_ber(malformed, &limits).is_err());
    }
    let short_input = Limits {
        max_input_bytes: 3,
        ..limits
    };
    let short_work = Limits {
        max_work_bits: 0,
        ..limits
    };
    let short_output = Limits {
        max_output_bytes: 3,
        ..limits
    };
    assert!(SequenceOptional::decode_ber(&definite, &short_input).is_err());
    assert!(SequenceOptional::decode_ber(&definite, &short_work).is_err());
    assert!(present.encode_der(&short_output).is_err());
    assert!(matches!(
        present.encode_der(&Limits {
            max_output_bytes: 3,
            ..limits
        }),
        Err(asn1c_runtime::Error::LimitExceeded {
            resource: Resource::OutputBytes,
            ..
        })
    ));
}

/// Round-trip all six approved primitive leaf kinds inside an inline SET.
///
/// Parameters: none. Returns: no value; assertions compare complete vectors.
/// Errors: unsupported or malformed generated values must return errors.
/// Source: C-generated vectors and the six-leaf BER/CER gate.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: inline nested SET gate. Example: encode all fields in tag order.
#[test]
fn six_primitive_leaf_kinds_round_trip() {
    let limits = Limits::default();
    let child = SequenceLeavesChild {
        flag: true,
        number: 3,
        bits: asn1c_runtime::BitStringValue::new(vec![0xa0], 3).unwrap(),
        octets: vec![0xaa],
        nothing: (),
        state: SequenceLeavesChildState::On,
    };
    let value = SequenceLeaves { child };
    let der = value.encode_der(&limits).unwrap();
    let cer = value.encode_cer(&limits).unwrap();
    assert_eq!(
        SequenceLeaves::decode_ber(&der.bytes, &limits)
            .unwrap()
            .value,
        value
    );
    assert_eq!(
        SequenceLeaves::decode_cer(&cer.bytes, &limits)
            .unwrap()
            .value,
        value
    );
}
