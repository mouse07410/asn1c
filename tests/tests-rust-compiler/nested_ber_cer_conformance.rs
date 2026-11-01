//! BER, DER, and CER conformance for one inline SEQUENCE child.

use asn1c_generated::nested_records::{E, EChild, I, IChild, O, OChild, S, SChild};
use asn1c_runtime::{Error, Limits, Resource};

/// Compare natural and IMPLICIT child encodings against fixed C vectors.
///
/// Parameters: none. Returns: no value; assertions compare exact bytes.
/// Errors: generated codecs return errors for invalid data or exhausted limits.
/// Source: generated C BER/CER vectors. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: inline child codec stage.
/// Example: encode a child SEQUENCE with INTEGER value 2.
#[test]
fn natural_and_implicit_children_match_c_vectors() {
    let limits = Limits::default();
    let natural = S {
        before: 1,
        child: SChild { x: 2 },
        after: true,
    };
    let natural_definite = [0x30, 0x0b, 0x02, 1, 1, 0x30, 3, 0x02, 1, 2, 0x01, 1, 0xff];
    let natural_canonical = [
        0x30, 0x80, 0x02, 1, 1, 0x30, 0x80, 0x02, 1, 2, 0, 0, 0x01, 1, 0xff, 0, 0,
    ];
    assert_eq!(natural.encode_der(&limits).unwrap().bytes, natural_definite);
    assert_eq!(natural.encode_cer(&limits).unwrap().bytes, natural_canonical);
    assert_eq!(S::decode_ber(&natural_definite, &limits).unwrap().value, natural);
    assert_eq!(S::decode_cer(&natural_canonical, &limits).unwrap().value, natural);
    let packed = natural.encode_uper(&limits).unwrap();
    assert_eq!(S::decode_uper(&packed.bytes, &limits).unwrap().value, natural);

    let implicit = I {
        before: 1,
        child: IChild { x: 2 },
        after: true,
    };
    let implicit_definite = [0x30, 0x0b, 0x02, 1, 1, 0xa3, 3, 0x02, 1, 2, 0x01, 1, 0xff];
    let implicit_canonical = [
        0x30, 0x80, 0x02, 1, 1, 0xa3, 0x80, 0x02, 1, 2, 0, 0, 0x01, 1, 0xff, 0, 0,
    ];
    assert_eq!(implicit.encode_der(&limits).unwrap().bytes, implicit_definite);
    assert_eq!(implicit.encode_cer(&limits).unwrap().bytes, implicit_canonical);
    assert_eq!(I::decode_ber(&implicit_definite, &limits).unwrap().value, implicit);
    assert_eq!(I::decode_cer(&implicit_canonical, &limits).unwrap().value, implicit);
}

/// Check EXPLICIT nesting and optional child absence/presence.
///
/// Parameters: none. Returns: no value; assertions compare exact bytes.
/// Errors: generated codecs reject malformed or over-limit values.
/// Source: generated C BER/CER vectors and X.690 SET order.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: inline child codec stage. Example: an EXPLICIT child wraps a SEQUENCE.
#[test]
fn explicit_set_and_optional_children_round_trip() {
    let limits = Limits::default();
    let explicit = E {
        before: 1,
        child: EChild { x: 2 },
        after: true,
    };
    let explicit_definite = [
        0x30, 0x0d, 0x02, 1, 1, 0xa3, 5, 0x30, 3, 0x02, 1, 2, 0x01, 1, 0xff,
    ];
    let explicit_canonical = [
        0x30, 0x80, 0x02, 1, 1, 0xa3, 0x80, 0x30, 0x80, 0x02, 1, 2, 0, 0, 0, 0, 0x01, 1,
        0xff, 0, 0,
    ];
    assert_eq!(explicit.encode_der(&limits).unwrap().bytes, explicit_definite);
    assert_eq!(explicit.encode_cer(&limits).unwrap().bytes, explicit_canonical);
    assert_eq!(E::decode_ber(&explicit_definite, &limits).unwrap().value, explicit);
    assert_eq!(E::decode_cer(&explicit_canonical, &limits).unwrap().value, explicit);

    let absent = O {
        before: false,
        child: None,
        after: true,
    };
    let absent_definite = [0x30, 0x06, 0x80, 1, 0, 0x81, 1, 0xff];
    let absent_canonical = [0x30, 0x80, 0x80, 1, 0, 0x81, 1, 0xff, 0, 0];
    assert_eq!(absent.encode_der(&limits).unwrap().bytes, absent_definite);
    assert_eq!(absent.encode_cer(&limits).unwrap().bytes, absent_canonical);
    assert_eq!(O::decode_ber(&absent_definite, &limits).unwrap().value, absent);
    assert_eq!(O::decode_cer(&absent_canonical, &limits).unwrap().value, absent);
    let optional_child_limits = Limits {
        max_work_bits: 0,
        ..Limits::default()
    };
    assert!(absent.encode_der(&optional_child_limits).is_err());
    assert!(O::decode_ber(&absent_definite, &optional_child_limits).is_err());

    let present = O {
        before: false,
        child: Some(OChild { x: 2, flag: None, count: None, payload: None }),
        after: true,
    };
    let present_definite = [0x30, 0x0b, 0x80, 1, 0, 0x30, 3, 0x02, 1, 2, 0x81, 1, 0xff];
    let present_canonical = [
        0x30, 0x80, 0x80, 1, 0, 0x30, 0x80, 0x02, 1, 2, 0, 0, 0x81, 1, 0xff, 0, 0,
    ];
    assert_eq!(present.encode_der(&limits).unwrap().bytes, present_definite);
    assert_eq!(present.encode_cer(&limits).unwrap().bytes, present_canonical);
    assert_eq!(O::decode_ber(&present_definite, &limits).unwrap().value, present);
    assert_eq!(O::decode_cer(&present_canonical, &limits).unwrap().value, present);

    let tagged_leaves = O {
        before: false,
        child: Some(OChild {
            x: 2,
            flag: Some(true),
            count: Some(3),
            payload: None,
        }),
        after: true,
    };
    let tagged_leaves_definite = [
        0x30, 0x13, 0x80, 1, 0, 0x30, 0x0b, 0x02, 1, 2, 0x82, 1, 0xff,
        0xa3, 3, 0x02, 1, 3, 0x81, 1, 0xff,
    ];
    let tagged_leaves_canonical = [
        0x30, 0x80, 0x80, 1, 0, 0x30, 0x80, 0x02, 1, 2, 0x82, 1, 0xff,
        0xa3, 0x80, 0x02, 1, 3, 0, 0, 0, 0, 0x81, 1, 0xff, 0, 0,
    ];
    assert_eq!(tagged_leaves.encode_der(&limits).unwrap().bytes, tagged_leaves_definite);
    assert_eq!(tagged_leaves.encode_cer(&limits).unwrap().bytes, tagged_leaves_canonical);
    assert_eq!(O::decode_ber(&tagged_leaves_definite, &limits).unwrap().value, tagged_leaves);
    assert_eq!(O::decode_cer(&tagged_leaves_canonical, &limits).unwrap().value, tagged_leaves);
}

/// Reject malformed child boundaries and noncanonical nested CER.
///
/// Parameters: none. Returns: no value; assertions inspect typed errors.
/// Errors: malformed, truncated, or noncanonical data must return an error.
/// Source: X.690 constructed boundaries and CER canonical comparison.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: nested hostile-input regression. Example: a child length crosses its parent.
#[test]
fn malformed_nested_inputs_and_cer_canonicality_fail_closed() {
    let limits = Limits::default();
    let valid = [0x30, 0x0b, 0x02, 1, 1, 0x30, 3, 0x02, 1, 2, 0x01, 1, 0xff];
    let mut with_suffix = valid.to_vec();
    with_suffix.push(0xaa);
    let prefix = S::decode_ber(&with_suffix, &limits).unwrap();
    assert_eq!(prefix.consumed_bytes, valid.len());
    for malformed in [
        &valid[..valid.len() - 1],
        &[0x30, 0x09, 0x02, 1, 1, 0x30, 3, 0x02, 1, 2, 0x01, 1, 0xff][..],
        &[0x30, 0x0e, 0x02, 1, 1, 0x30, 3, 0x02, 1, 2, 0, 0, 0x01, 1, 0xff][..],
    ] {
        assert!(S::decode_ber(malformed, &limits).is_err());
    }

    // BER accepts a definite EXPLICIT wrapper around an indefinite child; CER
    // canonicality rejects this mixed length form after shared-context re-encoding.
    let mixed = [
        0x30, 0x0f, 0x02, 1, 1, 0xa3, 7, 0x30, 0x80, 0x02, 1, 2, 0, 0, 0x01, 1, 0xff,
    ];
    let explicit = E::decode_ber(&mixed, &limits).unwrap();
    assert_eq!(explicit.value.child.x, 2);
    assert!(E::decode_cer(&mixed, &limits).is_err());
    let wrong_inner_tag = [
        0x30, 0x0d, 0x02, 1, 1, 0xa3, 5, 0x31, 3, 0x02, 1, 2, 0x01, 1, 0xff,
    ];
    assert!(E::decode_ber(&wrong_inner_tag, &limits).is_err());

    let tiny_work = Limits {
        max_work_bits: 1,
        ..Limits::default()
    };
    assert!(matches!(
        S::decode_ber(&valid, &tiny_work),
        Err(Error::LimitExceeded {
            resource: Resource::WorkBits,
            ..
        })
    ));
}

/// Verify CER fragmentation for an OCTET STRING nested inside two SEQUENCEs.
///
/// Parameters: none. Returns: no value; assertions compare nested wire bytes.
/// Errors: generated codecs reject invalid sizes or resource exhaustion.
/// Source: X.690 CER string segmentation and C reference fixture.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: nested string boundary coverage. Example: 1001 octets use two fragments.
#[test]
fn nested_octet_string_fragmentation_matches_c_vector() {
    let limits = Limits::default();
    let payload = vec![0x5a; 1001];
    let value = O {
        before: false,
        child: Some(OChild {
            x: 2,
            flag: None,
            count: None,
            payload: Some(payload.clone()),
        }),
        after: true,
    };
    let mut definite = vec![
        0x30, 0x82, 0x03, 0xfa, 0x80, 1, 0, 0x30, 0x82, 0x03, 0xf0,
        0x02, 1, 2, 0x04, 0x82, 0x03, 0xe9,
    ];
    definite.extend_from_slice(&payload);
    definite.extend_from_slice(&[0x81, 1, 0xff]);
    let mut canonical = vec![
        0x30, 0x80, 0x80, 1, 0, 0x30, 0x80, 0x02, 1, 2,
        0x24, 0x80, 0x04, 0x82, 0x03, 0xe8,
    ];
    canonical.extend_from_slice(&payload[..1000]);
    canonical.extend_from_slice(&[0x04, 1, 0x5a, 0, 0, 0, 0, 0x81, 1, 0xff, 0, 0]);
    assert_eq!(value.encode_der(&limits).unwrap().bytes, definite);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, canonical);
    assert_eq!(O::decode_ber(&definite, &limits).unwrap().value, value);
    assert_eq!(O::decode_cer(&canonical, &limits).unwrap().value, value);
}
