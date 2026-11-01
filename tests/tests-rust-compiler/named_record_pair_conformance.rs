//! BER/DER/CER tests for two same-module named record children.

use asn1c_generated::named_record_pair::{
    A, B, BitsB, ByteA, C, EmptyPair, EmptyRecord, I, O, OwnedPair, P, Q, T, U, X,
};
use asn1c_runtime::Limits;

/// Compare the required/OPTIONAL sequence children with generated C vectors.
/// Inputs: none. Returns no value. Errors: assertion failures or codec errors.
/// Source: approved C vectors and X.690. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: two named record children.
/// Example: `P` contains required `A` and present optional `B`.
#[test]
fn sequence_pair_matches_c_vectors_and_prefix_consumption() {
    let limits = Limits::default();
    let value = P { a: A { n: 2 }, b: Some(B { b: true }) };
    let der = [0x30, 0x0a, 0x30, 0x03, 0x02, 0x01, 0x02, 0x31, 0x03, 0x01, 0x01, 0xff];
    let cer = [
        0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x31, 0x80, 0x01, 0x01, 0xff, 0, 0,
        0, 0,
    ];
    assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(P::decode_ber(&der, &limits).unwrap().value, value);
    assert_eq!(P::decode_ber(&cer, &limits).unwrap().value, value);
    assert_eq!(P::decode_cer(&cer, &limits).unwrap().value, value);
    assert!(P::decode_cer(&der, &limits).is_err());
    let mut suffixed = cer.to_vec();
    suffixed.push(0x5a);
    let decoded = P::decode_cer(&suffixed, &limits).unwrap();
    assert_eq!(decoded.value, value);
    assert_eq!(decoded.consumed_bytes, cer.len());
    assert_eq!(decoded.consumed_bits, cer.len() * 8);

    // Decode one definite record even when the input contains a trailing value.
    let mut suffixed = der.to_vec();
    suffixed.push(0x5a);
    let decoded = P::decode_ber(&suffixed, &limits).unwrap();
    assert_eq!(decoded.value, value);
    assert_eq!(decoded.consumed_bytes, der.len());
    assert_eq!(decoded.consumed_bits, der.len() * 8);

    // Every proper prefix lacks part of a required TLV or its enclosing frame.
    for end in 0..der.len() {
        assert!(P::decode_ber(&der[..end], &limits).is_err());
    }
    for end in 0..cer.len() {
        assert!(P::decode_ber(&cer[..end], &limits).is_err());
        assert!(P::decode_cer(&cer[..end], &limits).is_err());
    }
}

/// Exercise both OPTIONAL children in all four presence combinations.
/// Inputs: none. Returns no value. Errors: assertion failures or codec errors.
/// Source: schema and X.690. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: optional pair coverage.
/// Example: absent `A` and present `B` encodes only the SET child.
#[test]
fn optional_pair_covers_each_presence_state() {
    let limits = Limits::default();
    let cases = [
        (
            O { a: None, b: None },
            &[0x30, 0x00][..],
            &[0x30, 0x80, 0, 0][..],
        ),
        (
            O { a: Some(A { n: 2 }), b: None },
            &[0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02][..],
            &[0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0, 0][..],
        ),
        (
            O { a: None, b: Some(B { b: true }) },
            &[0x30, 0x05, 0x31, 0x03, 0x01, 0x01, 0xff][..],
            &[0x30, 0x80, 0x31, 0x80, 0x01, 0x01, 0xff, 0, 0, 0, 0][..],
        ),
        (
            O { a: Some(A { n: 2 }), b: Some(B { b: true }) },
            &[0x30, 0x0a, 0x30, 0x03, 0x02, 0x01, 0x02, 0x31, 0x03, 0x01, 0x01, 0xff][..],
            &[
                0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x31, 0x80, 0x01, 0x01, 0xff,
                0, 0, 0, 0,
            ][..],
        ),
    ];
    for (value, der, cer) in cases {
        assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
        assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
        assert_eq!(O::decode_ber(der, &limits).unwrap().value, value);
        assert_eq!(O::decode_cer(cer, &limits).unwrap().value, value);
    }
}

/// Cover an empty named SEQUENCE with the second OPTIONAL child absent/present.
/// Inputs: none. Returns no value. Errors: assertion failures or codec errors.
/// Source: named-empty C vectors. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: empty record in pair gate.
/// Example: the required empty record still emits its own constructed TLV.
#[test]
fn empty_named_sequence_pairs_with_optional_set_child() {
    let limits = Limits::default();
    let absent = EmptyPair {
        empty: EmptyRecord {},
        b: None,
    };
    let absent_definite = [0x30, 0x02, 0x30, 0x00];
    let absent_canonical = [0x30, 0x80, 0x30, 0x80, 0, 0, 0, 0];
    assert_eq!(absent.encode_der(&limits).unwrap().bytes, absent_definite);
    assert_eq!(absent.encode_cer(&limits).unwrap().bytes, absent_canonical);
    assert_eq!(
        EmptyPair::decode_cer(&absent_canonical, &limits).unwrap().value,
        absent
    );

    let present = EmptyPair {
        empty: EmptyRecord {},
        b: Some(B { b: true }),
    };
    let present_definite = [0x30, 0x07, 0x30, 0x00, 0x31, 0x03, 0x01, 0x01, 0xff];
    let present_canonical = [
        0x30, 0x80, 0x30, 0x80, 0, 0, 0x31, 0x80, 0x01, 0x01, 0xff, 0, 0, 0, 0,
    ];
    assert_eq!(present.encode_der(&limits).unwrap().bytes, present_definite);
    assert_eq!(present.encode_cer(&limits).unwrap().bytes, present_canonical);
    assert_eq!(
        EmptyPair::decode_cer(&present_canonical, &limits).unwrap().value,
        present
    );
}

/// Preserve owned string values and BIT STRING padding across both children.
/// Inputs: none. Returns no value. Errors: assertion failures or codec errors.
/// Source: generated C string vectors and X.690 padding rules. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: owned fields in sibling records.
/// Example: one child owns two octets while its sibling owns three meaningful bits.
#[test]
fn owned_child_fields_match_c_and_validate_second_child_padding() {
    let limits = Limits::default();
    let value = OwnedPair {
        a: ByteA { octets: vec![0xaa, 0xbb] },
        b: BitsB { bits: vec![0xa0] },
    };
    let der = [
        0x30, 0x0c, 0x30, 0x04, 0x04, 0x02, 0xaa, 0xbb,
        0x31, 0x04, 0x03, 0x02, 0x05, 0xa0,
    ];
    let cer = [
        0x30, 0x80, 0x30, 0x80, 0x04, 0x02, 0xaa, 0xbb, 0, 0,
        0x31, 0x80, 0x03, 0x02, 0x05, 0xa0, 0, 0, 0, 0,
    ];
    assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(OwnedPair::decode_ber(&der, &limits).unwrap().value, value);
    assert_eq!(OwnedPair::decode_ber(&cer, &limits).unwrap().value, value);
    assert_eq!(OwnedPair::decode_cer(&cer, &limits).unwrap().value, value);

    // BER normalizes ignored padding bits; strict CER requires their canonical zero form.
    let mut bad_padding = cer;
    bad_padding[15] = 0xa1;
    assert_eq!(OwnedPair::decode_ber(&bad_padding, &limits).unwrap().value, value);
    assert!(OwnedPair::decode_cer(&bad_padding, &limits).is_err());

    // An impossible unused-bit count is malformed under both decoding rules.
    let mut bad_count = cer;
    bad_count[14] = 8;
    assert!(OwnedPair::decode_ber(&bad_count, &limits).is_err());
    assert!(OwnedPair::decode_cer(&bad_count, &limits).is_err());
}

/// Verify parent SET ordering and BER acceptance of the reverse permutation.
/// Inputs: none. Returns no value. Errors: assertion failures or codec errors.
/// Source: approved C vectors and X.690 SET ordering. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: two-child SET parent.
/// Example: natural SEQUENCE tag 16 sorts before named SET tag 17.
#[test]
fn set_parent_sorts_named_children_by_outer_effective_tag() {
    let limits = Limits::default();
    let value = T { b: Some(B { b: true }), a: A { n: 2 } };
    let der = [0x31, 0x0a, 0x30, 0x03, 0x02, 0x01, 0x02, 0x31, 0x03, 0x01, 0x01, 0xff];
    let cer = [
        0x31, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x31, 0x80, 0x01, 0x01, 0xff, 0, 0,
        0, 0,
    ];
    assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(T::decode_ber(&der, &limits).unwrap().value, value);
    assert_eq!(T::decode_cer(&cer, &limits).unwrap().value, value);
    let reversed = [
        0x31, 0x80, 0x31, 0x03, 0x01, 0x01, 0xff, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0, 0,
    ];
    assert_eq!(T::decode_ber(&reversed, &limits).unwrap().value, value);
    assert!(T::decode_cer(&reversed, &limits).is_err());
}

/// Verify a multi-member SET child sorts independently under both parent kinds.
/// Inputs: none. Returns no value. Errors: assertion failures or codec errors.
/// Source: generated C vectors and X.690. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: nested SET pair ordering.
/// Example: child tag 0 precedes tag 1 although declared after it.
#[test]
fn child_set_and_parent_set_each_sort_their_own_members() {
    let limits = Limits::default();
    let sequence = Q {
        a: A { n: 2 },
        c: Some(C { flag: true, number: 2 }),
        enabled: false,
    };
    let sequence_definite = [
        0x30, 0x0d, 0x30, 0x03, 0x02, 0x01, 0x02, 0x31, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff,
    ];
    let sequence_canonical = [
        0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01,
        0xff, 0, 0, 0, 0,
    ];
    assert_eq!(sequence.encode_der(&limits).unwrap().bytes, sequence_definite);
    assert_eq!(sequence.encode_cer(&limits).unwrap().bytes, sequence_canonical);
    assert_eq!(Q::decode_ber(&sequence_definite, &limits).unwrap().value, sequence);
    assert_eq!(Q::decode_cer(&sequence_canonical, &limits).unwrap().value, sequence);

    let child_reversed = [
        0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x31, 0x80, 0x81, 0x01, 0xff, 0x80, 0x01,
        0x02, 0, 0, 0, 0,
    ];
    assert_eq!(Q::decode_ber(&child_reversed, &limits).unwrap().value, sequence);
    assert!(Q::decode_cer(&child_reversed, &limits).is_err());

    let child_absent = Q {
        a: A { n: 2 },
        c: None,
        enabled: false,
    };
    let absent_definite = [0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02];
    let absent_canonical = [0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0, 0];
    assert_eq!(child_absent.encode_der(&limits).unwrap().bytes, absent_definite);
    assert_eq!(child_absent.encode_cer(&limits).unwrap().bytes, absent_canonical);
    assert_eq!(
        Q::decode_cer(&absent_canonical, &limits).unwrap().value,
        child_absent
    );

    let enabled = Q {
        a: A { n: 2 },
        c: Some(C { flag: true, number: 2 }),
        enabled: true,
    };
    let enabled_definite = [
        0x30, 0x10, 0x30, 0x03, 0x02, 0x01, 0x02, 0x31, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff,
        0x01, 0x01, 0xff,
    ];
    let enabled_canonical = [
        0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01,
        0xff, 0, 0, 0x01, 0x01, 0xff, 0, 0,
    ];
    assert_eq!(enabled.encode_der(&limits).unwrap().bytes, enabled_definite);
    assert_eq!(enabled.encode_cer(&limits).unwrap().bytes, enabled_canonical);
    assert_eq!(Q::decode_cer(&enabled_canonical, &limits).unwrap().value, enabled);

    let present_default = [
        0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01,
        0xff, 0, 0, 0x01, 0x01, 0x00, 0, 0, 0,
    ];
    assert!(Q::decode_ber(&present_default, &limits).is_ok());
    assert!(Q::decode_cer(&present_default, &limits).is_err());

    let set = U {
        c: Some(C { flag: true, number: 2 }),
        a: A { n: 2 },
    };
    let set_definite = [
        0x31, 0x0d, 0x30, 0x03, 0x02, 0x01, 0x02, 0x31, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff,
    ];
    let set_canonical = [
        0x31, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01,
        0xff, 0, 0, 0, 0,
    ];
    assert_eq!(set.encode_der(&limits).unwrap().bytes, set_definite);
    assert_eq!(set.encode_cer(&limits).unwrap().bytes, set_canonical);
    assert_eq!(U::decode_ber(&set_definite, &limits).unwrap().value, set);
    assert_eq!(U::decode_cer(&set_canonical, &limits).unwrap().value, set);
    let parent_reversed = [
        0x31, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0x30, 0x80, 0x02, 0x01,
        0x02, 0, 0, 0, 0,
    ];
    assert_eq!(U::decode_ber(&parent_reversed, &limits).unwrap().value, set);
    assert!(U::decode_cer(&parent_reversed, &limits).is_err());
}

/// Compare same-target IMPLICIT and EXPLICIT references with distinct tags.
/// Inputs: none. Returns no value. Errors: assertion failures or codec errors.
/// Source: generated C EXPLICIT and IMPLICIT vectors and bounded target schema.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: same-target effective-tag support. Example: `X` wraps `A` twice.
#[test]
fn repeated_target_accepts_distinct_implicit_and_explicit_tags() {
    let limits = Limits::default();
    let explicit = X { a: A { n: 2 }, b: A { n: 3 } };
    let explicit_definite = [
        0x30, 0x0e, 0xa2, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02, 0xa3, 0x05, 0x30, 0x03, 0x02, 0x01,
        0x03,
    ];
    let explicit_canonical = [
        0x30, 0x80, 0xa2, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0, 0, 0xa3, 0x80, 0x30,
        0x80, 0x02, 0x01, 0x03, 0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(explicit.encode_der(&limits).unwrap().bytes, explicit_definite);
    assert_eq!(explicit.encode_cer(&limits).unwrap().bytes, explicit_canonical);
    assert_eq!(X::decode_ber(&explicit_definite, &limits).unwrap().value, explicit);
    assert_eq!(X::decode_cer(&explicit_canonical, &limits).unwrap().value, explicit);

    let implicit = I { a: A { n: 2 }, b: A { n: 3 } };
    let implicit_definite = [
        0x30, 0x0a, 0xa2, 0x03, 0x02, 0x01, 0x02, 0xa3, 0x03, 0x02, 0x01, 0x03,
    ];
    let implicit_canonical = [
        0x30, 0x80, 0xa2, 0x80, 0x02, 0x01, 0x02, 0, 0, 0xa3, 0x80, 0x02, 0x01, 0x03, 0, 0, 0,
        0,
    ];
    assert_eq!(implicit.encode_der(&limits).unwrap().bytes, implicit_definite);
    assert_eq!(implicit.encode_cer(&limits).unwrap().bytes, implicit_canonical);
    assert_eq!(I::decode_ber(&implicit_definite, &limits).unwrap().value, implicit);
    assert_eq!(I::decode_cer(&implicit_canonical, &limits).unwrap().value, implicit);

    // Each reference independently retains the target's inclusive INTEGER bounds.
    for bound in [0, 5] {
        let value = X { a: A { n: bound }, b: A { n: bound } };
        let wire = value.encode_cer(&limits).unwrap().bytes;
        assert_eq!(X::decode_cer(&wire, &limits).unwrap().value, value);
    }
    let invalid = X { a: A { n: 2 }, b: A { n: 6 } };
    assert!(invalid.encode_der(&limits).is_err());
    assert!(invalid.encode_cer(&limits).is_err());

    // The second child's invalid value must also fail through both decoders.
    let mut invalid_definite = explicit_definite;
    invalid_definite[15] = 6;
    let mut invalid_canonical = explicit_canonical;
    invalid_canonical[19] = 6;
    assert!(X::decode_ber(&invalid_definite, &limits).is_err());
    assert!(X::decode_ber(&invalid_canonical, &limits).is_err());
    assert!(X::decode_cer(&invalid_canonical, &limits).is_err());
}

/// Find the lowest work allowance that encodes this value as CER.
/// Inputs: value and exact output bytes; returns the minimum successful budget.
/// Errors: panics if no allowance through 4096 bits succeeds.
/// Source: generated record limits. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: exact pair work boundary.
/// Example: the returned limit succeeds and one bit less must fail.
fn minimum_encode_work(value: &P, output_size: usize) -> usize {
    (0..=4096)
        .find(|work| {
            value
                .encode_cer(&Limits {
                    max_output_bytes: output_size,
                    max_work_bits: *work,
                    ..Limits::default()
                })
                .is_ok()
        })
        .expect("pair CER encoding must fit within the probe budget")
}

/// Find the lowest work allowance that strictly decodes this CER value.
/// Inputs: bytes are one CER record; returns the minimum successful budget.
/// Errors: panics if no allowance through 4096 bits succeeds.
/// Source: generated record limits. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: exact pair work boundary.
/// Example: probe cumulative work for both named children and parent framing.
fn minimum_decode_work(bytes: &[u8]) -> usize {
    (0..=4096)
        .find(|work| {
            P::decode_cer(
                bytes,
                &Limits {
                    max_input_bytes: bytes.len(),
                    max_output_bytes: bytes.len(),
                    max_work_bits: *work,
                },
            )
            .is_ok()
        })
        .expect("pair CER decoding must fit within the probe budget")
}

/// Reject malformed second children and exercise cumulative shared limits.
/// Inputs: none. Returns no value. Errors: assertion failures or codec errors.
/// Source: X.690 malformed frames and record work accounting. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: pair failures and limits.
/// Example: a repeated BOOLEAN tag in the second SET rejects the whole parent.
#[test]
fn malformed_second_child_and_shared_limits_are_rejected() {
    let limits = Limits::default();
    let malformed = [
        &[
            0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x31, 0x80, 0x01, 0x01, 0xff, 0x01,
            0x01, 0x00, 0, 0, 0, 0,
        ][..],
        &[
            0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x31, 0x80, 0x02, 0x01, 0x00, 0, 0,
            0, 0,
        ][..],
        &[
            0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x31, 0x80, 0x01, 0x01, 0xff, 0, 0,
        ][..],
    ];
    for wire in malformed {
        assert!(P::decode_ber(wire, &limits).is_err());
    }
    let wrong_wrapper = [
        0x30, 0x0e, 0xa2, 0x05, 0x31, 0x03, 0x01, 0x01, 0xff, 0xa3, 0x05, 0x30, 0x03, 0x02, 0x01,
        0x03,
    ];
    assert!(X::decode_ber(&wrong_wrapper, &limits).is_err());

    let value = P { a: A { n: 2 }, b: Some(B { b: true }) };
    let encoded = value.encode_cer(&limits).unwrap();
    let exact = Limits {
        max_input_bytes: encoded.bytes.len(),
        max_output_bytes: encoded.bytes.len(),
        max_work_bits: minimum_decode_work(&encoded.bytes),
    };
    assert_eq!(P::decode_cer(&encoded.bytes, &exact).unwrap().value, value);
    let encode_exact = Limits {
        max_output_bytes: encoded.bytes.len(),
        max_work_bits: minimum_encode_work(&value, encoded.bytes.len()),
        ..Limits::default()
    };
    assert_eq!(value.encode_cer(&encode_exact).unwrap().bytes, encoded.bytes);
    assert!(value
        .encode_cer(&Limits {
            max_work_bits: encode_exact.max_work_bits - 1,
            ..encode_exact
        })
        .is_err());
    assert!(value
        .encode_cer(&Limits {
            max_output_bytes: encoded.bytes.len() - 1,
            ..exact
        })
        .is_err());
    assert!(P::decode_cer(
        &encoded.bytes,
        &Limits {
            max_input_bytes: encoded.bytes.len() - 1,
            ..exact
        }
    )
    .is_err());
    assert!(P::decode_cer(
        &encoded.bytes,
        &Limits {
            max_work_bits: exact.max_work_bits - 1,
            ..exact
        }
    )
    .is_err());
}

/// Mutate every byte of the canonical pair and bound all accepted prefixes.
/// Inputs: none. Returns no value. Errors: assertion failures or codec errors.
/// Source: exact two-child CER vector. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: deterministic mutation test.
/// Example: each byte is `XORed` with every nonzero single-bit mask.
#[test]
fn pair_mutations_never_exceed_the_input_prefix() {
    let limits = Limits::default();
    let value = P { a: A { n: 2 }, b: Some(B { b: true }) };
    let canonical = value.encode_cer(&limits).unwrap().bytes;
    for index in 0..canonical.len() {
        for mask in [1, 2, 4, 8, 16, 32, 64, 128] {
            let mut mutated = canonical.clone();
            mutated[index] ^= mask;
            if let Ok(decoded) = P::decode_ber(&mutated, &limits) {
                assert!(decoded.consumed_bytes <= mutated.len());
                assert!(decoded.consumed_bits <= mutated.len() * 8);
            }
        }
    }
}
