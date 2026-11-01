//! BER/DER/CER vectors for a directly imported bounded INTEGER.

use asn1c_generated::imported_integer_base::Small;
use asn1c_generated::imported_integer_client::{
    DefaultSequence, DefaultSet, ExplicitSequence, ExplicitSet, ImplicitSequence, ImplicitSet,
    Local, LocalSequence, NaturalSequence, NaturalSet, OptionalSequence, OptionalSet,
};
use asn1c_runtime::Limits;

/// Find the lowest work budget that completes strict CER decoding.
/// Inputs: one canonical prefix; returns its minimum successful work limit.
/// Errors: panics if no budget through 8192 work bits succeeds.
/// Source: generated nested-record accounting. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: imported INTEGER limits.
/// Example: probe one imported scalar and the parent BOOLEAN sibling together.
fn minimum_decode_work(bytes: &[u8]) -> usize {
    (0..=8192)
        .find(|work| {
            NaturalSequence::decode_cer(
                bytes,
                &Limits {
                    max_input_bytes: bytes.len(),
                    max_output_bytes: bytes.len(),
                    max_work_bits: *work,
                },
            )
            .is_ok()
        })
        .expect("imported record must fit the bounded work probe")
}

/// Find the lowest work budget that completes CER encoding of one parent value.
/// Inputs: a schema value; returns its minimum successful work limit.
/// Errors: panics if no budget through 8192 work bits succeeds.
/// Source: generated record accounting. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: imported INTEGER limits.
/// Example: probe the imported scalar and sibling in one parent operation.
fn minimum_encode_work(value: &NaturalSequence) -> usize {
    (0..=8192)
        .find(|work| {
            value
                .encode_cer(&Limits {
                    max_input_bytes: usize::MAX,
                    max_output_bytes: usize::MAX,
                    max_work_bits: *work,
                })
                .is_ok()
        })
        .expect("imported record must fit the bounded work probe")
}

/// Verify imported constructor endpoints and rejected values.
/// Inputs: none. Returns no value. Errors: assertion failures.
/// Source: `Small ::= INTEGER (0..5)`. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: imported range invariants.
/// Example: endpoints zero and five are constructible; negative one and six are not.
#[test]
fn imported_newtype_preserves_both_range_endpoints() {
    assert_eq!(Small::new(0).unwrap().value(), 0);
    assert_eq!(Small::new(5).unwrap().value(), 5);
    assert!(Small::new(-1).is_err());
    assert!(Small::new(6).is_err());
    let limits = Limits::default();
    for endpoint in [0, 5] {
        let value = NaturalSequence { value: Small::new(endpoint).unwrap(), tail: true };
        let wire = value.encode_cer(&limits).unwrap().bytes;
        assert_eq!(NaturalSequence::decode_cer(&wire, &limits).unwrap().value, value);
    }
}

/// Compare the approved natural SEQUENCE vectors and exact prefix consumption.
/// Inputs: none. Returns no value. Errors: codec or assertion failures.
/// Source: live generated C vectors and X.690. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: direct imported INTEGER.
/// Example: `value = 2` followed by `[4] IMPLICIT BOOLEAN TRUE`.
#[test]
fn natural_sequence_matches_c_and_preserves_prefix_consumption() {
    let limits = Limits::default();
    let value = NaturalSequence {
        value: Small::new(2).unwrap(),
        tail: true,
    };
    let definite = [0x30, 0x06, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff];
    let canonical = [0x30, 0x80, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff, 0, 0];
    assert_eq!(value.encode_der(&limits).unwrap().bytes, definite);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, canonical);
    assert_eq!(NaturalSequence::decode_ber(&definite, &limits).unwrap().value, value);
    assert_eq!(NaturalSequence::decode_ber(&canonical, &limits).unwrap().value, value);
    assert_eq!(NaturalSequence::decode_cer(&canonical, &limits).unwrap().value, value);
    assert!(NaturalSequence::decode_cer(&definite, &limits).is_err());

    let mut suffixed = canonical.to_vec();
    suffixed.push(0x5a);
    let decoded = NaturalSequence::decode_cer(&suffixed, &limits).unwrap();
    assert_eq!(decoded.value, value);
    assert_eq!(decoded.consumed_bytes, canonical.len());
    assert_eq!(decoded.consumed_bits, canonical.len() * 8);
    let mut ber_suffixed = definite.to_vec();
    ber_suffixed.push(0x5a);
    let decoded = NaturalSequence::decode_ber(&ber_suffixed, &limits).unwrap();
    assert_eq!(decoded.value, value);
    assert_eq!(decoded.consumed_bytes, definite.len());
    for end in 0..definite.len() {
        assert!(NaturalSequence::decode_ber(&definite[..end], &limits).is_err());
    }
    for end in 0..canonical.len() {
        assert!(NaturalSequence::decode_ber(&canonical[..end], &limits).is_err());
    }
    for end in 0..canonical.len() {
        assert!(NaturalSequence::decode_cer(&canonical[..end], &limits).is_err());
    }
}

/// Exercise OPTIONAL, IMPLICIT, and EXPLICIT imported fields under SEQUENCE.
/// Inputs: none. Returns no value. Errors: codec or assertion failures.
/// Source: live C vectors and X.680/X.690 tags. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: import composition slice.
/// Example: `[3] EXPLICIT` wraps exactly one INTEGER TLV.
#[test]
fn optional_implicit_and_explicit_sequence_forms_match_c_vectors() {
    let limits = Limits::default();
    let absent = OptionalSequence { value: None, tail: true };
    let absent_definite = [0x30, 0x03, 0x84, 0x01, 0xff];
    let absent_canonical = [0x30, 0x80, 0x84, 0x01, 0xff, 0, 0];
    assert_eq!(absent.encode_der(&limits).unwrap().bytes, absent_definite);
    assert_eq!(absent.encode_cer(&limits).unwrap().bytes, absent_canonical);
    assert_eq!(OptionalSequence::decode_cer(&absent_canonical, &limits).unwrap().value, absent);

    let present = OptionalSequence { value: Some(Small::new(2).unwrap()), tail: true };
    let present_canonical = [0x30, 0x80, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff, 0, 0];
    assert_eq!(
        present.encode_der(&limits).unwrap().bytes,
        [0x30, 0x06, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff]
    );
    assert_eq!(present.encode_cer(&limits).unwrap().bytes, present_canonical);
    assert_eq!(
        OptionalSequence::decode_cer(&present_canonical, &limits).unwrap().value,
        present
    );
    assert_eq!(OptionalSequence::decode_ber(
        &present.encode_der(&limits).unwrap().bytes,
        &limits
    ).unwrap().value, present);

    let implicit = ImplicitSequence { value: Small::new(2).unwrap(), tail: true };
    let implicit_definite = [0x30, 0x06, 0x83, 0x01, 0x02, 0x84, 0x01, 0xff];
    let implicit_canonical = [0x30, 0x80, 0x83, 0x01, 0x02, 0x84, 0x01, 0xff, 0, 0];
    assert_eq!(implicit.encode_der(&limits).unwrap().bytes, implicit_definite);
    assert_eq!(implicit.encode_cer(&limits).unwrap().bytes, implicit_canonical);
    assert_eq!(ImplicitSequence::decode_cer(&implicit_canonical, &limits).unwrap().value, implicit);

    let explicit = ExplicitSequence { value: Small::new(2).unwrap(), tail: true };
    let explicit_definite = [0x30, 0x08, 0xa3, 0x03, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff];
    let explicit_canonical = [
        0x30, 0x80, 0xa3, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x84, 0x01, 0xff, 0, 0,
    ];
    assert_eq!(explicit.encode_der(&limits).unwrap().bytes, explicit_definite);
    assert_eq!(explicit.encode_cer(&limits).unwrap().bytes, explicit_canonical);
    assert_eq!(ExplicitSequence::decode_cer(&explicit_canonical, &limits).unwrap().value, explicit);
}

/// Check imported INTEGER ordering under SET and its OPTIONAL form.
/// Inputs: none. Returns no value. Errors: codec or assertion failures.
/// Source: generated C SET vectors and X.690. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: imported SET fields.
/// Example: universal tag 2 sorts before context tag 4.
#[test]
fn imported_set_fields_sort_and_decode_unordered_ber() {
    let limits = Limits::default();
    let value = NaturalSet { tail: true, value: Small::new(2).unwrap() };
    let definite = [0x31, 0x06, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff];
    let canonical = [0x31, 0x80, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff, 0, 0];
    assert_eq!(value.encode_der(&limits).unwrap().bytes, definite);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, canonical);
    assert_eq!(NaturalSet::decode_cer(&canonical, &limits).unwrap().value, value);
    let reversed = [0x31, 0x80, 0x84, 0x01, 0xff, 0x02, 0x01, 0x02, 0, 0];
    assert_eq!(NaturalSet::decode_ber(&reversed, &limits).unwrap().value, value);
    assert!(NaturalSet::decode_cer(&reversed, &limits).is_err());

    let absent = OptionalSet { tail: true, value: None };
    let absent_definite = [0x31, 0x03, 0x84, 0x01, 0xff];
    let absent_canonical = [0x31, 0x80, 0x84, 0x01, 0xff, 0, 0];
    assert_eq!(absent.encode_der(&limits).unwrap().bytes, absent_definite);
    assert_eq!(absent.encode_cer(&limits).unwrap().bytes, absent_canonical);
    assert_eq!(OptionalSet::decode_cer(&absent_canonical, &limits).unwrap().value, absent);
    let present_set = OptionalSet { value: Some(Small::new(2).unwrap()), tail: true };
    let present_set_canonical = [0x31, 0x80, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff, 0, 0];
    assert_eq!(present_set.encode_cer(&limits).unwrap().bytes, present_set_canonical);
    assert_eq!(
        OptionalSet::decode_cer(&present_set_canonical, &limits).unwrap().value,
        present_set
    );

    let implicit = ImplicitSet { tail: true, value: Small::new(2).unwrap() };
    let implicit_definite = [0x31, 0x06, 0x83, 0x01, 0x02, 0x84, 0x01, 0xff];
    let implicit_canonical = [0x31, 0x80, 0x83, 0x01, 0x02, 0x84, 0x01, 0xff, 0, 0];
    assert_eq!(implicit.encode_der(&limits).unwrap().bytes, implicit_definite);
    assert_eq!(implicit.encode_cer(&limits).unwrap().bytes, implicit_canonical);
    assert_eq!(ImplicitSet::decode_ber(&implicit_definite, &limits).unwrap().value, implicit);
    assert_eq!(ImplicitSet::decode_cer(&implicit_canonical, &limits).unwrap().value, implicit);

    let explicit = ExplicitSet { tail: true, value: Small::new(2).unwrap() };
    let explicit_definite = [0x31, 0x08, 0xa3, 0x03, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff];
    let explicit_canonical = [
        0x31, 0x80, 0xa3, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x84, 0x01, 0xff, 0, 0,
    ];
    assert_eq!(explicit.encode_der(&limits).unwrap().bytes, explicit_definite);
    assert_eq!(explicit.encode_cer(&limits).unwrap().bytes, explicit_canonical);
    assert_eq!(ExplicitSet::decode_ber(&explicit_definite, &limits).unwrap().value, explicit);
    assert_eq!(ExplicitSet::decode_cer(&explicit_canonical, &limits).unwrap().value, explicit);
}

/// Verify scalar DEFAULT omission and emission beside an imported field.
/// Inputs: none. Returns no value. Errors: codec or assertion failures.
/// Source: generated C vectors. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: imported DEFAULT siblings.
/// Example: false is omitted; true is encoded as BOOLEAN TRUE.
#[test]
fn imported_integer_keeps_parent_boolean_default_behavior() {
    let limits = Limits::default();
    let omitted = DefaultSequence { value: Small::new(2).unwrap(), enabled: false };
    let omitted_definite = [0x30, 0x03, 0x02, 0x01, 0x02];
    let omitted_canonical = [0x30, 0x80, 0x02, 0x01, 0x02, 0, 0];
    assert_eq!(omitted.encode_der(&limits).unwrap().bytes, omitted_definite);
    assert_eq!(omitted.encode_cer(&limits).unwrap().bytes, omitted_canonical);
    assert_eq!(DefaultSequence::decode_cer(&omitted_canonical, &limits).unwrap().value, omitted);
    let emitted = DefaultSequence { value: Small::new(2).unwrap(), enabled: true };
    let emitted_definite = [0x30, 0x06, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff];
    let emitted_canonical = [0x30, 0x80, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0, 0];
    assert_eq!(emitted.encode_der(&limits).unwrap().bytes, emitted_definite);
    assert_eq!(emitted.encode_cer(&limits).unwrap().bytes, emitted_canonical);

    let set_default = DefaultSet { value: Small::new(2).unwrap(), enabled: false };
    let set_default_cer = [0x31, 0x80, 0x02, 0x01, 0x02, 0, 0];
    assert_eq!(set_default.encode_der(&limits).unwrap().bytes, [0x31, 0x03, 0x02, 0x01, 0x02]);
    assert_eq!(set_default.encode_cer(&limits).unwrap().bytes, set_default_cer);
    assert_eq!(DefaultSet::decode_cer(&set_default_cer, &limits).unwrap().value, set_default);
    let set_enabled = DefaultSet { enabled: true, ..set_default };
    let set_enabled_cer = [0x31, 0x80, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff, 0, 0];
    assert_eq!(set_enabled.encode_cer(&limits).unwrap().bytes, set_enabled_cer);
    assert_eq!(
        DefaultSet::decode_cer(&set_enabled_cer, &limits).unwrap().value,
        set_enabled
    );
    let explicit_default_false = [0x30, 0x06, 0x02, 0x01, 0x02, 0x01, 0x01, 0x00];
    assert_eq!(
        DefaultSequence::decode_ber(&explicit_default_false, &limits)
            .unwrap()
            .value,
        omitted
    );
    assert!(DefaultSequence::decode_cer(&explicit_default_false, &limits).is_err());
    let cer_default_false = [0x30, 0x80, 0x02, 0x01, 0x02, 0x01, 0x01, 0, 0, 0];
    assert!(DefaultSequence::decode_ber(&cer_default_false, &limits).is_ok());
    assert!(DefaultSequence::decode_cer(&cer_default_false, &limits).is_err());
    let explicit_set_default_false = [0x31, 0x06, 0x02, 0x01, 0x02, 0x84, 0x01, 0x00];
    assert!(DefaultSet::decode_ber(&explicit_set_default_false, &limits).is_ok());
    assert!(DefaultSet::decode_cer(&explicit_set_default_false, &limits).is_err());
    let cer_set_default_false = [0x31, 0x80, 0x02, 0x01, 0x02, 0x84, 0x01, 0, 0, 0];
    assert!(DefaultSet::decode_ber(&cer_set_default_false, &limits).is_ok());
    assert!(DefaultSet::decode_cer(&cer_set_default_false, &limits).is_err());
}

/// Verify imported-type shared input/output/work limits at exact boundaries.
/// Inputs: none. Returns no value. Errors: assertion failures or codec errors.
/// Source: generated CER vector and bounded record context. Date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: import limit accounting.
/// Example: exact input/output/work succeeds and each one-unit-short value fails.
#[test]
fn imported_scalar_uses_exact_parent_resource_limits() {
    let value = NaturalSequence { value: Small::new(2).unwrap(), tail: true };
    let limits = Limits::default();
    let canonical = value.encode_cer(&limits).unwrap().bytes;
    let work = minimum_decode_work(&canonical);
    let exact = Limits {
        max_input_bytes: canonical.len(),
        max_output_bytes: canonical.len(),
        max_work_bits: work,
    };
    assert_eq!(NaturalSequence::decode_cer(&canonical, &exact).unwrap().value, value);
    assert_eq!(value.encode_cer(&exact).unwrap().bytes, canonical);
    let encode_work = minimum_encode_work(&value);
    assert!(encode_work > 0);

    // Module ownership must not change work accounting for an equivalent local scalar.
    let local = LocalSequence { value: Local::new(2).unwrap(), tail: true };
    assert_eq!(LocalSequence::decode_cer(&canonical, &exact).unwrap().value, local);
    assert!(LocalSequence::decode_cer(&canonical, &Limits {
        max_work_bits: work - 1,
        ..exact
    }).is_err());
    assert_eq!(local.encode_cer(&Limits {
        max_work_bits: encode_work,
        ..exact
    }).unwrap().bytes, canonical);
    assert!(local.encode_cer(&Limits {
        max_work_bits: encode_work - 1,
        ..exact
    }).is_err());

    // Check the imported record against the same exact encode threshold.
    assert_eq!(
        value
            .encode_cer(&Limits {
                max_work_bits: encode_work,
                ..exact
            })
            .unwrap()
            .bytes,
        canonical
    );
    assert!(value
        .encode_cer(&Limits {
            max_work_bits: encode_work - 1,
            ..exact
        })
        .is_err());
    assert!(NaturalSequence::decode_cer(&canonical, &Limits {
        max_work_bits: work - 1,
        ..exact
    }).is_err());
    assert!(NaturalSequence::decode_cer(&canonical, &Limits {
        max_input_bytes: canonical.len() - 1,
        ..exact
    }).is_err());
    assert!(value.encode_cer(&Limits {
        max_output_bytes: canonical.len() - 1,
        ..limits
    }).is_err());
}

/// Reject malformed tags, wrappers, range values, and deterministic mutations.
/// Inputs: none. Returns no value. Errors: assertion failures or codec errors.
/// Source: X.690 and generated C range vector. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: imported malformed inputs.
/// Example: `[3] EXPLICIT` must contain one and only one INTEGER TLV.
#[test]
fn malformed_imported_values_and_mutations_are_bounded() {
    let limits = Limits::default();
    let wrong_natural_tag = [0x30, 0x06, 0x01, 0x01, 0xff, 0x84, 0x01, 0xff];
    let out_of_range = [0x30, 0x06, 0x02, 0x01, 0x06, 0x84, 0x01, 0xff];
    let wrong_explicit_inner = [0x30, 0x08, 0xa3, 0x03, 0x01, 0x01, 0xff, 0x84, 0x01, 0xff];
    let multiple_explicit_inner = [
        0x30, 0x0b, 0xa3, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03, 0x84, 0x01, 0xff,
    ];
    let duplicate_value = [0x30, 0x09, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03, 0x84, 0x01, 0xff];
    let unknown_member = [0x30, 0x06, 0x02, 0x01, 0x02, 0x85, 0x01, 0xff];
    let missing_required_tail = [0x30, 0x03, 0x02, 0x01, 0x02];
    let malformed_eoc = [0x30, 0x80, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff, 0, 1];
    for wire in [wrong_natural_tag.as_slice(), out_of_range.as_slice()] {
        assert!(NaturalSequence::decode_ber(wire, &limits).is_err());
    }
    assert!(ExplicitSequence::decode_ber(&wrong_explicit_inner, &limits).is_err());
    assert!(ExplicitSequence::decode_ber(&multiple_explicit_inner, &limits).is_err());
    for wire in [
        duplicate_value.as_slice(),
        unknown_member.as_slice(),
        missing_required_tail.as_slice(),
        malformed_eoc.as_slice(),
    ] {
        assert!(NaturalSequence::decode_ber(wire, &limits).is_err());
    }

    let seed = NaturalSequence { value: Small::new(2).unwrap(), tail: true };
    let canonical = seed.encode_cer(&limits).unwrap().bytes;
    for index in 0..canonical.len() {
        for mask in [1, 2, 4, 8, 16, 32, 64, 128] {
            let mut changed = canonical.clone();
            changed[index] ^= mask;
            if let Ok(decoded) = NaturalSequence::decode_ber(&changed, &limits) {
                assert!(decoded.consumed_bytes <= changed.len());
                assert!(decoded.consumed_bits <= changed.len() * 8);
            }
        }
    }
}
