//! BER/CER compatibility and public API tests for packed BOOLEAN records.

use asn1c_generated::bool_import_base::RemoteLeaf;
use asn1c_generated::bool_import_client::ImportedParent;
use asn1c_generated::bool_storage::{
    Bool4, InlineParent, InlineParentChild, LocalLeaf, NamedParent, OwnedFour, SixRequiredSet,
};
use asn1c_runtime::Limits;

/// Find the smallest work budget accepted by one supplied operation.
///
/// Parameters: `succeeds` tests a candidate work limit. Returns the first success
/// from 0 through 4096. Errors: panics if the operation exceeds this bounded probe.
/// Original source: generated record resource contract. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: bitset resource checks.
/// Example: `minimum_work(|work| value.encode_cer(&limits(work)).is_ok())`.
fn minimum_work(mut succeeds: impl FnMut(usize) -> bool) -> usize {
    (0..=4096)
        .find(|work| succeeds(*work))
        .expect("BOOLEAN record must fit the bounded work probe")
}

/// Check fixed vectors, DEFAULT omission, and the Rust keyword field accessor.
///
/// Parameters: none. Returns no value; exact vectors and accessors are asserted.
/// Errors: byte, value, or strict-canonicality mismatches fail the test.
/// Original source: C DER/CER vectors for `Bool4`. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: packed BOOLEAN API.
/// Example: `Bool4::new([true, false, false, true], (2, None))`.
#[test]
fn bool4_vectors_and_defaults_are_stable() {
    let limits = Limits::default();
    let defaults = Bool4::new([true, false, false, true], (2, None));
    let der = [0x30, 0x06, 0x01, 0x01, 0xff, 0x80, 0x01, 0x00];
    let cer = [0x30, 0x80, 0x01, 0x01, 0xff, 0x80, 0x01, 0x00, 0, 0];
    assert!(defaults.get_first());
    assert!(!defaults.get_asn1_type());
    assert_eq!(defaults.get_maybe(), None);
    assert!(!defaults.get_third());
    assert!(defaults.get_fourth());
    assert_eq!(defaults.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(defaults.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(Bool4::decode_ber(&der, &limits).unwrap().value, defaults);
    assert_eq!(Bool4::decode_cer(&cer, &limits).unwrap().value, defaults);

    let present = Bool4::new([true, false, true, false], (4, Some(false)));
    // Independent C bytes exercise present nondefault values and OPTIONAL FALSE.
    let definite_present = [
        0x30, 0x14, 1, 1, 0xff, 2, 1, 4, 0x80, 1, 0, 0x81, 1, 0, 0xa2, 3, 1, 1, 0xff, 0x83, 1, 0,
    ];
    let canonical_present = [
        0x30, 0x80, 1, 1, 0xff, 2, 1, 4, 0x80, 1, 0, 0x81, 1, 0, 0xa2, 0x80, 1, 1, 0xff, 0, 0,
        0x83, 1, 0, 0, 0,
    ];
    assert_eq!(present.encode_der(&limits).unwrap().bytes, definite_present);
    assert_eq!(
        present.encode_cer(&limits).unwrap().bytes,
        canonical_present
    );
    let encoded = present.encode_cer(&limits).unwrap();
    assert_eq!(
        Bool4::decode_cer(&encoded.bytes, &limits).unwrap().value,
        present
    );
    let mut explicit_default = vec![0x30, 0x80, 0x01, 0x01, 0xff, 0x80, 0x01, 0x00];
    explicit_default.extend_from_slice(&[0xa2, 0x80, 0x01, 0x01, 0x00, 0, 0, 0, 0]);
    assert_eq!(
        Bool4::decode_ber(&explicit_default, &limits).unwrap().value,
        defaults
    );
    assert!(Bool4::decode_cer(&explicit_default, &limits).is_err());
}

/// Exercise all sixteen packed patterns with OPTIONAL and INTEGER sibling states.
///
/// Parameters: none. Returns no value; DER/CER roundtrips and accessors are checked.
/// Errors: any pattern, setter, getter, or roundtrip mismatch fails.
/// Original source: packed `Bool4` fields and public accessors. Version/date:
/// 2026-11-01. Responsible party: asn1c maintainers. History: bitset equivalence.
/// Example: iterate each four-bit value and optional BOOLEAN state.
#[test]
fn bool4_all_patterns_and_optional_states_round_trip() {
    let limits = Limits::default();
    for pattern in 0_u8..16 {
        let packed = core::array::from_fn(|index| pattern & (1 << index) != 0);
        for (count, maybe) in [(2, None), (4, Some(false)), (5, Some(true))] {
            let value = Bool4::new(packed, (count, maybe));
            assert_eq!(
                [
                    value.get_first(),
                    value.get_asn1_type(),
                    value.get_third(),
                    value.get_fourth()
                ],
                packed,
            );
            assert_eq!(value.get_maybe(), maybe);
            let mut changed = value.clone();
            changed.set_asn1_type(!packed[1]);
            assert_eq!(changed.get_asn1_type(), !packed[1]);
            changed.set_asn1_type(packed[1]);
            let der = value.encode_der(&limits).unwrap().bytes;
            let cer = value.encode_cer(&limits).unwrap().bytes;
            assert_eq!(Bool4::decode_ber(&der, &limits).unwrap().value, value);
            assert_eq!(Bool4::decode_cer(&cer, &limits).unwrap().value, value);
        }
    }
}

/// Verify alternating six-bit SET values and canonical tag order.
///
/// Parameters: none. Returns no value; fixed DER/CER vectors are asserted.
/// Errors: encoding, decoding, or accessor mismatch fails the test.
/// Original source: generated C six-BOOLEAN SET vectors. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: packed SET boundary.
/// Example: encode `[false, true, false, true, false, true]`.
#[test]
fn six_required_boolean_set_matches_alternating_vectors() {
    let limits = Limits::default();
    let mut value = SixRequiredSet::new([false, true, false, true, false, true], ());
    let der = [
        0x31, 0x12, 0x01, 0x01, 0x00, 0x80, 0x01, 0xff, 0x81, 0x01, 0x00, 0x82, 0x01, 0xff, 0x83,
        0x01, 0x00, 0x84, 0x01, 0xff,
    ];
    let cer = [
        0x31, 0x80, 0x01, 0x01, 0x00, 0x80, 0x01, 0xff, 0x81, 0x01, 0x00, 0x82, 0x01, 0xff, 0x83,
        0x01, 0x00, 0x84, 0x01, 0xff, 0, 0,
    ];
    value.set_sixth(false);
    assert!(!value.get_sixth());
    value.set_sixth(true);
    assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(
        SixRequiredSet::decode_cer(&cer, &limits).unwrap().value,
        value
    );
}

/// Cover inline, named-local, and owned-field packed child records.
///
/// Parameters: none. Returns no value; child bytes and values are compared.
/// Errors: nested callback, accessor, or codec mismatches fail the test.
/// Original source: `BoolStorage.asn1` record shapes and C codec rules.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: nested bitset storage. Example: `InlineParentChild::new(flags, ())`.
#[test]
fn inline_named_and_owned_children_keep_packed_boolean_values() {
    let limits = Limits::default();
    let inline_child = InlineParentChild::new([true, false, true, false], ());
    let inline = InlineParent {
        child: inline_child,
        enabled: false,
        count: 2,
    };
    let inline_definite = [
        0x30, 0x10, 0x30, 0x0e, 0x01, 0x01, 0xff, 0x80, 0x01, 0x00, 0xa1, 0x03, 0x01, 0x01, 0xff,
        0x82, 0x01, 0x00,
    ];
    let inline_canonical = [
        0x30, 0x80, 0x30, 0x80, 0x01, 0x01, 0xff, 0x80, 0x01, 0x00, 0xa1, 0x80, 0x01, 0x01, 0xff,
        0, 0, 0x82, 0x01, 0x00, 0, 0, 0, 0,
    ];
    assert_eq!(inline.encode_der(&limits).unwrap().bytes, inline_definite);
    assert_eq!(inline.encode_cer(&limits).unwrap().bytes, inline_canonical);
    assert_eq!(
        InlineParent::decode_cer(&inline_canonical, &limits)
            .unwrap()
            .value,
        inline
    );

    let leaf = LocalLeaf::new([true, false, true, false], ());
    let named = NamedParent {
        child: Some(leaf),
        enabled: false,
        count: 2,
    };
    // Match C's explicit wrapper and all child/parent end-of-contents markers.
    let definite_named = [
        0x30, 18, 0xa3, 16, 0x30, 14, 1, 1, 0xff, 0x80, 1, 0, 0xa1, 3, 1, 1, 0xff, 0x82, 1, 0,
    ];
    let canonical_named = [
        0x30, 0x80, 0xa3, 0x80, 0x30, 0x80, 1, 1, 0xff, 0x80, 1, 0, 0xa1, 0x80, 1, 1, 0xff, 0, 0,
        0x82, 1, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(named.encode_der(&limits).unwrap().bytes, definite_named);
    assert_eq!(named.encode_cer(&limits).unwrap().bytes, canonical_named);
    let decoded =
        NamedParent::decode_cer(&named.encode_cer(&limits).unwrap().bytes, &limits).unwrap();
    assert_eq!(decoded.value, named);
    let owned = OwnedFour::new([true, false, true, false], (vec![0xaa, 0xbb],));
    let decoded =
        OwnedFour::decode_cer(&owned.encode_cer(&limits).unwrap().bytes, &limits).unwrap();
    assert_eq!(decoded.value, owned);
    assert!(!decoded.value.get_fourth());
}

/// Roundtrip a packed imported SET child and verify suffix/truncation handling.
///
/// Parameters: none. Returns no value; values, canonical bytes, and consumption match.
/// Errors: malformed prefix, child, or callback behavior fails the test.
/// Original source: `BoolImportBase` C SET vector and imported callback API.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: imported bitset child. Example: import `RemoteLeaf` under EXPLICIT tag.
#[test]
fn imported_set_child_preserves_prefix_and_rejects_truncations() {
    let limits = Limits::default();
    let remote = RemoteLeaf::new([true, false, true, false], ());
    let imported = ImportedParent {
        child: remote,
        enabled: false,
        count: 2,
    };
    let der = [
        0x31, 0x12, 0xa4, 0x10, 0x31, 0x0e, 0x80, 0x01, 0xff, 0x81, 0x01, 0x00, 0xa2, 0x03, 0x01,
        0x01, 0xff, 0x83, 0x01, 0x00,
    ];
    let cer = [
        0x31, 0x80, 0xa4, 0x80, 0x31, 0x80, 0x80, 0x01, 0xff, 0x81, 0x01, 0x00, 0xa2, 0x80, 0x01,
        0x01, 0xff, 0, 0, 0x83, 0x01, 0x00, 0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(imported.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(imported.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(
        ImportedParent::decode_ber(&der, &limits).unwrap().value,
        imported
    );
    let mut suffixed = cer.to_vec();
    suffixed.push(0xee);
    let decoded = ImportedParent::decode_cer(&suffixed, &limits).unwrap();
    assert_eq!(decoded.value, imported);
    assert_eq!(decoded.consumed_bytes, cer.len());
    for end in 0..cer.len() {
        assert!(ImportedParent::decode_ber(&cer[..end], &limits).is_err());
        assert!(ImportedParent::decode_cer(&cer[..end], &limits).is_err());
    }
}

/// Check exact input/output/work boundaries and deterministic hostile mutations.
///
/// Parameters: none. Returns no value; exact limits and successful re-encodes assert.
/// Errors: limit acceptance, panic, or invalid successful roundtrip fails.
/// Original source: runtime limits and deterministic CER bit mutations.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: packed record robustness. Example: flip each bit of one canonical value.
#[test]
fn bool4_limits_mutations_and_truncations_are_bounded() {
    let value = Bool4::new([true, false, true, false], (4, Some(true)));
    let defaults = Limits::default();
    let cer = value.encode_cer(&defaults).unwrap().bytes;
    let encode_work = minimum_work(|work| {
        value
            .encode_cer(&Limits {
                max_output_bytes: cer.len(),
                max_work_bits: work,
                ..defaults
            })
            .is_ok()
    });
    assert!(value
        .encode_cer(&Limits {
            max_output_bytes: cer.len(),
            max_work_bits: encode_work,
            ..defaults
        })
        .is_ok());
    assert!(value
        .encode_cer(&Limits {
            max_output_bytes: cer.len(),
            max_work_bits: encode_work - 1,
            ..defaults
        })
        .is_err());
    assert!(value
        .encode_cer(&Limits {
            max_output_bytes: cer.len() - 1,
            ..defaults
        })
        .is_err());

    let decode_work = minimum_work(|work| {
        Bool4::decode_cer(
            &cer,
            &Limits {
                max_input_bytes: cer.len(),
                max_output_bytes: cer.len(),
                max_work_bits: work,
            },
        )
        .is_ok()
    });
    let exact = Bool4::decode_cer(
        &cer,
        &Limits {
            max_input_bytes: cer.len(),
            max_output_bytes: cer.len(),
            max_work_bits: decode_work,
        },
    )
    .unwrap();
    assert_eq!(exact.value, value);
    assert!(Bool4::decode_cer(
        &cer,
        &Limits {
            max_input_bytes: cer.len(),
            max_output_bytes: cer.len(),
            max_work_bits: decode_work - 1,
        }
    )
    .is_err());
    assert!(Bool4::decode_cer(
        &cer,
        &Limits {
            max_input_bytes: cer.len() - 1,
            ..defaults
        }
    )
    .is_err());
    for end in 0..cer.len() {
        assert!(Bool4::decode_ber(&cer[..end], &defaults).is_err());
        assert!(Bool4::decode_cer(&cer[..end], &defaults).is_err());
    }
    for index in 0..cer.len() {
        for mask in [1_u8, 0x80] {
            let mut mutated = cer.clone();
            mutated[index] ^= mask;
            if let Ok(decoded) = Bool4::decode_ber(&mutated, &defaults) {
                let consumed = decoded.consumed_bytes;
                assert!(consumed <= mutated.len());
                let canonical = decoded.value.encode_der(&defaults).unwrap().bytes;
                assert_eq!(
                    Bool4::decode_ber(&canonical, &defaults).unwrap().value,
                    decoded.value
                );
            }
            if let Ok(decoded) = Bool4::decode_cer(&mutated, &defaults) {
                let consumed = decoded.consumed_bytes;
                assert!(consumed <= mutated.len());
                let canonical = decoded.value.encode_cer(&defaults).unwrap().bytes;
                assert_eq!(canonical, mutated[..consumed]);
            }
        }
    }
}
