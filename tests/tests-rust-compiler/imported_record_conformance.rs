//! BER/DER/CER vectors for directly imported named SEQUENCE and SET children.

use asn1c_generated::imported_common_alpha_client::AlphaPacket;
use asn1c_generated::imported_common_alpha_source::Common as AlphaCommon;
use asn1c_generated::imported_common_beta_client::BetaPacket;
use asn1c_generated::imported_common_beta_source::Common as BetaCommon;
use asn1c_generated::imported_default_client::DefaultParent;
use asn1c_generated::imported_empty_client::EmptyPair;
use asn1c_generated::imported_equivalent_client::{
    ImportedEquivalent, LocalEquivalent, LocalEquivalentLeaf,
};
use asn1c_generated::imported_nonempty_set_client::NonemptySetPair;
use asn1c_generated::imported_optional_order_client::OptionalOrder;
use asn1c_generated::imported_owned_client::OwnedPair;
use asn1c_generated::imported_record_base::{
    EmptyRemoteSeq, NonemptyRemoteSet, RemoteOwned, RemoteSeq,
};
use asn1c_generated::imported_repeated_client::RepeatedPair;
use asn1c_generated::imported_seq_pair_client::{LocalSet, SeqPair};
use asn1c_generated::imported_set_pair_client::{LocalPairSeq, SetPair};
use asn1c_runtime::Limits;

/// Find the smallest work budget accepted by the supplied operation.
///
/// Parameters: `succeeds` performs one operation with a candidate work limit.
/// Returns: the first successful limit from zero through 4096.
/// Errors: panics if no candidate budget succeeds.
/// Original source: generated record resource contract.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: imported record shared-context probes.
/// Example: `minimum_work(|work| value.encode_cer(&limits(work)).is_ok())`.
fn minimum_work(mut succeeds: impl FnMut(usize) -> bool) -> usize {
    (0..=4096)
        .find(|work| succeeds(*work))
        .expect("imported record operation must fit the bounded work probe")
}

/// Verify natural imported SEQUENCE/SET pairs, prefixes, and independent SET order.
///
/// Parameters: none. Returns: no value; assertions compare C vectors and values.
/// Errors: codec failures, malformed prefixes, or byte mismatches fail the test.
/// Original source: generated C differential vectors and X.690 record rules.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: imported record composition. Example: `RemoteSeq` plus a local SET.
#[test]
fn natural_imported_pairs_match_vectors_and_set_order() {
    let limits = Limits::default();
    let sequence = SeqPair {
        imported: RemoteSeq {
            number: 2,
            flag: Some(true),
        },
        local: LocalSet {
            number: 3,
            flag: true,
        },
    };
    let sequence_definite = [
        0x30, 0x10, 0x30, 0x06, 0x02, 1, 2, 0x01, 1, 0xff,
        0x31, 0x06, 0x80, 1, 3, 0x81, 1, 0xff,
    ];
    let sequence_canonical = [
        0x30, 0x80, 0x30, 0x80, 0x02, 1, 2, 0x01, 1, 0xff, 0, 0,
        0x31, 0x80, 0x80, 1, 3, 0x81, 1, 0xff, 0, 0, 0, 0,
    ];
    assert_eq!(sequence.encode_der(&limits).unwrap().bytes, sequence_definite);
    assert_eq!(sequence.encode_cer(&limits).unwrap().bytes, sequence_canonical);
    assert_eq!(SeqPair::decode_ber(&sequence_definite, &limits).unwrap().value, sequence);
    assert_eq!(SeqPair::decode_cer(&sequence_canonical, &limits).unwrap().value, sequence);
    assert!(SeqPair::decode_cer(&sequence_definite, &limits).is_err());

    let mut suffix = sequence_canonical.to_vec();
    suffix.push(0xee);
    let decoded = SeqPair::decode_cer(&suffix, &limits).unwrap();
    assert_eq!(decoded.value, sequence);
    assert_eq!(decoded.consumed_bytes, sequence_canonical.len());
    for end in 0..sequence_canonical.len() {
        assert!(SeqPair::decode_ber(&sequence_canonical[..end], &limits).is_err());
        assert!(SeqPair::decode_cer(&sequence_canonical[..end], &limits).is_err());
    }

    let set = SetPair {
        imported: NonemptyRemoteSet {
            number: 2,
            flag: true,
        },
        local: LocalPairSeq {
            number: 3,
            flag: true,
        },
    };
    let set_der = [
        0x31, 0x10, 0x30, 0x06, 0x02, 1, 3, 0x01, 1, 0xff,
        0x31, 0x06, 0x80, 1, 2, 0x81, 1, 0xff,
    ];
    let set_cer = [
        0x31, 0x80, 0x30, 0x80, 0x02, 1, 3, 0x01, 1, 0xff, 0, 0,
        0x31, 0x80, 0x80, 1, 2, 0x81, 1, 0xff, 0, 0, 0, 0,
    ];
    assert_eq!(set.encode_der(&limits).unwrap().bytes, set_der);
    assert_eq!(set.encode_cer(&limits).unwrap().bytes, set_cer);
    assert_eq!(SetPair::decode_cer(&set_cer, &limits).unwrap().value, set);
    let reversed = [
        0x31, 0x10, 0x31, 0x06, 0x81, 1, 0xff, 0x80, 1, 2,
        0x30, 0x06, 0x02, 1, 3, 0x01, 1, 0xff,
    ];
    assert_eq!(SetPair::decode_ber(&reversed, &limits).unwrap().value, set);
    assert!(SetPair::decode_cer(&reversed, &limits).is_err());
    let reversed_cer = [
        0x31, 0x80, 0x31, 0x80, 0x81, 1, 0xff, 0x80, 1, 2, 0, 0,
        0x30, 0x80, 0x02, 1, 3, 0x01, 1, 0xff, 0, 0, 0, 0,
    ];
    assert_eq!(SetPair::decode_ber(&reversed_cer, &limits).unwrap().value, set);
    assert!(SetPair::decode_cer(&reversed_cer, &limits).is_err());
}

/// Check repeated imported targets and OPTIONAL parent-child states.
///
/// Parameters: none. Returns: no value; assertions compare DER/CER vectors.
/// Errors: codec failures, duplicate tags, or malformed wrappers fail the test.
/// Original source: C vectors for distinct IMPLICIT and EXPLICIT tags.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: repeated imported record references.
/// Example: `RemoteSeq` appears twice under tags `[2]` and `[3]`.
#[test]
fn repeated_target_tags_and_optional_states_match_vectors() {
    let limits = Limits::default();
    let remote = RemoteSeq {
        number: 2,
        flag: Some(true),
    };
    let repeated = RepeatedPair {
        implicit_child: remote.clone(),
        explicit_child: remote.clone(),
    };
    let repeated_definite = [
        0x30, 0x12, 0xa2, 0x06, 0x02, 1, 2, 0x01, 1, 0xff,
        0xa3, 0x08, 0x30, 0x06, 0x02, 1, 2, 0x01, 1, 0xff,
    ];
    let repeated_canonical = [
        0x30, 0x80, 0xa2, 0x80, 0x02, 1, 2, 0x01, 1, 0xff, 0, 0,
        0xa3, 0x80, 0x30, 0x80, 0x02, 1, 2, 0x01, 1, 0xff, 0, 0,
        0, 0, 0, 0,
    ];
    assert_eq!(repeated.encode_der(&limits).unwrap().bytes, repeated_definite);
    assert_eq!(repeated.encode_cer(&limits).unwrap().bytes, repeated_canonical);
    assert_eq!(RepeatedPair::decode_ber(&repeated_definite, &limits).unwrap().value, repeated);
    assert_eq!(RepeatedPair::decode_cer(&repeated_canonical, &limits).unwrap().value, repeated);
    assert!(RepeatedPair::decode_cer(&repeated_definite, &limits).is_err());

    let absent = OptionalOrder {
        explicit_child: None,
        marker: true,
        implicit_child: remote.clone(),
    };
    let absent_definite = [
        0x31, 0x0b, 0x80, 1, 0xff, 0xa2, 0x06,
        0x02, 1, 2, 0x01, 1, 0xff,
    ];
    let absent_canonical = [
        0x31, 0x80, 0x80, 1, 0xff, 0xa2, 0x80,
        0x02, 1, 2, 0x01, 1, 0xff, 0, 0, 0, 0,
    ];
    assert_eq!(absent.encode_der(&limits).unwrap().bytes, absent_definite);
    assert_eq!(absent.encode_cer(&limits).unwrap().bytes, absent_canonical);
    assert_eq!(OptionalOrder::decode_cer(&absent_canonical, &limits).unwrap().value, absent);

    let present = OptionalOrder {
        explicit_child: Some(remote.clone()),
        marker: true,
        implicit_child: remote,
    };
    let present_definite = [
        0x31, 0x15, 0x80, 1, 0xff, 0xa2, 0x06,
        0x02, 1, 2, 0x01, 1, 0xff, 0xa3, 0x08,
        0x30, 0x06, 0x02, 1, 2, 0x01, 1, 0xff,
    ];
    let present_canonical = [
        0x31, 0x80, 0x80, 1, 0xff, 0xa2, 0x80,
        0x02, 1, 2, 0x01, 1, 0xff, 0, 0,
        0xa3, 0x80, 0x30, 0x80, 0x02, 1, 2, 0x01, 1, 0xff,
        0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(present.encode_der(&limits).unwrap().bytes, present_definite);
    assert_eq!(present.encode_cer(&limits).unwrap().bytes, present_canonical);
    assert_eq!(OptionalOrder::decode_cer(&present_canonical, &limits).unwrap().value, present);

    let duplicate = [
        0x31, 0x80, 0x80, 1, 0xff,
        0xa2, 0x80, 0x02, 1, 2, 0x01, 1, 0xff, 0, 0,
        0xa2, 0x80, 0x02, 1, 2, 0x01, 1, 0xff, 0, 0, 0, 0,
    ];
    let wrong_explicit = [
        0x30, 0x0e, 0xa2, 0x05, 0x30, 0x03, 0x02, 1, 2,
        0xa3, 0x05, 0x31, 0x03, 0x02, 1, 3,
    ];
    assert!(OptionalOrder::decode_ber(&duplicate, &limits).is_err());
    assert!(RepeatedPair::decode_ber(&wrong_explicit, &limits).is_err());
}

/// Check empty/nonempty imported targets and owned OCTET/BIT STRING leaves.
///
/// Parameters: none. Returns: no value; assertions compare fixed C wire bytes.
/// Errors: codec failures, malformed padding, or truncated children fail the test.
/// Original source: X.690 constructed types and generated C vectors.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: imported empty and owned child types.
/// Example: `RemoteOwned` retains two octets and three significant bits.
#[test]
fn empty_set_and_owned_imports_preserve_values_and_boundaries() {
    let limits = Limits::default();
    let empty = EmptyPair {
        child: EmptyRemoteSeq {},
    };
    let empty_definite = [0x30, 0x02, 0x30, 0x00];
    let empty_canonical = [0x30, 0x80, 0x30, 0x80, 0, 0, 0, 0];
    assert_eq!(empty.encode_der(&limits).unwrap().bytes, empty_definite);
    assert_eq!(empty.encode_cer(&limits).unwrap().bytes, empty_canonical);
    assert_eq!(EmptyPair::decode_cer(&empty_canonical, &limits).unwrap().value, empty);

    let nonempty = NonemptySetPair {
        child: NonemptyRemoteSet {
            number: 2,
            flag: true,
        },
    };
    let set_der = [0x30, 0x08, 0x31, 0x06, 0x80, 1, 2, 0x81, 1, 0xff];
    let set_cer = [0x30, 0x80, 0x31, 0x80, 0x80, 1, 2, 0x81, 1, 0xff, 0, 0, 0, 0];
    assert_eq!(nonempty.encode_der(&limits).unwrap().bytes, set_der);
    assert_eq!(nonempty.encode_cer(&limits).unwrap().bytes, set_cer);
    assert_eq!(NonemptySetPair::decode_cer(&set_cer, &limits).unwrap().value, nonempty);

    let owned_value = RemoteOwned {
        octets: vec![0xaa, 0xbb],
        bits: vec![0xa0],
    };
    let owned = OwnedPair {
        implicit_child: owned_value.clone(),
        explicit_child: owned_value,
    };
    let owned_definite = [
        0x30, 0x16, 0xa2, 0x08, 0x04, 2, 0xaa, 0xbb, 0x03, 2, 5, 0xa0,
        0xa3, 0x0a, 0x30, 0x08, 0x04, 2, 0xaa, 0xbb, 0x03, 2, 5, 0xa0,
    ];
    let owned_canonical = [
        0x30, 0x80, 0xa2, 0x80, 0x04, 2, 0xaa, 0xbb, 0x03, 2, 5, 0xa0, 0, 0,
        0xa3, 0x80, 0x30, 0x80, 0x04, 2, 0xaa, 0xbb, 0x03, 2, 5, 0xa0,
        0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(owned.encode_der(&limits).unwrap().bytes, owned_definite);
    assert_eq!(owned.encode_cer(&limits).unwrap().bytes, owned_canonical);
    assert_eq!(OwnedPair::decode_ber(&owned_definite, &limits).unwrap().value, owned);
    assert_eq!(OwnedPair::decode_cer(&owned_canonical, &limits).unwrap().value, owned);

    let mut bad_padding = owned_canonical;
    bad_padding[25] = 0xa1;
    assert_eq!(OwnedPair::decode_ber(&bad_padding, &limits).unwrap().value, owned);
    assert!(OwnedPair::decode_cer(&bad_padding, &limits).is_err());
    let mut wrong_second_child = owned_canonical;
    wrong_second_child[16] = 0x31;
    assert!(OwnedPair::decode_ber(&wrong_second_child, &limits).is_err());
    assert!(OwnedPair::decode_cer(&wrong_second_child, &limits).is_err());
    for end in 0..owned_canonical.len() {
        assert!(OwnedPair::decode_ber(&owned_canonical[..end], &limits).is_err());
        assert!(OwnedPair::decode_cer(&owned_canonical[..end], &limits).is_err());
    }
    for index in 0..owned_canonical.len() {
        for mask in [1, 2, 4, 8, 16, 32, 64, 128] {
            let mut mutated = owned_canonical;
            mutated[index] ^= mask;
            if let Ok(decoded) = OwnedPair::decode_ber(&mutated, &limits) {
                assert!(decoded.consumed_bytes <= mutated.len());
            }
        }
    }
}

/// Verify parent DEFAULT omission and strict CER rejection of present defaults.
///
/// Parameters: none. Returns: no value; assertions compare C vectors and values.
/// Errors: codec failures or an incorrectly accepted noncanonical default fail.
/// Original source: ASN.1 DEFAULT rules and generated C vectors.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: imported-child parent defaults.
/// Example: a false BOOLEAN and INTEGER 3 default are omitted by both encoders.
#[test]
fn parent_scalar_defaults_are_omitted_and_cer_rejects_explicit_defaults() {
    let limits = Limits::default();
    let value = DefaultParent {
        child: RemoteSeq {
            number: 2,
            flag: Some(true),
        },
        enabled: false,
        count: 3,
    };
    let der = [0x30, 0x08, 0x30, 0x06, 0x02, 1, 2, 0x01, 1, 0xff];
    let cer = [0x30, 0x80, 0x30, 0x80, 0x02, 1, 2, 0x01, 1, 0xff, 0, 0, 0, 0];
    assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(DefaultParent::decode_ber(&der, &limits).unwrap().value, value);
    assert_eq!(DefaultParent::decode_cer(&cer, &limits).unwrap().value, value);

    let present_definite = [
        0x30, 0x0e, 0x30, 0x06, 0x02, 1, 2, 0x01, 1, 0xff,
        0x01, 1, 0x00, 0x02, 1, 3,
    ];
    let present_canonical = [
        0x30, 0x80, 0x30, 0x80, 0x02, 1, 2, 0x01, 1, 0xff, 0, 0,
        0x01, 1, 0x00, 0x02, 1, 3, 0, 0,
    ];
    assert_eq!(DefaultParent::decode_ber(&present_definite, &limits).unwrap().value, value);
    assert!(DefaultParent::decode_cer(&present_canonical, &limits).is_err());
    assert!(DefaultParent::decode_ber(
        &der,
        &Limits { max_work_bits: 0, ..limits }
    ).is_err());
}

/// Compare shared work budgets for structurally equivalent local/imported children.
///
/// Parameters: none. Returns: no value; assertions compare exact minima.
/// Errors: no viable budget or a reset child context fails the test.
/// Original source: generated record resource contract and local/imported vectors.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: shared context regression. Example: both schemas encode to identical TLVs.
#[test]
fn imported_child_uses_the_same_operation_budget_as_a_local_child() {
    let limits = Limits::default();
    let local = LocalEquivalent {
        child: LocalEquivalentLeaf {
            number: 2,
            flag: Some(true),
        },
        tail: true,
    };
    let imported = ImportedEquivalent {
        child: RemoteSeq {
            number: 2,
            flag: Some(true),
        },
        tail: true,
    };
    let der = [
        0x30, 0x0b, 0x30, 0x06, 0x02, 1, 2, 0x01, 1, 0xff, 0x84, 1, 0xff,
    ];
    let cer = [
        0x30, 0x80, 0x30, 0x80, 0x02, 1, 2, 0x01, 1, 0xff, 0, 0,
        0x84, 1, 0xff, 0, 0,
    ];
    assert_eq!(local.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(imported.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(local.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(imported.encode_cer(&limits).unwrap().bytes, cer);

    let local_encode = minimum_work(|work| {
        local.encode_cer(&Limits {
            max_output_bytes: cer.len(),
            max_work_bits: work,
            ..limits
        }).is_ok()
    });
    let imported_encode = minimum_work(|work| {
        imported.encode_cer(&Limits {
            max_output_bytes: cer.len(),
            max_work_bits: work,
            ..limits
        }).is_ok()
    });
    let local_decode = minimum_work(|work| {
        LocalEquivalent::decode_cer(&cer, &Limits {
            max_input_bytes: cer.len(),
            max_output_bytes: cer.len(),
            max_work_bits: work,
        }).is_ok()
    });
    let imported_decode = minimum_work(|work| {
        ImportedEquivalent::decode_cer(&cer, &Limits {
            max_input_bytes: cer.len(),
            max_output_bytes: cer.len(),
            max_work_bits: work,
        }).is_ok()
    });
    assert_eq!(imported_encode, local_encode);
    assert_eq!(imported_decode, local_decode);
    assert!(imported.encode_cer(&Limits {
        max_work_bits: imported_encode - 1,
        ..limits
    }).is_err());
    let short_output = Limits {
        max_output_bytes: cer.len() - 1,
        ..limits
    };
    assert!(local.encode_cer(&short_output).is_err());
    assert!(imported.encode_cer(&short_output).is_err());
    assert!(ImportedEquivalent::decode_cer(&cer, &Limits {
        max_input_bytes: cer.len(),
        max_output_bytes: cer.len(),
        max_work_bits: imported_decode - 1,
    }).is_err());
    let short_input = Limits {
        max_input_bytes: cer.len() - 1,
        ..limits
    };
    assert!(LocalEquivalent::decode_cer(&cer, &short_input).is_err());
    assert!(ImportedEquivalent::decode_cer(&cer, &short_input).is_err());
}

/// Keep same-spelled record assignments independent across source modules.
///
/// Parameters: none. Returns: no value; assertions compare range-specific values.
/// Errors: generated path collisions or leaked bounds fail the test.
/// Original source: two modules exporting `Common` with distinct ranges.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: normalized crate path regression.
/// Example: Alpha permits 0..3 while Beta permits 0..7.
#[test]
fn same_spelled_imported_targets_keep_independent_bounds() {
    let limits = Limits::default();
    let alpha = AlphaPacket {
        child: AlphaCommon { value: 2 },
    };
    let beta = BetaPacket {
        child: BetaCommon { value: 6 },
    };
    let alpha_der = [0x30, 0x05, 0x30, 0x03, 0x02, 1, 2];
    let beta_der = [0x30, 0x05, 0x30, 0x03, 0x02, 1, 6];
    assert_eq!(alpha.encode_der(&limits).unwrap().bytes, alpha_der);
    assert_eq!(beta.encode_der(&limits).unwrap().bytes, beta_der);
    assert_eq!(AlphaPacket::decode_ber(&alpha_der, &limits).unwrap().value, alpha);
    assert_eq!(BetaPacket::decode_ber(&beta_der, &limits).unwrap().value, beta);
    assert!(AlphaPacket { child: AlphaCommon { value: 4 } }
        .encode_der(&limits).is_err());
    assert!(AlphaPacket::decode_ber(&beta_der, &limits).is_err());
    assert!(BetaPacket::decode_ber(&alpha_der, &limits).is_ok());
}
