//! BER/DER/CER coverage for one same-module named SEQUENCE child.

use asn1c_generated::named_sequence_record::{
    Inner, InnerLeaves, InnerLeavesMode, Packet, PacketLeaves, SequenceExplicit, SequenceImplicit,
    SequenceOptional, SetDefaults, SetExplicit, SetImplicit, SetOptional, SetPacket,
};
use asn1c_runtime::Limits;

/// Verify a natural required child shares its parent's canonical codec context.
///
/// Inputs: none. Returns no value. Errors are assertion failures or codec errors.
/// Source: live C vectors and X.690. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: named SEQUENCE child gate.
/// Example: `(2, TRUE)` is nested before context tag 4.
#[test]
fn natural_sequence_child_matches_c_der_cer_and_prefixes() {
    let limits = Limits::default();
    let value = Packet {
        before: false,
        child: Inner {
            number: 2,
            flag: true,
        },
        after: true,
    };
    let der = [
        0x30, 0x0b, 0x30, 0x06, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0x84, 0x01, 0xff,
    ];
    let cer = [
        0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0, 0, 0x84, 0x01, 0xff, 0, 0,
    ];
    assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(Packet::decode_ber(&der, &limits).unwrap().value, value);
    assert_eq!(Packet::decode_ber(&cer, &limits).unwrap().value, value);
    assert!(Packet::decode_cer(&der, &limits).is_err());
    let mut suffixed = cer.to_vec();
    suffixed.push(0x5a);
    let decoded = Packet::decode_cer(&suffixed, &limits).unwrap();
    assert_eq!(decoded.value, value);
    assert_eq!(decoded.consumed_bytes, cer.len());
    assert_eq!(decoded.consumed_bits, cer.len() * 8);

    let child_alias = [
        0x30, 0x80, 0x3f, 0x10, 0x80, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0, 0, 0x84, 0x01, 0xff,
        0, 0,
    ];
    let decoded_alias = Packet::decode_ber(&child_alias, &limits).unwrap();
    assert_eq!(decoded_alias.value, value);
    assert_eq!(decoded_alias.consumed_bytes, child_alias.len());
    assert!(Packet::decode_cer(&child_alias, &limits).is_err());
}

/// Verify named-target ENUMERATED and bounded tagged BIT/OCTET leaves.
///
/// Inputs: none. Returns no value. Errors are assertion failures or codec errors.
/// Source: live C vectors for the five-leaf target. Date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: target AST/name resolution.
/// Example: the parent's nested target preserves its generated enum type.
#[test]
fn named_target_enumerated_and_bounded_string_leaves_match_c() {
    let limits = Limits::default();
    let value = PacketLeaves {
        child: InnerLeaves {
            number: 2,
            flag: true,
            mode: InnerLeavesMode::On,
            data: vec![0xaa],
            bits: vec![0xa0],
        },
    };
    let der = [
        0x30, 0x12, 0x30, 0x10, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0x0a, 0x01, 0x01, 0x81, 0x01,
        0xaa, 0x03, 0x02, 0x03, 0xa0,
    ];
    let cer = [
        0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0x0a, 0x01, 0x01, 0x81, 0x01,
        0xaa, 0x03, 0x02, 0x03, 0xa0, 0, 0, 0, 0,
    ];
    assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(
        PacketLeaves::decode_ber(&der, &limits).unwrap().value,
        value
    );
    assert_eq!(
        PacketLeaves::decode_cer(&cer, &limits).unwrap().value,
        value
    );
}

/// Verify natural, IMPLICIT, and EXPLICIT child framing over shared context.
///
/// Inputs: none. Returns no value. Errors are assertion failures or codec errors.
/// Source: live C probes and X.690. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: tagged named-child paths.
/// Example: IMPLICIT replaces the child tag; EXPLICIT wraps its complete SEQUENCE.
#[test]
fn implicit_and_explicit_sequence_children_use_their_effective_tags() {
    let limits = Limits::default();
    let implicit = SequenceImplicit {
        child: Inner {
            number: 2,
            flag: true,
        },
        after: true,
    };
    let implicit_der = [
        0x30, 0x0b, 0xa3, 0x06, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0x84, 0x01, 0xff,
    ];
    assert_eq!(implicit.encode_der(&limits).unwrap().bytes, implicit_der);
    assert_eq!(
        SequenceImplicit::decode_ber(&implicit_der, &limits)
            .unwrap()
            .value,
        implicit
    );

    let explicit = SequenceExplicit {
        child: Inner {
            number: 2,
            flag: true,
        },
        after: true,
    };
    let explicit_definite = [
        0x30, 0x0d, 0xa3, 0x08, 0x30, 0x06, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0x84, 0x01, 0xff,
    ];
    let explicit_canonical = [
        0x30, 0x80, 0xa3, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0, 0, 0, 0, 0x84,
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
    assert!(SequenceExplicit::decode_cer(&explicit_definite, &limits).is_err());
    assert_eq!(
        SequenceExplicit::decode_cer(&explicit_canonical, &limits)
            .unwrap()
            .value,
        explicit
    );

    let mixed_lengths = [
        0x30, 0x80, 0xa3, 0x0a, 0x30, 0x80, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0, 0, 0x84, 0x01,
        0xff, 0, 0,
    ];
    let mixed = SequenceExplicit::decode_ber(&mixed_lengths, &limits).unwrap();
    assert_eq!(mixed.value, explicit);
    assert_eq!(mixed.consumed_bytes, mixed_lengths.len());
    assert!(SequenceExplicit::decode_cer(&mixed_lengths, &limits).is_err());
}

/// Verify an absent OPTIONAL child leaves subsequent parent fields decodable.
///
/// Inputs: none. Returns no value. Errors are assertion failures or codec errors.
/// Source: live C vectors. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: optional named child.
/// Example: absence is encoded as `30 03 84 01 ff`.
#[test]
fn optional_child_absence_and_presence_are_distinct() {
    let limits = Limits::default();
    let absent = SequenceOptional {
        child: None,
        after: true,
    };
    let definite_absence = [0x30, 0x03, 0x84, 0x01, 0xff];
    let canonical_absence = [0x30, 0x80, 0x84, 0x01, 0xff, 0, 0];
    assert_eq!(absent.encode_der(&limits).unwrap().bytes, definite_absence);
    assert_eq!(absent.encode_cer(&limits).unwrap().bytes, canonical_absence);
    assert_eq!(
        SequenceOptional::decode_ber(&canonical_absence, &limits)
            .unwrap()
            .value,
        absent
    );

    let present = SequenceOptional {
        child: Some(Inner {
            number: 2,
            flag: true,
        }),
        after: true,
    };
    assert_eq!(
        SequenceOptional::decode_ber(&present.encode_der(&limits).unwrap().bytes, &limits)
            .unwrap()
            .value,
        present
    );
}

/// Verify SET children sort independently and BER accepts parent permutations.
///
/// Inputs: none. Returns no value. Errors are assertion failures or codec errors.
/// Source: live C vectors and X.690 SET ordering. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: named child under SET.
/// Example: universal child tag sorts before context tags 0 and 4.
#[test]
fn set_child_uses_outer_tag_order_and_ber_dispatch_is_unordered() {
    let limits = Limits::default();
    let value = SetPacket {
        after: true,
        child: Inner {
            number: 2,
            flag: true,
        },
        before: true,
    };
    let der = [
        0x31, 0x0e, 0x30, 0x06, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0x80, 0x01, 0xff, 0x84, 0x01,
        0xff,
    ];
    let cer = [
        0x31, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0, 0, 0x80, 0x01, 0xff, 0x84,
        0x01, 0xff, 0, 0,
    ];
    assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(SetPacket::decode_ber(&der, &limits).unwrap().value, value);
    assert_eq!(SetPacket::decode_cer(&cer, &limits).unwrap().value, value);

    let reversed = [
        0x31, 0x80, 0x84, 0x01, 0xff, 0x80, 0x01, 0xff, 0x30, 0x80, 0x02, 0x01, 0x02, 0x01, 0x01,
        0xff, 0, 0, 0, 0,
    ];
    assert_eq!(
        SetPacket::decode_ber(&reversed, &limits).unwrap().value,
        value
    );
    assert!(SetPacket::decode_cer(&reversed, &limits).is_err());
}

/// Verify IMPLICIT and EXPLICIT named children in SET roots.
///
/// Inputs: none. Returns no value. Errors are assertion failures or codec errors.
/// Source: live C vectors and X.690. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: named child SET variants.
/// Example: one context-specific child sorts by its effective outer tag.
#[test]
fn tagged_named_children_work_in_set_roots() {
    let limits = Limits::default();
    let implicit = SetImplicit {
        child: Inner {
            number: 2,
            flag: true,
        },
        after: true,
    };
    let implicit_der = [
        0x31, 0x0b, 0xa3, 0x06, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0x84, 0x01, 0xff,
    ];
    assert_eq!(implicit.encode_der(&limits).unwrap().bytes, implicit_der);
    assert_eq!(
        SetImplicit::decode_ber(&implicit_der, &limits)
            .unwrap()
            .value,
        implicit
    );

    let explicit = SetExplicit {
        child: Inner {
            number: 2,
            flag: true,
        },
        after: true,
    };
    let explicit_definite = [
        0x31, 0x0d, 0xa3, 0x08, 0x30, 0x06, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0x84, 0x01, 0xff,
    ];
    assert_eq!(
        explicit.encode_der(&limits).unwrap().bytes,
        explicit_definite
    );
    assert_eq!(
        SetExplicit::decode_ber(&explicit_definite, &limits)
            .unwrap()
            .value,
        explicit
    );
}

/// Verify OPTIONAL child absence and literal DEFAULT siblings in SET roots.
///
/// Inputs: none. Returns no value. Errors are assertion failures or codec errors.
/// Source: live C vectors and X.690. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: SET optional/default fields.
/// Example: an absent child is omitted and defaults follow tag order.
#[test]
fn optional_and_default_children_work_in_set_roots() {
    let limits = Limits::default();
    let absent = SetOptional {
        child: None,
        after: true,
    };
    let optional_definite = [0x31, 0x03, 0x84, 0x01, 0xff];
    let optional_canonical = [0x31, 0x80, 0x84, 0x01, 0xff, 0, 0];
    assert_eq!(absent.encode_der(&limits).unwrap().bytes, optional_definite);
    assert_eq!(
        absent.encode_cer(&limits).unwrap().bytes,
        optional_canonical
    );
    assert_eq!(
        SetOptional::decode_cer(&optional_canonical, &limits)
            .unwrap()
            .value,
        absent
    );

    let defaults_absent = SetDefaults {
        child: Inner {
            number: 2,
            flag: true,
        },
        enabled: false,
        count: 2,
    };
    let default_der = [0x31, 0x08, 0x30, 0x06, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff];
    assert_eq!(
        defaults_absent.encode_der(&limits).unwrap().bytes,
        default_der
    );
    assert_eq!(
        SetDefaults::decode_ber(&default_der, &limits)
            .unwrap()
            .value,
        defaults_absent
    );

    let defaults_present = SetDefaults {
        child: Inner {
            number: 2,
            flag: true,
        },
        enabled: true,
        count: 3,
    };
    let nondefault_definite = [
        0x31, 0x0e, 0x01, 0x01, 0xff, 0x02, 0x01, 0x03, 0x30, 0x06, 0x02, 0x01, 0x02, 0x01, 0x01,
        0xff,
    ];
    let nondefault_canonical = [
        0x31, 0x80, 0x01, 0x01, 0xff, 0x02, 0x01, 0x03, 0x30, 0x80, 0x02, 0x01, 0x02, 0x01, 0x01,
        0xff, 0, 0, 0, 0,
    ];
    assert_eq!(
        defaults_present.encode_der(&limits).unwrap().bytes,
        nondefault_definite
    );
    assert_eq!(
        defaults_present.encode_cer(&limits).unwrap().bytes,
        nondefault_canonical
    );
    assert_eq!(
        SetDefaults::decode_cer(&nondefault_canonical, &limits)
            .unwrap()
            .value,
        defaults_present
    );
}

/// Reject child truncation, extra EOCs, and out-of-range target leaf values.
///
/// Inputs: none. Returns no value. Errors are assertion failures or codec errors.
/// Source: malformed BER mutations and target range `(0..5)`. Date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: child boundary validation.
/// Example: `number = 6` is rejected during generated Rust decoding.
#[test]
fn malformed_child_frames_and_target_constraints_fail_closed() {
    let limits = Limits::default();
    let malformed: &[&[u8]] = &[
        &[0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0, 0],
        &[0x30, 0x04, 0x30, 0x02, 0x02, 0x01],
        &[
            0x30, 0x80, 0x1f, 0x10, 0x80, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0, 0, 0x84, 0x01,
            0xff, 0, 0,
        ],
    ];
    for wire in malformed {
        assert!(Packet::decode_ber(wire, &limits).is_err());
    }
    let out_of_range = [
        0x30, 0x0b, 0x30, 0x06, 0x02, 0x01, 0x06, 0x01, 0x01, 0xff, 0x84, 0x01, 0xff,
    ];
    assert!(Packet::decode_ber(&out_of_range, &limits).is_err());
    let valid = Packet {
        before: false,
        child: Inner {
            number: 2,
            flag: true,
        },
        after: true,
    };
    let encoded = valid.encode_der(&limits).unwrap();
    for end in 0..encoded.bytes.len() {
        assert!(Packet::decode_ber(&encoded.bytes[..end], &limits).is_err());
    }
    let limited = Limits {
        max_input_bytes: 4,
        ..limits
    };
    assert!(Packet::decode_ber(&encoded.bytes, &limited).is_err());
}

/// Pin a full nested strict-CER operation at its exact work/output ceilings.
///
/// Inputs: none. Returns no value. Errors are assertion failures or codec errors.
/// Source: fixed nested CER vector and runtime work accounting. Date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: generated shared-context limits.
/// Example: this canonical prefix succeeds at 792 work bits and fails at 791.
#[test]
fn strict_cer_shares_pinned_nested_work_and_output_limits() {
    let value = Packet {
        before: false,
        child: Inner {
            number: 2,
            flag: true,
        },
        after: true,
    };
    let cer = value.encode_cer(&Limits::default()).unwrap().bytes;
    let exact_limits = Limits {
        max_input_bytes: cer.len(),
        max_output_bytes: cer.len(),
        max_work_bits: 792,
    };
    assert_eq!(
        Packet::decode_cer(&cer, &exact_limits).unwrap().value,
        value
    );
    let one_below = Limits {
        max_work_bits: 791,
        ..exact_limits
    };
    assert!(Packet::decode_cer(&cer, &one_below).is_err());

    let output_exact = Limits {
        max_output_bytes: cer.len(),
        ..Limits::default()
    };
    assert_eq!(value.encode_cer(&output_exact).unwrap().bytes, cer);
    let output_short = Limits {
        max_output_bytes: cer.len() - 1,
        ..Limits::default()
    };
    assert!(value.encode_cer(&output_short).is_err());
}

/// Mutate every byte of a nested BER/CER value and bound all accepted prefixes.
///
/// Inputs: none. Returns no value. Errors are assertion failures or codec errors.
/// Source: generated C/Rust canonical vector. Date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: nested-record mutation coverage.
/// Example: each changed octet is tried with both a low-bit and high-bit flip.
#[test]
fn nested_record_mutations_remain_bounded() {
    let limits = Limits::default();
    let value = Packet {
        before: false,
        child: Inner {
            number: 2,
            flag: true,
        },
        after: true,
    };
    let canonical = value.encode_cer(&limits).unwrap().bytes;
    for index in 0..canonical.len() {
        for mask in [0x01, 0x80] {
            let mut mutated = canonical.clone();
            mutated[index] ^= mask;
            if let Ok(decoded) = Packet::decode_ber(&mutated, &limits) {
                assert!(decoded.consumed_bytes <= mutated.len());
                assert_eq!(decoded.consumed_bits, decoded.consumed_bytes * 8);
            }
            if let Ok(decoded) = Packet::decode_cer(&mutated, &limits) {
                assert!(decoded.consumed_bytes <= mutated.len());
                assert_eq!(decoded.consumed_bits, decoded.consumed_bytes * 8);
            }
        }
    }
}
