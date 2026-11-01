//! Generated BER/DER/CER tests for flat direct-field SET values.

use asn1c_generated::set_ber_cer::{
    HyphenatedSet, HyphenatedSetState, SetAllRecord, SetAllRecordState, SetBoundaryRecord,
    SetEmptyRecord, SetPresenceRecord, SetPresenceRecordState,
};
use asn1c_runtime::{BitStringValue, Error, Limits, Resource};

/// Advance a fixed index array to its next lexicographic permutation.
///
/// Parameters: `items` is the mutable permutation state.
/// Returns: true when advanced; false when it was already the final order.
/// Errors: this in-place bounded helper cannot fail or panic.
/// Original source: lexicographic permutation algorithm.
/// Version/date: 2026-10-31. Author: asn1c maintainers. History: SET coverage.
/// Example: `[0, 1]` advances to `[1, 0]`.
fn next_permutation(items: &mut [usize]) -> bool {
    let Some(pivot) = (0..items.len().saturating_sub(1))
        .rev()
        .find(|index| items[*index] < items[*index + 1])
    else {
        return false;
    };
    let successor = (pivot + 1..items.len())
        .rev()
        .find(|index| items[pivot] < items[*index])
        .expect("pivot has a successor");
    items.swap(pivot, successor);
    items[pivot + 1..].reverse();
    true
}

/// Check universal-tag sorting and declared ENUMERATED numbers in both rules.
///
/// Parameters: none. Returns: no value; assertions compare exact wire vectors.
/// Errors: runtime encoding or decoding failures fail the test.
/// Original source: X.690 SET tag order and independent C conformance vectors.
/// Version/date: 2026-10-31. Author: asn1c maintainers. History: fourth wave.
/// Example: the BOOLEAN tag sorts before the INTEGER and ENUMERATED tags.
#[test]
fn required_fields_sort_by_universal_tag() {
    let limits = Limits::default();
    let value = SetAllRecord {
        number: 3,
        bits: BitStringValue::new(vec![0xa8], 5).unwrap(),
        state: SetAllRecordState::Active,
        flag: true,
        octets: b"AB".to_vec(),
        empty: (),
    };
    let der = [
        0x31, 0x13, 0x01, 0x01, 0xff, 0x02, 0x01, 0x03, 0x03, 0x02, 0x03, 0xa8, 0x04, 0x02, 0x41,
        0x42, 0x05, 0x00, 0x0a, 0x01, 0x03,
    ];
    let cer = [
        0x31, 0x80, 0x01, 0x01, 0xff, 0x02, 0x01, 0x03, 0x03, 0x02, 0x03, 0xa8, 0x04, 0x02, 0x41,
        0x42, 0x05, 0x00, 0x0a, 0x01, 0x03, 0x00, 0x00,
    ];

    assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(
        SetAllRecord::decode_ber(&der, &limits).unwrap().value,
        value
    );
    assert_eq!(
        SetAllRecord::decode_cer(&cer, &limits).unwrap().value,
        value
    );
}

/// Verify inline enum names use the sanitized parent assignment name.
///
/// Parameters: none. Returns: no value; generated names and wire bytes are checked.
/// Errors: enum generation or BER/CER codec failures fail this test.
/// Original source: Rust identifier normalization for nested generated enums.
/// Version/date: 2026-10-31. Author: asn1c maintainers. History: SET naming; CamelCase correction 2026-11-01.
/// Example: `Hyphenated-set` becomes the sanitized `HyphenatedSet` identifier.
#[test]
fn sanitized_parent_name_is_used_for_inline_enums() {
    let value = HyphenatedSet {
        state: HyphenatedSetState::Ready,
    };
    let der = [0x31, 0x03, 0x0a, 0x01, 0x08];
    let limits = Limits::default();

    assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(
        HyphenatedSet::decode_ber(&der, &limits).unwrap().value,
        value
    );
}

/// Verify BER accepts any field order while strict CER requires canonical order.
///
/// Parameters: none. Returns: no value; assertions inspect decoded values/errors.
/// Errors: malformed or noncanonical encodings return typed runtime errors.
/// Original source: X.690 unordered SET BER and canonical CER ordering.
/// Version/date: 2026-10-31. Author: asn1c maintainers. History: fourth wave.
/// Example: reversed child TLVs decode under BER and fail CER canonicality.
#[test]
fn reordered_ber_is_accepted_but_reordered_cer_is_rejected() {
    let limits = Limits::default();
    let ber_permuted = [
        0x31, 0x13, 0x0a, 0x01, 0x03, 0x05, 0x00, 0x04, 0x02, 0x41, 0x42, 0x03, 0x02, 0x03, 0xa8,
        0x02, 0x01, 0x03, 0x01, 0x01, 0xff,
    ];
    let cer_permuted = [
        0x31, 0x80, 0x0a, 0x01, 0x03, 0x05, 0x00, 0x04, 0x02, 0x41, 0x42, 0x03, 0x02, 0x03, 0xa8,
        0x02, 0x01, 0x03, 0x01, 0x01, 0xff, 0x00, 0x00,
    ];

    assert!(SetAllRecord::decode_ber(&ber_permuted, &limits).is_ok());
    assert!(matches!(
        SetAllRecord::decode_cer(&cer_permuted, &limits),
        Err(Error::InvalidEncoding { .. })
    ));
}

/// Decode all 720 possible BER child orders for the six unique SET tags.
///
/// Parameters: none. Returns: no value; every child permutation must decode.
/// Errors: any order rejected by BER fails this exhaustive interop test.
/// Original source: X.690 permits arbitrary BER order for SET components.
/// Version/date: 2026-10-31. Author: asn1c maintainers. History: fourth wave.
/// Example: all permutations use the same required semantic record value.
#[test]
fn every_ber_field_permutation_is_accepted() {
    let children: [&[u8]; 6] = [
        &[0x01, 0x01, 0xff],
        &[0x02, 0x01, 0x03],
        &[0x03, 0x02, 0x03, 0xa8],
        &[0x04, 0x02, 0x41, 0x42],
        &[0x05, 0x00],
        &[0x0a, 0x01, 0x03],
    ];
    let expected = SetAllRecord {
        number: 3,
        bits: BitStringValue::new(vec![0xa8], 5).unwrap(),
        state: SetAllRecordState::Active,
        flag: true,
        octets: b"AB".to_vec(),
        empty: (),
    };
    let limits = Limits::default();
    let mut order = [0, 1, 2, 3, 4, 5];
    let mut permutations = 0;

    loop {
        let mut wire = Vec::with_capacity(21);
        wire.extend_from_slice(&[0x31, 0x13]);
        for index in order {
            wire.extend_from_slice(children[index]);
        }
        assert_eq!(
            SetAllRecord::decode_ber(&wire, &limits).unwrap().value,
            expected
        );
        permutations += 1;
        if !next_permutation(&mut order) {
            break;
        }
    }
    assert_eq!(permutations, 720);
}

/// Check DEFAULT omission/substitution, OPTIONAL presence, and empty framing.
///
/// Parameters: none. Returns: no value; assertions compare values and bytes.
/// Errors: malformed explicit DEFAULT values fail strict CER validation.
/// Original source: X.690 SET optional/default omission rules.
/// Version/date: 2026-10-31. Author: asn1c maintainers. History: fourth wave.
/// Example: all absent/default fields encode as an empty SET.
#[test]
fn optional_default_and_empty_sets_roundtrip() {
    let limits = Limits::default();
    let absent = SetPresenceRecord {
        number: 1,
        bits: None,
        state: None,
        flag: false,
        octets: None,
        empty: None,
    };
    let present = SetPresenceRecord {
        number: 2,
        bits: Some(BitStringValue::new(vec![0xa8], 5).unwrap()),
        state: Some(SetPresenceRecordState::Queued),
        flag: true,
        octets: Some(b"AB".to_vec()),
        empty: Some(()),
    };
    let der_empty = [0x31, 0x00];
    let cer_empty = [0x31, 0x80, 0x00, 0x00];
    let der_present = [
        0x31, 0x13, 0x01, 0x01, 0xff, 0x02, 0x01, 0x02, 0x03, 0x02, 0x03, 0xa8, 0x04, 0x02, 0x41,
        0x42, 0x05, 0x00, 0x0a, 0x01, 0x11,
    ];
    let cer_present = [
        0x31, 0x80, 0x01, 0x01, 0xff, 0x02, 0x01, 0x02, 0x03, 0x02, 0x03, 0xa8, 0x04, 0x02, 0x41,
        0x42, 0x05, 0x00, 0x0a, 0x01, 0x11, 0x00, 0x00,
    ];
    let empty = SetEmptyRecord {};

    assert_eq!(absent.encode_der(&limits).unwrap().bytes, der_empty);
    assert_eq!(absent.encode_cer(&limits).unwrap().bytes, cer_empty);
    assert_eq!(
        SetPresenceRecord::decode_ber(&der_empty, &limits)
            .unwrap()
            .value,
        absent
    );
    assert_eq!(
        SetPresenceRecord::decode_cer(&cer_empty, &limits)
            .unwrap()
            .value,
        absent
    );
    assert_eq!(present.encode_der(&limits).unwrap().bytes, der_present);
    assert_eq!(present.encode_cer(&limits).unwrap().bytes, cer_present);
    assert_eq!(
        SetPresenceRecord::decode_ber(&der_present, &limits)
            .unwrap()
            .value,
        present
    );
    assert_eq!(
        SetPresenceRecord::decode_cer(&cer_present, &limits)
            .unwrap()
            .value,
        present
    );
    assert_eq!(empty.encode_der(&limits).unwrap().bytes, der_empty);
    assert_eq!(empty.encode_cer(&limits).unwrap().bytes, cer_empty);
    assert_eq!(
        SetEmptyRecord::decode_ber(&der_empty, &limits)
            .unwrap()
            .value,
        empty
    );
    assert_eq!(
        SetEmptyRecord::decode_cer(&cer_empty, &limits)
            .unwrap()
            .value,
        empty
    );

    let explicit_default = [0x31, 0x03, 0x02, 0x01, 0x01];
    assert!(SetPresenceRecord::decode_ber(&explicit_default, &limits).is_ok());
    assert!(matches!(
        SetPresenceRecord::decode_cer(&[0x31, 0x80, 0x02, 0x01, 0x01, 0, 0], &limits),
        Err(Error::InvalidEncoding { .. })
    ));
}

/// Check exact prefix consumption, truncation, and malformed SET dispatch.
///
/// Parameters: none. Returns: no value; each prefix is classified by decoder.
/// Errors: incomplete prefixes and invalid tags must return a typed error.
/// Original source: robust X.690 record decoding.
/// Version/date: 2026-10-31. Author: asn1c maintainers. History: fourth wave.
/// Example: an unknown universal tag cannot be ignored by a nonextensible SET.
#[test]
fn malformed_fields_and_prefix_consumption_are_checked() {
    let limits = Limits::default();
    let der = [
        0x31, 0x13, 0x01, 0x01, 0xff, 0x02, 0x01, 0x03, 0x03, 0x02, 0x03, 0xa8, 0x04, 0x02, 0x41,
        0x42, 0x05, 0x00, 0x0a, 0x01, 0x03,
    ];
    let cer = [
        0x31, 0x80, 0x01, 0x01, 0xff, 0x02, 0x01, 0x03, 0x03, 0x02, 0x03, 0xa8, 0x04, 0x02, 0x41,
        0x42, 0x05, 0x00, 0x0a, 0x01, 0x03, 0x00, 0x00,
    ];
    let mut with_suffix = cer.to_vec();
    with_suffix.push(0xaa);
    let prefix = SetAllRecord::decode_cer(&with_suffix, &limits).unwrap();
    assert_eq!(prefix.consumed_bytes, cer.len());
    assert_eq!(prefix.consumed_bits, cer.len() * 8);
    let mut der_with_suffix = der.to_vec();
    der_with_suffix.push(0xaa);
    let der_prefix = SetAllRecord::decode_ber(&der_with_suffix, &limits).unwrap();
    assert_eq!(der_prefix.consumed_bytes, der.len());
    assert_eq!(der_prefix.consumed_bits, der.len() * 8);
    for end in 0..cer.len() {
        assert!(
            SetAllRecord::decode_cer(&cer[..end], &limits).is_err(),
            "prefix {end}"
        );
    }
    for end in 0..der.len() {
        assert!(
            SetAllRecord::decode_ber(&der[..end], &limits).is_err(),
            "DER prefix {end}"
        );
    }

    let unknown = [
        0x31, 0x15, 0x01, 0x01, 0xff, 0x02, 0x01, 0x03, 0x03, 0x02, 0x03, 0xa8, 0x04, 0x02, 0x41,
        0x42, 0x05, 0x00, 0x06, 0x00, 0x0a, 0x01, 0x03,
    ];
    let duplicate = [0x31, 0x06, 0x01, 0x01, 0xff, 0x01, 0x01, 0x00];
    let missing_required = [0x31, 0x00];
    let unknown_enum = [
        0x31, 0x13, 0x01, 0x01, 0xff, 0x02, 0x01, 0x03, 0x03, 0x02, 0x03, 0xa8, 0x04, 0x02, 0x41,
        0x42, 0x05, 0x00, 0x0a, 0x01, 0x7f,
    ];
    assert!(SetAllRecord::decode_ber(&unknown, &limits).is_err());
    assert!(SetAllRecord::decode_ber(&duplicate, &limits).is_err());
    assert!(SetAllRecord::decode_ber(&missing_required, &limits).is_err());
    assert!(SetAllRecord::decode_ber(&unknown_enum, &limits).is_err());
    let out_of_range = [
        0x31, 0x13, 0x01, 0x01, 0xff, 0x02, 0x01, 0x04, 0x03, 0x02, 0x03, 0xa8, 0x04, 0x02, 0x41,
        0x42, 0x05, 0x00, 0x0a, 0x01, 0x03,
    ];
    assert!(matches!(
        SetAllRecord::decode_ber(&out_of_range, &limits),
        Err(Error::ValueOutOfRange { .. })
    ));
    assert!(SetPresenceRecord::decode_ber(&[0x31, 0x03, 0x03, 0x01, 0x00], &limits).is_err());
    let mut oversized_octets = vec![0x31, 0x81, 0x84, 0x04, 0x81, 0x81];
    oversized_octets.resize(6 + 129, 0x41);
    assert!(SetPresenceRecord::decode_ber(&oversized_octets, &limits).is_err());
}

/// Verify whole-operation input, output, and work ceilings on an empty record.
///
/// Parameters: none. Returns: no value; errors identify the exceeded resource.
/// Errors: configured ceilings reject input and encoding before completion.
/// Original source: shared BER/CER `RecordContext` accounting.
/// Version/date: 2026-10-31. Author: asn1c maintainers. History: fourth wave.
/// Example: DER framing needs two bytes even with no SET members.
#[test]
fn empty_set_obeys_shared_resource_limits() {
    let empty = SetEmptyRecord {};
    let input_limits = Limits {
        max_input_bytes: 1,
        ..Limits::default()
    };
    let output_limits = Limits {
        max_output_bytes: 1,
        ..Limits::default()
    };
    let work_limits = Limits {
        max_work_bits: 0,
        ..Limits::default()
    };

    assert!(matches!(
        SetEmptyRecord::decode_ber(&[0x31, 0x00], &input_limits),
        Err(Error::LimitExceeded {
            resource: Resource::InputBytes,
            ..
        })
    ));
    assert!(matches!(
        empty.encode_der(&output_limits),
        Err(Error::LimitExceeded {
            resource: Resource::OutputBytes,
            ..
        })
    ));
    assert!(matches!(
        empty.encode_der(&work_limits),
        Err(Error::LimitExceeded {
            resource: Resource::WorkBits,
            ..
        })
    ));
}

/// Exercise CER string fragmentation immediately below and above 1000 content octets.
///
/// Parameters: none. Returns: no value; framing and round-trip sizes are asserted.
/// Errors: invalid values, allocation, or resource failures fail the test.
/// Original source: X.690 CER string fragment threshold.
/// Version/date: 2026-10-31. Author: asn1c maintainers. History: fourth wave.
/// Example: a 1001-octet OCTET STRING uses constructed CER form.
#[test]
fn cer_fragments_octet_and_bit_set_fields_at_the_threshold() {
    let limits = Limits::default();
    for length in [1000, 1001] {
        let value = SetBoundaryRecord {
            bits: None,
            octets: vec![0x5a; length],
        };
        let encoded = value.encode_cer(&limits).unwrap();
        assert_eq!(encoded.bytes[0..2], [0x31, 0x80]);
        assert!(SetBoundaryRecord::decode_cer(&encoded.bytes, &limits).is_ok());
        if length == 1000 {
            assert_eq!(&encoded.bytes[2..4], &[0x04, 0x82]);
            assert_eq!(encoded.bytes[4..6], [0x03, 0xe8]);
        } else {
            assert_eq!(&encoded.bytes[2..6], &[0x24, 0x80, 0x04, 0x82]);
        }
    }

    for octets in [999, 1000] {
        let bits = BitStringValue::new(vec![0xa5; octets], octets * 8).unwrap();
        let value = SetBoundaryRecord {
            bits: Some(bits),
            octets: Vec::new(),
        };
        let encoded = value.encode_cer(&limits).unwrap();
        assert!(SetBoundaryRecord::decode_cer(&encoded.bytes, &limits).is_ok());
        if octets == 999 {
            assert_eq!(&encoded.bytes[2..4], &[0x03, 0x82]);
            assert_eq!(encoded.bytes[4..6], [0x03, 0xe8]);
        } else {
            assert_eq!(&encoded.bytes[2..6], &[0x23, 0x80, 0x03, 0x82]);
        }
    }
}

/// Check outer and child DER lengths around the short/long-form boundaries.
///
/// Parameters: none. Returns: no value; exact headers and decoded lengths are checked.
/// Errors: encoding, decoding, or incorrect X.690 length forms fail the test.
/// Original source: X.690 minimal definite-length encoding.
/// Version/date: 2026-11-01. Author: asn1c maintainers. History: SET boundaries.
/// Example: payloads 125 and 126 cross the outer SET short-length boundary.
#[test]
fn der_set_and_octet_child_length_boundaries_are_minimal() {
    let limits = Limits::default();
    for length in [125, 126, 127, 128] {
        let value = SetBoundaryRecord {
            bits: None,
            octets: vec![0x5a; length],
        };
        let encoded = value.encode_der(&limits).unwrap();
        if length == 125 {
            assert_eq!(&encoded.bytes[..2], &[0x31, 0x7f]);
            assert_eq!(&encoded.bytes[2..4], &[0x04, 0x7d]);
        } else if length == 126 {
            assert_eq!(&encoded.bytes[..3], &[0x31, 0x81, 0x80]);
            assert_eq!(&encoded.bytes[3..5], &[0x04, 0x7e]);
        } else if length == 127 {
            assert_eq!(&encoded.bytes[..3], &[0x31, 0x81, 0x81]);
            assert_eq!(&encoded.bytes[3..5], &[0x04, 0x7f]);
        } else {
            assert_eq!(&encoded.bytes[..3], &[0x31, 0x81, 0x83]);
            assert_eq!(&encoded.bytes[3..6], &[0x04, 0x81, 0x80]);
        }
        assert_eq!(
            SetBoundaryRecord::decode_ber(&encoded.bytes, &limits)
                .unwrap()
                .value,
            value
        );
    }
}
