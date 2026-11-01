use asn1c_generated::of_collections::{
    SequenceBoolean, SequenceInteger, SequenceNull, SetBoolean, SetInteger, SetNull,
};
use asn1c_runtime::{Decoded, Error, Limits};

/// Build the default resource policy used by the conformance vectors.
///
/// Source: the generated BER/CER collection codec API. Version/date: 2026-11-01.
/// Parameters: none. Returns: the runtime's finite default `Limits` value.
/// Errors: none; this helper copies a `Copy` configuration value.
/// Responsible party: asn1c maintainers. History: added for direct OF coverage.
/// Example: `let limits = default_limits();`
fn default_limits() -> Limits {
    Limits::default()
}

/// Check exact byte and bit prefix accounting for one decoded TLV.
///
/// Source: X.690 octet-aligned collection TLVs. Version/date: 2026-11-01.
/// Parameters: `decoded` is a runtime prefix result; `bytes` is expected use.
/// Returns: unit. Errors: assertions fail if either count differs.
/// Responsible party: asn1c maintainers. History: shared prefix assertion helper.
/// Example: `assert_consumed(&decoded, encoded.len());`
fn assert_consumed<T>(decoded: &Decoded<T>, bytes: usize) {
    assert_eq!(decoded.consumed_bytes, bytes);
    assert_eq!(decoded.consumed_bits, bytes * 8);
}

/// Compare ordered BOOLEAN DER/CER vectors and suffixed prefix decodes.
///
/// Source: X.690 DER/CER collection rules and live C vectors.
/// Version/date: 2026-11-01. Parameters: none; all values are local vectors.
/// Returns: unit. Errors: assertions detect encoding, value, or prefix mismatch.
/// Responsible party: asn1c maintainers. History: direct SEQUENCE OF support.
/// Example: the input `[TRUE, FALSE]` retains that order in both encodings.
#[test]
fn sequence_boolean_der_cer_and_prefix_decode() {
    let empty = SequenceBoolean::new(Vec::new());
    assert_eq!(
        empty.encode_der(&default_limits()).unwrap().bytes,
        [0x30, 0]
    );
    assert_eq!(
        empty.encode_cer(&default_limits()).unwrap().bytes,
        [0x30, 0x80, 0, 0]
    );
    let singleton = SequenceBoolean::new(vec![true]);
    assert_eq!(
        singleton.encode_der(&default_limits()).unwrap().bytes,
        [0x30, 3, 1, 1, 0xff]
    );
    assert_eq!(
        singleton.encode_cer(&default_limits()).unwrap().bytes,
        [0x30, 0x80, 1, 1, 0xff, 0, 0]
    );

    let values = SequenceBoolean::new(vec![true, false, true]);
    let der = [0x30, 9, 1, 1, 0xff, 1, 1, 0, 1, 1, 0xff];
    let cer = [0x30, 0x80, 1, 1, 0xff, 1, 1, 0, 1, 1, 0xff, 0, 0];
    assert_eq!(values.encode_der(&default_limits()).unwrap().bytes, der);
    assert_eq!(values.encode_cer(&default_limits()).unwrap().bytes, cer);

    let suffixed = [cer.as_slice(), &[0xaa, 0xbb]].concat();
    let decoded = SequenceBoolean::decode_ber(&suffixed, &default_limits()).unwrap();
    assert_eq!(decoded.value.as_slice(), [true, false, true]);
    assert_consumed(&decoded, cer.len());
    let decoded = SequenceBoolean::decode_cer(&suffixed, &default_limits()).unwrap();
    assert_eq!(decoded.value.as_slice(), [true, false, true]);
    assert_consumed(&decoded, cer.len());
}

/// Check complete-TLV sorting and strict rejection of reversed SET OF BER.
///
/// Source: X.690 SET OF canonical ordering and live C vectors.
/// Version/date: 2026-11-01. Parameters: none; the test owns its values and TLVs.
/// Returns: unit. Errors: assertions detect wrong sorting or CER acceptance.
/// Responsible party: asn1c maintainers. History: direct SET OF support.
/// Example: `TRUE, FALSE` encodes in complete child-TLV order.
#[test]
fn set_boolean_sorts_complete_child_tlvs() {
    let values = SetBoolean::new(vec![true, false, true]);
    let der = [0x31, 9, 1, 1, 0, 1, 1, 0xff, 1, 1, 0xff];
    let cer = [0x31, 0x80, 1, 1, 0, 1, 1, 0xff, 1, 1, 0xff, 0, 0];
    assert_eq!(values.encode_der(&default_limits()).unwrap().bytes, der);
    assert_eq!(values.encode_cer(&default_limits()).unwrap().bytes, cer);

    let reversed_ber = [0x31, 0x80, 1, 1, 0xff, 1, 1, 0, 0, 0];
    let decoded = SetBoolean::decode_ber(&reversed_ber, &default_limits()).unwrap();
    assert_eq!(decoded.value.as_slice(), [true, false]);
    assert_consumed(&decoded, reversed_ber.len());
    assert!(SetBoolean::decode_cer(&reversed_ber, &default_limits()).is_err());
    let decoded = SetBoolean::decode_cer(&cer, &default_limits()).unwrap();
    assert_eq!(decoded.value.as_slice(), [false, true, true]);
}

/// Preserve empty and repeated NULL elements through count-backed vectors.
///
/// Source: X.690 NULL and collection encodings. Version/date: 2026-11-01.
/// Parameters: none. Returns: unit. Errors: assertions detect lost NULL counts
/// or incorrect empty, duplicate, DER, CER, or decode behavior.
/// Responsible party: asn1c maintainers. History: count-backed NULL coverage.
/// Example: three NULL items encode as three `05 00` child TLVs.
#[test]
fn null_collections_preserve_duplicate_count() {
    let empty_sequence = SequenceNull::new(Vec::new());
    assert_eq!(
        empty_sequence.encode_der(&default_limits()).unwrap().bytes,
        [0x30, 0]
    );
    assert_eq!(
        empty_sequence.encode_cer(&default_limits()).unwrap().bytes,
        [0x30, 0x80, 0, 0]
    );
    let sequence = SequenceNull::new(vec![(), (), ()]);
    let der = [0x30, 6, 5, 0, 5, 0, 5, 0];
    let cer = [0x30, 0x80, 5, 0, 5, 0, 5, 0, 0, 0];
    assert_eq!(sequence.encode_der(&default_limits()).unwrap().bytes, der);
    assert_eq!(sequence.encode_cer(&default_limits()).unwrap().bytes, cer);
    let decoded = SequenceNull::decode_ber(&der, &default_limits()).unwrap();
    assert_eq!(decoded.value.as_slice().len(), 3);
    let decoded_sequence_cer = SequenceNull::decode_cer(&cer, &default_limits()).unwrap();
    assert_eq!(decoded_sequence_cer.value.as_slice().len(), 3);

    let set = SetNull::new(vec![(), (), ()]);
    assert_eq!(
        set.encode_der(&default_limits()).unwrap().bytes,
        [0x31, 6, 5, 0, 5, 0, 5, 0]
    );
    assert_eq!(
        set.encode_cer(&default_limits()).unwrap().bytes,
        [0x31, 0x80, 5, 0, 5, 0, 5, 0, 0, 0]
    );
    let decoded_set = SetNull::decode_ber(&[0x31, 6, 5, 0, 5, 0, 5, 0], &default_limits()).unwrap();
    assert_eq!(decoded_set.value.as_slice().len(), 3);
    let decoded_cer =
        SetNull::decode_cer(&[0x31, 0x80, 5, 0, 5, 0, 5, 0, 0, 0], &default_limits()).unwrap();
    assert_eq!(decoded_cer.value.as_slice().len(), 3);
    let empty_set = SetNull::new(Vec::new());
    assert_eq!(
        empty_set.encode_der(&default_limits()).unwrap().bytes,
        [0x31, 0]
    );
    assert_eq!(
        empty_set.encode_cer(&default_limits()).unwrap().bytes,
        [0x31, 0x80, 0, 0]
    );
}

/// Validate bounded INTEGER values and canonical ordering in both root kinds.
///
/// Source: X.690 INTEGER and SET OF ordering; generated C range vectors.
/// Version/date: 2026-11-01. Parameters: none. Returns: unit.
/// Errors: assertions detect wrong range checks, order, bytes, or decoded values.
/// Responsible party: asn1c maintainers. History: bounded INTEGER OF coverage.
/// Example: SET OF includes 128 to distinguish full-TLV order from numeric order.
#[test]
fn bounded_integer_collections_validate_ranges_and_sort() {
    assert_eq!(
        SequenceInteger::new(Vec::new())
            .encode_der(&default_limits())
            .unwrap()
            .bytes,
        [0x30, 0]
    );
    assert_eq!(
        SetInteger::new(Vec::new())
            .encode_cer(&default_limits())
            .unwrap()
            .bytes,
        [0x31, 0x80, 0, 0]
    );
    let values = SequenceInteger::new(vec![2, -1, 0]);
    let der = [0x30, 9, 2, 1, 2, 2, 1, 0xff, 2, 1, 0];
    let cer = [0x30, 0x80, 2, 1, 2, 2, 1, 0xff, 2, 1, 0, 0, 0];
    assert_eq!(values.encode_der(&default_limits()).unwrap().bytes, der);
    assert_eq!(values.encode_cer(&default_limits()).unwrap().bytes, cer);

    let set = SetInteger::new(vec![2, -1, 0, 128]);
    let encoded_definite = [0x31, 0x0d, 2, 1, 0, 2, 1, 2, 2, 1, 0xff, 2, 2, 0, 0x80];
    let encoded_indefinite = [
        0x31, 0x80, 2, 1, 0, 2, 1, 2, 2, 1, 0xff, 2, 2, 0, 0x80, 0, 0,
    ];
    assert_eq!(
        set.encode_der(&default_limits()).unwrap().bytes,
        encoded_definite
    );
    assert_eq!(
        set.encode_cer(&default_limits()).unwrap().bytes,
        encoded_indefinite
    );
    let decoded_sequence = SequenceInteger::decode_ber(&der, &default_limits()).unwrap();
    assert_eq!(decoded_sequence.value.as_slice(), [2, -1, 0]);
    let decoded_sequence_cer = SequenceInteger::decode_cer(&cer, &default_limits()).unwrap();
    assert_eq!(decoded_sequence_cer.value.as_slice(), [2, -1, 0]);
    let decoded_set_ber = SetInteger::decode_ber(&encoded_definite, &default_limits()).unwrap();
    assert_eq!(decoded_set_ber.value.as_slice(), [0, 2, -1, 128]);
    let decoded_set = SetInteger::decode_cer(&encoded_indefinite, &default_limits()).unwrap();
    assert_eq!(decoded_set.value.as_slice(), [0, 2, -1, 128]);
    let reversed = [
        0x31, 0x80, 2, 2, 0, 0x80, 2, 1, 0xff, 2, 1, 2, 2, 1, 0, 0, 0,
    ];
    let reversed_values = SetInteger::decode_ber(&reversed, &default_limits()).unwrap();
    assert_eq!(reversed_values.value.as_slice(), [128, -1, 2, 0]);
    assert!(SetInteger::decode_cer(&reversed, &default_limits()).is_err());
    assert!(SequenceInteger::new(vec![4])
        .encode_der(&default_limits())
        .is_err());
    let out_of_range = [0x30, 3, 2, 1, 4];
    assert!(SequenceInteger::decode_ber(&out_of_range, &default_limits()).is_err());
}

/// Check BER scalar aliases and their strict CER canonicality rejection.
///
/// Source: live C BER probes and strict CER re-encoding rules.
/// Version/date: 2026-11-01. Parameters: none. Returns: unit.
/// Errors: assertions detect missed normalization or accepted noncanonical CER.
/// Responsible party: asn1c maintainers. History: scalar and identifier aliases.
/// Example: BER normalizes an INTEGER sign octet; CER rejects that wire form.
#[test]
fn ber_scalar_aliases_normalize_and_strict_cer_rejects_them() {
    let zero_length_boolean = [0x30, 2, 1, 0];
    let decoded = SequenceBoolean::decode_ber(&zero_length_boolean, &default_limits()).unwrap();
    assert_eq!(decoded.value.as_slice(), [false]);
    assert_eq!(
        decoded.value.encode_der(&default_limits()).unwrap().bytes,
        [0x30, 3, 1, 1, 0]
    );
    assert!(SequenceBoolean::decode_cer(&zero_length_boolean, &default_limits()).is_err());

    let multi_octet_boolean = [0x30, 4, 1, 2, 0, 1];
    let decoded = SequenceBoolean::decode_ber(&multi_octet_boolean, &default_limits()).unwrap();
    assert_eq!(decoded.value.as_slice(), [true]);
    assert!(SequenceBoolean::decode_cer(&multi_octet_boolean, &default_limits()).is_err());

    let redundant_integer = [0x30, 4, 2, 2, 0, 2];
    let decoded = SequenceInteger::decode_ber(&redundant_integer, &default_limits()).unwrap();
    assert_eq!(decoded.value.as_slice(), [2]);
    assert!(SequenceInteger::decode_cer(&redundant_integer, &default_limits()).is_err());

    let root_alias = [0x3f, 0x10, 0];
    let decoded = SequenceBoolean::decode_ber(&root_alias, &default_limits()).unwrap();
    assert_eq!(decoded.value.as_slice(), []);
    assert!(SequenceBoolean::decode_cer(&root_alias, &default_limits()).is_err());
}

/// Reject truncated, malformed, and over-limit collection inputs.
///
/// Source: collection BER framing and runtime resource policy.
/// Version/date: 2026-11-01. Parameters: none. Returns: unit.
/// Errors: assertions detect malformed acceptance, bad prefixes, or missed limits.
/// Responsible party: asn1c maintainers. History: hostile-input regression vectors.
/// Example: a missing indefinite-form EOC must fail without consuming a suffix.
#[test]
fn malformed_and_truncated_collection_inputs_are_rejected() {
    let canonical = [0x30, 0x80, 1, 1, 0xff, 1, 1, 0, 0, 0];
    for prefix in 0..canonical.len() {
        assert!(SequenceBoolean::decode_ber(&canonical[..prefix], &default_limits()).is_err());
    }
    assert!(SequenceBoolean::decode_ber(&[0x30, 2, 5, 0], &default_limits()).is_err());
    let empty_with_suffix =
        SequenceBoolean::decode_ber(&[0x30, 0x80, 0, 0, 0, 0], &default_limits()).unwrap();
    assert_eq!(empty_with_suffix.value.as_slice(), []);
    assert_consumed(&empty_with_suffix, 4);
    assert!(SequenceBoolean::decode_ber(&[0x30, 0x80, 1, 1, 0xff], &default_limits()).is_err());

    let mut limits = default_limits();
    limits.max_input_bytes = 2;
    assert!(SequenceBoolean::decode_ber(&canonical, &limits).is_err());
    limits = default_limits();
    limits.max_work_bits = 1;
    assert!(SequenceBoolean::decode_ber(&canonical, &limits).is_err());

    for index in 0..canonical.len() {
        for mask in [1, 0x20, 0x80] {
            let mut mutated = canonical;
            mutated[index] ^= mask;
            if let Ok(decoded) = SequenceBoolean::decode_ber(&mutated, &default_limits()) {
                assert!(decoded.consumed_bytes > 0);
                assert!(decoded.consumed_bytes <= mutated.len());
                assert_eq!(decoded.consumed_bits, decoded.consumed_bytes * 8);
            }
        }
    }

    let excessive = SequenceBoolean::new(vec![false; 1_000_001]);
    assert!(excessive.encode_der(&default_limits()).is_err());
}

/// Confirm generated decoder errors use the runtime error contract.
///
/// Source: generated BER decoder and `asn1c_runtime::Error`.
/// Version/date: 2026-11-01. Parameters: none. Returns: unit.
/// Errors: assertions fail if malformed input returns an unexpected error kind.
/// Responsible party: asn1c maintainers. History: public generated API contract.
/// Example: a truncated SET OF child returns a runtime encoding/truncation error.
#[test]
fn generated_decode_error_type_is_runtime_error() {
    let malformed = [0x31, 2, 2, 0];
    let error: Error = SetBoolean::decode_ber(&malformed, &default_limits()).unwrap_err();
    assert!(matches!(
        error,
        Error::InvalidEncoding { .. } | Error::NeedMoreBytes { .. }
    ));
}
