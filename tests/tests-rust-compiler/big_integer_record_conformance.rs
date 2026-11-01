//! Generated record tests for unconstrained BER/CER INTEGER fields.

use asn1c_generated::big_integer_record::{Sequence, SequenceRequired, SetOptional, SetRequired};
use asn1c_runtime::{BigInteger, Limits};

/// Append a definite BER/DER length to an expected wire buffer.
///
/// Parameters: `length` is content length and `output` receives length octets.
/// Returns no value. Errors: none; callers use bounded test values.
/// Source: X.690 length encoding. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: `BigInteger` record vectors.
/// Example: length 128 appends `81 80`.
fn append_length(length: usize, output: &mut Vec<u8>) {
    let bytes = length.to_le_bytes();
    if length < 128 {
        output.push(bytes[0]);
    } else if length <= 255 {
        output.extend_from_slice(&[0x81, bytes[0]]);
    } else {
        assert!(length <= 0xffff);
        output.extend_from_slice(&[0x82, bytes[1], bytes[0]]);
    }
}

/// Build an independently framed definite or indefinite record TLV.
///
/// Parameters: `tag` is SEQUENCE/SET, `body` contains complete fields, and
/// `cer` selects indefinite CER framing. Returns exact bytes. Errors: none.
/// Source: X.690 record framing. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: C/Rust record parity.
/// Example: a CER SEQUENCE starts `30 80` and ends `00 00`.
fn wrap_record(tag: u8, body: &[u8], cer: bool) -> Vec<u8> {
    let mut output = vec![tag];
    if cer {
        output.push(0x80);
        output.extend_from_slice(body);
        output.extend_from_slice(&[0, 0]);
    } else {
        append_length(body.len(), &mut output);
        output.extend_from_slice(body);
    }
    output
}

/// Construct an exact expected BOOLEAN, INTEGER, and OCTET STRING body.
///
/// Parameters: `integer` is canonical signed two's-complement content.
/// Returns complete child TLVs in universal-tag order. Errors: none.
/// Source: X.690 primitive content framing. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: record differential vectors.
/// Example: INTEGER 128 uses content `00 80`.
fn scalar_record_body(integer: Option<&[u8]>) -> Vec<u8> {
    let mut body = vec![0x01, 0x01, 0xff];
    if let Some(content) = integer {
        body.push(0x02);
        append_length(content.len(), &mut body);
        body.extend_from_slice(content);
    }
    body.extend_from_slice(&[0x04, 0x01, 0xa5]);
    body
}

/// Verify one content length in both SEQUENCE and SET record encodings.
///
/// Parameters: `length` is the canonical signed INTEGER content size and
/// `limits` bounds the generated operations. Returns no value.
/// Errors: encode/decode mismatches panic the test. Source: X.690 length forms.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: wide INTEGER record boundaries. Example: 1001 stays primitive CER.
fn check_content_length_case(length: usize, limits: &Limits) {
    let mut signed_bytes = vec![0; length];
    signed_bytes[0] = 1;
    let sequence = Sequence {
        flag: true,
        value: Some(BigInteger::try_from_signed_bytes(&signed_bytes, limits).unwrap()),
        tail: vec![0xa5],
    };
    let set = SetOptional {
        flag: true,
        value: Some(BigInteger::try_from_signed_bytes(&signed_bytes, limits).unwrap()),
        tail: vec![0xa5],
    };
    for cer in [false, true] {
        let sequence_wire = wrap_record(0x30, &scalar_record_body(Some(&signed_bytes)), cer);
        let sequence_encoded = if cer {
            sequence.encode_cer(limits).unwrap()
        } else {
            sequence.encode_der(limits).unwrap()
        };
        assert_eq!(sequence_encoded.bytes, sequence_wire);
        let sequence_decoded = if cer {
            Sequence::decode_cer(&sequence_wire, limits).unwrap()
        } else {
            Sequence::decode_ber(&sequence_wire, limits).unwrap()
        };
        assert_eq!(
            sequence_decoded.value.value.unwrap().as_signed_bytes(),
            signed_bytes
        );

        let set_wire = wrap_record(0x31, &scalar_record_body(Some(&signed_bytes)), cer);
        let set_encoded = if cer {
            set.encode_cer(limits).unwrap()
        } else {
            set.encode_der(limits).unwrap()
        };
        assert_eq!(set_encoded.bytes, set_wire);
        let set_decoded = if cer {
            SetOptional::decode_cer(&set_wire, limits).unwrap()
        } else {
            SetOptional::decode_ber(&set_wire, limits).unwrap()
        };
        assert_eq!(
            set_decoded.value.value.unwrap().as_signed_bytes(),
            signed_bytes
        );
    }
}

/// Test every signed boundary and long content through record wrappers.
///
/// Parameters: none. Returns no value; assertions compare C-verifiable bytes.
/// Errors: generated codec failures cause test failure.
/// Source: X.690 INTEGER vectors and wide C reference. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: `BigInteger` record stage.
/// Example: the value `2^64` round-trips as an OPTIONAL field.
#[test]
fn sequence_and_set_vectors_match_der_cer_and_prefix_decoders() {
    let limits = Limits::default();
    let vectors: &[&[u8]] = &[
        &[0],
        &[1],
        &[0xff],
        &[0xff, 0x7f],
        &[0x80],
        &[0x7f],
        &[0, 0x80],
        &[0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        &[0x80, 0, 0, 0, 0, 0, 0, 0],
        &[1, 0, 0, 0, 0, 0, 0, 0, 0],
        &[0xfe, 0, 0, 0, 0, 0, 0, 0, 0],
    ];
    for signed_bytes in vectors {
        let integer = BigInteger::try_from_signed_bytes(signed_bytes, &limits).unwrap();
        let value = Sequence {
            flag: true,
            value: Some(integer),
            tail: vec![0xa5],
        };
        for cer in [false, true] {
            let expected = wrap_record(0x30, &scalar_record_body(Some(signed_bytes)), cer);
            let encoded = if cer {
                value.encode_cer(&limits).unwrap()
            } else {
                value.encode_der(&limits).unwrap()
            };
            assert_eq!(encoded.bytes, expected);
            let mut suffix = expected.clone();
            suffix.push(0xff);
            let decoded = if cer {
                Sequence::decode_cer(&suffix, &limits).unwrap()
            } else {
                Sequence::decode_ber(&suffix, &limits).unwrap()
            };
            assert_eq!(
                decoded.value.value.as_ref().unwrap().as_signed_bytes(),
                *signed_bytes
            );
            assert_eq!(decoded.value.tail, [0xa5]);
            assert_eq!(decoded.consumed_bytes, expected.len());
            assert_eq!(decoded.consumed_bits, expected.len() * 8);
        }

        let set = SetOptional {
            flag: true,
            value: Some(BigInteger::try_from_signed_bytes(signed_bytes, &limits).unwrap()),
            tail: vec![0xa5],
        };
        let expected = wrap_record(0x31, &scalar_record_body(Some(signed_bytes)), false);
        assert_eq!(set.encode_der(&limits).unwrap().bytes, expected);
        let decoded = SetOptional::decode_ber(&expected, &limits).unwrap();
        assert_eq!(
            decoded.value.value.unwrap().as_signed_bytes(),
            *signed_bytes
        );
    }

    for length in [127, 128, 1000, 1001] {
        check_content_length_case(length, &limits);
    }
}

/// Verify OPTIONAL omission, required fields, SET order, and long INTEGERs.
///
/// Parameters: none. Returns no value; assertions compare exact TLVs.
/// Errors: generated codec failures cause test failure.
/// Source: C wide-type record vectors. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: optional SET coverage.
/// Example: an absent OPTIONAL INTEGER is omitted from canonical SET output.
#[test]
fn optional_absence_required_values_and_long_content_are_canonical() {
    let limits = Limits::default();
    let absent = Sequence {
        flag: true,
        value: None,
        tail: vec![0xa5],
    };
    let absent_sequence = wrap_record(0x30, &scalar_record_body(None), false);
    assert_eq!(absent.encode_der(&limits).unwrap().bytes, absent_sequence);
    let absent_cer = wrap_record(0x30, &scalar_record_body(None), true);
    assert_eq!(absent.encode_cer(&limits).unwrap().bytes, absent_cer);

    let absent_set = SetOptional {
        flag: true,
        value: None,
        tail: vec![0xa5],
    };
    let absent_set_definite = wrap_record(0x31, &scalar_record_body(None), false);
    let absent_set_canonical = wrap_record(0x31, &scalar_record_body(None), true);
    assert_eq!(
        absent_set.encode_der(&limits).unwrap().bytes,
        absent_set_definite
    );
    assert_eq!(
        absent_set.encode_cer(&limits).unwrap().bytes,
        absent_set_canonical
    );

    let reversed_set_ber = [
        0x31, 0x09, 0x04, 0x01, 0xa5, 0x02, 0x01, 0x01, 0x01, 0x01, 0xff,
    ];
    let reversed = SetOptional::decode_ber(&reversed_set_ber, &limits).unwrap();
    assert!(reversed.value.flag);
    assert_eq!(reversed.value.tail, [0xa5]);
    assert_eq!(reversed.value.value.unwrap().as_signed_bytes(), [1]);
    let reordered_set_canonical = [
        0x31, 0x80, 0x04, 0x01, 0xa5, 0x02, 0x01, 0x01, 0x01, 0x01, 0xff, 0, 0,
    ];
    assert!(SetOptional::decode_cer(&reordered_set_canonical, &limits).is_err());

    let integer = BigInteger::try_from_signed_bytes(&[0, 0x80], &limits).unwrap();
    let required_sequence = SequenceRequired {
        value: integer,
        flag: true,
    };
    let expected_sequence = [0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x01, 0x01, 0xff];
    assert_eq!(
        required_sequence.encode_der(&limits).unwrap().bytes,
        expected_sequence
    );

    let integer = BigInteger::try_from_signed_bytes(&[0, 0x80], &limits).unwrap();
    let required_set = SetRequired {
        flag: true,
        value: integer,
        tail: vec![0xa5],
    };
    let expected_set = wrap_record(0x31, &scalar_record_body(Some(&[0, 0x80])), false);
    assert_eq!(
        required_set.encode_der(&limits).unwrap().bytes,
        expected_set
    );

    let mut long_content = vec![0; 129];
    long_content[0] = 1;
    let integer = BigInteger::try_from_signed_bytes(&long_content, &limits).unwrap();
    let value = Sequence {
        flag: true,
        value: Some(integer),
        tail: vec![0xa5],
    };
    let expected = wrap_record(0x30, &scalar_record_body(Some(&long_content)), false);
    assert_eq!(value.encode_der(&limits).unwrap().bytes, expected);
    let decoded = Sequence::decode_ber(&expected, &limits).unwrap();
    assert_eq!(decoded.value.value.unwrap().as_signed_bytes(), long_content);
}

/// Test BER normalization and strict CER rejection for malformed INTEGER TLVs.
///
/// Parameters: none. Returns no value; assertions verify field and framing rules.
/// Errors: malformed input and noncanonical CER must return runtime errors.
/// Source: X.690 signed INTEGER decoding. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: record mutation tests.
/// Example: BER accepts a redundant sign octet; strict CER rejects it.
#[test]
fn aliases_redundant_signs_and_malformed_records_are_checked() {
    let limits = Limits::default();
    let mut redundant_body = vec![0x01, 0x01, 0xff, 0x02, 0x02, 0x00, 0x01];
    redundant_body.extend_from_slice(&[0x04, 0x01, 0xa5]);
    let redundant = wrap_record(0x30, &redundant_body, false);
    let decoded = Sequence::decode_ber(&redundant, &limits).unwrap();
    assert_eq!(decoded.value.value.unwrap().as_signed_bytes(), [1]);

    let mut alias_body = scalar_record_body(Some(&[1]));
    alias_body.splice(3..6, [0x1f, 0x02, 0x01, 0x01]);
    let alias = wrap_record(0x30, &alias_body, false);
    let alias_decoded = Sequence::decode_ber(&alias, &limits).unwrap();
    assert_eq!(alias_decoded.value.value.unwrap().as_signed_bytes(), [1]);
    assert!(Sequence::decode_cer(&wrap_record(0x30, &redundant_body, true), &limits).is_err());
    assert!(Sequence::decode_cer(&wrap_record(0x30, &alias_body, true), &limits).is_err());

    let empty_integer = [0x30, 0x05, 0x01, 0x01, 0xff, 0x02, 0x00];
    assert!(Sequence::decode_ber(&empty_integer, &limits).is_err());
    assert!(Sequence::decode_cer(&empty_integer, &limits).is_err());
}

/// Exercise truncation, mutations, and operation resource limits.
///
/// Parameters: none. Returns no value; assertions require bounded outcomes.
/// Errors: malformed or over-limit input must be rejected without panics.
/// Source: generated-record hostile-input checks. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: safe prefix decoding.
/// Example: a truncated outer length is rejected.
#[test]
fn truncation_mutation_and_limits_fail_safely() {
    let limits = Limits::default();
    let value = Sequence {
        flag: true,
        value: Some(BigInteger::try_from_signed_bytes(&[1, 0, 0], &limits).unwrap()),
        tail: vec![0xa5],
    };
    let wire = value.encode_cer(&limits).unwrap().bytes;
    for end in 0..wire.len() {
        assert!(Sequence::decode_ber(&wire[..end], &limits).is_err());
        assert!(Sequence::decode_cer(&wire[..end], &limits).is_err());
    }
    for index in 0..wire.len() {
        let mut mutated = wire.clone();
        mutated[index] ^= 0x80;
        for decoded in [
            Sequence::decode_ber(&mutated, &limits),
            Sequence::decode_cer(&mutated, &limits),
        ]
        .into_iter()
        .flatten()
        {
            assert!(decoded.consumed_bytes <= mutated.len());
            assert_eq!(decoded.consumed_bits, decoded.consumed_bytes * 8);
        }
    }

    let small_input = Limits {
        max_input_bytes: 4,
        ..limits
    };
    let small_output = Limits {
        max_output_bytes: 4,
        ..limits
    };
    let no_work = Limits {
        max_work_bits: 0,
        ..limits
    };
    assert!(Sequence::decode_ber(&wire, &small_input).is_err());
    assert!(value.encode_der(&small_output).is_err());
    assert!(value.encode_cer(&no_work).is_err());
}
