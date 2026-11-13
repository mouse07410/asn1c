//! Generated BER/DER/CER tests for unbounded BIT and OCTET STRING values.

use asn1c_generated::unconstrained_strings::{Bits, Octets};
use asn1c_runtime::{BitStringValue, Limits};

/// Append the shortest definite length form used by the test vectors.
///
/// Parameters: `output` receives length octets; `length` is the content size.
/// Returns no value. Errors are impossible for tested vectors and panic in tests.
/// Original source: X.690 short/long definite lengths. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: string boundary vectors.
/// Example: length 1000 appends `82 03 e8`.
fn append_length(output: &mut Vec<u8>, length: usize) {
    if length < 128 {
        output.push(u8::try_from(length).unwrap());
    } else if length < 256 {
        output.extend_from_slice(&[0x81, u8::try_from(length).unwrap()]);
    } else {
        output.push(0x82);
        output.extend_from_slice(&u16::try_from(length).unwrap().to_be_bytes());
    }
}

/// Build one primitive TLV from a tag and content slice.
///
/// Parameters: `tag` is the one-octet universal tag; `content` is payload.
/// Returns the full TLV. Errors are impossible for tested vectors.
/// Original source: X.690 primitive TLV structure. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: C/Rust fixed vectors.
/// Example: empty OCTET STRING is `[04, 00]`.
fn primitive_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    append_length(&mut output, content.len());
    output.extend_from_slice(content);
    output
}

/// Build independent canonical OCTET STRING CER bytes.
///
/// Parameters: `value` is the payload. Returns a primitive or 1000-octet
/// constructed fragments. Errors are impossible for tested sizes.
/// Original source: X.690 CER OCTET STRING fragmentation. Version/date:
/// 2026-11-01. Responsible party: asn1c maintainers.
/// History: fragmentation boundary vectors. Example: 1001 bytes yields two parts.
fn octet_cer_vector(value: &[u8]) -> Vec<u8> {
    if value.len() <= 1000 {
        return primitive_tlv(0x04, value);
    }
    let mut output = vec![0x24, 0x80];
    for fragment in value.chunks(1000) {
        output.extend_from_slice(&primitive_tlv(0x04, fragment));
    }
    output.extend_from_slice(&[0x00, 0x00]);
    output
}

/// Build independent canonical BIT STRING CER bytes with the final padding.
///
/// Parameters: `bytes` is packed payload; `unused` is its final unused-bit count.
/// Returns a primitive or constructed CER TLV. Errors are impossible for inputs.
/// Original source: X.690 CER BIT STRING fragmentation. Version/date:
/// 2026-11-01. Responsible party: asn1c maintainers.
/// History: non-byte-aligned final fragment. Example: unused bits are 3.
fn bit_cer_vector(bytes: &[u8], unused: u8) -> Vec<u8> {
    let content_len = bytes.len() + 1;
    if content_len <= 1000 {
        let mut content = vec![unused];
        content.extend_from_slice(bytes);
        return primitive_tlv(0x03, &content);
    }
    let mut output = vec![0x23, 0x80];
    let fragments = bytes.chunks(999);
    let count = fragments.len();
    for (index, fragment) in fragments.enumerate() {
        let fragment_unused = if index + 1 == count { unused } else { 0 };
        let mut content = vec![fragment_unused];
        content.extend_from_slice(fragment);
        output.extend_from_slice(&primitive_tlv(0x03, &content));
    }
    output.extend_from_slice(&[0x00, 0x00]);
    output
}

/// Make a validated bit value whose trailing unused bits are zero.
///
/// Parameters: `length` is packed data bytes; `unused` is in 0..=7.
/// Returns validated storage. Invalid helper arguments panic within this test.
/// Original source: runtime `BitStringValue` invariant. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: CER fragment cases.
/// Example: `bit_value(1000, 3)` ends in `0x58`.
fn bit_value(length: usize, unused: u8) -> BitStringValue {
    let mut bytes = vec![0x5a; length];
    if unused > 0 {
        if let Some(last) = bytes.last_mut() {
            *last &= 0xff << unused;
        }
    }
    BitStringValue::new(bytes, length * 8 - usize::from(unused)).unwrap()
}

/// Compare empty and 999/1000/1001/2001 OCTET STRING vectors and prefixes.
///
/// Parameters: none. Returns no value; assertions compare exact DER/CER bytes.
/// Errors: codec errors or incorrect prefix consumption fail the test.
/// Original source: C wide OCTET STRING vectors and X.690. Version/date:
/// 2026-11-01. Responsible party: asn1c maintainers.
/// History: direct unbounded string generator coverage. Example: 1001 fragments.
#[test]
fn octet_string_boundaries_and_cer_fragments_match() {
    let limits = Limits::default();
    for length in [0, 999, 1000, 1001, 2001] {
        let bytes = vec![0x5a; length];
        let value = Octets::new(bytes.clone());
        let der = primitive_tlv(0x04, &bytes);
        let cer = octet_cer_vector(&bytes);
        assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
        assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
        let mut prefixed = der.clone();
        prefixed.push(0xff);
        let ber = Octets::decode_ber(&prefixed, &limits).unwrap();
        assert_eq!(ber.value.as_bytes(), bytes);
        assert_eq!(ber.consumed_bytes, der.len());
        assert_eq!(ber.consumed_bits, der.len() * 8);
        if length <= 1000 {
            let strict = Octets::decode_cer(&prefixed, &limits).unwrap();
            assert_eq!(strict.value.as_bytes(), bytes);
            assert_eq!(strict.consumed_bytes, der.len());
            assert_eq!(strict.consumed_bits, der.len() * 8);
        } else {
            assert!(Octets::decode_cer(&prefixed, &limits).is_err());
        }
        let cer_decoded = Octets::decode_cer(&cer, &limits).unwrap();
        assert_eq!(cer_decoded.value.as_bytes(), bytes);
        assert_eq!(cer_decoded.consumed_bytes, cer.len());
        let mut cer_prefix = cer.clone();
        cer_prefix.push(0xff);
        let cer_decoded = Octets::decode_cer(&cer_prefix, &limits).unwrap();
        assert_eq!(cer_decoded.value.as_bytes(), bytes);
        assert_eq!(cer_decoded.consumed_bytes, cer.len());
        assert_eq!(cer_decoded.consumed_bits, cer.len() * 8);
    }
}

/// Check BIT STRING fragment cutovers and non-byte-aligned final fragments.
///
/// Parameters: none. Returns no value; assertions compare exact DER/CER bytes.
/// Errors: codec errors or incorrect prefix consumption fail the test.
/// Original source: C wide BIT STRING vectors and X.690. Version/date:
/// 2026-11-01. Responsible party: asn1c maintainers.
/// History: direct unbounded BIT STRING generator coverage.
/// Example: 2001 data octets use three CER fragments.
#[test]
fn bit_string_boundaries_preserve_fragment_padding() {
    let limits = Limits::default();
    for (length, unused) in [(0, 0), (998, 0), (999, 0), (1000, 0), (1000, 3), (2001, 3)] {
        let bits = bit_value(length, unused);
        let value = Bits::new(bits);
        let mut der_content = vec![unused];
        der_content.extend_from_slice(value.as_bytes());
        let der = primitive_tlv(0x03, &der_content);
        let cer = bit_cer_vector(value.as_bytes(), unused);
        assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
        assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
        let mut cer_prefix = cer.clone();
        cer_prefix.push(0xff);
        let decoded = Bits::decode_cer(&cer_prefix, &limits).unwrap();
        assert_eq!(decoded.value.as_bit_string(), value.as_bit_string());
        assert_eq!(decoded.consumed_bytes, cer.len());
        assert_eq!(decoded.consumed_bits, cer.len() * 8);
        let mut der_prefix = der.clone();
        der_prefix.push(0xff);
        let ber = Bits::decode_ber(&der_prefix, &limits).unwrap();
        assert_eq!(ber.value.as_bit_string(), value.as_bit_string());
        assert_eq!(ber.consumed_bytes, der.len());
        assert_eq!(ber.consumed_bits, der.len() * 8);
    }
}

/// Decode BER constructed strings, nested forms, aliases, and malformed input.
///
/// Parameters: none. Returns no value; assertions inspect decoded contents.
/// Errors: malformed identifiers, fragments, padding, and EOCs are rejected.
/// Original source: X.690 BER constructed string rules. Version/date:
/// 2026-11-01. Responsible party: asn1c maintainers.
/// History: hostile input coverage. Example: BER flattens nested OCTET fragments.
#[test]
fn ber_strings_flatten_nested_forms_and_reject_malformed_inputs() {
    let limits = Limits::default();
    let octet_cases: &[(&[u8], &[u8])] = &[
        (&[0x24, 0x08, 0x04, 0x02, 0x5a, 0x5a, 0x24, 0x02, 0x04, 0x00], &[0x5a, 0x5a]),
        (&[0x24, 0x80, 0x04, 0x01, 0xaa, 0x24, 0x80, 0x04, 0x01, 0xbb,
           0x00, 0x00, 0x00, 0x00], &[0xaa, 0xbb]),
        (&[0x1f, 0x04, 0x01, 0xaa], &[0xaa]),
    ];
    for (wire, expected) in octet_cases {
        let decoded = Octets::decode_ber(wire, &limits).unwrap();
        assert_eq!(decoded.value.as_bytes(), *expected);
        assert_eq!(decoded.consumed_bits, wire.len() * 8);
        assert!(Octets::decode_cer(wire, &limits).is_err());
    }
    let octet_fragment_alias = [0x24, 0x80, 0x1f, 0x04, 0x01, 0xaa, 0, 0];
    let decoded = Octets::decode_ber(&octet_fragment_alias, &limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), [0xaa]);
    assert_eq!(decoded.consumed_bytes, octet_fragment_alias.len());
    assert!(Octets::decode_cer(&octet_fragment_alias, &limits).is_err());

    let definite_bits = [0x23, 0x08, 0x03, 0x02, 0, 0xa0, 0x03, 0x02, 0, 0x58];
    let decoded = Bits::decode_ber(&definite_bits, &limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), [0xa0, 0x58]);
    assert_eq!(decoded.value.bit_len(), 16);
    let nested_bits = [
        0x23, 0x80, 0x03, 0x02, 0, 0xa0, 0x23, 0x80, 0x03, 0x02, 0, 0x58,
        0, 0, 0, 0,
    ];
    let decoded = Bits::decode_ber(&nested_bits, &limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), [0xa0, 0x58]);
    assert_eq!(decoded.consumed_bytes, nested_bits.len());

    let alias = [0x1f, 0x03, 0x02, 0x00, 0x80];
    let decoded = Bits::decode_ber(&alias, &limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), [0x80]);
    assert!(Bits::decode_cer(&alias, &limits).is_err());
    let bit_fragment_alias = [0x23, 0x80, 0x1f, 0x03, 0x02, 0x00, 0xa0, 0, 0];
    let decoded = Bits::decode_ber(&bit_fragment_alias, &limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), [0xa0]);
    assert_eq!(decoded.consumed_bytes, bit_fragment_alias.len());
    assert!(Bits::decode_cer(&bit_fragment_alias, &limits).is_err());

    for malformed in [
        &[0x24, 0x80, 0x04, 0x01, 0xaa, 0x00, 0x01][..],
        &[0x24, 0x03, 0x04, 0x02, 0xaa][..],
        &[0x24, 0x03, 0x05, 0x01, 0][..],
    ] {
        assert!(Octets::decode_ber(malformed, &limits).is_err());
        assert!(Octets::decode_cer(malformed, &limits).is_err());
    }
    let normalized = Bits::decode_ber(&[0x03, 0x02, 0x03, 0xa7], &limits).unwrap();
    assert_eq!(normalized.value.as_bytes(), [0xa0]);
    assert_eq!(normalized.value.bit_len(), 5);
    assert!(Bits::decode_cer(&[0x03, 0x02, 0x03, 0xa7], &limits).is_err());

    // Issue #602 requires C and Rust to reject padding before the final fragment.
    let nonfinal_padding = [0x23, 0x80, 0x03, 0x02, 0x03, 0xa0,
                            0x03, 0x02, 0x00, 0xaa, 0x00, 0x00];
    assert!(Bits::decode_ber(&nonfinal_padding, &limits).is_err());
    assert!(Bits::decode_cer(&nonfinal_padding, &limits).is_err());
}

/// Test every truncation and one-byte mutation of large string TLVs.
///
/// Parameters: none. Returns no value; assertions bound every accepted prefix.
/// Errors: truncated inputs must fail and mutations must not panic.
/// Original source: BER/CER parser boundary tests. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: direct string robustness.
/// Example: every proper prefix of canonical CER is rejected.
#[test]
fn truncation_and_mutation_inputs_are_checked() {
    let limits = Limits::default();
    let constructed_ber = [
        0x24, 0x80, 0x04, 0x01, 0xaa, 0x24, 0x80, 0x04, 0x01, 0xbb, 0, 0, 0, 0,
    ];
    let octet_cer = octet_cer_vector(&vec![0x5a; 1001]);
    let bit_value = bit_value(1000, 3);
    let bit_cer = bit_cer_vector(bit_value.as_bytes(), 3);
    let mut constructed_prefix = constructed_ber.to_vec();
    constructed_prefix.push(0xff);
    let decoded = Octets::decode_ber(&constructed_prefix, &limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), [0xaa, 0xbb]);
    assert_eq!(decoded.consumed_bytes, constructed_ber.len());

    for end in 0..constructed_ber.len() {
        assert!(Octets::decode_ber(&constructed_ber[..end], &limits).is_err());
    }
    for end in 0..octet_cer.len() {
        assert!(Octets::decode_cer(&octet_cer[..end], &limits).is_err());
    }
    for end in 0..bit_cer.len() {
        assert!(Bits::decode_cer(&bit_cer[..end], &limits).is_err());
    }
    for index in 0..octet_cer.len() {
        let mut changed = octet_cer.clone();
        changed[index] ^= 0x80;
        if let Ok(decoded) = Octets::decode_ber(&changed, &limits) {
            assert!(decoded.consumed_bytes <= changed.len());
            assert_eq!(decoded.consumed_bits, decoded.consumed_bytes * 8);
        }
    }
    for index in 0..bit_cer.len() {
        let mut changed = bit_cer.clone();
        changed[index] ^= 0x80;
        if let Ok(decoded) = Bits::decode_ber(&changed, &limits) {
            assert!(decoded.consumed_bytes <= changed.len());
            assert_eq!(decoded.consumed_bits, decoded.consumed_bytes * 8);
        }
    }
}

/// Check ownership, validated bit padding, and codec resource ceilings.
///
/// Parameters: none. Returns no value; assertions check owned representation.
/// Errors: invalid BIT values and exhausted input/output/work limits fail.
/// Original source: standalone BER string APIs. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: limits and ownership checks.
/// Example: a value with three significant bits stores `a0`.
#[test]
fn string_ownership_and_limits_are_checked() {
    let limits = Limits::default();
    let octets = Octets::new(vec![0xaa, 0xbb]);
    let bits = Bits::new(BitStringValue::new(vec![0xa0], 3).unwrap());
    assert_eq!(octets.as_bytes(), [0xaa, 0xbb]);
    assert_eq!(bits.as_bytes(), [0xa0]);
    assert_eq!(bits.bit_len(), 3);
    let valid_non_aligned = Bits::new(BitStringValue::new(vec![0xa0], 5).unwrap());
    assert_eq!(
        valid_non_aligned.encode_der(&limits).unwrap().bytes,
        [0x03, 0x02, 0x03, 0xa0]
    );
    assert!(BitStringValue::new(vec![0xa7], 5).is_err());
    assert_eq!(
        Bits::decode_ber(&[0x03, 0x02, 0x03, 0xa7], &limits)
            .unwrap()
            .value
            .as_bytes(),
        [0xa0]
    );
    assert!(Bits::decode_cer(&[0x03, 0x02, 0x03, 0xa7], &limits).is_err());
    assert!(BitStringValue::new(vec![0xa0], 2).is_err());

    let small_input = Limits { max_input_bytes: 3, ..limits };
    let small_output = Limits { max_output_bytes: 3, ..limits };
    let no_work = Limits { max_work_bits: 0, ..limits };
    assert!(Octets::decode_ber(&[0x04, 0x02, 0xaa, 0xbb], &small_input).is_err());
    assert!(Bits::decode_ber(&[0x03, 0x02, 0x00, 0xa0], &small_input).is_err());
    assert!(octets.encode_der(&small_output).is_err());
    assert!(bits.encode_cer(&small_output).is_err());
    assert!(Octets::decode_ber(&[0x04, 0x00], &no_work).is_err());
}
