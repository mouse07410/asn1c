//! Generated BER/DER/CER tests for direct unbounded `IA5String` values.

use asn1c_generated::ia5_values::AsciiValue;
use asn1c_runtime::Limits;

/// Append the shortest definite length encoding used by fixed vectors.
///
/// Parameters: `output` receives length octets; `length` is content size.
/// Returns no value. Errors are impossible for the tested bounded vectors.
/// Source: X.690 definite length encoding. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: IA5 wire vectors.
/// Example: length 1001 appends `82 03 e9`.
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

/// Build a primitive `IA5String` or OCTET STRING TLV.
///
/// Parameters: `tag` is the universal tag; `content` is payload bytes.
/// Returns the full TLV. Errors are impossible for test vector sizes.
/// Source: X.690 primitive TLV form. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: independent IA5 vectors.
/// Example: tag 22 and empty content produce `[16, 0]`.
fn primitive(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    append_length(&mut output, content.len());
    output.extend_from_slice(content);
    output
}

/// Build the canonical CER `IA5String` form with universal OCTET fragments.
///
/// Parameters: `content` is valid 7-bit IA5 data. Returns primitive content
/// through 1000 octets, then an indefinite constructed value. Errors are none.
/// Source: X.690 CER string fragmentation. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: IA5 fragmentation vectors.
/// Example: 1001 bytes use tag 36 and tags 04 for both chunks.
fn cer_vector(content: &[u8]) -> Vec<u8> {
    if content.len() <= 1000 {
        return primitive(0x16, content);
    }
    let mut output = vec![0x36, 0x80];
    for fragment in content.chunks(1000) {
        output.extend_from_slice(&primitive(0x04, fragment));
    }
    output.extend_from_slice(&[0, 0]);
    output
}

/// Compare exact DER/CER bytes and BER/CER prefix values for a valid payload.
///
/// Parameters: `content` is a valid IA5 byte string; `limits` bounds operations.
/// Returns no value. Errors are codec or assertion failures.
/// Source: C IA5 fixed vectors and X.690. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: direct IA5 interoperability.
/// Example: test 1001 bytes and its constructed CER fragments.
fn check_valid_case(content: &[u8], limits: &Limits) {
    let value = AsciiValue::try_from_bytes(content, limits).unwrap();
    let der = primitive(0x16, content);
    let cer = cer_vector(content);
    assert_eq!(value.as_bytes(), content);
    assert_eq!(value.encode_der(limits).unwrap().bytes, der);
    assert_eq!(value.encode_cer(limits).unwrap().bytes, cer);
    let mut der_prefix = der.clone();
    der_prefix.push(0xff);
    let decoded = AsciiValue::decode_ber(&der_prefix, limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), content);
    assert_eq!(decoded.consumed_bytes, der.len());
    assert_eq!(decoded.consumed_bits, der.len() * 8);
    if content.len() <= 1000 {
        let decoded = AsciiValue::decode_cer(&der_prefix, limits).unwrap();
        assert_eq!(decoded.value.as_bytes(), content);
        assert_eq!(decoded.consumed_bytes, der.len());
    } else {
        assert!(AsciiValue::decode_cer(&der_prefix, limits).is_err());
    }
    let mut cer_prefix = cer.clone();
    cer_prefix.push(0xff);
    let decoded = AsciiValue::decode_cer(&cer_prefix, limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), content);
    assert_eq!(decoded.consumed_bytes, cer.len());
    assert_eq!(decoded.consumed_bits, cer.len() * 8);
}

/// Check empty values, all 7-bit bytes, and CER content boundaries.
///
/// Parameters: none. Returns no value. Errors are codec or assertion failures.
/// Source: C IA5 BER/CER probes. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: IA5 boundary coverage.
/// Example: NUL, ESC, and DEL remain valid IA5 bytes.
#[test]
fn ia5_empty_repertoire_and_cer_boundaries_match() {
    let limits = Limits::default();
    for length in [0, 127, 128, 999, 1000, 1001, 2001] {
        check_valid_case(&vec![b'A'; length], &limits);
    }
    check_valid_case(&[0, 0x1b, 0x7f], &limits);
}

/// Preserve invalid IA5 bytes in BER/DER and reject them in CER.
///
/// Parameters: none. Returns no value. Errors are assertion failures.
/// Source: C encoder constraint timing. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: BER/CER timing parity.
/// Example: byte `80` encodes as `16 01 80` under DER but CER rejects it.
#[test]
fn high_bit_bytes_are_raw_for_ber_der_and_invalid_for_cer() {
    let limits = Limits::default();
    let value = AsciiValue::try_from_bytes(&[0x80], &limits).unwrap();
    let expected = [0x16, 0x01, 0x80];
    assert_eq!(value.encode_der(&limits).unwrap().bytes, expected);
    assert!(value.encode_cer(&limits).is_err());
    let decoded = AsciiValue::decode_ber(&expected, &limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), [0x80]);
    assert_eq!(decoded.consumed_bytes, expected.len());
    assert!(AsciiValue::decode_cer(&expected, &limits).is_err());
}

/// Flatten constructed BER OCTET STRING children and reject other child tags.
///
/// Parameters: none. Returns no value. Errors are assertion failures.
/// Source: X.690 BER character-string forms and C probes. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: nested IA5 input.
/// Example: a nested constructed empty value decodes to empty content.
#[test]
fn constructed_ber_aliases_and_child_tags_are_checked() {
    let limits = Limits::default();
    let definite = [0x36, 0x08, 0x04, 0x01, b'A', 0x24, 0x03, 0x04, 0x01, b'B'];
    let indefinite = [
        0x36, 0x80, 0x04, 0x01, b'A', 0x24, 0x80, 0x04, 0x01, b'B', 0, 0, 0, 0,
    ];
    for (wire, expected) in [(&definite[..], &b"AB"[..]), (&indefinite[..], &b"AB"[..])] {
        let decoded = AsciiValue::decode_ber(wire, &limits).unwrap();
        assert_eq!(decoded.value.as_bytes(), expected);
        assert_eq!(decoded.consumed_bytes, wire.len());
        assert!(AsciiValue::decode_cer(wire, &limits).is_err());
    }
    let empty_constructed = [0x36, 0x80, 0, 0];
    let decoded = AsciiValue::decode_ber(&empty_constructed, &limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), []);
    assert_eq!(decoded.consumed_bytes, empty_constructed.len());
    assert_eq!(decoded.value.encode_cer(&limits).unwrap().bytes, [0x16, 0]);
    assert!(AsciiValue::decode_cer(&empty_constructed, &limits).is_err());

    let root_alias = [0x1f, 0x16, 0x01, b'A'];
    let child_alias = [0x36, 0x80, 0x1f, 0x04, 0x01, b'A', 0, 0];
    for wire in [&root_alias[..], &child_alias[..]] {
        let decoded = AsciiValue::decode_ber(wire, &limits).unwrap();
        assert_eq!(decoded.value.as_bytes(), b"A");
        assert_eq!(decoded.consumed_bytes, wire.len());
        assert!(AsciiValue::decode_cer(wire, &limits).is_err());
    }
    let high_child = [0x36, 0x80, 0x04, 0x01, 0x80, 0, 0];
    let decoded = AsciiValue::decode_ber(&high_child, &limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), [0x80]);
    assert!(AsciiValue::decode_cer(&high_child, &limits).is_err());
    let wrong_child = [0x36, 0x80, 0x16, 0x01, b'A', 0, 0];
    assert!(AsciiValue::decode_ber(&wrong_child, &limits).is_err());
}

/// Check malformed inputs, truncation, mutation bounds, and exact codec limits.
///
/// Parameters: none. Returns no value. Errors are assertion failures.
/// Source: BER parser robustness and C IA5 probes. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: IA5 hostile-input coverage.
/// Example: every proper prefix of canonical constructed CER is rejected.
#[test]
fn malformed_truncated_mutated_and_limited_inputs_are_checked() {
    let limits = Limits::default();
    for malformed in [
        &[0x16, 0x80, 0, 0][..],
        &[0x16, 0x82, 0, 1][..],
        &[0x36, 0x80, 0x04, 0x01, b'A', 0][..],
        &[0x36, 0x80, 0x04, 0x01, b'A', 0, 1][..],
    ] {
        assert!(AsciiValue::decode_ber(malformed, &limits).is_err());
        assert!(AsciiValue::decode_cer(malformed, &limits).is_err());
    }
    let canonical = cer_vector(&vec![b'A'; 1001]);
    for end in 0..canonical.len() {
        assert!(AsciiValue::decode_ber(&canonical[..end], &limits).is_err());
        assert!(AsciiValue::decode_cer(&canonical[..end], &limits).is_err());
    }
    for index in 0..canonical.len() {
        let mut changed = canonical.clone();
        changed[index] ^= 0x80;
        if let Ok(decoded) = AsciiValue::decode_ber(&changed, &limits) {
            assert!(decoded.consumed_bytes <= changed.len());
            assert_eq!(decoded.consumed_bits, decoded.consumed_bytes * 8);
        }
    }
    let exact = Limits {
        max_input_bytes: 4,
        max_output_bytes: 3,
        ..limits
    };
    let value = AsciiValue::try_from_bytes(&[0x80], &exact).unwrap();
    assert_eq!(value.encode_der(&exact).unwrap().bytes, [0x16, 0x01, 0x80]);
    let decoded = AsciiValue::decode_ber(&[0x16, 1, 0x80, 0xff], &exact).unwrap();
    assert_eq!(decoded.value.as_bytes(), [0x80]);
    assert_eq!(decoded.consumed_bytes, 3);
    assert!(value.encode_cer(&exact).is_err());
    let no_input = Limits { max_input_bytes: 3, ..exact };
    let no_output = Limits { max_output_bytes: 2, ..exact };
    let no_work = Limits {
        max_work_bits: 0,
        ..exact
    };
    assert!(AsciiValue::decode_ber(&[0x16, 1, 0x80, 0xff], &no_input).is_err());
    assert!(value.encode_der(&no_output).is_err());
    assert!(AsciiValue::try_from_bytes(b"A", &no_work).is_err());
}
