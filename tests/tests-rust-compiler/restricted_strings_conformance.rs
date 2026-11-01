//! Generated BER/DER/CER tests for direct restricted character strings.

use asn1c_generated::restricted_strings::*;
use asn1c_runtime::Limits;

/// Append a shortest definite length for independently assembled vectors.
/// Parameters: `out` receives length octets; `length` is content size.
/// Returns no value. Errors are impossible for the bounded test vectors.
/// Source: X.690 definite lengths. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: restricted-string vectors.
/// Example: length 1001 appends `82 03 e9`.
fn append_length(out: &mut Vec<u8>, length: usize) {
    if length < 128 {
        out.push(u8::try_from(length).unwrap());
    } else if length < 256 {
        out.extend_from_slice(&[0x81, u8::try_from(length).unwrap()]);
    } else {
        out.push(0x82);
        out.extend_from_slice(&u16::try_from(length).unwrap().to_be_bytes());
    }
}

/// Assemble one primitive universal string TLV.
/// Parameters: `tag` is the universal tag; `content` is raw content.
/// Returns the complete TLV. Errors are impossible for these vector lengths.
/// Source: X.690 primitive TLV form. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: string wire vectors.
/// Example: tag 12 and empty content produce `[12, 0]`.
fn primitive(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    append_length(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

/// Build canonical CER with universal OCTET STRING fragments.
/// Parameters: `tag` identifies the character-string type; `content` is raw.
/// Returns primitive CER through 1000 octets, then fragmented CER.
/// Source: X.690 CER character-string form. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: generic string vectors.
/// Example: 1001 octets use a constructed outer value with two children.
fn cer_vector(tag: u8, content: &[u8]) -> Vec<u8> {
    if content.len() <= 1000 {
        return primitive(tag, content);
    }
    let mut out = vec![tag | 0x20, 0x80];
    for chunk in content.chunks(1000) {
        out.extend_from_slice(&primitive(0x04, chunk));
    }
    out.extend_from_slice(&[0, 0]);
    out
}

/// Check one direct string wrapper against primitive and fragmented vectors.
/// Parameters: `T` is a generated type; `tag` and `content` are its vector.
/// Returns no value. Errors are codec or assertion failures.
/// Source: C differential vectors and X.690. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: per-kind interoperability.
/// Example: `check_case!(Utf8Value, 12, b"text")`.
macro_rules! check_case {
    ($type:ty, $tag:expr, $content:expr, $limits:expr) => {{
        let content: &[u8] = $content;
        let limits: &Limits = $limits;
        let value = <$type>::try_from_bytes(content, limits).unwrap();
        let der = primitive($tag, content);
        let cer = cer_vector($tag, content);
        assert_eq!(value.as_bytes(), content);
        assert_eq!(value.encode_der(limits).unwrap().bytes, der);
        assert_eq!(value.encode_cer(limits).unwrap().bytes, cer);
        let mut ber_prefix = der.clone();
        ber_prefix.push(0xff);
        let decoded = <$type>::decode_ber(&ber_prefix, limits).unwrap();
        assert_eq!(decoded.value.as_bytes(), content);
        assert_eq!(decoded.consumed_bytes, der.len());
        assert_eq!(decoded.consumed_bits, der.len() * 8);
        if content.len() > 1000 {
            assert!(<$type>::decode_cer(&der, limits).is_err());
        }
        let mut cer_prefix = cer.clone();
        cer_prefix.push(0xff);
        let decoded = <$type>::decode_cer(&cer_prefix, limits).unwrap();
        assert_eq!(decoded.value.as_bytes(), content);
        assert_eq!(decoded.consumed_bytes, cer.len());
        assert_eq!(decoded.consumed_bits, cer.len() * 8);
    }};
}

/// Exercise every supported AST spelling, including both shared-tag aliases.
/// Parameters: none. Returns no value. Errors are codec or assertion failures.
/// Source: direct restricted-string matrix. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: initial kind coverage.
/// Example: Teletex and T61 use tag 20 but distinct wrappers.
#[test]
fn every_kind_and_alias_uses_its_intrinsic_tag() {
    let limits = Limits::default();
    check_case!(ObjectDescriptorValue, 7, &[0xff], &limits);
    check_case!(UTF8Value, 12, &[0x41], &limits);
    check_case!(NumericValue, 18, b" 0129", &limits);
    check_case!(PrintableValue, 19, b"Az09 '()+,-./:=?", &limits);
    check_case!(TeletexValue, 20, &[0xff], &limits);
    check_case!(T61Value, 20, &[0xfe], &limits);
    check_case!(VideotexValue, 21, &[0x80], &limits);
    check_case!(GraphicValue, 25, &[0x81], &limits);
    check_case!(VisibleValue, 26, b" ~", &limits);
    check_case!(ISO646Value, 26, b" ~", &limits);
    check_case!(GeneralValue, 27, &[0xff], &limits);
    check_case!(UniversalValue, 28, &[0, 0, 0, 65], &limits);
    check_case!(BMPValue, 30, &[0, 65], &limits);
}

/// Check CER fragmentation boundaries for all kinds with valid unit alignment.
/// Parameters: none. Returns no value. Errors are codec or assertion failures.
/// Source: live C CER boundary vectors. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: string fragmentation.
/// Example: BMP and Universal lengths retain two- and four-byte units.
#[test]
fn cer_fragmentation_boundaries_match_each_kind() {
    let limits = Limits::default();
    for length in [0, 127, 128, 999, 1000, 1001] {
        let content = vec![b'A'; length];
        check_case!(ObjectDescriptorValue, 7, &content, &limits);
        check_case!(UTF8Value, 12, &content, &limits);
        let numeric = vec![b'1'; length];
        check_case!(NumericValue, 18, &numeric, &limits);
        check_case!(PrintableValue, 19, &content, &limits);
        check_case!(TeletexValue, 20, &content, &limits);
        check_case!(T61Value, 20, &content, &limits);
        check_case!(VideotexValue, 21, &content, &limits);
        check_case!(GraphicValue, 25, &content, &limits);
        check_case!(VisibleValue, 26, &content, &limits);
        check_case!(ISO646Value, 26, &content, &limits);
        check_case!(GeneralValue, 27, &content, &limits);
    }
    for length in [0, 126, 128, 998, 1000, 1002] {
        let content = vec![0x41; length];
        check_case!(BMPValue, 30, &content, &limits);
    }
    for length in [0, 124, 128, 996, 1000, 1004] {
        let content = vec![0x41; length];
        check_case!(UniversalValue, 28, &content, &limits);
    }
}

/// Apply the documented C-compatible CER validators after byte reassembly.
/// Parameters: none. Returns no value. Errors are assertion failures.
/// Source: C descriptor constraints. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: CER repertoire behavior.
/// Example: BER/DER retain invalid `PrintableString` bytes; CER rejects them.
#[test]
fn cer_validates_repertoires_and_code_unit_alignment() {
    let limits = Limits::default();
    let invalid_numeric = NumericValue::try_from_bytes(b"A", &limits).unwrap();
    assert_eq!(invalid_numeric.encode_der(&limits).unwrap().bytes, [18, 1, b'A']);
    assert!(invalid_numeric.encode_cer(&limits).is_err());
    assert!(NumericValue::decode_ber(&[18, 1, b'A'], &limits).is_ok());
    assert!(NumericValue::decode_cer(&[18, 1, b'A'], &limits).is_err());

    let invalid_printable = PrintableValue::try_from_bytes(b"@", &limits).unwrap();
    assert!(invalid_printable.encode_der(&limits).is_ok());
    assert!(invalid_printable.encode_cer(&limits).is_err());
    let invalid_visible = VisibleValue::try_from_bytes(&[0x7f], &limits).unwrap();
    assert!(invalid_visible.encode_der(&limits).is_ok());
    assert!(invalid_visible.encode_cer(&limits).is_err());
    let invalid_iso = ISO646Value::try_from_bytes(&[0x1f], &limits).unwrap();
    assert!(invalid_iso.encode_der(&limits).is_ok());
    assert!(invalid_iso.encode_cer(&limits).is_err());

    let odd_bmp = BMPValue::try_from_bytes(&[0x41], &limits).unwrap();
    assert!(odd_bmp.encode_der(&limits).is_ok());
    assert!(odd_bmp.encode_cer(&limits).is_err());
    check_case!(BMPValue, 30, &[0xd8, 0x00], &limits);
    let partial_universal = UniversalValue::try_from_bytes(&[0, 0, 0], &limits).unwrap();
    assert!(partial_universal.encode_der(&limits).is_ok());
    assert!(partial_universal.encode_cer(&limits).is_err());
    check_case!(UniversalValue, 28, &[0xff, 0xff, 0xff, 0xff], &limits);
}

/// Match C's minimal one- through six-byte UTF8 sequence checks.
/// Parameters: none. Returns no value. Errors are codec or assertion failures.
/// Source: approved C-compatibility rules. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: legacy UTF8 compatibility.
/// Example: minimal five- and six-byte forms are accepted by CER.
#[test]
fn utf8_cer_accepts_minimal_legacy_and_scalar_edge_sequences() {
    let limits = Limits::default();
    for valid in [
        &[0x00][..],
        &[0xc2, 0x80],
        &[0xe0, 0xa0, 0x80],
        &[0xed, 0xa0, 0x80],
        &[0xf4, 0x90, 0x80, 0x80],
        &[0xf8, 0x88, 0x80, 0x80, 0x80],
        &[0xfc, 0x84, 0x80, 0x80, 0x80, 0x80],
    ] {
        check_case!(UTF8Value, 12, valid, &limits);
    }
    for invalid in [
        &[0xc0, 0x80][..],
        &[0xe2, 0x82],
        &[0xe2, 0x28, 0xa1],
        &[0xfe],
        &[0xf8, 0x80, 0x80, 0x80, 0x80],
    ] {
        let value = UTF8Value::try_from_bytes(invalid, &limits).unwrap();
        assert!(value.encode_der(&limits).is_ok());
        assert!(value.encode_cer(&limits).is_err());
        let wire = primitive(12, invalid);
        assert!(UTF8Value::decode_ber(&wire, &limits).is_ok());
        assert!(UTF8Value::decode_cer(&wire, &limits).is_err());
    }
}

/// Validate UTF8 content only after CER fragments have been reassembled.
/// Parameters: none. Returns no value. Errors are codec or assertion failures.
/// Source: C bytewise fragmentation. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: split UTF8 sequence.
/// Example: a three-byte character begins at content offset 999.
#[test]
fn utf8_sequence_may_cross_a_cer_fragment_boundary() {
    let limits = Limits::default();
    let mut content = vec![b'A'; 999];
    content.extend_from_slice(&[0xe2, 0x82, 0xac]);
    check_case!(UTF8Value, 12, &content, &limits);
}

/// Check constructed BER flattening, prefix accounting, malformed input, limits.
/// Parameters: none. Returns no value. Errors are assertion failures.
/// Source: BER parser robustness and C string probes. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: constructed input coverage.
/// Example: nested universal OCTET STRING children become `AB`.
#[test]
fn constructed_ber_prefix_truncation_and_limits_are_checked() {
    let limits = Limits::default();
    let definite = [0x2c, 8, 4, 1, b'A', 0x24, 3, 4, 1, b'B'];
    let indefinite = [0x2c, 0x80, 4, 1, b'A', 0x24, 0x80, 4, 1, b'B', 0, 0, 0, 0];
    for (wire, expected) in [(&definite[..], &b"AB"[..]), (&indefinite[..], &b"AB"[..])] {
        let decoded = UTF8Value::decode_ber(wire, &limits).unwrap();
        assert_eq!(decoded.value.as_bytes(), expected);
        assert_eq!(decoded.consumed_bytes, wire.len());
        assert!(UTF8Value::decode_cer(wire, &limits).is_err());
    }
    let empty_constructed = [0x2c, 0x80, 0, 0];
    let decoded = UTF8Value::decode_ber(&empty_constructed, &limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), []);
    assert_eq!(decoded.value.encode_cer(&limits).unwrap().bytes, [12, 0]);
    assert!(UTF8Value::decode_cer(&empty_constructed, &limits).is_err());
    for malformed in [
        &[0x2c, 0x80, 0x0c, 1, b'A', 0, 0][..],
        &[0x2c, 0x80, 4, 1, b'A', 0][..],
        &[0x2c, 0x80, 4, 1, b'A', 0, 1][..],
        &[0x0c, 0x82, 0, 1][..],
    ] {
        assert!(UTF8Value::decode_ber(malformed, &limits).is_err());
        assert!(UTF8Value::decode_cer(malformed, &limits).is_err());
    }
    let canonical = cer_vector(12, &vec![b'A'; 1001]);
    for end in 0..canonical.len() {
        assert!(UTF8Value::decode_ber(&canonical[..end], &limits).is_err());
        assert!(UTF8Value::decode_cer(&canonical[..end], &limits).is_err());
    }
    let exact = Limits { max_input_bytes: 4, max_output_bytes: 3, ..limits };
    let one = UTF8Value::try_from_bytes(b"A", &exact).unwrap();
    assert_eq!(one.encode_der(&exact).unwrap().bytes, [12, 1, b'A']);
    assert!(UTF8Value::decode_ber(&[12, 1, b'A', 0xff], &exact).is_ok());
    let output_limit = Limits { max_output_bytes: 2, ..exact };
    assert!(one.encode_der(&output_limit).is_err());
    let no_work = Limits { max_work_bits: 0, ..exact };
    assert!(UTF8Value::try_from_bytes(b"A", &no_work).is_err());
}
