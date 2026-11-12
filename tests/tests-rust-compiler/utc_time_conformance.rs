//! Generated BER/DER/CER tests for direct untagged `UTCTime` values.

use asn1c_generated::utc_time_values::UtcValue;
use asn1c_runtime::{decode_utc_time_ber_tolerant, Limits};

/// Append a shortest definite length for a fixed independent TLV vector.
/// Parameters: `output` receives length octets; `length` is content size.
/// Returns no value. Errors are impossible for bounded test cases.
/// Source: X.690 definite length form. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: `UTCTime` wire vectors.
/// Example: content length four appends `[4]`.
fn append_length(output: &mut Vec<u8>, length: usize) {
    assert!(length < 128);
    output.push(u8::try_from(length).unwrap());
}

/// Build one primitive `UTCTime` TLV with raw content.
/// Parameters: `content` is the exact textual payload.
/// Returns tag 23, definite length, and content. Errors are impossible.
/// Source: X.690 universal tag 23. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: raw DER/CER vectors.
/// Example: `primitive(b"bad")` produces `17 03 62 61 64`.
fn primitive(content: &[u8]) -> Vec<u8> {
    let mut output = vec![0x17];
    append_length(&mut output, content.len());
    output.extend_from_slice(content);
    output
}

/// Check BER/DER raw preservation and normalized CER for one valid time.
/// Parameters: `raw` is an allowed `UTCTime` spelling; `canonical` is its UTC
/// seconds-and-Z form. Returns no value. Errors are codec or assertion failures.
/// Source: C CER time vectors and approved design. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: direct `UTCTime` support.
/// Example: omitted seconds are restored in CER output.
fn check_time(raw: &[u8], canonical: &[u8], limits: &Limits) {
    let value = UtcValue::try_from_bytes(raw, limits).unwrap();
    let der = primitive(raw);
    let cer = primitive(canonical);
    assert_eq!(value.as_bytes(), raw);
    assert_eq!(value.encode_der(limits).unwrap().bytes, der);
    assert_eq!(value.encode_cer(limits).unwrap().bytes, cer);
    let mut der_prefix = der.clone();
    der_prefix.push(0xff);
    let decoded = UtcValue::decode_ber(&der_prefix, limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), raw);
    assert_eq!(decoded.consumed_bytes, der.len());
    assert_eq!(decoded.consumed_bits, der.len() * 8);
    let mut cer_prefix = cer.clone();
    cer_prefix.push(0xff);
    let decoded = UtcValue::decode_cer(&cer_prefix, limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), canonical);
    assert_eq!(decoded.consumed_bytes, cer.len());
    assert_eq!(decoded.consumed_bits, cer.len() * 8);
    if raw != canonical {
        assert!(UtcValue::decode_cer(&der, limits).is_err());
    }
}

/// Cover all supported syntax lengths, pivots, leap dates, and zone signs.
/// Parameters: none. Returns no value. Errors are codec or assertion failures.
/// Source: C `UTCTime` CER vectors. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: syntax normalization.
/// Example: positive and negative offsets normalize to UTC.
#[test]
fn allowed_lengths_and_offsets_normalize_to_seconds_z() {
    let limits = Limits::default();
    for (raw, canonical) in [
        (&b"5001010000Z"[..], &b"500101000000Z"[..]),
        (&b"9912312359Z"[..], &b"991231235900Z"[..]),
        (&b"4912312359Z"[..], &b"491231235900Z"[..]),
        (&b"991231235900Z"[..], &b"991231235900Z"[..]),
        (&b"9912312359+0000"[..], &b"991231235900Z"[..]),
        (&b"991231235900+0000"[..], &b"991231235900Z"[..]),
        (&b"240101120000+0230"[..], &b"240101093000Z"[..]),
        (&b"240101120000-0230"[..], &b"240101143000Z"[..]),
        (&b"0001010030+0100"[..], &b"991231233000Z"[..]),
        (&b"000229120000Z"[..], &b"000229120000Z"[..]),
    ] {
        check_time(raw, canonical, &limits);
    }
}

/// Require strict default BER time validation while retaining DER passthrough.
/// Parameters: none. Returns no value. Errors are assertion failures.
/// Source: C OCTET STRING BER adapter and CER parser. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: codec-specific validation.
/// Example: `junk` survives DER, fails strict BER, and passes tolerant BER.
#[test]
fn arbitrary_bytes_fail_strict_ber_and_cer() {
    let limits = Limits::default();
    for invalid in [
        &b"junk"[..],
        &b"991332000000Z"[..],
        &b"010229000000Z"[..],
        &b"991231246000Z"[..],
        &b"9912312359"[..],
        &b"991231235900+2460"[..],
    ] {
        let value = UtcValue::try_from_bytes(invalid, &limits).unwrap();
        let wire = primitive(invalid);
        assert_eq!(value.encode_der(&limits).unwrap().bytes, wire);
        assert!(value.encode_cer(&limits).is_err());
        assert!(UtcValue::decode_ber(&wire, &limits).is_err());
        let decoded = decode_utc_time_ber_tolerant(&wire, &limits).unwrap();
        assert_eq!(decoded.value.as_bytes(), invalid);
        assert!(UtcValue::decode_cer(&wire, &limits).is_err());
    }
}

/// Enforce pivot-window bounds after timezone conversion and accept epoch time.
/// Parameters: none. Returns no value. Errors are assertion failures.
/// Source: checked Gregorian UTC arithmetic and C `time_t` divergence.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: pivot and epoch edge cases. Example: 1969-12-31 23:59:59 is valid.
#[test]
fn pivot_crossings_and_c_time_t_sentinel_are_handled() {
    let limits = Limits::default();
    for outside in [
        &b"5001010000+0100"[..],
        &b"4912312359-0001"[..],
    ] {
        let value = UtcValue::try_from_bytes(outside, &limits).unwrap();
        assert!(value.encode_der(&limits).is_ok());
        assert!(value.encode_cer(&limits).is_err());
    }
    check_time(b"691231235959Z", b"691231235959Z", &limits);
}

/// Strictly accept constructed BER containing one complete valid time value.
/// Parameters: none. Returns no value. Errors are assertion failures.
/// Source: C OCTET STRING decoder probes. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: constructed `UTCTime` BER.
/// Example: nested fragments flatten without canonicalizing the text.
#[test]
fn constructed_ber_is_flattened_and_cer_rejects_it() {
    let limits = Limits::default();
    let canonical_time = b"991231235900Z";
    let definite = [
        0x37, 0x13, 0x04, 0x06, b'9', b'9', b'1', b'2', b'3', b'1',
        0x24, 0x09, 0x04, 0x07, b'2', b'3', b'5', b'9', b'0', b'0', b'Z',
    ];
    let indefinite = [
        0x37, 0x80, 0x04, 0x06, b'9', b'9', b'1', b'2', b'3', b'1',
        0x24, 0x80, 0x04, 0x07, b'2', b'3', b'5', b'9', b'0', b'0', b'Z',
        0, 0, 0, 0,
    ];
    let decoded = UtcValue::decode_ber(&definite, &limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), canonical_time);
    assert_eq!(decoded.consumed_bytes, definite.len());
    let decoded = UtcValue::decode_ber(&indefinite, &limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), canonical_time);
    assert_eq!(decoded.consumed_bytes, indefinite.len());
    assert!(UtcValue::decode_cer(&definite, &limits).is_err());
    assert!(UtcValue::decode_cer(&indefinite, &limits).is_err());

    // Keep valid time syntax here so strict CER rejection isolates constructed framing.
    let mut canonical_constructed = vec![0x37, 0x80, 0x04, 0x0d];
    canonical_constructed.extend_from_slice(canonical_time);
    canonical_constructed.extend_from_slice(&[0, 0]);
    let decoded = UtcValue::decode_ber(&canonical_constructed, &limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), canonical_time);
    assert_eq!(decoded.consumed_bytes, canonical_constructed.len());
    assert!(UtcValue::decode_cer(&canonical_constructed, &limits).is_err());

    let empty_constructed = [0x37, 0x80, 0, 0];
    assert!(UtcValue::decode_ber(&empty_constructed, &limits).is_err());
    let decoded = decode_utc_time_ber_tolerant(&empty_constructed, &limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), b"");
    assert_eq!(decoded.consumed_bytes, empty_constructed.len());
    assert!(UtcValue::decode_cer(&empty_constructed, &limits).is_err());
}

/// Check aliases, wrong fragment tags, malformed EOCs, truncation, and limits.
/// Parameters: none. Returns no value. Errors are assertion failures.
/// Source: BER parser robustness and C time probes. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: hostile `UTCTime` framing.
/// Example: BER accepts a high-tag alias when the enclosed date is valid.
#[test]
fn aliases_malformed_prefixes_and_resource_limits_are_checked() {
    let limits = Limits::default();
    let mut root_alias = vec![0x1f, 0x17, 0x0d];
    root_alias.extend_from_slice(b"991231235900Z");
    let decoded = UtcValue::decode_ber(&root_alias, &limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), b"991231235900Z");
    assert_eq!(decoded.consumed_bytes, root_alias.len());
    assert!(UtcValue::decode_cer(&root_alias, &limits).is_err());

    let child_alias = [0x37, 0x80, 0x1f, 0x04, 0x01, b'A', 0, 0];
    assert!(UtcValue::decode_ber(&child_alias, &limits).is_err());
    let decoded = decode_utc_time_ber_tolerant(&child_alias, &limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), b"A");
    assert!(UtcValue::decode_cer(&child_alias, &limits).is_err());
    let wrong_child = [0x37, 0x80, 0x1a, 0x01, b'A', 0, 0];
    assert!(UtcValue::decode_ber(&wrong_child, &limits).is_err());

    for malformed in [
        &[0x17, 0x80, 0, 0][..],
        &[0x37, 0x80, 0x04, 0x01, b'A', 0][..],
        &[0x37, 0x80, 0x04, 0x01, b'A', 0, 1][..],
        &[0x17, 0x82, 0, 1][..],
    ] {
        assert!(UtcValue::decode_ber(malformed, &limits).is_err());
        assert!(UtcValue::decode_cer(malformed, &limits).is_err());
    }
    let canonical = primitive(b"240101120000Z");
    for end in 0..canonical.len() {
        assert!(UtcValue::decode_ber(&canonical[..end], &limits).is_err());
        assert!(UtcValue::decode_cer(&canonical[..end], &limits).is_err());
    }
    let exact = Limits { max_input_bytes: 6, max_output_bytes: 6, ..limits };
    let raw = UtcValue::try_from_bytes(b"junk", &exact).unwrap();
    assert_eq!(raw.encode_der(&exact).unwrap().bytes, primitive(b"junk"));
    let no_input = Limits { max_input_bytes: 5, ..exact };
    let no_output = Limits { max_output_bytes: 5, ..exact };
    let no_work = Limits { max_work_bits: 0, ..exact };
    assert!(UtcValue::decode_ber(&primitive(b"junk"), &no_input).is_err());
    assert!(raw.encode_der(&no_output).is_err());
    assert!(UtcValue::try_from_bytes(b"A", &no_work).is_err());
}
