//! Generated BER/DER/CER tests for direct untagged `GeneralizedTime` values.

use asn1c_generated::generalized_time_values::GenValue;
use asn1c_runtime::Limits;

/// Append a shortest definite length for the bounded fixed vectors.
/// Parameters: `output` receives length octets; `length` is content size.
/// Returns no value. Errors are impossible for this fixture's short values.
/// Source: X.690 definite length form. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: `GeneralizedTime` vectors.
/// Example: content length fifteen appends `[15]`.
fn append_length(output: &mut Vec<u8>, length: usize) {
    assert!(length < 128);
    output.push(u8::try_from(length).unwrap());
}

/// Build one primitive universal tag-24 TLV from canonical or raw content.
/// Parameters: `content` is the exact text payload.
/// Returns the independent tag, length, and content bytes.
/// Source: X.690 universal tag 24. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: `GeneralizedTime` wire vectors.
/// Example: canonical seconds text begins with `18 0f`.
fn primitive(content: &[u8]) -> Vec<u8> {
    let mut output = vec![0x18];
    append_length(&mut output, content.len());
    output.extend_from_slice(content);
    output
}

/// Compare normalized DER/CER output and BER/CER decoding for one valid time.
/// Parameters: `raw` is explicitly zoned input; `canonical` is UTC output.
/// Returns no value. Errors are codec or assertion failures.
/// Source: C `GeneralizedTime` adapter and approved design. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: direct tag-24 support.
/// Example: a numeric zone normalizes to UTC seconds and `Z`.
fn check_time(raw: &[u8], canonical: &[u8], limits: &Limits) {
    let value = GenValue::try_from_bytes(raw, limits).unwrap();
    let canonical_wire = primitive(canonical);
    assert_eq!(value.as_bytes(), raw);
    assert_eq!(value.encode_der(limits).unwrap().bytes, canonical_wire);
    assert_eq!(value.encode_cer(limits).unwrap().bytes, canonical_wire);

    let mut raw_wire = primitive(raw);
    raw_wire.push(0xff);
    let decoded = GenValue::decode_ber(&raw_wire, limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), raw);
    assert_eq!(decoded.consumed_bytes, raw_wire.len() - 1);
    assert_eq!(decoded.consumed_bits, decoded.consumed_bytes * 8);

    let mut cer_prefix = canonical_wire.clone();
    cer_prefix.push(0xff);
    let decoded = GenValue::decode_cer(&cer_prefix, limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), canonical);
    assert_eq!(decoded.consumed_bytes, canonical_wire.len());
    assert_eq!(decoded.consumed_bits, decoded.consumed_bytes * 8);
    if raw != canonical {
        assert!(GenValue::decode_cer(&primitive(raw), limits).is_err());
    }
}

/// Cover optional clock pairs, both zone widths/signs, and fraction trimming.
/// Parameters: none. Returns no value. Errors are codec or assertion failures.
/// Source: existing C CER `GeneralizedTime` vectors. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: normalized vector coverage.
/// Example: a comma fraction trims trailing zeros and becomes a period.
#[test]
fn valid_zoned_forms_normalize_to_canonical_utc() {
    let limits = Limits::default();
    for (raw, canonical) in [
        (&b"2026010112Z"[..], &b"20260101120000Z"[..]),
        (&b"202601011200Z"[..], &b"20260101120000Z"[..]),
        (&b"20260101120000Z"[..], &b"20260101120000Z"[..]),
        (&b"20260101120000.123456789Z"[..], &b"20260101120000.123456789Z"[..]),
        (&b"20260101120000,123450000Z"[..], &b"20260101120000.12345Z"[..]),
        (&b"20260101120000.000Z"[..], &b"20260101120000Z"[..]),
        (&b"20260101140000+0200"[..], &b"20260101120000Z"[..]),
        (&b"20260101140000+02"[..], &b"20260101120000Z"[..]),
        (&b"20260101100000-0200"[..], &b"20260101120000Z"[..]),
        (&b"20260101100000-02"[..], &b"20260101120000Z"[..]),
        (&b"20000229000000Z"[..], &b"20000229000000Z"[..]),
        (&b"00010101000000Z"[..], &b"00010101000000Z"[..]),
        (&b"99991231235959Z"[..], &b"99991231235959Z"[..]),
    ] {
        check_time(raw, canonical, &limits);
    }
}

/// Reject source forms outside the bounded explicit-zone normalization subset.
/// Parameters: none. Returns no value. Errors are assertion failures.
/// Source: approved `GeneralizedTime` contract. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: invalid text checks.
/// Example: a fractional minute remains BER data but cannot be encoded.
#[test]
fn invalid_text_remains_ber_data_but_cannot_be_encoded() {
    let limits = Limits::default();
    for invalid in [
        &b""[..],
        &b"junk"[..],
        &b"00000101000000Z"[..],
        &b"20260230120000Z"[..],
        &b"20260101240000Z"[..],
        &b"20260101126000Z"[..],
        &b"20260101120060Z"[..],
        &b"20260101120000"[..],
        &b"20260101120000+2460"[..],
        &b"20260101120000.1234567890Z"[..],
        &b"2026010112.5Z"[..],
        &b"202601011230.5Z"[..],
        &b"20260101120000.Z"[..],
    ] {
        let value = GenValue::try_from_bytes(invalid, &limits).unwrap();
        let wire = primitive(invalid);
        let decoded = GenValue::decode_ber(&wire, &limits).unwrap();
        assert_eq!(decoded.value.as_bytes(), invalid);
        assert_eq!(decoded.consumed_bytes, wire.len());
        assert!(value.encode_der(&limits).is_err());
        assert!(value.encode_cer(&limits).is_err());
        assert!(GenValue::decode_cer(&wire, &limits).is_err());
    }
}

/// Record year-window conversion and the C `time_t == -1` divergence.
/// Parameters: none. Returns no value. Errors are assertion failures.
/// Source: checked Gregorian arithmetic and approved C divergence.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: year edges and epoch. Example: year 0001 remains representable.
#[test]
fn year_edges_offsets_and_epoch_use_checked_calendar_arithmetic() {
    let limits = Limits::default();
    for outside in [
        &b"00010101000000+0100"[..],
        &b"99991231235959-0001"[..],
    ] {
        let value = GenValue::try_from_bytes(outside, &limits).unwrap();
        assert!(value.encode_der(&limits).is_err());
        assert!(value.encode_cer(&limits).is_err());
    }
    check_time(b"19691231235959Z", b"19691231235959Z", &limits);
}

/// Accept constructed BER and root tag aliases only in the BER decoder.
/// Parameters: none. Returns no value. Errors are assertion failures.
/// Source: C OCTET STRING BER adapter and strict CER re-encoding.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: canonical-content framing aliases. Example: constructed fragments flatten.
#[test]
fn constructed_and_aliased_framing_preserves_valid_content() {
    let limits = Limits::default();
    let canonical = b"20260101120000Z";
    let mut constructed = vec![0x38, 0x80, 0x04, 0x08];
    constructed.extend_from_slice(&canonical[..8]);
    constructed.extend_from_slice(&[0x04, 0x07]);
    constructed.extend_from_slice(&canonical[8..]);
    constructed.extend_from_slice(&[0, 0]);
    let decoded = GenValue::decode_ber(&constructed, &limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), canonical);
    assert_eq!(decoded.consumed_bytes, constructed.len());
    assert!(GenValue::decode_cer(&constructed, &limits).is_err());

    let mut alias = vec![0x1f, 0x18, 0x0f];
    alias.extend_from_slice(canonical);
    let decoded = GenValue::decode_ber(&alias, &limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), canonical);
    assert_eq!(decoded.consumed_bytes, alias.len());
    assert!(GenValue::decode_cer(&alias, &limits).is_err());

    let wrong_child = [0x38, 0x80, 0x1a, 0x01, b'A', 0, 0];
    assert!(GenValue::decode_ber(&wrong_child, &limits).is_err());
    for malformed in [
        &[0x18, 0x80, 0, 0][..],
        &[0x38, 0x80, 0x04, 0x01, b'A', 0][..],
        &[0x38, 0x80, 0x04, 0x01, b'A', 0, 1][..],
    ] {
        assert!(GenValue::decode_ber(malformed, &limits).is_err());
        assert!(GenValue::decode_cer(malformed, &limits).is_err());
    }
}

/// Enforce prefix truncation, exact resource budgets, and raw BER limits.
/// Parameters: none. Returns no value. Errors are assertion failures.
/// Source: runtime operation-limit contract. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: limit and prefix checks.
/// Example: an exact encoded length succeeds and one octet less fails.
#[test]
fn truncation_prefix_and_resource_limits_are_checked() {
    let limits = Limits::default();
    let raw = b"2026010112Z";
    let canonical = b"20260101120000Z";
    let canonical_wire = primitive(canonical);
    for end in 0..canonical_wire.len() {
        assert!(GenValue::decode_ber(&canonical_wire[..end], &limits).is_err());
        assert!(GenValue::decode_cer(&canonical_wire[..end], &limits).is_err());
    }
    let exact = Limits {
        max_input_bytes: canonical_wire.len(),
        max_output_bytes: canonical_wire.len(),
        ..limits
    };
    let value = GenValue::try_from_bytes(raw, &exact).unwrap();
    assert_eq!(value.encode_der(&exact).unwrap().bytes, canonical_wire);
    let exact_decode = GenValue::decode_cer(&canonical_wire, &exact).unwrap();
    assert_eq!(exact_decode.consumed_bytes, canonical_wire.len());
    let mut prefix = canonical_wire.clone();
    prefix.push(0xff);
    let decoded = GenValue::decode_cer(&prefix, &limits).unwrap();
    assert_eq!(decoded.consumed_bytes, canonical_wire.len());
    let no_input = Limits { max_input_bytes: canonical_wire.len() - 1, ..exact };
    let no_output = Limits { max_output_bytes: canonical_wire.len() - 1, ..exact };
    let no_work = Limits { max_work_bits: 0, ..exact };
    assert!(GenValue::decode_ber(&canonical_wire, &no_input).is_err());
    assert!(value.encode_der(&no_output).is_err());
    assert!(GenValue::try_from_bytes(raw, &no_work).is_err());
}
