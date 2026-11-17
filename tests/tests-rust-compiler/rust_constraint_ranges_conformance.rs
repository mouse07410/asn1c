//! Boundary conformance for generated full-range and narrow INTEGER types.
//!
//! The schema is emitted with UPER and APER enabled and CER disabled so this
//! test checks codec methods produced by a normal Rust crate generation run.

use asn1c_generated::signed64_boundaries::{All, Positive, Small};
use asn1c_runtime::Limits;

/// Round-trip signed i64 extrema and their representable neighbours.
///
/// # Parameters and returns
/// No parameters or return value. Exercises the generated full-range INTEGER.
///
/// # Errors and panics
/// Panics if construction, encoding, decoding, or the decoded value differs.
///
/// # Source, history, and example
/// Original source: ASN.1 full signed64 range with generated PER codecs.
/// Version/date: 1, 2026-11-16. Responsible party: asn1c maintainers.
/// History: covers valid signed limits and adjacent interior values.
/// Example: `i64::MIN` and `i64::MAX` each round-trip through UPER and APER.
#[test]
fn signed64_extrema_and_neighbours_round_trip() {
    let limits = Limits::default();
    let candidates = [i64::MIN, i64::MIN + 1, i64::MAX - 1, i64::MAX];

    for candidate in candidates {
        let value = All::new(candidate).expect("every i64 value is in the schema range");

        let uper = value.encode_uper(&limits).expect("UPER encoding succeeds");
        let uper_decoded = All::decode_uper(&uper.bytes, &limits).expect("UPER decoding succeeds");
        assert_eq!(uper_decoded.value.value(), candidate);
        assert_eq!(uper_decoded.consumed_bits, uper.bit_len);

        let aper = value.encode_aper(&limits).expect("APER encoding succeeds");
        let aper_decoded = All::decode_aper(&aper.bytes, &limits).expect("APER decoding succeeds");
        assert_eq!(aper_decoded.value.value(), candidate);
        assert_eq!(aper_decoded.consumed_bits, aper.bit_len);
    }
}

/// Check the positive i64 range and its 63-bit UPER width.
///
/// # Parameters and returns
/// No parameters or return value. Exercises the generated positive INTEGER.
///
/// # Errors and panics
/// Panics if bounds, width, or PER round trips differ from the schema.
///
/// # Source, history, and example
/// Original source: ASN.1 INTEGER (0..9223372036854775807).
/// Version/date: 1, 2026-11-17. Responsible party: asn1c maintainers.
/// History: covers the positive power-of-two cardinality boundary.
/// Example: `Positive::new(i64::MAX)` uses 63 UPER bits.
#[test]
fn positive_i64_boundary_round_trip() {
    let limits = Limits::default();
    assert!(Positive::new(-1).is_err());
    for candidate in [0, 1, i64::MAX - 1, i64::MAX] {
        let value = Positive::new(candidate).expect("value fits the schema");
        let uper = value.encode_uper(&limits).expect("UPER encoding succeeds");
        assert_eq!(uper.bit_len, 63);
        let decoded = Positive::decode_uper(&uper.bytes, &limits).expect("UPER decoding succeeds");
        assert_eq!(decoded.value.value(), candidate);

        let aper = value.encode_aper(&limits).expect("APER encoding succeeds");
        let decoded = Positive::decode_aper(&aper.bytes, &limits).expect("APER decoding succeeds");
        assert_eq!(decoded.value.value(), candidate);
    }
}

/// Check narrow INTEGER endpoints and reject adjacent out-of-range values.
///
/// # Parameters and returns
/// No parameters or return value. Exercises the generated narrow INTEGER.
///
/// # Errors and panics
/// Panics if an endpoint is rejected, an outside value is accepted, or a PER
/// round-trip changes the value.
///
/// # Source, history, and example
/// Original source: ASN.1 INTEGER (-2..2) with generated PER codecs.
/// Version/date: 1, 2026-11-16. Responsible party: asn1c maintainers.
/// History: ensures constructor validation remains inclusive and bounded.
/// Example: `Small::new(-3)` fails while `Small::new(-2)` succeeds.
#[test]
fn narrow_integer_rejects_adjacent_out_of_range_values() {
    let limits = Limits::default();
    assert!(Small::new(-3).is_err());
    assert!(Small::new(3).is_err());
    assert!(Small::decode_uper(&[], &limits).is_err());
    assert!(Small::decode_aper(&[], &limits).is_err());
    assert!(Small::decode_uper(&[0xa0], &limits).is_err());
    assert!(Small::decode_aper(&[0xa0], &limits).is_err());

    for candidate in -2..=2 {
        let value = Small::new(candidate).expect("inclusive schema endpoint is valid");

        let uper = value.encode_uper(&limits).expect("UPER encoding succeeds");
        let uper_decoded =
            Small::decode_uper(&uper.bytes, &limits).expect("UPER decoding succeeds");
        assert_eq!(uper_decoded.value.value(), candidate);

        let aper = value.encode_aper(&limits).expect("APER encoding succeeds");
        let aper_decoded =
            Small::decode_aper(&aper.bytes, &limits).expect("APER decoding succeeds");
        assert_eq!(aper_decoded.value.value(), candidate);
    }
}
