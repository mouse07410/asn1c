//! BER, DER, and CER tests for an empty inline SEQUENCE child.

use asn1c_generated::nested_empty_records::{Empty, EmptyChild};
use asn1c_runtime::Limits;

/// Encode and decode a required empty inline child SEQUENCE.
///
/// Parameters: none. Returns: no value; assertions compare exact C vectors.
/// Errors: generated codecs reject malformed framing or resource exhaustion.
/// Source: generated C nested-record vectors. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: empty child coverage.
/// Example: an empty child is still a complete constructed SEQUENCE value.
#[test]
fn empty_inline_child_matches_c_vectors() {
    let limits = Limits::default();
    let value = Empty { child: EmptyChild {} };
    let definite = [0x30, 0x02, 0x30, 0x00];
    let canonical = [0x30, 0x80, 0x30, 0x80, 0, 0, 0, 0];
    assert_eq!(value.encode_der(&limits).unwrap().bytes, definite);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, canonical);
    assert_eq!(Empty::decode_ber(&definite, &limits).unwrap().value, value);
    assert_eq!(Empty::decode_cer(&canonical, &limits).unwrap().value, value);
    let zero_work = Limits {
        max_work_bits: 0,
        ..Limits::default()
    };
    assert!(value.encode_der(&zero_work).is_err());
    assert!(Empty::decode_ber(&definite, &zero_work).is_err());
}
