//! BER, DER, and CER tests for a SET containing one inline SEQUENCE child.

use asn1c_generated::nested_set_records::{T, TChild};
use asn1c_runtime::Limits;

/// Check canonical SET order and nested EXPLICIT child vectors from C.
///
/// Parameters: none. Returns: no value; assertions compare exact bytes.
/// Errors: generated codecs return errors for malformed data or resource limits.
/// Source: generated C BER/CER vectors and X.690 SET order.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: inline child codec stage. Example: context tags 0, 1, then 3.
#[test]
fn set_child_encoding_and_decoding_match_c_vectors() {
    let limits = Limits::default();
    let value = T {
        before: 1,
        child: TChild { x: 2 },
        after: true,
    };
    let definite_vector = [
        0x31, 0x0d, 0x80, 1, 1, 0x81, 1, 0xff, 0xa3, 5, 0x30, 3, 0x02, 1, 2,
    ];
    let canonical_vector = [
        0x31, 0x80, 0x80, 1, 1, 0x81, 1, 0xff, 0xa3, 0x80, 0x30, 0x80, 0x02, 1, 2, 0, 0, 0, 0,
        0, 0,
    ];
    assert_eq!(value.encode_der(&limits).unwrap().bytes, definite_vector);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, canonical_vector);
    assert_eq!(T::decode_ber(&definite_vector, &limits).unwrap().value, value);
    assert_eq!(T::decode_cer(&canonical_vector, &limits).unwrap().value, value);
    let reordered = [
        0x31, 0x80, 0xa3, 0x80, 0x30, 0x80, 0x02, 1, 2, 0, 0, 0, 0,
        0x80, 1, 1, 0x81, 1, 0xff, 0, 0,
    ];
    assert_eq!(T::decode_ber(&reordered, &limits).unwrap().value, value);
    assert!(T::decode_cer(&reordered, &limits).is_err());
}
