//! Generated ENUMERATED JER conformance and strict-decoding tests.

use asn1c_generated::enum_slice::{Color, Keyword, Only, Three};
use asn1c_runtime::{Encoded, Error, Limits, Resource};

/// Compare a generated enum token with its compact JSON string spelling.
///
/// # Parameters
/// actual is the generated token; expected is the fixed JSON string.
///
/// # Returns
/// No value; mismatches panic and fail the calling test.
///
/// # Errors and panics
/// Panics if bytes or complete-octet bit length differ.
///
/// # Source, version, history, and example
/// Original source: the C ENUMERATED JER skeleton mapping.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// initial generated enum JER tests. Example: compare one token spelling.
fn assert_token(actual: &Encoded, expected: &str) {
    assert_eq!(actual.bytes, expected.as_bytes());
    assert_eq!(actual.bit_len, expected.len() * 8);
}

/// Verify enum names map to strings in declaration order and round-trip.
///
/// # Parameters and returns
/// No parameters or return value; checks generated encode and decode methods.
///
/// # Errors and panics
/// Panics if generated tokens, values, or complete-input consumption differ.
///
/// # Source, version, history, and example
/// Original source: ASN.1 JER ENUMERATED string mapping and EnumSlice.asn1.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// added opt-in generated enum JER coverage. Example: map one color variant to its ASN.1 name.
#[test]
fn names_encode_and_decode_as_json_strings() {
    let limits = Limits::default();
    for (value, expected) in [
        (Color::Blue, "\"blue\""),
        (Color::Red, "\"red\""),
        (Color::Green, "\"green\""),
    ] {
        let encoded = value.encode_jer(&limits).unwrap();
        assert_token(&encoded, expected);
        let decoded = Color::decode_jer(expected.as_bytes(), &limits).unwrap();
        assert_eq!(decoded.value, value);
        assert_eq!(decoded.consumed_bits, expected.len() * 8);
    }

    let singleton = Only::Sole.encode_jer(&limits).unwrap();
    assert_token(&singleton, "\"sole\"");
    assert_eq!(
        Only::decode_jer(b"\"sole\"", &limits).unwrap().value,
        Only::Sole
    );
    let signed_named = Three::First.encode_jer(&limits).unwrap();
    assert_token(&signed_named, "\"first\"");
    assert_eq!(
        Three::decode_jer(b"\"third\"", &limits).unwrap().value,
        Three::Third
    );
    let keyword = Keyword::Asn1Self.encode_jer(&limits).unwrap();
    assert_token(&keyword, "\"sELF\"");
    assert_eq!(
        Keyword::decode_jer(b"\"sELF\"", &limits).unwrap().value,
        Keyword::Asn1Self
    );
}

/// Reject malformed, unknown, and trailing data around enum JSON strings.
///
/// # Parameters and returns
/// No parameters or return value; invokes every generated strict decoder.
///
/// # Errors and panics
/// Panics if a malformed token or an exhausted resource limit is accepted.
///
/// # Source, version, history, and example
/// Original source: complete-input JER contract in the Rust runtime.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// added opt-in generated enum JER coverage. Example: "\"red\"x" is rejected.
#[test]
fn strict_complete_input_and_resource_limits() {
    let limits = Limits::default();
    for token in [
        b"".as_slice(),
        b"red",
        b"\"unknown\"",
        b"\"red\"x",
        b"\"red\" \"blue\"",
        b"\"r\\u0065d\"",
        b"\"red",
        b"red\"",
    ] {
        assert!(
            Color::decode_jer(token, &limits).is_err(),
            "accepted {token:?}"
        );
    }
    let padded = b" \n\"red\"\t";
    let decoded = Color::decode_jer(padded, &limits).unwrap();
    assert_eq!(decoded.value, Color::Red);
    assert_eq!(decoded.consumed_bytes, padded.len());
    assert_eq!(decoded.consumed_bits, padded.len() * 8);

    let input_limit = Limits {
        max_input_bytes: 4,
        ..limits
    };
    assert!(matches!(
        Color::decode_jer(b"\"red\"", &input_limit),
        Err(Error::LimitExceeded {
            resource: Resource::InputBytes,
            ..
        })
    ));
    let work_limit = Limits {
        max_work_bits: 1,
        ..limits
    };
    assert!(matches!(
        Color::decode_jer(b"\"red\"", &work_limit),
        Err(Error::LimitExceeded {
            resource: Resource::WorkBits,
            ..
        })
    ));
    let output_limit = Limits {
        max_output_bytes: 4,
        ..limits
    };
    assert!(matches!(
        Color::Red.encode_jer(&output_limit),
        Err(Error::LimitExceeded {
            resource: Resource::OutputBytes,
            ..
        })
    ));
    let encode_work_limit = Limits {
        max_work_bits: 39,
        ..limits
    };
    assert!(matches!(
        Color::Red.encode_jer(&encode_work_limit),
        Err(Error::LimitExceeded {
            resource: Resource::WorkBits,
            ..
        })
    ));
}
