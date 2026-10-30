//! Generated primitive JER tests for canonical JSON tokens and bounded decode.

use asn1c_generated::first_slice::{Count, Empty, Flag, SignBounds, Singleton};
use asn1c_runtime::{Encoded, Error, Limits, Resource};
use std::path::Path;

/// Compare a generated JER token with its independent compact JSON spelling.
///
/// # Parameters
/// `actual` is the generated output, `expected` is the fixed UTF-8 token, and
/// `case` labels an assertion failure.
///
/// # Returns
/// No value; mismatches panic and fail the calling test.
///
/// # Errors and panics
/// Panics if bytes or the complete-octet bit count differ.
///
/// # Source, history, and example
/// Original source: independent ASN.1 JER primitive vectors. Version/date:
/// 2026-10-30. Responsible party: asn1c maintainers. History: initial JER
/// primitive tests. Example: `assert_token(&encoded, "true", "BOOLEAN TRUE").`
fn assert_token(actual: &Encoded, expected: &str, case: &str) {
    assert_eq!(actual.bytes, expected.as_bytes(), "{case} token");
    assert_eq!(actual.bit_len, expected.len() * 8, "{case} bit count");
}

/// Optionally save a token so the separately compiled C decoder can consume it.
///
/// # Parameters
/// `filename` is one stable `jer_*.json` fixture name; `bytes` is Rust output.
///
/// # Returns
/// No value. When `ASN1C_RUST_JER_VECTORS` is set, writes the token there.
///
/// # Errors and panics
/// Panics if the configured directory cannot be created or the file cannot be
/// written; an unset directory simply disables cross-language fixture output.
///
/// # Source, history, and example
/// Original source: generated Rust and C JER comparison fixture. Version/date:
/// 2026-10-30. Responsible party: asn1c maintainers. History: initial JER
/// interop vectors. Example: `save_rust_token("jer_flag_true.json", b"true").`
fn save_rust_token(filename: &str, bytes: &[u8]) {
    let Some(directory) = std::env::var_os("ASN1C_RUST_JER_VECTORS") else {
        return;
    };
    let path = Path::new(&directory).join(filename);
    std::fs::create_dir_all(&directory).unwrap_or_else(|error| {
        panic!("cannot create {}: {error}", Path::new(&directory).display())
    });
    std::fs::write(&path, bytes)
        .unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
}

/// Check BOOLEAN and NULL encodings and accepted surrounding JSON whitespace.
///
/// # Parameters and returns
/// No parameters or return value; verifies the generated primitive API.
///
/// # Errors and panics
/// Panics if compact tokens, decoded values, or complete-input consumption
/// differ from the JER contract.
///
/// # Source, history, and example
/// Original source: ITU-T X.697 JER primitive mappings and RFC 8259 JSON syntax.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// first primitive JER vectors. Example: ASN.1 BOOLEAN TRUE encodes as `true`.
#[test]
fn boolean_and_null_tokens() {
    let limits = Limits::default();
    for (value, expected, filename) in [
        (false, "false", "jer_flag_false.json"),
        (true, "true", "jer_flag_true.json"),
    ] {
        let encoded = Flag::new(value).encode_jer(&limits).unwrap();
        assert_token(&encoded, expected, "BOOLEAN");
        save_rust_token(filename, &encoded.bytes);

        let padded = format!(" \n\t{expected} \r\n");
        let decoded = Flag::decode_jer(padded.as_bytes(), &limits).unwrap();
        assert_eq!(decoded.value.value(), value);
        assert_eq!(decoded.consumed_bytes, padded.len());
    }

    let encoded = Empty.encode_jer(&limits).unwrap();
    assert_token(&encoded, "null", "NULL");
    save_rust_token("jer_empty.json", &encoded.bytes);
    let decoded = Empty::decode_jer(b"\t null \n", &limits).unwrap();
    assert_eq!(decoded.value, Empty);
    assert_eq!(decoded.consumed_bytes, 8);
}

/// Check constrained integer decimal formatting, including signed boundaries.
///
/// # Parameters and returns
/// No parameters or return value; verifies exact JER tokens and typed values.
///
/// # Errors and panics
/// Panics if a value encodes with nonminimal decimal text or fails to decode.
///
/// # Source, history, and example
/// Original source: independent JSON integer vectors and ASN.1 constraints.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// initial JER integer coverage. Example: `-129` encodes without extra zeros.
#[test]
fn constrained_integer_tokens() {
    let limits = Limits::default();
    for (value, expected, filename) in [
        (-10, "-10", "jer_count_min.json"),
        (-1, "-1", ""),
        (0, "0", ""),
        (1, "1", ""),
        (10, "10", "jer_count_max.json"),
    ] {
        let value = Count::new(value).unwrap();
        let encoded = value.encode_jer(&limits).unwrap();
        assert_token(&encoded, expected, "Count");
        if !filename.is_empty() {
            save_rust_token(filename, &encoded.bytes);
        }
        let decoded = Count::decode_jer(expected.as_bytes(), &limits).unwrap();
        assert_eq!(decoded.value.value(), value.value());
    }

    for (value, expected, filename) in [
        (-129, "-129", "jer_sign_bounds_min.json"),
        (-128, "-128", ""),
        (-1, "-1", ""),
        (0, "0", ""),
        (127, "127", ""),
        (128, "128", "jer_sign_bounds_max.json"),
    ] {
        let value = SignBounds::new(value).unwrap();
        let encoded = value.encode_jer(&limits).unwrap();
        assert_token(&encoded, expected, "SignBounds");
        if !filename.is_empty() {
            save_rust_token(filename, &encoded.bytes);
        }
        let decoded = SignBounds::decode_jer(expected.as_bytes(), &limits).unwrap();
        assert_eq!(decoded.value.value(), value.value());
    }

    let singleton = Singleton::new(5).unwrap();
    let encoded = singleton.encode_jer(&limits).unwrap();
    assert_token(&encoded, "5", "Singleton");
    save_rust_token("jer_singleton.json", &encoded.bytes);
    assert_eq!(
        Singleton::decode_jer(b"5", &limits).unwrap().value.value(),
        5
    );
}

/// Reject malformed, noncanonical, out-of-range, and overflowing JSON values.
///
/// # Parameters and returns
/// No parameters or return value; invokes each generated full-input decoder.
///
/// # Errors and panics
/// Panics if any invalid token is accepted. JSON whitespace around a complete
/// token remains accepted by the valid-token checks in the other test.
///
/// # Source, history, and example
/// Original source: JSON number grammar and ASN.1 JER range constraints.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// malformed-token regression coverage. Example: `01` is not a JSON number.
#[test]
fn invalid_and_out_of_range_tokens_are_rejected() {
    let limits = Limits::default();
    for token in [b"TRUE".as_slice(), b"truex", b"0", b"", b"true false"] {
        assert!(
            Flag::decode_jer(token, &limits).is_err(),
            "accepted {token:?}"
        );
    }
    for token in [b"nullx".as_slice(), b"{}", b"null null", b""] {
        assert!(
            Empty::decode_jer(token, &limits).is_err(),
            "accepted {token:?}"
        );
    }
    for token in [
        b"".as_slice(),
        b"+1",
        b"01",
        b"-01",
        b"--1",
        b"-",
        b"1.0",
        b"1e0",
        b"11",
        b"-11",
        b"9223372036854775808",
        b"-9223372036854775809",
        b"1 2",
    ] {
        assert!(
            Count::decode_jer(token, &limits).is_err(),
            "accepted {token:?}"
        );
    }
    for token in [b"-130".as_slice(), b"129", b"1.0", b"1e0"] {
        assert!(
            SignBounds::decode_jer(token, &limits).is_err(),
            "accepted {token:?}"
        );
    }
    for token in [b"4".as_slice(), b"6", b"5 5"] {
        assert!(
            Singleton::decode_jer(token, &limits).is_err(),
            "accepted {token:?}"
        );
    }
}

/// Enforce input, output, and work ceilings for JER primitive operations.
///
/// # Parameters and returns
/// No parameters or return value; checks typed failures at exact token bounds.
///
/// # Errors and panics
/// Panics if any too-small resource ceiling is ignored or an exact ceiling
/// rejects the four-byte BOOLEAN token.
///
/// # Source, history, and example
/// Original source: runtime `Limits` contract and compact JER token size.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// initial resource-bound coverage. Example: `max_output_bytes = 3` rejects `true`.
#[test]
fn primitive_resource_limits_are_enforced() {
    let defaults = Limits::default();
    let too_few_output = Limits {
        max_output_bytes: 3,
        ..defaults
    };
    assert!(matches!(
        Flag::new(true).encode_jer(&too_few_output),
        Err(Error::LimitExceeded {
            resource: Resource::OutputBytes,
            ..
        })
    ));

    let too_little_encode_work = Limits {
        max_work_bits: 31,
        ..defaults
    };
    assert!(matches!(
        Flag::new(true).encode_jer(&too_little_encode_work),
        Err(Error::LimitExceeded {
            resource: Resource::WorkBits,
            ..
        })
    ));

    let too_few_input = Limits {
        max_input_bytes: 3,
        ..defaults
    };
    assert!(matches!(
        Flag::decode_jer(b"true", &too_few_input),
        Err(Error::LimitExceeded {
            resource: Resource::InputBytes,
            ..
        })
    ));

    let too_little_decode_work = Limits {
        max_work_bits: 31,
        ..defaults
    };
    assert!(matches!(
        Flag::decode_jer(b"true", &too_little_decode_work),
        Err(Error::LimitExceeded {
            resource: Resource::WorkBits,
            ..
        })
    ));

    let exact = Limits {
        max_input_bytes: 4,
        max_output_bytes: 4,
        max_work_bits: 32,
    };
    assert_token(
        &Flag::new(true).encode_jer(&exact).unwrap(),
        "true",
        "exact resource ceiling",
    );
    assert!(Flag::decode_jer(b"true", &exact).unwrap().value.value());
}
