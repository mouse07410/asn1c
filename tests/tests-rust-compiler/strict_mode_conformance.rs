//! Strict-mode supported-codec checks; generated via check-rust-strict-mode.sh.
use asn1c_generated::strict_scalar::{Wide, N};
use asn1c_runtime::{Error, Limits};

/// Exercise schema bounds in every supported scalar format.
/// Source: strict-mode policy; version/date: 2026-11-17; owner: asn1c maintainers.
/// Inputs: none. Returns a codec error on unexpected failure; assertions panic
/// on acceptance of malformed data. History: strict flag regression.
/// Example: `cargo test --test strict_mode_conformance`.
#[test]
fn scalar_formats() -> Result<(), Error> {
    let limits = Limits::default();
    let value = N::new(2)?;
    let outside = Wide::new(3)?;
    assert!(N::new(-1).is_err());
    assert!(N::new(3).is_err());

    // The same encoded 3 fits Wide and must be rejected by N in every format.
    macro_rules! check_codec {
        ($encode:ident, $decode:ident) => {{
            let encoded = value.$encode(&limits)?;
            assert_eq!(N::$decode(&encoded.bytes, &limits)?.value.value(), 2);
            assert!(N::$decode(&[], &limits).is_err());
            let invalid = outside.$encode(&limits)?;
            assert!(N::$decode(&invalid.bytes, &limits).is_err());
        }};
    }
    check_codec!(encode_uper, decode_uper);
    check_codec!(encode_aper, decode_aper);
    check_codec!(encode_oer, decode_oer);
    check_codec!(encode_der, decode_ber);
    check_codec!(encode_cer, decode_cer);
    check_codec!(encode_jer, decode_jer);
    check_codec!(encode_cbor, decode_cbor);
    Ok(())
}

/// Mutate short inputs without allowing panics or out-of-range successful values.
/// Source: bounded hostile-input regression; date: 2026-11-17; owner: asn1c.
/// Inputs/returns: none. Exceptions: assertions. History: strict mutation coverage.
/// Example: all 256 first-octet mutations reach the seven scalar decoders.
#[test]
fn malformed_inputs() {
    let limits = Limits::default();
    for byte in 0..=u8::MAX {
        let input = [byte, 1, 3];
        let results = [
            N::decode_uper(&input, &limits),
            N::decode_aper(&input, &limits),
            N::decode_oer(&input, &limits),
            N::decode_ber(&input, &limits),
            N::decode_cer(&input, &limits),
            N::decode_jer(&input, &limits),
            N::decode_cbor(&input, &limits),
        ];
        for result in results.into_iter().flatten() {
            assert!((0..=2).contains(&result.value.value()));
        }
    }
}

/// Check that the generator's policy reaches its vendored string runtime.
/// Source: X.680 `UTF8String` repertoire; date: 2026-11-17; owner: asn1c.
/// Inputs/returns: none. Exceptions: assertions. History: feature propagation.
/// Example: strict BER rejects a UTF-8 encoded surrogate; default preserves it.
#[test]
fn runtime_policy_propagates() {
    use asn1c_runtime::ber::{
        decode_character_string_ber, encode_character_string_der, CharacterString,
        CharacterStringKind,
    };
    let limits = Limits::default();
    let kind = CharacterStringKind::Utf8String;
    let bytes = [0xed, 0xa0, 0x80];
    let value = CharacterString::try_from_bytes(kind, &bytes, &limits).unwrap();
    assert_eq!(
        encode_character_string_der(&value, &limits).is_err(),
        asn1c_runtime::STRICT_MODE
    );
    assert_eq!(
        decode_character_string_ber(&[12, 3, 0xed, 0xa0, 0x80], kind, &limits).is_err(),
        asn1c_runtime::STRICT_MODE
    );
}
