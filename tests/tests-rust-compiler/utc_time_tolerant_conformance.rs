//! Generated tests for the explicit tolerant BER `UTCTime` policy.

use asn1c_generated::utc_time_values::UtcValue;
use asn1c_runtime::{decode_utc_time_ber, Limits};

/// Preserve invalid date bytes through generated tolerant BER decoding.
/// Parameters: none. Returns no value. Errors are decode or assertion failures.
/// Source: pre-issue raw `UTCTime` BER behavior. Version/date: 2026-11-12.
/// Responsible party: asn1c maintainers. History: explicit Rust compatibility.
/// Example: `junk` decodes raw but fails strict BER and CER.
#[test]
fn generated_ber_option_selects_raw_compatibility_decoder() {
    let limits = Limits::default();
    for raw in [
        &b"junk"[..],
        &b"040231120000Z"[..],
        &b"0002310030+0100"[..],
    ] {
        let wire = {
            let mut bytes = vec![0x17, u8::try_from(raw.len()).unwrap()];
            bytes.extend_from_slice(raw);
            bytes
        };
        let decoded = UtcValue::decode_ber(&wire, &limits).unwrap();
        assert_eq!(decoded.value.as_bytes(), raw);
        assert_eq!(decoded.consumed_bytes, wire.len());
        assert!(decode_utc_time_ber(&wire, &limits).is_err());
        assert!(decoded.value.encode_cer(&limits).is_err());
    }
}

/// Keep tolerant BER raw preservation while leaving valid CER normalization intact.
/// Parameters: none. Returns no value. Errors are codec or assertion failures.
/// Source: approved `UTCTime` policy. Version/date: 2026-11-12.
/// Responsible party: asn1c maintainers. History: checks C and Rust parity.
/// Example: BER preserves `+0100`; CER renders UTC `Z` seconds.
#[test]
fn tolerant_ber_does_not_change_cer_or_der_policy() {
    let limits = Limits::default();
    let raw = b"0001010030+0100";
    let value = UtcValue::try_from_bytes(raw, &limits).unwrap();
    let der = value.encode_der(&limits).unwrap();
    assert_eq!(&der.bytes[2..], raw);

    let decoded = UtcValue::decode_ber(&der.bytes, &limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), raw);
    assert_eq!(
        value.encode_cer(&limits).unwrap().bytes,
        [0x17, 13, b'9', b'9', b'1', b'2', b'3', b'1',
         b'2', b'3', b'3', b'0', b'0', b'0', b'Z']
    );
}
