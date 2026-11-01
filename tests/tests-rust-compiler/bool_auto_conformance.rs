//! Cross-codec BOOLEAN packing preserves interleaved scalar and presence order.

use asn1c_generated::bool_auto::Flags;
use asn1c_runtime::Limits;

/// Exhaust the four-bit values, optional states, and integer DEFAULT branches.
/// Inputs: none. Returns: none. Errors: any differing decoded value fails.
/// Source: `BoolAuto` schema. Version/date: 2026-11-01; asn1c maintainers.
/// History: private bitset qualification. Example: cargo test.
#[test]
fn packed_fields_preserve_order_in_all_selected_codecs() {
    let limits = Limits::default();
    // Pattern is a state variable covering every packed bit combination.
    for pattern in 0_u8..16 {
        let flags = std::array::from_fn(|index| pattern & (1 << index) != 0);
        for maybe in [None, Some(false), Some(true)] {
            for count in [2, 4] {
                let mut value = Flags::new(flags, (count, maybe));
                assert_eq!(value.get_first(), flags[0]);
                assert_eq!(value.get_asn1_type(), flags[1]);
                assert_eq!(value.get_third(), flags[2]);
                assert_eq!(value.get_fourth(), flags[3]);
                assert_eq!(value.get_maybe(), maybe);
                value.set_first(!flags[0]);
                value.set_first(flags[0]);
                value.set_asn1_type(!flags[1]);
                value.set_asn1_type(flags[1]);
                value.set_third(!flags[2]);
                value.set_third(flags[2]);
                value.set_fourth(!flags[3]);
                value.set_fourth(flags[3]);
                value.set_maybe(None);
                value.set_maybe(maybe);
                let der = value.encode_der(&limits).unwrap();
                let cer = value.encode_cer(&limits).unwrap();
                let cbor = value.encode_cbor(&limits).unwrap();
                let uper = value.encode_uper(&limits).unwrap();
                assert_eq!(Flags::decode_ber(&der.bytes, &limits).unwrap().value, value);
                assert_eq!(Flags::decode_cer(&cer.bytes, &limits).unwrap().value, value);
                assert_eq!(
                    Flags::decode_cbor(&cbor.bytes, &limits).unwrap().value,
                    value
                );
                assert_eq!(
                    Flags::decode_uper(&uper.bytes, &limits).unwrap().value,
                    value
                );
            }
        }
    }
}

/// Reject invalid scalar siblings and truncated encodings after bit packing.
/// Inputs: none. Returns: none. Errors: accepting invalid/truncated input fails.
/// Source: `BoolAuto` codec contracts. Version/date: 2026-11-01; asn1c maintainers.
/// History: hostile-input regression. Example: cargo test.
#[test]
fn packing_keeps_scalar_validation_and_truncation_checks() {
    let limits = Limits::default();
    let invalid = Flags::new([false; 4], (6, None));
    assert!(invalid.encode_der(&limits).is_err());
    assert!(invalid.encode_cer(&limits).is_err());
    assert!(invalid.encode_cbor(&limits).is_err());
    assert!(invalid.encode_uper(&limits).is_err());
    let value = Flags::new([true, false, true, false], (4, Some(false)));
    let der = value.encode_der(&limits).unwrap().bytes;
    let cer = value.encode_cer(&limits).unwrap().bytes;
    let cbor = value.encode_cbor(&limits).unwrap().bytes;
    let uper = value.encode_uper(&limits).unwrap().bytes;
    for end in 0..der.len() {
        assert!(Flags::decode_ber(&der[..end], &limits).is_err());
    }
    for end in 0..cer.len() {
        assert!(Flags::decode_cer(&cer[..end], &limits).is_err());
    }
    for end in 0..cbor.len() {
        assert!(Flags::decode_cbor(&cbor[..end], &limits).is_err());
    }
    for end in 0..uper.len() {
        assert!(Flags::decode_uper(&uper[..end], &limits).is_err());
    }
}
