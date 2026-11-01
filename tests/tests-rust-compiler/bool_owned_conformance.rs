use asn1c_generated::bool_owned::Packet;
use asn1c_runtime::Limits;

/// Verify packed BOOLEAN setters preserve owned OCTET and BIT STRING siblings.
///
/// Inputs: no external inputs; the fixture has two owned siblings and four bits.
/// Returns: no value; assertions inspect fields and DER, CER, and UPER roundtrips.
/// Errors: codec failures fail the test; the selected values are valid.
/// Source: `BoolOwned` ASN.1 fixture and generated constructor/accessors.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: packed constructor ownership regression. Example: update one bit.
#[test]
fn setters_keep_owned_siblings_and_all_codecs_roundtrip() {
    let limits = Limits::default();
    let payload = vec![0xAA, 0x55];
    let bits = vec![0xA0];
    let mut value = Packet::new([true, false, true, false], (payload.clone(), bits.clone()));
    value.set_first(false);
    value.set_fourth(true);
    assert!(!value.get_first());
    assert!(value.get_fourth());
    assert_eq!(value.payload, payload);
    assert_eq!(value.bits, bits);

    let der = value.encode_der(&limits).unwrap();
    let der_value = Packet::decode_ber(&der.bytes, &limits).unwrap().value;
    assert_eq!(der_value, value);
    assert_eq!(der_value.payload, payload);
    assert_eq!(der_value.bits, bits);

    let cer = value.encode_cer(&limits).unwrap();
    let cer_value = Packet::decode_cer(&cer.bytes, &limits).unwrap().value;
    assert_eq!(cer_value, value);
    assert_eq!(cer_value.payload, payload);
    assert_eq!(cer_value.bits, bits);

    let uper = value.encode_uper(&limits).unwrap();
    let uper_value = Packet::decode_uper(&uper.bytes, &limits).unwrap().value;
    assert_eq!(uper_value, value);
    assert_eq!(uper_value.payload, payload);
    assert_eq!(uper_value.bits, bits);
}

/// Verify invalid owned siblings are rejected without changing their storage.
///
/// Inputs: one packet has an empty constrained OCTET STRING; another has dirty
/// unused BIT STRING bits. Returns: no value; assertions inspect failures/state.
/// Errors: each invalid value must fail its UPER encoder.
/// Source: generated fixed-size sibling validation. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: packed storage validation.
/// Example: an OCTET STRING below SIZE(1..10) is rejected.
#[test]
fn invalid_owned_siblings_fail_encoding_without_mutation() {
    let limits = Limits::default();
    let invalid_payload = Packet::new([true; 4], (Vec::new(), vec![0xA0]));
    assert!(invalid_payload.encode_uper(&limits).is_err());
    assert_eq!(invalid_payload.payload.as_slice(), &[]);
    assert_eq!(invalid_payload.bits, [0xA0]);

    let invalid_bits = Packet::new([true; 4], (vec![0xAA], vec![0xA1]));
    assert!(invalid_bits.encode_uper(&limits).is_err());
    assert_eq!(invalid_bits.payload, [0xAA]);
    assert_eq!(invalid_bits.bits, [0xA1]);
}
