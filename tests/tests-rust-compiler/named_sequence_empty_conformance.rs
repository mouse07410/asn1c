//! BER/DER/CER coverage for empty named SEQUENCE children.

use asn1c_generated::named_sequence_empty::{
    Empty, OptionalOnly, OptionalPacket, RequiredOnly, RequiredPacket,
};
use asn1c_runtime::Limits;

/// Check required and OPTIONAL empty children while sharing parent framing.
///
/// Inputs: none. Returns no value. Errors are assertion failures or codec errors.
/// Source: live C vectors and X.690. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: empty named child gate.
/// Example: a present empty child emits `30 00` under DER.
#[test]
fn empty_child_presence_matches_der_and_cer() {
    let limits = Limits::default();
    let required = RequiredOnly { child: Empty {} };
    let definite_present = [0x30, 0x02, 0x30, 0x00];
    let canonical_present = [0x30, 0x80, 0x30, 0x80, 0, 0, 0, 0];
    assert_eq!(
        required.encode_der(&limits).unwrap().bytes,
        definite_present
    );
    assert_eq!(
        required.encode_cer(&limits).unwrap().bytes,
        canonical_present
    );
    assert_eq!(
        RequiredOnly::decode_ber(&canonical_present, &limits)
            .unwrap()
            .value,
        required
    );
    assert_eq!(
        RequiredOnly::decode_cer(&canonical_present, &limits)
            .unwrap()
            .value,
        required
    );
    assert!(RequiredOnly::decode_cer(&definite_present, &limits).is_err());

    let absent = OptionalOnly { child: None };
    let definite_absence = [0x30, 0x00];
    let canonical_absence = [0x30, 0x80, 0, 0];
    assert_eq!(absent.encode_der(&limits).unwrap().bytes, definite_absence);
    assert_eq!(absent.encode_cer(&limits).unwrap().bytes, canonical_absence);
    assert_eq!(
        OptionalOnly::decode_ber(&canonical_absence, &limits)
            .unwrap()
            .value,
        absent
    );
    assert_eq!(
        OptionalOnly::decode_cer(&canonical_absence, &limits)
            .unwrap()
            .value,
        absent
    );

    let present = OptionalOnly {
        child: Some(Empty {}),
    };
    assert_eq!(present.encode_der(&limits).unwrap().bytes, definite_present);
    assert_eq!(
        present.encode_cer(&limits).unwrap().bytes,
        canonical_present
    );
    assert_eq!(
        OptionalOnly::decode_cer(&canonical_present, &limits)
            .unwrap()
            .value,
        present
    );
}

/// Check parent BOOLEAN/INTEGER DEFAULT omission around an empty child.
///
/// Inputs: none. Returns no value. Errors are assertion failures or codec errors.
/// Source: C default omission vectors. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: parent default preservation.
/// Example: absent child and both default values encode as `30 00`.
#[test]
fn parent_literal_defaults_are_omitted_and_nondefaults_encoded() {
    let limits = Limits::default();
    let absent = OptionalPacket {
        child: None,
        enabled: false,
        count: 0,
    };
    assert_eq!(absent.encode_der(&limits).unwrap().bytes, [0x30, 0x00]);
    assert_eq!(
        absent.encode_cer(&limits).unwrap().bytes,
        [0x30, 0x80, 0, 0]
    );
    assert_eq!(
        OptionalPacket::decode_ber(&[0x30, 0x00], &limits)
            .unwrap()
            .value,
        absent
    );

    let present = RequiredPacket {
        child: Empty {},
        enabled: true,
        count: 3,
    };
    let der = [0x30, 0x08, 0x30, 0x00, 0x01, 0x01, 0xff, 0x02, 0x01, 0x03];
    let cer = [
        0x30, 0x80, 0x30, 0x80, 0, 0, 0x01, 0x01, 0xff, 0x02, 0x01, 0x03, 0, 0,
    ];
    assert_eq!(present.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(present.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(
        RequiredPacket::decode_ber(&der, &limits).unwrap().value,
        present
    );

    let default_present = [0x30, 0x80, 0x30, 0x80, 0, 0, 0x01, 0x01, 0x00, 0, 0];
    let default_value = RequiredPacket {
        child: Empty {},
        enabled: false,
        count: 0,
    };
    assert_eq!(
        RequiredPacket::decode_ber(&default_present, &limits)
            .unwrap()
            .value,
        default_value
    );
    assert!(RequiredPacket::decode_cer(&default_present, &limits).is_err());
}
