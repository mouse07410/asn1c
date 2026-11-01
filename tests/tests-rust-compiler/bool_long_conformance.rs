//! Maximum admitted identifiers work with packed values and DEFAULT slots.

use asn1c_generated::bool_long_name::{DefaultFlags, Flags};
use asn1c_runtime::Limits;

/// Check the longest accessor and a long default expression in SET construction.
/// Inputs: none. Returns: none. Errors: byte, value, or accessor mismatches fail.
/// Source: `BoolLongName` schema. Version/date: 2026-11-01; asn1c maintainers.
/// History: long-name bitset regression. Example: cargo test.
#[test]
fn maximum_identifiers_support_required_and_default_values() {
    let limits = Limits::default();
    let value = Flags::new([true, false, true, false], ());
    assert!(value
        .get_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa());
    let cer = value.encode_cer(&limits).unwrap();
    assert_eq!(Flags::decode_cer(&cer.bytes, &limits).unwrap().value, value);
    let mut defaults = DefaultFlags::new([false, true, false, true], ());
    let omitted = [0x31, 9, 0x81, 1, 0xff, 0x82, 1, 0, 0x83, 1, 0xff];
    assert_eq!(defaults.encode_der(&limits).unwrap().bytes, omitted);
    assert_eq!(
        DefaultFlags::decode_ber(&omitted, &limits).unwrap().value,
        defaults
    );
    defaults
        .set_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa(true);
    assert!(defaults
        .get_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa());
    let der = defaults.encode_der(&limits).unwrap().bytes;
    assert_eq!(&der[..5], &[0x31, 12, 0x80, 1, 0xff]);
    let cer = defaults.encode_cer(&limits).unwrap();
    assert_eq!(
        DefaultFlags::decode_cer(&cer.bytes, &limits).unwrap().value,
        defaults
    );
}
