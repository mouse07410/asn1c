//! Imported Rust modules whose normalized names require a reserved-name prefix.

use asn1c_generated::asn1_self::Small;
use asn1c_generated::imported_integer_reserved_client::Packet;
use asn1c_runtime::Limits;

/// Resolve a source module named `Self` through its sanitized Rust path.
/// Inputs: none. Returns no value. Errors: assertion failures or codec errors.
/// Source: module identifier sanitizer. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: import path collision guard.
/// Example: generated field type is owned by `crate::asn1_self::Small`.
#[test]
fn reserved_source_module_uses_the_generated_prefix() {
    let value = Packet { value: Small::new(2).unwrap() };
    let wire = [0x30, 0x03, 0x02, 0x01, 0x02];
    assert_eq!(value.encode_der(&Limits::default()).unwrap().bytes, wire);
    assert_eq!(Packet::decode_ber(&wire, &Limits::default()).unwrap().value, value);
}
