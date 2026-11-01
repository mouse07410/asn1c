//! Verify normalized type names without changing module, field, or enum rules.

use asn1c_generated::foo_base::FooBar as ImportedFooBar;
use asn1c_generated::foo_client::{FooBar as LocalFooBar, Packet};
use asn1c_generated::type_name_keyword::{Asn1Self, KeywordPacket};
use asn1c_generated::type_name_naming::{Color, NamedRoot, NamedRootChildRecord};
use asn1c_runtime::Limits;

/// Use the imported normalized type beside the same-spelled local type.
/// Inputs: none. Returns no value. Errors: assertion or codec failures.
/// Source: imported `Foo-Bar` and local `FooBar`. Date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: sanitized imported type paths.
/// Example: encode a packet using `crate::foo_base::FooBar`.
#[test]
fn imported_dashed_type_uses_qualified_camel_name() {
    let imported = ImportedFooBar::new(5).unwrap();
    let local = LocalFooBar::new(false);
    assert!(!local.value());
    let packet = Packet { value: imported, some_enabled: true };
    let wire = [0x30, 0x06, 0x02, 0x01, 0x05, 0x01, 0x01, 0xff];
    assert_eq!(packet.encode_der(&Limits::default()).unwrap().bytes, wire);
    assert_eq!(Packet::decode_ber(&wire, &Limits::default()).unwrap().value, packet);
}

/// Keep module, field, nested type, reserved type, and enum names stable.
/// Inputs: none. Returns no value. Errors: assertion or codec failures.
/// Source: unchanged module/field/enum sanitizers. Date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: type-name normalization.
/// Example: `Named-Root.child-record.some-value` maps to Rust snake fields.
#[test]
fn type_normalization_preserves_other_identifier_rules() {
    let child = NamedRootChildRecord { some_value: 3 };
    let root = NamedRoot { child_record: child };
    assert_eq!(root.child_record.some_value, 3);

    let limits = Limits::default();
    assert_eq!(Color::RedBlue.encode_der(&limits).unwrap().bytes, [0x0a, 0x01, 0x00]);
    assert_eq!(Color::Darkgreen.encode_der(&limits).unwrap().bytes, [0x0a, 0x01, 0x01]);
    let keyword = Asn1Self::new(5).unwrap();
    assert_eq!(keyword.value(), 5);
    let packet = KeywordPacket { value: keyword };
    assert_eq!(packet.encode_der(&limits).unwrap().bytes, [0x30, 0x03, 0x02, 0x01, 0x05]);
}
