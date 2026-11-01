//! An unused supported import still validates and emits both modules.

use asn1c_generated::imported_integer_unused_supported_base::Small;
use asn1c_generated::imported_integer_unused_supported_client::Packet;
use asn1c_runtime::Limits;

/// Verify the unused imported INTEGER and the importing module's own BOOLEAN.
/// Inputs: none. Returns no value. Errors: codec or assertion failures panic.
/// Source: direct unused-import schema. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: unused import validation gate.
/// Example: importing Small without using it preserves Packet's BOOLEAN codec.
#[test]
fn supported_unused_import_preserves_both_module_codecs() {
    let limits = Limits::default();
    let integer = Small::new(2).unwrap();
    let integer_wire = [0x02, 0x01, 0x02];
    assert!(Small::new(6).is_err());
    assert_eq!(integer.encode_der(&limits).unwrap().bytes, integer_wire);
    assert_eq!(Small::decode_cer(&integer_wire, &limits).unwrap().value, integer);

    // The client has a direct BOOLEAN despite its unused INTEGER declaration.
    let packet = Packet::new(true);
    let boolean_wire = [0x01, 0x01, 0xff];
    assert_eq!(packet.encode_der(&limits).unwrap().bytes, boolean_wire);
    assert_eq!(packet.encode_cer(&limits).unwrap().bytes, boolean_wire);
    assert_eq!(Packet::decode_ber(&boolean_wire, &limits).unwrap().value, packet);
    assert_eq!(Packet::decode_cer(&boolean_wire, &limits).unwrap().value, packet);
}
