//! Imported assignments with the same spelling retain module ownership.

use asn1c_generated::imported_integer_alpha::Small as AlphaSmall;
use asn1c_generated::imported_integer_beta::Small as BetaSmall;
use asn1c_generated::imported_integer_client_alpha::Packet as AlphaPacket;
use asn1c_generated::imported_integer_client_beta::Packet as BetaPacket;
use asn1c_runtime::Limits;

/// Keep imported `Small` assignments distinct across their source modules.
/// Inputs: none. Returns no value. Errors: assertion failures or codec errors.
/// Source: imported alpha/beta schema pair. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: same-spelled import targets.
/// Example: alpha permits 3; beta permits 9.
#[test]
fn same_spelled_imports_keep_distinct_ranges_and_paths() {
    let limits = Limits::default();
    let alpha = AlphaPacket { value: AlphaSmall::new(3).unwrap() };
    let beta = BetaPacket { value: BetaSmall::new(9).unwrap() };
    assert_eq!(alpha.encode_der(&limits).unwrap().bytes, [0x30, 0x03, 0x02, 0x01, 0x03]);
    assert_eq!(beta.encode_der(&limits).unwrap().bytes, [0x30, 0x03, 0x02, 0x01, 0x09]);
    assert_eq!(AlphaPacket::decode_ber(
        &alpha.encode_der(&limits).unwrap().bytes,
        &limits
    ).unwrap().value, alpha);
    assert_eq!(BetaPacket::decode_ber(
        &beta.encode_der(&limits).unwrap().bytes,
        &limits
    ).unwrap().value, beta);
    assert!(AlphaSmall::new(9).is_err());
    assert!(BetaSmall::new(9).is_ok());
    let beta_cer = beta.encode_cer(&limits).unwrap().bytes;
    assert_eq!(BetaPacket::decode_cer(&beta_cer, &limits).unwrap().value, beta);
    assert!(AlphaPacket::decode_ber(&beta_cer, &limits).is_err());
    assert!(AlphaPacket::decode_cer(&beta_cer, &limits).is_err());
}
