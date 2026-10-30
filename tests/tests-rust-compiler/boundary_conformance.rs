//! Generated fixed-size string tests at the direct UPER size threshold.

use asn1c_generated::boundary_strings::{MaxBits, MaxOctets};
use asn1c_runtime::{Error, Limits, Resource};

/// Check the maximum admitted fixed lengths and operation output limit.
///
/// Parameters: none. Returns: no value; assertions inspect byte/bit counts.
/// Errors: one over-limit encode returns a typed error. Original source:
/// fixed-size UPER threshold in C PER constraints. Version/date: 2026-10-30.
/// Responsible party: asn1c maintainers. History: size boundary regression.
/// Example: SIZE(65535) OCTET STRING has 524280 meaningful bits.
#[test]
fn maximum_direct_sizes_round_trip() {
    let limits = Limits::default();
    let octets = MaxOctets::new(vec![0x5a; 65_535]).unwrap();
    let encoded = octets.encode_uper(&limits).unwrap();
    assert_eq!(encoded.bit_len, 65_535 * 8);
    assert_eq!(encoded.bytes.len(), 65_535);
    assert_eq!(MaxOctets::decode_uper(&encoded.bytes, &limits).unwrap().value, octets);

    let bits = MaxBits::new(vec![0xaa; 8192]).unwrap();
    let encoded = bits.encode_uper(&limits).unwrap();
    assert_eq!(encoded.bit_len, 65_535);
    assert_eq!(encoded.bytes.len(), 8192);
    assert_eq!(MaxBits::decode_uper(&encoded.bytes, &limits).unwrap().value, bits);

    let small = Limits { max_output_bytes: 8191, ..limits };
    assert!(matches!(bits.encode_uper(&small), Err(Error::LimitExceeded {
        resource: Resource::OutputBytes, ..
    })));
}
