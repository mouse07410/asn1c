//! Regression coverage for imported record cases formerly rejected by the harness.

use asn1c_generated::imported_record_constructed_client::Packet as IntegerPacket;
use asn1c_generated::imported_record_legacy_base::{
    BooleanSequence, BooleanSet, IntegerChild,
};
use asn1c_generated::imported_record_sequence_client::Packet as SequencePacket;
use asn1c_generated::imported_record_set_client::Packet as SetPacket;
use asn1c_runtime::Limits;

/// Verify formerly rejected imported INTEGER-child, SEQUENCE, and SET targets.
///
/// Parameters: none. Returns no value; assertions compare fixed C-compatible bytes.
/// Errors: codec failures, value mismatches, or byte mismatches fail the test.
/// Original source: converted imported-record rejection fixtures and X.690.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: imported record gate conversion. Example: encode an imported SET child.
#[test]
fn former_import_rejections_match_constructed_type_vectors() {
    let limits = Limits::default();
    let integer = IntegerPacket {
        value: IntegerChild { value: 2 },
    };
    let sequence = SequencePacket {
        child: BooleanSequence { flag: true },
    };
    let set = SetPacket {
        child: BooleanSet { flag: true },
    };
    let integer_definite = [0x30, 0x05, 0x30, 0x03, 0x02, 1, 2];
    let integer_canonical = [0x30, 0x80, 0x30, 0x80, 0x02, 1, 2, 0, 0, 0, 0];
    let sequence_definite = [0x30, 0x05, 0x30, 0x03, 0x01, 1, 0xff];
    let sequence_canonical = [0x30, 0x80, 0x30, 0x80, 0x01, 1, 0xff, 0, 0, 0, 0];
    let set_definite = [0x30, 0x05, 0x31, 0x03, 0x01, 1, 0xff];
    let set_canonical = [0x30, 0x80, 0x31, 0x80, 0x01, 1, 0xff, 0, 0, 0, 0];

    assert_eq!(integer.encode_der(&limits).unwrap().bytes, integer_definite);
    assert_eq!(integer.encode_cer(&limits).unwrap().bytes, integer_canonical);
    assert_eq!(IntegerPacket::decode_cer(&integer_canonical, &limits).unwrap().value, integer);
    assert_eq!(sequence.encode_der(&limits).unwrap().bytes, sequence_definite);
    assert_eq!(sequence.encode_cer(&limits).unwrap().bytes, sequence_canonical);
    assert_eq!(SequencePacket::decode_cer(&sequence_canonical, &limits).unwrap().value, sequence);
    assert_eq!(set.encode_der(&limits).unwrap().bytes, set_definite);
    assert_eq!(set.encode_cer(&limits).unwrap().bytes, set_canonical);
    assert_eq!(SetPacket::decode_cer(&set_canonical, &limits).unwrap().value, set);
}
