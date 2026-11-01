//! Generated BER/DER/CER tests for explicit-tag SET fields.

use asn1c_generated::explicit_set_module::{ExplicitSetRecord, ExplicitSetRecordSetstate};
use asn1c_runtime::{Error, Limits, Resource};

/// Verify SET canonical sorting includes the effective outer tag class.
///
/// Parameters: none. Returns: no value; byte vectors prove ordering.
/// Errors: a reordered BER SET remains readable but fails strict CER.
/// Source: X.690 SET canonical tag ordering. Version/date: 2026-11-01.
/// Author: asn1c maintainers. History: explicit SET wrapper coverage.
/// Example: universal BOOLEAN sorts before context-specific tag zero.
#[test]
fn explicit_set_sorts_and_decodes_independent_of_ber_order() {
    let limits = Limits::default();
    let value = ExplicitSetRecord {
        flag: true,
        plain: Some(false),
        count: 4,
        marker: Some(()),
        setstate: ExplicitSetRecordSetstate::Two,
        extra: Some(false),
    };
    let der = [
        0x31, 0x1f, 0x01, 0x01, 0x00, 0xa0, 0x03, 0x01, 0x01, 0xff, 0xbe, 0x03, 0x02, 0x01, 0x04,
        0xbf, 0x1f, 0x02, 0x05, 0x00, 0xbf, 0x7f, 0x03, 0x0a, 0x01, 0x02, 0xbf, 0x81, 0x00, 0x03,
        0x01, 0x01, 0x00,
    ];
    assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
    assert!(der
        .windows(5)
        .any(|window| window == [0xa0, 0x03, 0x01, 0x01, 0xff]));
    assert_eq!(
        ExplicitSetRecord::decode_ber(&der, &limits).unwrap().value,
        value
    );
    let cer = [
        0x31, 0x80, 0x01, 0x01, 0x00, 0xa0, 0x80, 0x01, 0x01, 0xff, 0, 0, 0xbe, 0x80, 0x02, 0x01,
        0x04, 0, 0, 0xbf, 0x1f, 0x80, 0x05, 0x00, 0, 0, 0xbf, 0x7f, 0x80, 0x0a, 0x01, 0x02, 0, 0,
        0xbf, 0x81, 0x00, 0x80, 0x01, 0x01, 0x00, 0, 0, 0, 0,
    ];
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(
        ExplicitSetRecord::decode_cer(&cer, &limits).unwrap().value,
        value
    );

    let missing_required = [0x31, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff];
    let unknown = [0x31, 0x04, 0xbd, 0x02, 0x05, 0x00];
    let duplicate = [
        0x31, 0x0a, 0xa0, 0x03, 0x01, 0x01, 0xff, 0xa0, 0x03, 0x01, 0x01, 0x00,
    ];
    let primitive_wrapper = [0x31, 0x05, 0x80, 0x03, 0x01, 0x01, 0xff];
    for malformed in [
        missing_required.as_slice(),
        unknown.as_slice(),
        duplicate.as_slice(),
        primitive_wrapper.as_slice(),
    ] {
        assert!(ExplicitSetRecord::decode_ber(malformed, &limits).is_err());
    }
    for end in 0..der.len() {
        assert!(ExplicitSetRecord::decode_ber(&der[..end], &limits).is_err());
    }
    let no_input = Limits {
        max_input_bytes: 1,
        ..limits
    };
    assert!(matches!(
        ExplicitSetRecord::decode_ber(&der, &no_input),
        Err(Error::LimitExceeded {
            resource: Resource::InputBytes,
            ..
        })
    ));
    let no_output = Limits {
        max_output_bytes: der.len() - 1,
        ..limits
    };
    assert!(matches!(
        value.encode_der(&no_output),
        Err(Error::LimitExceeded {
            resource: Resource::OutputBytes,
            ..
        })
    ));
    let no_work = Limits {
        max_work_bits: 0,
        ..limits
    };
    assert!(matches!(
        ExplicitSetRecord::decode_ber(&der, &no_work),
        Err(Error::LimitExceeded {
            resource: Resource::WorkBits,
            ..
        })
    ));

    let reordered = [
        0x31, 0x0e, 0xa0, 0x03, 0x01, 0x01, 0xff, 0x01, 0x01, 0x00, 0xbf, 0x7f, 0x03, 0x0a, 0x01,
        0x02,
    ];
    let ber = ExplicitSetRecord::decode_ber(&reordered, &limits).unwrap();
    assert!(ber.value.flag);
    assert_eq!(ber.value.plain, Some(false));
    assert_eq!(ber.value.setstate, ExplicitSetRecordSetstate::Two);
    assert!(ExplicitSetRecord::decode_cer(&reordered, &limits).is_err());
}
