//! Exact aggregate schema-work boundary for imported and local record children.

use asn1c_generated::imported_record_work12_base::RemoteFive;
use asn1c_generated::imported_record_work12_client::{LocalFive, Work12Packet};
use asn1c_runtime::Limits;

/// Find the smallest work budget accepted by one supplied operation.
///
/// Parameters: `succeeds` tests a candidate work limit. Returns its minimum from 0..=4096.
/// Errors: panics if the operation cannot succeed inside the bounded probe.
/// Original source: generated record resource contract. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: imported schema-work boundary.
/// Example: `minimum_work(|work| value.encode_cer(&limits(work)).is_ok())`.
fn minimum_work(mut succeeds: impl FnMut(usize) -> bool) -> usize {
    (0..=4096)
        .find(|work| succeeds(*work))
        .expect("imported record operation must fit the bounded work probe")
}

/// Exercise the imported/local twelve-field schema-work boundary with fixed C vectors.
///
/// Parameters: none. Returns no value; assertions compare exact bytes and values.
/// Errors: codec, prefix, or one-short budget failures must be rejected.
/// Original source: generated C DER/CER vectors and schema-work boundary rules.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: imported-record exact schema boundary. Example: two five-leaf children.
#[test]
fn imported_pair_accepts_exact_twelve_field_schema_work() {
    let value = Work12Packet {
        remote: RemoteFive {
            one: 1,
            two: 2,
            three: 3,
            four: 4,
            five: 5,
        },
        local: LocalFive {
            one: 5,
            two: 4,
            three: 3,
            four: 2,
            five: 1,
        },
    };
    let der = [
        0x30, 0x22, 0x30, 0x0f, 0x80, 1, 1, 0x81, 1, 2, 0x82, 1, 3, 0x83, 1, 4, 0x84, 1, 5, 0x31,
        0x0f, 0x85, 1, 5, 0x86, 1, 4, 0x87, 1, 3, 0x88, 1, 2, 0x89, 1, 1,
    ];
    let cer = [
        0x30, 0x80, 0x30, 0x80, 0x80, 1, 1, 0x81, 1, 2, 0x82, 1, 3, 0x83, 1, 4, 0x84, 1, 5, 0, 0,
        0x31, 0x80, 0x85, 1, 5, 0x86, 1, 4, 0x87, 1, 3, 0x88, 1, 2, 0x89, 1, 1, 0, 0, 0, 0,
    ];
    let defaults = Limits::default();
    assert_eq!(value.encode_der(&defaults).unwrap().bytes, der);
    assert_eq!(value.encode_cer(&defaults).unwrap().bytes, cer);
    assert_eq!(
        Work12Packet::decode_ber(&der, &defaults).unwrap().value,
        value
    );
    assert_eq!(
        Work12Packet::decode_cer(&cer, &defaults).unwrap().value,
        value
    );

    check_work_boundaries(&value, &cer);

    let mut suffixed = cer.to_vec();
    suffixed.push(0xee);
    let prefix = Work12Packet::decode_cer(&suffixed, &defaults).unwrap();
    assert_eq!(prefix.value, value);
    assert_eq!(prefix.consumed_bytes, cer.len());
}

/// Check exact and one-short CER work budgets for the twelve-field parent.
///
/// Parameters: `value` is the full record; `wire` is its canonical CER encoding.
/// Returns no value. Errors: mismatches, codec failures, or budget failures panic.
/// Original source: generated record shared resource contract.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: factor independent encoder/decoder budget checks for bounded test size.
/// Example: both child callbacks must consume one cumulative parent work budget.
fn check_work_boundaries(value: &Work12Packet, wire: &[u8]) {
    let defaults = Limits::default();
    let encode_work = minimum_work(|work| {
        value
            .encode_cer(&Limits {
                max_output_bytes: wire.len(),
                max_work_bits: work,
                ..defaults
            })
            .is_ok()
    });
    assert!(encode_work > 0);
    assert_eq!(
        value
            .encode_cer(&Limits {
                max_output_bytes: wire.len(),
                max_work_bits: encode_work,
                ..defaults
            })
            .unwrap()
            .bytes,
        wire
    );
    assert!(value
        .encode_cer(&Limits {
            max_output_bytes: wire.len(),
            max_work_bits: encode_work - 1,
            ..defaults
        })
        .is_err());

    let decode_work = minimum_work(|work| {
        Work12Packet::decode_cer(
            wire,
            &Limits {
                max_input_bytes: wire.len(),
                max_output_bytes: wire.len(),
                max_work_bits: work,
            },
        )
        .is_ok()
    });
    assert!(decode_work > 0);
    let exact = Work12Packet::decode_cer(
        wire,
        &Limits {
            max_input_bytes: wire.len(),
            max_output_bytes: wire.len(),
            max_work_bits: decode_work,
        },
    )
    .unwrap();
    assert_eq!(&exact.value, value);
    assert_eq!(exact.consumed_bytes, wire.len());
    assert!(Work12Packet::decode_cer(
        wire,
        &Limits {
            max_input_bytes: wire.len(),
            max_output_bytes: wire.len(),
            max_work_bits: decode_work - 1,
        }
    )
    .is_err());
}
