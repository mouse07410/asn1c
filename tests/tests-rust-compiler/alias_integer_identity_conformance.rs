//! Public type identity and shared limits for a transparent local INTEGER alias.

use asn1c_generated::alias_integer_record::{Base, Sequence, Small};
use asn1c_generated::alias_integer_standalone::{ForwardAlias, OtherAlias};
use asn1c_generated::named_integer_record::{Sequence as DirectSequence, Small as DirectSmall};
use asn1c_runtime::Limits;

/// Find the smallest work limit accepted by one bounded codec operation.
///
/// Inputs: `succeeds` runs the operation at a candidate work budget.
/// Returns: the first successful budget from zero through 4096.
/// Errors: panics if no candidate succeeds within the bounded probe.
/// Original source: named/imported INTEGER resource regression contracts.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: transparent INTEGER alias acceptance.
/// Example: `minimum_work(|work| value.encode_der(&limits(work)).is_ok())`.
fn minimum_work(mut succeeds: impl FnMut(usize) -> bool) -> usize {
    (0..=4096)
        .find(|work| succeeds(*work))
        .expect("bounded INTEGER operation must fit the work probe")
}

/// Keep alias/base identity, checked construction, standalone codecs, and prefixes.
///
/// Inputs: none. Returns: no value; assertions check generated alias semantics.
/// Errors: failed assertions or unexpected codec errors fail the test.
/// Original source: approved transparent-alias API and named INTEGER C vectors.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: aliases reuse their direct base without a conversion or new context.
/// Example: a `Small` value can be assigned directly to a `Base` binding.
#[test]
fn alias_and_base_share_identity_and_checked_public_methods() {
    let limits = Limits::default();
    for value in [0, 2, 5] {
        // Both bindings have the same checked Rust type and INTEGER wire value.
        let base = Base::new(value).unwrap();
        let alias: Small = base;
        let recovered: Base = alias;
        let der = [0x02, 0x01, u8::try_from(value).unwrap()];
        assert_eq!(alias.value(), recovered.value());
        assert_eq!(alias.encode_der(&limits).unwrap().bytes, der);
        assert_eq!(alias.encode_cer(&limits).unwrap().bytes, der);
        assert_eq!(Small::decode_ber(&der, &limits).unwrap().value, base);
        assert_eq!(Small::decode_cer(&der, &limits).unwrap().value, base);

        // Prefix decoders retain exact consumption even through the alias name.
        let suffixed = [0x02, 0x01, u8::try_from(value).unwrap(), 0xee];
        let decoded = Small::decode_cer(&suffixed, &limits).unwrap();
        assert_eq!(decoded.value, base);
        assert_eq!(decoded.consumed_bytes, der.len());
        assert_eq!(decoded.consumed_bits, der.len() * 8);
        for end in 0..der.len() {
            assert!(Small::decode_ber(&der[..end], &limits).is_err());
            assert!(Small::decode_cer(&der[..end], &limits).is_err());
        }
    }

    // The inherited constructor and decoders enforce both range endpoints.
    for (value, content) in [(-1, 0xff), (6, 0x06)] {
        assert!(Small::new(value).is_err());
        let outside = [0x02, 0x01, content];
        assert!(Small::decode_ber(&outside, &limits).is_err());
        assert!(Small::decode_cer(&outside, &limits).is_err());
    }
    // A module containing no parent records still exports both forward aliases.
    let standalone: ForwardAlias = OtherAlias::new(2).unwrap();
    assert_eq!(standalone.encode_der(&limits).unwrap().bytes, [2, 1, 2]);
    let padded = [0x02, 0x02, 0x00, 0x02];
    assert_eq!(
        Small::decode_ber(&padded, &limits).unwrap().value.value(),
        2
    );
    assert!(Small::decode_cer(&padded, &limits).is_err());
}

/// Compare direct and aliased parent resource thresholds without resetting limits.
///
/// Inputs: none. Returns: no value; assertions compare bytes and exact budgets.
/// Errors: failed assertions or unexpected codec errors fail the test.
/// Original source: named INTEGER shared-parent record contract.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: a second module supplies the equivalent direct-type baseline.
/// Example: `Sequence` with `Small ::= Base` has the direct record's work limit.
#[test]
fn aliases_preserve_direct_parent_work_and_storage_limits() {
    let limits = Limits::default();
    let alias = Sequence {
        flag: true,
        value: Small::new(2).unwrap(),
        tail: vec![0xaa],
    };
    let direct = DirectSequence {
        flag: true,
        value: DirectSmall::new(2).unwrap(),
        tail: vec![0xaa],
    };
    let der = alias.encode_der(&limits).unwrap().bytes;
    let cer = alias.encode_cer(&limits).unwrap().bytes;
    assert_eq!(der, direct.encode_der(&limits).unwrap().bytes);
    assert_eq!(cer, direct.encode_cer(&limits).unwrap().bytes);

    // Every public operation must retain the direct record's exact work budget.
    for canonical in [false, true] {
        let alias_encode_work = minimum_work(|work| {
            let bounded = Limits {
                max_work_bits: work,
                ..limits
            };
            if canonical {
                alias.encode_cer(&bounded)
            } else {
                alias.encode_der(&bounded)
            }
            .is_ok()
        });
        let direct_encode_work = minimum_work(|work| {
            let bounded = Limits {
                max_work_bits: work,
                ..limits
            };
            if canonical {
                direct.encode_cer(&bounded)
            } else {
                direct.encode_der(&bounded)
            }
            .is_ok()
        });
        assert_eq!(alias_encode_work, direct_encode_work);
        assert!(alias_encode_work > 0);
        let encode_short = Limits {
            max_work_bits: alias_encode_work - 1,
            ..limits
        };
        if canonical {
            assert!(alias.encode_cer(&encode_short).is_err());
        } else {
            assert!(alias.encode_der(&encode_short).is_err());
        }

        let input = if canonical { &cer } else { &der };
        let alias_decode_work = minimum_work(|work| {
            let bounded = Limits {
                max_work_bits: work,
                ..limits
            };
            if canonical {
                Sequence::decode_cer(input, &bounded)
            } else {
                Sequence::decode_ber(input, &bounded)
            }
            .is_ok()
        });
        let direct_decode_work = minimum_work(|work| {
            let bounded = Limits {
                max_work_bits: work,
                ..limits
            };
            if canonical {
                DirectSequence::decode_cer(input, &bounded)
            } else {
                DirectSequence::decode_ber(input, &bounded)
            }
            .is_ok()
        });
        assert_eq!(alias_decode_work, direct_decode_work);
        assert!(alias_decode_work > 0);
        let decode_short = Limits {
            max_work_bits: alias_decode_work - 1,
            ..limits
        };
        if canonical {
            assert!(Sequence::decode_cer(input, &decode_short).is_err());
        } else {
            assert!(Sequence::decode_ber(input, &decode_short).is_err());
        }
    }

    // Operation input/output limits still include the complete parent value.
    let output_short = Limits {
        max_output_bytes: der.len() - 1,
        ..limits
    };
    assert!(alias.encode_der(&output_short).is_err());
    let input_short = Limits {
        max_input_bytes: cer.len() - 1,
        ..limits
    };
    assert!(Sequence::decode_cer(&cer, &input_short).is_err());
}

/// Preserve signed and singleton ranges and dashed alias names.
///
/// Inputs: none. Returns: no value; assertions compare values and fixed wire bytes.
/// Errors: failed assertions or unexpected codec errors fail the test.
/// Original source: approved transparent alias design and X.690 INTEGER/DEFAULT rules.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: transparent aliases retain the direct base's signed range and defaults.
/// Example: a DEFAULT TRUE flag is omitted while INTEGER -2 remains `02 01 fe`.
#[test]
fn signed_and_singleton_aliases_keep_base_ranges() {
    use asn1c_generated::alias_integer_identity::{
        OtherSigned, SignedAlias, SignedBase, Singleton,
    };

    let limits = Limits::default();
    for (value, content) in [(-2, 0xfe), (0, 0x00), (5, 0x05)] {
        // Dashed aliases preserve the checked signed base's identity and bytes.
        let alias: SignedAlias = OtherSigned::new(value).unwrap();
        let base: SignedBase = alias;
        let expected = [0x02, 0x01, content];
        assert_eq!(base.encode_der(&limits).unwrap().bytes, expected);
        assert_eq!(alias.encode_cer(&limits).unwrap().bytes, expected);
        assert_eq!(
            SignedAlias::decode_ber(&expected, &limits).unwrap().value,
            alias
        );
        assert_eq!(
            SignedAlias::decode_cer(&expected, &limits).unwrap().value,
            alias
        );
    }
    assert!(SignedAlias::new(-3).is_err());
    assert!(SignedAlias::new(6).is_err());
    for content in [0xfd, 0x06] {
        let outside = [0x02, 0x01, content];
        assert!(SignedAlias::decode_ber(&outside, &limits).is_err());
        assert!(SignedAlias::decode_cer(&outside, &limits).is_err());
    }
    assert_eq!(
        Singleton::new(2)
            .unwrap()
            .encode_der(&limits)
            .unwrap()
            .bytes,
        [2, 1, 2]
    );
    assert!(Singleton::new(1).is_err());
    assert!(Singleton::new(3).is_err());
    for content in [0x01, 0x03] {
        let outside = [0x02, 0x01, content];
        assert!(Singleton::decode_ber(&outside, &limits).is_err());
        assert!(Singleton::decode_cer(&outside, &limits).is_err());
    }
}

/// Preserve scalar DEFAULT siblings and canonical SET ordering around an alias.
///
/// Inputs: none. Returns: no value; assertions compare values and fixed wire bytes.
/// Errors: failed assertions or unexpected codec errors fail the test.
/// Original source: approved transparent alias design and X.690 DEFAULT rules.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: alias fields retain the surrounding record's canonical default handling.
/// Example: a DEFAULT TRUE flag is omitted from canonical SEQUENCE and SET encodings.
#[test]
fn alias_default_siblings_keep_canonical_record_semantics() {
    use asn1c_generated::alias_integer_identity::{DefaultSequence, DefaultSet, SignedAlias};

    let limits = Limits::default();

    // Scalar DEFAULT handling remains owned by the surrounding record schema.
    let omitted = DefaultSequence {
        value: SignedAlias::new(-2).unwrap(),
        flag: true,
    };
    let omitted_definite = [0x30, 0x03, 0x02, 0x01, 0xfe];
    let omitted_canonical = [0x30, 0x80, 0x02, 0x01, 0xfe, 0, 0];
    assert_eq!(omitted.encode_der(&limits).unwrap().bytes, omitted_definite);
    assert_eq!(
        omitted.encode_cer(&limits).unwrap().bytes,
        omitted_canonical
    );
    assert_eq!(
        DefaultSequence::decode_cer(&omitted_canonical, &limits)
            .unwrap()
            .value,
        omitted
    );
    let emitted = DefaultSequence {
        flag: false,
        ..omitted
    };
    let emitted_definite = [0x30, 0x06, 0x02, 0x01, 0xfe, 0x84, 1, 0];
    let emitted_canonical = [0x30, 0x80, 0x02, 0x01, 0xfe, 0x84, 1, 0, 0, 0];
    assert_eq!(emitted.encode_der(&limits).unwrap().bytes, emitted_definite);
    assert_eq!(
        emitted.encode_cer(&limits).unwrap().bytes,
        emitted_canonical
    );
    assert_eq!(
        DefaultSequence::decode_cer(&emitted_canonical, &limits)
            .unwrap()
            .value,
        emitted
    );

    let set = DefaultSet {
        value: SignedAlias::new(-2).unwrap(),
        flag: false,
    };
    let set_definite = [0x31, 0x06, 0x02, 0x01, 0xfe, 0x84, 1, 0];
    let set_canonical = [0x31, 0x80, 0x02, 0x01, 0xfe, 0x84, 1, 0, 0, 0];
    assert_eq!(set.encode_der(&limits).unwrap().bytes, set_definite);
    assert_eq!(set.encode_cer(&limits).unwrap().bytes, set_canonical);
    assert_eq!(
        DefaultSet::decode_cer(&set_canonical, &limits)
            .unwrap()
            .value,
        set
    );
    let reversed = [0x31, 0x80, 0x84, 1, 0, 0x02, 0x01, 0xfe, 0, 0];
    assert_eq!(
        DefaultSet::decode_ber(&reversed, &limits).unwrap().value,
        set
    );
    assert!(DefaultSet::decode_cer(&reversed, &limits).is_err());

    // BER may carry an explicit default; strict CER must require its omission.
    let explicit_default = [0x30, 0x80, 0x02, 0x01, 0xfe, 0x84, 1, 0xff, 0, 0];
    assert!(
        DefaultSequence::decode_ber(&explicit_default, &limits)
            .unwrap()
            .value
            .flag
    );
    assert!(DefaultSequence::decode_cer(&explicit_default, &limits).is_err());
}
