//! XER BOOLEAN packing retains the encoder's existing optional/default API.

use asn1c_generated::bool_xer::Flags;
use asn1c_runtime::Limits;

/// Check packed required values and `Option<bool>` DEFAULT setters in XER.
/// Inputs: none. Returns: none. Errors: wrong XML/default/resource handling fails.
/// Source: `BoolXer` schema. Version/date: 2026-11-01; asn1c maintainers.
/// History: required-only XER packing. Example: cargo test.
#[test]
fn xer_defaults_keep_option_storage() {
    let mut value = Flags::new([true, false, true, false], (None, Some(0.5)));
    assert!(value.get_first());
    assert!(!value.get_second());
    assert!(value.get_third());
    assert!(!value.get_fourth());
    assert_eq!(value.get_maybe(), None);
    let limits = Limits::default();
    let encoded = value.encode_xer(&limits).unwrap();
    let text = String::from_utf8(encoded.clone()).unwrap();
    assert!(text.contains("<first><true/></first>"));
    assert!(text.contains("<second><false/></second>"));
    assert!(text.contains("<maybe><true/></maybe>"));
    value.set_maybe(Some(false));
    assert_eq!(value.get_maybe(), Some(false));
    let changed = value.encode_xer(&limits).unwrap();
    assert!(String::from_utf8(changed)
        .unwrap()
        .contains("<maybe><false/></maybe>"));
    value.set_maybe(None);
    value.set_first(false);
    value.set_first(true);
    assert_eq!(value.encode_xer(&limits).unwrap(), encoded);
    let exact = Limits {
        max_output_bytes: encoded.len(),
        ..limits
    };
    assert_eq!(value.encode_xer(&exact).unwrap(), encoded);
    let short = Limits {
        max_output_bytes: encoded.len() - 1,
        ..limits
    };
    assert!(value.encode_xer(&short).is_err());
}

/// Preserve a transparent tuple alias in the separate XER field layout.
///
/// Inputs: none. Returns: none. Errors: constructor, accessor, or XML mismatch fails.
/// Source: `BoolXer` nine-OPTIONAL schema. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: wide constructor qualification.
/// Example: pass a normal tuple despite the private generated alias.
#[test]
fn xer_optional_tuple_alias_preserves_presence() {
    use asn1c_generated::bool_xer::OptionFlags;
    let mut value = OptionFlags::new(
        [true, false, true, false],
        (None, None, None, None, None, None, None, None, None),
    );
    assert_eq!(value.get_extra8(), None);
    let before = value.encode_xer(&Limits::default()).unwrap();
    assert!(!String::from_utf8(before).unwrap().contains("<extra8>"));
    value.set_extra8(Some(false));
    assert_eq!(value.get_extra8(), Some(false));
    let after = value.encode_xer(&Limits::default()).unwrap();
    assert!(String::from_utf8(after)
        .unwrap()
        .contains("<extra8><false/></extra8>"));
}

/// Keep mixed XER constructor tuples transparent while moving owned strings.
///
/// Inputs: none. Returns: none. Errors: storage, XML, or limit mismatch fails.
/// Source: mixed `BoolXer` fields. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: heterogeneous tuple regression.
/// Example: pass ordinary `Option<String>` values to the constructor tuple.
#[test]
fn xer_mixed_tuple_moves_strings_and_preserves_absence() {
    use asn1c_generated::bool_xer::MixedFlags;
    let first_text = String::from("alpha");
    let final_text = String::from("omega");
    let address = first_text.as_ptr();
    let mut value = MixedFlags::new(
        [true, false, true, false],
        (
            Some(first_text),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(final_text),
        ),
    );
    assert_eq!(value.text0.as_ref().unwrap().as_ptr(), address);
    assert!(value.get_first());
    assert!(!value.get_fourth());
    let limits = Limits::default();
    let encoded = value.encode_xer(&limits).unwrap();
    let text = String::from_utf8(encoded.clone()).unwrap();
    assert!(text.contains("<text0>alpha</text0>"));
    assert!(text.contains("<text11>omega</text11>"));
    assert!(!text.contains("<text1>"));
    assert_eq!(
        value
            .encode_xer(&Limits {
                max_output_bytes: encoded.len(),
                ..limits
            })
            .unwrap(),
        encoded
    );
    assert!(value
        .encode_xer(&Limits {
            max_output_bytes: encoded.len() - 1,
            ..limits
        })
        .is_err());
    value.text11 = Some(String::from("bad\u{0001}"));
    assert!(value.encode_xer(&limits).is_err());
}
