//! Tests of the bounded generated basic XER record encoder.

use asn1c_generated::xer_slice::{Empty, Q, S};
use asn1c_runtime::{Error, Limits};

/// Verify SET and SEQUENCE output, defaults, XML escapes, and resource limits.
/// No parameters; returns an error if encoding fails unexpectedly. Source:
/// issue #594; version/date: 2026-10-31; responsible: asn1c maintainers.
/// History: initial generated XER slice. Example: run `cargo test`.
#[test]
fn records_and_limits() -> Result<(), Error> {
    let limits = Limits::default();
    assert_eq!(Empty { text: None }.encode_xer(&limits)?, b"<Empty></Empty>\n");
    let set = S { flag: None, count: None, text: Some("a&<b".into()), ratio: None };
    let sequence = Q { flag: None, count: None, text: Some("a&<b".into()), ratio: None };
    let expected_set = if std::env::var_os("ASN1C_XER_AUTOMATIC").is_some() {
        concat!("<S>\n    <flag><true/></flag>\n    <count>2</count>\n",
                "    <text>a&amp;&lt;b</text>\n    <ratio>0.5</ratio>\n</S>\n")
    } else {
        concat!("<S>\n    <flag><true/></flag>\n    <count>2</count>\n",
                "    <ratio>0.5</ratio>\n    <text>a&amp;&lt;b</text>\n</S>\n")
    };
    assert_eq!(set.encode_xer(&limits)?, expected_set.as_bytes());
    assert_eq!(sequence.encode_xer(&limits)?,
        concat!("<Q>\n    <flag><true/></flag>\n    <count>2</count>\n",
                "    <text>a&amp;&lt;b</text>\n    <ratio>0.5</ratio>\n</Q>\n").as_bytes());
    let invalid = S { count: Some(6), ..set.clone() };
    assert!(invalid.encode_xer(&limits).is_err());
    let invalid = S { text: Some("\u{1}".into()), ..set };
    assert!(invalid.encode_xer(&limits).is_err());
    let invalid = S { text: Some("é".into()), ..set };
    assert!(invalid.encode_xer(&limits).is_err());
    let invalid = S { ratio: Some(f64::NAN), ..set.clone() };
    assert!(invalid.encode_xer(&limits).is_err());
    let invalid = S { ratio: Some(1e10), ..set.clone() };
    assert!(invalid.encode_xer(&limits).is_err());
    let invalid = S { ratio: Some(1.000_000_000_000_000_2), ..set.clone() };
    assert!(invalid.encode_xer(&limits).is_err());
    let invalid = S { ratio: Some(1.5e-15), ..set.clone() };
    assert!(invalid.encode_xer(&limits).is_err());
    let carriage_return = Empty { text: Some("a\rb".into()) };
    assert_eq!(carriage_return.encode_xer(&limits)?, b"<Empty>\n    <text>a&#xD;b</text>\n</Empty>\n");
    assert!(set.encode_xer(&Limits { max_output_bytes: 4, ..limits }).is_err());
    assert!(set.encode_xer(&Limits { max_work_bits: 8, ..limits }).is_err());
    let omitted = S { flag: Some(false), count: Some(3), text: None, ratio: Some(1.25) };
    assert_eq!(omitted.encode_xer(&limits)?,
        b"<S>\n    <flag><false/></flag>\n    <count>3</count>\n    <ratio>1.25</ratio>\n</S>\n");
    Ok(())
}
