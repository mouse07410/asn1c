//! Strict-mode Rust XER output checks; no XER decoder is currently generated.
use asn1c_generated::strict_xer::Record;
use asn1c_runtime::{Error, Limits};

/// Validate public record fields before XER serialization.
/// Source: strict-mode/X.693 constraints; date: 2026-11-17; owner: asn1c.
/// Inputs: none. Returns a codec error on unexpected failure; assertions panic.
/// History: strict XER coverage. Example: `cargo test --test strict_mode_xer`.
#[test]
fn xer_output() -> Result<(), Error> {
    let limits = Limits::default();
    assert_eq!(
        Record { n: 2 }.encode_xer(&limits)?,
        b"<Record>\n    <n>2</n>\n</Record>\n"
    );
    assert!(Record { n: 3 }.encode_xer(&limits).is_err());
    assert!(Record { n: -1 }.encode_xer(&limits).is_err());
    Ok(())
}
