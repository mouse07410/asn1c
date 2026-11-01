//! Bounded basic XER output for flat generated records.

use crate::{check_work_limit, enforce_limit, Error, Limits, Resource};
use std::fmt::{self, Write};

/// Fixed storage for the bounded decimal representations accepted here.
struct DecimalBuffer {
    /// Decimal byte storage state variable.
    bytes: [u8; 64],
    /// Occupied byte count state variable.
    used: usize,
}

impl Write for DecimalBuffer {
    /// Append `text` to this fixed buffer. Returns an error if it does not fit.
    /// Source: new Rust XER slice, 2026-10-31, asn1c maintainers.
    /// History: allocation-free numeric formatting. Example: `write!(buffer, "1")`.
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.used.checked_add(text.len()).ok_or(fmt::Error)?;
        let destination = self.bytes.get_mut(self.used..end).ok_or(fmt::Error)?;
        destination.copy_from_slice(text.as_bytes());
        self.used = end;
        Ok(())
    }
}

impl DecimalBuffer {
    /// Return the formatted bytes as text. Returns an error for invalid UTF-8.
    /// Source: new Rust XER slice, 2026-10-31, asn1c maintainers.
    /// History: allocation-free numeric formatting. Example: `buffer.text()?`.
    fn text(&self) -> Result<&str, Error> {
        std::str::from_utf8(&self.bytes[..self.used]).map_err(|_| Error::InvalidEncoding {
            reason: "invalid decimal formatting",
        })
    }
}

/// Incremental XER output and operation-wide resource limits.
pub struct XerWriter {
    /// Output bytes state variable.
    bytes: Vec<u8>,
    /// Resource limits state variable.
    limits: Limits,
}

impl XerWriter {
    /// Create a writer using `limits`. Returns an empty writer; never fails.
    /// Source: new Rust XER slice, 2026-10-31, asn1c maintainers.
    /// History: initial implementation. Example: `XerWriter::new(limits)`.
    #[must_use]
    pub const fn new(limits: &Limits) -> Self {
        Self {
            bytes: Vec::new(),
            limits: *limits,
        }
    }

    /// Append `text` with checked allocation and output/work limits.
    ///
    /// # Errors
    /// Returns a limit, overflow, or allocation error; never panics.
    /// Source: new Rust XER slice, 2026-10-31, asn1c maintainers.
    /// History: initial implementation. Example: `writer.append("<x>")?`.
    pub fn append(&mut self, text: &str) -> Result<(), Error> {
        let length = self
            .bytes
            .len()
            .checked_add(text.len())
            .ok_or(Error::SizeOverflow)?;
        enforce_limit(Resource::OutputBytes, length, self.limits.max_output_bytes)?;
        check_work_limit(
            length.checked_mul(8).ok_or(Error::SizeOverflow)?,
            &self.limits,
        )?;
        self.bytes
            .try_reserve(text.len())
            .map_err(|_| Error::AllocationFailed {
                requested_bytes: length,
            })?;
        self.bytes.extend_from_slice(text.as_bytes());
        Ok(())
    }

    /// Write a BOOLEAN `value`.
    ///
    /// # Errors
    /// Returns a budget error if output cannot fit.
    /// Source: X.693 basic XER, 2026-10-31, asn1c maintainers.
    /// History: initial implementation. Example: `writer.boolean(true)?`.
    pub fn boolean(&mut self, value: bool) -> Result<(), Error> {
        self.append(if value { "<true/>" } else { "<false/>" })
    }

    /// Write `value` after checking inclusive `lower` and `upper` bounds.
    ///
    /// # Errors
    /// Returns a range or resource error; allocation failure is reported.
    /// Source: X.693 basic XER, 2026-10-31, asn1c maintainers.
    /// History: initial implementation. Example: `writer.integer(1, 0, 5)?`.
    pub fn integer(&mut self, value: i64, lower: i64, upper: i64) -> Result<(), Error> {
        if value < lower || value > upper {
            return Err(Error::ValueOutOfRange {
                value,
                lower,
                upper,
            });
        }
        let mut text = DecimalBuffer {
            bytes: [0; 64],
            used: 0,
        };
        write!(&mut text, "{value}").map_err(|_| Error::SizeOverflow)?;
        self.append(text.text()?)
    }

    /// Write a finite `value` in the supported basic XER REAL range.
    ///
    /// # Errors
    /// Returns an error for nonfinite, out-of-scope, or inexact values, or exhausted resources.
    /// Source: `REAL__dump`, 2026-10-31, asn1c maintainers.
    /// History: fixed decimal formatting for the narrow default slice.
    /// Example: `writer.real(0.5)?`.
    pub fn real(&mut self, value: f64) -> Result<(), Error> {
        if !value.is_finite() || value.abs() > 1_000_000.0 || (value != 0.0 && value.abs() < 1e-15)
        {
            return Err(Error::InvalidEncoding {
                reason: "REAL outside XER slice",
            });
        }
        if value == 0.0 {
            return self.append(if value.is_sign_negative() { "-0" } else { "0" });
        }
        // C basic XER prints 15 fractional digits and retains at least one.
        let mut text = DecimalBuffer {
            bytes: [0; 64],
            used: 0,
        };
        write!(&mut text, "{value:.15}").map_err(|_| Error::SizeOverflow)?;
        let trimmed = text.text()?.trim_end_matches('0');
        // Reject decimal rounding that would change the represented REAL.
        if trimmed.parse::<f64>().ok() != Some(value) {
            return Err(Error::InvalidEncoding {
                reason: "REAL loses precision in XER slice",
            });
        }
        if trimmed.ends_with('.') {
            self.append(trimmed)?;
            self.append("0")
        } else {
            self.append(trimmed)
        }
    }

    /// Escape IA5 `value` for XML; reject controls without an XML representation.
    ///
    /// # Errors
    /// Returns an invalid encoding or resource error; never panics.
    /// Source: X.693 basic XER, 2026-10-31, asn1c maintainers.
    /// History: initial implementation. Example: `writer.ia5("&")?`.
    pub fn ia5(&mut self, value: &str) -> Result<(), Error> {
        for byte in value.bytes() {
            match byte {
                b'&' => self.append("&amp;")?,
                b'<' => self.append("&lt;")?,
                b'>' => self.append("&gt;")?,
                b'\r' => self.append("&#xD;")?,
                0x09 | 0x0a | 0x20..=0x7f => {
                    let one = [byte];
                    self.append(std::str::from_utf8(&one).map_err(|_| {
                        Error::InvalidEncoding {
                            reason: "invalid IA5 character",
                        }
                    })?)?;
                }
                _ => {
                    return Err(Error::InvalidEncoding {
                        reason: "invalid IA5 XML character",
                    })
                }
            }
        }
        Ok(())
    }

    /// Return whether output exceeds the `prefix` byte count; never fails.
    /// Source: new Rust XER slice, 2026-10-31, asn1c maintainers.
    /// History: empty record formatting. Example: `writer.has_content_after(3)`.
    #[must_use]
    pub const fn has_content_after(&self, prefix: usize) -> bool {
        self.bytes.len() > prefix
    }

    /// Finish and return accumulated bytes; `self` is consumed; never fails.
    /// Source: new Rust XER slice, 2026-10-31, asn1c maintainers.
    /// History: initial implementation. Example: `writer.finish()`.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }
}
