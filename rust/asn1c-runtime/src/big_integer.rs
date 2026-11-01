//! Bounded arbitrary-precision signed INTEGER values and BER/DER/CER codecs.
//!
//! Original source: X.690 INTEGER representation and the asn1c wide INTEGER
//! runtime. Version/date: 2026-11-01. Responsible party: asn1c maintainers.
//! Example: `decode_big_integer_ber(input, &Limits::default())?`.

use crate::{Decoded, Encoded, Error, Limits, Resource};

/// Maximum simultaneous `BigInteger` codec scratch capacity (128 MiB).
const MAX_BIG_INTEGER_SCRATCH_BYTES: usize = 128 * 1024 * 1024;
/// Maximum BER tag value accepted by the C-compatible runtime parser.
const MAX_TAG_NUMBER: u32 = 0x3fff_ffff;
/// Universal ASN.1 INTEGER identifier octet.
const INTEGER_IDENTIFIER: u8 = 0x02;

/// Signed arbitrary-precision INTEGER in minimal big-endian two's-complement form.
///
/// Values are nonempty and never contain redundant leading sign-extension
/// octets. Construction and decoding allocate fallibly under caller limits.
///
/// Original source: X.690 signed INTEGER contents and asn1c wide INTEGER.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: initial arbitrary-precision Rust runtime type.
/// Example: `BigInteger::try_from_signed_bytes(&[0x80], &Limits::default())?`.
#[derive(Debug, Eq, PartialEq)]
pub struct BigInteger {
    /// Minimal nonempty signed bytes; private state variable preserving the value invariant.
    signed_bytes: Vec<u8>,
}

impl BigInteger {
    /// Transfer validated canonical bytes into the private invariant-bearing wrapper.
    ///
    /// # Parameters and returns
    /// `signed_bytes` is a nonempty, minimal two's-complement Vec allocated by
    /// a caller that already charged its normalization, copy, and invariant
    /// checks. Returns a wrapper without copying or allocating.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` for empty bytes or redundant sign padding.
    /// No panic or allocation occurs.
    ///
    /// # Source, version, history, example
    /// Source: X.690 INTEGER content invariant. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: shared record normalization.
    /// Example: called after `copy_signed_bytes` in a record reader.
    pub(crate) fn from_normalized_signed_bytes(signed_bytes: Vec<u8>) -> Result<Self, Error> {
        if signed_bytes.is_empty() {
            return Err(invalid("signed INTEGER bytes must not be empty"));
        }
        let redundant_prefix = signed_bytes.get(1).is_some_and(|next| {
            (signed_bytes[0] == 0 && next & 0x80 == 0)
                || (signed_bytes[0] == 0xff && next & 0x80 != 0)
        });
        if redundant_prefix {
            return Err(invalid("signed INTEGER bytes must be minimally encoded"));
        }
        Ok(Self { signed_bytes })
    }

    /// Create a value from signed big-endian bytes, trimming redundant sign padding.
    ///
    /// # Parameters and returns
    /// `bytes` is a nonempty signed two's-complement byte sequence; `limits`
    /// bounds input, retained output, and work. Returns its minimal value.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` for empty input, a configured limit error, a
    /// checked-size error, or an allocation error. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 signed INTEGER content. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: arbitrary-precision support.
    /// Example: `BigInteger::try_from_signed_bytes(&[0xff, 0x7f], limits)?`.
    pub fn try_from_signed_bytes(bytes: &[u8], limits: &Limits) -> Result<Self, Error> {
        check_resource(Resource::InputBytes, bytes.len(), limits.max_input_bytes)?;
        if bytes.is_empty() {
            return Err(invalid("signed INTEGER bytes must not be empty"));
        }

        let mut budget = ScalarBudget::new(limits);
        budget.charge_bytes(bytes.len())?;
        let start = normalized_start(bytes);
        let normalized_len = bytes.len().checked_sub(start).ok_or(Error::SizeOverflow)?;
        check_resource(
            Resource::OutputBytes,
            normalized_len,
            limits.max_output_bytes,
        )?;
        check_scratch(normalized_len)?;
        budget.charge_bytes(normalized_len)?;
        let signed_bytes = copy_signed_bytes(&bytes[start..], limits, 0)?;
        Ok(Self { signed_bytes })
    }

    /// Borrow the value's minimal signed big-endian representation.
    ///
    /// # Parameters and returns
    /// No parameters. Returns a nonempty slice with no redundant leading
    /// `00` or `ff` sign-extension octets.
    ///
    /// # Errors
    /// This accessor cannot fail and raises no exception.
    ///
    /// # Source, version, history, example
    /// Source: `BigInteger` value representation. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: arbitrary-precision support.
    /// Example: `value.as_signed_bytes() == [0x80]`.
    #[must_use]
    pub fn as_signed_bytes(&self) -> &[u8] {
        &self.signed_bytes
    }

    /// Convert to `i64` when the represented value fits that range.
    ///
    /// # Parameters and returns
    /// No parameters. Returns `Some(value)` for values in `i64`, otherwise
    /// `None`; the `BigInteger` remains unchanged.
    ///
    /// # Errors
    /// This conversion cannot fail or panic.
    ///
    /// # Source, version, history, example
    /// Source: signed two's-complement interpretation. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: arbitrary-precision support.
    /// Example: `BigInteger::try_from_signed_bytes(&[1], limits)?.try_to_i64() == Some(1)`.
    #[must_use]
    pub fn try_to_i64(&self) -> Option<i64> {
        signed_bytes_to_i64(&self.signed_bytes)
    }
}

/// Encode a `BigInteger` as a canonical DER INTEGER primitive TLV.
///
/// # Parameters and returns
/// `value` is an invariant-checked `BigInteger`; `limits` bounds complete output
/// and work. Returns a shortest definite-length universal INTEGER TLV.
///
/// # Errors
/// Returns output/work limit, checked-size, or allocation errors. No panic.
///
/// # Source, version, history, example
/// Source: X.690 DER INTEGER encoding. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: arbitrary-precision support.
/// Example: `encode_big_integer_der(&value, &Limits::default())?`.
pub fn encode_big_integer_der(value: &BigInteger, limits: &Limits) -> Result<Encoded, Error> {
    let mut budget = ScalarBudget::new(limits);
    encode_canonical(value, limits, value.signed_bytes.capacity(), &mut budget)
}

/// Encode a `BigInteger` as a canonical CER INTEGER primitive TLV.
///
/// # Parameters and returns
/// `value` is an invariant-checked `BigInteger`; `limits` bounds complete output
/// and work. Returns a shortest definite-length universal INTEGER TLV.
///
/// # Errors
/// Returns output/work limit, checked-size, or allocation errors. No panic.
///
/// # Source, version, history, example
/// Source: X.690 CER primitive INTEGER encoding. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: arbitrary-precision support.
/// Example: `encode_big_integer_cer(&value, &Limits::default())?`.
pub fn encode_big_integer_cer(value: &BigInteger, limits: &Limits) -> Result<Encoded, Error> {
    let mut budget = ScalarBudget::new(limits);
    encode_canonical(value, limits, value.signed_bytes.capacity(), &mut budget)
}

/// Decode a BER INTEGER prefix into a normalized `BigInteger` value.
///
/// # Parameters and returns
/// `input` is the complete available slice and may have a suffix; `limits`
/// bounds the full slice, retained payload, scratch, and cumulative work.
/// Returns the normalized signed value and exact TLV prefix consumption.
///
/// # Errors
/// Returns truncation, malformed identifier/length/content, input/output/work
/// limit, size, or allocation errors. Empty content is rejected deliberately,
/// even though the C wide INTEGER decoder accepts it as zero.
///
/// # Source, version, history, example
/// Source: X.690 BER INTEGER plus asn1c wide INTEGER compatibility.
/// Version: 2026-11-01. Responsible: asn1c maintainers.
/// History: arbitrary-precision support. Example: `decode_big_integer_ber(input, limits)?`.
pub fn decode_big_integer_ber(input: &[u8], limits: &Limits) -> Result<Decoded<BigInteger>, Error> {
    decode_integer(input, limits, false)
}

/// Strictly decode a canonical CER INTEGER prefix into `BigInteger`.
///
/// # Parameters and returns
/// `input` is the complete available slice and may have a suffix; `limits`
/// bounds input, retained/output scratch, and one cumulative parse/re-encode
/// work budget. Returns the value and exact consumed prefix.
///
/// # Errors
/// Returns BER parsing/resource errors or `InvalidEncoding` if the consumed
/// prefix differs from its shortest CER re-encoding. Empty content is rejected.
///
/// # Source, version, history, example
/// Source: X.690 CER canonical comparison. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: arbitrary-precision support.
/// Example: `decode_big_integer_cer(input, limits)?`.
pub fn decode_big_integer_cer(input: &[u8], limits: &Limits) -> Result<Decoded<BigInteger>, Error> {
    decode_integer(input, limits, true)
}

/// Track work for one scalar `BigInteger` operation.
struct ScalarBudget<'limits> {
    /// Caller-provided ceilings shared across every phase of the operation.
    limits: &'limits Limits,
    /// Cumulative work bits consumed by parsing, copying, encoding, and compare;
    /// this is a state variable.
    work_bits: usize,
}

impl<'limits> ScalarBudget<'limits> {
    /// Create a zeroed operation budget over caller limits.
    ///
    /// # Parameters and returns
    /// `limits` supplies per-operation ceilings. Returns an unused budget.
    ///
    /// # Errors
    /// This initializer cannot fail.
    ///
    /// # Source, version, history, example
    /// Source: runtime scalar budget policy. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: `BigInteger` codec.
    /// Example: initialized at each public codec boundary.
    const fn new(limits: &'limits Limits) -> Self {
        Self {
            limits,
            work_bits: 0,
        }
    }

    /// Check whether one future byte charge fits without changing the counter.
    ///
    /// # Parameters and returns
    /// `bytes` is the planned additional work in octets. Returns success if it
    /// fits the remaining bit budget.
    ///
    /// # Errors
    /// Returns size overflow or `LimitExceeded(WorkBits)`.
    ///
    /// # Source, version, history, example
    /// Source: caller-configurable work ceilings. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: `BigInteger` codec.
    /// Example: used before fallible allocation.
    fn check_bytes(&self, bytes: usize) -> Result<(), Error> {
        let added_bits = bytes.checked_mul(8).ok_or(Error::SizeOverflow)?;
        let requested = self
            .work_bits
            .checked_add(added_bits)
            .ok_or(Error::SizeOverflow)?;
        check_resource(Resource::WorkBits, requested, self.limits.max_work_bits)
    }

    /// Charge byte work after checking cumulative arithmetic and limits.
    ///
    /// # Parameters and returns
    /// `bytes` is newly processed work. Returns success after updating state.
    ///
    /// # Errors
    /// Returns size overflow or `LimitExceeded(WorkBits)`.
    ///
    /// # Source, version, history, example
    /// Source: caller-configurable work ceilings. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: `BigInteger` codec.
    /// Example: charges parser input before scanning contents.
    fn charge_bytes(&mut self, bytes: usize) -> Result<(), Error> {
        self.check_bytes(bytes)?;
        self.work_bits = self
            .work_bits
            .checked_add(bytes.checked_mul(8).ok_or(Error::SizeOverflow)?)
            .ok_or(Error::SizeOverflow)?;
        Ok(())
    }
}

/// Parse, normalize, and optionally canonicalize one INTEGER operation.
///
/// # Parameters and returns
/// `input` is the full available slice; `limits` supplies operation ceilings;
/// `strict_cer` selects same-budget canonical re-encoding. Returns value and
/// exact consumed prefix.
///
/// # Errors
/// Returns malformed/truncated BER, canonical mismatch, limit, size, or
/// allocation errors. No panic.
///
/// # Source, version, history, example
/// Source: X.690 INTEGER and strict CER comparison. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: `BigInteger` codec.
/// Example: called by the public BER and CER decoders.
fn decode_integer(
    input: &[u8],
    limits: &Limits,
    strict_cer: bool,
) -> Result<Decoded<BigInteger>, Error> {
    check_resource(Resource::InputBytes, input.len(), limits.max_input_bytes)?;
    let mut budget = ScalarBudget::new(limits);
    let (content_start, content_len, consumed_bytes) = parse_integer_tlv(input, &mut budget)?;
    if content_len == 0 {
        return Err(invalid("BER INTEGER content must not be empty"));
    }
    budget.charge_bytes(content_len)?;
    let contents = &input[content_start..consumed_bytes];
    let significant_start = normalized_start(contents);
    let retained_len = content_len
        .checked_sub(significant_start)
        .ok_or(Error::SizeOverflow)?;
    check_resource(Resource::OutputBytes, retained_len, limits.max_output_bytes)?;

    let canonical_len = encoded_integer_len(retained_len)?;
    if strict_cer {
        check_resource(
            Resource::OutputBytes,
            canonical_len,
            limits.max_output_bytes,
        )?;
        let expected_scratch = retained_len
            .checked_add(canonical_len)
            .ok_or(Error::SizeOverflow)?;
        check_scratch(expected_scratch)?;
    } else {
        check_scratch(retained_len)?;
    }

    let future_work = decode_future_work(retained_len, consumed_bytes, canonical_len, strict_cer)?;
    budget.check_bytes(future_work)?;
    budget.charge_bytes(retained_len)?;
    let value = BigInteger {
        signed_bytes: copy_signed_bytes(
            &contents[significant_start..],
            limits,
            if strict_cer { canonical_len } else { 0 },
        )?,
    };

    if strict_cer {
        let canonical =
            encode_canonical(&value, limits, value.signed_bytes.capacity(), &mut budget)?;
        let comparison_len = consumed_bytes.max(canonical.bytes.len());
        budget.charge_bytes(comparison_len)?;
        if input.get(..consumed_bytes) != Some(canonical.bytes.as_slice()) {
            return Err(invalid("CER INTEGER differs from canonical re-encoding"));
        }
    }

    let consumed_bits = consumed_bytes.checked_mul(8).ok_or(Error::SizeOverflow)?;
    Ok(Decoded {
        value,
        consumed_bits,
        consumed_bytes,
    })
}

/// Parse one primitive INTEGER identifier and definite length.
///
/// # Parameters and returns
/// `input` is already checked against the whole-slice input limit; `budget`
/// tracks wire parser work. Returns content start, content length, and prefix end.
///
/// # Errors
/// Returns wrong-tag, indefinite/reserved/malformed length, truncation, work,
/// or checked-size errors.
///
/// # Source, version, history, example
/// Source: X.690 BER primitive identifier/length forms. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: `BigInteger` codec.
/// Example: called before validating or copying INTEGER content.
fn parse_integer_tlv(
    input: &[u8],
    budget: &mut ScalarBudget<'_>,
) -> Result<(usize, usize, usize), Error> {
    require_bytes(input, 1)?;
    budget.charge_bytes(1)?;
    let identifier = input[0];
    if identifier >> 6 != 0 || identifier & 0x20 != 0 {
        return Err(invalid(
            "BER INTEGER identifier must be universal and primitive",
        ));
    }
    let short_tag = identifier & 0x1f;
    let (identifier_len, tag_number) = if short_tag == 0x1f {
        parse_high_tag(input, budget)?
    } else {
        (1, u32::from(short_tag))
    };
    if tag_number != u32::from(INTEGER_IDENTIFIER) {
        return Err(invalid("BER identifier is not an INTEGER tag"));
    }
    let length_index = identifier_len;
    let length_octet_end = length_index.checked_add(1).ok_or(Error::SizeOverflow)?;
    require_bytes(input, length_octet_end)?;
    budget.charge_bytes(1)?;
    let first_length = input[length_index];
    if first_length == 0xff {
        return Err(invalid("BER length FF is reserved"));
    }
    if first_length == 0x80 {
        return Err(invalid("primitive BER INTEGER length must be definite"));
    }

    let (content_start, content_len) = if first_length & 0x80 == 0 {
        (length_octet_end, usize::from(first_length))
    } else {
        parse_long_length(input, length_index, first_length, budget)?
    };
    budget.charge_bytes(content_len)?;
    let total_len = content_start
        .checked_add(content_len)
        .ok_or(Error::SizeOverflow)?;
    require_bytes(input, total_len)?;
    Ok((content_start, content_len, total_len))
}

/// Parse a universal high-tag identifier while preserving C BER aliases.
///
/// # Parameters and returns
/// `input` begins with the high-tag marker; `budget` meters each identifier
/// octet before it is read. Returns identifier length and checked tag number.
///
/// # Errors
/// Returns truncation, work-limit, or tag-number overflow errors.
///
/// # Source, version, history, example
/// Source: X.690 BER high-tag form and C `ber_tlv_tag_t` range.
/// Version: 2026-11-01. Responsible: asn1c maintainers.
/// History: wide INTEGER compatibility. Example: accepts `1f 80 02` as tag 2.
fn parse_high_tag(input: &[u8], budget: &mut ScalarBudget<'_>) -> Result<(usize, u32), Error> {
    let mut cursor = 1_usize;
    let mut number = 0_u32;
    loop {
        let end = cursor.checked_add(1).ok_or(Error::SizeOverflow)?;
        require_bytes(input, end)?;
        budget.charge_bytes(1)?;
        let octet = input[cursor];
        cursor = end;
        number = number
            .checked_mul(128)
            .and_then(|current| current.checked_add(u32::from(octet & 0x7f)))
            .ok_or(Error::SizeOverflow)?;
        if number > MAX_TAG_NUMBER {
            return Err(Error::SizeOverflow);
        }
        if octet & 0x80 == 0 {
            return Ok((cursor, number));
        }
    }
}

/// Parse long-form length octets, retaining BER's redundant leading-zero acceptance.
///
/// # Parameters and returns
/// `input` contains the length field; `length_index` locates it;
/// `first_length` is its initial long-form octet; `budget` meters the header.
/// Returns the content offset and checked numeric length.
///
/// # Errors
/// Returns truncation or `SizeOverflow` for an unrepresentable length.
///
/// # Source, version, history, example
/// Source: X.690 BER long-form lengths. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: `BigInteger` codec.
/// Example: accepts a leading-zero BER alias and CER later rejects it by comparison.
fn parse_long_length(
    input: &[u8],
    length_index: usize,
    first_length: u8,
    budget: &mut ScalarBudget<'_>,
) -> Result<(usize, usize), Error> {
    let count = usize::from(first_length & 0x7f);
    let count_start = length_index.checked_add(1).ok_or(Error::SizeOverflow)?;
    let content_start = count_start.checked_add(count).ok_or(Error::SizeOverflow)?;
    require_bytes(input, content_start)?;
    budget.charge_bytes(count)?;
    let mut content_len = 0_usize;
    for octet in &input[count_start..content_start] {
        content_len = content_len
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(*octet)))
            .ok_or(Error::SizeOverflow)?;
    }
    Ok((content_start, content_len))
}

/// Calculate all future BER/CER decode work before allocating the retained value.
///
/// # Parameters and returns
/// `retained_len` is normalized content bytes; `consumed` is BER prefix bytes;
/// `canonical_len` is the shortest output size; `strict_cer` selects encoder
/// and comparison passes. Returns their byte-work sum.
///
/// # Errors
/// Returns `SizeOverflow` when the sum cannot fit `usize`.
///
/// # Source, version, history, example
/// Source: one-operation scalar budget. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: strict `BigInteger` CER.
/// Example: preflighted before the first content allocation.
fn decode_future_work(
    retained_len: usize,
    consumed: usize,
    canonical_len: usize,
    strict_cer: bool,
) -> Result<usize, Error> {
    if !strict_cer {
        return Ok(retained_len);
    }
    retained_len
        .checked_add(canonical_len)
        .and_then(|work| work.checked_add(consumed.max(canonical_len)))
        .ok_or(Error::SizeOverflow)
}

/// Encode the minimal universal INTEGER TLV under a shared scalar budget.
///
/// # Parameters and returns
/// `value` is canonical signed content; `limits` bounds final bytes; `scratch`
/// is simultaneously live allocation capacity; `budget` charges this pass.
/// Returns complete encoded bytes and bit length.
///
/// # Errors
/// Returns output/scratch/work limit, checked-size, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 DER/CER INTEGER. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: `BigInteger` codec.
/// Example: used by encoders and strict CER decoding.
fn encode_canonical(
    value: &BigInteger,
    limits: &Limits,
    scratch: usize,
    budget: &mut ScalarBudget<'_>,
) -> Result<Encoded, Error> {
    if value.signed_bytes.is_empty() {
        return Err(invalid("BigInteger invariant requires nonempty content"));
    }
    let content_len = value.signed_bytes.len();
    let total_len = encoded_integer_len(content_len)?;
    check_resource(Resource::OutputBytes, total_len, limits.max_output_bytes)?;
    check_scratch(scratch.checked_add(total_len).ok_or(Error::SizeOverflow)?)?;
    budget.charge_bytes(total_len)?;
    let mut output = reserve_bytes(total_len, limits, scratch)?;
    output.push(INTEGER_IDENTIFIER);
    write_length(&mut output, content_len)?;
    output.extend_from_slice(&value.signed_bytes);
    if output.len() != total_len {
        return Err(Error::SizeOverflow);
    }
    let bit_len = total_len.checked_mul(8).ok_or(Error::SizeOverflow)?;
    Ok(Encoded {
        bytes: output,
        bit_len,
    })
}

/// Compute the complete canonical INTEGER TLV length with checked arithmetic.
///
/// # Parameters and returns
/// `content_len` is nonzero signed content. Returns tag, shortest length field,
/// and content byte count combined.
///
/// # Errors
/// Returns `SizeOverflow` if the complete TLV length cannot be represented.
///
/// # Source, version, history, example
/// Source: X.690 definite length sizing. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: `BigInteger` codec.
/// Example: content length 128 adds a two-octet long-form length.
fn encoded_integer_len(content_len: usize) -> Result<usize, Error> {
    1_usize
        .checked_add(length_field_len(content_len))
        .and_then(|header_len| header_len.checked_add(content_len))
        .ok_or(Error::SizeOverflow)
}

/// Return the canonical length-field size for a payload length.
///
/// # Parameters and returns
/// `length` is the content octet count. Returns one short octet or a long-form
/// marker plus the minimum big-endian length octets.
///
/// # Errors
/// This calculation cannot fail.
///
/// # Source, version, history, example
/// Source: X.690 definite length form. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: `BigInteger` codec.
/// Example: length 127 uses one octet; length 128 uses two.
const fn length_field_len(length: usize) -> usize {
    if length < 128 {
        1
    } else {
        let significant_bytes = length.bit_width().div_ceil(8) as usize;
        1 + significant_bytes
    }
}

/// Append the shortest definite-length form into pre-reserved output.
///
/// # Parameters and returns
/// `output` has capacity for the complete TLV; `length` is content octets.
/// Returns success after appending the canonical length field.
///
/// # Errors
/// Returns `SizeOverflow` if a length octet count cannot be represented.
///
/// # Source, version, history, example
/// Source: X.690 DER/CER length encoding. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: `BigInteger` codec.
/// Example: called after the INTEGER identifier.
fn write_length(output: &mut Vec<u8>, length: usize) -> Result<(), Error> {
    if length < 128 {
        output.push(u8::try_from(length).map_err(|_| Error::SizeOverflow)?);
        return Ok(());
    }
    let octets = length.to_be_bytes();
    let first = octets
        .iter()
        .position(|octet| *octet != 0)
        .ok_or(Error::SizeOverflow)?;
    let count = octets.len().checked_sub(first).ok_or(Error::SizeOverflow)?;
    output.push(0x80 | u8::try_from(count).map_err(|_| Error::SizeOverflow)?);
    output.extend_from_slice(&octets[first..]);
    Ok(())
}

/// Reserve a byte vector after output and simultaneous-scratch checks.
///
/// # Parameters and returns
/// `size` is requested capacity; `limits` bounds output; `scratch` is other
/// live capacity. Returns a vector reserved fallibly for at least `size`.
///
/// # Errors
/// Returns output/scratch limit, checked-size, or allocation errors.
///
/// # Source, version, history, example
/// Source: bounded Rust allocation policy. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: `BigInteger` codec.
/// Example: called before copying signed content or writing TLV bytes.
fn reserve_bytes(size: usize, limits: &Limits, scratch: usize) -> Result<Vec<u8>, Error> {
    check_resource(Resource::OutputBytes, size, limits.max_output_bytes)?;
    check_scratch(scratch.checked_add(size).ok_or(Error::SizeOverflow)?)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(size)
        .map_err(|_| Error::AllocationFailed {
            requested_bytes: size,
        })?;
    check_scratch(
        scratch
            .checked_add(output.capacity())
            .ok_or(Error::SizeOverflow)?,
    )?;
    Ok(output)
}

/// Copy already-normalized signed content into bounded fallible storage.
///
/// # Parameters and returns
/// `bytes` is nonempty minimal signed content; `limits` caps retained bytes;
/// `scratch` is other simultaneously live capacity. Returns its owned copy.
///
/// # Errors
/// Returns output/scratch limit, checked-size, or allocation errors.
///
/// # Source, version, history, example
/// Source: `BigInteger` value storage. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: arbitrary-precision support.
/// Example: called only after redundant sign padding is removed.
pub(crate) fn copy_signed_bytes(
    bytes: &[u8],
    limits: &Limits,
    scratch: usize,
) -> Result<Vec<u8>, Error> {
    if bytes.is_empty() {
        return Err(invalid("signed INTEGER bytes must not be empty"));
    }
    let mut output = reserve_bytes(bytes.len(), limits, scratch)?;
    output.extend_from_slice(bytes);
    Ok(output)
}

/// Return the first byte that cannot be removed without changing sign/value.
///
/// # Parameters and returns
/// `bytes` is nonempty signed big-endian two's-complement content. Returns an
/// index leaving one sign byte and the shortest equivalent representation.
///
/// # Errors
/// This scan cannot fail or panic for its documented nonempty input.
///
/// # Source, version, history, example
/// Source: X.690 minimal signed INTEGER content. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: arbitrary-precision support.
/// Example: `[0, 0, 0x80]` returns index 1.
pub(crate) const fn normalized_start(bytes: &[u8]) -> usize {
    if bytes.len() <= 1 {
        return 0;
    }
    let mut start = 0;
    let last = bytes.len() - 1;
    while start < last {
        let first = bytes[start];
        let next = bytes[start + 1];
        if (first == 0 && next & 0x80 == 0) || (first == 0xff && next & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    start
}

/// Convert a minimal signed byte sequence when it fits the signed 64-bit range.
///
/// # Parameters and returns
/// `bytes` is nonempty canonical content. Returns its `i64` value when at most
/// eight sign-extended bytes are needed, otherwise `None`.
///
/// # Errors
/// This bounded conversion cannot fail or panic for valid `BigInteger` content.
///
/// # Source, version, history, example
/// Source: two's-complement sign extension. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: arbitrary-precision support.
/// Example: `[0xff]` maps to `Some(-1)`.
fn signed_bytes_to_i64(bytes: &[u8]) -> Option<i64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    let sign_byte = if bytes[0] & 0x80 == 0 { 0 } else { 0xff };
    let mut expanded = [sign_byte; 8];
    let start = expanded.len() - bytes.len();
    expanded[start..].copy_from_slice(bytes);
    Some(i64::from_be_bytes(expanded))
}

/// Require a full byte prefix to be present without unchecked slicing.
///
/// # Parameters and returns
/// `input` is the complete available slice; `required` is the minimum length.
/// Returns success if enough bytes are present.
///
/// # Errors
/// Returns `NeedMoreBytes` with required and available counts.
///
/// # Source, version, history, example
/// Source: bounded BER parser slicing. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: `BigInteger` codec.
/// Example: called before reading each identifier or length field.
const fn require_bytes(input: &[u8], required: usize) -> Result<(), Error> {
    if required > input.len() {
        return Err(Error::NeedMoreBytes {
            required_bytes: required,
            available_bytes: input.len(),
        });
    }
    Ok(())
}

/// Check a byte resource against one configured ceiling.
///
/// # Parameters and returns
/// `resource` names the budget; `requested` is the amount needed; `limit` is
/// the maximum. Returns success when the request fits.
///
/// # Errors
/// Returns `LimitExceeded` when the request is above the caller's ceiling.
///
/// # Source, version, history, example
/// Source: runtime resource error contract. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: `BigInteger` codec.
/// Example: used for input and retained/output bytes.
const fn check_resource(resource: Resource, requested: usize, limit: usize) -> Result<(), Error> {
    if requested > limit {
        return Err(Error::LimitExceeded {
            resource,
            limit,
            requested,
        });
    }
    Ok(())
}

/// Check an allocation or combined live-capacity amount against the scratch cap.
///
/// # Parameters and returns
/// `bytes` is requested or actual simultaneous capacity. Returns success when
/// it fits the fixed internal `BigInteger` scratch ceiling.
///
/// # Errors
/// Returns `LimitExceeded(OutputBytes)` when the scratch cap is exceeded.
///
/// # Source, version, history, example
/// Source: bounded scalar temporary-storage policy. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: `BigInteger` codec.
/// Example: checks retained value plus canonical CER output.
const fn check_scratch(bytes: usize) -> Result<(), Error> {
    check_resource(Resource::OutputBytes, bytes, MAX_BIG_INTEGER_SCRATCH_BYTES)
}

/// Build a malformed BER/`BigInteger` error with a static reason.
///
/// # Parameters and returns
/// `reason` explains the rejected representation. Returns `InvalidEncoding`.
///
/// # Errors
/// This helper cannot fail.
///
/// # Source, version, history, example
/// Source: runtime invalid-encoding contract. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: `BigInteger` codec.
/// Example: used for empty and noncanonical values.
const fn invalid(reason: &'static str) -> Error {
    Error::InvalidEncoding { reason }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Normalize sign extensions and convert values at the `i64` boundaries.
    /// Source: X.690 signed INTEGER two's-complement representation.
    /// Version: 2026-11-01. Inputs: padded, minimal, and wide signed values.
    /// Returns: assertions. Errors: assertion failures. Responsible: maintainers.
    /// History: `BigInteger` regression tests. Example: run with `cargo test`.
    #[test]
    fn normalizes_sign_padding_and_converts_i64() {
        let limits = Limits::default();
        let cases: &[(&[u8], &[u8], Option<i64>)] = &[
            (&[0, 0, 0x80], &[0, 0x80], Some(128)),
            (&[0xff, 0xff, 0x7f], &[0xff, 0x7f], Some(-129)),
            (&[0, 0, 0], &[0], Some(0)),
            (&[0xff, 0xff], &[0xff], Some(-1)),
            (
                &[0x80, 0, 0, 0, 0, 0, 0, 0],
                &[0x80, 0, 0, 0, 0, 0, 0, 0],
                Some(i64::MIN),
            ),
            (
                &[0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                &[0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                Some(i64::MAX),
            ),
        ];
        for (source, expected, number) in cases {
            let value = BigInteger::try_from_signed_bytes(source, &limits).unwrap();
            assert_eq!(value.as_signed_bytes(), *expected);
            assert_eq!(value.try_to_i64(), *number);
        }

        let positive_wide = [1, 0, 0, 0, 0, 0, 0, 0, 0];
        let negative_wide = [0xff, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(BigInteger::try_from_signed_bytes(&positive_wide, &limits)
            .unwrap()
            .try_to_i64()
            .is_none());
        assert!(BigInteger::try_from_signed_bytes(&negative_wide, &limits)
            .unwrap()
            .try_to_i64()
            .is_none());
    }

    /// Reject empty values and enforce constructor input, output, and work limits.
    /// Source: `BigInteger` invariant and `Limits` resource contract.
    /// Version: 2026-11-01. Inputs: empty, padded, and tight-budget values.
    /// Returns: assertions. Errors: assertion failures. Responsible: maintainers.
    /// History: `BigInteger` regression tests. Example: run with `cargo test`.
    #[test]
    fn constructor_rejects_empty_and_checks_resource_boundaries() {
        let limits = Limits::default();
        assert!(BigInteger::try_from_signed_bytes(&[], &limits).is_err());
        let exact = Limits {
            max_input_bytes: 3,
            max_output_bytes: 1,
            max_work_bits: 32,
        };
        let value = BigInteger::try_from_signed_bytes(&[0, 0, 1], &exact).unwrap();
        assert_eq!(value.as_signed_bytes(), [1]);

        let low_input = Limits {
            max_input_bytes: 2,
            ..exact
        };
        assert!(BigInteger::try_from_signed_bytes(&[0, 0, 1], &low_input).is_err());
        let low_output = Limits {
            max_output_bytes: 0,
            ..exact
        };
        assert!(BigInteger::try_from_signed_bytes(&[0, 0, 1], &low_output).is_err());
        let low_work = Limits {
            max_work_bits: 31,
            ..exact
        };
        assert!(BigInteger::try_from_signed_bytes(&[0, 0, 1], &low_work).is_err());
    }

    /// Encode shortest DER/CER content and cross the 127/128 length boundary.
    /// Source: X.690 canonical signed INTEGER and definite lengths.
    /// Version: 2026-11-01. Inputs: positive/negative and 127/128-octet content.
    /// Returns: assertions. Errors: assertion failures. Responsible: maintainers.
    /// History: `BigInteger` regression tests. Example: run with `cargo test`.
    #[test]
    fn encoders_use_minimal_sign_and_length_forms() {
        let limits = Limits::default();
        for (source, expected) in [
            (&[0, 0x80][..], &[2, 2, 0, 0x80][..]),
            (&[0xff, 0x7f][..], &[2, 2, 0xff, 0x7f][..]),
        ] {
            let value = BigInteger::try_from_signed_bytes(source, &limits).unwrap();
            let der = encode_big_integer_der(&value, &limits).unwrap();
            let cer = encode_big_integer_cer(&value, &limits).unwrap();
            assert_eq!(der.bytes, expected);
            assert_eq!(cer.bytes, expected);
            assert_eq!(der.bit_len, expected.len() * 8);
        }

        for content in [
            &[1, 0, 0, 0, 0, 0, 0, 0, 0][..],
            &[0xff, 0, 0, 0, 0, 0, 0, 0, 0][..],
        ] {
            let value = BigInteger::try_from_signed_bytes(content, &limits).unwrap();
            assert!(value.try_to_i64().is_none());
            let der = encode_big_integer_der(&value, &limits).unwrap();
            let cer = encode_big_integer_cer(&value, &limits).unwrap();
            assert_eq!(der.bytes, cer.bytes);
            assert_eq!(
                decode_big_integer_ber(&der.bytes, &limits)
                    .unwrap()
                    .value
                    .as_signed_bytes(),
                content
            );
            assert_eq!(
                decode_big_integer_cer(&cer.bytes, &limits)
                    .unwrap()
                    .value
                    .as_signed_bytes(),
                content
            );
        }

        for (content_len, prefix) in [(127, &[2, 127][..]), (128, &[2, 0x81, 128][..])] {
            let content = vec![1; content_len];
            let value = BigInteger::try_from_signed_bytes(&content, &limits).unwrap();
            let encoded = encode_big_integer_der(&value, &limits).unwrap();
            assert_eq!(&encoded.bytes[..prefix.len()], prefix);
            assert_eq!(encoded.bytes.len(), content_len + prefix.len());
            assert_eq!(
                decode_big_integer_cer(&encoded.bytes, &limits)
                    .unwrap()
                    .value
                    .as_signed_bytes(),
                content
            );
        }
    }

    /// Check complete encoder output and work ceilings at exact and lower bounds.
    /// Source: runtime output/work limits for complete primitive encodings.
    /// Version: 2026-11-01. Inputs: one-octet INTEGER with tight ceilings.
    /// Returns: assertions. Errors: assertion failures. Responsible: maintainers.
    /// History: `BigInteger` regression tests. Example: run with `cargo test`.
    #[test]
    fn encoders_check_exact_output_and_work_limits() {
        let default_limits = Limits::default();
        let value = BigInteger::try_from_signed_bytes(&[1], &default_limits).unwrap();
        let exact = Limits {
            max_output_bytes: 3,
            max_work_bits: 24,
            ..default_limits
        };
        assert_eq!(
            encode_big_integer_der(&value, &exact).unwrap().bytes,
            [2, 1, 1]
        );
        assert_eq!(
            encode_big_integer_cer(&value, &exact).unwrap().bytes,
            [2, 1, 1]
        );

        let low_output = Limits {
            max_output_bytes: 2,
            ..exact
        };
        assert!(encode_big_integer_der(&value, &low_output).is_err());
        let low_work = Limits {
            max_work_bits: 23,
            ..exact
        };
        assert!(encode_big_integer_cer(&value, &low_work).is_err());
    }

    /// Accept BER sign/length aliases, preserve suffix consumption, and reject them in CER.
    /// Source: BER compatibility and canonical CER re-encoding.
    /// Version: 2026-11-01. Inputs: padded contents, long-length aliases, suffixes.
    /// Returns: assertions. Errors: assertion failures. Responsible: maintainers.
    /// History: `BigInteger` regression tests. Example: run with `cargo test`.
    #[test]
    fn ber_normalizes_aliases_and_strict_cer_rejects_them() {
        let limits = Limits::default();
        for alias in [
            &[2, 2, 0, 2, 0xaa][..],
            &[2, 0x81, 1, 2, 0xaa][..],
            &[2, 0x82, 0, 1, 2, 0xaa][..],
        ] {
            let decoded = decode_big_integer_ber(alias, &limits).unwrap();
            assert_eq!(decoded.value.as_signed_bytes(), [2]);
            assert_eq!(decoded.consumed_bytes, alias.len() - 1);
            assert_eq!(decoded.consumed_bits, (alias.len() - 1) * 8);
            assert!(decode_big_integer_cer(alias, &limits).is_err());
        }

        for high_tag_alias in [
            &[0x1f, 2, 1, 1][..],
            &[0x1f, 0x80, 2, 1, 1][..],
            &[0x1f, 0x80, 0x80, 2, 1, 1][..],
        ] {
            let decoded = decode_big_integer_ber(high_tag_alias, &limits).unwrap();
            assert_eq!(decoded.value.as_signed_bytes(), [1]);
            assert_eq!(decoded.consumed_bytes, high_tag_alias.len());
            assert!(decode_big_integer_cer(high_tag_alias, &limits).is_err());
        }

        let canonical = [2, 1, 0xff, 0xaa];
        let decoded = decode_big_integer_cer(&canonical, &limits).unwrap();
        assert_eq!(decoded.value.as_signed_bytes(), [0xff]);
        assert_eq!(decoded.consumed_bytes, 3);
        assert_eq!(decoded.consumed_bits, 24);
    }

    /// Reject malformed or truncated primitive INTEGER framing without panics.
    /// Source: X.690 BER primitive INTEGER identifier and definite lengths.
    /// Version: 2026-11-01. Inputs: empty, wrong tag, indefinite, overflow, truncation.
    /// Returns: assertions. Errors: assertion failures. Responsible: maintainers.
    /// History: `BigInteger` regression tests. Example: run with `cargo test`.
    #[test]
    fn decoders_reject_invalid_tags_lengths_and_empty_content() {
        let limits = Limits::default();
        for malformed in [
            &[][..],
            &[2][..],
            &[4, 0][..],
            &[0x22, 0][..],
            &[2, 0x80, 0, 0][..],
            &[2, 0xff][..],
            &[2, 0x82, 0][..],
            &[2, 2, 1][..],
            &[2, 0][..],
            &[0x1f][..],
            &[0x1f, 0x80][..],
            &[0x1f, 3, 1, 1][..],
            &[0x1f, 0x84, 0x80, 0x80, 0x80, 0, 1, 1][..],
        ] {
            assert!(decode_big_integer_ber(malformed, &limits).is_err());
            assert!(decode_big_integer_cer(malformed, &limits).is_err());
        }

        let mut overflow = vec![
            2,
            0x80 | u8::try_from(std::mem::size_of::<usize>()).unwrap(),
        ];
        overflow.extend(std::iter::repeat_n(0xff, std::mem::size_of::<usize>()));
        assert!(decode_big_integer_ber(&overflow, &limits).is_err());
    }

    /// Enforce decode output/work limits and one shared strict-CER budget.
    /// Source: runtime input, retained-output, re-encode, and comparison limits.
    /// Version: 2026-11-01. Inputs: canonical prefix and tight operation budgets.
    /// Returns: assertions. Errors: assertion failures. Responsible: maintainers.
    /// History: `BigInteger` regression tests. Example: run with `cargo test`.
    #[test]
    fn decoders_check_exact_payload_and_cumulative_work_limits() {
        let defaults = Limits::default();
        let input = [2, 1, 1];
        let ber_exact = Limits {
            max_input_bytes: 3,
            max_output_bytes: 1,
            max_work_bits: 40,
        };
        assert!(decode_big_integer_ber(&input, &ber_exact).is_ok());
        let ber_low_work = Limits {
            max_work_bits: 39,
            ..ber_exact
        };
        assert!(decode_big_integer_ber(&input, &ber_low_work).is_err());

        let cer_exact = Limits {
            max_output_bytes: 3,
            max_work_bits: 88,
            ..defaults
        };
        assert!(decode_big_integer_cer(&input, &cer_exact).is_ok());
        let cer_low_work = Limits {
            max_work_bits: 87,
            ..cer_exact
        };
        assert!(decode_big_integer_cer(&input, &cer_low_work).is_err());
        let cer_low_output = Limits {
            max_output_bytes: 2,
            ..cer_exact
        };
        assert!(decode_big_integer_cer(&input, &cer_low_output).is_err());

        let suffixed = [2, 1, 1, 0xaa];
        let low_full_input = Limits {
            max_input_bytes: 3,
            ..defaults
        };
        assert!(decode_big_integer_ber(&suffixed, &low_full_input).is_err());
    }

    /// Keep deterministic malformed byte mutations bounded in both decoders.
    /// Source: parser robustness for arbitrary INTEGER identifiers and lengths.
    /// Version: 2026-11-01. Inputs: canonical, padded, and long-form seed vectors.
    /// Returns: assertions. Errors: assertion failures. Responsible: maintainers.
    /// History: `BigInteger` mutation tests. Example: run with `cargo test`.
    #[test]
    fn byte_mutations_and_truncations_do_not_panic() {
        let limits = Limits::default();
        let vectors: &[&[u8]] = &[
            &[2, 1, 0],
            &[2, 1, 0x80],
            &[2, 2, 0, 0x80],
            &[2, 0x81, 1, 0xff],
            &[2, 0x82, 0, 1, 1],
        ];
        for vector in vectors {
            for end in 0..vector.len() {
                let _ = decode_big_integer_ber(&vector[..end], &limits);
                let _ = decode_big_integer_cer(&vector[..end], &limits);
            }
            for index in 0..vector.len() {
                for bit in 0..8 {
                    let mut changed = vector.to_vec();
                    changed[index] ^= 1 << bit;
                    let _ = decode_big_integer_ber(&changed, &limits);
                    let _ = decode_big_integer_cer(&changed, &limits);
                }
            }
        }
    }
}
