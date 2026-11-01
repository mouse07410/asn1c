//! Checked BER parsing and DER/CER codecs for ENUMERATED and string primitives.
//!
//! Original source: X.690 BER/DER/CER rules and asn1c runtime behavior.
//! Version/date: first expansion, 2026-10-31. Responsible party: asn1c
//! maintainers. Example: `decode_octet_string_ber(input, &Limits::default())?`.

use crate::{BitStringValue, Decoded, Encoded, Error, Limits, Resource};

/// Maximum constructed-TLV nesting accepted by this parser.
/// Initial fixed cap aligned with the C codec's `ASN_STACK_OVERFLOW_LIMIT` (30).
const MAX_DEPTH: usize = 30;
/// Maximum CER content octets in a primitive string value or fragment.
const CER_FRAGMENT_MAX: usize = 1000;
const TAG_BIT_STRING: u64 = 3;
const TAG_OCTET_STRING: u64 = 4;
const TAG_ENUMERATED: u64 = 10;

/// Parsed BER identifier and length metadata.
struct Header {
    /// Identifier class, with zero for universal.
    class: u8,
    /// Constructed bit from the identifier.
    constructed: bool,
    /// Numeric tag, including high-tag form.
    tag: u64,
    /// Number of identifier octets as received, including permissive BER form.
    identifier_len: usize,
    /// First content octet.
    content: usize,
    /// Definite content length; `None` denotes constructed indefinite form.
    length: Option<usize>,
}

/// State used to validate unused bits across BIT STRING leaves.
struct BitState {
    /// Unused bits in the most recently appended fragment; state variable.
    unused: u8,
    /// Count of primitive leaves; state variable.
    fragments: usize,
}

/// Accumulated BIT STRING payload and final-fragment metadata.
struct BitAccumulator {
    /// Packed payload bytes collected so far; this is a state variable.
    bytes: Vec<u8>,
    /// Fragment padding/count metadata; this is a state variable.
    state: BitState,
}

/// Decode one BER ENUMERATED prefix to a signed numeric value.
///
/// # Parameters
/// `input` is an available prefix, possibly followed by unrelated bytes;
/// `limits` caps the entire input and consumed wire work.
///
/// # Returns
/// The signed numeric value and complete TLV prefix consumption.
///
/// # Errors
/// Returns truncation, malformed encoding, range, or limit errors. No panic.
///
/// # Source, version, history, example
/// Source: X.690 ENUMERATED/INTEGER rules. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: first BER expansion.
/// Example: `decode_enumerated_ber(&[10, 1, 1], limits)?`.
pub fn decode_enumerated_ber(input: &[u8], limits: &Limits) -> Result<Decoded<i64>, Error> {
    let (header, end, bits, _) = parse_root(input, TAG_ENUMERATED, false, limits)?;
    let content_end = content_end(&header)?;
    let value = signed_value(&input[header.content..content_end])?;
    Ok(Decoded {
        value,
        consumed_bits: bits,
        consumed_bytes: end,
    })
}

/// Encode a numeric ENUMERATED value using canonical DER.
///
/// # Parameters
/// `value` is the mapped number; `limits` caps output bytes and wire work.
///
/// # Returns
/// A minimal universal tag 10 TLV.
///
/// # Errors
/// Returns size, limit, or allocation errors. No panic.
///
/// # Source, version, history, example
/// Source: X.690 DER ENUMERATED rules. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: first DER expansion.
/// Example: `encode_enumerated_der(1, limits)?`.
pub fn encode_enumerated_der(value: i64, limits: &Limits) -> Result<Encoded, Error> {
    encode_signed(TAG_ENUMERATED, value, limits)
}

/// Encode a numeric ENUMERATED value using canonical CER.
///
/// # Parameters
/// `value` is the mapped number; `limits` caps output bytes and wire work.
///
/// # Returns
/// A minimal universal tag 10 TLV.
///
/// # Errors
/// Returns size, limit, or allocation errors. No panic.
///
/// # Source, version, history, example
/// Source: X.690 CER ENUMERATED rules. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: first CER expansion.
/// Example: `encode_enumerated_cer(1, limits)?`.
pub fn encode_enumerated_cer(value: i64, limits: &Limits) -> Result<Encoded, Error> {
    encode_signed(TAG_ENUMERATED, value, limits)
}

/// Strictly decode a canonical CER ENUMERATED prefix.
///
/// # Parameters
/// `input` is an available prefix; `limits` caps input, output, and work.
///
/// # Returns
/// The signed value and complete canonical TLV consumption.
///
/// # Errors
/// Returns BER errors or `InvalidEncoding` when canonical re-encoding differs.
///
/// # Source, version, history, example
/// Source: X.690 CER canonical form. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: first strict CER decoder.
/// Example: `decode_enumerated_cer(&[10, 1, 1], limits)?`.
pub fn decode_enumerated_cer(input: &[u8], limits: &Limits) -> Result<Decoded<i64>, Error> {
    let decoded = decode_enumerated_ber(input, limits)?;
    let phase_limits = limits_after_work(decoded.consumed_bits, limits)?;
    let canonical = encode_enumerated_cer(decoded.value, &phase_limits)?;
    let mut work = decoded.consumed_bits;
    charge_work(&mut work, canonical.bytes.len(), limits)?;
    ensure_canonical(
        input,
        decoded.consumed_bytes,
        &canonical.bytes,
        &mut work,
        limits,
    )?;
    Ok(decoded)
}

/// Encode OCTET STRING as a canonical DER primitive TLV.
///
/// # Parameters
/// `value` is the payload; `limits` caps output bytes and wire work.
///
/// # Returns
/// A complete universal tag 4 TLV with minimal definite length.
///
/// # Errors
/// Returns size, limit, or allocation errors. No panic.
///
/// # Source, version, history, example
/// Source: X.690 DER OCTET STRING rules. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: first DER string API.
/// Example: `encode_octet_string_der(b"abc", limits)?`.
pub fn encode_octet_string_der(value: &[u8], limits: &Limits) -> Result<Encoded, Error> {
    write_primitive(TAG_OCTET_STRING, value, limits)
}

/// Encode OCTET STRING using canonical CER fragmentation above 1000 octets.
///
/// # Parameters
/// `value` is the payload; `limits` caps output bytes and wire work.
///
/// # Returns
/// A primitive TLV through 1000 octets, otherwise indefinite constructed form.
///
/// # Errors
/// Returns size, limit, or allocation errors. No panic.
///
/// # Source, version, history, example
/// Source: X.690 CER OCTET STRING fragmentation. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: first CER string API.
/// Example: `encode_octet_string_cer(b"abc", limits)?`.
pub fn encode_octet_string_cer(value: &[u8], limits: &Limits) -> Result<Encoded, Error> {
    check(Resource::OutputBytes, value.len(), limits.max_output_bytes)?;
    if value.len() <= CER_FRAGMENT_MAX {
        return write_primitive(TAG_OCTET_STRING, value, limits);
    }
    let count = value.len().div_ceil(CER_FRAGMENT_MAX);
    let size = fragmented_size(value.len(), count, false)?;
    let mut out = new_output(size, limits)?;
    push(&mut out, &[0x24, 0x80], limits)?;
    for fragment in value.chunks(CER_FRAGMENT_MAX) {
        push_primitive(&mut out, TAG_OCTET_STRING, fragment, limits)?;
    }
    push(&mut out, &[0, 0], limits)?;
    finish(out, limits)
}

/// Decode one BER OCTET STRING prefix, flattening primitive/constructed leaves.
///
/// # Parameters
/// `input` is an available prefix; `limits` caps full input, decoded storage,
/// and consumed wire work.
///
/// # Returns
/// Concatenated payload bytes with complete TLV prefix consumption.
///
/// # Errors
/// Returns malformed nesting, tag, EOC, length, depth, size, allocation, or
/// configured-limit errors. No panic.
///
/// # Source, version, history, example
/// Source: X.690 BER constructed strings. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: first BER string API.
/// Example: `decode_octet_string_ber(&[4, 1, b'x'], limits)?`.
pub fn decode_octet_string_ber(input: &[u8], limits: &Limits) -> Result<Decoded<Vec<u8>>, Error> {
    Ok(decode_octet_ber_work(input, limits)?.0)
}

/// Decode OCTET STRING and return its actual parser work for strict CER.
///
/// # Parameters and returns
/// `input` is the available prefix; `limits` caps input, payload and traversal.
/// Returns decoded value plus cumulative parser work bits.
///
/// # Errors
/// Returns malformed BER, resource, allocation, or size errors.
///
/// # Source, version, history, example
/// Source: BER OCTET STRING decoding. Version: 2026-10-31.
/// Responsible: maintainers. History: work accounting. Example: strict CER.
fn decode_octet_ber_work(
    input: &[u8],
    limits: &Limits,
) -> Result<(Decoded<Vec<u8>>, usize), Error> {
    let (header, end, bits, mut work) = parse_root(input, TAG_OCTET_STRING, true, limits)?;
    let mut value = Vec::new();
    flatten_octets(input, &header, end, 0, &mut value, limits, &mut work)?;
    Ok((
        Decoded {
            value,
            consumed_bits: bits,
            consumed_bytes: end,
        },
        work,
    ))
}

/// Strictly decode one canonical CER OCTET STRING prefix.
///
/// # Parameters
/// `input` is an available prefix; `limits` caps input, output, and wire work.
///
/// # Returns
/// Concatenated payload and canonical TLV prefix consumption.
///
/// # Errors
/// Returns BER errors or `InvalidEncoding` if re-encoding differs.
///
/// # Source, version, history, example
/// Source: X.690 CER canonical form. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: first strict CER string decoder.
/// Example: `decode_octet_string_cer(&[4, 1, b'x'], limits)?`.
pub fn decode_octet_string_cer(input: &[u8], limits: &Limits) -> Result<Decoded<Vec<u8>>, Error> {
    let (decoded, mut work) = decode_octet_ber_work(input, limits)?;
    let phase_limits = limits_after_work(work, limits)?;
    let canonical = encode_octet_string_cer(&decoded.value, &phase_limits)?;
    charge_work(&mut work, canonical.bytes.len(), limits)?;
    ensure_canonical(
        input,
        decoded.consumed_bytes,
        &canonical.bytes,
        &mut work,
        limits,
    )?;
    Ok(decoded)
}

/// Encode a validated BIT STRING as a canonical DER primitive TLV.
///
/// # Parameters
/// `value` is the packed bit value; `limits` caps output and wire work.
///
/// # Returns
/// A universal tag 3 TLV with an initial unused-bit count octet.
///
/// # Errors
/// Returns size, limit, or allocation errors. No panic.
///
/// # Source, version, history, example
/// Source: X.690 DER BIT STRING rules. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: first DER string API.
/// Example: `encode_bit_string_der(&bits, limits)?`.
pub fn encode_bit_string_der(value: &BitStringValue, limits: &Limits) -> Result<Encoded, Error> {
    write_bit_fragment(value.as_bytes(), unused_bits(value.bit_len()), limits)
}

/// Encode BIT STRING using CER fragmentation when content exceeds 1000 octets.
///
/// # Parameters
/// `value` is the packed bit value; `limits` caps output and wire work.
///
/// # Returns
/// A primitive through 1000 content octets, otherwise constructed fragments
/// of at most 1000 content octets including each unused-count octet.
///
/// # Errors
/// Returns size, limit, or allocation errors. No panic.
///
/// # Source, version, history, example
/// Source: X.690 CER BIT STRING fragmentation. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: first CER string API.
/// Example: `encode_bit_string_cer(&bits, limits)?`.
pub fn encode_bit_string_cer(value: &BitStringValue, limits: &Limits) -> Result<Encoded, Error> {
    let bytes = value.as_bytes();
    check(Resource::OutputBytes, bytes.len(), limits.max_output_bytes)?;
    let unused = unused_bits(value.bit_len());
    let content_len = bytes.len().checked_add(1).ok_or(Error::SizeOverflow)?;
    if content_len <= CER_FRAGMENT_MAX {
        return write_bit_fragment(bytes, unused, limits);
    }
    let fragment_payload = CER_FRAGMENT_MAX - 1;
    let count = bytes.len().div_ceil(fragment_payload);
    let size = fragmented_size(bytes.len(), count, true)?;
    let mut out = new_output(size, limits)?;
    push(&mut out, &[0x23, 0x80], limits)?;
    for (index, fragment) in bytes.chunks(fragment_payload).enumerate() {
        let fragment_unused = if index + 1 == count { unused } else { 0 };
        push_bit_fragment(&mut out, fragment, fragment_unused, limits)?;
    }
    push(&mut out, &[0, 0], limits)?;
    finish(out, limits)
}

/// Decode a BER BIT STRING prefix and concatenate constructed fragments.
///
/// # Parameters
/// `input` is an available prefix; `limits` caps input, decoded storage, and
/// consumed wire work.
///
/// # Returns
/// The packed bit value and complete TLV prefix consumption.
///
/// # Errors
/// Returns malformed nesting, tag, EOC, padding, depth, size, allocation, or
/// configured-limit errors. No panic.
///
/// # Source, version, history, example
/// Source: X.690 BER BIT STRING fragments. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: first BER string API.
/// Example: `decode_bit_string_ber(&[3, 2, 0, 0xa0], limits)?`.
pub fn decode_bit_string_ber(
    input: &[u8],
    limits: &Limits,
) -> Result<Decoded<BitStringValue>, Error> {
    Ok(decode_bit_ber_work(input, limits)?.0)
}

/// Decode BIT STRING and return actual parser work for strict CER.
///
/// # Parameters and returns
/// `input` is available prefix; `limits` caps input, payload and traversal.
/// Returns decoded value plus cumulative parser work bits.
///
/// # Errors
/// Returns malformed BER, resource, allocation, or size errors.
///
/// # Source, version, history, example
/// Source: BER BIT STRING decoding. Version: 2026-10-31.
/// Responsible: maintainers. History: work accounting. Example: strict CER.
fn decode_bit_ber_work(
    input: &[u8],
    limits: &Limits,
) -> Result<(Decoded<BitStringValue>, usize), Error> {
    let (header, end, bits, mut work) = parse_root(input, TAG_BIT_STRING, true, limits)?;
    let mut value = BitAccumulator {
        bytes: Vec::new(),
        state: BitState {
            unused: 0,
            fragments: 0,
        },
    };
    flatten_bits(input, &header, end, 0, &mut value, limits, &mut work)?;
    let bit_len = value
        .bytes
        .len()
        .checked_mul(8)
        .and_then(|n| n.checked_sub(usize::from(value.state.unused)))
        .ok_or(Error::SizeOverflow)?;
    let value = BitStringValue::new(value.bytes, bit_len)?;
    Ok((
        Decoded {
            value,
            consumed_bits: bits,
            consumed_bytes: end,
        },
        work,
    ))
}

/// Strictly decode one canonical CER BIT STRING prefix.
///
/// # Parameters
/// `input` is an available prefix; `limits` caps input, output, and wire work.
///
/// # Returns
/// The packed bit value and canonical TLV prefix consumption.
///
/// # Errors
/// Returns BER errors or `InvalidEncoding` if re-encoding differs.
///
/// # Source, version, history, example
/// Source: X.690 CER canonical form. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: first strict CER string decoder.
/// Example: `decode_bit_string_cer(&[3, 2, 0, 0xa0], limits)?`.
pub fn decode_bit_string_cer(
    input: &[u8],
    limits: &Limits,
) -> Result<Decoded<BitStringValue>, Error> {
    let (decoded, mut work) = decode_bit_ber_work(input, limits)?;
    let phase_limits = limits_after_work(work, limits)?;
    let canonical = encode_bit_string_cer(&decoded.value, &phase_limits)?;
    charge_work(&mut work, canonical.bytes.len(), limits)?;
    ensure_canonical(
        input,
        decoded.consumed_bytes,
        &canonical.bytes,
        &mut work,
        limits,
    )?;
    Ok(decoded)
}

/// Parse the expected root universal tag and charge its full TLV work.
///
/// # Parameters and returns
/// `input` is the full prefix; `tag` is expected universal tag; `constructed`
/// permits constructed form; `limits` supplies budgets. Returns header, end,
/// and wire bits.
///
/// # Errors
/// Returns malformed TLV, truncation, work, input-limit, or size errors.
///
/// # Source, version, history, example
/// Source: checked BER framing. Version: 2026-10-31. Responsible: maintainers.
/// History: initial parser. Example: used by each BER primitive decoder.
fn parse_root(
    input: &[u8],
    tag: u64,
    constructed: bool,
    limits: &Limits,
) -> Result<(Header, usize, usize, usize), Error> {
    check(Resource::InputBytes, input.len(), limits.max_input_bytes)?;
    let mut work_bits = 0;
    let header = parse_header(input, 0, input.len(), &mut work_bits, true, limits)?;
    if header.class != 0 || header.tag != tag {
        return Err(invalid(
            "BER identifier does not match expected universal tag",
        ));
    }
    if header.constructed && !constructed {
        return Err(invalid(
            "BER constructed form is not valid for this primitive",
        ));
    }
    let end = scan(input, 0, input.len(), 0, &mut work_bits, false, limits)?;
    let bits = end.checked_mul(8).ok_or(Error::SizeOverflow)?;
    Ok((header, end, bits, work_bits))
}

/// Parse identifier and length while respecting the parent boundary.
///
/// # Parameters and returns
/// `input` is the complete slice; `start` is the identifier position;
/// `bound` is its parent's exclusive end; `work`, `meter`, and `limits` enforce
/// incremental parser budgets. Returns checked metadata.
///
/// # Errors
/// Returns truncation, malformed high tag/length, parent-boundary, or overflow.
///
/// # Source, version, history, example
/// Source: X.690 BER identifier/length forms. Version: 2026-10-31.
/// Responsible: maintainers. History: initial parser. Example: `parse_header(..)`.
fn parse_header(
    input: &[u8],
    start: usize,
    bound: usize,
    work: &mut usize,
    meter: bool,
    limits: &Limits,
) -> Result<Header, Error> {
    require(input, start, 1, bound)?;
    if meter {
        charge_work(work, 1, limits)?;
    }
    let first = input[start];
    let class = first >> 6;
    let constructed = first & 0x20 != 0;
    let short = u64::from(first & 0x1f);
    let mut cursor = start + 1;
    let tag = if short == 0x1f {
        let mut value = 0_u64;
        loop {
            require(input, cursor, 1, bound)?;
            if meter {
                charge_work(work, 1, limits)?;
            }
            let byte = input[cursor];
            cursor += 1;
            value = value
                .checked_mul(128)
                .and_then(|n| n.checked_add(u64::from(byte & 0x7f)))
                .ok_or(Error::SizeOverflow)?;
            if byte & 0x80 == 0 {
                break;
            }
        }
        value
    } else {
        short
    };
    let identifier_len = cursor - start;
    require(input, cursor, 1, bound)?;
    let length_byte = input[cursor];
    cursor += 1;
    let length = if length_byte == 0x80 {
        if !constructed {
            return Err(invalid("primitive BER value has indefinite length"));
        }
        None
    } else if length_byte & 0x80 == 0 {
        Some(usize::from(length_byte))
    } else {
        if length_byte == 0xff {
            return Err(invalid("BER length FF is reserved"));
        }
        let count = usize::from(length_byte & 0x7f);
        require(input, cursor, count, bound)?;
        let mut size = 0_usize;
        for byte in &input[cursor..cursor + count] {
            size = size
                .checked_mul(256)
                .and_then(|n| n.checked_add(usize::from(*byte)))
                .ok_or(Error::SizeOverflow)?;
        }
        cursor += count;
        Some(size)
    };
    Ok(Header {
        class,
        constructed,
        tag,
        identifier_len,
        content: cursor,
        length,
    })
}

/// Scan one TLV and recursively validate all constructed children and EOCs.
///
/// # Parameters and returns
/// `input` is the whole slice; `start` locates this element; `bound` is its
/// parent limit; `depth` is current nesting; `work` and `limits` charge parsing;
/// `meter` controls whether identifier work was charged by the caller.
/// Returns exclusive end index.
///
/// # Errors
/// Returns malformed child/EOC, truncation, depth, or checked-size errors.
///
/// # Source, version, history, example
/// Source: BER constructed values and EOC rules. Version: 2026-10-31.
/// Responsible: maintainers. History: initial parser. Example: called by root.
fn scan(
    input: &[u8],
    start: usize,
    bound: usize,
    depth: usize,
    work: &mut usize,
    meter: bool,
    limits: &Limits,
) -> Result<usize, Error> {
    let header = parse_header(input, start, bound, work, meter, limits)?;
    let length_octets = header.content - start - header.identifier_len;
    charge_work(work, length_octets, limits)?;
    if header.class == 0 && header.tag == 0 {
        return Err(invalid("BER EOC is outside an indefinite value"));
    }
    let Some(length) = header.length else {
        if depth >= MAX_DEPTH {
            return Err(invalid("BER nesting exceeds depth limit"));
        }
        let mut cursor = header.content;
        loop {
            require(input, cursor, 1, bound)?;
            if input[cursor] == 0 {
                require(input, cursor, 2, bound)?;
                if input[cursor + 1] == 0 {
                    charge_work(work, 2, limits)?;
                    return cursor.checked_add(2).ok_or(Error::SizeOverflow);
                }
            }
            cursor = scan(input, cursor, bound, depth + 1, work, true, limits)?;
        }
    };
    let end = header
        .content
        .checked_add(length)
        .ok_or(Error::SizeOverflow)?;
    require(input, header.content, length, bound)?;
    if !header.constructed {
        charge_work(work, length, limits)?;
        return Ok(end);
    }
    if depth >= MAX_DEPTH {
        return Err(invalid("BER nesting exceeds depth limit"));
    }
    let mut cursor = header.content;
    while cursor < end {
        cursor = scan(input, cursor, end, depth + 1, work, true, limits)?;
    }
    if cursor != end {
        return Err(invalid("BER child crosses parent boundary"));
    }
    Ok(end)
}

/// Flatten primitive OCTET STRING leaves from a structurally validated TLV.
///
/// # Parameters and returns
/// `input`, `head`, and `end` identify the TLV; `depth` bounds recursion;
/// `out` accumulates payload; `limits` caps storage; `work` charges rescans.
/// Returns success.
///
/// # Errors
/// Returns child-tag, depth, output-limit, size, or allocation errors.
///
/// # Source, version, history, example
/// Source: BER constructed OCTET STRING. Version: 2026-10-31.
/// Responsible: maintainers. History: initial string decoder. Example: root use.
fn flatten_octets(
    input: &[u8],
    head: &Header,
    end: usize,
    depth: usize,
    out: &mut Vec<u8>,
    limits: &Limits,
    work: &mut usize,
) -> Result<(), Error> {
    if !head.constructed {
        let stop = content_end(head)?;
        charge_work(work, stop - head.content, limits)?;
        append_payload(out, &input[head.content..stop], limits)?;
        return Ok(());
    }
    if depth >= MAX_DEPTH {
        return Err(invalid("BER string nesting exceeds depth limit"));
    }
    let bound = head
        .length
        .map_or_else(|| end.saturating_sub(2), |n| head.content + n);
    let mut cursor = head.content;
    while cursor < bound {
        if is_eoc(input, cursor, end) {
            break;
        }
        let child = parse_header(input, cursor, bound, work, true, limits)?;
        if child.class != 0 || child.tag != TAG_OCTET_STRING {
            return Err(invalid("constructed OCTET STRING contains another tag"));
        }
        let child_end = scan(input, cursor, bound, depth + 1, work, false, limits)?;
        flatten_octets(input, &child, child_end, depth + 1, out, limits, work)?;
        cursor = child_end;
    }
    Ok(())
}

/// Flatten primitive BIT STRING leaves while enforcing non-final padding rules.
///
/// # Parameters and returns
/// `input`, `head`, and `end` locate the TLV; `depth` bounds recursion;
/// `value` accumulates payload and fragment state; `limits` caps storage;
/// `work` charges rescans. Returns success.
///
/// # Errors
/// Returns malformed tags or unused counts, depth, limit, size, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 BER BIT STRING fragments. Version: 2026-10-31.
/// Responsible: maintainers. History: initial string decoder. Example: root use.
fn flatten_bits(
    input: &[u8],
    head: &Header,
    end: usize,
    depth: usize,
    value: &mut BitAccumulator,
    limits: &Limits,
    work: &mut usize,
) -> Result<(), Error> {
    if !head.constructed {
        let stop = content_end(head)?;
        let content = &input[head.content..stop];
        if content.is_empty() {
            return Err(invalid("BIT STRING lacks unused-bit count"));
        }
        let unused = content[0];
        let payload = &content[1..];
        validate_bits(payload, unused)?;
        if value.state.fragments > 0 && value.state.unused != 0 {
            return Err(invalid("non-final BIT STRING fragment has unused bits"));
        }
        let offset = value.bytes.len();
        charge_work(work, payload.len(), limits)?;
        append_payload(&mut value.bytes, payload, limits)?;
        if unused > 0 && !payload.is_empty() {
            charge_work(work, 1, limits)?;
        }
        normalize_padding_at(&mut value.bytes, offset, payload.len(), unused);
        value.state.fragments = value
            .state
            .fragments
            .checked_add(1)
            .ok_or(Error::SizeOverflow)?;
        value.state.unused = unused;
        return Ok(());
    }
    if depth >= MAX_DEPTH {
        return Err(invalid("BER BIT STRING nesting exceeds depth limit"));
    }
    let bound = head
        .length
        .map_or_else(|| end.saturating_sub(2), |n| head.content + n);
    let mut cursor = head.content;
    while cursor < bound {
        if is_eoc(input, cursor, end) {
            break;
        }
        let child = parse_header(input, cursor, bound, work, true, limits)?;
        if child.class != 0 || child.tag != TAG_BIT_STRING {
            return Err(invalid("constructed BIT STRING contains another tag"));
        }
        let child_end = scan(input, cursor, bound, depth + 1, work, false, limits)?;
        flatten_bits(input, &child, child_end, depth + 1, value, limits, work)?;
        cursor = child_end;
    }
    Ok(())
}

/// Detect the only valid EOC encoding at a known input position.
///
/// # Parameters and returns
/// `input` is the full slice; `offset` is candidate position; `end` is TLV end.
/// Returns true for two zero octets in range.
///
/// # Errors
/// Cannot fail or raise.
///
/// # Source, version, history, example
/// Source: X.690 BER EOC. Version: 2026-10-31. Responsible: maintainers.
/// History: initial parser. Example: called while flattening indefinite values.
fn is_eoc(input: &[u8], offset: usize, end: usize) -> bool {
    offset
        .checked_add(1)
        .is_some_and(|next| next < end && input[offset] == 0 && input[next] == 0)
}

/// Convert minimal or redundantly sign-extended BER contents to an i64.
///
/// # Parameters and returns
/// `bytes` are signed two's-complement content octets; returns represented i64.
///
/// # Errors
/// Returns `InvalidEncoding` for empty or out-of-range content. No panic.
///
/// # Source, version, history, example
/// Source: X.690 signed integer content. Version: 2026-10-31.
/// Responsible: maintainers. History: direct ENUMERATED support.
/// Example: `signed_value(&[0xff])? == -1`.
fn signed_value(bytes: &[u8]) -> Result<i64, Error> {
    if bytes.is_empty() {
        return Err(invalid("ENUMERATED content is empty"));
    }
    let mut significant = bytes;
    while significant.len() > 8 {
        let first = significant[0];
        let next = significant[1];
        if !((first == 0 && next & 0x80 == 0) || (first == 0xff && next & 0x80 != 0)) {
            return Err(invalid("ENUMERATED value exceeds i64 range"));
        }
        significant = &significant[1..];
    }
    let sign = if significant[0] & 0x80 != 0 { 0xff } else { 0 };
    let mut full = [sign; 8];
    full[8 - significant.len()..].copy_from_slice(significant);
    Ok(i64::from_be_bytes(full))
}

/// Encode a signed value as minimal canonical universal TLV.
///
/// # Parameters and returns
/// `tag` selects the universal tag; `value` is signed; `limits` bounds output.
/// Returns the complete DER/CER encoding.
///
/// # Errors
/// Returns invalid-size, limit, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 canonical signed integer content. Version: 2026-10-31.
/// Responsible: maintainers. History: shared ENUMERATED encoder.
/// Example: `encode_signed(TAG_ENUMERATED, 4, limits)?`.
fn encode_signed(tag: u64, value: i64, limits: &Limits) -> Result<Encoded, Error> {
    let bytes = value.to_be_bytes();
    let mut first = 0;
    while first < 7 {
        let a = bytes[first];
        let b = bytes[first + 1];
        if (a == 0 && b & 0x80 == 0) || (a == 0xff && b & 0x80 != 0) {
            first += 1;
        } else {
            break;
        }
    }
    write_primitive(tag, &bytes[first..], limits)
}

/// Write a canonical primitive universal TLV.
///
/// # Parameters and returns
/// `tag` is a universal number; `contents` is payload; `limits` sets ceilings.
/// Returns a complete minimal definite-length TLV.
///
/// # Errors
/// Returns checked-size, limit, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 DER/CER identifier and length rules. Version: 2026-10-31.
/// Responsible: maintainers. History: initial writer. Example: used by DER API.
fn write_primitive(tag: u64, contents: &[u8], limits: &Limits) -> Result<Encoded, Error> {
    let size = identifier_size(tag)?
        .checked_add(length_size(contents.len()))
        .and_then(|n| n.checked_add(contents.len()))
        .ok_or(Error::SizeOverflow)?;
    let mut out = new_output(size, limits)?;
    push_identifier(&mut out, false, tag, limits)?;
    push_length(&mut out, contents.len(), limits)?;
    push(&mut out, contents, limits)?;
    finish(out, limits)
}

/// Write a primitive BIT STRING TLV with its leading unused-bit count.
///
/// # Parameters and returns
/// `payload` holds packed bits; `unused` is 0..=7; `limits` caps output.
/// Returns one complete primitive TLV.
///
/// # Errors
/// Returns invalid padding, size, limit, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 BIT STRING encoding. Version: 2026-10-31.
/// Responsible: maintainers. History: initial writer. Example: DER API calls it.
fn write_bit_fragment(payload: &[u8], unused: u8, limits: &Limits) -> Result<Encoded, Error> {
    validate_bits(payload, unused)?;
    let content_len = payload.len().checked_add(1).ok_or(Error::SizeOverflow)?;
    let size = 1_usize
        .checked_add(length_size(content_len))
        .and_then(|n| n.checked_add(content_len))
        .ok_or(Error::SizeOverflow)?;
    let mut out = new_output(size, limits)?;
    push_bit_fragment(&mut out, payload, unused, limits)?;
    finish(out, limits)
}

/// Append one primitive BIT STRING fragment to an output buffer.
///
/// # Parameters and returns
/// `out` receives bytes; `payload` is packed data; `unused` is its count;
/// `limits` caps complete output. Returns success.
///
/// # Errors
/// Returns invalid padding, limit, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 BIT STRING fragment content. Version: 2026-10-31.
/// Responsible: maintainers. History: initial writer. Example: CER API calls it.
fn push_bit_fragment(
    out: &mut Vec<u8>,
    payload: &[u8],
    unused: u8,
    limits: &Limits,
) -> Result<(), Error> {
    validate_bits(payload, unused)?;
    let size = payload.len().checked_add(1).ok_or(Error::SizeOverflow)?;
    push_identifier(out, false, TAG_BIT_STRING, limits)?;
    push_length(out, size, limits)?;
    push(out, &[unused], limits)?;
    push(out, payload, limits)
}

/// Append one primitive string fragment with a definite length.
///
/// # Parameters and returns
/// `out` is the output; `tag` is its universal number; `fragment` is payload;
/// `limits` caps output. Returns success.
///
/// # Errors
/// Returns limit, size, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 primitive string TLVs. Version: 2026-10-31.
/// Responsible: maintainers. History: initial writer. Example: CER OCTET API.
fn push_primitive(
    out: &mut Vec<u8>,
    tag: u64,
    fragment: &[u8],
    limits: &Limits,
) -> Result<(), Error> {
    push_identifier(out, false, tag, limits)?;
    push_length(out, fragment.len(), limits)?;
    push(out, fragment, limits)
}

/// Compute exact encoded size for the CER constructed string framing.
///
/// # Parameters and returns
/// `payload_len` is data octets; `fragments` is leaf count; `bits` adds one
/// count octet per BIT fragment. Returns exact total output bytes.
///
/// # Errors
/// Returns `SizeOverflow` on arithmetic overflow.
///
/// # Source, version, history, example
/// Source: X.690 CER fragment form. Version: 2026-10-31.
/// Responsible: maintainers. History: initial writer. Example: CER encoders.
fn fragmented_size(payload_len: usize, fragments: usize, bits: bool) -> Result<usize, Error> {
    if fragments == 0 {
        return Err(Error::SizeOverflow);
    }
    let capacity = if bits {
        CER_FRAGMENT_MAX - 1
    } else {
        CER_FRAGMENT_MAX
    };
    let full_payload = capacity
        .checked_mul(fragments - 1)
        .ok_or(Error::SizeOverflow)?;
    if full_payload >= payload_len {
        return Err(Error::SizeOverflow);
    }
    let last_payload = payload_len - full_payload;
    let full_content = capacity
        .checked_add(usize::from(bits))
        .ok_or(Error::SizeOverflow)?;
    let last_content = last_payload
        .checked_add(usize::from(bits))
        .ok_or(Error::SizeOverflow)?;
    let full_size = (fragments - 1)
        .checked_mul(1 + length_size(full_content) + full_content)
        .ok_or(Error::SizeOverflow)?;
    4_usize
        .checked_add(full_size)
        .and_then(|n| n.checked_add(1 + length_size(last_content) + last_content))
        .ok_or(Error::SizeOverflow)
}

/// Append shortest universal identifier, including high-tag form.
///
/// # Parameters and returns
/// `out` receives bytes; `constructed` selects form; `tag` is numeric tag;
/// `limits` caps output. Returns success.
///
/// # Errors
/// Returns size, output-limit, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 identifier encoding. Version: 2026-10-31.
/// Responsible: maintainers. History: canonical writer. Example: tag 4.
fn push_identifier(
    out: &mut Vec<u8>,
    constructed: bool,
    tag: u64,
    limits: &Limits,
) -> Result<(), Error> {
    let form = if constructed { 0x20 } else { 0 };
    if tag < 31 {
        return push(
            out,
            &[form | u8::try_from(tag).map_err(|_| Error::SizeOverflow)?],
            limits,
        );
    }
    push(out, &[form | 0x1f], limits)?;
    let mut groups = [0_u8; 10];
    let mut n = 0;
    let mut value = tag;
    loop {
        groups[n] = (value & 0x7f) as u8;
        n += 1;
        value >>= 7;
        if value == 0 {
            break;
        }
    }
    for index in (0..n).rev() {
        let more = if index > 0 { 0x80 } else { 0 };
        push(out, &[groups[index] | more], limits)?;
    }
    Ok(())
}

/// Append a shortest definite length field.
///
/// # Parameters and returns
/// `out` receives length octets; `length` is content size; `limits` caps output.
/// Returns success.
///
/// # Errors
/// Returns output-limit or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 BER definite lengths. Version: 2026-10-31.
/// Responsible: maintainers. History: canonical writer. Example: length 128.
fn push_length(out: &mut Vec<u8>, length: usize, limits: &Limits) -> Result<(), Error> {
    if length < 128 {
        return push(
            out,
            &[u8::try_from(length).map_err(|_| Error::SizeOverflow)?],
            limits,
        );
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .ok_or(Error::SizeOverflow)?;
    let count = bytes.len() - first;
    push(
        out,
        &[0x80 | u8::try_from(count).map_err(|_| Error::SizeOverflow)?],
        limits,
    )?;
    push(out, &bytes[first..], limits)
}

/// Append bytes after checking output budget and reserving fallibly.
///
/// # Parameters and returns
/// `out` is the growing vector; `bytes` is appended; `limits` caps total output.
/// Returns success.
///
/// # Errors
/// Returns `LimitExceeded`, `SizeOverflow`, or `AllocationFailed`.
///
/// # Source, version, history, example
/// Source: bounded Rust output safety. Version: 2026-10-31.
/// Responsible: maintainers. History: first writer. Example: all append paths.
fn push(out: &mut Vec<u8>, bytes: &[u8], limits: &Limits) -> Result<(), Error> {
    let next = out
        .len()
        .checked_add(bytes.len())
        .ok_or(Error::SizeOverflow)?;
    check(Resource::OutputBytes, next, limits.max_output_bytes)?;
    out.try_reserve(bytes.len())
        .map_err(|_| Error::AllocationFailed {
            requested_bytes: next,
        })?;
    out.extend_from_slice(bytes);
    Ok(())
}

/// Allocate a checked output vector with capacity for one complete encoding.
///
/// # Parameters and returns
/// `size` is expected output bytes; `limits` supplies output/work ceilings.
/// Returns a fallibly reserved vector.
///
/// # Errors
/// Returns configured limit, arithmetic, or allocation errors.
///
/// # Source, version, history, example
/// Source: bounded Rust output safety. Version: 2026-10-31.
/// Responsible: maintainers. History: first writer. Example: primitive writer.
fn new_output(size: usize, limits: &Limits) -> Result<Vec<u8>, Error> {
    check(Resource::OutputBytes, size, limits.max_output_bytes)?;
    let work = size.checked_mul(8).ok_or(Error::SizeOverflow)?;
    check(Resource::WorkBits, work, limits.max_work_bits)?;
    let mut out = Vec::new();
    out.try_reserve_exact(size)
        .map_err(|_| Error::AllocationFailed {
            requested_bytes: size,
        })?;
    Ok(out)
}

/// Finalize output and derive its octet-aligned bit length.
///
/// # Parameters and returns
/// `bytes` is complete TLV; `limits` supplies final ceilings. Returns `Encoded`.
///
/// # Errors
/// Returns size or resource-limit errors.
///
/// # Source, version, history, example
/// Source: runtime `Encoded` contract. Version: 2026-10-31.
/// Responsible: maintainers. History: first writer. Example: output helpers.
fn finish(bytes: Vec<u8>, limits: &Limits) -> Result<Encoded, Error> {
    let bits = bytes.len().checked_mul(8).ok_or(Error::SizeOverflow)?;
    check(Resource::OutputBytes, bytes.len(), limits.max_output_bytes)?;
    check(Resource::WorkBits, bits, limits.max_work_bits)?;
    Ok(Encoded {
        bytes,
        bit_len: bits,
    })
}

/// Return shortest identifier length for a universal tag number.
///
/// # Parameters and returns
/// `tag` is the number; returns 1 for low tags and shortest high-tag length.
///
/// # Errors
/// Returns overflow if calculation cannot be represented.
///
/// # Source, version, history, example
/// Source: X.690 high-tag form. Version: 2026-10-31.
/// Responsible: maintainers. History: canonical writer. Example: tag 3 is 1.
fn identifier_size(tag: u64) -> Result<usize, Error> {
    if tag < 31 {
        return Ok(1);
    }
    let bits = 64_usize
        .checked_sub(tag.leading_zeros() as usize)
        .ok_or(Error::SizeOverflow)?;
    1_usize
        .checked_add(bits.div_ceil(7))
        .ok_or(Error::SizeOverflow)
}

/// Return shortest definite length-field byte count.
///
/// # Parameters and returns
/// `length` is content size; returns one byte for short form or count plus data.
///
/// # Errors
/// Cannot fail.
///
/// # Source, version, history, example
/// Source: X.690 length forms. Version: 2026-10-31.
/// Responsible: maintainers. History: canonical writer. Example: 128 maps to 2.
const fn length_size(length: usize) -> usize {
    if length < 128 {
        return 1;
    }
    let bits = length.bit_width();
    1 + bits.div_ceil(8) as usize
}

/// Validate BIT STRING unused count and low padding bits.
///
/// # Parameters and returns
/// `payload` is packed octets and `unused` is the count. Returns success.
///
/// # Errors
/// Returns `InvalidEncoding` for count/padding violations.
///
/// # Source, version, history, example
/// Source: X.690 BIT STRING unused-count rules. Version: 2026-10-31.
/// Responsible: maintainers. History: first string API. Example: empty/partial.
const fn validate_bits(payload: &[u8], unused: u8) -> Result<(), Error> {
    if unused > 7 || (payload.is_empty() && unused != 0) {
        return Err(invalid("BIT STRING unused-bit count is invalid"));
    }
    Ok(())
}

/// Compute final octet unused bits from a validated logical bit count.
///
/// # Parameters and returns
/// `bit_len` is meaningful bits; returns an integer from 0 to 7.
///
/// # Errors
/// Cannot fail.
///
/// # Source, version, history, example
/// Source: packed ASN.1 BIT STRING. Version: 2026-10-31.
/// Responsible: maintainers. History: first encoder. Example: length 3 gives 5.
const fn unused_bits(bit_len: usize) -> u8 {
    match bit_len % 8 {
        0 => 0,
        1 => 7,
        2 => 6,
        3 => 5,
        4 => 4,
        5 => 3,
        6 => 2,
        _ => 1,
    }
}

/// Return the checked exclusive end of a definite value's content.
///
/// # Parameters and returns
/// `head` is parsed TLV metadata; returns content offset plus length.
///
/// # Errors
/// Returns malformed indefinite content or checked-size error.
///
/// # Source, version, history, example
/// Source: checked BER parsing. Version: 2026-10-31.
/// Responsible: maintainers. History: initial parser. Example: primitive decode.
fn content_end(head: &Header) -> Result<usize, Error> {
    head.length
        .and_then(|n| head.content.checked_add(n))
        .ok_or_else(|| invalid("primitive content requires definite length"))
}

/// Append decoded semantic bytes within output and allocation ceilings.
///
/// # Parameters and returns
/// `out` is payload storage; `payload` is a source slice; `limits` caps bytes.
/// Returns success.
///
/// # Errors
/// Returns configured limit, overflow, or allocation error.
///
/// # Source, version, history, example
/// Source: bounded Rust decode allocation. Version: 2026-10-31.
/// Responsible: maintainers. History: first string API. Example: flattening.
fn append_payload(out: &mut Vec<u8>, payload: &[u8], limits: &Limits) -> Result<(), Error> {
    let next = out
        .len()
        .checked_add(payload.len())
        .ok_or(Error::SizeOverflow)?;
    check(Resource::OutputBytes, next, limits.max_output_bytes)?;
    out.try_reserve(payload.len())
        .map_err(|_| Error::AllocationFailed {
            requested_bytes: next,
        })?;
    out.extend_from_slice(payload);
    Ok(())
}

/// Ensure strict CER input matches the re-encoded canonical prefix.
///
/// # Parameters and returns
/// `input` is available data, `used` is decoded TLV size, and `canonical` is
/// output; `work` accumulates operation bits; `limits` supplies its ceiling.
/// Returns success for exact byte equality.
///
/// # Errors
/// Returns `InvalidEncoding` on mismatch.
///
/// # Source, version, history, example
/// Source: CER canonicality by BER decode/re-encode. Version: 2026-10-31.
/// Responsible: maintainers. History: first strict decoder. Example: CER APIs.
fn ensure_canonical(
    input: &[u8],
    used: usize,
    canonical: &[u8],
    work: &mut usize,
    limits: &Limits,
) -> Result<(), Error> {
    charge_work(work, used.max(canonical.len()), limits)?;
    if input.get(..used) != Some(canonical) {
        return Err(invalid("CER differs from canonical re-encoding"));
    }
    Ok(())
}

/// Require a bounded byte range to be present in input and its parent.
///
/// # Parameters and returns
/// `input` is the full slice; `start`, `size` describe range; `bound` caps it.
/// Returns success when available.
///
/// # Errors
/// Returns `NeedMoreBytes`, `InvalidEncoding`, or `SizeOverflow`.
///
/// # Source, version, history, example
/// Source: BER parser safe slicing. Version: 2026-10-31.
/// Responsible: maintainers. History: initial parser. Example: parse header.
fn require(input: &[u8], start: usize, size: usize, bound: usize) -> Result<(), Error> {
    let end = start.checked_add(size).ok_or(Error::SizeOverflow)?;
    if end > bound {
        if end > input.len() {
            return Err(Error::NeedMoreBytes {
                required_bytes: end,
                available_bytes: input.len(),
            });
        }
        return Err(invalid("BER child crosses parent boundary"));
    }
    if end > input.len() {
        return Err(Error::NeedMoreBytes {
            required_bytes: end,
            available_bytes: input.len(),
        });
    }
    Ok(())
}

/// Check a requested resource against its configured ceiling.
///
/// # Parameters and returns
/// `resource` names the budget; `used` is requested amount; `limit` is maximum.
/// Returns success when usage fits.
///
/// # Errors
/// Returns `LimitExceeded` when requested amount is greater than limit.
///
/// # Source, version, history, example
/// Source: runtime resource contract. Version: 2026-10-31.
/// Responsible: maintainers. History: first BER API. Example: work check.
const fn check(resource: Resource, used: usize, limit: usize) -> Result<(), Error> {
    if used > limit {
        return Err(Error::LimitExceeded {
            resource,
            limit,
            requested: used,
        });
    }
    Ok(())
}

/// Construct an invalid-encoding error with a static reason.
///
/// # Parameters and returns
/// `reason` explains malformed data; returns the typed error.
///
/// # Errors
/// Cannot fail.
///
/// # Source, version, history, example
/// Source: runtime error contract. Version: 2026-10-31.
/// Responsible: maintainers. History: first BER API. Example: `invalid("bad")`.
const fn invalid(reason: &'static str) -> Error {
    Error::InvalidEncoding { reason }
}

/// Clear unused low bits in one just-appended BIT STRING fragment.
///
/// # Parameters and returns
/// `bytes` is output; `offset` and `len` identify its fragment; `unused` is
/// padding count. Mutates its final fragment byte when applicable.
///
/// # Errors
/// Cannot fail; caller supplies a range created by a successful append.
///
/// # Source, version, history, example
/// Source: C BER compatibility in `OCTET_STRING_ber.c`. Version: 2026-10-31.
/// Responsible: maintainers. History: C parity. Example: called by flattener.
const fn normalize_padding_at(bytes: &mut [u8], offset: usize, len: usize, unused: u8) {
    if unused > 0 && len > 0 {
        let index = offset + len - 1;
        bytes[index] &= !((1_u8 << unused) - 1);
    }
}

/// Charge BER parser work as header, payload, or EOC octets are visited.
///
/// # Parameters and returns
/// `work` accumulates bits; `bytes` is newly examined octets; `limits` caps work.
/// Returns success if the cumulative request is permitted.
///
/// # Errors
/// Returns `SizeOverflow` or work `LimitExceeded`.
///
/// # Source, version, history, example
/// Source: runtime work budget. Version: 2026-10-31. Responsible: maintainers.
/// History: incremental BER parser checks. Example: called during scanning.
fn charge_work(work: &mut usize, bytes: usize, limits: &Limits) -> Result<(), Error> {
    let add = bytes.checked_mul(8).ok_or(Error::SizeOverflow)?;
    let total = work.checked_add(add).ok_or(Error::SizeOverflow)?;
    check(Resource::WorkBits, total, limits.max_work_bits)?;
    *work = total;
    Ok(())
}

/// Check strict CER parse and canonical re-encoding work cumulatively.
///
/// # Parameters and returns
/// `used` is parser work; `limits` supplies the common ceiling. Returns a copy
/// with only the unspent work budget available to canonical re-encoding.
///
/// # Errors
/// Returns `SizeOverflow` or work `LimitExceeded`.
///
/// # Source, version, history, example
/// Source: bounded strict CER operation policy. Version: 2026-10-31.
/// Responsible: maintainers. History: cumulative strict check. Example: CER APIs.
const fn limits_after_work(used: usize, limits: &Limits) -> Result<Limits, Error> {
    if used > limits.max_work_bits {
        return Err(Error::LimitExceeded {
            resource: Resource::WorkBits,
            limit: limits.max_work_bits,
            requested: used,
        });
    }
    let mut remaining = *limits;
    remaining.max_work_bits -= used;
    Ok(remaining)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cover signed values, redundant BER sign octets, and CER rejection.
    /// Source: X.690 ENUMERATED; version: 2026-10-31; inputs: i64 edges.
    /// Returns: assertions; errors: assertion failures; responsible: maintainers.
    /// History: first BER expansion. Example: run via `cargo test`.
    #[test]
    fn enumerated_round_trip_and_canonical_rejection() {
        let limits = Limits::default();
        for n in [i64::MIN, -129, -1, 0, 127, 128, i64::MAX] {
            let der = encode_enumerated_der(n, &limits).unwrap();
            assert_eq!(der, encode_enumerated_cer(n, &limits).unwrap());
            assert_eq!(decode_enumerated_ber(&der.bytes, &limits).unwrap().value, n);
            assert_eq!(decode_enumerated_cer(&der.bytes, &limits).unwrap().value, n);
        }
        assert_eq!(
            decode_enumerated_ber(&[10, 2, 0, 1], &limits)
                .unwrap()
                .value,
            1
        );
        assert!(decode_enumerated_cer(&[10, 2, 0, 1], &limits).is_err());
        assert!(decode_enumerated_ber(&[10, 0x80, 0, 0], &limits).is_err());
        assert!(decode_enumerated_ber(&[10, 0xff], &limits).is_err());
        assert!(decode_enumerated_ber(&[10, 9, 1, 2], &limits).is_err());
    }

    /// Cover constructed strings, EOC nesting, high tags, and malformed lengths.
    /// Source: X.690 BER strings; version: 2026-10-31; inputs: definite/indefinite.
    /// Returns: assertions; errors: assertion failures; responsible: maintainers.
    /// History: first BER expansion. Example: run via `cargo test`.
    #[test]
    fn octet_ber_constructed_and_checked_tlv_forms() {
        let limits = Limits::default();
        let inputs: &[&[u8]] = &[
            &[4, 3, b'a', b'b', b'c'],
            &[0x24, 6, 4, 1, b'a', 4, 1, b'b'],
            &[0x24, 0x80, 4, 1, b'a', 4, 1, b'b', 0, 0],
            &[0x24, 0x80, 0, 0],
        ];
        let expected: &[&[u8]] = &[b"abc", b"ab", b"ab", b""];
        for (input, value) in inputs.iter().zip(expected) {
            assert_eq!(
                decode_octet_string_ber(input, &limits).unwrap().value,
                *value
            );
        }
        assert_eq!(
            decode_octet_string_ber(&[0x24, 0x80, 0, 0], &limits)
                .unwrap()
                .consumed_bytes,
            4
        );
        // BER accepts high-tag encodings of low tags; canonical CER rejects them.
        assert_eq!(
            decode_octet_string_ber(&[0x1f, 0x80, 4, 1, 0xaa], &limits)
                .unwrap()
                .value,
            [0xaa]
        );
        assert!(decode_octet_string_cer(&[0x1f, 4, 1, 0xaa], &limits).is_err());
        assert!(decode_octet_string_ber(&[0x24, 0x80, 4, 1, b'x'], &limits).is_err());
        assert!(decode_octet_string_ber(&[4, 0x80, 0, 0], &limits).is_err());
        assert!(decode_octet_string_ber(&[4, 0xff], &limits).is_err());
        assert!(decode_octet_string_ber(&[4, 0x82, 0, 4, 1], &limits).is_err());
        assert!(decode_octet_string_ber(&[0x24, 2, 0, 0], &limits).is_err());
        assert!(decode_octet_string_ber(&[0x1f, 0x81], &limits).is_err());
        let mut overflow_tag = vec![0x1f];
        overflow_tag.extend([0xff; 10]);
        overflow_tag.push(0);
        assert!(decode_octet_string_ber(&overflow_tag, &limits).is_err());
        let mut overflow_length = vec![4, 0x89];
        overflow_length.extend([0xff; 9]);
        assert!(decode_octet_string_ber(&overflow_length, &limits).is_err());
        assert_eq!(
            decode_octet_string_ber(&[4, 0x82, 0, 1, 0xaa], &limits)
                .unwrap()
                .value,
            [0xaa]
        );
    }

    /// Check CER primitive boundaries, fragmentation, and strict canonicality.
    /// Source: X.690 CER strings; version: 2026-10-31; inputs: 1000/1001 edges.
    /// Returns: assertions; errors: assertion failures; responsible: maintainers.
    /// History: first CER expansion. Example: run via `cargo test`.
    #[test]
    fn octet_cer_fragmentation_and_strict_decode() {
        let limits = Limits::default();
        for size in [0, 127, 128, 999, 1000, 1001, 2001] {
            let value = vec![0x5a; size];
            let encoded = encode_octet_string_cer(&value, &limits).unwrap();
            assert_eq!(
                decode_octet_string_cer(&encoded.bytes, &limits)
                    .unwrap()
                    .value,
                value
            );
        }
        assert_eq!(
            encode_octet_string_cer(&vec![0; 1000], &limits)
                .unwrap()
                .bytes[0],
            4
        );
        assert_eq!(
            encode_octet_string_cer(&vec![0; 1001], &limits)
                .unwrap()
                .bytes[0],
            0x24
        );
        assert!(decode_octet_string_cer(&[4, 0x81, 1, 0x5a], &limits).is_err());
        assert!(decode_octet_string_cer(&[0x24, 0x80, 4, 1, 0x5a, 0, 0], &limits).is_err());
        assert!(decode_octet_string_cer(&[0x24, 0x80, 0, 0], &limits).is_err());
    }

    /// Check BIT STRING padding normalization, fragment rules, and CER forms.
    /// Source: X.690 BIT STRING; version: 2026-10-31; inputs: empty/partial/large.
    /// Returns: assertions; errors: assertion failures; responsible: maintainers.
    /// History: first BER expansion. Example: run via `cargo test`.
    #[test]
    fn bit_string_ber_and_cer_canonicality() {
        let limits = Limits::default();
        let permissive = decode_bit_string_ber(&[3, 2, 3, 0xa7], &limits).unwrap();
        assert_eq!(permissive.value.as_bytes(), &[0xa0]);
        assert_eq!(permissive.value.bit_len(), 5);
        assert!(decode_bit_string_cer(&[3, 2, 3, 0xa7], &limits).is_err());
        for (bytes, bits) in [(vec![], 0), (vec![0xa0], 3), (vec![0xff; 1000], 8000)] {
            let value = BitStringValue::new(bytes, bits).unwrap();
            let der = encode_bit_string_der(&value, &limits).unwrap();
            assert_eq!(
                decode_bit_string_ber(&der.bytes, &limits).unwrap().value,
                value
            );
            let cer = encode_bit_string_cer(&value, &limits).unwrap();
            assert_eq!(
                decode_bit_string_cer(&cer.bytes, &limits).unwrap().value,
                value
            );
        }
        let fragmented = BitStringValue::new(vec![0xa0; 1000], 7995).unwrap();
        let cer = encode_bit_string_cer(&fragmented, &limits).unwrap();
        assert_eq!(cer.bytes[0], 0x23);
        assert_eq!(
            decode_bit_string_cer(&cer.bytes, &limits).unwrap().value,
            fragmented
        );
        assert!(decode_bit_string_ber(&[3, 1, 1], &limits).is_err());
        assert!(decode_bit_string_ber(&[3, 2, 8, 0], &limits).is_err());
        assert!(decode_bit_string_ber(&[0x23, 6, 3, 2, 1, 0x80, 3, 0], &limits).is_err());
    }

    /// Ensure parser depth and operation budgets reject work incrementally.
    /// Source: BER safety limits; version: 2026-10-31; inputs: nested TLVs.
    /// Returns: assertions; errors: assertion failures; responsible: maintainers.
    /// History: first BER expansion. Example: run via `cargo test`.
    #[test]
    fn depth_and_resource_limits() {
        let limits = Limits::default();
        let mut nested = vec![0x24, 0x80];
        for _ in 0..=MAX_DEPTH {
            nested.extend_from_slice(&[0x24, 0x80]);
        }
        nested.extend_from_slice(&[4, 0, 0, 0]);
        assert!(decode_octet_string_ber(&nested, &limits).is_err());
        let no_work = Limits {
            max_work_bits: 0,
            ..limits
        };
        assert!(decode_octet_string_ber(&[0x24, 0x80, 4, 1, 1, 0, 0], &no_work).is_err());
        let mut long_identifier = vec![0x1f];
        long_identifier.extend(std::iter::repeat_n(0x80, 4096));
        long_identifier.extend_from_slice(&[4, 0]);
        assert!(decode_octet_string_ber(&long_identifier, &no_work).is_err());
        let tiny_input = Limits {
            max_input_bytes: 2,
            ..limits
        };
        assert!(decode_octet_string_ber(&[4, 1, 0], &tiny_input).is_err());
        let tiny_output = Limits {
            max_output_bytes: 0,
            ..limits
        };
        assert!(encode_octet_string_cer(&vec![0; 100_000], &tiny_output).is_err());
        let strict_work = Limits {
            max_work_bits: 79,
            ..limits
        };
        assert!(decode_octet_string_cer(&[4, 1, 7], &strict_work).is_err());
        let exact_strict_work = Limits {
            max_work_bits: 80,
            ..limits
        };
        assert_eq!(
            decode_octet_string_cer(&[4, 1, 7], &exact_strict_work)
                .unwrap()
                .value,
            [7]
        );
    }

    /// Mutate valid BER vectors and ensure malformed inputs never panic.
    /// Source: BER parser hardening cases; version: 2026-10-31; inputs: all
    /// one-byte substitutions in primitive and constructed OCTET/BIT TLVs.
    /// Returns: assertions; errors: panic if a decoder unwinds; responsible:
    /// asn1c maintainers. History: first BER expansion. Example: cargo test.
    #[test]
    fn single_byte_mutations_do_not_panic() {
        let limits = Limits::default();
        let vectors: &[&[u8]] = &[
            &[4, 3, 0x11, 0x22, 0x33],
            &[0x24, 0x80, 4, 1, 0xaa, 4, 1, 0xbb, 0, 0],
            &[3, 2, 3, 0xa0],
            &[0x23, 0x80, 3, 2, 0, 0xaa, 0, 0],
        ];
        for vector in vectors {
            for index in 0..vector.len() {
                for octet in 0..=u8::MAX {
                    let mut mutated = vector.to_vec();
                    mutated[index] = octet;
                    assert!(std::panic::catch_unwind(|| {
                        let _ = decode_octet_string_ber(&mutated, &limits);
                        let _ = decode_bit_string_ber(&mutated, &limits);
                    })
                    .is_ok());
                }
            }
        }
    }
}
