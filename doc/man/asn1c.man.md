---
title: "asn1c(1) ASN.1 Compiler"
author:
  - 'Lev Walkin \<vlm@lionet.info\>'
  - 'Mouse \<5923577+mouse07410@users.noreply.github.com\>'
date: "October 11, 2026"
---

# NAME

asn1c -- the ASN.1 Compiler

# SYNOPSIS

asn1c [**--rust** | **-E** [**-F**] | **-P** | **-R**] \
      [**-S** *dir*] [**-D** *dir*] [**-X**] \
      [**-W***debug-*...] [**-f***option*] [**-gen-***option*]
      [**-pdu**={**all**|**auto**|*Type*}] \
      [**-print-***option*] \
      *input-filenames*...

# DESCRIPTION

asn1c compiles ASN.1 specifications into C/C++ encoders and decoders for BER,
DER, CER, PER, XER, OER, JER, CBOR and other encoding rules. Its optional
**--rust** mode generates a Rust Cargo project for the supported subset.

The **--rust** mode generates a standalone Cargo project with a safe runtime
using the Rust 2021 edition. The current subset provides UPER encoding and
decoding, and strict CER encoding and decoding, for top-level BOOLEAN, NULL,
and finite non-extensible INTEGER ranges fitting `i64`. Opt-in BER/DER,
APER, OER, and JER cover those primitives. UPER alone also supports fixed
strings, ENUMERATED, and flat SEQUENCE with required or OPTIONAL direct fields.
Other types and codec combinations produce a diagnostic until implemented.

# OPTIONS

## Stage Selection Options

--rust
:   Select the complete Rust output mode, including Rust types, codec methods,
    Cargo metadata, and a copied native Rust runtime. The current default codec
    set is UPER and CER encoding. `-no-gen-UPER` selects CER-only output;
    `-no-gen-CER` leaves UPER enabled. Unavailable codec requests fail;
    `-ftolerant-utc-time` is supported and selects legacy UTCTime BER decoding.
    The default output directory in this
    mode is `asn1c-rust`. Build the generated package with
    `cargo check --offline --manifest-path asn1c-rust/Cargo.toml`.

For example, save this schema as `Demo.asn1`:

```asn1
Demo DEFINITIONS ::= BEGIN
Flag ::= BOOLEAN
END
```

Generate and check it with:

```sh
asn1c --rust -D generated Demo.asn1
cargo check --offline --manifest-path generated/Cargo.toml
```

-E
:   Run the ASN.1 parsing stage only. Print the reconstructed ASN.1 tree (text).

-F
:   Used together with **-E**,
    instructs the compiler to stop after the ASN.1 syntax
    tree fixing stage and dump the reconstructed ASN.1 specification
    to the standard output.

-P
:   Dump the compiled output to the standard output instead of creating the
    target language files on disk.

-R
:   Restrict the compiler to generate only the ASN.1 tables,
    omitting the usual support code.

-S *directory*
:   Use the specified directory with ASN.1 skeleton files.

-D *directory*
:   Destination directory for generated files (default current directory for
    C, or `asn1c-rust` for Rust). Rust mode stages output and rejects unrelated
    existing files or symlinks in the destination.

-X
:   Generate an XML DTD schema for the specified ASN.1 files.

## Warning Options

-Werror
:   Treat warnings as errors; abort if any warning is produced.

-Wdebug-lexer
:   Enable lexer debugging during the ASN.1 lexing stage.

-Wdebug-parser
:   Enable lexer debugging during the ASN.1 parsing stage.

-Wdebug-fixer
:   Enable ASN.1 syntax tree fixer debugging during the fixing stage.

-Wdebug-compiler
:   Enable debugging during the actual compile time.

## Language Options

-fbless-SIZE
:   Allow `SIZE()` constraint for `INTEGER`, `ENUMERATED`,
    and other types for which this constraint is normally prohibited
    by the standard.
    This is a violation of ASN.1 standard, and the compiler may
    fail to produce a meaningful code.

-fcompound-names
:   Using this option prevents name collisions in the target source code
    by using complex names for target language structures.
    (Name collisions may occur if the ASN.1 module reuses the same identifiers
    in multiple contexts).

-findirect-choice
:   When generating code for a `CHOICE` type, compile the `CHOICE` members
    as indirect pointers instead of declaring them inline.
    Consider using this option together with **-fno-include-deps**
    to prevent circular references.

-fincludes-quoted
:   Refer to header files in `#include`s using **"**double**"** instead of
    **\<**angle**>** quotes.

-fknown-extern-type=*name*
:   Pretend the specified type is known.
    The compiler will assume the target language source files
    for the given type have been provided manually.

-fline-refs
:   Include ASN.1 module's line numbers in generated code comments.

-fno-constraints
:   Do not generate ASN.1 subtype constraint checking code.
    This may make a shorter executable.

-ftolerant-utc-time
:   Keep legacy permissive `UTCTime` decoding. By default, the C runtime and
    generated Rust BER decoder validate UTCTime syntax, clock ranges, and
    calendar dates independently of generated subtype constraint checks;
    C's `-fno-constraints` does not turn off this validation.
    Strict mode accepts optional seconds and requires `Z` or a complete
    `+hhmm` / `-hhmm` offset. The legacy year mapping remains `00..59` to
    2000..2059 and `60..99` to 1960..1999; it is not an RFC 5280 profile
    check. For C output, this option emits `ASN_ENABLE_TOLERANT_UTCTIME` in
    generated `asn_config.h`. When using a separately built C runtime, define
    the macro while compiling the runtime skeleton objects; defining it only
    in application code does not affect a prebuilt runtime. With `-R`, build
    the runtime with the macro directly because runtime support and its
    configuration header are omitted. For Rust output, the generated type
    selects a tolerant BER decoder without a Cargo feature; DER encoding
    remains raw and CER validation remains strict.
    The strict UTCTime constraint callback checks syntax and calendar fields
    without converting through `time_t`. `asn_UT2time()` does convert through
    `time_t`, returns `(time_t)-1` for errors, and may return the same value
    for the valid UTC instant 1969-12-31 23:59:59; its range also depends on
    the platform's `time_t` representation. See X.680 47.2 and 47.3 at
    <https://www.itu.int/rec/T-REC-X.680-202102-I/en>.
    The option affects UTCTime only; GeneralizedTime behavior is unchanged.

-fno-include-deps
:   Do not generate courtesy #include lines for non-critical type dependencies.
    Helps prevent namespace collisions.

-fprefer-import-source
:   Resolve only names that an IMPORTS group lists (`xp_members`).
    In both modes, a name listed in any IMPORTS group resolves to the module
    that its group names (X.680 13.19).
    Without this option, a name that no IMPORTS group lists is also searched
    for in the body of each FROM module (whole-module fallback), which X.680
    does not allow.
    Enable this option to disable that fallback.

-fprefix=*prefix*
: Add the specified prefix to all generated type names and filenames.
 This helps avoid naming conflicts in several scenarios:

* **System header conflicts**: On case-insensitive filesystems (macOS HFS+, Windows),
   ASN.1 types like "Time" would generate `Time.h`, which can conflict with
   system header `<time.h>`. asn1c now automatically disambiguates these generated
   filenames (for example, `Time.h` becomes `asn1c_time.h` when no explicit prefix
   is set). Likewise, types whose names match a runtime skeleton file
   case-insensitively (e.g. "Null" vs `NULL.h`, "Integer" vs `INTEGER.h`)
   are generated as `asn1c_Null.h`, `asn1c_Integer.h`, etc.
   Using `-fprefix=ASN1_` still generates `ASN1_Time.h` when you need a
   project-specific naming convention.

* **Multiple ASN.1 modules**: When generating code for multiple ASN.1 syntaxes
   that have type name clashes, a prefix prevents symbol collisions.

* **Integration with existing code**: Prefixes help avoid conflicts with
   existing types in your codebase.

 **Important**: use this flag when you want a consistent custom namespace for all
 generated symbols and filenames, especially when integrating multiple schemas.

 Example: `asn1c -fprefix=PKIX_ rfc3280.asn1`

-funnamed-unions
:   Enable unnamed unions in the definitions of target language's structures.

-fwide-types
:   Use the unbounded size data types (`INTEGER_t`, `ENUMERATED_t`, `REAL_t`)
    by default, instead of using the native machine's data types (long, double).

-flong-size=*bits*
:   Select the target C `long` model used by the default native INTEGER
    storage policy.  *bits* is one of `32` or `64`; the default `auto`
    behavior preserves the historical portable 32-bit assumption.  Use this
    option when generating code on one platform for a target with a different
    `long` size.

-finteger-native-type=*mode*
:   Select the fixed-width native C storage policy for constrained ASN.1
    INTEGER types.  *mode* is one of `auto`, `int32`, `uint32`, `int64`, or
    `uint64`; the default is `auto`.  `auto` preserves the traditional storage
    decision: `long` or `unsigned long` for ranges that fit the target `long`
    model, and `INTEGER_t` otherwise.  `int32`/`int64` permit signed fixed-width
    storage for ranges that fit signed 32-bit or 64-bit values; `uint32`/
    `uint64` permit unsigned fixed-width storage only when the compiler can
    prove a non-negative bounded range that fits unsigned 32-bit or 64-bit
    values.  Values that do not fit the selected native policy are generated
    as `INTEGER_t`.  Unsigned
    upper bounds such as `18446744073709551615` are preserved without signed
    wraparound, and bounds beyond 64 bits are stored as static
    arbitrary-precision constraint values.

## Codecs Generation Options

-fgen-only-pdu-deps
:   Generate code only for types that are dependencies of -pdu types

-flist-deps
: List PDU dependencies (requires -pdu option, no code generated)

-no-gen-BER
:   Do not generate BER-family support code, including the shared dependencies
    used by DER and CER encoding.

-gen-CER
:   Generate Canonical Encoding Rules (CER, X.690) support with its required
    BER-family dependencies. The C target enables CER by default.

-no-gen-CER
:   Disable CER encoding and strict CER decoding support. The converter's
    `-icer` selector is then rejected; `-iber` still accepts BER input
    unless BER support is disabled.

-no-gen-XER
:   Do not generate the XML Encoding Rules (XER, X.693) support code

-no-gen-OER
:   Do not generate the Octet Encoding Rules (OER, X.696) support code

-no-gen-CBOR
:   Do not generate the Concise Binary Object Representation (CBOR, RFC 8949)
    support code.
    By default, CBOR encoder and decoder support code is generated.

-no-gen-UPER
:   Do not generate the Unaligned Packed Encoding Rules (PER, X.691) support code

-no-gen-APER
:   Do not generate the Aligned Packed Encoding Rules (PER, X.691) support code

-no-gen-print
:   Do not generate the print code

-no-gen-random-fill
:   Do not generate the random fill code

-no-gen-example
:   Do not generate the ASN.1 format converter example

-gen-autotools
: Generate example top-level configure.ac and Makefile.am

-pdu={all|auto|*Type*}
:   Create a PDU table for specified types, or discover Protocol Data Units
    automatically. In case of **-pdu=all**,
    all ASN.1 types defined in all modules will form a PDU table.
    In case of **-pdu=auto**, all types not referenced by any other type will
    form a PDU table.
    If *Type* is an ASN.1 type identifier, the identifier is added to
    the generated PDU table.
    The last form may be specified multiple times to add any number of PDUs.

## Output Options

-print-class-matrix
: Print out the collected object class matrix (debug)

-print-constraints
:   When **-EF** options are also specified,
    this option forces the compiler to explain its internal understanding
    of subtype constraints.

-print-lines
:   Generate "`-- #line`" comments in **-E** output.

# TRANSFER SYNTAXES

The ASN.1 family of standards defines a number of ways to encode data,
including byte-oriented (e.g., BER and CBOR), bit-oriented (e.g., PER),
and textual (e.g., XER and JER). Some encoding variants (e.g., DER) are
stricter variants of more general encodings (e.g., BER).

The interoperability table below specifies which API functions can be used
to exchange data in a compatible manner. If you need to *produce* data
conforming to the standard specified in the column 1,
use the API function in the column 2.
If you need to *process* data conforming to the standard(s) specified in the
column 3, use the API function specified in column 4.
See the `asn1c-usage.pdf` for details.

| Encoding | API function | Understood by | API function |
| -------------- | -------------------- | -------------- | -------------- |
| BER | `der_encode()` | BER | `ber_decode()` |
| DER | `der_encode()` | DER, BER | `ber_decode()` |
| CER | `cer_encode()` | CER | `cer_decode()` |
| BASIC-OER | `oer_encode()` | *-OER | `oer_decode()` |
| CANONICAL-OER | `oer_encode()` | *-OER | `oer_decode()` |
| BASIC-UPER | `uper_encode()` | *-UPER | `uper_decode()` |
| CANONICAL-UPER | `uper_encode()` | *-UPER | `uper_decode()` |
| BASIC-APER | `aper_encode()` | *-APER | `aper_decode()` |
| CANONICAL-APER | `aper_encode()` | *-APER | `aper_decode()` |
| BASIC-XER | `xer_encode()` | *-XER | `xer_decode()` |
| CANONICAL-XER | `xer_encode()` | *-XER | `xer_decode()` |
| JER | `jer_encode()` | JER | `jer_decode()` |
| JER-MINIFIED | `jer_encode()` | JER | `jer_decode()` |
| CBOR | `cbor_encode()` | CBOR | `cbor_decode()` |

For CANONICAL-XER, call `xer_encode()` with `XER_F_CANONICAL`.

CER encoding uses `cer_encode()` or `asn_encode(ATS_CER, ...)`; the generated
converter accepts `-ocer` output. The C backend generates CER support by
default, and the `ASN_DISABLE_CER_SUPPORT` build macro disables both the
encoder and the strict decoder. The generated converter's `-iber` and `-ider`
selectors use the permissive BER decoder. `cer_decode()`,
`asn_decode(ATS_CER, ...)`, and the `-icer` selector decode with the BER
decoder, re-encode the value with `cer_encode()`, and fail with `EBADF` unless
the re-encoding is byte-identical to the consumed input. Non-canonical input
such as long-form lengths, definite-length constructed values, non-minimal
INTEGER, unsorted SET OF, or unsegmented long strings is rejected. Trailing
bytes after the first TLV are not consumed. `-icer` requires CER generation
and buffers the whole input rather than decoding incrementally. Type support
depends on the generated descriptor and canonical
value forms supported by the encoder. Opaque ANY and unresolved standalone
open types are rejected. Raw REAL accepts zero, special values, and minimal
base-2 forms with exponents of at most eight octets; decimal or non-canonical
raw forms are rejected. UTCTime is normalized to UTC seconds. GeneralizedTime
requires an explicit zone and supports at most nine fractional-second digits;
comma input is normalized to a period.
Constructed character strings retain their outer type tag and use universal
OCTET STRING tag 4 for fragments. BIT STRING fragments use universal tag 3.
BER input preserves legacy opaque ANY containers while validating their
lengths, nesting, and EOC markers; typed string wrappers require one child.
The encoder applies finite output, scratch, collection, work, recursion, and
descriptor tag-chain limits. An additional explicit member tag counts against
the tag-chain cap; see the binary codec support documentation for defaults.

The direct `cer_encode_to_buffer()` function fails if the caller's buffer is
too small. The generic `asn_encode_to_buffer(ATS_CER, ...)` follows the generic
buffer API: `.encoded` reports the full required size, and a short buffer
contains only an output prefix.

The generated converter can read BER and write CER with
`./converter-example -iber -ocer input.ber > output.cer`.

The Rust backend currently encodes CER for BOOLEAN, NULL, and bounded
non-extensible INTEGER ranges fitting `i64`, and generates a strict
`decode_cer()` that accepts only the canonical short-form TLV. Its UPER and
CER codecs are enabled by default. To generate only the CER methods, pass
`--rust -no-gen-UPER`.

*) Asterisk means both BASIC and CANONICAL variants. Pass `XER_F_BASIC` or
`XER_F_CANONICAL` to `xer_encode()` for the corresponding XER variant. Use
`JER_F_MINIFIED` with `jer_encode()` for whitespace-free output; `jer_decode()`
accepts either JER form.

# XER AND JER ENCODING INSTRUCTIONS

asn1c supports a selected set of schema-level encoding instructions for XER
and JER. Instructions may be written as bracketed type prefixes or in
`ENCODING-CONTROL` sections.

```asn1
Flag ::= [TEXT] BOOLEAN
Mode ::= [XER:TEXT] ENUMERATED { idle(0), busy(1) }
Blob ::= [JER:BASE64] OCTET STRING

ENCODING-CONTROL XER
    GLOBAL-DEFAULTS MODIFIED-ENCODINGS
    DECIMAL Ratio
    TEXT Count.one AS "uno"
END

ENCODING-CONTROL JER
    BASE64 Blob
    TEXT Mode.busy AS "occupied"
    NAME Packet.payload AS "payload64"
END
```

Supported XER instructions:

* `BASE64` for `OCTET STRING`; bare `[BASE64]` remains XER for compatibility.
* legacy `Type OCTET STRING ::= hexadecimal`, `base64`, and `utf8` forms.
* `TEXT` for `BOOLEAN`, `ENUMERATED`, named-number `INTEGER`, and named-bit
  `BIT STRING`.
* `DECIMAL` for `REAL`, only when `GLOBAL-DEFAULTS MODIFIED-ENCODINGS` is
  present in the XER control section.
* `GLOBAL-DEFAULTS MODIFIED-ENCODINGS`.

Supported JER instructions:

* `BASE64` for `OCTET STRING`; use `[JER:BASE64]` for type prefixes.
* `TEXT Type.value AS "json-string"` for named values of `ENUMERATED`.
* `NAME Type.member AS "json-key"` for members of `SEQUENCE`, `SET`, and
  `CHOICE`.

The compiler rejects incompatible targets, unknown targets, missing `AS`
values where required, XER `DECIMAL` without
`GLOBAL-DEFAULTS MODIFIED-ENCODINGS`, and duplicate JER wire names within the
same constructed type. JER `NAME` affects JSON keys only; it does not rename
generated C fields or XER XML tags.

# CBOR TAGS

CBOR (RFC 8949) supports *tags* (major type 6) as optional semantic
annotations on any data item.  A tag consists of a tag number followed
by the tagged value.  Common tag numbers are registered by IANA at:
<https://www.iana.org/assignments/cbor-tags/>

**Encoding:** Call `cbor_encode_tag(tag_number, cb, app_key)` immediately
before encoding the value to prepend a tag header.  Symbolic constants
for well-known tags (e.g., `CBOR_TAG_DATETIME_STRING`, `CBOR_TAG_URI`,
`CBOR_TAG_SELF_DESCRIBED`) are defined in `cbor_support.h`.

**Decoding:** All asn1c CBOR decoders are *tag-transparent*: any number
of leading tag headers are silently consumed before the underlying value
is decoded. Applications must validate registered tag semantics as needed.
The helper `cbor_skip_tags(buf, size)` (in `cbor_support.h`) returns the
number of bytes occupied by leading tag headers, or -1 on error.
When decoder code must skip a complete raw CBOR value, it should call
`cbor_skip_item_with_ctx(opt_codec_ctx, buf, size)` so recursive arrays,
maps, and tags are bounded by the decoder stack limit.  The compatibility
wrapper `cbor_skip_item(buf, size)` remains available for callers without
decoder context.

**Bignum tags:** Tags 2 and 3 are used internally by the INTEGER encoder
and decoder for values beyond the ordinary major-type 0/1 range, per RFC 8949.

Typed containers use definite lengths. REAL accepts binary16/32/64 and emits
shortest exact widths; NaN is f9 7e 00. Maps retain definition order and do
not claim deterministic key ordering. Raw item scanning accepts indefinite
containers and imposes a 128-level nesting limit even with stack checks disabled.

# EXIT STATUS

**0**
:   Success. No FATAL diagnostic was reported.

**64** (`EX_USAGE`)
:   Command line usage error, or no input files.

**65** (`EX_DATAERR`)
:   ASN.1 input error: a syntax error, or a FATAL diagnostic during
    semantic processing (**-F** and code generation).

**66** (`EX_NOINPUT`)
:   An input file cannot be opened.

**70** (`EX_SOFTWARE`)
:   Printing or code generation failed, or reported a FATAL diagnostic.
    Files can be written, but the output is incomplete.

**72** (`EX_OSFILE`)
:   Skeleton files were not found and **-Werror** is in effect.

A FATAL diagnostic always gives a non-zero exit status.

# SEE ALSO

`unber`(1), `enber`(1).
