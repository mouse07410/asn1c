# README

## About

asn1c compiles ASN.1 modules into C++-compatible C source by default. Its
opt-in `--rust` backend generates Rust source and Cargo metadata for the
supported subset. Generated code can serialize native values into compact
BER-family, OER, PER, XER, JER, and CBOR data, and decode them where supported.

Various ASN.1 based formats are widely used in the industry,
such as to encode the X.509 certificates employed in the HTTPS handshake,
to exchange control data between mobile phones and cellular networks,
to perform car-to-car communication in intelligent transportation networks.

The ASN.1 family of standards is large and complex, and no open source
compiler supports it in its entirety.
The asn1c is arguably the most evolved open source ASN.1 compiler.

### Latest release

Current release: **1.5.3**

This release corrects imported-name resolution and compiler diagnostics,
fixes PER extensibility, avoids generated-file collisions with runtime
skeletons on case-insensitive filesystems, and addresses a skeleton build race.
It also includes header usability improvements and updated compiler
documentation.
See the [v1.5.3 release notes](release-notes/v1.5.3.md) for details.

#### Upgrade warning: unknown extensions

> **Important:** Decoding behavior for unknown extensions has changed from
> "fail" to "skip/relay". Evaluate the impact on your application before
> upgrading; define `ASN_REJECT_UNKNOWN_EXTENSIONS` to restore the previous
> strict behavior.

This forward-compatible default applies to unknown alternatives of extensible
UPER/OER `CHOICE` values and unknown additions of extensible UPER/APER
`ENUMERATED` values. Existing deployments may rely on the old `RC_FAIL` result
as an implicit input-validation gate or as a protocol error in a state machine.
Compile all decoder skeleton objects with the macro and perform a clean rebuild;
defining it only in application code does not change an already-built runtime
library. Compatibility warning contributed by <shakespark@gmail.com>.

See [ChangeLog](ChangeLog) for the complete release history and
[release-notes/v1.5.3.md](release-notes/v1.5.3.md) for these release notes,
[release-notes/v1.4.2.md](release-notes/v1.4.2.md) for v1.4.2, and
[release-notes/v1.4.md](release-notes/v1.4.md) for v1.4.

The [JER converter and BER string security review](docs/issues-578-581-security-review.md)
documents the fixes for issues #578/#581 and the corrections to PRs #579/#580,
including reproduction cases and regression coverage.
The [extension semantics and security review](docs/issues-582-584-review.md)
documents fixes for extensible permitted alphabets, SEQUENCE extension addition
groups, and implied ENUMERATED extensibility (#582–#584). Regenerate C output
with the matching updated runtime because SEQUENCE group descriptors now carry
additional metadata. The follow-up [SET extension-group notes](docs/set-extension-groups.md)
describe transparent SET groups, regenerated descriptor layout, stack bounds,
and UPER, APER, OER, and JER group support.

The [incremental JER design proposal](docs/jer-streaming-design.md) describes
how to progress from buffering one PDU to decoding large messages in chunks,
with explicit memory limits, framing and an optional application sink.

## ASN.1 Transfer Syntaxes

<!-- markdownlint-disable MD033 -->
<details>
<summary>ASN.1 encodings interoperability table</summary>
<!-- markdownlint-enable MD033 -->

The ASN.1 family of standards define a number of ways to encode data,
including byte-oriented (e.g., BER), bit-oriented (e.g., PER),
and textual (e.g., XER). Some encoding variants (e.g., DER) are just stricter
variants of the more general encodings (e.g., BER).

The interoperability table below specifies which API functions can be used
to exchange data in a compatible manner. If you need to _produce_ data
conforming to the standard specified in the column 1,
use the API function in the column 2.
If you need to _process_ data conforming to the standard(s) specified in the
column 3, use the API function specified in column 4.
See the [doc/asn1c-usage.pdf](doc/asn1c-usage.pdf) for details.

Encoding       | API function               | Understood by | API function
-------------- | -------------------------- | ------------- | -------------
BER            | der_encode()               | BER           | ber_decode()
DER            | der_encode()               | DER, BER      | ber_decode()
CER            | cer_encode()               | CER           | cer_decode()
BASIC-OER      | oer_encode()               | *-OER         | oer_decode()
CANONICAL-OER  | oer_encode()               | *-OER         | oer_decode()
BASIC-UPER     | uper_encode()              | *-UPER        | uper_decode()
CANONICAL-UPER | uper_encode()              | *-UPER        | uper_decode()
BASIC-APER     | aper_encode()              | *-APER        | aper_decode()
CANONICAL-APER | aper_encode()              | *-APER        | aper_decode()
BASIC-XER      | xer_encode(XER_F_BASIC)    | *-XER         | xer_decode()
CANONICAL-XER  | xer_encode(XER_F_CANONICAL)| *-XER         | xer_decode()
JER            | jer_encode()               | JER           | jer_decode()
JER-MINIFIED   | jer_encode(JER_F_MINIFIED) | JER           | jer_decode()
CBOR           | cbor_encode()              | CBOR          | cbor_decode()

*) Asterisk means both BASIC and CANONICAL variants. JER-MINIFIED produces
whitespace-free JSON, and `jer_decode()` accepts either JER form.
</details>

CER encoding is available through `cer_encode()`, `asn_encode(ATS_CER, ...)`,
and the generated converter's `-ocer` output selector. The default C target
generates CER support together with BER support; `-gen-CER` enables its
BER-family dependencies, `-no-gen-CER` omits CER encoding, and `-no-gen-BER`
omits the shared family. CER decoding is strict: `cer_decode()`,
`asn_decode(ATS_CER, ...)`, and the converter's `-icer` input selector decode
with the BER decoder, re-encode the value with `cer_encode()`, and reject input
that is not byte-identical to the canonical CER encoding (for example long-form
lengths, definite-length constructed values, or unsorted SET OF). `-icer`
requires CER generation and buffers the whole input. As with the other
generated codecs, availability depends on the generated descriptor kinds and
canonical value forms handled by the encoder. `ASN_DISABLE_CER_SUPPORT`
disables both CER encoding and strict CER decoding at build time. See the
[binary codec support audit](docs/binary-codec-support.md) for the current
descriptor, value, and resource boundaries.

Constructed CER character strings retain their outer string tag and use
universal OCTET STRING tags for the fragments; BIT STRING fragments use their
universal BIT STRING tag. BER input also preserves legacy opaque `ANY`
containers under the bounds described in that audit.

In Rust output mode, CER supports top-level BOOLEAN, NULL, finite
nonextensible INTEGER values whose bounds fit signed 64-bit integers, direct
nonextensible ENUMERATED values fitting signed 64-bit integers, and direct
fixed or bounded BIT STRING and OCTET STRING values with supported finite
`SIZE` constraints. Long strings use CER fragmentation; `decode_cer()`
re-encodes and compares the consumed prefix to reject noncanonical forms.
Flat SEQUENCE records with an untagged outer type and distinct effective tags
for direct BOOLEAN, NULL, bounded INTEGER, ENUMERATED, and finite bounded
BIT/OCTET STRING fields also support
required and OPTIONAL members, literal BOOLEAN/INTEGER DEFAULT members, and
an empty record. Their BER/DER/CER operations share one record-wide resource
budget.
Flat SET records with an untagged outer type support the same six direct field kinds
under BER/DER/CER-only selection (`-no-gen-UPER`), with unordered BER field
decoding and canonical tag-ordered DER/CER output. The current XER-only SET
slice remains a separate codec selection.
The same flat BER/DER/CER records accept resolved context-specific IMPLICIT
member tags, including automatic tags, and one context-specific EXPLICIT
wrapper per direct field. High tag numbers within the C runtime's range and
repeated primitive kinds with distinct effective tags are supported; SET
output sorts by effective class and tag number. One nonrecursive inline
SEQUENCE child is supported in an untagged SEQUENCE or BER/CER-only SET, with
required or OPTIONAL direct primitive leaves and a shared resource budget.
Root tags, multi-tag stacks, aliases, and deeper constructed records remain
outside this slice.
Rust CER output is selected by default with UPER; `-no-gen-UPER` selects
CER-only output. `-gen-BER` adds BER prefix decoding and DER encoding for
these direct types. See [Rust output usage and limits](docs/rust/implementation.md)
and the [parity design](docs/rust/ber-der-cer-design.md) for remaining gaps.
The same primitive Rust subset also supports opt-in APER and OER encoding and
decoding with `-gen-APER` and `-gen-OER`.

Basic/canonical OER, UPER, and APER selectors share each family's decoder;
CBOR has its own encoder and decoder. Support still depends on the generated
type's codec operations and enabled codec families. See the
[binary codec audit](docs/binary-codec-support.md) for dispatch details and limits.

## XER and JER Encoding Instructions

asn1c supports schema-level XER and JER encoding instructions for selected
standard-style encodings. Supported instructions include XER `BASE64`, `TEXT`,
`DECIMAL`, `GLOBAL-DEFAULTS MODIFIED-ENCODINGS`, and the legacy XER OCTET
STRING controls `hexadecimal` and `utf8`; JER supports `BASE64`, enumerated
value `TEXT`, and member `NAME`.

```asn1
Flag ::= [TEXT] BOOLEAN
Blob ::= [JER:BASE64] OCTET STRING

ENCODING-CONTROL XER
    GLOBAL-DEFAULTS MODIFIED-ENCODINGS
    DECIMAL Ratio
    TEXT Count.one AS "uno"
END

ENCODING-CONTROL JER
    NAME Packet.payload AS "payload64"
    TEXT Mode.busy AS "occupied"
END
```

Bare `[BASE64]` remains a XER instruction for compatibility; use
`[JER:BASE64]` for JER. XER `DECIMAL` applies only to `REAL` and requires
`GLOBAL-DEFAULTS MODIFIED-ENCODINGS`. JER `NAME` changes JSON keys only; it
does not rename C fields or XER XML tags. See
[ENCODING_CONTROL_STATUS.md](ENCODING_CONTROL_STATUS.md) for the support
matrix and diagnostics.

## Build and Install

If you haven't installed the asn1c yet, read the [INSTALL.md](INSTALL.md) file
for a short installation guide.

[![Build Status](https://travis-ci.com/mouse07410/asn1c.svg?branch=vlm_master)](https://travis-ci.com/mouse07410/asn1c)

## Documentation

`--rust` selects native Rust output as a complete compiler mode. It generates a
standalone Cargo package with safe, dependency-free UPER and CER codecs for
BOOLEAN, NULL, and finite nonextensible INTEGER ranges fitting `i64`.
APER, OER, BER/DER, and JER are available for selected direct primitive types
when explicitly enabled. Unsupported schemas, codec requests, and C-specific
output options fail with diagnostics. Build the generated package with Cargo
in offline mode.

With UPER as the only selected codec (`-no-gen-CER`), SEQUENCE assignments can
contain required, OPTIONAL, and supported primitive DEFAULT fields, including
inline nested SEQUENCE records. A shared cursor enforces one resource budget
across the complete value. Direct fixed-size OCTET STRING and BIT STRING types,
and either string type with one bounded contiguous `SIZE` range below 65536,
support UPER, including required and OPTIONAL SEQUENCE fields. Bounded BIT
STRING values carry their exact meaningful bit length. Direct
nonextensible ENUMERATED assignments use UPER indexes in numeric value order.
ENUMERATED and direct fixed-size or bounded OCTET STRING assignments can also
opt into JER.
Direct fixed-size and bounded BIT STRING assignments support the C-compatible
JER hexadecimal forms, including the bit length for bounded values.
Named-bit lists and other unsupported forms are rejected with diagnostics.

See [the initial implementation](docs/rust/implementation.md) for usage and
limits, and [the conversion plan](docs/rust/README.md) for incremental delivery
of all current codec families and test migration.

For the list of asn1c command line options, see `asn1c -h` or `man asn1c`.

The comprehensive documentation on this compiler is in [doc/asn1c-usage.pdf](doc/asn1c-usage.pdf).

Extensible UPER and OER types, plus extensible APER `ENUMERATED` types, decode
unknown extension additions forward-compatibly by default. Unknown CHOICE
alternatives are skipped and reported with no selected local alternative;
unknown UPER/APER ENUMERATED values are represented by the reserved
`LONG_MAX - extension_index` range so they can be relayed with the same PER
transfer syntax. Applications that require the historical strict rejection
behavior may compile generated skeletons with `ASN_REJECT_UNKNOWN_EXTENSIONS`;
this forfeits forward compatibility.

APER open types governed by extensible information-object sets retain unknown
values in an opaque `ANY_t` alternative (`choice.asn1cUnknown`, with a numeric
suffix if that name is already used). Applications can copy, modify other fields,
and re-encode these values with APER. Regenerate C sources with the updated
compiler and runtime to obtain the new alternative. See the
[issue #586 notes](docs/issue-586-aper-unknown-open-type.md) for ownership,
identifier validation, and round-trip limits.

Please also read the [FAQ](FAQ) file.

An excellent book on ASN.1 is written by Olivier Dubuisson:
"ASN.1 Communication between heterogeneous systems", ISBN:0-12-6333361-0.

## Quick start

(also check out [doc/asn1c-quick.pdf](doc/asn1c-quick.pdf))

After installing the compiler (see [INSTALL.md](INSTALL.md)), you may use
the asn1c command to compile the ASN.1 specification:

```sh
    asn1c <module.asn1>                         # Compile module
```

If several specifications contain interdependencies, all of them must be
specified at the same time:

```sh
    asn1c <module1.asn1> <module2.asn1> ...     # Compile interdependent modules
```

The asn1c source tarball contains the [examples/](examples/) directory
with several ASN.1 modules and a [script](examples/crfc2asn1.pl)
to extract the ASN.1 modules from RFC documents.
Refer to the [examples/README](examples/README) file in that directory.

To compile the X.509 PKI module:

```sh
    ./asn1c/asn1c -P ./examples/rfc3280-*.asn1  # Compile-n-print
```

In this example, the **-P** option is to print the compiled text on the
standard output. The default behavior is that asn1c compiler creates
multiple .c and .h files for every ASN.1 type found inside the specified
ASN.1 modules.

The compiler's **-E** and **-EF** options are used for testing the parser and
the semantic fixer, respectively. These options will instruct the compiler
to dump out the parsed (and fixed) ASN.1 specification as it was
"understood" by the compiler. It might be useful for checking
whether a particular syntactic construction is properly supported
by the compiler.

```sh
    asn1c -EF <module-to-test.asn1>             # Check semantic validity
```

### Working with large specifications (PDU selection)

When working with large ASN.1 specifications (such as 3GPP 5G specs), you may
only need to generate code for specific PDU (Protocol Data Unit) types and their
dependencies. The asn1c compiler provides options for this:

#### List PDU dependencies

To list all types that a specific PDU depends on without generating code:

```sh
    asn1c -pdu=PDUType -flist-deps module.asn1
```

This will output a list of type names that are dependencies of the specified PDU.

#### Generate code only for PDU dependencies

To generate code only for a specific PDU and its dependencies (reducing the
amount of generated code):

```sh
    asn1c -pdu=PDUType -fgen-only-pdu-deps module.asn1
```

This is particularly useful for large specifications where you only need a subset
of the types. You can specify multiple PDUs:

```sh
    asn1c -pdu=PDU1 -pdu=PDU2 -fgen-only-pdu-deps module.asn1
```

The `-fgen-only-pdu-deps` option also works with `-pdu=all` and `-pdu=auto`.

## Resolving imported names (-fprefer-import-source)

A name listed in an IMPORTS group always resolves to the module that its
`FROM ModuleName` names (X.680 13.19), with or without this flag. So when
two ASN.1 modules export identically-named types and a third module imports
one from each, each name binds to the module that it is imported from.

Without the flag (the default), a name that no IMPORTS group lists is also
searched for in the body of each FROM module (whole-module fallback).
X.680 does not allow this, but some specifications rely on it. Use
`-fprefer-import-source` to disable the fallback and resolve only names
that an IMPORTS group lists:

```sh
    asn1c -fprefer-import-source <module1.asn1> <module2.asn1> ...
```

With the flag, a name that is used but not listed in IMPORTS (and not
defined locally) is reported as an error.

## Model of operation

The asn1c compiler works by processing the ASN.1 module specifications
in several stages:

1. During the first stage, the ASN.1 file is parsed.
   (Parsing produces an ASN.1 syntax tree for the subsequent levels)
2. During the second stage, the syntax tree is "fixed".
   (Fixing is a process of checking the tree for semantic errors,
   accompanied by the tree transformation into the canonical form)
3. During the third stage, the syntax tree is compiled into the target language.

There are several command-line options reserved for printing the results
after each stage of operation:

```text
    <parser> => print                                       (-E)
    <parser> => <fixer> => print                            (-E -F)
    <parser> => <fixer> => <compiler> => print              (-P)
    <parser> => <fixer> => <compiler> => save-compiled      [default]
```

## Partial Decoding Support

When decoding fails (e.g., due to truncated or malformed input), the converter
tool can print partial decoding results to help with debugging. Use the `-P`
flag with the generated converter to see what was successfully decoded before
the error occurred:

```sh
./converter-example -iper -P truncated-message.uper
```

For more details, see [PARTIAL_DECODING.md](PARTIAL_DECODING.md).

--
Mouse and Lev Walkin
<!-- markdownlint-disable MD033 -->
<5923577+mouse07410@users.noreply.github.com>    <vlm@lionet.info>
<!-- markdownlint-enable MD033 -->
