# About

ASN.1 to C compiler takes the ASN.1 module files (example) and generates
the C++ compatible C source code. That code can be used to serialize
the native C structures into compact and unambiguous BER/OER/PER/XER/JER-based
data files, and deserialize the files back.

Various ASN.1 based formats are widely used in the industry,
such as to encode the X.509 certificates employed in the HTTPS handshake,
to exchange control data between mobile phones and cellular networks,
to perform car-to-car communication in intelligent transportation networks.

The ASN.1 family of standards is large and complex, and no open source
compiler supports it in its entirety.
The asn1c is arguably the most evolved open source ASN.1 compiler.

## Latest release

Current release: **1.5.0**

This release adds the `-fprefer-import-source` flag, which fixes incorrect type
binding when two modules export identically-named types and a consumer imports
one from each. It also includes post-v1.4 fixes across APER/UPER/OER decoding,
PER size constraint handling, `-fprefix` generation for anonymous typedefs
and member symbols, parser/compiler warning cleanup, circular-reference
include fixes, and multiple code-scanning fixes. It also addresses security
vulnerabilities, including formatting-related code scanning findings and
hardening of integer decoder edge cases.

See [ChangeLog](ChangeLog) for the complete release history and
[release-notes/v1.4.md](release-notes/v1.4.md) for the v1.4 release notes.

# ASN.1 Transfer Syntaxes
<details>
<summary>ASN.1 encodings interoperability table</summary>

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
CER            | _not supported_            | CER, BER      | ber_decode()
BASIC-OER      | oer_encode()               | *-OER         | oer_decode()
CANONICAL-OER  | oer_encode()               | *-OER         | oer_decode()
BASIC-UPER     | uper_encode()              | *-UPER        | uper_decode()
CANONICAL-UPER | uper_encode()              | *-UPER        | uper_decode()
BASIC-APER     | aper_encode()              | *-APER        | aper_decode()
CANONICAL-APER | aper_encode()              | *-APER        | aper_decode()
BASIC-XER      | xer_encode(XER_F_BASIC)    | *-XER         | xer_decode()
CANONICAL-XER  | xer_encode(XER_F_CANONICAL)| *-XER         | xer_decode()
JER            | jer_encode()               | JER           | jer_decode()

*) Asterisk means both BASIC and CANONICAL variants.
</details>

# XER and JER Encoding Instructions

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

# Build and Install

If you haven't installed the asn1c yet, read the [INSTALL.md](INSTALL.md) file
for a short installation guide.

[![Build Status](https://travis-ci.com/mouse07410/asn1c.svg?branch=vlm_master)](https://travis-ci.com/mouse07410/asn1c)

# Documentation

For the list of asn1c command line options, see `asn1c -h` or `man asn1c`.

The comprehensive documentation on this compiler is in [doc/asn1c-usage.pdf](doc/asn1c-usage.pdf).

Please also read the [FAQ](FAQ) file.

An excellent book on ASN.1 is written by Olivier Dubuisson:
"ASN.1 Communication between heterogeneous systems", ISBN:0-12-6333361-0.

# Quick start

(also check out [doc/asn1c-quick.pdf](doc/asn1c-quick.pdf))

After installing the compiler (see [INSTALL.md](INSTALL.md)), you may use
the asn1c command to compile the ASN.1 specification:

    asn1c <module.asn1>                         # Compile module

If several specifications contain interdependencies, all of them must be
specified at the same time:

    asn1c <module1.asn1> <module2.asn1> ...     # Compile interdependent modules

The asn1c source tarball contains the [examples/](examples/) directory
with several ASN.1 modules and a [script](examples/crfc2asn1.pl)
to extract the ASN.1 modules from RFC documents.
Refer to the [examples/README](examples/README) file in that directory.

To compile the X.509 PKI module:

    ./asn1c/asn1c -P ./examples/rfc3280-*.asn1  # Compile-n-print

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

    asn1c -EF <module-to-test.asn1>             # Check semantic validity

## Working with large specifications (PDU selection)

When working with large ASN.1 specifications (such as 3GPP 5G specs), you may
only need to generate code for specific PDU (Protocol Data Unit) types and their
dependencies. The asn1c compiler provides options for this:

### List PDU dependencies

To list all types that a specific PDU depends on without generating code:

    asn1c -pdu=PDUType -flist-deps module.asn1

This will output a list of type names that are dependencies of the specified PDU.

### Generate code only for PDU dependencies

To generate code only for a specific PDU and its dependencies (reducing the
amount of generated code):

    asn1c -pdu=PDUType -fgen-only-pdu-deps module.asn1

This is particularly useful for large specifications where you only need a subset
of the types. You can specify multiple PDUs:

    asn1c -pdu=PDU1 -pdu=PDU2 -fgen-only-pdu-deps module.asn1

The `-fgen-only-pdu-deps` option also works with `-pdu=all` and `-pdu=auto`.

## Resolving ambiguous imports (-fprefer-import-source)

When two ASN.1 modules export identically-named types and a third module
imports one from each, the resolver can silently bind to the wrong module's
definition. Use `-fprefer-import-source` to restrict the lookup to the
explicit IMPORTS list only:

    asn1c -fprefer-import-source <module1.asn1> <module2.asn1> ...

Without this flag (the default) the resolver falls back to scanning the full
module body when a name is not found in the IMPORTS list, which can produce
incorrect bindings. With the flag, only an explicit `FROM ModuleName` import
is accepted, and an error is raised if the name cannot be resolved that way.

# Model of operation

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

    <parser> => print                                       (-E)
    <parser> => <fixer> => print                            (-E -F)
    <parser> => <fixer> => <compiler> => print              (-P)
    <parser> => <fixer> => <compiler> => save-compiled      [default]

# Partial Decoding Support

When decoding fails (e.g., due to truncated or malformed input), the converter
tool can print partial decoding results to help with debugging. Use the `-P` 
flag with the generated converter to see what was successfully decoded before
the error occurred:

    ./converter-example -iper -P truncated-message.uper

For more details, see [PARTIAL_DECODING.md](PARTIAL_DECODING.md).


-- 
Mouse and Lev Walkin
<none>    vlm@lionet.info
