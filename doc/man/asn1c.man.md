% asn1c(1) ASN.1 Compiler
% Lev Walkin <vlm@lionet.info>, Mouse <5923577+mouse07410@users.noreply.github.com>
% 2025-11-27

# NAME

asn1c -- the ASN.1 Compiler

# SYNOPSIS

asn1c [**-E** [**-F**] | **-P** | **-R**] \
      [**-S** *dir*] [**-D** *dir*] [**-X**] \
      [**-W***debug-*...] [**-f***option*] [**-gen-***option*] 
      [**-pdu**={**all**|**auto**|*Type*}] \
      [**-print-***option*] \
      *input-filenames*...

# DESCRIPTION

asn1c compiles ASN.1 specifications into a set of
target language (C/C++) encoders and decoders for BER, DER, PER, XER, OER,
CBOR and other encoding rules.

# OPTIONS

## Stage Selection Options

-E
:   Run the ASN.1 parsing stage only. Print the reconstructed ASN.1 tre (text).

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
:	Destination directory for generated files (default current dir)

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
:   Refer to header files in `#include`s using **"**double**"** instead of **\<**angle**>** quotes.

-fknown-extern-type=*name*
:   Pretend the specified type is known.
    The compiler will assume the target language source files
    for the given type have been provided manually.

-fallow-newer-modules
:   Accept a module whose version OID is newer than the OID listed in
    `IMPORTS`; fail if the available module is older.

-fline-refs
:   Include ASN.1 module's line numbers in generated code comments.

-fno-constraints
:   Do not generate ASN.1 subtype constraint checking code.
    This may make a shorter executable.

-fno-include-deps
:   Do not generate courtesy #include lines for non-critical type dependencies.
    Helps prevent namespace collisions.
    
-fprefix=*prefix*
:	Add the specified prefix to all generated type names and filenames.
	This helps avoid naming conflicts in several scenarios:
	
	* **System header conflicts**: On case-insensitive filesystems (macOS HFS+, Windows),
	  ASN.1 types like "Time" would generate `Time.h`, which can conflict with 
	  system header `<time.h>`. asn1c now automatically disambiguates these generated
	  filenames (for example, `Time.h` becomes `asn1c_time.h` when no explicit prefix
	  is set). Using `-fprefix=ASN1_` still generates `ASN1_Time.h` when you need a
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

## Codecs Generation Options

-fgen-only-pdu-deps
:   Generate code only for types that are dependencies of -pdu types

-flist-deps
:	List PDU dependencies (requires -pdu option, no code generated)

-no-gen-BER
:   Do not generate the Basic Encoding Rules (BER, X.690) support code

-no-gen-XER
:   Do not generate the XML Encoding Rules (XER, X.693) support code

-no-gen-OER
:   Do not generate the Octet Encoding Rules (OER, X.696) support code

-no-gen-CBOR
:   Do not generate the Concise Binary Object Representation (CBOR, RFC 8949) support code.
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
:	Generate example top-level configure.ac and Makefile.am

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
:	Print out the collected object class matrix (debug)

-print-constraints
:   When **-EF** options are also specified,
    this option forces the compiler to explain its internal understanding
    of subtype constraints.

-print-lines
:   Generate "`-- #line`" comments in **-E** output.

# TRANSFER SYNTAXES

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
See the `asn1c-usage.pdf` for details.

-------------------------------------------------------------
Encoding       API function       Understood by API function
-------------- ------------------ ------------- -------------
BER            der_encode()       BER           ber_decode()

DER            der_encode()       DER, BER      ber_decode()

CER            _not supported_    CER, BER      ber_decode()

JER			   jer_encode()	      JER           jer_decode_

CBOR           cbor_encode()      CBOR          cbor_decode()

BASIC-OER      oer_encode()       *-OER         oer_decode()

CANONICAL-OER  oer_encode()       *-OER         oer_decode()

BASIC-UPER     uper_encode()      *-UPER        uper_decode()

CANONICAL-UPER uper_encode()      *-UPER        uper_decode()

*-APER         _not supported_    *-APER        _not supported_

BASIC-XER      xer_encode(...)    *-XER         xer_decode()

CANONICAL-XER  xer_encode         *-XER         xer_decode()
               (XER_F_CANONICAL)
-------------------------------------------------------------

*) Asterisk means both BASIC and CANONICAL variants.

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
is decoded.  No application changes are required to accept tagged data.
The helper `cbor_skip_tags(buf, size)` (in `cbor_support.h`) returns the
number of bytes occupied by leading tag headers, or -1 on error.

**Bignum tags:** Tags 2 and 3 are used internally by the INTEGER encoder
and decoder for values that exceed the 64-bit signed range, per RFC 8949.

# SEE ALSO

`unber`(1), `enber`(1).
