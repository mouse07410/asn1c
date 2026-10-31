# Rust information-object OPEN TYPE

The Rust backend supports a narrow UPER, APER, OER, and CBOR subset: a module containing one
local class, one nonextensible object set of at most 32 rows, and one SEQUENCE
with exactly two required fields. A bounded INTEGER selector precedes the
selected OPEN TYPE field. The class has one UNIQUE INTEGER selector column and
one type column. Rows contain direct BOOLEAN or bounded INTEGER types, including
singleton INTEGERs. The generated enum uses object-set row order for its
variant names. Encoding verifies the selector matches the variant; decoding
rejects unknown selectors, malformed envelopes, spare values, and nonzero
padding. UPER and APER use a shared cursor and resource budget. OER accounts
for both the outer framing and selected primitive work in one operation budget.
APER requires selector bounds 0..255 and each selected INTEGER's range span at
most 255, so both the selector and OPEN TYPE envelope start octet-aligned.
CBOR uses the ordinary SEQUENCE text-key map. The selected field contains a
direct CBOR BOOLEAN or bounded INTEGER. Decoding accepts either field order,
skips unique unknown keys, rejects duplicates and missing fields, and requires
the selected value to consume its complete encoded item.

C interoperability tests cover BOOLEAN, bounded INTEGER, and singleton rows,
including multi-octet OER selector and value widths. Rust tests cover selector mismatch, unknown values, truncation,
invalid length and padding, spare codes, and work limits. This is a limited
implementation, not complete OPEN TYPE or codec conformance.
CBOR tests compare C/Rust wire vectors and reject selector mismatch, malformed
selected values, duplicate keys, and missing fields.

Future work includes extensible object sets with an explicit opaque unknown
variant; OPTIONAL fields and additional SEQUENCE members; nested, aliased and
imported selected types; other selector forms and ordering; fragmentation for
larger inner encodings; wider APER constraints; and JER and other codecs. Each needs
independent validation, resource accounting, and C interoperability vectors.
