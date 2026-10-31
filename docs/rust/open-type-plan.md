# Rust information-object OPEN TYPE

The Rust backend supports one narrow UPER subset: a module containing one
local class, one nonextensible object set of at most 32 rows, and one SEQUENCE
with exactly two required fields. A bounded INTEGER selector precedes the
selected OPEN TYPE field. The class has one UNIQUE INTEGER selector column and
one type column. Rows contain direct BOOLEAN or bounded INTEGER types, including
singleton INTEGERs. The generated enum uses object-set row order for its
variant names. Encoding verifies the selector matches the variant; decoding
rejects unknown selectors, malformed envelopes, spare values, and nonzero
padding. Both operations use the shared UPER cursor and resource budget.

C interoperability tests cover BOOLEAN, bounded INTEGER, and zero-width
singleton rows. Rust tests cover selector mismatch, unknown values, truncation,
invalid length and padding, spare codes, and work limits. This is a limited
implementation, not complete OPEN TYPE or codec conformance.

Future work includes extensible object sets with an explicit opaque unknown
variant; OPTIONAL fields and additional SEQUENCE members; nested, aliased and
imported selected types; other selector forms and ordering; fragmentation for
larger inner encodings; and APER, OER, JER and other codec support. Each needs
independent validation, resource accounting, and C interoperability vectors.
