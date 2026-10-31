# Rust information-object OPEN TYPE implementation plan

The Rust backend currently rejects information-object class and object-set
declarations and selector-driven OPEN TYPE fields. This plan describes future
work; it does not claim that these schemas or codecs are supported today.

1. Resolve each component-relation constraint to its object set, selector
   field, class selector column, and type column. Validate unique selector
   values, supported row types, selector ordering, references, and extension
   markers before publishing generated output. Start with one direct integer
   selector and one nonextensible, local object set in a UPER SEQUENCE.
2. Generate a typed enum whose variants correspond to the selected row types.
   Define how encoding rejects disagreement between a selector and variant.
   Define an explicit opaque unknown variant before accepting extensible sets.
3. Encode the selected inner value using the correct UPER open-type octet
   envelope. Decode within that bounded envelope, check inner constraints,
   exact consumption and padding, and charge inner and outer work to the same
   caller-provided resource budget. Handle fragmentation and length overflow.
4. Add generated C interoperability vectors for each selector, nested values,
   present and absent OPTIONAL fields, and unknown selectors. Test malformed
   lengths, truncation, invalid padding, spare codes, conflicting selectors,
   limits, and allocation failures. Run the required all-target, all-feature
   strict Clippy command on runtime and generated crates.
5. Expand only after the preceding subset is validated: additional selector
   shapes, constructed selected types, extensibility, other encodings, nested
   relations and imported object sets each require separate semantics and tests.
