# Standards policy: `--strict-mode`

`asn1c --strict-mode schema.asn1` selects the standards policy for every
selected codec. Add `--rust` to select the Rust backend. Existing invocations
retain their compatibility behavior. This is an opt-in generation policy;
regenerate and rebuild the entire generated library when changing it.

The motivating [PR #494 comment](https://github.com/mouse07410/asn1c/pull/494#issuecomment-6562932108)
correctly distinguishes the X.691 non-known-multiplier string rules from this
fork's NGAP interoperability behavior. The standard determines the encoding
rule; deployment observations in that comment are the comment author's report,
not independent interoperability evidence collected for this implementation.

## Design and standards

The compiler stores one target-independent `A1C_STRICT_MODE` flag. C projects
persist `ASN_STRICT_MODE` in `asn_config.h`; Rust projects enable the vendored
runtime's Cargo `strict-mode` feature. Library dispatch rejects the same policy
compiler-flag conflicts as the CLI; the CLI also forbids the fixer-only
nonstandard SIZE applicability switch. Per-codec options select availability, independently of
this policy. No process-wide mutable runtime mode or new codec-context ABI is
introduced. Constraint validation reuses the existing thread-local syntax and
nested-CONTAINING depth limit; decoded-value validation additionally records a
scoped context so decoder-produced unknown extensions remain distinguishable
from application values that lack a selected CHOICE alternative.

* [X.691 (2021), 10.3.18 and 30.6–30.6.3](https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.691-202102-I%21%21PDF-E&lang=e&type=items):
  constraints on non-known-multiplier strings do not affect PER lengths or
  extensibility. Strict C output disables the generic SIZE fallback for UPER
  and APER. Abstract SIZE validation remains, including character counting for
  UTF8String. Other encodings retain their own constraint visibility rules.
* X.691 11.1 requires zero filler for complete PER encodings and octet
  alignment. Strict C complete decoders reject nonzero final filler; APER also
  rejects nonzero alignment filler. The raw bit-stream decoder retains its
  caller-specified framing contract.
* [X.680 (2021), clause 41](https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.680-202102-I%21%21PDF-E&lang=e&type=items)
  defines restricted string types. Strict C subtype callbacks preserve base
  repertoire/alignment checks before SIZE/FROM checks. Strict UTF8String uses
  one-to-four-octet Unicode scalar encodings, excluding surrogates and values
  beyond U+10FFFF, consistent with the ISO/IEC 10646 transformation described
  in [RFC 3629, section 3](https://www.rfc-editor.org/rfc/rfc3629.html#section-3).
* [X.690 (2021)](https://www.itu.int/rec/T-REC-X.690-202102-I/en)
  distinguishes BER from DER/CER. BER remains BER: legal BER representation
  alternatives are accepted. Strict C `asn_decode(..., ATS_DER, ...)` compares
  the decoded prefix with DER re-encoding; CER keeps its existing canonical
  validator. Strict mode does not rename BER as DER or turn basic OER/PER/XER
  into canonical variants.
* [X.693 (2021), OCTET STRING and collection rules](https://www.itu.int/rec/T-REC-X.693-202102-I/en):
  strict C rejects the nonstandard `H'...'` OCTET STRING wrapper, implicit
  Base64 guessing, BIT STRING quote/hex guessing, debug `SEQUENCE-OF`/`SET-OF` wrappers, arbitrary collection
  text, and mismatched collection closing tags. Explicit schema BASE64
  instructions continue to select their dedicated decoder. Schema-derived
  wrappers and normal streaming XER remain supported.

Example from the comment, `T ::= SEQUENCE { s UTF8String (SIZE(0..32)) }`,
with `s = "ab"`:

| UPER profile | Octets | Meaningful bits |
| --- | --- | --- |
| Compatibility default | `09 85 88` | 22 |
| `--strict-mode` | `02 61 62` | 24 |

The comment's “5-bit constrained length” is an off-by-one description:
`SIZE(0..32)` has 33 possible lengths and needs six length bits, hence 22
meaningful bits for the compatibility vector. Its three reported octets match.

This is a wire-format change. Both peers must agree on the profile. Strict
mode never guesses the peer's profile or silently retries the other encoding.
The same rule covers non-known-multiplier roots, aliases, members and
extensible SIZE constraints. Known-multiplier strings keep their PER rules.

## Codec and target coverage

| Format | C strict policy | Rust strict policy within the supported subset |
| --- | --- | --- |
| BER/DER/CER | Validate root constraints before encoding and after successful decode; exact DER verification through `ATS_DER`; existing CER canonical verification | Existing schema bounds and CER canonical checks; feature validates restricted-string content on BER input and DER output, including record fields; scalar UTF-8 |
| UPER/APER | Standards NKM metadata, root constraints, zero complete-encoding filler; APER alignment filler | Existing mandatory bounds and framing checks; unsupported NKM string schemas still fail before crate publication |
| OER | Root constraints; existing OER visibility rules | Existing mandatory supported-schema bounds and framing checks |
| XER | Root constraints; standard default OCTET STRING syntax; schema-derived collection wrappers | Existing field bounds and XML character checks for supported flat record encoding; no generated XER decoder |
| JER | Root constraints in addition to existing JSON grammar checks | Existing mandatory supported-schema bounds and JSON grammar checks |
| CBOR | Root constraints in addition to existing CBOR framing checks | Existing mandatory supported-schema bounds and framing checks |

`--strict-mode` conflicts with `-fno-constraints`, `-fbless-SIZE`, and
`-ftolerant-utc-time` in
either argument order and for either target. Duplicate strict switches and
spellings with values are errors. `--` and operands of short options retain
their usual interpretation. C compilation also rejects a runtime configured
with both `ASN_STRICT_MODE` and `ASN_ENABLE_TOLERANT_UTCTIME`.

Strict native ENUMERATED validation checks the full stored `long`, avoiding
C enum-width truncation. Unknown extensions permitted by the selected encoding and extensible schema
remain permitted, including existing skipped-CHOICE and ENUMERATED markers.
`ASN_REJECT_UNKNOWN_EXTENSIONS` remains an independent application policy.
Applications must still inspect the markers described in the README.

## API contracts and limits

C enforcement covers the public root codec functions (`ber_decode`,
`der_encode` and its buffer variant, `cer_encode`/`cer_decode`, `oer_*`,
`uper_*`, `aper_*`, `xer_*`, `jer_*`, and `cbor_*`) and the generic
`asn_encode*`/`asn_decode` APIs. Direct calls to descriptor operations such as
`td->op->ber_decoder` are internal operations and bypass root validation.
For `-R` output or a separately built support library, configure every runtime
translation unit with `ASN_STRICT_MODE`; defining it in application code alone
cannot change an already-built runtime. Do not mix generated PER descriptors
from different profiles.

Ordinary streaming decoders validate only after `RC_OK`. They retain their
consumed units and storage ownership on a constraint failure; callers must
free/reset output as after other decode failures. Strict DER verification is
one-shot, like the existing CER validator: on `RC_WMORE` supply the complete
input again, not just the unconsumed suffix. Partial/error DER output is freed
or caller-owned storage reset and consumption is zero. Successful verification
consumes one PDU prefix, allowing concatenated PDUs. Encoders validate before
publishing callback output.

The profile targets identified compatibility allowances and existing
constraint callbacks. It is not a certification of every ASN.1 rule, adds no
unsupported Rust codec/type combinations, and cannot validate constraints or
character repertoires that the compiler/runtime does not implement. In
particular, the legacy ISO-2022-based string repertoires still have incomplete
semantic validators. Existing canonical-OER/PER/XER support limits also remain.
Opaque ANY/open-type bytes are not independently canonicalized by DER
re-encoding; applications must validate their selected contents. A comparison
against an encoder that preserves opaque bytes cannot certify those bytes.
Rust still exposes BER decoding and DER encoding, not a new DER decode API.
Cargo unifies dependency features: sharing this runtime with a strict crate
also enables its strict checks for other users of the same dependency.

## Security and validation

The security objective is to reduce inconsistent acceptance, value-validation
bypasses and profile ambiguity. Untrusted wire data is checked after bounded
codec parsing, never while a streaming value is incomplete. Existing codec
resource limits, allocation failures and nested-CONTAINING depth bounds remain
in force. DER comparison uses the consumed input length as its output-comparison
budget, without allocating another encoding. Unknown extensions are not treated
as malformed solely because the local schema predates them.

`check-strict-mode.sh` builds separate default and strict C projects and checks
independent PER bytes, all format families, invalid values, streaming and
canonical distinctions, explicit XER BASE64, collection wrappers, extension
markers, subtype repertoire/alignment and deterministic short-input mutation.
`check-strict-mode-cli.sh` checks policy conflicts, extended SIZE rejection
and long-option parsing. `check-rust-strict-mode.sh` exercises supported scalar codecs in both profiles,
strict XER output, unsupported NKM rejection and exact pedantic/nursery Clippy.
Runtime tests cover feature-dependent character-string acceptance. These tests
are bounded regressions, not exhaustive fuzzing or a standards-conformance
proof. See [the validation record](strict-mode-validation.md) for the checks actually executed.
