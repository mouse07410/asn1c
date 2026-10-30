dist_check_SCRIPTS = check-rust-backend.sh
TESTS = $(dist_check_SCRIPTS)
TESTS_ENVIRONMENT = top_srcdir=$(top_srcdir) top_builddir=$(top_builddir)

ASN1C = $(top_builddir)/asn1c/asn1c

$(ASN1C):
	$(MAKE) -C $(top_builddir)/asn1c asn1c

# Depend on the compiler through the log list. Naming the individual log target
# here would override Automake's generated driver recipe for this single test.
$(TEST_LOGS): $(ASN1C)

EXTRA_DIST = $(srcdir)/FirstSlice.asn1 \
    $(srcdir)/SequenceSlice.asn1 \
    $(srcdir)/StringSlice.asn1 \
    $(srcdir)/OctetJER.asn1 \
    $(srcdir)/BitJERUnsupported.asn1 \
    $(srcdir)/BoundaryStrings.asn1 \
    $(srcdir)/OversizeOctets.asn1 \
    $(srcdir)/OversizeBits.asn1 \
    $(srcdir)/EnumSlice.asn1 \
    $(srcdir)/ExtensibleEnum.asn1 \
    $(srcdir)/VariableString.asn1 \
    $(srcdir)/ExtensibleString.asn1 \
    $(srcdir)/NamedBitString.asn1 \
    $(srcdir)/SequenceOptional.asn1 \
    $(srcdir)/SequenceDefaults.asn1 \
    $(srcdir)/SequenceNested.asn1 \
    $(srcdir)/NestedNameCollision.asn1 \
    $(srcdir)/SequenceExtension.asn1 \
    $(srcdir)/CParity.asn1 \
    $(srcdir)/Unsupported.asn1 \
    $(srcdir)/InvalidBounds.asn1 \
    $(srcdir)/NameCollision.asn1 \
    $(srcdir)/Alias.asn1 \
    $(srcdir)/Import.asn1 \
    $(srcdir)/TaggedBoolean.asn1 \
    $(srcdir)/ExtensibleInteger.asn1 \
    $(srcdir)/UnionInteger.asn1 \
    $(srcdir)/UnconstrainedInteger.asn1 \
    $(srcdir)/NamedNumber.asn1 \
    $(srcdir)/EncodingControl.asn1 \
    $(srcdir)/ReservedModule.asn1 \
    $(srcdir)/conformance.rs \
    $(srcdir)/additional_codecs.rs \
    $(srcdir)/jer_conformance.rs \
    $(srcdir)/sequence_conformance.rs \
    $(srcdir)/string_conformance.rs \
    $(srcdir)/boundary_conformance.rs \
    $(srcdir)/enum_conformance.rs \
    $(srcdir)/enum_jer_conformance.rs \
    $(srcdir)/octet_jer_conformance.rs \
    $(srcdir)/c_reference.c \
    $(srcdir)/c_additional.c \
    $(srcdir)/c_jer.c \
    $(srcdir)/c_sequence.c \
    $(srcdir)/nested_conformance.rs \
    $(srcdir)/c_string.c \
    $(srcdir)/c_enum.c \
    $(srcdir)/coverage.json \
    $(srcdir)/README.md
