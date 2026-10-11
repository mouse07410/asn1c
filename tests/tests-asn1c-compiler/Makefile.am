
dist_check_SCRIPTS = check-parsing.sh check-version-string.sh check-options.sh \
    check-generated-warnings.sh check-exit-status.sh \
    check-tagged-choice-sequence-of.sh \
    check-pdu-deps-primitive-helpers.sh
TESTS_ENVIRONMENT= top_srcdir=${top_srcdir} top_builddir=${top_builddir}
TESTS = $(dist_check_SCRIPTS)
CLEANFILES = .check-parsing.*.tmp

ASN1C = $(top_builddir)/asn1c/asn1c

$(ASN1C):
	$(MAKE) -C $(top_builddir)/asn1c asn1c

check-parsing.sh.log check-version-string.sh.log check-options.sh.log \
check-generated-warnings.sh.log check-exit-status.sh.log \
check-tagged-choice-sequence-of.sh.log \
check-pdu-deps-primitive-helpers.sh.log: $(ASN1C)

EXTRA_DIST = README $(srcdir)/*asn1* $(srcdir)/exit-status/*.asn1
