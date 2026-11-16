
dist_check_SCRIPTS = check-parsing.sh check-version-string.sh check-options.sh \
    check-generated-warnings.sh check-exit-status.sh \
    check-tagged-choice-sequence-of.sh \
    check-pdu-deps-primitive-helpers.sh check-issue-586.sh
dist_check_SCRIPTS += check-no-applicable-constraints.sh
dist_check_SCRIPTS += check-xer-text-bitstring.sh
dist_check_SCRIPTS += check-issue-592.sh
dist_check_SCRIPTS += check-standard-module-order.sh
dist_check_SCRIPTS += check-reversed-ranges.sh
dist_check_SCRIPTS += check-boundary-ranges.sh
TESTS_ENVIRONMENT= top_srcdir=${top_srcdir} top_builddir=${top_builddir} \
	CC="$(CC)"
TESTS = $(dist_check_SCRIPTS)
CLEANFILES = .check-parsing.*.tmp

ASN1C = $(top_builddir)/asn1c/asn1c

$(ASN1C):
	$(MAKE) -C $(top_builddir)/asn1c asn1c

check-parsing.sh.log check-version-string.sh.log check-options.sh.log \
check-generated-warnings.sh.log check-exit-status.sh.log \
check-tagged-choice-sequence-of.sh.log \
check-pdu-deps-primitive-helpers.sh.log \
check-issue-586.sh.log check-no-applicable-constraints.sh.log \
check-xer-text-bitstring.sh.log check-issue-592.sh.log \
check-standard-module-order.sh.log check-reversed-ranges.sh.log: $(ASN1C)

EXTRA_DIST = README $(srcdir)/*asn1* $(srcdir)/exit-status/*.asn1 \
    $(srcdir)/issue-586/OpenV1.asn1 \
    $(srcdir)/issue-586/issue-586.c \
    $(srcdir)/no-applicable-constraints/NoApplicable.asn1 \
    $(srcdir)/no-applicable-constraints/check-no-applicable-constraints.c \
    $(srcdir)/214-xer-text-bitstring-OK.asn1 \
    $(srcdir)/check-xer-text-bitstring.c \
    $(srcdir)/issue-592/StructTags.asn1
