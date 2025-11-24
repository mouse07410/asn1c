dist_check_SCRIPTS = run.sh

TESTS_ENVIRONMENT = \
	abs_top_srcdir=${abs_top_srcdir} \
	abs_top_builddir=${abs_top_builddir} \
	srcdir=${srcdir}

TESTS = $(dist_check_SCRIPTS)

EXTRA_DIST = C2X.asn s4.xer

CLEANFILES = *.[choa] converter-example converter-example.mk Makefile.am.*

# Remove files copied from srcdir during out-of-tree builds (distcheck)
clean-local:
	if [ "$(srcdir)" != "." ]; then \
		rm -f C2X.asn s4.xer; \
	fi
