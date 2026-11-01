@CODE_COVERAGE_RULES@

SUBDIRS = check-src

dist_check_SCRIPTS = check-assembly.sh

#Filter out the coverage options from CFLAGS as we don't need
#code coverage data for the tests executables
CFLAGS = $(filter-out $(CODE_COVERAGE_CFLAGS), @CFLAGS@)

TESTS_ENVIRONMENT= \
				   CC="${CC}" \
				   CXX="${CXX}" \
				   CFLAGS="${TESTSUITE_CFLAGS} ${CFLAGS} ${DEFS}" \
				   CXXFLAGS="${CXXFLAGS} ${DEFS}" \
				   LDFLAGS="${LDFLAGS}" \
				   LIBFUZZER_CFLAGS="${LIBFUZZER_CFLAGS}" \
				   FUZZ_TIME="${FUZZ_TIME}" \
				   FUZZ_ASAN_OPTIONS="${FUZZ_ASAN_OPTIONS}" \
				   ASAN_ENV_FLAGS="@ASAN_ENV_FLAGS@"       \
				   srcdir=${srcdir} \
				   abs_top_srcdir=${abs_top_srcdir} \
				   abs_top_builddir=${abs_top_builddir} \
				   ${srcdir}/check-assembly.sh

TESTS = 
TESTS += check-src/check-03.-fwide-types.c
TESTS += check-src/check-119.-fwide-types.-gen-UPER.c
TESTS += check-src/check-119.-gen-UPER.c
TESTS += check-src/check-126.-gen-UPER.c
TESTS += check-src/check-126.-gen-APER.c
TESTS += check-src/check-127.-gen-UPER.c
TESTS += check-src/check-131.-gen-UPER.c
TESTS += check-src/check-132.-gen-UPER.c
TESTS += check-src/check-133.-gen-UPER.c
TESTS += check-src/check-135.-gen-OER.c
TESTS += check-src/check-148.c
TESTS += check-src/check-19.c
TESTS += check-src/check-22.-fwide-types.c
TESTS += check-src/check-24.-fwide-types.c
TESTS += check-src/check-25.-fwide-types.c
TESTS += check-src/check-30.-fwide-types.c
TESTS += check-src/check-31.-fwide-types.c
TESTS += check-src/check-32.c
TESTS += check-src/check-33.c
TESTS += check-src/check-35.c
TESTS += check-src/check-39.c
TESTS += check-src/check-41.-fwide-types.c
TESTS += check-src/check-41.c
TESTS += check-src/check-42.c
TESTS += check-src/check-43.c
TESTS += check-src/check-44.c
TESTS += check-src/check-46.c
TESTS += check-src/check-48.c
TESTS += check-src/check-50.c
TESTS += check-src/check-59.c
TESTS += check-src/check-60.c
TESTS += check-src/check-62.c
TESTS += check-src/check-65.c
TESTS += check-src/check-70.-fwide-types.c
TESTS += check-src/check-70.c
TESTS += check-src/check-72.-fcompound-names.c
TESTS += check-src/check-73.c
TESTS += check-src/check-92.-findirect-choice.c
TESTS += check-src/check-92.c
TESTS += check-src/check-158.-fcompound-names.c
TESTS += check-src/check-159.c
TESTS += check-src/check-164.c
TESTS += check-src/check-539.-gen-UPER.c
TESTS += check-src/check-540.-gen-UPER.c
TESTS += check-src/check-541.-gen-UPER.c
TESTS += check-src/check-542.-gen-UPER.c
TESTS += check-src/check-543.-gen-UPER.c
TESTS += check-src/check-544.-gen-OER.c
TESTS += check-src/check-545.-gen-UPER.c
TESTS += check-src/check-546.-gen-UPER.c
TESTS += check-src/check-547.c
TESTS += check-src/check-548.-gen-UPER.c
TESTS += check-src/check-548.-gen-APER.c
TESTS += check-src/check-550.-gen-UPER.c
TESTS += check-src/check-552.-gen-UPER.-gen-APER.c
TESTS += check-src/check-561.-gen-UPER.-gen-APER.c
TESTS += check-src/check-563.-gen-UPER.-gen-APER.c
TESTS += check-src/check-583.-fcompound-names.-gen-UPER.-gen-APER.c
TESTS += check-src/check-584.-gen-UPER.-gen-APER.c
TESTS += check-src/check-585.-fcompound-names.c
TESTS += check-src/check-593.-gen-UPER.c
TESTS += check-src/check-594.-gen-OER.c
check_595_prefix = check-src/check-595.-gen-APER.
check_595_disabled_a = -no-gen-BER.-no-gen-XER.-no-gen-JER.-no-gen-CBOR.
check_595_disabled_b = -no-gen-OER.-no-gen-UPER.-no-gen-print.-no-gen-random-fill.c
TESTS += $(check_595_prefix)$(check_595_disabled_a)$(check_595_disabled_b)
TESTS += check-src/check-596.-gen-UPER.c
TESTS += check-src/check-597.-gen-UPER.c
TESTS += check-src/check-598.-gen-APER.c
TESTS += check-src/check-599.-gen-OER.c
TESTS += check-src/check-600.-gen-UPER.-gen-APER.-gen-OER.c
TESTS += check-src/check-601.-fcompound-names.-gen-JER.-gen-CBOR.c
TESTS += check-src/check-601.-findirect-choice.-fcompound-names.-gen-CBOR.c
TESTS += check-src/check-602.-findirect-choice.-fcompound-names.-gen-JER.c
TESTS += check-src/check-603.-gen-UPER.c
TESTS += check-src/check-582.-gen-UPER.-gen-APER.c
TESTS += check-src/check-569.-gen-UPER.c
TESTS += check-src/check-570.c
TESTS += check-src/check-173.-findirect-choice.-fcompound-names.-gen-UPER.-gen-APER.c
TESTS += check-src/check-184.c
TESTS += check-src/check-185.c
TESTS += check-src/check-201.c
TESTS += check-src/check-202.-gen-CBOR.c
TESTS += check-src/check-203.c
TESTS += check-src/check-204.c
TESTS += check-src/check-211.c
TESTS += check-src/check-212.-fcompound-names.c
TESTS += check-src/check-213.c

if TEST_64BIT
TESTS += check-src/check64-134.-gen-UPER.c
TESTS += check-src/check64-136.-gen-OER.c
endif

XFAIL_TESTS =

EXTRA_DIST =    \
    data-583    \
    data-585    \
    data-62     \
    data-70     \
    data-119    \
    data-126    \
    data-202    \
    data-203    \
    check-src/check64-134.-gen-UPER.c    \
    check-src/check64-136.-gen-OER.c
EXTRA_DIST += $(check_595_prefix)$(check_595_disabled_a)$(check_595_disabled_b)
EXTRA_DIST += check-src/check-596.-gen-UPER.c
EXTRA_DIST += check-src/check-597.-gen-UPER.c
EXTRA_DIST += check-src/check-598.-gen-APER.c
EXTRA_DIST += check-src/check-599.-gen-OER.c
EXTRA_DIST += check-src/check-600.-gen-UPER.-gen-APER.-gen-OER.c
EXTRA_DIST += check-src/check-601.-fcompound-names.-gen-JER.-gen-CBOR.c
EXTRA_DIST += check-src/check-601.-findirect-choice.-fcompound-names.-gen-CBOR.c
EXTRA_DIST += check-src/check-602.-findirect-choice.-fcompound-names.-gen-JER.c
EXTRA_DIST += check-src/check-603.-gen-UPER.c

clean-local:
	rm -rf test-*

TESTS += check-src/check-604.-findirect-choice.-fcompound-names.-gen-XER.c
EXTRA_DIST += check-src/check-604.-findirect-choice.-fcompound-names.-gen-XER.c
TESTS += check-src/check-605.-findirect-choice.-fcompound-names.-gen-CBOR.c
EXTRA_DIST += check-src/check-605.-findirect-choice.-fcompound-names.-gen-CBOR.c
EXTRA_DIST += data-605
TESTS += check-src/check-606.-gen-CBOR.c
EXTRA_DIST += check-src/check-606.-gen-CBOR.c
EXTRA_DIST += data-606
TESTS += check-src/check-608.-fcompound-names.-gen-JER.c
EXTRA_DIST += check-src/check-608.-fcompound-names.-gen-JER.c
TESTS += check-src/check-609.-gen-UPER.-gen-APER.c
EXTRA_DIST += check-src/check-609.-gen-UPER.-gen-APER.c
