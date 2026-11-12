#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include <GeneralizedTime.c>
#include <UTCTime.h>

/*
 * Purpose: verify whether the runtime accepts one UTCTime value.
 * Original source: X.680 47.3 and issue #596 compatibility requirements.
 * Version/date: 1.0, 2026-11-12.
 * Parameters: value is a NUL-terminated UTCTime string; accepted is expected.
 * Returns: none; failure is reported by assertion.
 * Errors: malformed values set errno in the runtime parser.
 * Responsible party: asn1c maintainers.
 * History: added strict calendar and lexical regression coverage.
 * Example: expect_parse("0002291200Z", 1).
 */
static void
expect_parse(const char *value, int accepted) {
	UTCTime_t input;
	time_t parsed;

	input.buf = (uint8_t *)value;
	input.size = strlen(value);
	errno = 0;
	parsed = asn_UT2time(&input, 0, 1);
	if((parsed != (time_t)-1) != accepted) {
		fprintf(stderr, "UTCTime [%s]: expected %s, errno=%d\n", value,
		        accepted ? "success" : "failure", errno);
		assert((parsed != (time_t)-1) == accepted);
	}
}

/*
 * Purpose: exercise strict grammar and tolerant compatibility behavior.
 * Original source: X.680 47.3 and issue #596 regression requirements.
 * Version/date: 1.0, 2026-11-12.
 * Parameters: none; the compile-time macro selects tolerant expectations.
 * Returns: none; failure is reported by assertion.
 * Errors: reports the exact value when parsing differs from expectation.
 * Responsible party: asn1c maintainers.
 * History: covers leap years, calendar bounds, ranges, and lexical forms.
 * Example: called by main() in both default and tolerant builds.
 */
static void
check_strict_grammar(void) {
	/* Seconds may be present or omitted; four-digit offsets remain valid. */
	expect_parse("0002291200Z", 1);      /* 2000 leap day, without seconds. */
	expect_parse("040229120000Z", 1);    /* 2004 leap day, with seconds. */
	expect_parse("0402291200+0530", 1);  /* Positive hhmm offset. */
	expect_parse("0402291200-0800", 1);  /* Negative hhmm offset. */
	expect_parse("991231235959Z", 1);    /* Year pivot maps 99 to 1999. */
	expect_parse("000101000000Z", 1);    /* Year pivot maps 00 to 2000. */

	/* Strict mode rejects impossible dates, out-of-range fields, and syntax. */
#ifndef ASN_ENABLE_TOLERANT_UTCTIME
	expect_parse("010229120000Z", 0);    /* 2001 is not a leap year. */
	expect_parse("040231120000Z", 0);    /* February 31 does not exist. */
	expect_parse("040230120000Z", 0);    /* February 30 does not exist. */
	expect_parse("040200120000Z", 0);    /* Day zero. */
	expect_parse("041332120000Z", 0);    /* Month 13. */
	expect_parse("041231240000Z", 0);    /* Hour 24. */
	expect_parse("041231236000Z", 0);    /* Minute 60. */
	expect_parse("041231235960Z", 0);    /* Seconds are limited to 00..59. */
	expect_parse("040229120000+00", 0);  /* Short offset is not hhmm. */
	expect_parse("040229120000+0560", 0);/* Offset minute 60. */
	expect_parse("040229120000.1Z", 0); /* Fractions are not UTCTime syntax. */
	expect_parse("040229120000", 0);     /* Timezone is required. */
	/* Compatibility mode keeps selected legacy parser normalization. */
#else
	expect_parse("040229120000+00", 1);
	expect_parse("040231120000Z", 1);
	expect_parse("040230120000Z", 1);
	expect_parse("041231236000Z", 1);
	expect_parse("041231235960Z", 1);
	expect_parse("040229120000+0560", 1);
	expect_parse("040229120000.1Z", 1);
	expect_parse("040229120000", 1);
	/* These fields were already checked by the old parser. */
	expect_parse("010229120000Z", 1);
	expect_parse("040200120000Z", 0);
	expect_parse("041332120000Z", 0);
	expect_parse("041231240000Z", 0);
#endif
}

/*
 * Purpose: ensure syntax validation does not rely on time_t conversion.
 * Original source: issue #596 conversion-sentinel regression requirement.
 * Version/date: 1.0, 2026-11-12.
 * Parameters: none.
 * Returns: none; assertion failure means a valid syntax value was rejected.
 * Errors: asn_UT2time may use -1 as both conversion error and a valid instant.
 * Responsible party: asn1c maintainers. History: added for strict constraints.
 * Example: checks 1969-12-31T23:59:59Z without using the time result alone.
 */
static void
check_epoch_sentinel(void) {
#ifndef ASN_ENABLE_TOLERANT_UTCTIME
	UTCTime_t input;
	const char text[] = "691231235959Z";

	input.buf = (uint8_t *)text;
	input.size = sizeof(text) - 1;
	assert(UTCTime_constraint(&asn_DEF_UTCTime, &input, 0, 0) == 0);
#endif
}

static void
check(char *time_str, time_t sample, int as_gmt) {
	UTCTime_t gt;
	struct tm tm;
	time_t tloc;

	gt.buf = (uint8_t *)time_str;
	gt.size = strlen(time_str);

	tloc = asn_UT2time(&gt, &tm, as_gmt);
	printf("[%s] -> %ld == %ld\n", time_str, (long)tloc, (long)sample);
	if(tloc != -1)
	printf("\t%d-%d-%dT%02d:%02d:%02d %ld\n",
		tm.tm_year + 1900,
		tm.tm_mon + 1,
		tm.tm_mday,
		tm.tm_hour,
		tm.tm_min,
		tm.tm_sec,
		GMTOFF(tm)
	);
	assert(tloc == sample);

	assert(tloc == -1 || as_gmt == 0 || GMTOFF(tm) == 0);

	if(as_gmt) check(time_str, sample, as_gmt);
}

static void
compare(int lineno, int cmp_control, const char *astr, const char *bstr) {
    UTCTime_t a = {(uint8_t *)strdup(astr), strlen(astr), {0, 0, 0, 0, 0}};
    UTCTime_t b = {(uint8_t *)strdup(bstr), strlen(bstr), {0, 0, 0, 0, 0}};
    int cmp_result =
        asn_DEF_UTCTime.op->compare_struct(&asn_DEF_UTCTime, &a, &b);
    if(cmp_result != cmp_control) {
        fprintf(stderr, "%03d: [%s] == [%s] = %d, expected %d\n", lineno, astr,
                bstr, cmp_result, cmp_control);
        assert(cmp_result == cmp_control);
    }
    ASN_STRUCT_RESET(asn_DEF_UTCTime, &a);
    ASN_STRUCT_RESET(asn_DEF_UTCTime, &b);
}

int
main(int ac, char **av) {

	(void)av;
	check_strict_grammar();
	check_epoch_sentinel();

	check("0401250", -1, 0);
	check("0401250930", -1, 0);	/* "Z" or "(+|-)hhmm" required */
	check("04012509300", -1, 0);
	check("040125093000-", -1, 0);
	check("040125093007-0", -1, 0);
	check("040125093007-080", -1, 0);
	check("0401250930.01Z", -1, 0);

	check("040125093007Z", 1075023007, 0);
#ifdef ASN_ENABLE_TOLERANT_UTCTIME
	check("040125093007+00", 1075023007, 0);
#else
	check("040125093007+00", -1, 0);
#endif
	check("040125093007-0800", 1075051807, 0);

	if(ac > 1) {
		/* These will be valid only inside PST time zone */
		check("040125093007", 1075051807, 0);
		check("040125093000,01", 1075051800, 0);
		check("040125093000,1234", 1075051800, 0);
	}

    compare(__LINE__, 0, "040125093007", "040125093007");
    compare(__LINE__, 0, "040125093007-0000", "040125093007Z");
    compare(__LINE__, 1, "040125093008", "040125093007");
    compare(__LINE__, 1, "040125093008-0000", "040125093007-0000");
    compare(__LINE__, 0, "040125093008-0000", "040125093008-0000");
    compare(__LINE__, 1, "040125093008-0000", "040125093007Z");
    compare(__LINE__, 0, "040125093007-0000", "040125093007+0000");
    compare(__LINE__, 1, "040125093007-0030", "040125093007Z");
    compare(__LINE__, -1, "040125093007+0030", "040125093007Z");

	return 0;
}

