#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "Inner.h"
#include "Outer.h"
#include "Wrapped.h"
#include <asn_application.h>
#include <uper_decoder.h>
#include <uper_encoder.h>

/* BIT STRING (CONTAINING Type) is an encoding of the Type (X.682 #11) */

static void
check_checker(void) {
	static const uint8_t bad[] = { 0x08, 0xa9 };
	static const uint8_t good[] = { 0xaa, 0x55, 0x2a };
	Outer_t outer;
	Wrapped_t wrapped;
	char errbuf[128];
	size_t errlen = sizeof(errbuf);

	/* An 8-bit value is not an encoding of Inner (24 bits). */
	memset(&outer, 0, sizeof(outer));
	outer.c.buf = (uint8_t *)bad;
	outer.c.size = sizeof(bad);
	assert(asn_check_constraints_with_syntax(
		   &asn_DEF_Outer, &outer, ATS_UNALIGNED_BASIC_PER, errbuf,
		   &errlen) != 0);

	outer.c.buf = (uint8_t *)good;
	outer.c.size = sizeof(good);
	errlen = sizeof(errbuf);
	assert(asn_check_constraints_with_syntax(
		   &asn_DEF_Outer, &outer, ATS_UNALIGNED_BASIC_PER, errbuf,
		   &errlen) == 0);

	/* Unused bits cannot be part of an encoding. */
	outer.c.bits_unused = 1;
	errlen = sizeof(errbuf);
	assert(asn_check_constraints_with_syntax(
		   &asn_DEF_Outer, &outer, ATS_UNALIGNED_BASIC_PER, errbuf,
		   &errlen) != 0);

	/* The same through a named type. */
	memset(&wrapped, 0, sizeof(wrapped));
	wrapped.buf = (uint8_t *)bad;
	wrapped.size = sizeof(bad);
	errlen = sizeof(errbuf);
	assert(asn_check_constraints_with_syntax(
		   &asn_DEF_Wrapped, &wrapped, ATS_UNALIGNED_BASIC_PER, errbuf,
		   &errlen) != 0);
	wrapped.buf = (uint8_t *)good;
	wrapped.size = sizeof(good);
	errlen = sizeof(errbuf);
	assert(asn_check_constraints_with_syntax(
		   &asn_DEF_Wrapped, &wrapped, ATS_UNALIGNED_BASIC_PER, errbuf,
		   &errlen) == 0);
}

static void
check_random(void) {
	int i;

	for(i = 0; i < 200; i++) {
		Outer_t *outer = 0;
		Wrapped_t *wrapped = 0;
		char errbuf[128];
		size_t errlen = sizeof(errbuf);

		assert(asn_random_fill_with_syntax(
			   &asn_DEF_Outer, (void **)&outer, 64,
			   ATS_UNALIGNED_BASIC_PER) == 0);
		assert(outer->c.bits_unused == 0);
		assert(outer->c.size == 3);	/* 16 + 8 bits */
		assert(asn_check_constraints_with_syntax(
			   &asn_DEF_Outer, outer, ATS_UNALIGNED_BASIC_PER, errbuf,
			   &errlen) == 0);
		ASN_STRUCT_FREE(asn_DEF_Outer, outer);

		errlen = sizeof(errbuf);
		assert(asn_random_fill_with_syntax(
			   &asn_DEF_Wrapped, (void **)&wrapped, 64,
			   ATS_UNALIGNED_BASIC_PER) == 0);
		assert(wrapped->bits_unused == 0);
		assert(wrapped->size == 3);
		assert(asn_check_constraints_with_syntax(
			   &asn_DEF_Wrapped, wrapped, ATS_UNALIGNED_BASIC_PER, errbuf,
			   &errlen) == 0);
		ASN_STRUCT_FREE(asn_DEF_Wrapped, wrapped);
	}
}

int
main(void) {
	check_checker();
	check_random();
	return 0;
}
