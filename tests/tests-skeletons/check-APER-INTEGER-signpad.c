/*
 * Regression tests for PER INTEGER representations (APER).
 *
 * X.691 distinguishes three cases for a whole number that carries a
 * length determinant:
 *
 *   - Unconstrained whole number (X.691 11.8, formerly 10.8): the value
 *     n is encoded as a 2's-complement-binary-integer in the minimum
 *     number of octets. A positive value whose most significant octet
 *     has the high bit set therefore DOES carry a leading 0x00 sign
 *     octet, e.g. 65000 -> 03 00 fd e8.
 *
 *   - Semi-constrained whole number (X.691 11.7, formerly 10.7): the
 *     offset (n - lb) is encoded as a non-negative-binary-integer in the
 *     minimum number of octets, so the sign octet must NOT be emitted,
 *     e.g. 65000 in INTEGER (0..MAX) -> 02 fd e8.
 *
 *   - Constrained whole number (X.691 11.5): encoded as a bit-field or
 *     as a length-prefixed minimal value (offset from the lower bound),
 *     again with no sign octet, e.g. 65000 in INTEGER (0..100000) ->
 *     40 fd e8 (aligned).
 *
 * The bug this guards against: INTEGER_encode_aper() leaked the signed
 * two's-complement storage of a non-negative SEMI-CONSTRAINED value into
 * the length-determinant encoding (65000 -> 03 00 fd e8 instead of
 * 02 fd e8). The fix normalizes only the semi-constrained case and
 * leaves the unconstrained 2's-complement form untouched (verified
 * against the FFASN1 reference implementation).
 */

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <INTEGER.h>
#include <INTEGER.c>
#include <INTEGER_aper.c>
#include <per_support.c>
#include <aper_support.c>
#include <aper_support.h>

static int FailOut(const void *data, size_t size, void *op_key) {
	(void)data;
	(void)size;
	(void)op_key;
	assert(!"UNREACHABLE");
	return 0;
}

static void normalize(asn_per_outp_t *po) {
	if(po->nboff >= 8) {
		po->buffer += (po->nboff >> 3);
		po->nbits  -= (po->nboff & ~0x07);
		po->nboff  &= 0x07;
	}
}

static void
check_case(int lineno, const char *what, int unsigned_spec, intmax_t value,
           const asn_per_constraints_t *constraints,
           const uint8_t *expected, size_t expected_bytes, int roundtrip) {
	INTEGER_t st;
	INTEGER_t *reconstructed_st = 0;
	struct asn_INTEGER_specifics_s specs;
	asn_enc_rval_t enc_rval;
	asn_dec_rval_t dec_rval;
	asn_per_outp_t po;
	asn_per_data_t pd;
	size_t i;

	printf("%d: [%s] encoding %s %jd, expect", lineno, what,
		unsigned_spec ? "unsigned" : "signed", value);
	for(i = 0; i < expected_bytes; i++)
		printf(" %02x", expected[i]);
	printf("\n");

	memset(&st, 0, sizeof(st));
	memset(&po, 0, sizeof(po));
	memset(&specs, 0, sizeof(specs));

	if(unsigned_spec) {
		assert(value >= 0);
		asn_ulong2INTEGER(&st, (unsigned long)value);
	} else {
		asn_imax2INTEGER(&st, value);
	}

	po.buffer = po.tmpspace;
	po.nboff = 0;
	po.nbits = 8 * sizeof(po.tmpspace);
	po.output = FailOut;

	specs.field_width = sizeof(long);
	specs.field_unsigned = unsigned_spec;

	asn_DEF_INTEGER.specifics = &specs;
	enc_rval = INTEGER_encode_aper(&asn_DEF_INTEGER, constraints, &st, &po);
	assert(enc_rval.encoded == 0);
	assert(po.nboff % 8 == 0);
	normalize(&po);

	size_t bytes_used = po.buffer - po.tmpspace;
	if(bytes_used != expected_bytes) {
		fprintf(stderr, "%d: encoded %zu octets, expected %zu\n",
			lineno, bytes_used, expected_bytes);
		assert(0);
	}
	if(memcmp(po.tmpspace, expected, expected_bytes) != 0) {
		fprintf(stderr, "%d:", lineno);
		for(i = 0; i < bytes_used; i++)
			fprintf(stderr, " %02x", po.tmpspace[i]);
		fprintf(stderr, " differs from the expected octets\n");
		assert(0);
	}

	if(roundtrip) {
		pd.buffer = po.tmpspace;
		pd.nboff = 0;
		pd.nbits = 8 * (po.buffer - po.tmpspace) + po.nboff;
		pd.moved = 0;
		dec_rval = INTEGER_decode_aper(0, &asn_DEF_INTEGER, constraints,
						(void **)&reconstructed_st, &pd);
		assert(dec_rval.code == RC_OK);
		if(unsigned_spec) {
			unsigned long reconstructed_value = 0;
			asn_INTEGER2ulong(reconstructed_st, &reconstructed_value);
			if(reconstructed_value != (unsigned long)value) {
				fprintf(stderr, "%d: decoded %lu, expected %lu\n", lineno,
					reconstructed_value, (unsigned long)value);
				assert(0);
			}
		} else {
			long reconstructed_value = 0;
			asn_INTEGER2long(reconstructed_st, &reconstructed_value);
			assert(reconstructed_value == value);
		}
		ASN_STRUCT_FREE(asn_DEF_INTEGER, reconstructed_st);
	}
	ASN_STRUCT_RESET(asn_DEF_INTEGER, &st);
}

int
main() {
	/* No PER constraints: unconstrained whole number (X.691 11.8). */
	static struct asn_per_constraints_s ct_unconstrained = {
		{APC_UNCONSTRAINED, -1, -1, 0, 0},
		{APC_UNCONSTRAINED, -1, -1, 0, 0}, 0, 0};

	/* INTEGER (0..65535), 16-bit fully constrained (X.691 11.5). */
	static struct asn_per_constraints_s ct_0_65535 = {
		{APC_CONSTRAINED, 16, 16, 0, 65535},
		{APC_UNCONSTRAINED, -1, -1, 0, 0}, 0, 0};

	/* INTEGER (0..100000), 17-bit fully constrained (X.691 11.5). */
	static struct asn_per_constraints_s ct_0_100000 = {
		{APC_CONSTRAINED, 17, 17, 0, 100000},
		{APC_UNCONSTRAINED, -1, -1, 0, 0}, 0, 0};

	/* INTEGER (0..MAX), semi-constrained (X.691 11.7). */
	static struct asn_per_constraints_s ct_semi_0 = {
		{APC_SEMI_CONSTRAINED, -1, -1, 0, 0},
		{APC_UNCONSTRAINED, -1, -1, 0, 0}, 0, 0};

	/* INTEGER (8..MAX), semi-constrained (X.691 11.7). */
	static struct asn_per_constraints_s ct_semi_8 = {
		{APC_SEMI_CONSTRAINED, -1, -1, 8, 0},
		{APC_UNCONSTRAINED, -1, -1, 0, 0}, 0, 0};

	/* INTEGER (-8..MAX), semi-constrained (X.691 11.7). */
	static struct asn_per_constraints_s ct_semi_m8 = {
		{APC_SEMI_CONSTRAINED, -1, -1, -8, 0},
		{APC_UNCONSTRAINED, -1, -1, 0, 0}, 0, 0};

	/* ---- Unconstrained: 2's-complement, sign octet significant ---- */
	/* 65000 = 0xfde8 needs the leading 0x00 sign octet here. */
	static const uint8_t un_65000[] = {0x03, 0x00, 0xfd, 0xe8};
	check_case(__LINE__, "unconstrained", 0, 65000, &ct_unconstrained,
		un_65000, sizeof(un_65000), 1);
	check_case(__LINE__, "unconstrained", 1, 65000, &ct_unconstrained,
		un_65000, sizeof(un_65000), 1);

	/* 128 = 0x80 also needs a sign octet; 32768 = 0x8000 likewise. */
	static const uint8_t un_128[] = {0x02, 0x00, 0x80};
	static const uint8_t un_32768[] = {0x03, 0x00, 0x80, 0x00};
	check_case(__LINE__, "unconstrained", 0, 128, &ct_unconstrained,
		un_128, sizeof(un_128), 1);
	check_case(__LINE__, "unconstrained", 0, 32768, &ct_unconstrained,
		un_32768, sizeof(un_32768), 1);

	/* Top bit clear: no sign octet needed (0x01000000). */
	static const uint8_t un_16777216[] = {0x04, 0x01, 0x00, 0x00, 0x00};
	check_case(__LINE__, "unconstrained", 0, 16777216, &ct_unconstrained,
		un_16777216, sizeof(un_16777216), 1);

	/* Negative values keep the minimal 2's-complement form. */
	static const uint8_t un_m129[] = {0x02, 0xff, 0x7f};
	static const uint8_t un_m300[] = {0x02, 0xfe, 0xd4};
	check_case(__LINE__, "unconstrained", 0, -129, &ct_unconstrained,
		un_m129, sizeof(un_m129), 1);
	check_case(__LINE__, "unconstrained", 0, -300, &ct_unconstrained,
		un_m300, sizeof(un_m300), 1);

	/* Zero needs exactly one content octet (X.691 13.2.6 / 12.2.3). */
	static const uint8_t un_zero[] = {0x01, 0x00};
	check_case(__LINE__, "unconstrained", 0, 0, &ct_unconstrained,
		un_zero, sizeof(un_zero), 1);

	/* ---- Fully constrained (X.691 11.5) ---- */
	static const uint8_t c16_65000[] = {0xfd, 0xe8};
	static const uint8_t c17_65000[] = {0x40, 0xfd, 0xe8};
	check_case(__LINE__, "constrained 16-bit", 0, 65000, &ct_0_65535,
		c16_65000, sizeof(c16_65000), 1);
	check_case(__LINE__, "constrained 17-bit", 0, 65000, &ct_0_100000,
		c17_65000, sizeof(c17_65000), 1);

	/* ---- Semi-constrained: non-negative offset, no sign octet ---- */
	/* INTEGER (0..MAX), 65000 -> offset 65000 = 0xfde8. */
	static const uint8_t semi_65000[] = {0x02, 0xfd, 0xe8};
	check_case(__LINE__, "semi (0..MAX)", 1, 65000, &ct_semi_0,
		semi_65000, sizeof(semi_65000), 1);
	/* 2147483648 = 0x80000000 -> offset 0x80000000, no 0x00 prefix. */
	static const uint8_t semi_2g[] = {0x04, 0x80, 0x00, 0x00, 0x00};
	check_case(__LINE__, "semi (0..MAX)", 1, 2147483648, &ct_semi_0,
		semi_2g, sizeof(semi_2g), 1);
	/* INTEGER (8..MAX), 65000 -> offset 64992 = 0xfde0. */
	static const uint8_t semi8_65000[] = {0x02, 0xfd, 0xe0};
	check_case(__LINE__, "semi (8..MAX)", 0, 65000, &ct_semi_8,
		semi8_65000, sizeof(semi8_65000), 1);
	/* INTEGER (-8..MAX), 0 -> offset 8; 64992 -> offset 65000. */
	static const uint8_t semi_m8_0[] = {0x01, 0x08};
	static const uint8_t semi_m8_64992[] = {0x02, 0xfd, 0xe8};
	check_case(__LINE__, "semi (-8..MAX)", 0, 0, &ct_semi_m8,
		semi_m8_0, sizeof(semi_m8_0), 1);
	check_case(__LINE__, "semi (-8..MAX)", 0, 64992, &ct_semi_m8,
		semi_m8_64992, sizeof(semi_m8_64992), 1);

	return 0;
}
