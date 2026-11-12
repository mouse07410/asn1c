/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <UTCTime.h>

/*
 * Generate a sample UTCTime accepted by the selected validation policy.
 * Source: asn1c runtime; version/date: 2026-11-12; author: asn1c maintainers.
 * Inputs: td describes the type; sptr owns the output; constraints is unused;
 * max_length bounds creation. Returns ARFILL_OK, FAILED, or SKIPPED; no exceptions.
 * History: issue #596 excludes zone-less legacy samples in strict mode.
 * Example: call through asn_DEF_UTCTime.op->random_fill.
 */
asn_random_fill_result_t
UTCTime_random_fill(const asn_TYPE_descriptor_t *td, void **sptr,
                    const asn_encoding_constraints_t *constraints,
                    size_t max_length) {
    asn_random_fill_result_t result_ok = {ARFILL_OK, 1};
    asn_random_fill_result_t result_failed = {ARFILL_FAILED, 0};
    asn_random_fill_result_t result_skipped = {ARFILL_SKIPPED, 0};
    static const char *values[] = {
        /* Strict samples always include the mandatory UTCTime time zone. */
#ifdef ASN_ENABLE_TOLERANT_UTCTIME
        "700101000000", "821106210623",
#endif
        "700101000000-0000", "700101000000+0000",
        "700101000000Z", "691106210827-0500",
        "821106210629Z",
    };
    size_t rnd = asn_random_between(0, sizeof(values)/sizeof(values[0])-1);

    (void)constraints;

    if(!sptr) return result_failed;
  
    if(max_length < sizeof("yymmddhhmmss") && !*sptr) {
        return result_skipped;
    }

    if(*sptr) {
        if(OCTET_STRING_fromBuf(*sptr, values[rnd], -1) != 0) {
            return result_failed;
        }
    } else {
        *sptr = OCTET_STRING_new_fromBuf(td, values[rnd], -1); 
        if (!*sptr) return result_failed;
    }

    return result_ok;
}
