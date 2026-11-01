/* C/Rust vectors for two same-module named record children. */
/* Source: generated C descriptors and the approved BER/DER/CER design vectors. */
/* Version/date: 2026-11-01. Responsible party: asn1c maintainers. */
#include <A.h>
#include <B.h>
#include <C.h>
#include <EmptyPair.h>
#include <I.h>
#include <O.h>
#include <OwnedPair.h>
#include <P.h>
#include <Q.h>
#include <T.h>
#include <U.h>
#include <X.h>
#include <asn_application.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define WIRE_MAX 64

/*
 * Purpose: decode exact DER/CER inputs and compare their C semantic values.
 * Inputs: descriptor and TLVs identify one generated type/vector pair.
 * Returns zero on both successful exact-prefix decodes and semantic equality.
 * Errors: invalid arguments or codec/comparison failure return one.
 * Source: generated C descriptors. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: named record pair vectors.
 * Example: decode P's definite and canonical indefinite encodings.
 */
static int
decode_pair(asn_TYPE_descriptor_t *descriptor,
            const uint8_t *der, size_t der_size,
            const uint8_t *cer, size_t cer_size,
            void **from_der, void **from_cer) {
    asn_dec_rval_t result;
    if(!descriptor || !descriptor->op || !descriptor->op->compare_struct
       || !der || !cer || !from_der || !from_cer) return 1;
    result = asn_decode(NULL, ATS_BER, descriptor, from_der, der, der_size);
    if(result.code != RC_OK || result.consumed != der_size || !*from_der) {
        fprintf(stderr, "%s DER BER decode failed: status=%d consumed=%zu/%zu\n",
                descriptor->name, result.code, result.consumed, der_size);
        return 1;
    }
    result = asn_decode(NULL, ATS_BER, descriptor, from_cer, cer, cer_size);
    if(result.code != RC_OK || result.consumed != cer_size || !*from_cer) {
        fprintf(stderr, "%s CER BER decode failed: status=%d consumed=%zu/%zu\n",
                descriptor->name, result.code, result.consumed, cer_size);
        return 1;
    }
    if(descriptor->op->compare_struct(descriptor, *from_der, *from_cer)) {
        fprintf(stderr, "%s DER/CER semantic comparison failed\n", descriptor->name);
        return 1;
    }
    return 0;
}

/*
 * Purpose: encode one decoded semantic value and compare its DER/CER bytes.
 * Inputs: descriptor/value identify the record; TLVs and sizes are expected.
 * Returns zero on exact matching bytes. Errors: codec or byte mismatch returns one.
 * Source: generated C encoder. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: named record pair vectors.
 * Example: re-encode a P value decoded from its DER vector.
 */
static int
check_encoded_bytes(asn_TYPE_descriptor_t *descriptor, const void *value,
                    const uint8_t *der, size_t der_size,
                    const uint8_t *cer, size_t cer_size) {
    uint8_t actual[WIRE_MAX];
    asn_enc_rval_t encoded;
    if(!descriptor || !descriptor->op || !value || !der || !cer || der_size > sizeof(actual)
       || cer_size > sizeof(actual)) return 1;
    encoded = asn_encode_to_buffer(NULL, ATS_DER, descriptor, value,
                                   actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != der_size
       || memcmp(actual, der, der_size)) return 1;
    encoded = asn_encode_to_buffer(NULL, ATS_CER, descriptor, value,
                                   actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != cer_size
       || memcmp(actual, cer, cer_size)) return 1;
    return 0;
}

/*
 * Purpose: require canonical CER input to decode and DER input to fail CER.
 * Inputs: descriptor and DER/CER TLVs identify a vector pair.
 * Returns zero when strict CER accepts canonical bytes and rejects DER.
 * Errors: unexpected status, prefix, or allocation returns one.
 * Source: generated strict CER decoder. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: strict pair validation.
 * Example: reject the definite DER form of P as CER.
 */
static int
check_strict_cer(asn_TYPE_descriptor_t *descriptor,
                 const uint8_t *der, size_t der_size,
                 const uint8_t *cer, size_t cer_size) {
    void *decoded = NULL;
    asn_dec_rval_t result;
    int failed;
    if(!descriptor || !descriptor->op || !descriptor->op->free_struct || !der || !cer) return 1;
    result = asn_decode(NULL, ATS_CER, descriptor, &decoded, cer, cer_size);
    failed = result.code != RC_OK || result.consumed != cer_size || !decoded;
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    decoded = NULL;
    result = asn_decode(NULL, ATS_CER, descriptor, &decoded, der, der_size);
    failed |= result.code == RC_OK && result.consumed == der_size;
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    return failed;
}

/*
 * Purpose: verify strict CER decoding stops before a permitted suffix.
 * Inputs: descriptor and canonical CER TLV identify one generated record.
 * Returns zero when one extra octet remains outside the decoded prefix.
 * Errors: oversized input or a status/consumption mismatch returns one.
 * Source: generated prefix decoder. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: pair prefix behavior.
 * Example: append 0x5a after the canonical P value.
 */
static int
check_cer_suffix(asn_TYPE_descriptor_t *descriptor,
                 const uint8_t *cer, size_t cer_size) {
    uint8_t suffixed[WIRE_MAX];
    void *decoded = NULL;
    asn_dec_rval_t result;
    if(!descriptor || !descriptor->op || !descriptor->op->free_struct || !cer
       || cer_size >= sizeof(suffixed)) return 1;
    memcpy(suffixed, cer, cer_size);
    suffixed[cer_size] = 0x5a;
    result = asn_decode(NULL, ATS_CER, descriptor, &decoded, suffixed, cer_size + 1);
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    return result.code != RC_OK || result.consumed != cer_size;
}

/*
 * Purpose: run all exact-byte, semantic, strict-CER, and prefix checks.
 * Inputs: descriptor and DER/CER TLVs identify a differential vector.
 * Returns zero when every check passes. Errors: failures return one and free objects.
 * Source: generated C descriptors and X.690. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: named record pair vectors.
 * Example: compare the optional-present P record.
 */
static int
check_vector(asn_TYPE_descriptor_t *descriptor,
             const uint8_t *der, size_t der_size,
             const uint8_t *cer, size_t cer_size) {
    void *from_der = NULL;
    void *from_cer = NULL;
    int failed = 0;
    const char *phase = "argument validation";
    if(!descriptor || !descriptor->op || !descriptor->op->free_struct
       || !der || !cer || der_size > WIRE_MAX || cer_size >= WIRE_MAX) return 1;
    phase = "BER decode/value comparison";
    failed = decode_pair(descriptor, der, der_size, cer, cer_size, &from_der, &from_cer);
    if(!failed) {
        phase = "DER/CER encoding";
        failed = check_encoded_bytes(descriptor, from_der, der, der_size, cer, cer_size);
    }
    if(from_der) descriptor->op->free_struct(descriptor, from_der, ASFM_FREE_EVERYTHING);
    if(from_cer) descriptor->op->free_struct(descriptor, from_cer, ASFM_FREE_EVERYTHING);
    if(!failed) {
        phase = "strict CER canonicality";
        failed = check_strict_cer(descriptor, der, der_size, cer, cer_size);
    }
    if(!failed) {
        phase = "CER suffix consumption";
        failed = check_cer_suffix(descriptor, cer, cer_size);
    }
    if(failed) fprintf(stderr, "named pair %s failed during %s\n", descriptor->name, phase);
    return failed;
}

/*
 * Purpose: require malformed framing or duplicate/unknown child tags to fail.
 * Inputs: descriptor selects the schema; wire and size contain one BER TLV.
 * Returns zero on rejection. Errors: unexpected acceptance returns one.
 * Source: X.690 malformed-wrapper rules. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: pair malformed tests.
 * Example: reject a duplicate BOOLEAN inside the second SET child.
 */
static int
check_rejected(asn_TYPE_descriptor_t *descriptor,
               const uint8_t *wire, size_t size) {
    void *decoded = NULL;
    asn_dec_rval_t result;
    int failed;
    if(!descriptor || !descriptor->op || !descriptor->op->free_struct || !wire) return 1;
    result = asn_decode(NULL, ATS_BER, descriptor, &decoded, wire, size);
    failed = result.code == RC_OK && result.consumed == size;
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    if(failed) fprintf(stderr, "malformed pair input accepted by %s\n", descriptor->name);
    return failed;
}

/*
 * Purpose: check a canonical value against a BER-accepted noncanonical form.
 * Inputs: canonical and wire are canonical and equivalent noncanonical TLVs.
 * Returns zero when BER accepts the value and strict CER rejects its wire form.
 * Errors: status, value, or canonicality mismatch returns one.
 * Source: generated descriptors and X.690. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: SET order and padding aliases.
 * Example: reverse SET members or set an ignored BIT STRING padding bit.
 */
static int
check_noncanonical(asn_TYPE_descriptor_t *descriptor,
                const uint8_t *canonical, size_t canonical_size,
                const uint8_t *wire, size_t size) {
    void *expected = NULL;
    void *decoded = NULL;
    void *strict = NULL;
    asn_dec_rval_t expected_result;
    asn_dec_rval_t ber;
    asn_dec_rval_t cer;
    int failed;
    if(!descriptor || !descriptor->op || !descriptor->op->free_struct
       || !descriptor->op->compare_struct || !canonical || !wire) return 1;
    expected_result = asn_decode(NULL, ATS_BER, descriptor, &expected,
                                 canonical, canonical_size);
    ber = asn_decode(NULL, ATS_BER, descriptor, &decoded, wire, size);
    cer = asn_decode(NULL, ATS_CER, descriptor, &strict, wire, size);
    failed = expected_result.code != RC_OK || expected_result.consumed != canonical_size
        || !expected || ber.code != RC_OK
        || ber.consumed != size || !decoded
        || descriptor->op->compare_struct(descriptor, expected, decoded)
        || (cer.code == RC_OK && cer.consumed == size);
    if(expected) descriptor->op->free_struct(descriptor, expected, ASFM_FREE_EVERYTHING);
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    if(strict) descriptor->op->free_struct(descriptor, strict, ASFM_FREE_EVERYTHING);
    if(failed) fprintf(stderr, "noncanonical named pair check failed for %s\n", descriptor->name);
    return failed;
}

/*
 * Purpose: compare sequence, optional, SET, and same-target tag vectors.
 * Inputs: none. Returns zero after all C byte/value and malformed checks pass.
 * Errors: any mismatch returns one. Source: approved live C vector set.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: two same-module named record gate. Example: compare P and T.
 */
int
main(void) {
    static const uint8_t p_der[] = {
        0x30, 0x0a, 0x30, 0x03, 0x02, 0x01, 0x02, 0x31, 0x03, 0x01, 0x01, 0xff,
    };
    static const uint8_t p_cer[] = {
        0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x31, 0x80, 0x01, 0x01, 0xff, 0, 0,
        0, 0,
    };
    static const uint8_t p_absent_der[] = {0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02};
    static const uint8_t p_absent_cer[] = {
        0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0, 0,
    };
    static const uint8_t o_empty_der[] = {0x30, 0x00};
    static const uint8_t o_empty_cer[] = {0x30, 0x80, 0, 0};
    static const uint8_t o_a_der[] = {0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02};
    static const uint8_t o_a_cer[] = {0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0, 0};
    static const uint8_t o_b_der[] = {0x30, 0x05, 0x31, 0x03, 0x01, 0x01, 0xff};
    static const uint8_t o_b_cer[] = {
        0x30, 0x80, 0x31, 0x80, 0x01, 0x01, 0xff, 0, 0, 0, 0,
    };
    static const uint8_t empty_absent_der[] = {0x30, 0x02, 0x30, 0x00};
    static const uint8_t empty_absent_cer[] = {0x30, 0x80, 0x30, 0x80, 0, 0, 0, 0};
    static const uint8_t empty_present_der[] = {
        0x30, 0x07, 0x30, 0x00, 0x31, 0x03, 0x01, 0x01, 0xff,
    };
    static const uint8_t empty_present_cer[] = {
        0x30, 0x80, 0x30, 0x80, 0, 0, 0x31, 0x80, 0x01, 0x01, 0xff, 0, 0, 0, 0,
    };
    static const uint8_t t_der[] = {
        0x31, 0x0a, 0x30, 0x03, 0x02, 0x01, 0x02, 0x31, 0x03, 0x01, 0x01, 0xff,
    };
    static const uint8_t t_cer[] = {
        0x31, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x31, 0x80, 0x01, 0x01, 0xff, 0, 0,
        0, 0,
    };
    static const uint8_t q_der[] = {
        0x30, 0x0d, 0x30, 0x03, 0x02, 0x01, 0x02, 0x31, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff,
    };
    static const uint8_t q_cer[] = {
        0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01,
        0xff, 0, 0, 0, 0,
    };
    static const uint8_t q_absent_der[] = {0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02};
    static const uint8_t q_absent_cer[] = {
        0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0, 0,
    };
    static const uint8_t q_enabled_der[] = {
        0x30, 0x10, 0x30, 0x03, 0x02, 0x01, 0x02, 0x31, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff,
        0x01, 0x01, 0xff,
    };
    static const uint8_t q_enabled_cer[] = {
        0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01,
        0xff, 0, 0, 0x01, 0x01, 0xff, 0, 0,
    };
    static const uint8_t u_der[] = {
        0x31, 0x0d, 0x30, 0x03, 0x02, 0x01, 0x02, 0x31, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff,
    };
    static const uint8_t u_cer[] = {
        0x31, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01,
        0xff, 0, 0, 0, 0,
    };
    static const uint8_t x_der[] = {
        0x30, 0x0e, 0xa2, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02, 0xa3, 0x05, 0x30, 0x03, 0x02, 0x01,
        0x03,
    };
    static const uint8_t x_cer[] = {
        0x30, 0x80, 0xa2, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0, 0, 0xa3, 0x80, 0x30, 0x80,
        0x02, 0x01, 0x03, 0, 0, 0, 0, 0, 0,
    };
    static const uint8_t i_der[] = {
        0x30, 0x0a, 0xa2, 0x03, 0x02, 0x01, 0x02, 0xa3, 0x03, 0x02, 0x01, 0x03,
    };
    static const uint8_t i_cer[] = {
        0x30, 0x80, 0xa2, 0x80, 0x02, 0x01, 0x02, 0, 0, 0xa3, 0x80, 0x02, 0x01, 0x03, 0, 0, 0, 0,
    };
    static const uint8_t reversed_t[] = {
        0x31, 0x80, 0x31, 0x03, 0x01, 0x01, 0xff, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0, 0,
    };
    static const uint8_t reversed_q_child[] = {
        0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x31, 0x80, 0x81, 0x01, 0xff, 0x80, 0x01,
        0x02, 0, 0, 0, 0,
    };
    static const uint8_t reversed_u_parent[] = {
        0x31, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0x30, 0x80, 0x02, 0x01,
        0x02, 0, 0, 0, 0,
    };
    static const uint8_t duplicate_b[] = {
        0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x31, 0x80, 0x01, 0x01, 0xff, 0x01, 0x01,
        0, 0, 0, 0,
    };
    static const uint8_t unknown_b[] = {
        0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x31, 0x80, 0x02, 0x01, 0, 0, 0, 0, 0,
    };
    static const uint8_t wrong_explicit[] = {
        0x30, 0x0e, 0xa2, 0x05, 0x31, 0x03, 0x01, 0x01, 0xff, 0xa3, 0x05, 0x30, 0x03, 0x02, 0x01,
        0x03,
    };
    static const uint8_t extra_eoc[] = {
        0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x31, 0x80, 0x01, 0x01, 0xff,
        0, 0, 0, 0, 0, 0,
    };
    static const uint8_t owned_der[] = {
        0x30, 0x0c, 0x30, 0x04, 0x04, 0x02, 0xaa, 0xbb,
        0x31, 0x04, 0x03, 0x02, 0x05, 0xa0,
    };
    static const uint8_t owned_cer[] = {
        0x30, 0x80, 0x30, 0x80, 0x04, 0x02, 0xaa, 0xbb, 0, 0,
        0x31, 0x80, 0x03, 0x02, 0x05, 0xa0, 0, 0, 0, 0,
    };
    static const uint8_t owned_padding_alias[] = {
        0x30, 0x80, 0x30, 0x80, 0x04, 0x02, 0xaa, 0xbb, 0, 0,
        0x31, 0x80, 0x03, 0x02, 0x05, 0xa1, 0, 0, 0, 0,
    };
    int failed = 0;

    failed |= check_vector(&asn_DEF_P, p_der, sizeof(p_der), p_cer, sizeof(p_cer));
    failed |= check_vector(&asn_DEF_P, p_absent_der, sizeof(p_absent_der),
                           p_absent_cer, sizeof(p_absent_cer));
    failed |= check_vector(&asn_DEF_O, o_empty_der, sizeof(o_empty_der),
                           o_empty_cer, sizeof(o_empty_cer));
    failed |= check_vector(&asn_DEF_O, o_a_der, sizeof(o_a_der), o_a_cer, sizeof(o_a_cer));
    failed |= check_vector(&asn_DEF_O, o_b_der, sizeof(o_b_der), o_b_cer, sizeof(o_b_cer));
    failed |= check_vector(&asn_DEF_EmptyPair, empty_absent_der, sizeof(empty_absent_der),
                           empty_absent_cer, sizeof(empty_absent_cer));
    failed |= check_vector(&asn_DEF_EmptyPair, empty_present_der, sizeof(empty_present_der),
                           empty_present_cer, sizeof(empty_present_cer));
    failed |= check_vector(&asn_DEF_O, p_der, sizeof(p_der), p_cer, sizeof(p_cer));
    failed |= check_vector(&asn_DEF_T, t_der, sizeof(t_der), t_cer, sizeof(t_cer));
    failed |= check_vector(&asn_DEF_Q, q_der, sizeof(q_der), q_cer, sizeof(q_cer));
    failed |= check_vector(&asn_DEF_Q, q_absent_der, sizeof(q_absent_der),
                           q_absent_cer, sizeof(q_absent_cer));
    failed |= check_vector(&asn_DEF_Q, q_enabled_der, sizeof(q_enabled_der),
                           q_enabled_cer, sizeof(q_enabled_cer));
    failed |= check_vector(&asn_DEF_U, u_der, sizeof(u_der), u_cer, sizeof(u_cer));
    failed |= check_vector(&asn_DEF_X, x_der, sizeof(x_der), x_cer, sizeof(x_cer));
    failed |= check_vector(&asn_DEF_I, i_der, sizeof(i_der), i_cer, sizeof(i_cer));
    failed |= check_vector(&asn_DEF_OwnedPair, owned_der, sizeof(owned_der),
                           owned_cer, sizeof(owned_cer));
    failed |= check_noncanonical(&asn_DEF_OwnedPair, owned_cer, sizeof(owned_cer),
                              owned_padding_alias, sizeof(owned_padding_alias));
    failed |= check_noncanonical(&asn_DEF_T, t_cer, sizeof(t_cer), reversed_t, sizeof(reversed_t));
    failed |= check_noncanonical(&asn_DEF_Q, q_cer, sizeof(q_cer),
                              reversed_q_child, sizeof(reversed_q_child));
    failed |= check_noncanonical(&asn_DEF_U, u_cer, sizeof(u_cer),
                              reversed_u_parent, sizeof(reversed_u_parent));
    failed |= check_rejected(&asn_DEF_P, duplicate_b, sizeof(duplicate_b));
    failed |= check_rejected(&asn_DEF_P, unknown_b, sizeof(unknown_b));
    failed |= check_rejected(&asn_DEF_X, wrong_explicit, sizeof(wrong_explicit));
    failed |= check_rejected(&asn_DEF_P, extra_eoc, sizeof(extra_eoc));
    return failed;
}
