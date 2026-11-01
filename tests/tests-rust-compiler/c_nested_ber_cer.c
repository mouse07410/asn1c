/* Verify C-generated DER/CER vectors used by the Rust nested-record tests. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "E.h"
#include "Empty.h"
#include "I.h"
#include "O.h"
#include "S.h"
#include "T.h"
#include "ber_decoder.h"
#include "cer_decoder.h"
#include "cer_encoder.h"
#include "der_encoder.h"

static int check_ber_decode(asn_TYPE_descriptor_t *, const uint8_t *, size_t);
static int check_cer_decode(asn_TYPE_descriptor_t *, const uint8_t *, size_t);

/*
 * Encode one C value under both rules and compare its bytes with fixed vectors.
 * Inputs: name identifies diagnostics; td/value select the generated C type;
 * der/cer and lengths contain the independent expected encodings.
 * Returns zero on success or one on mismatch. Errors: encoding failure fails.
 * Source: generated C BER/CER runtime. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: nested Rust codec reference vectors.
 * Example: check_encoding("S", &asn_DEF_S, &value, der, sizeof(der), cer, sizeof(cer)).
 */
static int
check_encoding(const char *name, asn_TYPE_descriptor_t *td, const void *value,
               const uint8_t *der, size_t der_size,
               const uint8_t *cer, size_t cer_size) {
    uint8_t buffer[64];
    asn_enc_rval_t encoded;
    if(!name || !td || !value || !der || !cer
       || der_size > sizeof(buffer) || cer_size > sizeof(buffer)) return 1;
    encoded = der_encode_to_buffer(td, value, buffer, sizeof(buffer));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != der_size
       || memcmp(buffer, der, der_size)
       || check_ber_decode(td, der, der_size)) return 1;
    encoded = cer_encode_to_buffer(NULL, td, value, buffer, sizeof(buffer));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != cer_size
       || memcmp(buffer, cer, cer_size)) return 1;
    return 0;
}

/*
 * Confirm C BER decoding accepts one complete DER vector.
 * Inputs: td identifies the type; bytes/size contain one complete DER TLV.
 * Returns zero for full consumption, one otherwise. Errors: malformed input fails.
 * Source: generated C BER decoder. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: nested Rust/C vectors.
 * Example: check_ber_decode(&asn_DEF_S, der, sizeof(der)).
 */
static int
check_ber_decode(asn_TYPE_descriptor_t *td, const uint8_t *bytes, size_t size) {
    void *decoded = NULL;
    if(!td || !bytes || !size) return 1;
    asn_dec_rval_t result = ber_decode(NULL, td, &decoded, bytes, size);
    int failed = result.code != RC_OK || result.consumed != size || !decoded;
    if(decoded) ASN_STRUCT_FREE(*td, decoded);
    return failed;
}

/*
 * Confirm that strict C CER decode accepts a complete canonical vector.
 * Inputs: td identifies the ASN.1 type; bytes/size contain one complete CER TLV.
 * Returns zero for full successful consumption, one otherwise. Errors: malformed
 * or noncanonical input fails. Source: skeleton CER decoder. Version/date:
 * 2026-11-01. Author: asn1c maintainers. History: nested record reference.
 * Example: check_cer_decode(&asn_DEF_E, cer, sizeof(cer)).
 */
static int
check_cer_decode(asn_TYPE_descriptor_t *td, const uint8_t *bytes, size_t size) {
    void *decoded = NULL;
    if(!td || !bytes || !size) return 1;
    asn_dec_rval_t result = cer_decode(NULL, td, &decoded, bytes, size);
    int failed = result.code != RC_OK || result.consumed != size || !decoded;
    if(decoded) ASN_STRUCT_FREE(*td, decoded);
    return failed;
}

/*
 * Compare nested C DER/CER OCTET STRING fragmentation against fixed framing.
 * Inputs: none. Returns zero for exact vectors, one for encoding mismatch.
 * Errors: encoder failures and byte mismatches return one. Source: X.690 CER.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: nested strings.
 * Example: a 1001-octet value is split into 1000 and one octets in CER.
 */
static int
check_nested_payload(void) {
    static const uint8_t der_prefix[] = {
        0x30, 0x82, 0x03, 0xfa, 0x80, 1, 0, 0x30, 0x82, 0x03, 0xf0,
        0x02, 1, 2, 0x04, 0x82, 0x03, 0xe9,
    };
    static const uint8_t der_suffix[] = {0x81, 1, 0xff};
    static const uint8_t cer_prefix[] = {
        0x30, 0x80, 0x80, 1, 0, 0x30, 0x80, 0x02, 1, 2,
        0x24, 0x80, 0x04, 0x82, 0x03, 0xe8,
    };
    static const uint8_t cer_suffix[] = {
        0x04, 1, 0x5a, 0, 0, 0, 0, 0x81, 1, 0xff, 0, 0,
    };
    uint8_t payload[1001];
    uint8_t expected[1100];
    uint8_t actual[1100];
    struct O__child child = {0};
    OCTET_STRING_t octets = {0};
    O_t value = {0};
    asn_enc_rval_t encoded;
    size_t offset = 0;
    if(sizeof(der_prefix) + sizeof(payload) + sizeof(der_suffix) > sizeof(expected)
       || sizeof(cer_prefix) + 1000 + sizeof(cer_suffix) > sizeof(expected)
       || sizeof(expected) > sizeof(actual)) return 1;
    memset(payload, 0x5a, sizeof(payload));
    child.x = 2;
    child.payload = &octets;
    octets.buf = payload;
    octets.size = sizeof(payload);
    value.before = 0;
    value.child = &child;
    value.after = 1;
    memcpy(expected + offset, der_prefix, sizeof(der_prefix));
    offset += sizeof(der_prefix);
    memcpy(expected + offset, payload, sizeof(payload));
    offset += sizeof(payload);
    memcpy(expected + offset, der_suffix, sizeof(der_suffix));
    offset += sizeof(der_suffix);
    encoded = der_encode_to_buffer(&asn_DEF_O, &value, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != offset
       || memcmp(actual, expected, offset)
       || check_ber_decode(&asn_DEF_O, expected, offset)) return 1;
    offset = 0;
    memcpy(expected + offset, cer_prefix, sizeof(cer_prefix));
    offset += sizeof(cer_prefix);
    memcpy(expected + offset, payload, 1000);
    offset += 1000;
    memcpy(expected + offset, cer_suffix, sizeof(cer_suffix));
    offset += sizeof(cer_suffix);
    encoded = cer_encode_to_buffer(NULL, &asn_DEF_O, &value, actual, sizeof(actual));
    return encoded.encoded < 0 || (size_t)encoded.encoded != offset
        || memcmp(actual, expected, offset)
        || check_cer_decode(&asn_DEF_O, expected, offset);
}

/*
 * Build four checked C values and compare all canonical child vectors.
 * Inputs: none. Returns zero when natural, IMPLICIT, EXPLICIT, and SET encodings
 * match the fixed test vectors. Errors: any mismatch returns one.
 * Source: X.690 tags plus generated C encoder/decoder. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: nested Rust codec differential vectors.
 * Example: the SET value is encoded in ascending context-tag order.
 */
int
main(void) {
    S_t natural = {0};
    I_t implicit = {0};
    E_t explicit_value = {0};
    Empty_t empty_child = {0};
    O_t optional_absent = {0};
    O_t optional_child = {0};
    struct O__child optional_child_value = {0};
    BOOLEAN_t optional_flag = 1;
    long optional_count = 3;
    T_t set = {0};
    static const uint8_t natural_der[] = {
        0x30, 0x0b, 0x02, 1, 1, 0x30, 3, 0x02, 1, 2, 0x01, 1, 0xff,
    };
    static const uint8_t natural_cer[] = {
        0x30, 0x80, 0x02, 1, 1, 0x30, 0x80, 0x02, 1, 2, 0, 0, 0x01, 1, 0xff, 0, 0,
    };
    static const uint8_t implicit_der[] = {
        0x30, 0x0b, 0x02, 1, 1, 0xa3, 3, 0x02, 1, 2, 0x01, 1, 0xff,
    };
    static const uint8_t implicit_cer[] = {
        0x30, 0x80, 0x02, 1, 1, 0xa3, 0x80, 0x02, 1, 2, 0, 0, 0x01, 1, 0xff, 0, 0,
    };
    static const uint8_t explicit_der[] = {
        0x30, 0x0d, 0x02, 1, 1, 0xa3, 5, 0x30, 3, 0x02, 1, 2, 0x01, 1, 0xff,
    };
    static const uint8_t explicit_cer[] = {
        0x30, 0x80, 0x02, 1, 1, 0xa3, 0x80, 0x30, 0x80, 0x02, 1, 2, 0, 0, 0, 0,
        0x01, 1, 0xff, 0, 0,
    };
    static const uint8_t empty_child_der[] = {0x30, 0x02, 0x30, 0x00};
    static const uint8_t empty_child_cer[] = {
        0x30, 0x80, 0x30, 0x80, 0, 0, 0, 0,
    };
    static const uint8_t set_der[] = {
        0x31, 0x0d, 0x80, 1, 1, 0x81, 1, 0xff, 0xa3, 5, 0x30, 3, 0x02, 1, 2,
    };
    static const uint8_t set_cer[] = {
        0x31, 0x80, 0x80, 1, 1, 0x81, 1, 0xff, 0xa3, 0x80, 0x30, 0x80,
        0x02, 1, 2, 0, 0, 0, 0, 0, 0,
    };
    static const uint8_t optional_absent_der[] = {
        0x30, 0x06, 0x80, 1, 0, 0x81, 1, 0xff,
    };
    static const uint8_t optional_absent_cer[] = {
        0x30, 0x80, 0x80, 1, 0, 0x81, 1, 0xff, 0, 0,
    };
    static const uint8_t optional_inner_der[] = {
        0x30, 0x0b, 0x80, 1, 0, 0x30, 3, 0x02, 1, 2, 0x81, 1, 0xff,
    };
    static const uint8_t optional_inner_cer[] = {
        0x30, 0x80, 0x80, 1, 0, 0x30, 0x80, 0x02, 1, 2, 0, 0,
        0x81, 1, 0xff, 0, 0,
    };
    static const uint8_t tagged_inner_der[] = {
        0x30, 0x13, 0x80, 1, 0, 0x30, 0x0b, 0x02, 1, 2, 0x82, 1, 0xff,
        0xa3, 3, 0x02, 1, 3, 0x81, 1, 0xff,
    };
    static const uint8_t tagged_inner_cer[] = {
        0x30, 0x80, 0x80, 1, 0, 0x30, 0x80, 0x02, 1, 2, 0x82, 1, 0xff,
        0xa3, 0x80, 0x02, 1, 3, 0, 0, 0, 0, 0x81, 1, 0xff, 0, 0,
    };

    natural.before = implicit.before = explicit_value.before = set.before = 1;
    optional_absent.before = 0;
    optional_absent.after = 1;
    optional_child.before = 0;
    optional_child.after = 1;
    optional_child_value.x = 2;
    optional_child_value.flag = &optional_flag;
    optional_child_value.count = &optional_count;
    optional_child.child = &optional_child_value;
    natural.child.x = implicit.child.x = explicit_value.child.x = set.child.x = 2;
    natural.after = implicit.after = explicit_value.after = set.after = 1;
    ASN_SET_MKPRESENT(set._presence_map, T_PR_before);
    ASN_SET_MKPRESENT(set._presence_map, T_PR_child);
    ASN_SET_MKPRESENT(set._presence_map, T_PR_after);

    if(check_encoding("S", &asn_DEF_S, &natural,
                      natural_der, sizeof(natural_der),
                      natural_cer, sizeof(natural_cer))
       || check_encoding("I", &asn_DEF_I, &implicit,
                         implicit_der, sizeof(implicit_der),
                         implicit_cer, sizeof(implicit_cer))
       || check_encoding("E", &asn_DEF_E, &explicit_value,
                         explicit_der, sizeof(explicit_der),
                         explicit_cer, sizeof(explicit_cer))
       || check_encoding("Empty", &asn_DEF_Empty, &empty_child,
                         empty_child_der, sizeof(empty_child_der),
                         empty_child_cer, sizeof(empty_child_cer))
       || check_encoding("T", &asn_DEF_T, &set,
                         set_der, sizeof(set_der), set_cer, sizeof(set_cer))
       || check_encoding("O absent", &asn_DEF_O, &optional_absent,
                         optional_absent_der, sizeof(optional_absent_der),
                         optional_absent_cer, sizeof(optional_absent_cer))
       || check_encoding("O tagged child", &asn_DEF_O, &optional_child,
                         tagged_inner_der, sizeof(tagged_inner_der),
                         tagged_inner_cer, sizeof(tagged_inner_cer))) return 1;
    optional_child_value.flag = NULL;
    optional_child_value.count = NULL;
    if(check_encoding("O optional leaves", &asn_DEF_O, &optional_child,
                      optional_inner_der, sizeof(optional_inner_der),
                      optional_inner_cer, sizeof(optional_inner_cer))) return 1;
    if(check_cer_decode(&asn_DEF_S, natural_cer, sizeof(natural_cer))
       || check_cer_decode(&asn_DEF_I, implicit_cer, sizeof(implicit_cer))
       || check_cer_decode(&asn_DEF_E, explicit_cer, sizeof(explicit_cer))
       || check_cer_decode(&asn_DEF_Empty, empty_child_cer, sizeof(empty_child_cer))
       || check_cer_decode(&asn_DEF_T, set_cer, sizeof(set_cer))
       || check_cer_decode(&asn_DEF_O, optional_absent_cer, sizeof(optional_absent_cer))
       || check_cer_decode(&asn_DEF_O, optional_inner_cer, sizeof(optional_inner_cer))
       || check_cer_decode(&asn_DEF_O, tagged_inner_cer, sizeof(tagged_inner_cer))) return 1;
    if(check_nested_payload()) return 1;
    return 0;
}
