/* Compare basic C XER output with the generated Rust record vectors.
 * Source: issue #594. Version/date: 2026-10-31; asn1c maintainers.
 * History: initial XER parity slice. Example: run the Rust compiler harness.
 */
#include <S.h>
#include <Q.h>
#include <Empty.h>
#include <xer_encoder.h>
#include <string.h>
#include <stdio.h>

/* Bounded callback output, including its used length. */
struct output {
    char bytes[512]; /* Encoded byte storage state variable. */
    size_t used; /* Number of encoded bytes state variable. */
};

/* Append bytes to the bounded buffer. Inputs: data, size, and opaque buffer.
 * Returns zero or -1 on overflow; no exceptions. Source: parity harness.
 * Version/date: 2026-10-31; asn1c maintainers. History: initial callback.
 * Example: xer_encode(&asn_DEF_S, &value, XER_F_BASIC, collect, &out).
 */
static int
collect(const void *data, size_t size, void *key) {
    struct output *out = key;
    if(size > sizeof(out->bytes) - out->used) return -1;
    memcpy(out->bytes + out->used, data, size);
    out->used += size;
    return 0;
}

/* Check complete output. Inputs: descriptor, value and expected text.
 * Returns zero on match, -1 otherwise; callback errors propagate. Source:
 * parity harness. Version/date: 2026-10-31; asn1c maintainers. History:
 * initial check. Example: compare(&asn_DEF_S, &value, "<S>...</S>\n").
 */
static int
compare(const asn_TYPE_descriptor_t *td, const void *value, const char *expected) {
    struct output out = {{0}, 0};
    asn_enc_rval_t result = xer_encode(td, value, XER_F_BASIC, collect, &out);
    if(result.encoded < 0 || out.used != strlen(expected)
       || memcmp(out.bytes, expected, out.used)) {
        fprintf(stderr, "C XER mismatch: %.*s\n", (int)out.used, out.bytes);
        return -1;
    }
    return 0;
}

/* Exercise C defaults and explicit REAL against Rust's fixed test vectors.
 * Inputs: none. Returns zero on success, one on mismatch; no exceptions.
 * Source: issue #594. Version/date: 2026-10-31; asn1c maintainers.
 * History: initial C/Rust parity. Example: execute c-xer-record.
 */
int
main(void) {
    S_t set = {0};
    Q_t sequence = {0};
    Empty_t empty = {0};
    BOOLEAN_t false_value = 0;
    long count = 3;
    double ratio = 1.25;
    IA5String_t text = {0};
    text.buf = (uint8_t *)"a&<b";
    text.size = 4;
    if(compare(&asn_DEF_Empty, &empty, "<Empty></Empty>\n")) return 1;
    set.text = &text;
    sequence.text = &text;
#ifdef XER_AUTOMATIC
    if(compare(&asn_DEF_S, &set, "<S>\n    <flag><true/></flag>\n    <count>2</count>\n"
               "    <text>a&amp;&lt;b</text>\n    <ratio>0.5</ratio>\n</S>\n")
#else
    if(compare(&asn_DEF_S, &set, "<S>\n    <flag><true/></flag>\n    <count>2</count>\n"
               "    <ratio>0.5</ratio>\n    <text>a&amp;&lt;b</text>\n</S>\n")
#endif
       || compare(&asn_DEF_Q, &sequence, "<Q>\n    <flag><true/></flag>\n    <count>2</count>\n"
                  "    <text>a&amp;&lt;b</text>\n    <ratio>0.5</ratio>\n</Q>\n")) return 1;
    set.flag = &false_value;
    set.count = &count;
    set.text = NULL;
    set.ratio = &ratio;
    if(compare(&asn_DEF_S, &set, "<S>\n    <flag><false/></flag>\n    <count>3</count>\n"
               "    <ratio>1.25</ratio>\n</S>\n")) return 1;
    return 0;
}
