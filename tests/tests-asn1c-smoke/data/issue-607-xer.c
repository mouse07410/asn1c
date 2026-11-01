/*
 * Purpose: cover GitHub issue #594 with generated XER fixture 607.
 * Original source: generated C descriptors from issue-607-xer.asn1.
 * Version/date: 1.0, 2026-10-31.
 * Inputs: no command-line parameters; links the generated asn1c codec archive.
 * Returns/errors: zero on exact XER matches; failures return nonzero.
 * Responsible party: asn1c maintainers. History: generated XER regression.
 * Example: run once with native C storage and once with -fwide-types.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <asn_application.h>
#include <jer_encoder.h>
#include <xer_encoder.h>
#include <SetDefaults.h>
#include <SequenceDefault.h>

/*
 * Purpose: hold bytes produced by the XER callback.
 * Original source: the public ASN.1 callback interface; GitHub issue #594.
 * Version/date: 1.0, 2026-10-31.
 * Inputs: callback state is supplied to append_xer_bytes.
 * Returns/errors: owns a NUL-terminated allocation or remains empty.
 * Responsible party: asn1c maintainers. History: added for GitHub issue #594.
 * Example: { buffer = NULL, length = 0, capacity = 0 } is an empty result.
 */
struct xer_output {
    char *buffer;       /* Allocated XER byte buffer. */
    size_t length;      /* Number of output bytes, excluding the NUL terminator. */
    size_t capacity;    /* Allocated buffer size, including room for the NUL. */
};

/*
 * Purpose: append one encoder callback chunk to the bounded result buffer.
 * Original source: asn_app_consume_bytes_f callback contract.
 * Version/date: 1.0, 2026-10-31.
 * Inputs: bytes/size select the chunk; key points to struct xer_output.
 * Returns: zero after appending; nonzero for invalid input or allocation error.
 * Errors: overflow, invalid state, or realloc failure leaves old storage valid.
 * Responsible party: asn1c maintainers. History: added for GitHub issue #594.
 * Example: xer_encode(..., append_xer_bytes, &output).
 */
static int
append_xer_bytes(const void *bytes, size_t size, void *key) {
    struct xer_output *output = key;
    size_t needed;

    if(!output || (size && !bytes)
    || (output->buffer && output->length >= output->capacity)
    || size > (size_t)-1 - output->length - 1) return -1;
    needed = output->length + size + 1;
    if(needed > output->capacity) {
        size_t next = output->capacity ? output->capacity : 128;
        char *resized;
        while(next < needed) {
            if(next > (size_t)-1 / 2) {
                next = needed;
                break;
            }
            next *= 2;
        }
        resized = realloc(output->buffer, next);
        if(!resized) return -1;
        output->buffer = resized;
        output->capacity = next;
    }
    if(size) memcpy(output->buffer + output->length, bytes, size);
    output->length += size;
    output->buffer[output->length] = '\0';
    return 0;
}

/*
 * Purpose: compare one generated type's output with the expected XER string.
 * Original source: GitHub issue #594's XER regression requirements.
 * Version/date: 1.0, 2026-10-31.
 * Inputs: td/value identify the value; flags select XER mode; expected is exact.
 * Returns: zero for a successful exact match; nonzero for encode/match errors.
 * Errors: encoder failures and allocation failures are reported to stderr.
 * Responsible party: asn1c maintainers. History: added for GitHub issue #594.
 * Example: check_xer(&asn_DEF_SetDefaults, &value, XER_F_BASIC, expected).
 */
static int
check_xer(asn_TYPE_descriptor_t *td, const void *value,
          enum xer_encoder_flags_e flags, const char *expected) {
    struct xer_output output = {0, 0, 0};
    asn_enc_rval_t encoded;
    int failed = 0;

    encoded = xer_encode(td, value, flags, append_xer_bytes, &output);
    if(encoded.encoded < 0 || !output.buffer
    || strcmp(output.buffer, expected) != 0) {
        fprintf(stderr, "GitHub issue #594 (fixture 607): XER mismatch for %s (%s mode)\n",
                td->name, (flags & XER_F_CANONICAL) ? "canonical" : "basic");
        fprintf(stderr, "expected: %s\nactual:   %s\n", expected,
                output.buffer ? output.buffer : "<no output>");
        failed = 1;
    }
    free(output.buffer);
    return failed;
}

/*
 * Purpose: verify one generated JER DEFAULT with exact minified JSON output.
 * Original source: GitHub issue #594 and the generated REAL DEFAULT callback.
 * Version/date: 1.0, 2026-10-31.
 * Inputs: td/value identify the generated record; expected is exact JSON.
 * Returns: zero for a successful exact match; nonzero for encode/match errors.
 * Errors: encoder failures and allocation failures are reported to stderr.
 * Responsible party: asn1c maintainers. History: shared REAL DEFAULT coverage.
 * Example: the absent REAL DEFAULT encodes as {"ratio":5.0E-1} in minified JER.
 */
static int
check_jer(asn_TYPE_descriptor_t *td, const void *value, const char *expected) {
    struct xer_output output = {0, 0, 0};
    asn_enc_rval_t encoded;
    int failed = 0;

    encoded = jer_encode(td, value, JER_F_MINIFIED, append_xer_bytes, &output);
    if(encoded.encoded < 0 || !output.buffer
    || strcmp(output.buffer, expected) != 0) {
        fprintf(stderr, "GitHub issue #594 (fixture 607): JER mismatch for %s\n",
                td->name);
        fprintf(stderr, "expected: %s\nactual:   %s\n", expected,
                output.buffer ? output.buffer : "<no output>");
        failed = 1;
    }
    free(output.buffer);
    return failed;
}

/*
 * Purpose: verify absent DEFAULT materialization in both XER modes.
 * Original source: generated SET/SEQUENCE descriptors and GitHub issue #594.
 * Version/date: 1.0, 2026-10-31.
 * Inputs: none; generated values are zero-initialized in this function.
 * Returns: zero when SET spacing and SET/SEQUENCE defaults match exactly.
 * Errors: failed exact comparisons return nonzero.
 * Responsible party: asn1c maintainers. History: generated fixture 607.
 * Example: the empty SetDefaults value encodes its INTEGER and BOOLEAN defaults.
 */
int
main(void) {
    const char *set_basic =
        "<SetDefaults>\n"
        "    <enabled><true/></enabled>\n"
        "    <number>7</number>\n"
        "</SetDefaults>\n";
    const char *set_canonical =
        "<SetDefaults><enabled><true/></enabled><number>7</number></SetDefaults>";
    const char *sequence_basic =
        "<SequenceDefault>\n"
        "    <ratio>0.5</ratio>\n"
        "</SequenceDefault>\n";
    const char *sequence_canonical =
        "<SequenceDefault><ratio>5.0E-1</ratio></SequenceDefault>";
    const char *sequence_jer = "{\"ratio\":5.0E-1}";
    SetDefaults_t set_value = {0};
    SequenceDefault_t sequence_value = {0};
    int failed = 0;

    failed |= check_xer(&asn_DEF_SetDefaults, &set_value, XER_F_BASIC,
                        set_basic);
    failed |= check_xer(&asn_DEF_SetDefaults, &set_value, XER_F_CANONICAL,
                        set_canonical);
    failed |= check_xer(&asn_DEF_SequenceDefault, &sequence_value, XER_F_BASIC,
                        sequence_basic);
    failed |= check_xer(&asn_DEF_SequenceDefault, &sequence_value,
                        XER_F_CANONICAL, sequence_canonical);
    failed |= check_jer(&asn_DEF_SequenceDefault, &sequence_value,
                        sequence_jer);
    if(set_value.number || set_value.enabled || sequence_value.ratio) {
        fprintf(stderr, "GitHub issue #594 (fixture 607): encoding changed a DEFAULT field\n");
        failed = 1;
    }
    return failed;
}
