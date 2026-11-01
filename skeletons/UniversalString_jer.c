/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <UniversalString.h>
#include <UTF8String.h>
#include <jer_string.h>

/*
 * Decode a UTF-8 JER string and convert its contents to UCS-4.
 * Original source: asn1c UniversalString JER runtime skeleton.
 * Version/date: 1.0, 2017-06-16.
 * Inputs: codec context, descriptor, constraints, destination, and input chunk.
 * Returns: Decoder status and consumed input count.
 * Errors: Allocation or UTF-8 conversion failures return RC_FAIL.
 * Responsible party: asn1c maintainers. History: Existing runtime decoder.
 * Example: UniversalString_decode_jer(ctx, td, c, &value, json, length).
 */
asn_dec_rval_t
UniversalString_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                           const asn_TYPE_descriptor_t *td,
                           const asn_jer_constraints_t *constraints,
                           void **sptr, const void *buf_ptr, size_t size) {
    asn_dec_rval_t rc;

    rc = OCTET_STRING_decode_jer_utf8(opt_codec_ctx, td, constraints, sptr, buf_ptr, size);
    if(rc.code == RC_OK) {
        /*
         * Now we have a whole string in UTF-8 format.
         * Convert it into UCS-4.
         */
        uint32_t *wcs;
        size_t wcs_len;
        UTF8String_t *st;
#ifndef WORDS_BIGENDIAN
        int little_endian = 1;
#endif

        assert(*sptr);
        st = (UTF8String_t *)*sptr;
        assert(st->buf);
        wcs_len = UTF8String_to_wcs(st, 0, 0);

        wcs = (uint32_t *)MALLOC(4 * (wcs_len + 1));
        if(wcs == 0 || UTF8String_to_wcs(st, wcs, wcs_len) != wcs_len) {
            rc.code = RC_FAIL;
            rc.consumed = 0;
            return rc;
        } else {
            wcs[wcs_len] = 0;  /* nul-terminate */
        }

#ifndef WORDS_BIGENDIAN
        if(*(char *)&little_endian) {
            /* Swap byte order in encoding */
            uint32_t *wc = wcs;
            uint32_t *wc_end = wcs + wcs_len;
            for(; wc < wc_end; wc++) {
                /* *wc = htonl(*wc); */
                uint32_t wch = *wc;
                *((uint8_t *)wc + 0) = wch >> 24;
                *((uint8_t *)wc + 1) = wch >> 16;
                *((uint8_t *)wc + 2) = wch >> 8;
                *((uint8_t *)wc + 3) = wch;
            }
        }
#endif  /* WORDS_BIGENDIAN */

        FREEMEM(st->buf);
        st->buf = (uint8_t *)wcs;
        st->size = 4 * wcs_len;
    }
    return rc;
}

/*
 * Encode one UniversalString as a quoted JER string.
 * Original source: asn1c UniversalString JER runtime skeleton.
 * Version/date: 1.1, 2026-10-24.
 * Inputs: td/constraints describe the type; sptr is its UCS-4 value; cb/key
 *         receive output; ilevel and flags select formatting.
 * Returns: Encoded byte count, or -1 with the failing type and value recorded.
 * Errors: Invalid values, dump errors, and callback failures return failure.
 * Responsible party: asn1c maintainers. History: callback failure fix, 2026-10-24.
 * Example: UniversalString_encode_jer(td, NULL, value, 0, JER_F, cb, key).
 */
asn_enc_rval_t
UniversalString_encode_jer(const asn_TYPE_descriptor_t *td,
                           const asn_jer_constraints_t *constraints,
                           const void *sptr, int ilevel,
                           enum jer_encoder_flags_e flags,
                           asn_app_consume_bytes_f *cb, void *app_key) {
    const UniversalString_t *st = (const UniversalString_t *)sptr;
    asn_enc_rval_t er = {0,0,0};
    size_t offset;

    (void)ilevel;
    (void)flags;

    if(!st || (!st->buf && st->size) || (st->size % 4) || !cb)
        ASN__ENCODE_FAILED;

    ASN__CALLBACK("\"", 1);
    for(offset = 0; offset < st->size; offset += 4) {
        uint32_t codepoint = ((uint32_t)st->buf[offset] << 24)
                           | ((uint32_t)st->buf[offset + 1] << 16)
                           | ((uint32_t)st->buf[offset + 2] << 8)
                           | st->buf[offset + 3];
        ssize_t written = jer_write_escaped_codepoint(codepoint, cb, app_key);
        if(written < 0 || written > SSIZE_MAX - er.encoded) goto cb_failed;
        er.encoded += written;
    }
    ASN__CALLBACK("\"", 1);

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}
