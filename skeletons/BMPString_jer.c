/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <BMPString.h>
#include <UTF8String.h>
#include <jer_string.h>

asn_dec_rval_t
BMPString_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                     const asn_TYPE_descriptor_t *td,
                     const asn_jer_constraints_t *constraints, void **sptr,
                     const void *buf_ptr, size_t size) {
    asn_dec_rval_t rc;

    rc = OCTET_STRING_decode_jer_utf8(opt_codec_ctx, td, constraints, sptr, buf_ptr, size);
    if(rc.code == RC_OK) {
        /*
         * Now we have a whole string in UTF-8 format.
         * Convert it into UCS-2.
         */
        uint32_t *wcs;
        size_t wcs_len;
        UTF8String_t *st;

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

        if(1) {
            /* Swap byte order and trim encoding to 2 bytes */
            uint32_t *wc = wcs;
            uint32_t *wc_end = wcs + wcs_len;
            uint16_t *dstwc = (uint16_t *)wcs;
            for(; wc < wc_end; wc++, dstwc++) {
                uint32_t wch = *wc;
                if(wch > 0xffff) {
                    FREEMEM(wcs);
                    rc.code = RC_FAIL;
                    rc.consumed = 0;
                    return rc;
                }
                *((uint8_t *)dstwc + 0) = wch >> 8;
                *((uint8_t *)dstwc + 1) = wch;
            }
            dstwc = (uint16_t *)REALLOC(wcs, 2 * (wcs_len + 1));
            if(!dstwc) {
                FREEMEM(wcs);
                rc.code = RC_FAIL;
                rc.consumed = 0;
                return rc;
            } else {
                dstwc[wcs_len] = 0;  /* nul-terminate */
                wcs = (uint32_t *)(void *)dstwc;  /* Alignment OK */
            }
        }

        FREEMEM(st->buf);
        st->buf = (uint8_t *)wcs;
        st->size = 2 * wcs_len;
    }
    return rc;
}

/*
 * Purpose: encode BMPString code units as a valid quoted JER JSON string.
 * Original source: BMPString JER skeleton with JSON scalar escaping.
 * Version/date: 1.0, 2026-10-31. Inputs: td/constraints describe the type;
 * sptr is a big-endian UCS-2 value; cb/key receive the JSON bytes.
 * Returns: encoded size or -1 for invalid storage, scalar, or callback failure.
 * Exceptions: none. Responsible party: asn1c maintainers.
 * History: replaced raw UTF-8 dumping with JSON-safe output.
 * Example: a stored quote is emitted as `\"` inside the JSON string.
 */
asn_enc_rval_t
BMPString_encode_jer(const asn_TYPE_descriptor_t *td,
                     const asn_jer_constraints_t* constraints,
                     const void *sptr, int ilevel,
                     enum jer_encoder_flags_e flags,
                     asn_app_consume_bytes_f *cb, void *app_key) {
    const BMPString_t *st = (const BMPString_t *)sptr;
    asn_enc_rval_t er = {0,0,0};
    size_t offset;

    (void)ilevel;
    (void)flags;

    if(!st || (!st->buf && st->size) || (st->size & 1) || !cb)
        ASN__ENCODE_FAILED;

    ASN__CALLBACK("\"", 1);
    for(offset = 0; offset < st->size; offset += 2) {
        uint32_t codepoint = ((uint32_t)st->buf[offset] << 8)
                           | st->buf[offset + 1];
        ssize_t written = jer_write_escaped_codepoint(codepoint, cb, app_key);
        if(written < 0 || written > SSIZE_MAX - er.encoded) goto cb_failed;
        er.encoded += written;
    }
    ASN__CALLBACK("\"", 1);

    ASN__ENCODED_OK(er);

cb_failed:
    ASN__ENCODE_FAILED;
}
