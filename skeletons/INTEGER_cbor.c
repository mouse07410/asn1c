/*-
 * Copyright (c) 2025 Contributors. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <INTEGER.h>
#include <cbor_encoder.h>
#include <cbor_decoder.h>
#include <cbor_support.h>

/*
 * Purpose: encode a signed BER-backed INTEGER using preferred CBOR integers.
 * Source: RFC 8949 integer and bignum representation. Version: 2026-11-12.
 * Inputs: td identifies the ASN.1 type; sptr holds the value; cb and app_key
 * receive bytes. Returns: encoded byte count or failure. Errors: invalid value,
 * allocation failure, or callback failure. Author: asn1c maintainers.
 * History: major type 1 covers all values down to -2^64. Example: -1 emits 20.
 */
asn_enc_rval_t
INTEGER_encode_cbor(const asn_TYPE_descriptor_t *td, const void *sptr,
                    asn_app_consume_bytes_f *cb, void *app_key) {
    const INTEGER_t *st = (const INTEGER_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};
    ssize_t ret;

    (void)td;

    if(!st || !st->buf) ASN__ENCODE_FAILED;

    if(st->size == 0) {
        /* Zero */
        ret = cbor_encode_uint(0, cb, app_key);
        if(ret < 0) ASN__ENCODE_FAILED;
        er.encoded = ret;
        ASN__ENCODED_OK(er);
    }

    /* Check sign: BER INTEGER is two's complement big-endian */
    int is_negative = (st->buf[0] & 0x80) != 0;

    /* Try to fit in int64_t / uint64_t first */
    if(is_negative) {
        intmax_t val;
        if(asn_INTEGER2imax(st, &val) == 0) {
            /* val < 0: CBOR negint = -(val+1) stored as -(argument+1)
             * so argument = (-val) - 1 = ~val (for negative val)
             */
            uint64_t argument = (uint64_t)(-(val + 1));
            ret = cbor_encode_negint(argument, cb, app_key);
            if(ret < 0) ASN__ENCODE_FAILED;
            er.encoded = ret;
            ASN__ENCODED_OK(er);
        }

        /*
         * Value too small for intmax_t: compute the unsigned CBOR argument.
         * For negative bignum, the byte string represents the one's
         * complement magnitude: -(n+1) where n is the magnitude.
         * The BER INTEGER bytes are two's complement.
         * We need to strip the sign byte and convert to unsigned magnitude.
         *
         * For a negative BER INTEGER:
         *   - flip all bytes (ones complement) to get magnitude - 1
         *   - then tag 3 encodes -(n+1) where n is the unsigned byte value
         * Actually, CBOR tag 3 says: the encoded value is -1 - N where N
         * is the unsigned integer represented by the byte string.
         * For BER two's complement negative number, we can compute:
         * value = -2^(8*k) + (buf interpreted as unsigned)
         * We need to find N such that value = -1 - N
         * N = -1 - value = -1 - (-2^(8*k) + unsigned) = 2^(8*k) - 1 - unsigned
         * = ones_complement(unsigned)
         * i.e. flip all bits.
         */
        size_t len = st->size;
        const uint8_t *p = st->buf;

        /* Complementing N removes every leading FF, even a BER sign octet. */
        while(len > 1 && p[0] == 0xFF) {
            p++;
            len--;
        }

        /* Major type 1 represents all N up to UINT64_MAX, not just INT64_MAX. */
        if(len <= sizeof(uint64_t)) {
            uint64_t argument = 0;
            size_t i;
            for(i = 0; i < len; i++) {
                argument = (argument << 8) | (uint8_t)~p[i];
            }
            ret = cbor_encode_negint(argument, cb, app_key);
            if(ret < 0) ASN__ENCODE_FAILED;
            er.encoded = ret;
            ASN__ENCODED_OK(er);
        }

        /* Build the ones-complement byte string */
        uint8_t *mag = (uint8_t *)MALLOC(len);
        if(!mag) ASN__ENCODE_FAILED;
        for(size_t i = 0; i < len; i++) {
            mag[i] = (uint8_t)(~p[i]);
        }

        /* Tag 3 + byte string */
        ret = cbor_encode_tag(CBOR_TAG_NEGINT_BIGNUM, cb, app_key);
        if(ret < 0) { FREEMEM(mag); ASN__ENCODE_FAILED; }
        er.encoded += ret;

        ret = cbor_encode_bytes(mag, len, cb, app_key);
        FREEMEM(mag);
        if(ret < 0) ASN__ENCODE_FAILED;
        er.encoded += ret;

        ASN__ENCODED_OK(er);
    } else {
        /* Positive or zero */
        uintmax_t val;
        if(asn_INTEGER2umax(st, &val) == 0) {
            ret = cbor_encode_uint((uint64_t)val, cb, app_key);
            if(ret < 0) ASN__ENCODE_FAILED;
            er.encoded = ret;
            ASN__ENCODED_OK(er);
        }

        /*
         * Positive bignum (tag 2 + byte string).
         * Strip leading zero bytes from BER INTEGER representation.
         */
        size_t len = st->size;
        const uint8_t *p = st->buf;

        /* Strip leading zero bytes (but positive, so 0x00 prefix) */
        while(len > 1 && p[0] == 0x00) {
            p++;
            len--;
        }

        ret = cbor_encode_tag(CBOR_TAG_POSINT_BIGNUM, cb, app_key);
        if(ret < 0) ASN__ENCODE_FAILED;
        er.encoded += ret;

        ret = cbor_encode_bytes(p, len, cb, app_key);
        if(ret < 0) ASN__ENCODE_FAILED;
        er.encoded += ret;

        ASN__ENCODED_OK(er);
    }

    /* This path is unreachable if all branches above are covered */
    ASN__ENCODE_FAILED;
}

/*
 * Purpose: decode one CBOR integer or bignum into fresh BER-backed storage.
 * Source: repository CBOR mapping. Version: 2026-10-30.
 * Inputs: opt_codec_ctx limits nesting; td identifies the type; sptr receives
 * allocated output; buf_ptr/size bound the CBOR item. Returns: status and bytes.
 * Errors: malformed heads, truncated bignums, and allocation failures fail.
 * Author: asn1c maintainers. History: fixed host-independent negative values
 * below INT64_MIN and checked bignum lengths. Caller frees partial output.
 * Example: major-one argument 2^63 becomes BER FF 7F FF FF FF FF FF FF FF.
 */
static asn_dec_rval_t
INTEGER_decode_cbor_value(const asn_codec_ctx_t *opt_codec_ctx,
                          const asn_TYPE_descriptor_t *td,
                          void **sptr, const void *buf_ptr, size_t size) {
    INTEGER_t *st;
    const uint8_t *buf = (const uint8_t *)buf_ptr;
    uint8_t major;
    uint64_t argument;
    ssize_t hlen;
    asn_dec_rval_t rval = {RC_FAIL, 0};

    (void)opt_codec_ctx;
    (void)td;

    if(!sptr || !buf || size < 1) ASN__DECODE_FAILED;
    st = (INTEGER_t *)*sptr;
    if(!st) {
        st = (INTEGER_t *)CALLOC(1, sizeof(*st));
        if(!st) ASN__DECODE_FAILED;
        *sptr = st;
    }

    /*
     * Skip any leading CBOR tags that are NOT bignum tags (2/3).
     * Tags 2 and 3 carry semantic meaning for INTEGER (bignum encoding),
     * so they are handled explicitly below.  All other tags (e.g., tag 1
     * for epoch timestamps, tag 100 for calendar dates) are optional
     * metadata and should be ignored per RFC 8949 §3.4.
     */
    {
        size_t tag_skip = 0;
        for(;;) {
            uint8_t m;
            uint64_t a;
            ssize_t h;
            if(tag_skip >= size) ASN__DECODE_FAILED;
            h = cbor_decode_head(buf + tag_skip, size - tag_skip, &m, &a);
            if(h < 0) ASN__DECODE_FAILED;
            if(m != CBOR_MAJOR_TAG) break;
            if(a == CBOR_TAG_POSINT_BIGNUM || a == CBOR_TAG_NEGINT_BIGNUM)
                break;  /* bignum tag: handle below */
            tag_skip += (size_t)h;
        }
        buf  += tag_skip;
        size -= tag_skip;
        rval.consumed = tag_skip;  /* will be added to inner consumed */
    }

    hlen = cbor_decode_head(buf, size, &major, &argument);
    if(hlen < 0) ASN__DECODE_FAILED;

    if(major == CBOR_MAJOR_UINT) {
        /* Positive integer: argument is the value */
        if(asn_umax2INTEGER(st, (uintmax_t)argument)) ASN__DECODE_FAILED;
        rval.consumed += (size_t)hlen;
        rval.code = RC_OK;
        return rval;
    } else if(major == CBOR_MAJOR_NEGINT) {
        /*
         * Negative integer: value = -(argument + 1)
         * If argument >= INT64_MAX+1u, value < INT64_MIN: need bignum path.
         */
        if(argument <= (uint64_t)INT64_MAX) {
            intmax_t val = -(intmax_t)argument - 1;
            if(asn_imax2INTEGER(st, val)) ASN__DECODE_FAILED;
        } else {
            /*
             * argument > INT64_MAX: value = -(argument+1) which doesn't
             * fit in int64_t. Encode as negative BER INTEGER via bignum.
             * We need to store -(argument+1) in two's complement.
             * Compute ones_complement(argument) and store as negative BER.
             *
             * argument is the CBOR negint argument (unsigned magnitude - 1).
             * BER twos-complement: flip bits of (argument) and add 1,
             * but that's for the magnitude. Actually:
             * value = -(argument + 1)
             * In two's complement 9-byte form:
             *   magnitude = argument + 1 (could overflow to 2^64)
             *   For argument == UINT64_MAX: magnitude = 0 (2^64 mod 2^64)
             *   This is -2^64 which needs 9 bytes in BER.
             */
            uint8_t ber[9];
            size_t ber_len = sizeof(ber);
            size_t octet;
            uint64_t pattern = ~argument;

            /* A value below INT64_MIN needs 0xFF plus eight big-endian bytes. */
            ber[0] = 0xFF;
            for(octet = 0; octet < 8; octet++) {
                ber[octet + 1] = (uint8_t)(pattern >> (56 - 8 * octet));
            }
            /* Store in INTEGER_t */
            void *p = MALLOC(ber_len);
            if(!p) ASN__DECODE_FAILED;
            FREEMEM(st->buf);
            st->buf = (uint8_t *)p;
            st->size = ber_len;
            memcpy(st->buf, ber, ber_len);
        }
        rval.consumed += (size_t)hlen;
        rval.code = RC_OK;
        return rval;
    } else if(major == CBOR_MAJOR_TAG) {
        /* Bignum: tag 2 (positive) or tag 3 (negative) */
        uint8_t tag_major;
        uint64_t bstr_len;
        ssize_t bstr_hlen;
        const uint8_t *bstr_buf;

        if(argument != CBOR_TAG_POSINT_BIGNUM
           && argument != CBOR_TAG_NEGINT_BIGNUM)
            ASN__DECODE_FAILED;

        bstr_hlen = cbor_decode_head(buf + hlen, size - (size_t)hlen,
                                     &tag_major, &bstr_len);
        if(bstr_hlen < 0 || tag_major != CBOR_MAJOR_BYTES)
            ASN__DECODE_FAILED;
        if(bstr_len > SIZE_MAX - 1
           || bstr_len > size - (size_t)hlen - (size_t)bstr_hlen)
            ASN__DECODE_FAILED;

        bstr_buf = buf + hlen + bstr_hlen;

        if(argument == CBOR_TAG_POSINT_BIGNUM) {
            /*
             * Positive bignum: byte string is the unsigned magnitude.
             * BER encoding: prepend 0x00 if high bit is set.
             */
            size_t ber_len = bstr_len;
            uint8_t *ber;
            int need_pad = (bstr_len > 0 && (bstr_buf[0] & 0x80)) ? 1 : 0;
            ber_len += need_pad;
            if(ber_len == 0) ber_len = 1;  /* zero */
            ber = (uint8_t *)MALLOC(ber_len);
            if(!ber) ASN__DECODE_FAILED;
            if(need_pad) {
                ber[0] = 0x00;
                memcpy(ber + 1, bstr_buf, bstr_len);
            } else if(bstr_len > 0) {
                memcpy(ber, bstr_buf, bstr_len);
            } else {
                ber[0] = 0x00;
            }
            FREEMEM(st->buf);
            st->buf = ber;
            st->size = ber_len;
        } else {
            /*
             * Negative bignum (tag 3): value = -1 - N where N is unsigned
             * integer from byte string.
             * To get BER two's complement:
             *   value = -N - 1
             *   In BER: flip all bits of N (ones complement), which gives -N-1
             *   for unsigned N interpreted as non-negative big-endian.
             *   The result needs sign extension (high bit must be 1).
             */
            size_t ber_len = bstr_len;
            if(ber_len == 0) ber_len = 1;
            uint8_t *ber = (uint8_t *)MALLOC(ber_len);
            if(!ber) ASN__DECODE_FAILED;
            if(bstr_len == 0) {
                ber[0] = 0xFF;  /* -1 */
            } else {
                size_t i;
                for(i = 0; i < bstr_len; i++) {
                    ber[i] = (uint8_t)(~bstr_buf[i]);
                }
                /* If high bit not set, need to prepend 0xFF for sign */
                if(!(ber[0] & 0x80)) {
                    ber_len = bstr_len + 1;
                    uint8_t *new_ber = (uint8_t *)MALLOC(ber_len);
                    if(!new_ber) { FREEMEM(ber); ASN__DECODE_FAILED; }
                    new_ber[0] = 0xFF;
                    memcpy(new_ber + 1, ber, bstr_len);
                    FREEMEM(ber);
                    ber = new_ber;
                }
            }
            FREEMEM(st->buf);
            st->buf = ber;
            st->size = ber_len;
        }

        rval.consumed += (size_t)hlen + (size_t)bstr_hlen + (size_t)bstr_len;
        rval.code = RC_OK;
        return rval;
    }

    ASN__DECODE_FAILED;
}

/*
 * Purpose: decode CBOR INTEGER transactionally into caller-owned storage.
 * Source: repository CBOR mapping. Version: 2026-10-30.
 * Inputs: opt_codec_ctx limits nesting; td identifies the type; sptr owns
 * output; buf_ptr/size bound the item. Returns: status and consumed bytes.
 * Errors: malformed input and allocation failures preserve prior output.
 * Author: asn1c maintainers. History: isolated partial-value cleanup.
 * Example: an invalid bignum leaves a preallocated INTEGER unchanged.
 */
asn_dec_rval_t
INTEGER_decode_cbor(const asn_codec_ctx_t *opt_codec_ctx,
                    const asn_TYPE_descriptor_t *td,
                    void **sptr, const void *buf_ptr, size_t size) {
    INTEGER_t *fresh = NULL;
    asn_dec_rval_t result;

    if(!sptr) ASN__DECODE_FAILED;
    result = INTEGER_decode_cbor_value(opt_codec_ctx, td, (void **)&fresh,
                                       buf_ptr, size);
    if(result.code != RC_OK) {
        if(fresh) {
            FREEMEM(fresh->buf);
            FREEMEM(fresh);
        }
        return result;
    }

    /* Commit only after the whole item and all bounds have passed. */
    if(*sptr) {
        INTEGER_t *prior = (INTEGER_t *)*sptr;
        FREEMEM(prior->buf);
        prior->buf = fresh->buf;
        prior->size = fresh->size;
        FREEMEM(fresh);
    } else {
        *sptr = fresh;
    }
    return result;
}
