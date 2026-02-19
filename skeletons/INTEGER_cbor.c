/*
 * Copyright (c) 2024 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/*
 * INTEGER CBOR codec.
 * ASN.1 INTEGER is encoded as CBOR unsigned integer (major type 0) for
 * non-negative values, or CBOR negative integer (major type 1) for
 * negative values, following RFC 8949 §3.1.
 * For large integers exceeding 64-bit range, CBOR bignum tags 2/3 are used.
 */
#include <asn_internal.h>
#include <INTEGER.h>
#include <cbor_support.h>

asn_enc_rval_t
INTEGER_encode_cbor(const asn_TYPE_descriptor_t *td,
                    const asn_cbor_constraints_t *constraints,
                    const void *sptr,
                    asn_app_consume_bytes_f *cb, void *app_key) {
    const INTEGER_t *st = (const INTEGER_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};
    int64_t value;
    ssize_t ret;

    (void)td;
    (void)constraints;

    if(!st || !st->buf) ASN__ENCODE_FAILED;

    /* Try to fit into native 64-bit signed integer */
    if(asn_INTEGER2int64(st, &value) == 0) {
        if(value >= 0) {
            ret = cbor_write_uint_header(CBOR_MAJOR_UNSIGNED,
                                         (uint64_t)value, cb, app_key);
        } else {
            /* CBOR negative: encode as major type 1 with value -1 - n */
            ret = cbor_write_uint_header(CBOR_MAJOR_NEGATIVE,
                                         (uint64_t)(-1 - value), cb, app_key);
        }
        if(ret < 0) ASN__ENCODE_FAILED;
        er.encoded = ret;
        ASN__ENCODED_OK(er);
    }

    /*
     * Large integer: use CBOR bignum tags (RFC 8949 §3.4.3).
     * Determine sign from the BER/DER encoding (high bit of first byte).
     */
    {
        const uint8_t *buf = st->buf;
        size_t size = st->size;
        int is_negative = (size > 0 && (buf[0] & 0x80));

        if(is_negative) {
            /*
             * Negative bignum: CBOR tag 3 followed by byte string.
             * The byte string is the one's complement of the absolute value.
             * Per RFC 8949 §3.4.3: -1 - n where n is the byte string value.
             * We need to produce the one's complement.
             */
            uint8_t *complement;
            size_t i;

            ret = cbor_write_tag(CBOR_TAG_BIGNUM_NEG, cb, app_key);
            if(ret < 0) ASN__ENCODE_FAILED;
            er.encoded += ret;

            /* Allocate and compute one's complement */
            complement = (uint8_t *)MALLOC(size);
            if(!complement) ASN__ENCODE_FAILED;
            for(i = 0; i < size; i++) {
                complement[i] = ~buf[i];
            }
            /* Strip leading 0xFF bytes (equivalent of leading zeros) */
            {
                size_t skip = 0;
                while(skip < size - 1 && complement[skip] == 0) skip++;
                ret = cbor_write_bytes_header(size - skip, cb, app_key);
                if(ret >= 0 && cb(complement + skip, size - skip, app_key) < 0) ret = -1;
            }
            FREEMEM(complement);
        } else {
            /*
             * Positive bignum: CBOR tag 2 followed by byte string.
             * Strip leading zero bytes from the BER representation.
             */
            size_t skip = 0;
            while(skip < size - 1 && buf[skip] == 0) skip++;

            ret = cbor_write_tag(CBOR_TAG_BIGNUM_POS, cb, app_key);
            if(ret < 0) ASN__ENCODE_FAILED;
            er.encoded += ret;

            ret = cbor_write_bytes_header(size - skip, cb, app_key);
            if(ret >= 0 && cb(buf + skip, size - skip, app_key) < 0) ret = -1;
        }
        if(ret < 0) ASN__ENCODE_FAILED;
        er.encoded += ret + (ssize_t)(st->size - (size_t)(st->buf - buf));
    }

    ASN__ENCODED_OK(er);
}

asn_dec_rval_t
INTEGER_decode_cbor(const asn_codec_ctx_t *opt_codec_ctx,
                    const asn_TYPE_descriptor_t *td,
                    const asn_cbor_constraints_t *constraints,
                    void **sptr, const void *buf_ptr, size_t size) {
    INTEGER_t *st = (INTEGER_t *)*sptr;
    const uint8_t *p = (const uint8_t *)buf_ptr;
    uint8_t major;
    uint64_t value;
    ssize_t hlen;

    (void)opt_codec_ctx;
    (void)td;
    (void)constraints;

    hlen = cbor_read_uint_header(p, size, &major, &value);
    if(hlen == 0) ASN__DECODE_STARVED;
    if(hlen < 0) ASN__DECODE_FAILED;

    if(!st) {
        st = (INTEGER_t *)(*sptr = CALLOC(1, sizeof(*st)));
        if(!st) ASN__DECODE_FAILED;
    }

    if(major == CBOR_MAJOR_UNSIGNED) {
        /* Non-negative integer */
        if(asn_uint642INTEGER(st, value) != 0) ASN__DECODE_FAILED;
        asn_dec_rval_t rval = {RC_OK, (size_t)hlen};
        return rval;
    } else if(major == CBOR_MAJOR_NEGATIVE) {
        /* Negative integer: n = -1 - value */
        if(value <= (uint64_t)INT64_MAX) {
            int64_t neg = -1 - (int64_t)value;
            if(asn_int642INTEGER(st, neg) != 0) ASN__DECODE_FAILED;
        } else {
            /*
             * value > INT64_MAX: result n = -1 - value does not fit in int64_t.
             * Since value is in [2^63, 2^64-1], n is in [-2^64, -2^63-1].
             * Construct a 9-byte big-endian two's complement buffer:
             * 0xFF || NOT(big-endian-8-byte(value)).
             */
            uint8_t *bignum_buf;
            size_t i;
            uint64_t tmp = value;

            bignum_buf = (uint8_t *)MALLOC(9);
            if(!bignum_buf) ASN__DECODE_FAILED;

            bignum_buf[0] = 0xFF;  /* sign byte: NOT of leading 0x00 */
            for(i = 0; i < 8; i++) {
                bignum_buf[8 - i] = (uint8_t)(~(tmp & 0xFF));
                tmp >>= 8;
            }

            if(st->buf) FREEMEM(st->buf);
            st->buf = bignum_buf;
            st->size = 9;
        }
        asn_dec_rval_t rval = {RC_OK, (size_t)hlen};
        return rval;
    } else if(major == CBOR_MAJOR_TAG) {
        /* Handle bignum tags (2 = positive, 3 = negative) */
        if(value != CBOR_TAG_BIGNUM_POS && value != CBOR_TAG_BIGNUM_NEG) {
            ASN__DECODE_FAILED;
        }
        {
            int is_neg = (value == CBOR_TAG_BIGNUM_NEG);
            uint8_t bytes_major;
            uint64_t bytes_len;
            ssize_t bh_len;
            const uint8_t *body;
            size_t remaining = size - (size_t)hlen;

            bh_len = cbor_read_uint_header(p + hlen, remaining,
                                           &bytes_major, &bytes_len);
            if(bh_len == 0) ASN__DECODE_STARVED;
            if(bh_len < 0 || bytes_major != CBOR_MAJOR_BYTES) {
                ASN__DECODE_FAILED;
            }
            if(bytes_len > remaining - (size_t)bh_len) ASN__DECODE_STARVED;

            body = p + hlen + bh_len;

            if(is_neg) {
                /*
                 * Negative bignum: value = -1 - n where n is the bignum.
                 * Reconstruct as two's complement.
                 */
                uint8_t *tmp = (uint8_t *)MALLOC(bytes_len + 1);
                if(!tmp) ASN__DECODE_FAILED;
                tmp[0] = 0xFF;  /* Sign extension for negative */
                size_t i;
                for(i = 0; i < bytes_len; i++) tmp[i+1] = ~body[i];
                /* Convert the one's complement to two's complement */
                /* Increment the result */
                ssize_t carry = 1;
                for(i = bytes_len; i > 0 && carry; i--) {
                    int sum = tmp[i] + carry;
                    tmp[i] = (uint8_t)(sum & 0xFF);
                    carry = sum >> 8;
                }
                /* Set high byte for sign */
                if(tmp[1] & 0x80) {
                    /* Already negative, good */
                } else {
                    /* Need a 0xFF prefix for sign */
                }
                FREEMEM(st->buf);
                st->buf = tmp;
                st->size = (int)(bytes_len + 1);
            } else {
                /* Positive bignum */
                uint8_t *tmp;
                size_t need = bytes_len + 1; /* +1 for 0x00 sign byte if needed */
                if(bytes_len > 0 && (body[0] & 0x80)) {
                    /* Need a leading 0x00 to keep it positive */
                    tmp = (uint8_t *)MALLOC(need);
                    if(!tmp) ASN__DECODE_FAILED;
                    tmp[0] = 0x00;
                    memcpy(tmp + 1, body, bytes_len);
                    FREEMEM(st->buf);
                    st->buf = tmp;
                    st->size = (int)need;
                } else {
                    tmp = (uint8_t *)MALLOC(bytes_len ? bytes_len : 1);
                    if(!tmp) ASN__DECODE_FAILED;
                    if(bytes_len) {
                        memcpy(tmp, body, bytes_len);
                    } else {
                        tmp[0] = 0;
                    }
                    FREEMEM(st->buf);
                    st->buf = tmp;
                    st->size = (int)(bytes_len ? bytes_len : 1);
                }
            }
            asn_dec_rval_t rval = {RC_OK,
                (size_t)(hlen + bh_len + bytes_len)};
            return rval;
        }
    }

    ASN__DECODE_FAILED;
}
