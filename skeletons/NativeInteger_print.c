/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <NativeInteger.h>

/*
 * INTEGER specific human-readable output.
 */
int
NativeInteger_print(const asn_TYPE_descriptor_t *td, const void *sptr,
                    int ilevel, asn_app_consume_bytes_f *cb, void *app_key) {
    const asn_INTEGER_specifics_t *specs =
        (const asn_INTEGER_specifics_t *)td->specifics;
    char scratch[32];  /* Enough for 64-bit int */
    int ret;

    (void)ilevel;  /* Unused argument */

    if(sptr) {
        if(specs && specs->field_unsigned) {
            uintmax_t value = NativeInteger_load_u(sptr, specs);
            ret = snprintf(scratch, sizeof(scratch), "%ju", value);
        } else {
            intmax_t value = NativeInteger_load_s(sptr, specs);
            ret = snprintf(scratch, sizeof(scratch), "%jd", value);
        }
        assert(ret > 0 && (size_t)ret < sizeof(scratch));
        if(cb(scratch, ret, app_key) < 0) return -1;
        {
            intmax_t value = NativeInteger_load_s(sptr, specs);
            const asn_INTEGER_enum_map_t *el =
                (specs && (value >= 0 || !specs->field_unsigned))
                    ? INTEGER_map_value2enum(specs, (long)value) : 0;
            if(el) {
                if(cb(" (", 2, app_key) < 0) return -1;
                if(cb(el->enum_name, el->enum_len, app_key) < 0) return -1;
                if(cb(")", 1, app_key) < 0) return -1;
            }
        }
        return 0;
    } else {
        return (cb("<absent>", 8, app_key) < 0) ? -1 : 0;
    }
}
