/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <OPEN_TYPE.h>
#include <constr_CHOICE.h>

int
OPEN_TYPE_print(const asn_TYPE_descriptor_t *td, const void *sptr, int ilevel,
                asn_app_consume_bytes_f *cb, void *app_key) {
    
    if(!sptr) {
        return (cb("<absent>", 8, app_key) < 0) ? -1 : 0;
    }

    /* Check if this is direct type mode (no CHOICE wrapper) */
    if(td->elements_count == 0) {
        /* Direct type mode: use type selector to find the actual type */
        const asn_ioc_set_t *ioc_set = td->specifics;
        if(ioc_set && ioc_set->rows_count > 0) {
            const asn_ioc_row_t *row = &ioc_set->rows[0];
            if(row->columns_count > 0) {
                const asn_ioc_cell_t *type_cell = &row->columns[row->columns_count - 1];
                if(type_cell->type_descriptor) {
                    /* Print using the actual type descriptor */
                    return type_cell->type_descriptor->op->print_struct(
                        type_cell->type_descriptor, sptr, ilevel, cb, app_key);
                }
            }
        }
        /* No type information available */
        return (cb("<unknown>", 9, app_key) < 0) ? -1 : 0;
    }

    /* CHOICE wrapper mode: use CHOICE printer */
    return CHOICE_print(td, sptr, ilevel, cb, app_key);
}
