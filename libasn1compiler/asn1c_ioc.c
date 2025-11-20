#include "asn1c_internal.h"
#include "asn1c_ioc.h"
#include "asn1c_out.h"
#include "asn1c_misc.h"
#include <asn1fix_export.h>
#include <asn1print.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define MKID(expr) asn1c_make_identifier(AMI_USE_PREFIX, (expr), 0)

/*
 * Given the table constraint or component relation constraint
 * ({ObjectSetName}{...}) returns "ObjectSetName" as a reference.
 */
asn1p_ref_t *
asn1c_get_information_object_set_reference_from_constraint(arg_t *arg,
    const asn1p_constraint_t *ct) {

    if(!ct) return NULL;
    assert(ct->type == ACT_CA_CRC);
    assert(ct->el_count >= 1);

    DEBUG("Component Relation Constraint: %s", asn1p_constraint_string(ct));

    assert(ct->elements[0]->type == ACT_EL_VALUE);

    asn1p_value_t *val = ct->elements[0]->value;
    if(val->type == ATV_VALUESET && val->value.constraint->type == ACT_EL_TYPE) {
        asn1p_value_t *csub = val->value.constraint->containedSubtype;
        if(!csub) {
            /* Ignore */
        } else if(csub->type == ATV_REFERENCED) {
            return csub->value.reference;
        } else if(csub->type == ATV_TYPE) {
            if(csub->value.v_type->expr_type == A1TC_REFERENCE) {
                assert(csub->value.v_type->reference);
                return csub->value.v_type->reference;
            }
        }
    }
    if(val->type != ATV_REFERENCED) {
        FATAL("Set reference: %s", asn1f_printable_value(val));
        assert(val->type == ATV_REFERENCED);
    }

    return val->value.reference;
}

static asn1c_ioc_table_and_objset_t
asn1c_get_ioc_table_from_objset(arg_t *arg, const asn1p_ref_t *objset_ref, asn1p_expr_t *objset) {
    asn1c_ioc_table_and_objset_t ioc_tao = { 0, 0, 1 };

    (void)objset_ref;

    if(objset->ioc_table) {
        ioc_tao.ioct = objset->ioc_table;
        ioc_tao.objset = objset;
        ioc_tao.fatal_error = 0;
    } else {
        /* Information Object Set is empty, which is valid ASN.1.
         * This can happen with empty extension sets in protocols like GSM MAP.
         * Return a valid but empty ioc_tao structure to allow processing to continue. */
        DEBUG("Information Object Set %s contains no objects at line %d (empty set)",
              objset->Identifier, objset->_lineno);
        ioc_tao.ioct = NULL;
        ioc_tao.objset = objset;
        ioc_tao.fatal_error = 0;
    }

    return ioc_tao;
}

asn1c_ioc_table_and_objset_t
asn1c_get_ioc_table(arg_t *arg) {
    asn1p_expr_t *expr = arg->expr;
	asn1p_expr_t *memb;
    asn1p_expr_t *objset = 0;
    asn1p_ref_t *objset_ref = NULL;
    asn1c_ioc_table_and_objset_t safe_ioc_tao = {0, 0, 0};
    asn1c_ioc_table_and_objset_t failed_ioc_tao = { 0, 0, 1 };

    TQ_FOR(memb, &(expr->members), next) {
        const asn1p_constraint_t *cr_ct =
            asn1p_get_component_relation_constraint(memb->constraints);
        asn1p_ref_t *tmpref =
            asn1c_get_information_object_set_reference_from_constraint(arg,
                                                                       cr_ct);
        if(tmpref) {
            if(objset_ref && asn1p_ref_compare(objset_ref, tmpref) != 0) {
                FATAL(
                    "Object set reference on line %d differs from object set "
                    "reference on line %d",
                    objset_ref->_lineno, tmpref->_lineno);
                return failed_ioc_tao;
            }
            objset_ref = tmpref;
        }

    }

    if(!objset_ref) {
        return safe_ioc_tao;
    }

    objset = WITH_MODULE_NAMESPACE(
        arg->expr->module, expr_ns,
        asn1f_lookup_symbol_ex(arg->asn, expr_ns, arg->expr, objset_ref));
    if(!objset) {
        FATAL("Cannot found %s", asn1p_ref_string(objset_ref));
        return failed_ioc_tao;
    }

    return asn1c_get_ioc_table_from_objset(arg, objset_ref, objset);
}

/* ===== helpers to encode OBJECT IDENTIFIER as BER arcs (base-128) ===== */

static int oid_arc_encode(uint64_t arc, unsigned char *tmp) {
    unsigned char buf[10]; int i = 0;
    if(arc == 0) { tmp[0] = 0; return 1; }
    while(arc) { buf[i++] = (unsigned char)(arc & 0x7F); arc >>= 7; }
    for(int j = i - 1, k = 0; j >= 0; j--, k++) tmp[k] = buf[j] | (j ? 0x80 : 0);
    return i;
}
/* Parse textual OID: "1.2.3", "1 2 3", or "{ 1 2 3 }" */
static int parse_unparsed_oid(const char *buf, int len, uint64_t arcs[], int max_arcs) {
    int n = 0, i = 0;
    while(i < len && isspace((unsigned char)buf[i])) i++;
    if(i < len && buf[i] == '{') i++;
    while(i < len) {
        while(i < len && isspace((unsigned char)buf[i])) i++;
        if(i < len && buf[i] == '}') { i++; break; }
        if(n >= max_arcs) return -1;
        if(i < len && buf[i] == '.') { i++; continue; }
        if(i >= len || !isdigit((unsigned char)buf[i])) return -1;
        uint64_t v = 0; while(i < len && isdigit((unsigned char)buf[i])) v =
		   v*10 + (uint64_t)(buf[i++] - '0');
        arcs[n++] = v;
    }
    return n;
}

/*
 * Emit content for a value cell.
 * FIX: when the primitive type is OBJECT IDENTIFIER and the value is ATV_UNPARSED,
 *      parse the textual OID and emit proper bytes+length.
 */
static int
emit_ioc_value(arg_t *arg, struct asn1p_ioc_cell_s *cell) {

    if(cell->value && cell->value->meta_type == AMT_VALUE) {
        const char *prim_type = NULL;
        int primitive_representation = 0;

        asn1p_expr_t *cv_type =
            asn1f_find_terminal_type_ex(arg->asn, arg->ns, cell->value);

        switch(cv_type->expr_type) {
        case ASN_BASIC_INTEGER:
        case ASN_BASIC_ENUMERATED:
            switch(asn1c_type_fits_long(arg, cell->value /* sic */)) {
            case FL_NOTFIT:
                GEN_INCLUDE_STD("INTEGER");
                prim_type = "INTEGER_t";
                break;
            case FL_PRESUMED:
            case FL_FITS_SIGNED:
                primitive_representation = 1;
                prim_type = "long";
                break;
            case FL_FITS_UNSIGN:
                prim_type = "unsigned long";
                primitive_representation = 1;
                break;
            }
            break;
        case ASN_BASIC_OBJECT_IDENTIFIER:
            prim_type = "OBJECT_IDENTIFIER_t";
            break;
        case ASN_BASIC_RELATIVE_OID:
            prim_type = "RELATIVE_OID_t";
            break;
        default: {
            char *p = strdup(MKID(cell->value));
            FATAL("Unsupported type %s for value %s",
                  asn1c_type_name(arg, cell->value, TNF_UNMODIFIED), p);
            free(p);
            return -1;
        }
        }
        OUT("static const %s asn_VAL_%d_%s = ", prim_type,
            cell->value->_type_unique_index, MKID(cell->value));

        asn1p_expr_t *expr_value = cell->value;
        while(expr_value->value->type == ATV_REFERENCED) {
            expr_value = WITH_MODULE_NAMESPACE(
                expr_value->module, expr_ns,
                asn1f_lookup_symbol_ex(arg->asn, expr_ns, expr_value,
                                       expr_value->value->value.reference));
            if(!expr_value) {
                FATAL("Unrecognized value type for %s", MKID(cell->value));
                return -1;
            }
        }

        if(!primitive_representation) OUT("{ ");

        switch(expr_value->value->type) {
        case ATV_INTEGER:
            if(primitive_representation) {
                OUT("%s", asn1p_itoa(expr_value->value->value.v_integer));
                break;
            } else {
                asn1c_integer_t v = expr_value->value->value.v_integer;
                if(v >= 0) {
                    if(v <= 127) {
                        OUT("\"\\x%02x\", 1", (int)v);
                        break;
                    } else if(v <= 32767) {
                        OUT("\"\\x%02x\\x%02x\", 2", (int)(v >> 8), (int)(v & 0xff));
                        break;
                    }
                }
                FATAL("Unsupported value %s range for type %s",
                      asn1f_printable_value(expr_value->value),
                      MKID(cell->value));
                return -1;
            }

        case ATV_UNPARSED:
            if(prim_type && (strcmp(prim_type, "OBJECT_IDENTIFIER_t") == 0 || strcmp(prim_type, "RELATIVE_OID_t") == 0)
               && expr_value->value->value.string.buf
               && expr_value->value->value.string.size > 0) {
                const char *buf = (const char *)expr_value->value->value.string.buf;
                int len = expr_value->value->value.string.size;
                uint64_t arcs[64];
                int n = parse_unparsed_oid(buf, len, arcs, (int)(sizeof(arcs)/sizeof(arcs[0])));
                int is_relative_oid = (strcmp(prim_type, "RELATIVE_OID_t") == 0);
                int min_arcs = is_relative_oid ? 1 : 2;
                if(n >= min_arcs) {
                    unsigned char bytes[256]; size_t off = 0;
                    int start_arc = 0;
                    if(!is_relative_oid) {
                        /* OBJECT_IDENTIFIER: encode first two arcs as arcs[0]*40 + arcs[1] */
                        off += oid_arc_encode(arcs[0]*40 + arcs[1], bytes + off);
                        start_arc = 2;
                    }
                    /* Encode remaining arcs (or all arcs for RELATIVE-OID) */
                    for(int i = start_arc; i < n; i++) {
                        off += oid_arc_encode(arcs[i], bytes + off);
                        if(off >= sizeof(bytes)) { FATAL("OID too long"); return -1; }
                    }
                    OUT("(uint8_t[]){");
                    for(size_t i = 0; i < off; i++)
	                    OUT("%s%u", (i ? ", " : " "), bytes[i]);
                    OUT("}, %zu", off);
                    break;
                }
            }
            FATAL("Inappropriate or unparsable value %s for type %s",
                  asn1f_printable_value(expr_value->value), MKID(cell->value));
            return -1;

        default:
            FATAL("Inappropriate value %s for type %s",
                  asn1f_printable_value(expr_value->value), MKID(cell->value));
            return -1;
        }

        if(primitive_representation) {
            OUT(";\n");
        } else {
            OUT(" };");
            OUT(" /* %s */\n", asn1f_printable_value(expr_value->value));
        }
    }

    return 0;
}

/*
 * Emit a single IOC cell initializer.
 * FIX: for TYPE cells, resolve to the concrete descriptor symbol using TNF_RSAFE
 *      so we reference e.g. &asn_DEF_SEQUENCE_OF_CommTxPDU_1 instead of
 *      the non-descriptor placeholder &asn_DEF_SEQUENCE_OF.
 */
static int
emit_ioc_cell(arg_t *arg, struct asn1p_ioc_cell_s *cell) {
    OUT("{ \"%s\", ", cell->field->Identifier);

    if(!cell->value) {
        /* Ignore */
    } else if(cell->value->meta_type == AMT_VALUE) {
        /* For value cells (e.g., &id): take the VALUE's terminal type and
         * use the built-in descriptor (no _t / no RSAFE here). */
        asn1p_expr_t *vt =
            asn1f_find_terminal_type_ex(arg->asn, arg->ns, cell->value);
        if(!vt) return -1;
        GEN_INCLUDE(asn1c_type_name(arg, vt, TNF_INCLUDE));
        OUT("aioc__value, &asn_DEF_%s, ", asn1c_type_name(arg, vt, TNF_SAFE));
        OUT("&asn_VAL_%d_%s", cell->value->_type_unique_index, MKID(cell->value));

    /* } else if(cell->value->meta_type == AMT_TYPE) { */
    /*     /\* Anonymous / constructed type (e.g., SEQUENCE OF CommTxPDU): */
    /*      * reference the concrete, suffixed descriptor defined in this TU. *\/ */
    /*     GEN_INCLUDE(asn1c_type_name(arg, cell->value, TNF_INCLUDE)); */
    /*     OUT("aioc__type, &asn_DEF_%s_%d", */
    /*         MKID(cell->value), cell->value->_type_unique_index); */

    /* } else if(cell->value->meta_type == AMT_TYPEREF) { */
    /*     /\* Named type reference: use SAFE so we get the proper (usually */
    /*      * unsuffixed) descriptor symbol defined in its own TU. *\/ */
    /*     GEN_INCLUDE(asn1c_type_name(arg, cell->value, TNF_INCLUDE)); */
    /*     OUT("aioc__type, &asn_DEF_%s", */
    /*         asn1c_type_name(arg, cell->value, TNF_SAFE)); */

    } else if(cell->value->meta_type == AMT_TYPEREF) {
        /* Named type reference: use SAFE for the standard descriptor name */
        GEN_INCLUDE(asn1c_type_name(arg, cell->value, TNF_INCLUDE));
        OUT("aioc__type, &asn_DEF_%s", asn1c_type_name(arg, cell->value, TNF_SAFE));
    } else if(cell->value->meta_type == AMT_TYPE) {
        /* Anonymous/constructed type: reference the suffixed descriptor */
        GEN_INCLUDE(asn1c_type_name(arg, cell->value, TNF_INCLUDE));
        OUT("aioc__type, &asn_DEF_%s_%d", 
            MKID(cell->value), cell->value->_type_unique_index);
        
    } else {
        return -1;
    }

    OUT(" }");

    return 0;
}

/*
 * Refer to skeletons/asn_ioc.h
 */
/* ============================================================================
 * COMPLETE FIX - Replace emit_ioc_table() in asn1c_ioc.c
 * 
 * The Problem: Forward declarations were always using "extern" but definitions
 * could be "static", causing a storage class mismatch.
 * 
 * The Solution: Forward declarations must match the storage class that will be
 * used in the actual definition. This depends on:
 * - A1C_ALL_DEFS_GLOBAL flag: if set, all defs are non-static (extern)
 * - Otherwise, anonymous/constructed types are static
 * ============================================================================ */

/* ============================================================================
 * PART 1: Fix in asn1c_ioc.c - emit_ioc_table()
 * This fixes the IOC table type forward declarations
 * ============================================================================ */

int
emit_ioc_table(arg_t *arg, asn1p_expr_t *context, asn1c_ioc_table_and_objset_t ioc_tao) {
    size_t columns = 0;

    (void)context;
    GEN_INCLUDE_STD("asn_ioc");

    REDIR(OT_IOC_TABLES);

    /* Handle the case where the IOC table is NULL (empty Information Object Set) */
    if(!ioc_tao.ioct) {
        return 0;
    }

    /* Emit values that are used in the Information Object Set table first */
    for(size_t rn = 0; rn < ioc_tao.ioct->rows; rn++) {
        asn1p_ioc_row_t *row = ioc_tao.ioct->row[rn];
        for(size_t cn = 0; cn < row->columns; cn++) {
            if(emit_ioc_value(arg, &row->column[cn])) {
                return -1;
            }
        }
    }

    if(ioc_tao.ioct->rows == 0)
        return 0;

    /* Forward-declare concrete descriptors referenced by TYPE cells.
     * 
     * IOC table types are ALWAYS embedded (anonymous members), so:
     * - They're static UNLESS A1C_ALL_DEFS_GLOBAL is set
     */
    
    for(size_t rn = 0; rn < ioc_tao.ioct->rows; rn++) {
        asn1p_ioc_row_t *row = ioc_tao.ioct->row[rn];
        for(size_t cn = 0; cn < row->columns; cn++) {
            struct asn1p_ioc_cell_s *cell = &row->column[cn];
            
            if(cell->value && cell->value->meta_type == AMT_TYPE) {
                /* Anonymous/constructed type - will be static unless A1C_ALL_DEFS_GLOBAL */
                if(arg->flags & A1C_ALL_DEFS_GLOBAL) {
                    OUT("extern asn_TYPE_descriptor_t asn_DEF_%s_%d;\n",
                        MKID(cell->value), cell->value->_type_unique_index);
                } else {
                    OUT("static asn_TYPE_descriptor_t asn_DEF_%s_%d;\n",
                        MKID(cell->value), cell->value->_type_unique_index);
                }
            } else if(cell->value && cell->value->meta_type == AMT_TYPEREF) {
                /* Named type reference - defined elsewhere, always extern */
                OUT("extern asn_TYPE_descriptor_t asn_DEF_%s;\n",
                    MKID(cell->value));
            }
        }
    }
    OUT("\n");

    /* Emit the Information Object Set */
    OUT("static const asn_ioc_cell_t asn_IOS_%s_%d_rows[] = {\n",
        MKID(ioc_tao.objset), ioc_tao.objset->_type_unique_index);
    INDENT(+1);

    for(size_t rn = 0; rn < ioc_tao.ioct->rows; rn++) {
        asn1p_ioc_row_t *row = ioc_tao.ioct->row[rn];
        columns = columns ? columns : row->columns;
        if(columns != row->columns) {
            FATAL("Information Object Set %s row column mismatch on line %d",
                  ioc_tao.objset->Identifier, ioc_tao.objset->_lineno);
            return -1;
        }
        for(size_t cn = 0; cn < row->columns; cn++) {
            if(rn || cn) OUT(",\n");
            emit_ioc_cell(arg, &row->column[cn]);
        }
    }
    OUT("\n");

    INDENT(-1);
    OUT("};\n");

    OUT("static const asn_ioc_set_t asn_IOS_%s_%d[] = {\n",
        MKID(ioc_tao.objset), ioc_tao.objset->_type_unique_index);
    INDENT(+1);
    OUT("{ %zu, %zu, asn_IOS_%s_%d_rows }\n", ioc_tao.ioct->rows, columns,
        MKID(ioc_tao.objset), ioc_tao.objset->_type_unique_index);
    INDENT(-1);
    OUT("};\n");

    return 0;
}
