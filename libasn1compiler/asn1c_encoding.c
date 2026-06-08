/*
 * Encoding control processing for asn1c compiler.
 */
#include "asn1c_internal.h"
#include "asn1c_encoding.h"
#include <asn1fix_export.h>
#include <asn1_namespace.h>

static asn1p_expr_t *
find_module_type(asn1p_module_t *mod, const char *name) {
    asn1p_expr_t *expr;

    if(!mod || !name) return NULL;
    TQ_FOR(expr, &(mod->members), next) {
        if((expr->_mark & TM_ENCODING_INSTRUCTION) == 0
        && expr->Identifier && strcmp(expr->Identifier, name) == 0) {
            return expr;
        }
    }
    return NULL;
}

static asn1p_expr_t *
find_member(asn1p_expr_t *parent, const char *name) {
    asn1p_expr_t *memb;

    if(!parent || !name) return NULL;
    TQ_FOR(memb, &(parent->members), next) {
        if(memb->Identifier && strcmp(memb->Identifier, name) == 0)
            return memb;
    }
    return NULL;
}

static char *
split_first(const char *path, char **rest) {
    const char *dot = path ? strchr(path, '.') : NULL;
    char *head;

    *rest = NULL;
    if(!path) return NULL;
    if(!dot) return strdup(path);
    head = malloc((size_t)(dot - path) + 1);
    if(!head) return NULL;
    memcpy(head, path, (size_t)(dot - path));
    head[dot - path] = '\0';
    *rest = strdup(dot + 1);
    if(!*rest) {
        free(head);
        return NULL;
    }
    return head;
}

static asn1p_expr_type_e
terminal_type(asn1p_t *asn, asn1p_expr_t *expr) {
    asn1p_expr_type_e etype = expr ? expr->expr_type : A1TC_INVALID;

    if(expr && etype == A1TC_REFERENCE && expr->reference) {
        asn1p_expr_t *resolved = WITH_MODULE_NAMESPACE(
            expr->module, expr_ns,
            asn1f_find_terminal_type_ex(asn, expr_ns, expr));
        if(resolved) etype = resolved->expr_type;
    }
    return etype;
}

static int
is_xer_text_type(asn1p_expr_t *expr) {
    if(!expr) return 0;
    switch(expr->expr_type) {
    case ASN_BASIC_BOOLEAN:
    case ASN_BASIC_ENUMERATED:
        return 1;
    case ASN_BASIC_INTEGER:
    case ASN_BASIC_BIT_STRING:
        return TQ_FIRST(&expr->members) != NULL;
    default:
        return 0;
    }
}

static void
copy_control(asn1p_expr_t *dst, const asn1p_expr_t *src) {
    dst->encoding_control.encoding_type = src->encoding_control.encoding_type;
    free(dst->encoding_control.encoding_reference);
    free(dst->encoding_control.target_path);
    free(dst->encoding_control.target_value);
    free(dst->encoding_control.replacement);
    dst->encoding_control.encoding_reference =
        src->encoding_control.encoding_reference
            ? strdup(src->encoding_control.encoding_reference) : NULL;
    dst->encoding_control.target_path =
        src->encoding_control.target_path
            ? strdup(src->encoding_control.target_path) : NULL;
    dst->encoding_control.target_value =
        src->encoding_control.target_value
            ? strdup(src->encoding_control.target_value) : NULL;
    dst->encoding_control.replacement =
        src->encoding_control.replacement
            ? strdup(src->encoding_control.replacement) : NULL;
}

static int
validate_no_duplicate_jer_names(asn1p_module_t *mod) {
    asn1p_expr_t *type;

    TQ_FOR(type, &(mod->members), next) {
        asn1p_expr_t *a;
        if(type->_mark & TM_ENCODING_INSTRUCTION) continue;
        if(type->expr_type != ASN_CONSTR_SEQUENCE
        && type->expr_type != ASN_CONSTR_SET
        && type->expr_type != ASN_CONSTR_CHOICE) continue;

        TQ_FOR(a, &(type->members), next) {
            asn1p_expr_t *b;
            const char *an = a->encoding_control.encoding_type == EC_JER_NAME
                && a->encoding_control.replacement
                ? a->encoding_control.replacement : a->Identifier;
            if(!an) continue;
            for(b = TQ_NEXT(a, next); b; b = TQ_NEXT(b, next)) {
                const char *bn = b->encoding_control.encoding_type == EC_JER_NAME
                    && b->encoding_control.replacement
                    ? b->encoding_control.replacement : b->Identifier;
                if(bn && strcmp(an, bn) == 0) {
                    fprintf(stderr,
                        "ERROR: duplicate JER NAME '%s' in %s at line %d\n",
                        an, type->Identifier ? type->Identifier : "<anonymous>",
                        b->_lineno);
                    return -1;
                }
            }
        }
    }
    return 0;
}

static int
target_is_all(const char *head, const char *rest) {
    return head && strcmp(head, "ALL") == 0 && rest == NULL;
}

static int
encoding_control_applies_to_all_octets(
        enum asn1p_encoding_control_type_e itype) {
    switch(itype) {
    case EC_XER_BASE64:
    case EC_JER_BASE64:
        return 1;
    default:
        return 0;
    }
}

static int
apply_to_octet_strings(asn1p_t *asn, asn1p_expr_t *expr,
                       const asn1p_expr_t *instr,
                       enum asn1p_encoding_control_type_e itype) {
    asn1p_expr_t *memb;
    int applied = 0;

    if(!expr || (expr->_mark & TM_ENCODING_INSTRUCTION))
        return 0;

    /*
     * References inherit their target descriptor.  Applying ALL to the
     * reference itself would create redundant generated member descriptors.
     */
    if(expr->expr_type != A1TC_REFERENCE
    && expr->encoding_control.encoding_type == EC_NONE
    && terminal_type(asn, expr) == ASN_BASIC_OCTET_STRING) {
        copy_control(expr, instr);
        expr->encoding_control.encoding_type = itype;
        applied++;
    }

    TQ_FOR(memb, &(expr->members), next) {
        applied += apply_to_octet_strings(asn, memb, instr, itype);
    }

    return applied;
}

int
asn1c_apply_encoding_controls(asn1p_t *asn, asn1p_module_t *mod) {
    asn1p_expr_t *instr;
    int applied = 0;
    int global_modified = 0;

    if(!asn || !mod) return -1;

    TQ_FOR(instr, &(mod->members), next) {
        if((instr->_mark & TM_ENCODING_INSTRUCTION) == 0) continue;
        if(instr->encoding_control.encoding_type
           == EC_XER_GLOBAL_DEFAULTS_MODIFIED_ENCODINGS) {
            global_modified = 1;
        }
    }

    TQ_FOR(instr, &(mod->members), next) {
        enum asn1p_encoding_control_type_e itype;
        const char *eref;
        char *rest = NULL;
        char *head = NULL;
        asn1p_expr_t *target = NULL;

        if((instr->_mark & TM_ENCODING_INSTRUCTION) == 0) continue;
        itype = instr->encoding_control.encoding_type;
        if(itype == EC_NONE
        || itype == EC_XER_GLOBAL_DEFAULTS_MODIFIED_ENCODINGS) continue;

        eref = instr->encoding_control.encoding_reference;
        if(eref && strcmp(eref, "JER") == 0) {
            if(itype == EC_XER_BASE64) itype = EC_JER_BASE64;
            else if(itype == EC_XER_TEXT) itype = EC_JER_TEXT;
        }

        head = split_first(instr->encoding_control.target_path
                           ? instr->encoding_control.target_path
                           : instr->Identifier, &rest);
        if(!head) return -1;

        instr->encoding_control.encoding_type = itype;

        if(target_is_all(head, rest)
        && encoding_control_applies_to_all_octets(itype)) {
            asn1p_expr_t *type;
            TQ_FOR(type, &(mod->members), next) {
                applied += apply_to_octet_strings(asn, type, instr, itype);
            }
            free(head);
            free(rest);
            continue;
        }

        target = find_module_type(mod, head);
        if(!target) {
            fprintf(stderr,
                "ERROR: encoding control target '%s' not found at line %d\n",
                head, instr->_lineno);
            free(head);
            free(rest);
            return -1;
        }

        if(itype == EC_JER_NAME) {
            asn1p_expr_t *memb;
            if(!rest || !instr->encoding_control.replacement) {
                fprintf(stderr,
                    "ERROR: JER NAME requires component target and AS value at line %d\n",
                    instr->_lineno);
                free(head);
                free(rest);
                return -1;
            }
            if(target->expr_type != ASN_CONSTR_SEQUENCE
            && target->expr_type != ASN_CONSTR_SET
            && target->expr_type != ASN_CONSTR_CHOICE) {
                fprintf(stderr,
                    "ERROR: JER NAME target '%s' is not SEQUENCE, SET, or CHOICE\n",
                    head);
                free(head);
                free(rest);
                return -1;
            }
            memb = find_member(target, rest);
            if(!memb) {
                fprintf(stderr,
                    "ERROR: JER NAME member '%s.%s' not found\n",
                    head, rest);
                free(head);
                free(rest);
                return -1;
            }
            copy_control(memb, instr);
            applied++;
        } else if(itype == EC_JER_TEXT || (itype == EC_XER_TEXT && rest)) {
            asn1p_expr_t *value;
            if(!rest || !instr->encoding_control.replacement) {
                if(itype == EC_JER_TEXT) {
                    fprintf(stderr,
                        "ERROR: JER TEXT requires enumerated value target and AS value at line %d\n",
                        instr->_lineno);
                    free(head);
                    free(rest);
                    return -1;
                }
            } else {
                value = find_member(target, rest);
                if(!value || value->expr_type != A1TC_UNIVERVAL) {
                    fprintf(stderr,
                        "ERROR: TEXT target '%s.%s' is not a named value\n",
                        head, rest);
                    free(head);
                    free(rest);
                    return -1;
                }
                if((itype == EC_JER_TEXT
                    && target->expr_type != ASN_BASIC_ENUMERATED)
                || (itype == EC_XER_TEXT
                    && target->expr_type != ASN_BASIC_ENUMERATED
                    && target->expr_type != ASN_BASIC_INTEGER
                    && target->expr_type != ASN_BASIC_BIT_STRING)) {
                    fprintf(stderr,
                        "ERROR: TEXT target '%s' has incompatible type\n", head);
                    free(head);
                    free(rest);
                    return -1;
                }
                copy_control(value, instr);
                applied++;
            }
        } else {
            asn1p_expr_type_e ttype = terminal_type(asn, target);
            if(itype == EC_XER_DECIMAL) {
                if(!global_modified) {
                    fprintf(stderr,
                        "ERROR: XER DECIMAL for '%s' requires GLOBAL-DEFAULTS MODIFIED-ENCODINGS\n",
                        head);
                    free(head);
                    free(rest);
                    return -1;
                }
                if(ttype != ASN_BASIC_REAL) {
                    fprintf(stderr,
                        "ERROR: XER DECIMAL target '%s' is not REAL\n", head);
                    free(head);
                    free(rest);
                    return -1;
                }
            } else if(itype == EC_XER_TEXT) {
                if(!is_xer_text_type(target)) {
                    fprintf(stderr,
                        "ERROR: XER TEXT target '%s' has incompatible type\n",
                        head);
                    free(head);
                    free(rest);
                    return -1;
                }
            } else if(itype == EC_XER_BASE64 || itype == EC_XER_HEXADECIMAL
                   || itype == EC_XER_UTF8 || itype == EC_JER_BASE64) {
                if(ttype != ASN_BASIC_OCTET_STRING) {
                    fprintf(stderr,
                        "ERROR: %s BASE64/UTF8/HEXADECIMAL target '%s' is not OCTET STRING\n",
                        eref ? eref : "XER", head);
                    free(head);
                    free(rest);
                    return -1;
                }
            }
            copy_control(target, instr);
            target->encoding_control.encoding_type = itype;
            applied++;
        }

        free(head);
        free(rest);
    }

    if(validate_no_duplicate_jer_names(mod) < 0)
        return -1;

    if(applied > 0) {
        fprintf(stderr,
            "NOTE: Applied %d encoding control directive(s) in module %s\n",
            applied, mod->ModuleName);
    }

    return applied;
}
