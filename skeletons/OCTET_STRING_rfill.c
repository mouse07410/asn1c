/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <asn_random_fill.h>
#include <constraints.h>
#include <OCTET_STRING.h>

#define OCTET_STRING_RFILL_ATTEMPTS 128

/*
 * Select a character with a bias toward the permitted range boundaries.
 * Original source: asn1c OCTET STRING random-fill implementation.
 * Version/date: 1.2, 2026-10-21.
 * Inputs: lb and ub are inclusive character bounds.
 * Returns: a uniformly or boundary-biased value in [lb, ub].
 * Errors: None; lb must not exceed ub.
 * Responsible party: asn1c maintainers. History: documented for #582.
 * Example: OCTET_STRING__random_char(0, 255).
 */
static uint32_t
OCTET_STRING__random_char(unsigned long lb, unsigned long ub) {
    assert(lb <= ub);
    switch(asn_random_between(0, 16)) {
    case 0:
        if(lb < ub) return lb + 1;
        /* Fall through */
    case 1:
        return lb;
    case 2:
        if(lb < ub) return ub - 1;
        /* Fall through */
    case 3:
        return ub;
    default:
        return asn_random_between(lb, ub);
    }
}

/*
 * Select one character accepted by the applicable PER alphabet map.
 * Original source: issue #582 bounded random-fill regression fix.
 * Version/date: 1.1, 2026-11-01.
 * Inputs: map callbacks and bits describe an optional PER map; lb/ub are the
 *         allowed character bounds; unit_bytes selects string storage width;
 *         output receives the selected character.
 * Returns: zero on success or -1 when no valid character is found.
 * Errors: A sparse or malformed map is bounded to 128 attempts.
 * Responsible party: asn1c maintainers. History: added for #582; exclude
 * surrogate code points from wide strings for JER, 2026-11-01.
 * Example: select a character from the NumericString PER alphabet.
 */
static int
OCTET_STRING__random_valid_char(int (*value2code)(unsigned int),
                                int (*code2value)(unsigned int), int bits,
                                unsigned long lb, unsigned long ub,
                                unsigned int unit_bytes,
                                uint32_t *output) {
    int attempt;

    if(!output || lb > ub || (unit_bytes != 1 && unit_bytes != 2
                              && unit_bytes != 4)) return -1;

    /* Generated standard alphabet maps contain at most 256 code ordinals. */
    if(value2code && code2value && bits >= 0 && bits <= 8) {
        unsigned int max_code = bits == 0 ? 0U : (1U << bits) - 1U;

        for(attempt = 0; attempt < OCTET_STRING_RFILL_ATTEMPTS; attempt++) {
            unsigned int code = (unsigned int)asn_random_between(0, max_code);
            int mapped = code2value(code);

            if(mapped < 0 || (unsigned long)mapped < lb
               || (unsigned long)mapped > ub)
                continue;
            if(unit_bytes > 1 && mapped >= 0xd800 && mapped <= 0xdfff)
                continue;
            if(value2code((unsigned int)mapped) != (int)code) continue;
            *output = (uint32_t)mapped;
            return 0;
        }
        return -1;
    }

    /* Rejection-sample non-ordinal maps without accepting an unmapped value. */
    for(attempt = 0; attempt < OCTET_STRING_RFILL_ATTEMPTS; attempt++) {
        uint32_t value = OCTET_STRING__random_char(lb, ub);

        if(unit_bytes > 1 && value >= 0xd800 && value <= 0xdfff)
            continue;
        if(value2code && value2code(value) < 0) continue;
        *output = value;
        return 0;
    }

    return -1;
}

/*
 * Store one Unicode code point in the OCTET STRING's selected byte order.
 * Original source: issue #582 bounded random-fill regression fix.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: target points to one unit; unit_bytes is 1, 2, or 4; value is a
 *         nonnegative code point already checked against its range.
 * Returns: no value.
 * Errors: None; callers provide a valid target and unit size.
 * Responsible party: asn1c maintainers. History: added for #582.
 * Example: store the code point U+0041 in a two-byte string unit.
 */
static void
OCTET_STRING__store_char(uint8_t *target, unsigned int unit_bytes,
                         uint32_t value) {
    switch(unit_bytes) {
    case 1:
        target[0] = (uint8_t)value;
        break;
    case 2:
        target[0] = (uint8_t)(value >> 8);
        target[1] = (uint8_t)value;
        break;
    case 4:
        target[0] = (uint8_t)(value >> 24);
        target[1] = (uint8_t)(value >> 16);
        target[2] = (uint8_t)(value >> 8);
        target[3] = (uint8_t)value;
        break;
    }
}

/*
 * Fill a temporary string with characters valid in the PER alphabet map.
 * Original source: issue #582 bounded random-fill regression fix.
 * Version/date: 1.1, 2026-11-01.
 * Inputs: buf has room for length units plus a terminator; unit_bytes is 1,
 *         2, or 4; remaining arguments describe the map and codepoint range.
 * Returns: zero when every character is valid; -1 after a bounded map miss.
 * Errors: None; the caller owns buf and frees it on any failure.
 * Responsible party: asn1c maintainers. History: added for #582; wide-string
 * scalar validation added for randomized JER round trips, 2026-11-01.
 * Example: fill a temporary NumericString candidate before validation.
 */
static int
OCTET_STRING__fill_candidate(uint8_t *buf, size_t length,
                             unsigned int unit_bytes,
                             int (*value2code)(unsigned int),
                             int (*code2value)(unsigned int), int bits,
                             unsigned long lb, unsigned long ub) {
    size_t index;

    for(index = 0; index < length; index++) {
        uint32_t value;
        if(OCTET_STRING__random_valid_char(value2code, code2value, bits, lb,
                                           ub, unit_bytes, &value))
            return -1;
        OCTET_STRING__store_char(buf + index * unit_bytes, unit_bytes, value);
    }

    memset(buf + length * unit_bytes, 0, unit_bytes);
    return 0;
}

/*
 * Check a candidate with one descriptor's general constraint callback.
 * Original source: issue #582 bounded random-fill regression fix.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: td describes the candidate; callback is the constraint to run;
 *         value is the candidate and syntax is the selected encoding syntax.
 * Returns: one when accepted or absent, zero when rejected.
 * Errors: Constraint failure rejects the candidate without changing storage.
 * Responsible party: asn1c maintainers. History: added for #582.
 * Example: check a generated string against PrintableString constraints.
 */
static int
OCTET_STRING__constraint_accepts(const asn_TYPE_descriptor_t *td,
                                 asn_constr_check_f *callback,
                                 const OCTET_STRING_t *value, int syntax) {
    asn_TYPE_descriptor_t callback_td;

    if(!callback) return 1;
    if(callback == td->encoding_constraints.general_constraints) {
        return asn_check_constraints_with_syntax(td, value, syntax, NULL,
                                                NULL) == 0;
    }

    /* A local descriptor copy applies a member override without mutating td. */
    callback_td = *td;
    callback_td.encoding_constraints.general_constraints = callback;
    return asn_check_constraints_with_syntax(&callback_td, value, syntax, NULL,
                                            NULL) == 0;
}

/*
 * Apply both the type's own and any distinct member-level constraints.
 * Original source: issue #582 bounded random-fill regression fix.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: td and member_constraints identify callbacks; value is the candidate.
 * Returns: one if accepted by every applicable callback, otherwise zero.
 * Errors: A failed callback rejects the candidate; no exception is thrown.
 * Responsible party: asn1c maintainers. History: added for #582.
 * Example: validate NumericString plus a stricter member constraint.
 */
static int
OCTET_STRING__candidate_valid(
    const asn_TYPE_descriptor_t *td,
    const asn_encoding_constraints_t *member_constraints,
    const OCTET_STRING_t *value) {
    asn_constr_check_f *type_check =
        td->encoding_constraints.general_constraints;
    asn_constr_check_f *member_check =
        member_constraints ? member_constraints->general_constraints : NULL;
    int syntax = asn_random_fill_current_syntax();

    if(!OCTET_STRING__constraint_accepts(td, type_check, value, syntax))
        return 0;
    if(member_check && member_check != type_check
       && !OCTET_STRING__constraint_accepts(td, member_check, value, syntax))
        return 0;
    return 1;
}

/*
 * Install an already validated temporary value, preserving old storage until
 * the replacement structure can be allocated.
 * Original source: issue #582 bounded random-fill regression fix.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: specs describes structure size; sptr owns the prior value; buf and
 *         size describe the validated replacement value.
 * Returns: zero on success or -1 if a new structure cannot be allocated.
 * Errors: Allocation failure leaves *sptr and its buffer unchanged.
 * Responsible party: asn1c maintainers. History: added for #582.
 * Example: install a validated buffer after randomized candidate checks.
 */
static int
OCTET_STRING__install_candidate(const asn_OCTET_STRING_specifics_t *specs,
                                void **sptr, uint8_t *buf, size_t size) {
    OCTET_STRING_t *st;

    if(*sptr) {
        st = (OCTET_STRING_t *)*sptr;
    } else {
        st = (OCTET_STRING_t *)CALLOC(1, specs->struct_size);
        if(!st) return -1;
        *sptr = st;
    }

    FREEMEM(st->buf);
    st->buf = buf;
    st->size = size;
    return 0;
}

/*
 * Select and validate PER character and size metadata when available.
 * Original source: asn1c OCTET STRING random-fill implementation, hardened
 * for issue #582's alphabet-map validation.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: td provides fallback metadata; constraints selects overrides;
 *         unit_max bounds storage; remaining pointers receive PER settings.
 * Returns: zero for usable metadata or -1 for invalid bounds.
 * Errors: Negative, inverted, or unrepresentable constraints are rejected.
 * Responsible party: asn1c maintainers. History: extracted for #582.
 * Example: validate a PER alphabet before sampling characters.
 */
static int
OCTET_STRING__configure_per_constraints(
    const asn_TYPE_descriptor_t *td,
    const asn_encoding_constraints_t **constraints, unsigned long unit_max,
    unsigned long *clb, unsigned long *cub,
    int (**value2code)(unsigned int), int (**code2value)(unsigned int),
    int *value_bits) {
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
    if(!*constraints || !(*constraints)->per_constraints)
        *constraints = &td->encoding_constraints;
    if((*constraints)->per_constraints) {
        const asn_per_constraints_t *pc = (*constraints)->per_constraints;

        if(pc->value.flags & APC_CONSTRAINED) {
            if(pc->value.lower_bound < 0
               || pc->value.upper_bound < pc->value.lower_bound
               || (uintmax_t)pc->value.upper_bound > unit_max)
                return -1;
            *clb = (unsigned long)pc->value.lower_bound;
            *cub = (unsigned long)pc->value.upper_bound;
        } else if(pc->value.flags & APC_SEMI_CONSTRAINED) {
            if(pc->value.lower_bound < 0
               || (uintmax_t)pc->value.lower_bound > unit_max)
                return -1;
            *clb = (unsigned long)pc->value.lower_bound;
        }

        *value2code = pc->value2code;
        *code2value = pc->code2value;
        *value_bits = pc->value.effective_bits;
        if((pc->size.flags & APC_CONSTRAINED)
           && (pc->size.lower_bound < 0
               || pc->size.upper_bound < pc->size.lower_bound))
            return -1;
        if((pc->size.flags & APC_SEMI_CONSTRAINED)
           && pc->size.lower_bound < 0)
            return -1;
    }
#else
    if(!*constraints) *constraints = &td->encoding_constraints;
    (void)unit_max;
    (void)clb;
    (void)cub;
    (void)value2code;
    (void)code2value;
    (void)value_bits;
#endif

    return 0;
}

/*
 * Configure the unit size, character range, PER map, and length constraints.
 * Original source: asn1c OCTET STRING random-fill implementation, hardened
 * for issue #582 alphabet-map validation.
 * Version/date: 1.1, 2026-11-01.
 * Inputs: td and constraints select metadata; output pointers receive the
 *         active PER constraints and validated character-generation settings.
 * Returns: zero for usable metadata or -1 for malformed ranges.
 * Errors: Invalid bounds are rejected before any allocation or random range.
 * Responsible party: asn1c maintainers. History: added for #582; cap UCS-4
 * samples to Unicode scalar range for JER, 2026-11-01.
 * Example: configure NumericString's map and one-byte storage range.
 */
static int
OCTET_STRING__configure_random_fill(
    const asn_TYPE_descriptor_t *td,
    const asn_encoding_constraints_t **constraints,
    const asn_OCTET_STRING_specifics_t *specs, unsigned int *unit_bytes,
    unsigned long *clb, unsigned long *cub,
    int (**value2code)(unsigned int), int (**code2value)(unsigned int),
    int *value_bits) {
    unsigned long unit_max;

    switch(specs->subvariant) {
    case ASN_OSUBV_STR:
        *unit_bytes = 1;
        unit_max = 255;
        break;
    case ASN_OSUBV_U16:
        *unit_bytes = 2;
        unit_max = 65535;
        *cub = 65535;
        break;
    case ASN_OSUBV_U32:
        *unit_bytes = 4;
        unit_max = UINT32_MAX;
        *cub = 0x10FFFF;
        break;
    case ASN_OSUBV_ANY:
    case ASN_OSUBV_BIT:
    default:
        return -1;
    }

    if(OCTET_STRING__configure_per_constraints(
           td, constraints, unit_max, clb, cub, value2code, code2value,
           value_bits))
        return -1;

    /* UCS-4 PER metadata permits values above Unicode's scalar ceiling. */
    if(specs->subvariant == ASN_OSUBV_U32 && *cub > 0x10ffff)
        *cub = 0x10ffff;

    return *clb <= *cub && *cub <= unit_max ? 0 : -1;
}

/*
 * Select a length from a validated constrained PER size range.
 * Original source: asn1c OCTET STRING random-fill implementation.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: pc is a constrained size descriptor; max_length is the approximate
 *         caller budget; preferred is the initial table-selected length.
 * Returns: a root or extension length; malformed range metadata yields zero.
 * Errors: None; callers validate the resulting allocation size.
 * Responsible party: asn1c maintainers. History: extracted for #582 checks.
 * Example: select an extensible SIZE length before allocating a candidate.
 */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
static size_t
OCTET_STRING__random_constrained_length(const asn_per_constraint_t *pc,
                                       size_t max_length, size_t preferred) {
    ssize_t upper;
    size_t selected = preferred;

    if(pc->lower_bound < 0 || pc->upper_bound < pc->lower_bound) return 0;
    if(max_length <= (size_t)pc->lower_bound) return (size_t)pc->lower_bound;
    upper = pc->upper_bound < (ssize_t)max_length
                ? (ssize_t)pc->upper_bound
                : (ssize_t)max_length;

    if(pc->flags & APC_EXTENSIBLE) {
        switch(asn_random_between(0, 5)) {
        case 0:
            if(pc->lower_bound > 0) {
                selected = (size_t)pc->lower_bound - 1;
                break;
            }
            /* Fall through */
        case 1:
            if(pc->upper_bound < (ssize_t)max_length) {
                selected = (size_t)pc->upper_bound + 1;
                break;
            }
            /* Fall through */
        case 2:
            if(selected <= max_length) break;
            /* Fall through */
        default:
            selected = (size_t)asn_random_between(pc->lower_bound, upper);
        }
    } else {
        selected = (size_t)asn_random_between(pc->lower_bound, upper);
    }

    return selected;
}
#endif

/*
 * Create a random string satisfying PER alphabet and general constraints.
 * Original source: asn1c OCTET STRING random-fill implementation, hardened
 * for issue #582 alphabet-map and abstract-constraint validation.
 * Version/date: 1.2, 2026-10-21.
 * Inputs: td describes the string; sptr receives/reuses its value;
 *         constraints supplies member overrides; max_length is an approximate
 *         generation budget in string units, with bytes checked separately.
 * Returns: ARFILL_OK for a valid value, ARFILL_SKIPPED for an empty new value,
 *          or ARFILL_FAILED if input, allocation, or bounded validation fails.
 * Errors: Failure preserves *sptr and its previous buffer.
 * Responsible party: asn1c maintainers. History: hardened for #582.
 * Example: called by asn_random_fill with asn_DEF_NumericString.
 */
asn_random_fill_result_t
OCTET_STRING_random_fill(const asn_TYPE_descriptor_t *td, void **sptr,
                         const asn_encoding_constraints_t *constraints,
                         size_t max_length) {
    const asn_OCTET_STRING_specifics_t *specs;
    const asn_encoding_constraints_t *per_constraints = constraints;
    asn_random_fill_result_t result_ok = {ARFILL_OK, 1};
    asn_random_fill_result_t result_failed = {ARFILL_FAILED, 0};
    asn_random_fill_result_t result_skipped = {ARFILL_SKIPPED, 0};
    unsigned int unit_bytes = 1;
    unsigned long clb = 0;
    unsigned long cub = 255;
    int (*value2code)(unsigned int) = NULL;
    int (*code2value)(unsigned int) = NULL;
    int value_bits = -1;
    uint8_t *buf;
    size_t rnd_len;
    size_t value_size;
    OCTET_STRING_t candidate;
    int attempt;

    if(!td || !sptr || max_length > (size_t)RSSIZE_MAX) return result_failed;
    specs = td->specifics ? (const asn_OCTET_STRING_specifics_t *)td->specifics
                          : &asn_SPC_OCTET_STRING_specs;
    if(specs->struct_size < sizeof(OCTET_STRING_t)) return result_failed;
    if(max_length == 0 && !*sptr) return result_skipped;
    if(OCTET_STRING__configure_random_fill(
           td, &per_constraints, specs, &unit_bytes, &clb, &cub,
           &value2code, &code2value, &value_bits))
        return result_failed;

    rnd_len = OCTET_STRING_random_length_constrained(td, per_constraints,
                                                      max_length);
    if(rnd_len > (size_t)RSSIZE_MAX / unit_bytes
       || rnd_len >= SIZE_MAX / unit_bytes)
        return result_failed;
    value_size = rnd_len * unit_bytes;
    buf = (uint8_t *)CALLOC(unit_bytes, rnd_len + 1);
    if(!buf) return result_failed;

    memset(&candidate, 0, sizeof(candidate));
    candidate.buf = buf;
    candidate.size = value_size;
    for(attempt = 0; attempt < OCTET_STRING_RFILL_ATTEMPTS; attempt++) {
        if(OCTET_STRING__fill_candidate(buf, rnd_len, unit_bytes, value2code,
                                        code2value, value_bits, clb, cub))
            continue;
        if(OCTET_STRING__candidate_valid(td, constraints, &candidate)) break;
    }
    if(attempt == OCTET_STRING_RFILL_ATTEMPTS) {
        FREEMEM(buf);
        return result_failed;
    }

    if(OCTET_STRING__install_candidate(specs, sptr, buf, value_size)) {
        FREEMEM(buf);
        return result_failed;
    }
    result_ok.length = value_size;
    return result_ok;
}

/*
 * Choose a random length compatible with available PER size constraints.
 * Original source: asn1c OCTET STRING random-fill implementation.
 * Version/date: 1.2, 2026-10-21.
 * Inputs: td supplies fallback constraints; constraints overrides them when
 *         it has PER metadata; max_length is an approximate string-unit hint.
 * Returns: a selected unit count, which may exceed the hint to satisfy a
 *          required lower bound; invalid metadata yields zero.
 * Errors: None; callers validate the result before allocation.
 * Responsible party: asn1c maintainers. History: retained for #582.
 * Example: choose a random length for an unconstrained OCTET STRING.
 */
size_t
OCTET_STRING_random_length_constrained(
    const asn_TYPE_descriptor_t *td,
    const asn_encoding_constraints_t *constraints, size_t max_length) {
    const unsigned lengths[] = {0,     1,     2,     3,     4,     8,
                                126,   127,   128,   16383, 16384, 16385,
                                65534, 65535, 65536, 65537};
    size_t rnd_len;

    if(!td || max_length > (size_t)RSSIZE_MAX) return 0;
    rnd_len = lengths[asn_random_between(
        0, sizeof(lengths) / sizeof(lengths[0]) - 1)];

#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
    if(!constraints || !constraints->per_constraints)
        constraints = &td->encoding_constraints;
    if(constraints->per_constraints) {
        const asn_per_constraint_t *pc = &constraints->per_constraints->size;
        if(pc->flags & APC_CONSTRAINED)
            return OCTET_STRING__random_constrained_length(
                pc, max_length, rnd_len);
        if(pc->flags & APC_SEMI_CONSTRAINED) {
            if(pc->lower_bound < 0) return 0;
            if(max_length <= (size_t)pc->lower_bound)
                return (size_t)pc->lower_bound;
            return (size_t)asn_random_between(pc->lower_bound,
                                              (ssize_t)max_length);
        }
        return (size_t)asn_random_between(0, max_length);
    }
#else
    if(!constraints) constraints = &td->encoding_constraints;
#endif
    if(rnd_len > max_length)
        rnd_len = (size_t)asn_random_between(0, max_length);

    return rnd_len;
}
