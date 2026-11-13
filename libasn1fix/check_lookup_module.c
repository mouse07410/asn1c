/*
 * A name-only module lookup on a bare tree must not walk a missing
 * IMPORTS context.
 *
 * asn1f_lookup_module_ex() builds a zeroed arg_t and sets only arg.asn, so a
 * lookup by name has arg.mod == NULL. The oid == 0 path used to walk
 * arg->mod->imports and dereference it: the public helper crashed instead of
 * returning the module.
 *
 * Invariant: a name-only lookup returns the matching module or NULL and never
 * dereferences a missing current module.
 */
#include <stdio.h>

#include "asn1parser.h"
#include "asn1fix_export.h"

static const char schema[] =
    "M DEFINITIONS ::= BEGIN\n"
    "T ::= INTEGER\n"
    "END\n"
    "N DEFINITIONS ::= BEGIN\n"
    "IMPORTS T FROM M;\n"
    "U ::= T\n"
    "END\n";

static int
check_lookup(asn1p_t *asn, const char *name, int want_module) {
    asn1p_module_t *mod = asn1f_lookup_module_ex(asn, name, NULL);
    int ok = want_module ? (mod != NULL) : (mod == NULL);

    if(!ok) {
        fprintf(stderr, "FAIL: lookup %s returned %s\n", name,
                mod ? "a module" : "NULL");
        return 1;
    }
    printf("PASS: lookup %s %s\n", name,
           want_module ? "returns the module" : "returns NULL");
    return 0;
}

int
main(void) {
    asn1p_t *asn;
    int failures = 0;

    asn = asn1p_parse_buffer(schema, -1, "check-lookup-module", 1,
                             A1P_NOFLAGS);
    if(asn == NULL) {
        fprintf(stderr, "FAIL: cannot parse the schema\n");
        return 1;
    }

    failures += check_lookup(asn, "M", 1);
    failures += check_lookup(asn, "NoSuchModule", 0);
    failures += check_lookup(asn, "N", 1);

    asn1p_delete(asn);
    return failures ? 1 : 0;
}
