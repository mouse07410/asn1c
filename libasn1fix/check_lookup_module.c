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
#include <string.h>

#include "asn1parser.h"
#include "asn1fix_export.h"

static const char schema[] =
    "M { iso standard 8571 } DEFINITIONS ::= BEGIN\n"
    "T ::= INTEGER\n"
    "END\n"
    "N DEFINITIONS ::= BEGIN\n"
    "IMPORTS T FROM M;\n"
    "U ::= T\n"
    "END\n";

/*
 * Purpose: check a bare-tree module lookup and verify the returned identity.
 * Original source: PR #600 regression test for asn1c.
 * Version/date: 1.1, 2026-11-13.
 * Inputs: asn is the parsed tree; name is the lookup key; want_module says
 * whether the name should be present. Returns: zero on success, one on error.
 * Exceptions: none. Responsible party: asn1c maintainers.
 * History: strengthened to verify identity. Example: check_lookup(asn, "M", 1).
 */
static int
check_lookup(asn1p_t *asn, const char *name, int want_module) {
    asn1p_module_t *mod = asn1f_lookup_module_ex(asn, name, NULL);
    int ok = want_module ? (mod && mod->ModuleName
                            && strcmp(mod->ModuleName, name) == 0)
                         : (mod == NULL);

    if(!ok) {
        fprintf(stderr, "FAIL: lookup %s returned %s\n", name,
                mod && mod->ModuleName ? mod->ModuleName : "NULL");
        return 1;
    }
    printf("PASS: lookup %s %s\n", name,
           want_module ? "returns the module" : "returns NULL");
    return 0;
}

/*
 * Purpose: exercise name and OID lookup without a current module.
 * Original source: PR #600 regression test for asn1c.
 * Version/date: 1.1, 2026-11-13. Inputs: none.
 * Returns: zero on success, one on parse or lookup failure. Exceptions: none.
 * Responsible party: asn1c maintainers. History: added OID identity coverage.
 * Example: run check_lookup_module through the libasn1fix test suite.
 */
int
main(void) {
    asn1p_t *asn; /* state variable: parsed test schema. */
    asn1p_module_t *module; /* state variable: module selected by name. */
    int failures = 0; /* state variable: number of failed checks. */

    /* A parsed tree gives both the name and OID paths a realistic input. */
    asn = asn1p_parse_buffer(schema, -1, "check-lookup-module", 1,
                             A1P_NOFLAGS);
    if(asn == NULL) {
        fprintf(stderr, "FAIL: cannot parse the schema\n");
        return 1;
    }

    /* Check both module identities and a missing name. */
    failures += check_lookup(asn, "M", 1);
    failures += check_lookup(asn, "NoSuchModule", 0);
    failures += check_lookup(asn, "N", 1);

    /* An OID lookup must return M even when its supplied name differs. */
    module = asn1f_lookup_module_ex(asn, "M", NULL);
    if(!module || !module->module_oid
    || asn1f_lookup_module_ex(asn, "N", module->module_oid) != module) {
        fprintf(stderr, "FAIL: OID lookup did not return M\n");
        failures++;
    }

    asn1p_delete(asn);
    return failures ? 1 : 0;
}
