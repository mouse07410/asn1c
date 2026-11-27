/*
 * Tag fetching must report through the caller's diagnostic channel.
 *
 * asn1f_fetch_tags() and asn1f_fetch_outmost_tag() build a zeroed temporary
 * fixer context, so the DEBUG trace emitted while resolving a tag chain and
 * the tagging-mode WARNING/FATAL at asn1fix_tags.c are dropped. The _ex
 * variants accept the caller's legacy logger and debug flag.
 *
 * Invariant: every diagnostic raised while fetching tags reaches the channel
 * passed to the _ex entry point, and only then; the old entry points stay
 * silent. The fetched tag values do not depend on the channel.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "asn1parser.h"
#include "asn1fix.h"
#include "asn1fix_export.h"
#include "asn1_namespace.h"
#include "asn1fix_internal.h"

#define MAX_RECS 16
#define MAX_MSG  512

typedef struct {
    int count;
    int fatal[MAX_RECS];
    char msg[MAX_RECS][MAX_MSG];
} records_t;

static records_t *g_records;

static void
record_diag(int is_fatal, const char *fmt, ...) {
    va_list ap;
    int i;

    if(g_records == NULL || g_records->count >= MAX_RECS) return;
    i = g_records->count++;
    g_records->fatal[i] = is_fatal;
    va_start(ap, fmt);
    vsnprintf(g_records->msg[i], MAX_MSG, fmt, ap);
    va_end(ap);
}

static void
records_reset(records_t *r) {
    memset(r, 0, sizeof(*r));
    g_records = r;
}

/* Index of the first record containing needle, or -1. */
static int
records_find(const records_t *r, const char *needle) {
    int i;

    for(i = 0; i < r->count; i++) {
        if(strstr(r->msg[i], needle) != NULL) return i;
    }
    return -1;
}

static int
check(int ok, const char *what) {
    if(ok) {
        printf("PASS: %s\n", what);
        return 0;
    }
    fprintf(stderr, "FAIL: %s\n", what);
    return 1;
}

static asn1p_t *
parse_one(const char *definition) {
    char buf[512];

    snprintf(buf, sizeof(buf), "M DEFINITIONS ::= BEGIN\n%s\nEND\n",
             definition);
    return asn1p_parse_buffer(buf, -1, "check-tags", 1, A1P_NOFLAGS);
}

static void
dump_records(const records_t *r) {
    int i;

    for(i = 0; i < r->count; i++)
        fprintf(stderr, "  record %d (fatal %d): %s\n", i, r->fatal[i],
                r->msg[i]);
}

/*
 * Purpose: verify external, CHOICE, and successful outmost-tag contracts.
 * Source: Public tag-fetch API behavior and the known-external extension.
 * Version/date: 2026-11-26.
 * Inputs: none; KnownExt is registered by main before this helper is called.
 * Returns: number of failed assertions.
 * Errors: parser setup failure returns one; API failures are reported by check.
 * Author: asn1c maintainers.
 * History: Added regression coverage for ASN1F_TAG_EXTERNAL.
 * Example: an untagged KnownExt returns an external sentinel without writing.
 */
static int
check_external_fetch_contract(void) {
    records_t rec;
    asn1p_t *asn;
    asn1p_module_t *mod;
    asn1p_expr_t *expr;
    asn1_namespace_t *ns;
    struct asn1p_type_tag_s *tags;
    struct asn1p_type_tag_s tag;
    int count;
    int failures = 0;

    /* Known external tags return empty success through both array APIs. */
    asn = parse_one("T ::= KnownExt");
    if(asn == NULL) return 1;
    mod = TQ_FIRST(&asn->modules);
    expr = TQ_FIRST(&mod->members);
    ns = asn1_namespace_new_from_module(mod, 0);
    tags = (struct asn1p_type_tag_s *)1;
    records_reset(&rec);
    count = asn1f_fetch_tags_ex(asn, ns, mod, expr, &tags, 0, record_diag, 0);
    failures += check(count == 0 && tags == NULL,
                      "external _ex tag fetch returns empty success");
    failures += check(rec.count == 0,
                      "external _ex tag fetch emits no diagnostic");
    if(tags != (struct asn1p_type_tag_s *)1) free(tags);

    tags = (struct asn1p_type_tag_s *)1;
    count = asn1f_fetch_tags(asn, ns, mod, expr, &tags, 0);
    failures += check(count == 0 && tags == NULL,
                      "external legacy tag fetch returns empty success");
    if(tags != (struct asn1p_type_tag_s *)1) free(tags);

    /* Both outmost APIs return the sentinel without touching the output. */
    memset(&tag, 0, sizeof(tag));
    tag.tag_class = TC_PRIVATE;
    tag.tag_value = 123;
    tag.tag_mode = TM_EXPLICIT;
    count = asn1f_fetch_outmost_tag_ex(asn, ns, mod, expr, &tag, 0,
                                       record_diag, 0);
    failures += check(count == ASN1F_TAG_EXTERNAL && tag.tag_class == TC_PRIVATE
                      && tag.tag_value == 123 && tag.tag_mode == TM_EXPLICIT,
                      "external _ex outmost fetch returns sentinel unchanged");

    tag.tag_class = TC_PRIVATE;
    tag.tag_value = 123;
    tag.tag_mode = TM_EXPLICIT;
    count = asn1f_fetch_outmost_tag(asn, ns, mod, expr, &tag, 0);
    failures += check(count == ASN1F_TAG_EXTERNAL && tag.tag_class == TC_PRIVATE
                      && tag.tag_value == 123 && tag.tag_mode == TM_EXPLICIT,
                      "external legacy outmost fetch returns sentinel unchanged");
    asn1_namespace_free(ns);
    asn1p_delete(asn);

    /* Canonical CHOICE lookup propagates an unknown external branch. */
    asn = parse_one("T ::= CHOICE { ext KnownExt, value INTEGER }");
    if(asn == NULL) return 1;
    mod = TQ_FIRST(&asn->modules);
    expr = TQ_FIRST(&mod->members);
    ns = asn1_namespace_new_from_module(mod, 0);
    tag.tag_class = TC_PRIVATE;
    tag.tag_value = 123;
    tag.tag_mode = TM_EXPLICIT;
    count = asn1f_fetch_outmost_tag_ex(asn, ns, mod, expr, &tag,
                                       AFT_CANON_CHOICE, record_diag, 0);
    failures += check(count == ASN1F_TAG_EXTERNAL && tag.tag_class == TC_PRIVATE
                      && tag.tag_value == 123 && tag.tag_mode == TM_EXPLICIT,
                      "canonical CHOICE propagates external tag sentinel");
    asn1_namespace_free(ns);
    asn1p_delete(asn);

    /* Ordinary untagged CHOICE still fails and leaves the output untouched. */
    asn = parse_one("T ::= CHOICE { a INTEGER, b BOOLEAN }");
    if(asn == NULL) return 1;
    mod = TQ_FIRST(&asn->modules);
    expr = TQ_FIRST(&mod->members);
    ns = asn1_namespace_new_from_module(mod, 0);
    tags = (struct asn1p_type_tag_s *)1;
    count = asn1f_fetch_tags_ex(asn, ns, mod, expr, &tags, 0, record_diag, 0);
    failures += check(count == -1 && tags == NULL,
                      "untagged CHOICE tag fetch remains an error");
    if(tags != (struct asn1p_type_tag_s *)1) free(tags);

    tag.tag_class = TC_PRIVATE;
    tag.tag_value = 123;
    tag.tag_mode = TM_EXPLICIT;
    count = asn1f_fetch_outmost_tag_ex(asn, ns, mod, expr, &tag, 0,
                                       record_diag, 0);
    failures += check(count == -1 && tag.tag_class == TC_PRIVATE
                      && tag.tag_value == 123 && tag.tag_mode == TM_EXPLICIT,
                      "untagged CHOICE outmost fetch fails unchanged");
    asn1_namespace_free(ns);
    asn1p_delete(asn);

    /* A zero result is useful only when a valid tag was written. */
    asn = parse_one("T ::= [2] EXPLICIT INTEGER");
    if(asn == NULL) return 1;
    mod = TQ_FIRST(&asn->modules);
    expr = TQ_FIRST(&mod->members);
    ns = asn1_namespace_new_from_module(mod, 0);
    memset(&tag, 0, sizeof(tag));
    count = asn1f_fetch_outmost_tag(asn, ns, mod, expr, &tag, 0);
    failures += check(count == 0 && tag.tag_class == TC_CONTEXT_SPECIFIC
                      && tag.tag_value == 2 && tag.tag_mode == TM_EXPLICIT,
                      "successful outmost fetch returns a valid tag");
    asn1_namespace_free(ns);
    asn1p_delete(asn);

    return failures;
}

int
main(void) {
    records_t rec;
    asn1p_t *asn;
    asn1p_module_t *mod;
    asn1p_expr_t *expr;
    asn1_namespace_t *ns;
    struct asn1p_type_tag_s *tags;
    struct asn1p_type_tag_s tag;
    int count;
    int idx;
    int failures = 0;

    /* A failed lookup of this name must report EEXIST, not ESRCH. */
    if(asn1f_make_known_external_type("Unknown") != 0) {
        fprintf(stderr, "FAIL: cannot register the known external type\n");
        return 1;
    }
    if(asn1f_make_known_external_type("KnownExt") != 0) {
        fprintf(stderr, "FAIL: cannot register the external tag test type\n");
        return 1;
    }

    /*
     * (a) A tagged terminal type: the debug trace names T and the chain has
     * T's tag plus the universal INTEGER tag.
     */
    asn = parse_one("T ::= [2] INTEGER");
    if(asn == NULL) return 1;
    mod = TQ_FIRST(&asn->modules);
    expr = TQ_FIRST(&mod->members);
    ns = asn1_namespace_new_from_module(mod, 0);
    records_reset(&rec);
    count = asn1f_fetch_tags_ex(asn, ns, mod, expr, &tags, 0, record_diag, 1);
    asn1_namespace_free(ns);
    failures += check(count == 2, "tagged INTEGER yields two tags");
    idx = records_find(&rec, "Fetching tag from T");
    failures += check(idx >= 0, "debug fetch names the type");
    if(idx < 0) dump_records(&rec);
    free(tags);
    asn1p_delete(asn);

    /* (b) The same fetch without the debug flag emits no trace. */
    asn = parse_one("T ::= [2] INTEGER");
    if(asn == NULL) return 1;
    mod = TQ_FIRST(&asn->modules);
    expr = TQ_FIRST(&mod->members);
    ns = asn1_namespace_new_from_module(mod, 0);
    records_reset(&rec);
    count = asn1f_fetch_tags_ex(asn, ns, mod, expr, &tags, 0, record_diag, 0);
    asn1_namespace_free(ns);
    failures += check(count == 2, "quiet fetch still yields two tags");
    failures += check(records_find(&rec, "Fetching tag") < 0,
                      "quiet fetch emits no trace");
    if(rec.count) dump_records(&rec);
    free(tags);
    asn1p_delete(asn);

    /*
     * (c) An unresolved reference under an IMPLICIT tag keeps the tag and
     * reports one WARNING through the supplied logger.
     */
    asn = parse_one("T ::= [2] IMPLICIT Unknown");
    if(asn == NULL) return 1;
    mod = TQ_FIRST(&asn->modules);
    expr = TQ_FIRST(&mod->members);
    ns = asn1_namespace_new_from_module(mod, 0);
    records_reset(&rec);
    count = asn1f_fetch_tags_ex(asn, ns, mod, expr, &tags, 0, record_diag, 0);
    asn1_namespace_free(ns);
    failures += check(count == 1, "implicit unknown keeps one tag");
    idx = records_find(&rec, "Tagging mode for T is IMPLICIT");
    failures += check(rec.count == 1 && idx >= 0 && rec.fatal[idx] == 0,
                      "implicit unknown reports one warning");
    if(rec.count != 1 || idx < 0) dump_records(&rec);
    free(tags);
    asn1p_delete(asn);

    /*
     * (d) An unresolved reference under an EXPLICIT tag is fatal: no tag
     * can be assumed, so the fetch fails and reports the FATAL.
     */
    asn = parse_one("T ::= [2] EXPLICIT Unknown");
    if(asn == NULL) return 1;
    mod = TQ_FIRST(&asn->modules);
    expr = TQ_FIRST(&mod->members);
    ns = asn1_namespace_new_from_module(mod, 0);
    records_reset(&rec);
    count = asn1f_fetch_tags_ex(asn, ns, mod, expr, &tags, 0, record_diag, 0);
    asn1_namespace_free(ns);
    failures += check(count == -1, "explicit unknown fails the fetch");
    idx = records_find(&rec, "dangerously incompatible");
    failures += check(rec.count == 1 && idx >= 0 && rec.fatal[idx] != 0,
                      "explicit unknown reports one fatal");
    if(rec.count != 1 || idx < 0) dump_records(&rec);
    asn1p_delete(asn);

    /*
     * The outmost variant must delegate to the _ex tags variant (so it sees
     * the same channel). It stops after the outmost tag, so it succeeds
     * here and only the debug trace is observable.
     */
    asn = parse_one("T ::= [2] EXPLICIT Unknown");
    if(asn == NULL) return 1;
    mod = TQ_FIRST(&asn->modules);
    expr = TQ_FIRST(&mod->members);
    ns = asn1_namespace_new_from_module(mod, 0);
    records_reset(&rec);
    memset(&tag, 0, sizeof(tag));
    count = asn1f_fetch_outmost_tag_ex(asn, ns, mod, expr, &tag, 0,
                                       record_diag, 1);
    asn1_namespace_free(ns);
    failures += check(count == 0 && tag.tag_class == TC_CONTEXT_SPECIFIC
                      && tag.tag_value == 2 && tag.tag_mode == TM_EXPLICIT,
                      "outmost fetch returns the explicit tag");
    failures += check(records_find(&rec, "Fetching tag from T") >= 0,
                      "outmost fetch delegates to the _ex tags variant");
    if(records_find(&rec, "Fetching tag from T") < 0) dump_records(&rec);
    asn1p_delete(asn);

    /*
     * (e) The legacy entry point takes only .flags from the global fixer
     * snapshot. Install the recorder on both snapshot channels first: a
     * wrapper that copied them would report the IMPLICIT warning below.
     * debug_enabled is deliberately not set, so this also builds upstream,
     * where the field does not exist.
     */
    asn = parse_one("T ::= [2] IMPLICIT Unknown");
    if(asn == NULL) return 1;
    mod = TQ_FIRST(&asn->modules);
    expr = TQ_FIRST(&mod->members);
    ns = asn1_namespace_new_from_module(mod, 0);
    a1f_replace_me_with_proper_interface_arg.eh = record_diag;
    a1f_replace_me_with_proper_interface_arg.debug = record_diag;
    records_reset(&rec);
    count = asn1f_fetch_tags(asn, ns, mod, expr, &tags, 0);
    asn1_namespace_free(ns);
    failures += check(count == 1, "legacy fetch keeps one tag");
    failures += check(rec.count == 0,
                      "legacy fetch ignores the snapshot channels");
    if(rec.count) dump_records(&rec);
    free(tags);
    asn1p_delete(asn);
    memset(&a1f_replace_me_with_proper_interface_arg, 0,
           sizeof(a1f_replace_me_with_proper_interface_arg));

    failures += check_external_fetch_contract();

    return failures ? 1 : 0;
}
