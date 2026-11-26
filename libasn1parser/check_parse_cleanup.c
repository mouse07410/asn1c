/*
 * A failed parse must release the module it was building.
 *
 * The grammar creates the module object as soon as it recognises the module
 * header, but the object only becomes part of the returned tree when the
 * closing END is reduced.  An error in between used to leave the module (and
 * its member hash) owned by nobody, so every failed parse leaked it.  The
 * parser now clears its current-module pointer when it hands the module over
 * and frees a still-current module when the parse fails; this test exercises
 * both paths under LeakSanitizer.
 *
 * Parse-only: it uses nothing beyond the public parser API.
 */
#include <errno.h>
#include <stdio.h>

#include "asn1parser.h"
#include "asn1p_list.h"

/*
 * A schema that parses.  Used as a control before and after the failures so
 * that a crash or a leak in the failure paths cannot hide behind a clean
 * process exit.
 */
static const char *valid_schema =
	"TestModule DEFINITIONS ::= BEGIN\n"
	"A ::= INTEGER (0..10)\n"
	"B ::= SEQUENCE { a A }\n"
	"END\n";

/*
 * A syntax error inside the module body, after two assignments: the module
 * and its contents exist when the parse fails.
 */
static const char *bad_body_schema =
	"TestModule DEFINITIONS ::= BEGIN\n"
	"A ::= INTEGER (0..10)\n"
	"B ::= SEQUENCE { a A\n"
	"END\n";

/*
 * A valid module followed by a broken one.  This discards an already
 * completed ModuleList, so it also checks that the cleanup does not free a
 * module the <a_grammar> destructor already owns.
 */
static const char *good_then_bad_schema =
	"GoodModule DEFINITIONS ::= BEGIN\n"
	"A ::= INTEGER\n"
	"END\n"
	"BadModule DEFINITIONS ::= BEGIN\n"
	"B ::= SEQUENCE {\n"
	"END\n";

/*
 * A valid schema with two modules: the parser must hand both to the tree,
 * and the first module must not stay current while the second is built.
 */
static const char *two_module_schema =
	"FirstModule DEFINITIONS ::= BEGIN\n"
	"A ::= INTEGER\n"
	"END\n"
	"SecondModule DEFINITIONS ::= BEGIN\n"
	"B ::= BOOLEAN\n"
	"END\n";

/*
 * The error is in the module header, after the mid-rule action has created
 * the module: the object identifier precedes DEFINITIONS in the grammar but
 * is parsed after the mid-rule.  The module is therefore current and
 * incomplete when the parse fails.
 */
static const char *bad_header_oid_schema =
	"HdrOid { iso(1) bogus( } DEFINITIONS ::= BEGIN\n"
	"END\n";

/*
 * Parse a borrowed, NUL-terminated schema through the buffer entry point.
 * Source: Javier / @mr-j0nes, PR #620, 2026-11-25. Returns an owned tree
 * or NULL on error; throws no exceptions. Example: parse(valid_schema).
 */
static asn1p_t *
parse(const char *schema) {
	return asn1p_parse_buffer(schema, -1, "<check_parse_cleanup>", 1,
		A1P_NOFLAGS);
}

/*
 * Check a borrowed schema's module count and release any returned tree.
 * Source: PR #620 follow-up, 2026-11-25. Returns zero on match, one on
 * failure, without exceptions. Example: check_modules(valid_schema, 1).
 */
static int
check_modules(const char *schema, unsigned expected) {
	asn1p_t *tree = parse(schema);
	unsigned count = 0;

	if(tree) {
		for(asn1p_module_t *module = TQ_FIRST(&tree->modules); module;
		    module = TQ_NEXT(module, mod_next))
			count++;
		asn1p_delete(tree);
	} else if(expected == 0) {
		return 0;
	}

	if(count == expected && expected != 0)
		return 0;
	fprintf(stderr, "Expected %u modules, found %u in: %s", expected, count, schema);
	return 1;
}

/*
 * Verify failure of the file entry point with a read-only fixture.
 * Source: PR #620 follow-up, 2026-11-25. No inputs or exceptions. Returns
 * zero when parsing fails with EINVAL, one otherwise. Called by main().
 */
static int
check_file_parse(void) {
	asn1p_t *tree = asn1p_parse_file(PARSE_CLEANUP_INPUT, A1P_NOFLAGS);
	int error = errno;

	if(tree || error != EINVAL) {
		fprintf(stderr, "Expected EINVAL for %s, got errno %d\n", PARSE_CLEANUP_INPUT, error);
		asn1p_delete(tree);
		return 1;
	}
	return 0;
}

/*
 * Exercise ownership transfers and repeated parser reuse in one process.
 * Source: Javier / @mr-j0nes, PR #620, expanded 2026-11-25. No inputs
 * or exceptions. Returns zero on success or one on regression. Automake
 * runs this executable, with LeakSanitizer when available.
 */
int
main(void) {
	/* An explicit grammar rejection must unwind earlier completed modules. */
	const char *bad_enumeration =
		"GoodModule DEFINITIONS ::= BEGIN A ::= INTEGER END\n"
		"BadModule DEFINITIONS ::= BEGIN B ::= ENUMERATED { ... } END\n";
	const char *bad_imports =
		"BadModule DEFINITIONS ::= BEGIN IMPORTS FROM Other; END\n";

	if(check_modules(valid_schema, 1) || check_modules(two_module_schema, 2))
		return 1;

	for(int i = 0; i < 100; i++) {
		if(check_modules(bad_body_schema, 0))
			return 1;
	}

	if(check_modules(good_then_bad_schema, 0) || check_modules(bad_header_oid_schema, 0)
	|| check_modules(bad_enumeration, 0) || check_modules(bad_imports, 0))
		return 1;

	/* Alternate public entry points without a caller-managed scanner reset. */
	for(int i = 0; i < 2; i++) {
		if(check_file_parse() || check_modules(valid_schema, 1))
			return 1;
	}
	return 0;
}
