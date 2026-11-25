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
#include <assert.h>
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

/* The file wrapper's temporary input; CLEANFILES removes a stale copy. */
static const char *file_path = "check_parse_cleanup.tmp";

static asn1p_t *
parse(const char *schema) {
	return asn1p_parse_buffer(schema, -1, "<check_parse_cleanup>", 1,
		A1P_NOFLAGS);
}

/*
 * The same broken body through asn1p_parse_file(), which must run the
 * cleanup too and must leave no temporary file behind.
 */
static int
check_file_parse(void) {
	asn1p_t *a;
	FILE *fp;

	fp = fopen(file_path, "w");
	if(fp == NULL) {
		perror(file_path);
		return 1;
	}
	fputs(bad_body_schema, fp);
	fclose(fp);

	a = asn1p_parse_file(file_path, A1P_NOFLAGS);
	remove(file_path);
	if(a) {
		fprintf(stderr, "FAIL: bad_body_schema parsed from a file\n");
		asn1p_delete(a);
		return 1;
	}
	return 0;
}

int
main(void) {
	asn1p_t *a;
	int i;

	/* Control: a good parse before the failure paths. */
	a = parse(valid_schema);
	assert(a != NULL);
	assert(TQ_FIRST(&a->modules) != NULL);
	asn1p_delete(a);

	/* A successful multi-module parse keeps both modules in the tree. */
	a = parse(two_module_schema);
	assert(a != NULL);
	assert(TQ_FIRST(&a->modules) != NULL);
	assert(TQ_NEXT(TQ_FIRST(&a->modules), mod_next) != NULL);
	assert(TQ_NEXT(TQ_NEXT(TQ_FIRST(&a->modules), mod_next),
		mod_next) == NULL);
	asn1p_delete(a);

	/* Repeated failure inside the module body must not leak the module. */
	for(i = 0; i < 100; i++) {
		a = parse(bad_body_schema);
		if(a) {
			fprintf(stderr, "FAIL: bad_body_schema parsed on pass %d\n",
				i);
			asn1p_delete(a);
			return 1;
		}
	}

	/* A broken module after a valid one must not leak or double free. */
	a = parse(good_then_bad_schema);
	if(a) {
		fprintf(stderr, "FAIL: good_then_bad_schema parsed\n");
		asn1p_delete(a);
		return 1;
	}

	/* An error in the header after the mid-rule created the module. */
	a = parse(bad_header_oid_schema);
	if(a) {
		fprintf(stderr, "FAIL: bad_header_oid_schema parsed\n");
		asn1p_delete(a);
		return 1;
	}

	/*
	 * The file wrapper must release the module and its input file.
	 * asn1p_restart() leaves its lexer buffer current, so release it
	 * here: the next buffer parse would otherwise orphan it and add a
	 * lexer leak that is not this test's subject.
	 */
	if(check_file_parse())
		return 1;
	asn1p_lex_destroy();

	/* Control: the parser still works after the file failure. */
	a = parse(valid_schema);
	assert(a != NULL);
	assert(TQ_FIRST(&a->modules) != NULL);
	asn1p_delete(a);

	/* Release the scanner state for a clean LeakSanitizer report. */
	asn1p_lex_destroy();

	printf("PASS: failed parses release the partial module\n");
	return 0;
}
