/*
 * Source columns in the parser (ASN1-0112).
 *
 * Invariant: the lexer records the 1-based start column of every token in
 * asn1p_column, and the expressions the parser builds carry that column in
 * _column.  Tabs count as one character, only '\n' resets the column, and
 * line numbers keep their existing meaning.  Flex re-enters the per-match
 * action on REJECT and on the ENCODING-CONTROL unput(), and the
 * quoted-string token is built by two rules; none of them may shift the
 * column of the token that follows.
 *
 * The column is recorded at reduce time, so like _lineno it is exact only
 * where the grammar reduces without reading lookahead; the schemas below use
 * single-token types, which bison reduces by default.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "asn1parser.h"
#include "asn1p_list.h"
#include "asn1p_y.h"

/*
 * The lexer-level cases drive the scanner directly, because the quoted
 * string, the rejected keyword and the encoding-control re-scan are token
 * events that no expression reports.
 */
void *asn1p__scan_bytes(const char *, int);
void asn1p_restart(FILE *);
void asn1p_lexer_reset_position(void);
void asn1p_lexer_hack_push_encoding_control(void);
int asn1p_lex(void);
extern int asn1p_column;
extern int asn1p_lineno;
extern int asn1p_lexer_types_year;
extern char *asn1p_text;

static int failures;

static void
fail(const char *what, const char *detail) {
	fprintf(stderr, "FAIL: %s%s%s\n", what, detail ? ": " : "",
		detail ? detail : "");
	failures++;
}

/*
 * A type token after six spaces of indentation: the BOOLEAN starts in
 * column 18 on line 2.  The second assignment and END exist so that the
 * module is complete.
 */
static const char indented_schema[] =
	"TestModule DEFINITIONS ::= BEGIN\n"
	"      Spaced ::= BOOLEAN\n"
	"Second ::= BOOLEAN\n"
	"END\n";

/*
 * The element type on its own line: BOOLEAN starts in column 1 of line 3.
 */
static const char next_line_schema[] =
	"TestModule DEFINITIONS ::= BEGIN\n"
	"Seq ::= SEQUENCE OF\n"
	"BOOLEAN\n"
	"END\n";

static asn1p_expr_t *
find_member(asn1p_t *tree, const char *name) {
	asn1p_module_t *mod;
	asn1p_expr_t *expr;

	TQ_FOR(mod, &tree->modules, mod_next) {
		TQ_FOR(expr, &mod->members, next) {
			if(expr->Identifier
			&& strcmp(expr->Identifier, name) == 0)
				return expr;
		}
	}
	return NULL;
}

/*
 * Check one expression's source location, then release the tree.
 */
static void
check_member(const char *schema, const char *name, int lineno, int column) {
	asn1p_t *tree;
	asn1p_expr_t *expr;

	tree = asn1p_parse_buffer(schema, -1, "<check_asn1p_column>", 1,
		A1P_NOFLAGS);
	if(tree == NULL) {
		fail(name, "schema did not parse");
		return;
	}
	expr = find_member(tree, name);
	if(expr == NULL) {
		fail(name, "expression not found");
	} else if(expr->_lineno != lineno) {
		char detail[128];
		snprintf(detail, sizeof(detail), "line %d, want %d",
			expr->_lineno, lineno);
		fail(name, detail);
	} else if(expr->_column != column) {
		char detail[128];
		snprintf(detail, sizeof(detail), "column %d, want %d",
			expr->_column, column);
		fail(name, detail);
	} else {
		printf("PASS: %s is at %d:%d\n", name, expr->_lineno,
			expr->_column);
	}
	asn1p_delete(tree);
}

/*
 * A type after leading spaces keeps its line and reports its start column.
 */
static void
check_indented_type(void) {
	check_member(indented_schema, "Spaced", 2, 18);
}

/*
 * The element type that starts the next line is column 1.
 */
static void
check_next_line_type(void) {
	asn1p_t *tree;
	asn1p_expr_t *expr;
	asn1p_expr_t *element;

	tree = asn1p_parse_buffer(next_line_schema, -1,
		"<check_asn1p_column>", 1, A1P_NOFLAGS);
	if(tree == NULL) {
		fail("next-line type", "schema did not parse");
		return;
	}
	expr = find_member(tree, "Seq");
	element = expr ? TQ_FIRST(&expr->members) : NULL;
	if(element == NULL) {
		fail("next-line type", "element type not found");
	} else if(element->_lineno != 3 || element->_column != 1) {
		char detail[128];
		snprintf(detail, sizeof(detail), "line %d column %d, want 3:1",
			element->_lineno, element->_column);
		fail("next-line type", detail);
	} else {
		printf("PASS: next-line element type is at %d:%d\n",
			element->_lineno, element->_column);
	}
	asn1p_delete(tree);
}

/*
 * Start a direct lexer session on a borrowed buffer, at line 1.
 */
static void
lex_start(const char *text, int push_encoding_control) {
	asn1p__scan_bytes(text, (int)strlen(text));
	asn1p_lexer_reset_position();
	asn1p_lineno = 1;
	if(push_encoding_control)
		asn1p_lexer_hack_push_encoding_control();
}

/*
 * Release the token value of the rules these cases exercise; the scanner
 * does not own the strings it returns.
 */
static void
lex_free_token(int token) {
	if(token == TOK_cstring)
		free(asn1p_lval.tv_opaque.buf);
	else if(token == TOK_typereference || token == TOK_identifier)
		free(asn1p_lval.tv_str);
}

/*
 * Expect one token with a given column.  name identifies the case in the
 * failure text; the token text is reported too.
 */
static void
expect_token(const char *name, int token, int expected_token,
	int expected_column) {
	char detail[256];

	if(token != expected_token) {
		snprintf(detail, sizeof(detail), "token %d, want %d (\"%s\")",
			token, expected_token, asn1p_text);
		fail(name, detail);
	} else if(asn1p_column != expected_column) {
		snprintf(detail, sizeof(detail), "column %d, want %d (\"%s\")",
			asn1p_column, expected_column, asn1p_text);
		fail(name, detail);
	} else {
		printf("PASS: %s: \"%s\" is at %d:%d\n", name, asn1p_text,
			asn1p_lineno, asn1p_column);
	}
	lex_free_token(token);
}

/*
 * The quoted-string token starts at the opening quote, not at the closing
 * one; that holds on one line and when the string spans a newline, whose
 * line stays the closing line.
 */
static void
check_quoted_string(void) {
	int token;

	lex_start("  \"abc\"", 0);
	token = asn1p_lex();
	expect_token("quoted string", token, TOK_cstring, 3);
	asn1p_lex_destroy();

	lex_start("  \"ab\ncd\"", 0);
	token = asn1p_lex();
	expect_token("quoted string across a newline", token, TOK_cstring, 3);
	if(asn1p_lineno != 2) {
		char detail[128];
		snprintf(detail, sizeof(detail), "line %d, want 2",
			asn1p_lineno);
		fail("quoted string across a newline", detail);
	}
	asn1p_lex_destroy();
}

/*
 * A keyword rejected by the year rules is re-matched as a typereference;
 * neither the returned column nor the following token's column may move.
 */
static void
check_reject(void) {
	int token;

	asn1p_lexer_types_year = 1990;
	lex_start("UTF8String Foo", 0);
	token = asn1p_lex();
	expect_token("rejected keyword", token, TOK_typereference, 1);
	token = asn1p_lex();
	expect_token("token after a rejected keyword", token,
		TOK_typereference, 12);
	asn1p_lexer_types_year = 0;
	asn1p_lex_destroy();
}

/*
 * The ENCODING-CONTROL rule unputs its own text and rescans it in the
 * initial state; the token keeps its column and the next token starts right
 * after the 16 characters, not 16 columns further.
 */
static void
check_encoding_control(void) {
	int token;

	lex_start("  ENCODING-CONTROL Foo", 1);
	token = asn1p_lex();
	expect_token("encoding-control keyword", token,
		TOK_ENCODING_CONTROL, 3);
	token = asn1p_lex();
	expect_token("token after encoding-control", token,
		TOK_typereference, 20);
	asn1p_lex_destroy();
}

/*
 * A second parse in the same process starts at column 1 again; asn1de
 * parses several schemas without a new process.  A two-token input proves
 * that the match guard is cleared: the first token would otherwise be
 * skipped and the second token would carry the first scan's ending column.
 */
static void
check_repeated_parse(void) {
	int token;

	check_member(indented_schema, "Spaced", 2, 18);
	check_member(indented_schema, "Spaced", 2, 18);

	lex_start("Foo Bar", 0);
	token = asn1p_lex();
	expect_token("first scan, first token", token, TOK_typereference, 1);
	token = asn1p_lex();
	expect_token("first scan, second token", token, TOK_typereference, 5);
	asn1p_lex_destroy();

	lex_start("Foo Bar", 0);
	token = asn1p_lex();
	expect_token("second scan, first token", token, TOK_typereference, 1);
	token = asn1p_lex();
	expect_token("second scan, second token", token, TOK_typereference, 5);
	asn1p_lex_destroy();
}

/*
 * The guard is only observable when a new input starts with the same match
 * the previous input ended on.  Restarting the scanner on the same FILE
 * reuses its buffer, so the first token of the second pass sits at the same
 * address as the first token of the first pass: without the guard clear the
 * second pass would skip it and place "Bar" in column 1.
 */
static void
check_guard_reset(void) {
	FILE *fp;
	int token;

	fp = tmpfile();
	if(fp == NULL) {
		fail("guard reset", "cannot create a temporary file");
		return;
	}
	fputs("Foo Bar", fp);

	rewind(fp);
	asn1p_lineno = 1;
	asn1p_lexer_reset_position();
	asn1p_restart(fp);
	token = asn1p_lex();
	expect_token("guard reset, previous input", token,
		TOK_typereference, 1);

	rewind(fp);
	asn1p_lineno = 1;
	asn1p_lexer_reset_position();
	asn1p_restart(fp);
	token = asn1p_lex();
	expect_token("guard reset, first token", token, TOK_typereference, 1);
	token = asn1p_lex();
	expect_token("guard reset, second token", token, TOK_typereference, 5);

	asn1p_lex_destroy();
	fclose(fp);
}

/*
 * A UTF-8 byte order mark is consumed before the first column and has no
 * visible width, so it must not shift line 1.  The schema-level checks below
 * only see lines after a newline, where the column resets anyway; the
 * lexer-level case pins the mark's effect on the first line, which no
 * expression can report.  The same schema without the mark is the control.
 */
static void
check_bom(void) {
	static const char bom_schema[] =
		"\xef\xbb\xbf"
		"TestModule DEFINITIONS ::= BEGIN\n"
		"      Spaced ::= BOOLEAN\n"
		"Second ::= BOOLEAN\n"
		"END\n";
	int token;

	lex_start("\xef\xbb\xbf" "Foo Bar", 0);
	token = asn1p_lex();		/* The mark itself, at the line start. */
	expect_token("BOM, mark", token, UTF8_BOM, 1);
	token = asn1p_lex();
	expect_token("BOM line 1, first token", token, TOK_typereference, 1);
	token = asn1p_lex();
	expect_token("BOM line 1, second token", token, TOK_typereference, 5);
	asn1p_lex_destroy();

	check_member(indented_schema, "Spaced", 2, 18);
	check_member(bom_schema, "Spaced", 2, 18);
	check_member(bom_schema, "Second", 3, 12);
}

/*
 * A synthesized node has no source location; asn1p_expr_new() keeps 0.
 */
static void
check_synthesized_expr(void) {
	asn1p_expr_t *expr = asn1p_expr_new(7, NULL);

	if(expr == NULL) {
		fail("synthesized expression", "allocation failed");
		return;
	}
	if(expr->_lineno != 7 || expr->_column != 0) {
		char detail[128];
		snprintf(detail, sizeof(detail), "line %d column %d, want 7:0",
			expr->_lineno, expr->_column);
		fail("synthesized expression", detail);
	} else {
		printf("PASS: synthesized expression keeps column 0\n");
	}
	asn1p_expr_free(expr);
}

int
main(void) {
	check_indented_type();
	check_next_line_type();
	check_quoted_string();
	check_reject();
	check_encoding_control();
	check_repeated_parse();
	check_guard_reset();
	check_bom();
	check_synthesized_expr();

	if(failures != 0) {
		fprintf(stderr, "%d column check(s) failed\n", failures);
		return 1;
	}
	printf("PASS: token columns are tracked and reported\n");
	return 0;
}
