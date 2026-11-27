/*
 * Structured parser and fixer diagnostics.
 *
 * Invariant: with a diagnostic callback installed, the parser reports the
 * errors raised by yyerror() and the fixer reports its diagnostics through the
 * structured callback, and neither of those paths prints; without one, the
 * historical printed text, return values and error codes are unchanged.  This
 * is not a complete capture of parser output: the grammar actions and the
 * lexer still print their warnings directly to stderr, and those never reach
 * the callback.  A record carries the location the core actually knows: the
 * parser fills file, line, column and token; the fixer fills file and line of
 * the failing expression, and token is NULL outside the parser.  The column is
 * 0 until the lexer tracks it.
 *
 * The structured channel is callback-scoped: it must never outlive the
 * asn1f_process_diag() call that installed it, while the legacy channel may
 * persist for later lookups.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#ifdef _WIN32
#include <io.h>
#define dup _dup
#define dup2 _dup2
#define fileno _fileno
#define close _close
#else
#include <unistd.h>
#endif

#include "asn1parser.h"
#include "asn1fix.h"
#include "asn1fix_export.h"
#include "asn1_namespace.h"
#include "asn1c_diag.h"

#define MAX_RECS 8

/* Captured stderr is a handful of lines; this bounds every check. */
#define STDERR_MAX 4096

/*
 * Diagnostic capture.  The core's pointers are valid only during the
 * callback, so every string is copied and the stored record is re-pointed at
 * the copies.
 */
typedef struct {
    int count;
    asn1c_diag_t rec[MAX_RECS];
    char file[MAX_RECS][128];
    char token[MAX_RECS][128];
    char message[MAX_RECS][512];
} capture_t;

static void
capture_cb(void *key, const asn1c_diag_t *diag) {
    capture_t *c = key;
    int i;

    if(c->count >= MAX_RECS) return;
    i = c->count++;
    c->rec[i] = *diag;
    c->file[i][0] = '\0';
    c->token[i][0] = '\0';
    c->message[i][0] = '\0';
    if(diag->file)
        snprintf(c->file[i], sizeof(c->file[i]), "%s", diag->file);
    if(diag->token)
        snprintf(c->token[i], sizeof(c->token[i]), "%s", diag->token);
    if(diag->message)
        snprintf(c->message[i], sizeof(c->message[i]), "%s", diag->message);
    c->rec[i].file = diag->file ? c->file[i] : NULL;
    c->rec[i].token = diag->token ? c->token[i] : NULL;
    c->rec[i].message = c->message[i];
}

static int
first_of_severity(const capture_t *c, asn1c_diag_severity severity) {
    int i;
    for(i = 0; i < c->count; i++) {
        if(c->rec[i].severity == severity) return i;
    }
    return -1;
}

/*
 * Redirect one stream into a temporary file for a check, so the historical
 * printed text can be compared exactly.  capture_stop() always restores the
 * original descriptor, whatever the check does in between.
 */
static int
capture_start(FILE *stream, int *saved_fd, FILE **tmp) {
    FILE *f = tmpfile();
    int fd;

    if(f == NULL) return -1;
    fflush(stream);
    fd = dup(fileno(stream));
    if(fd < 0 || dup2(fileno(f), fileno(stream)) < 0) {
        if(fd >= 0) close(fd);
        fclose(f);
        return -1;
    }
    *saved_fd = fd;
    *tmp = f;
    return 0;
}

static void
capture_stop(FILE *stream, int saved_fd, FILE *tmp, char *buf, size_t size) {
    long len;

    fflush(stream);
    dup2(saved_fd, fileno(stream));
    close(saved_fd);
    len = (fseek(tmp, 0, SEEK_END) == 0) ? ftell(tmp) : -1;
    if(len < 0) len = 0;
    rewind(tmp);
    if((size_t)len >= size) len = (long)size - 1;
    if(len > 0 && fread(buf, 1, (size_t)len, tmp) != (size_t)len)
        len = 0;
    buf[len] = '\0';
    fclose(tmp);
}

/* A schema the parser rejects on a real token. */
static const char bad_schema[] =
    "M DEFINITIONS ::= BEGIN\n"
    "some garbage\n"
    "END\n";

/* A schema the fixer rejects: U does not exist. */
static const char unknown_type_schema[] =
    "M DEFINITIONS ::= BEGIN\n"
    "T ::= U\n"
    "END\n";

/* A schema the fixer only warns about: one module name, two OIDs. */
static const char warning_schema[] =
    "M { iso(1) 1 } DEFINITIONS ::= BEGIN\n"
    "END\n"
    "M { iso(1) 2 } DEFINITIONS ::= BEGIN\n"
    "END\n";

/* A clean schema used to exercise lookups after a fixer call returned. */
static const char clean_schema[] =
    "M DEFINITIONS ::= BEGIN\n"
    "T ::= INTEGER\n"
    "END\n";

/*
 * A schema whose grammar action prints a NOTE while parsing.  It is a stated
 * boundary: the callback must not receive it, and it must still reach stderr.
 */
static const char notice_schema[] =
    "M DEFINITIONS ::= BEGIN\n"
    "BinaryData ::= OCTET STRING\n"
    "ENCODING-CONTROL XER\n"
    "    BinaryData OCTET STRING ::= hexadecimal\n"
    "END\n"
    "END\n";

/*
 * Parser: a syntax error reaches the callback with file, line and message,
 * the parse still fails, and nothing is printed.
 */
static int
check_parser_diag(void) {
    capture_t cap;
    char err[STDERR_MAX];
    asn1p_t *asn;
    int saved;
    FILE *tmp;
    int i;

    if(capture_start(stderr, &saved, &tmp) != 0) {
        fprintf(stderr, "FAIL: cannot capture stderr\n");
        return 1;
    }
    memset(&cap, 0, sizeof(cap));
    asn = asn1p_parse_buffer_diag(bad_schema, -1, "bad-schema.asn1", 1,
                                  A1P_NOFLAGS, capture_cb, &cap);
    capture_stop(stderr, saved, tmp, err, sizeof(err));
    if(asn != NULL) {
        fprintf(stderr, "FAIL: parser accepted a broken schema\n");
        asn1p_delete(asn);
        return 1;
    }
    if(err[0] != '\0') {
        fprintf(stderr, "FAIL: parser printed with a callback: %s\n", err);
        return 1;
    }
    if(cap.count < 1) {
        fprintf(stderr, "FAIL: parser reported no diagnostics\n");
        return 1;
    }
    i = first_of_severity(&cap, ASN1C_DIAG_ERROR);
    if(i < 0) {
        fprintf(stderr, "FAIL: no ERROR record from the parser\n");
        return 1;
    }
    if(cap.rec[i].file == NULL
       || strcmp(cap.rec[i].file, "bad-schema.asn1") != 0) {
        fprintf(stderr, "FAIL: parser record has no file (%s)\n",
                cap.rec[i].file ? cap.rec[i].file : "(null)");
        return 1;
    }
    if(cap.rec[i].line <= 0) {
        fprintf(stderr, "FAIL: parser record has no line (%d)\n",
                cap.rec[i].line);
        return 1;
    }
    if(cap.rec[i].column != 0) {
        fprintf(stderr, "FAIL: parser record column is %d, want 0\n",
                cap.rec[i].column);
        return 1;
    }
    if(cap.rec[i].token == NULL
       || strcmp(cap.rec[i].token, "garbage") != 0) {
        fprintf(stderr, "FAIL: parser record token is %s\n",
                cap.rec[i].token ? cap.rec[i].token : "(null)");
        return 1;
    }
    if(cap.rec[i].message == NULL || cap.rec[i].message[0] == '\0') {
        fprintf(stderr, "FAIL: parser record has no message\n");
        return 1;
    }
    printf("PASS: parser record file=%s line=%d token=\"%s\" message=\"%s\"\n",
           cap.rec[i].file, cap.rec[i].line, cap.rec[i].token,
           cap.rec[i].message);
    return 0;
}

/*
 * Parser: without a callback the printed line keeps its historical shape and
 * the caller still gets NULL.  This pins the exact text, file, line and token.
 */
static int
check_parser_legacy(void) {
    static const char expected[] =
        "ASN.1 grammar parse error near bad-schema.asn1:2 "
        "(token \"garbage\"): syntax error\n";
    char text[STDERR_MAX];
    asn1p_t *asn;
    int saved;
    FILE *tmp;

    if(capture_start(stderr, &saved, &tmp) != 0) {
        fprintf(stderr, "FAIL: cannot capture stderr\n");
        return 1;
    }
    asn = asn1p_parse_buffer(bad_schema, -1, "bad-schema.asn1", 1,
                             A1P_NOFLAGS);
    capture_stop(stderr, saved, tmp, text, sizeof(text));
    if(asn != NULL) {
        fprintf(stderr, "FAIL: parser accepted a broken schema\n");
        asn1p_delete(asn);
        return 1;
    }
    if(strcmp(text, expected) != 0) {
        fprintf(stderr, "FAIL: no-callback parser text is \"%s\", want \"%s\"\n",
                text, expected);
        return 1;
    }
    printf("PASS: parser without a callback prints the pinned text\n");
    return 0;
}

/*
 * Parser: a message a grammar action prints directly keeps going to stderr
 * while a callback is installed, and never becomes a record.
 */
static int
check_parser_direct_print(void) {
    capture_t cap;
    char err[STDERR_MAX];
    asn1p_t *asn;
    int saved;
    FILE *tmp;

    if(capture_start(stderr, &saved, &tmp) != 0) {
        fprintf(stderr, "FAIL: cannot capture stderr\n");
        return 1;
    }
    memset(&cap, 0, sizeof(cap));
    asn = asn1p_parse_buffer_diag(notice_schema, -1, "notice.asn1", 1,
                                  A1P_NOFLAGS, capture_cb, &cap);
    capture_stop(stderr, saved, tmp, err, sizeof(err));
    if(asn == NULL) {
        fprintf(stderr, "FAIL: parser rejected the encoding-control schema\n");
        return 1;
    }
    asn1p_delete(asn);
    if(strstr(err, "NOTE: ENCODING-CONTROL XER at notice.asn1:5") == NULL) {
        fprintf(stderr,
                "FAIL: the grammar-action note is not on stderr: \"%s\"\n",
                err);
        return 1;
    }
    if(cap.count != 0) {
        fprintf(stderr,
                "FAIL: the grammar-action note became a record: %s\n",
                cap.rec[0].message ? cap.rec[0].message : "(null)");
        return 1;
    }
    printf("PASS: grammar-action note stays on stderr and off the callback\n");
    return 0;
}

/*
 * Fixer: an unknown type is an ERROR with the module file and the
 * expression's line, the message has no printed location suffix, and nothing
 * is printed.
 */
static int
check_fixer_diag(void) {
    capture_t cap;
    char err[STDERR_MAX];
    asn1p_t *asn;
    int saved;
    FILE *tmp;
    int ret;
    int i;

    asn = asn1p_parse_buffer(unknown_type_schema, -1, "-", 1, A1P_NOFLAGS);
    if(asn == NULL) {
        fprintf(stderr, "FAIL: cannot parse the fixer schema\n");
        return 1;
    }
    if(capture_start(stderr, &saved, &tmp) != 0) {
        fprintf(stderr, "FAIL: cannot capture stderr\n");
        asn1p_delete(asn);
        return 1;
    }
    memset(&cap, 0, sizeof(cap));
    ret = asn1f_process_diag(asn, A1F_NOFLAGS, capture_cb, &cap);
    capture_stop(stderr, saved, tmp, err, sizeof(err));
    if(ret != -1) {
        fprintf(stderr, "FAIL: fixer returned %d, want -1\n", ret);
        asn1p_delete(asn);
        return 1;
    }
    if(err[0] != '\0') {
        fprintf(stderr, "FAIL: fixer printed with a callback: %s\n", err);
        asn1p_delete(asn);
        return 1;
    }
    i = first_of_severity(&cap, ASN1C_DIAG_ERROR);
    if(i < 0) {
        fprintf(stderr, "FAIL: no ERROR record from the fixer\n");
        asn1p_delete(asn);
        return 1;
    }
    if(cap.rec[i].file == NULL) {
        fprintf(stderr, "FAIL: fixer record has no file\n");
        asn1p_delete(asn);
        return 1;
    }
    if(cap.rec[i].line <= 0) {
        fprintf(stderr, "FAIL: fixer record has no line (%d)\n",
                cap.rec[i].line);
        asn1p_delete(asn);
        return 1;
    }
    if(cap.rec[i].column != 0) {
        fprintf(stderr, "FAIL: fixer record column is %d, want 0\n",
                cap.rec[i].column);
        asn1p_delete(asn);
        return 1;
    }
    if(cap.rec[i].token != NULL) {
        fprintf(stderr, "FAIL: fixer record carries a token\n");
        asn1p_delete(asn);
        return 1;
    }
    if(strstr(cap.rec[i].message, "Unknown type \"U\"") == NULL) {
        fprintf(stderr, "FAIL: fixer message lost its detail: %s\n",
                cap.rec[i].message);
        asn1p_delete(asn);
        return 1;
    }
    if(strstr(cap.rec[i].message, " in -") != NULL) {
        fprintf(stderr,
                "FAIL: fixer record message keeps the file suffix: %s\n",
                cap.rec[i].message);
        asn1p_delete(asn);
        return 1;
    }
    printf("PASS: fixer record file=%s line=%d message=\"%s\"\n",
           cap.rec[i].file, cap.rec[i].line, cap.rec[i].message);
    asn1p_delete(asn);
    return 0;
}

/* Fixer: a warning-only schema reports a WARNING and returns 1. */
static int
check_fixer_warning(void) {
    capture_t cap;
    asn1p_t *asn;
    int ret;
    int i;

    asn = asn1p_parse_buffer(warning_schema, -1, "-", 1, A1P_NOFLAGS);
    if(asn == NULL) {
        fprintf(stderr, "FAIL: cannot parse the warning schema\n");
        return 1;
    }
    memset(&cap, 0, sizeof(cap));
    ret = asn1f_process_diag(asn, A1F_NOFLAGS, capture_cb, &cap);
    if(ret != 1) {
        fprintf(stderr, "FAIL: fixer returned %d, want 1\n", ret);
        asn1p_delete(asn);
        return 1;
    }
    i = first_of_severity(&cap, ASN1C_DIAG_WARNING);
    if(i < 0) {
        fprintf(stderr, "FAIL: no WARNING record from the fixer\n");
        asn1p_delete(asn);
        return 1;
    }
    if(strstr(cap.rec[i].message, "defined more than once") == NULL) {
        fprintf(stderr, "FAIL: unexpected warning text: %s\n",
                cap.rec[i].message);
        asn1p_delete(asn);
        return 1;
    }
    printf("PASS: fixer warning severity=%d message=\"%s\"\n",
           (int)cap.rec[i].severity, cap.rec[i].message);
    asn1p_delete(asn);
    return 0;
}

/* Debug notes for the tiny clean schema fit easily; keep a wide margin. */
static char legacy_text[8192];

static void
legacy_cb(int severity, const char *fmt, ...) {
    size_t used = strlen(legacy_text);
    va_list ap;

    (void)severity;
    if(used >= sizeof(legacy_text) - 1) return;
    va_start(ap, fmt);
    vsnprintf(legacy_text + used, sizeof(legacy_text) - used, fmt, ap);
    va_end(ap);
}

/* asn1f_process() keeps today's text, including the " in <src>" suffix. */
static int
check_fixer_legacy(void) {
    asn1p_t *asn;
    int ret;

    asn = asn1p_parse_buffer(unknown_type_schema, -1, "-", 1, A1P_NOFLAGS);
    if(asn == NULL) {
        fprintf(stderr, "FAIL: cannot parse the fixer schema\n");
        return 1;
    }
    legacy_text[0] = '\0';
    ret = asn1f_process(asn, A1F_NOFLAGS, legacy_cb);
    if(ret != -1) {
        fprintf(stderr, "FAIL: fixer returned %d, want -1\n", ret);
        asn1p_delete(asn);
        return 1;
    }
    if(strstr(legacy_text, "Unknown type \"U\"") == NULL) {
        fprintf(stderr, "FAIL: legacy callback lost the detail: %s\n",
                legacy_text);
        asn1p_delete(asn);
        return 1;
    }
    if(strstr(legacy_text, " in -") == NULL) {
        fprintf(stderr,
                "FAIL: legacy callback lost the file suffix: %s\n",
                legacy_text);
        asn1p_delete(asn);
        return 1;
    }
    printf("PASS: legacy callback text=\"%s\"\n", legacy_text);
    asn1p_delete(asn);
    return 0;
}

/*
 * Fixer: without a callback the internal default logger keeps printing the
 * historical "FATAL: <message> in <src>" text on stderr.
 */
static int
check_fixer_default_text(void) {
    static const char expected[] =
        "FATAL: Unknown type \"U\" referenced by \"T\" at line 3 in -\n";
    char text[STDERR_MAX];
    asn1p_t *asn;
    int saved;
    FILE *tmp;
    int ret;

    asn = asn1p_parse_buffer(unknown_type_schema, -1, "-", 1, A1P_NOFLAGS);
    if(asn == NULL) {
        fprintf(stderr, "FAIL: cannot parse the fixer schema\n");
        return 1;
    }
    if(capture_start(stderr, &saved, &tmp) != 0) {
        fprintf(stderr, "FAIL: cannot capture stderr\n");
        asn1p_delete(asn);
        return 1;
    }
    ret = asn1f_process(asn, A1F_NOFLAGS, NULL);
    capture_stop(stderr, saved, tmp, text, sizeof(text));
    asn1p_delete(asn);
    if(ret != -1) {
        fprintf(stderr, "FAIL: fixer returned %d, want -1\n", ret);
        return 1;
    }
    if(strcmp(text, expected) != 0) {
        fprintf(stderr,
                "FAIL: default fixer text is \"%s\", want \"%s\"\n",
                text, expected);
        return 1;
    }
    printf("PASS: default fixer text is pinned\n");
    return 0;
}

/*
 * The -Wdebug legacy text appends " in <src> (<C-file>:<line>)".  Pin the
 * shape but not the line number, which moves with the source.
 */
static int
has_debug_suffix(const char *text) {
    const char *p = strstr(text, " in - (");
    const char *ext;
    const char *q;

    if(p == NULL) return 0;
    p += strlen(" in - (");
    ext = strstr(p, ".c:");
    if(ext == NULL) return 0;
    /* The C-file part must belong to this note, not to an earlier one. */
    if(memchr(p, ')', (size_t)(ext - p)) != NULL) return 0;
    q = ext + 3;
    if(*q < '0' || *q > '9') return 0;
    while(*q >= '0' && *q <= '9') q++;
    return *q == ')';
}

/*
 * Fixer: A1F_DEBUG through a legacy callback keeps today's debug text,
 * including the " in <src> (<C-file>:<line>)" suffix.
 */
static int
check_fixer_debug_text(void) {
    asn1p_t *asn;
    int ret;

    asn = asn1p_parse_buffer(clean_schema, -1, "-", 1, A1P_NOFLAGS);
    if(asn == NULL) {
        fprintf(stderr, "FAIL: cannot parse the clean schema\n");
        return 1;
    }
    legacy_text[0] = '\0';
    ret = asn1f_process(asn, A1F_DEBUG, legacy_cb);
    asn1p_delete(asn);
    if(ret != 0) {
        fprintf(stderr, "FAIL: fixer returned %d, want 0\n", ret);
        return 1;
    }
    if(strstr(legacy_text, "Called with flags") == NULL) {
        fprintf(stderr, "FAIL: -Wdebug lost its call preamble: %s\n",
                legacy_text);
        return 1;
    }
    if(!has_debug_suffix(legacy_text)) {
        fprintf(stderr,
                "FAIL: -Wdebug text lacks the \"<src> (<C-file>:<line>)\" "
                "suffix: %s\n", legacy_text);
        return 1;
    }
    printf("PASS: -Wdebug legacy text keeps the (%%s:%%d) suffix shape\n");
    return 0;
}

/*
 * Fixer: A1F_DEBUG also gates the structured channel.  Without it no DEBUG
 * record is delivered; with it the preamble arrives as a record, without the
 * printed " in <src>" suffix.
 */
static int
check_fixer_debug_records(void) {
    capture_t cap;
    asn1p_t *asn;
    int i;

    asn = asn1p_parse_buffer(clean_schema, -1, "-", 1, A1P_NOFLAGS);
    if(asn == NULL) {
        fprintf(stderr, "FAIL: cannot parse the clean schema\n");
        return 1;
    }
    memset(&cap, 0, sizeof(cap));
    if(asn1f_process_diag(asn, A1F_NOFLAGS, capture_cb, &cap) != 0) {
        fprintf(stderr, "FAIL: the clean schema did not fix cleanly\n");
        asn1p_delete(asn);
        return 1;
    }
    asn1p_delete(asn);
    if(first_of_severity(&cap, ASN1C_DIAG_DEBUG) >= 0) {
        fprintf(stderr, "FAIL: debug records without A1F_DEBUG\n");
        return 1;
    }

    asn = asn1p_parse_buffer(clean_schema, -1, "-", 1, A1P_NOFLAGS);
    if(asn == NULL) {
        fprintf(stderr, "FAIL: cannot parse the clean schema\n");
        return 1;
    }
    memset(&cap, 0, sizeof(cap));
    if(asn1f_process_diag(asn, A1F_DEBUG, capture_cb, &cap) != 0) {
        fprintf(stderr, "FAIL: the clean schema did not fix cleanly\n");
        asn1p_delete(asn);
        return 1;
    }
    asn1p_delete(asn);
    i = first_of_severity(&cap, ASN1C_DIAG_DEBUG);
    if(i < 0) {
        fprintf(stderr, "FAIL: A1F_DEBUG produced no DEBUG record\n");
        return 1;
    }
    if(strstr(cap.rec[i].message, "Called with flags") == NULL) {
        fprintf(stderr, "FAIL: unexpected debug record text: %s\n",
                cap.rec[i].message);
        return 1;
    }
    if(strstr(cap.rec[i].message, " in -") != NULL) {
        fprintf(stderr,
                "FAIL: debug record keeps the file suffix: %s\n",
                cap.rec[i].message);
        return 1;
    }
    printf("PASS: A1F_DEBUG gates the structured debug records\n");
    return 0;
}

/* The finder used by both halves of the lifetime check. */static asn1p_expr_t *
find_type(asn1p_module_t *mod, const char *name) {
    asn1p_expr_t *expr;

    TQ_FOR(expr, &mod->members, next) {
        if(expr->Identifier && strcmp(expr->Identifier, name) == 0)
            return expr;
    }
    return NULL;
}

/*
 * The two-component reference "NoSuchModule.Member".  Resolving it makes the
 * lookup helper report a FATAL, which is the post-fixer diagnostic path the
 * lifetime rule must keep away from the structured channel.
 */
static asn1p_ref_t *
missing_module_ref(asn1p_module_t *mod, int lineno) {
    asn1p_ref_t *ref = asn1p_ref_new(lineno, mod);

    if(ref == NULL) return NULL;
    if(asn1p_ref_add_component(ref, "NoSuchModule", RLT_UNKNOWN)
       || asn1p_ref_add_component(ref, "Member", RLT_UNKNOWN)) {
        asn1p_ref_free(ref);
        return NULL;
    }
    return ref;
}

/*
 * The structured channel is callback-scoped to asn1f_process_diag(); the
 * legacy channel is the caller's own function and may persist.  A lookup that
 * runs after the fixer returned must therefore reach only the legacy channel.
 */
static int
check_diag_lifetime(void) {
    capture_t cap;
    asn1p_t *asn;
    asn1p_module_t *mod;
    asn1p_expr_t *expr;
    asn1p_ref_t *ref;
    asn1_namespace_t *ns;
    int before;

    /* (1) The diag channel must be dead once asn1f_process_diag() returns. */
    asn = asn1p_parse_buffer(clean_schema, -1, "-", 1, A1P_NOFLAGS);
    if(asn == NULL) {
        fprintf(stderr, "FAIL: cannot parse the clean schema\n");
        return 1;
    }
    memset(&cap, 0, sizeof(cap));
    if(asn1f_process_diag(asn, A1F_NOFLAGS, capture_cb, &cap) != 0) {
        fprintf(stderr, "FAIL: the clean schema did not fix cleanly\n");
        asn1p_delete(asn);
        return 1;
    }
    mod = TQ_FIRST(&asn->modules);
    expr = mod ? find_type(mod, "T") : NULL;
    ref = expr ? missing_module_ref(mod, expr->_lineno) : NULL;
    ns = mod ? asn1_namespace_new_from_module(mod, 0) : NULL;
    if(expr == NULL || ref == NULL || ns == NULL) {
        fprintf(stderr, "FAIL: cannot set up the post-fixer lookup\n");
        if(ref) asn1p_ref_free(ref);
        if(ns) asn1_namespace_free(ns);
        asn1p_delete(asn);
        return 1;
    }
    before = cap.count;
    (void)asn1f_lookup_symbol_ex(asn, ns, expr, ref);
    asn1_namespace_free(ns);
    asn1p_ref_free(ref);
    if(cap.count != before) {
        fprintf(stderr,
                "FAIL: a lookup after asn1f_process_diag() reached the "
                "structured callback\n");
        asn1p_delete(asn);
        return 1;
    }
    printf("PASS: the structured channel is dead after "
           "asn1f_process_diag()\n");
    asn1p_delete(asn);

    /* (2) The legacy channel may persist: it is the caller's own function. */
    asn = asn1p_parse_buffer(clean_schema, -1, "-", 1, A1P_NOFLAGS);
    if(asn == NULL) {
        fprintf(stderr, "FAIL: cannot parse the clean schema\n");
        return 1;
    }
    legacy_text[0] = '\0';
    if(asn1f_process(asn, A1F_NOFLAGS, legacy_cb) != 0) {
        fprintf(stderr, "FAIL: the clean schema did not fix cleanly\n");
        asn1p_delete(asn);
        return 1;
    }
    mod = TQ_FIRST(&asn->modules);
    expr = mod ? find_type(mod, "T") : NULL;
    ref = expr ? missing_module_ref(mod, expr->_lineno) : NULL;
    ns = mod ? asn1_namespace_new_from_module(mod, 0) : NULL;
    if(expr == NULL || ref == NULL || ns == NULL) {
        fprintf(stderr, "FAIL: cannot set up the post-fixer lookup\n");
        if(ref) asn1p_ref_free(ref);
        if(ns) asn1_namespace_free(ns);
        asn1p_delete(asn);
        return 1;
    }
    (void)asn1f_lookup_symbol_ex(asn, ns, expr, ref);
    asn1_namespace_free(ns);
    asn1p_ref_free(ref);
    if(strstr(legacy_text, "is not found") == NULL
       || strstr(legacy_text, " in -") == NULL) {
        fprintf(stderr,
                "FAIL: a lookup after asn1f_process() lost the legacy "
                "channel: %s\n", legacy_text);
        asn1p_delete(asn);
        return 1;
    }
    printf("PASS: the legacy channel survives asn1f_process()\n");
    asn1p_delete(asn);

    return 0;
}

int
main(void) {
    int failures = 0;

    failures += check_parser_diag();
    failures += check_parser_legacy();
    failures += check_parser_direct_print();
    failures += check_fixer_diag();
    failures += check_fixer_warning();
    failures += check_fixer_legacy();
    failures += check_fixer_default_text();
    failures += check_fixer_debug_text();
    failures += check_fixer_debug_records();
    failures += check_diag_lifetime();

    if(failures) {
        fprintf(stderr, "FAILED: %d check(s)\n", failures);
        return 1;
    }
    printf("All diagnostic checks passed\n");
    return 0;
}
