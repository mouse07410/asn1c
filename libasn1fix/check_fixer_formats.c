#include "asn1fix_internal.h"
#include "asn1p_list.h"

/* state variable: last fatal diagnostic captured by the test logger. */
static char fatal_message[256];

/*
 * Capture a fatal diagnostic for the runtime regression. The inputs are the
 * severity, printf format, and its arguments. Returns nothing and throws no
 * exceptions. Added by the asn1c maintainers for PR #621 on 2026-11-25.
 * Example: install capture_diagnostic as the error and debug callback.
 */
static void
capture_diagnostic(int severity, const char *format, ...) {
    if(severity > 0) {
        va_list args;
        va_start(args, format);
        vsnprintf(fatal_message, sizeof(fatal_message), format, args);
        va_end(args);
    }
}

/*
 * Check formatted diagnostics and the expression-name table. No inputs or
 * exceptions. Returns zero on success, one on a regression. Added by the
 * asn1c maintainers for PR #621 on 2026-11-25. Automake runs this executable
 * and compiles it with each negative test macro to verify format checking.
 */
int
main(void) {
    asn1p_value_t value = {.type = ATV_TRUE};
    asn1p_expr_t element = {
        .Identifier = "named", .expr_type = A1TC_UNIVERVAL, .value = &value, ._lineno = 7
    };
    asn1p_expr_t integer = {.Identifier = "Example", .expr_type = ASN_BASIC_INTEGER};
    asn1p_module_t module = {0};
    arg_t context = {.mod = &module, .expr = &integer, .eh = capture_diagnostic};
    arg_t *arg = &context;

    /* The negative compile checks exercise both decorated callback fields. */
#if defined(CHECK_BAD_DEBUG)
    arg->debug(-1, "Count: %u", "text");
#elif defined(CHECK_BAD_FATAL)
    arg->eh(1, "Count: %u", "text");
#endif

    /* The INTEGER error must render the actual element name and source line. */
    TQ_INIT(&integer.members);
    TQ_ADD(&integer.members, &element, next);
    for(int debug = 0; debug <= 1; debug++) {
        arg->debug = debug ? capture_diagnostic : NULL;
        fatal_message[0] = '\0';
        if(asn1f_fix_integer(arg) != -1
        || strstr(fatal_message, "INTEGER Example at line 7: Value for the identifier named") == NULL) {
            fprintf(stderr, "Unexpected INTEGER diagnostic: %s\n", fatal_message);
            return 1;
        }
    }

    /* Sparse and invalid enum values have no printable type name. */
    const char *name = ASN_EXPR_TYPE2STR(ASN_BASIC_INTEGER);
    if(!name || strcmp(name, "INTEGER") != 0
    || ASN_EXPR_TYPE2STR(A1TC_EXTENSIBLE) != NULL
    || ASN_EXPR_TYPE2STR((asn1p_expr_type_e)-1) != NULL) {
        fputs("Unexpected expression type name\n", stderr);
        return 1;
    }
    return 0;
}
