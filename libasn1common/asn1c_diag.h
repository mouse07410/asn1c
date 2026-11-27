/*
 * A small diagnostic record shared by the core libraries.
 *
 * The fixer's diagnostics, and the parser errors that yyerror() reports, can
 * go to a keyed callback instead of being printed to stderr.  This is not a
 * complete capture of parser output: warnings that the grammar actions and the
 * lexer print directly still go to stderr and never reach the callback.
 * Every pointer in a record is borrowed: it is valid only for the duration of
 * the callback, and a caller that needs to keep a string must copy it.
 *
 * A zero line/column and a NULL file/token always mean "unknown"; they are
 * never a guess.  The column is carried here but is 0 until the lexer tracks
 * it, and the token is filled by the parser only.
 */
#ifndef	ASN1C_DIAG_H
#define	ASN1C_DIAG_H

/*
 * Numeric values match the severity convention the fixer and the compiler
 * loggers already use: -1 debug, 0 warning, 1 error.
 */
typedef enum {
    ASN1C_DIAG_DEBUG = -1,
    ASN1C_DIAG_WARNING = 0,
    ASN1C_DIAG_ERROR = 1
} asn1c_diag_severity;

typedef struct {
    asn1c_diag_severity severity;
    const char *file;     /* NULL when unknown; callback-scoped */
    int line;             /* 0 when unknown */
    int column;           /* 0 when unknown */
    const char *token;    /* NULL when unknown; callback-scoped */
    const char *message;  /* formatted once; callback-scoped */
} asn1c_diag_t;

typedef void (*asn1c_diag_cb)(void *key, const asn1c_diag_t *diag);

#endif	/* ASN1C_DIAG_H */
