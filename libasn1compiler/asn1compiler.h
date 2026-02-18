#ifndef	ASN1_COMPILER_H
#define	ASN1_COMPILER_H

#include <asn1parser.h>

enum asn1c_flags {
	A1C_NOFLAGS,
	/*
	 * Debug the compiler.
	 */
	A1C_DEBUG		= 0x0001,
	/*
	 * Do not split the target output in several files, just print it.
	 * (Note: the output is not likely to be compilable in this case).
	 */
	A1C_PRINT_COMPILED	= 0x0002,
	/*
	 * Generate only the tables for ASN.1 types,
	 * do not emit ASN.1 parsing support code.
	 */
	A1C_OMIT_SUPPORT_CODE	= 0x0004,
	/*
	 * Use wide types by default (INTEGER_t etc) instead of native/long.
	 */
	A1C_USE_WIDE_TYPES	= 0x0008,
	/*
	 * Do not use C99 extensions.
	 */
	A1C_NO_C99		= 0x0010,
	/*
	 * Enable use of unnamed unions (non-portable feature).
	 */
	A1C_UNNAMED_UNIONS	= 0x0020,
	/*
	 * Don't make the asn1_DEF_'s of structure members "static".
	 */
	A1C_ALL_DEFS_GLOBAL	= 0x0040,
	/*
	 * Do not generate constraint checking code.
	 */
	A1C_NO_CONSTRAINTS	= 0x0080,
	/*
	 * Generate type_id_PR_member things identifiers of id_PR_member.
	 */
	A1C_COMPOUND_NAMES	= 0x0100,
	/*
	 * Do not generate courtesy #includes for external dependencies.
	 */
	A1C_NO_INCLUDE_DEPS	= 0x0200,
	/*
	 * Compile members of CHOICE as indirect pointers.
	 */
	A1C_INDIRECT_CHOICE	= 0x0400,
	/*
	 * -flink-skeletons
	 * Symlink support files rather than copy them.
	 */
	A1C_LINK_SKELETONS	= 0x0800,

	/*
	 * -pdu={all|auto|Type}
	 * Generate PDU table
	 */
	A1C_PDU_ALL			= 0x2000,
	A1C_PDU_AUTO		= 0x4000,
	A1C_PDU_TYPE		= 0x8000,
	/*
	 * -fincludes-quoted
	 * Avoid generating #include <foo>, generate "foo" instead.
	 */
	A1C_INCLUDES_QUOTED	= 0x10000,
	/*
	 * -fline-refs
	 * Include ASN.1 module's line numbers in comments.
	 */
	A1C_LINE_REFS       = 0x20000,
	/*
	 * -gen-OER / -no-gen-OER
	 * Generate Octet Encoding Rules support code
	 */
	A1C_GEN_OER			= 0x40000,
	/*
	 * -gen-UPER / -no-gen-UPER
	 * Generate Unaligned Packed Encoding Rules support code
	 */
	A1C_GEN_UPER			= 0x80000,
	/*
	 * -gen-example / -no-gen-example
	 * Generate converter-example.c and converter-example.mk
	 */
	A1C_GEN_EXAMPLE			= 0x100000,
	/*
	 * Generate top-level configure.ac and Makefile.am
	 */
	A1C_GEN_AUTOTOOLS_EXAMPLE	= 0x200000,
	/*
	 * Print the source of generated lines.
	 * -debug-output-origin-lines
	 */
	A1C_DEBUG_OUTPUT_ORIGIN_LINES = 0x400000,
	/*
	 * -gen-BER / -no-gen-BER
	 * Generate Basic Encoding Rules support code
	 */
	A1C_GEN_BER			= 0x800000,
	/*
	 * -gen-XER / -no-gen-XER
	 * Generate XML Encoding Rules support code
	 */
	A1C_GEN_XER			= 0x1000000,
	/*
	 * -gen-print / -no-gen-print
	 * Generate print code
	 */
	A1C_GEN_PRINT			= 0x2000000,
	/*
	 * -gen-random-fill / -no-gen-random-fill
	 * Generate random fill code
	 */
	A1C_GEN_RFILL			= 0x4000000,
	/*
	 * -gen-APER / -no-gen-APER
	 * Generate Aligned Packed Encoding Rules support code
	 */
	A1C_GEN_APER			= 0x8000000,
	/*
	 * -gen-JER / -no-gen-JER
	 * Generate JSON Encoding Rules support code
	 */
	A1C_GEN_JER                     = 0x100000000,
	/*
	 * -gen-CBOR / -no-gen-CBOR
	 * Generate Concise Binary Object Representation support code
	 */
	A1C_GEN_CBOR                    = 0x200000000,
	/*
	 * -fgen-only-pdu-deps
	 * Generate code only for PDU dependencies
	 */
	A1C_GEN_ONLY_PDU_DEPS           = 0x400000000,
	/*
	 * -flist-deps
	 * List PDU dependencies without generating code
	 */
	A1C_LIST_DEPS                   = 0x800000000,
};

/*
 * Compile the ASN.1 specification.
 */
int asn1_compile(asn1p_t *asn, const char *datadir, const char *destdir, enum asn1c_flags,
	int argc, int optc, char **argv, int complex_threshold);

void asn1c_debug_type_naming(asn1p_t *asn, enum asn1c_flags,
                             char **asn_type_names);

void asn1c__add_pdu_type(const char *typename);

void asn1c_prefix_set(const char *prefix);
const char* asn1c_prefix_get(void);

int asn1c_attach_streams(asn1p_expr_t *expr);

#endif	/* ASN1_COMPILER_H */
