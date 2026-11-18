#include <asn_internal.h>
#include <constraints.h>

int
asn_generic_no_constraint(const asn_TYPE_descriptor_t *type_descriptor,
                          const void *struct_ptr,
                          asn_app_constraint_failed_f *cb, void *key) {
    (void)type_descriptor;	/* Unused argument */
	(void)struct_ptr;	/* Unused argument */
	(void)cb;	/* Unused argument */
	(void)key;	/* Unused argument */

	/* Nothing to check */
	return 0;
}

int
asn_generic_unknown_constraint(const asn_TYPE_descriptor_t *type_descriptor,
                               const void *struct_ptr,
                               asn_app_constraint_failed_f *cb, void *key) {
    (void)type_descriptor;	/* Unused argument */
	(void)struct_ptr;	/* Unused argument */
	(void)cb;	/* Unused argument */
	(void)key;	/* Unused argument */

	/* Unknown how to check */
	return 0;
}

struct errbufDesc {
    const asn_TYPE_descriptor_t *failed_type;
    const void *failed_struct_ptr;
	char *errbuf;
	size_t errlen;
};

static void
CC_PRINTFLIKE(4, 5)
_asn_i_ctfailcb(void *key, const asn_TYPE_descriptor_t *td, const void *sptr,
                const char *fmt, ...) {
    struct errbufDesc *arg = key;
	va_list ap;
	ssize_t vlen;
	ssize_t maxlen;

	arg->failed_type = td;
	arg->failed_struct_ptr = sptr;

	maxlen = arg->errlen;
	if(maxlen <= 0)
		return;

	va_start(ap, fmt);
	vlen = vsnprintf(arg->errbuf, maxlen, fmt, ap);
	va_end(ap);
	if(vlen >= maxlen) {
		arg->errbuf[maxlen-1] = '\0';	/* Ensuring libc correctness */
		arg->errlen = maxlen - 1;	/* Not counting termination */
		return;
	} else if(vlen >= 0) {
		arg->errbuf[vlen] = '\0';	/* Ensuring libc correctness */
		arg->errlen = vlen;		/* Not counting termination */
	} else {
		/*
		 * The libc on this system is broken.
		 */
		vlen = sizeof("<broken vsnprintf>") - 1;
		maxlen--;
		arg->errlen = vlen < maxlen ? vlen : maxlen;
		memcpy(arg->errbuf, "<broken vsnprintf>", arg->errlen);
		arg->errbuf[arg->errlen] = 0;
	}

	return;
}

int
asn_check_constraints(const asn_TYPE_descriptor_t *type_descriptor,
                      const void *struct_ptr, char *errbuf, size_t *errlen) {
    return asn_check_constraints_with_syntax(type_descriptor, struct_ptr,
                                             ATS_BER, errbuf, errlen);
}

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_THREADS__)
static thread_local int constraint_check_syntax = ATS_BER;
static thread_local int constraint_check_decoding; /* state variable. */
static thread_local unsigned constraint_check_depth; /* state variable. */
#elif defined(__GNUC__) || defined(__clang__)
static __thread int constraint_check_syntax = ATS_BER;
static __thread int constraint_check_decoding; /* state variable. */
static __thread unsigned constraint_check_depth; /* state variable. */
#elif defined(_MSC_VER)
static __declspec(thread) int constraint_check_syntax = ATS_BER;
static __declspec(thread) int constraint_check_decoding; /* state variable. */
static __declspec(thread) unsigned constraint_check_depth; /* state variable. */
#else
static int constraint_check_syntax = ATS_BER;
static int constraint_check_decoding; /* state variable. */
static unsigned constraint_check_depth; /* state variable. */
#endif

/*
 * Identify validation of successful decoder output, including skipped additions.
 * Source: codec-boundary policy. Version/date: 2026-11-17. Inputs: none.
 * Returns nonzero within decoded-value checks; exceptions: none.
 * Responsible: asn1c maintainers. History: preserve standard extension skipping.
 * Example: CHOICE_constraint permits decoder-produced skipped extensions.
 */
int
asn_check_constraints_is_decoding(void) {
    return constraint_check_decoding;
}

/*
 * Identify both basic and canonical PER variants during constraint validation.
 * Source: transfer-syntax enum. Version/date: 2026-11-17. Inputs: none.
 * Returns nonzero for either alignment of PER; no exceptions.
 * Responsible: asn1c maintainers. History: preserve canonical extension relay.
 * Example: ATS_ALIGNED_CANONICAL_PER returns nonzero inside a constraint check.
 */
int
asn_check_constraints_is_per(void) {
    return constraint_check_syntax == ATS_UNALIGNED_BASIC_PER
        || constraint_check_syntax == ATS_UNALIGNED_CANONICAL_PER
        || constraint_check_syntax == ATS_ALIGNED_BASIC_PER
        || constraint_check_syntax == ATS_ALIGNED_CANONICAL_PER;
}

/*
 * Identify both basic and canonical OER during decoded-value validation.
 * Source: transfer-syntax enum. Version/date: 2026-11-17. Inputs: none.
 * Returns nonzero for either OER variant; no exceptions.
 * Responsible: asn1c maintainers. History: preserve skipped extension validation.
 * Example: ATS_CANONICAL_OER is recognized as OER rather than a different family.
 */
int
asn_check_constraints_is_oer(void) {
    return constraint_check_syntax == ATS_BASIC_OER
        || constraint_check_syntax == ATS_CANONICAL_OER;
}

int
asn_check_constraints_current_syntax(void) {
    return constraint_check_syntax;
}

int
asn_check_constraints_with_syntax(
    const asn_TYPE_descriptor_t *type_descriptor, const void *struct_ptr,
    int syntax, char *errbuf, size_t *errlen) {
    struct errbufDesc arg;
    int saved_syntax = constraint_check_syntax;
    int ret;

    /* Nested CONTAINING checks start fresh decoders; bound their total depth. */
    if(!type_descriptor || !type_descriptor->encoding_constraints.general_constraints
       || constraint_check_depth >= 64) return -1;
    ++constraint_check_depth;
    arg.failed_type = 0;
    arg.failed_struct_ptr = 0;
    arg.errbuf = errbuf;
    arg.errlen = errlen ? *errlen : 0;

    constraint_check_syntax = syntax;
    ret = type_descriptor->encoding_constraints.general_constraints(
        type_descriptor, struct_ptr, _asn_i_ctfailcb, &arg);
    constraint_check_syntax = saved_syntax;
    --constraint_check_depth;
    if(ret == -1 && errlen) *errlen = arg.errlen;

    return ret;
}

/*
 * Check a completed root without touching partial values or their ownership.
 * Source: asn1c constraint API. Version/date: 2026-11-17.
 * Parameters: td/sptr identify the decoded value; syntax selects CONTAINING;
 * result supplies the status and consumed count in the caller's native units.
 * Returns the original result, or RC_FAIL after unsuccessful validation.
 * Exceptions: none. Responsible: asn1c maintainers. History: strict policy.
 * Example: a BER INTEGER outside its ASN.1 range changes RC_OK to RC_FAIL.
 */
asn_dec_rval_t
asn_check_decoded_constraints(const asn_TYPE_descriptor_t *td, void **sptr,
                              int syntax, asn_dec_rval_t result) {
    int saved_decoding = constraint_check_decoding;
    /* Partial streaming values must remain resumable until RC_OK. */
    if(result.code != RC_OK) return result;
    constraint_check_decoding = 1;
    if(!sptr || !*sptr
       || asn_check_constraints_with_syntax(td, *sptr, syntax, NULL, NULL))
        result.code = RC_FAIL;
    constraint_check_decoding = saved_decoding;
    return result;
}
