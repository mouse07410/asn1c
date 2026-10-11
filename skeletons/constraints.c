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
#elif defined(__GNUC__) || defined(__clang__)
static __thread int constraint_check_syntax = ATS_BER;
#elif defined(_MSC_VER)
static __declspec(thread) int constraint_check_syntax = ATS_BER;
#else
static int constraint_check_syntax = ATS_BER;
#endif

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

    arg.failed_type = 0;
    arg.failed_struct_ptr = 0;
    arg.errbuf = errbuf;
    arg.errlen = errlen ? *errlen : 0;

    constraint_check_syntax = syntax;
    ret = type_descriptor->encoding_constraints.general_constraints(
        type_descriptor, struct_ptr, _asn_i_ctfailcb, &arg);
    constraint_check_syntax = saved_syntax;
    if(ret == -1 && errlen) *errlen = arg.errlen;

    return ret;
}
