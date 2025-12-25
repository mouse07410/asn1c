#include <asn_internal.h>

#if ASN_EMIT_DEBUG == 1 && __STDC_VERSION__ >= 199901L && !defined(ASN_THREAD_SAFE)
int asn_debug_indent = 0;
#endif

/*
 * Thread-local encoding recursion depth counter for preventing stack overflow.
 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_THREADS__)
/* C11 thread support */
thread_local int asn1_encoding_depth = 0;
#elif defined(__GNUC__) || defined(__clang__)
/* GCC/Clang thread-local extension */
__thread int asn1_encoding_depth = 0;
#elif defined(_MSC_VER)
/* MSVC thread-local */
__declspec(thread) int asn1_encoding_depth = 0;
#else
/* No thread-local support, use regular variable (not thread-safe) */
int asn1_encoding_depth = 0;
#endif

ssize_t
asn__format_to_callback(int (*cb)(const void *, size_t, void *key), void *key,
                        const char *fmt, ...) {
    char scratch[64];
    char *buf = scratch;
    size_t buf_size = sizeof(scratch);
    int wrote;
    int cb_ret;

    do {
        va_list args;
        va_start(args, fmt);

        wrote = vsnprintf(buf, buf_size, fmt, args);
        va_end(args);
        if(wrote < (ssize_t)buf_size) {
            if(wrote < 0) {
                if(buf != scratch) FREEMEM(buf);
                return -1;
            }
            break;
        }

        buf_size <<= 1;
        if(buf == scratch) {
            buf = MALLOC(buf_size);
            if(!buf) {
              return -1;
            }
        } else {
            void *p = REALLOC(buf, buf_size);
            if(!p) {
                FREEMEM(buf);
                return -1;
            }
            buf = p;
        }
    } while(1);

    cb_ret = cb(buf, wrote, key);
    if(buf != scratch) FREEMEM(buf);
    if(cb_ret < 0) {
        return -1;
    }

    return wrote;
}

