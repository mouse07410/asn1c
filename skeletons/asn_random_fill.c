/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <asn_random_fill.h>
#include <constr_TYPE.h>
#include <stdlib.h>

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_THREADS__)
static thread_local int random_fill_syntax = ATS_BER;
#elif defined(__GNUC__) || defined(__clang__)
static __thread int random_fill_syntax = ATS_BER;
#elif defined(_MSC_VER)
static __declspec(thread) int random_fill_syntax = ATS_BER;
#else
static int random_fill_syntax = ATS_BER;
#endif

int
asn_random_fill(const struct asn_TYPE_descriptor_s *td, void **struct_ptr,
                size_t length) {
    return asn_random_fill_with_syntax(td, struct_ptr, length, ATS_BER);
}

int
asn_random_fill_with_syntax(const struct asn_TYPE_descriptor_s *td,
                            void **struct_ptr, size_t length, int syntax) {
    int saved_syntax = random_fill_syntax;
    int result;

    random_fill_syntax = syntax;
    if(td && td->op->random_fill) {
        asn_random_fill_result_t res =
            td->op->random_fill(td, struct_ptr, 0, length);
        result = (res.code == ARFILL_OK) ? 0 : -1;
    } else {
        result = -1;
    }
    random_fill_syntax = saved_syntax;
    return result;
}

int
asn_random_fill_current_syntax(void) {
    return random_fill_syntax;
}

static uintmax_t
asn__intmax_range(intmax_t lb, intmax_t ub) {
    assert(lb <= ub);
    if((ub < 0) == (lb < 0)) {
        return ub - lb;
    } else if(lb < 0) {
        return 1 + ((uintmax_t)ub + (uintmax_t)-(lb + 1));
    } else {
        assert(!"Unreachable");
        return 0;
    }
}

intmax_t
asn_random_between(intmax_t lb, intmax_t rb) {
    if(lb == rb) {
        return lb;
    } else {
        const uintmax_t intmax_max = ((~(uintmax_t)0) >> 1);
        uintmax_t range = asn__intmax_range(lb, rb);
        uintmax_t value = 0;
        uintmax_t got_entropy = 0;
        (void)intmax_max;
        int max = 0xffffff;

#ifdef __WIN32__
        max = RAND_MAX-1;
#endif

        assert(RAND_MAX > max);    /* Seen 7ffffffd! */
        assert(range < intmax_max);

        for(; got_entropy < range;) {
            got_entropy = (got_entropy << 24) | max;
#ifdef HAVE_RANDOM
            value = (value << 24) | (random() % max);
#else
            value = (value << 24) | (rand() % max);
#endif
        }

        return lb + (intmax_t)(value % (range + 1));
    }
}
