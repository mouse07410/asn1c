/*
 * Test that empty or NULL names/type_names in XER encoding do not cause crashes.
 */
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <asn_internal.h>

/*
 * Test helper to verify asn_is_meta_syntax_keyword handles edge cases
 */
static void
test_asn_is_meta_syntax_keyword_edge_cases(void) {
    printf("Testing asn_is_meta_syntax_keyword with edge cases...\n");
    
    /* NULL pointer should return 0 */
    assert(asn_is_meta_syntax_keyword(NULL) == 0);
    printf("  NULL: OK\n");
    
    /* Empty string should return 0 */
    assert(asn_is_meta_syntax_keyword("") == 0);
    printf("  Empty string: OK\n");
    
    /* Normal strings should work */
    assert(asn_is_meta_syntax_keyword("SEQUENCE OF") == 1);
    printf("  'SEQUENCE OF': OK (meta-syntax)\n");
    
    assert(asn_is_meta_syntax_keyword("SET OF") == 1);
    printf("  'SET OF': OK (meta-syntax)\n");
    
    assert(asn_is_meta_syntax_keyword("NormalName") == 0);
    printf("  'NormalName': OK (not meta-syntax)\n");
    
    printf("asn_is_meta_syntax_keyword edge case tests: PASSED\n\n");
}

/*
 * Test that strlen is safe with NULL-checked inputs
 */
static void
test_strlen_with_empty_strings(void) {
    printf("Testing strlen with empty strings...\n");
    
    const char *empty = "";
    const char *normal = "test";
    size_t len;
    
    /* Empty string should return 0 */
    len = strlen(empty);
    assert(len == 0);
    printf("  strlen(\"\"): %zu OK\n", len);
    
    /* Normal string */
    len = strlen(normal);
    assert(len == 4);
    printf("  strlen(\"test\"): %zu OK\n", len);
    
    printf("strlen tests: PASSED\n\n");
}

/*
 * Simulate the pattern used in OPEN_TYPE_xer.c
 */
static void
test_open_type_xer_pattern(void) {
    printf("Testing OPEN_TYPE_xer.c pattern with edge cases...\n");
    
    /* Test 1: Normal case */
    {
        const char *type_name = "ValidType";
        size_t type_name_len = strlen(type_name);
        int skip_wrapper = asn_is_meta_syntax_keyword(type_name);
        if(skip_wrapper) {
            type_name_len = 0;
        }
        assert(type_name_len == 9);
        assert(skip_wrapper == 0);
        printf("  Normal type name: OK (len=%zu, skip=%d)\n", type_name_len, skip_wrapper);
    }
    
    /* Test 2: Meta-syntax keyword */
    {
        const char *type_name = "SEQUENCE OF";
        size_t type_name_len = strlen(type_name);
        int skip_wrapper = asn_is_meta_syntax_keyword(type_name);
        if(skip_wrapper) {
            type_name_len = 0;
        }
        assert(type_name_len == 0);
        assert(skip_wrapper == 1);
        printf("  Meta-syntax keyword: OK (len=%zu, skip=%d)\n", type_name_len, skip_wrapper);
    }
    
    /* Test 3: Empty string (edge case) */
    {
        const char *type_name = "";
        size_t type_name_len = strlen(type_name);
        int skip_wrapper = asn_is_meta_syntax_keyword(type_name);
        if(skip_wrapper) {
            type_name_len = 0;
        }
        assert(type_name_len == 0);
        assert(skip_wrapper == 0);
        printf("  Empty string: OK (len=%zu, skip=%d)\n", type_name_len, skip_wrapper);
    }
    
    printf("OPEN_TYPE_xer.c pattern tests: PASSED\n\n");
}

/*
 * Simulate the pattern used in constr_CHOICE_xer.c
 */
static void
test_choice_xer_pattern(void) {
    printf("Testing constr_CHOICE_xer.c pattern with edge cases...\n");
    
    /* Test 1: Normal case */
    {
        const char *mname = "choiceMember";
        unsigned int mlen = mname ? strlen(mname) : 0;
        int skip_wrapper = asn_is_meta_syntax_keyword(mname);
        if(skip_wrapper) {
            mlen = 0;
        }
        assert(mlen == 12);
        assert(skip_wrapper == 0);
        printf("  Normal member name: OK (len=%u, skip=%d)\n", mlen, skip_wrapper);
    }
    
    /* Test 2: NULL pointer */
    {
        const char *mname = NULL;
        unsigned int mlen = mname ? strlen(mname) : 0;
        int skip_wrapper = asn_is_meta_syntax_keyword(mname);
        if(skip_wrapper) {
            mlen = 0;
        }
        assert(mlen == 0);
        assert(skip_wrapper == 0);
        printf("  NULL pointer: OK (len=%u, skip=%d)\n", mlen, skip_wrapper);
    }
    
    /* Test 3: Empty string */
    {
        const char *mname = "";
        unsigned int mlen = mname ? strlen(mname) : 0;
        int skip_wrapper = asn_is_meta_syntax_keyword(mname);
        if(skip_wrapper) {
            mlen = 0;
        }
        assert(mlen == 0);
        assert(skip_wrapper == 0);
        printf("  Empty string: OK (len=%u, skip=%d)\n", mlen, skip_wrapper);
    }
    
    /* Test 4: Meta-syntax keyword */
    {
        const char *mname = "SET OF";
        unsigned int mlen = mname ? strlen(mname) : 0;
        int skip_wrapper = asn_is_meta_syntax_keyword(mname);
        if(skip_wrapper) {
            mlen = 0;
        }
        assert(mlen == 0);
        assert(skip_wrapper == 1);
        printf("  Meta-syntax keyword: OK (len=%u, skip=%d)\n", mlen, skip_wrapper);
    }
    
    printf("constr_CHOICE_xer.c pattern tests: PASSED\n\n");
}

int
main() {
    printf("========================================\n");
    printf("XER Empty Names Edge Case Tests\n");
    printf("========================================\n\n");
    
    test_asn_is_meta_syntax_keyword_edge_cases();
    test_strlen_with_empty_strings();
    test_open_type_xer_pattern();
    test_choice_xer_pattern();
    
    printf("========================================\n");
    printf("All tests PASSED\n");
    printf("========================================\n");
    
    return 0;
}
