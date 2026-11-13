/*
 * Test XER formatting regression tests for:
 * 1. Nested SEQUENCE closing tag indentation (should align with opening tag)
 * 2. Empty SEQUENCE_OF/SET_OF spacing (no spaces between tags)
 * 3. Primitive type closing tags (no extra spaces before closing tag)
 * 4. Value-list (as_XMLValueList) formatting for SET OF / SEQUENCE OF:
 *    mode 1 (NULL, ENUMERATED) and mode 2 (CHOICE), with exact bytes
 *    including newlines, indentation and trailing-space separator lines.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <asn_internal.h>
#include <xer_encoder.h>
#include <INTEGER.h>
#include <OCTET_STRING.h>
#include <VisibleString.h>
#include <NULL.h>
#include <NativeEnumerated.h>
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>
#include <constr_SEQUENCE_OF.h>
#include <constr_SET_OF.h>
#include <constr_CHOICE.h>

/* Inner SEQUENCE structure */
typedef struct InnerSeq {
    INTEGER_t innerField;
} InnerSeq_t;

static asn_TYPE_member_t asn_MBR_InnerSeq_1[] = {
    {
        .flags = 0,
        .name = "innerField",
        .type = &asn_DEF_INTEGER,
        .memb_offset = offsetof(InnerSeq_t, innerField),
    },
};

static const ber_tlv_tag_t asn_DEF_InnerSeq_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};

static const asn_TYPE_tag2member_t asn_MAP_InnerSeq_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 0, 0, 0 }
};

static asn_SEQUENCE_specifics_t asn_SPC_InnerSeq_specs_1 = {
    .struct_size = sizeof(InnerSeq_t),
    .ctx_offset = 0,
    .tag2el = asn_MAP_InnerSeq_tag2el_1,
    .tag2el_count = 1,
    .first_extension = -1
};

static asn_TYPE_descriptor_t asn_DEF_InnerSeq = {
    .name = "InnerSeq",
    .xml_tag = "InnerSeq",
    .op = &asn_OP_SEQUENCE,
    .tags = asn_DEF_InnerSeq_tags_1,
    .tags_count = 1,
    .elements = asn_MBR_InnerSeq_1,
    .elements_count = 1,
    .specifics = &asn_SPC_InnerSeq_specs_1
};

/* SEQUENCE OF INTEGER */
typedef struct IntList {
    struct {
        INTEGER_t **array;
        int count;
        int size;
        void (*free)(INTEGER_t *);
    } list;
    asn_struct_ctx_t _asn_ctx;
} IntList_t;

static asn_TYPE_member_t asn_MBR_IntList_1[] = {
    {
        .flags = 0,
        .name = "",
        .type = &asn_DEF_INTEGER,
    },
};

static const ber_tlv_tag_t asn_DEF_IntList_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};

static asn_SET_OF_specifics_t asn_SPC_IntList_specs_1 = {
    .struct_size = sizeof(IntList_t),
    .ctx_offset = offsetof(IntList_t, _asn_ctx),
};

static asn_TYPE_descriptor_t asn_DEF_IntList = {
    .name = "IntList",
    .xml_tag = "IntList",
    .op = &asn_OP_SEQUENCE_OF,
    .tags = asn_DEF_IntList_tags_1,
    .tags_count = 1,
    .elements = asn_MBR_IntList_1,
    .elements_count = 1,
    .specifics = &asn_SPC_IntList_specs_1
};

/* Outer test structure */
typedef struct TestStruct {
    INTEGER_t primitiveField;
    InnerSeq_t *nestedSeq;
    IntList_t *emptyList;
    IntList_t *filledList;
} TestStruct_t;

static asn_TYPE_member_t asn_MBR_TestStruct_1[] = {
    {
        .flags = 0,
        .name = "primitiveField",
        .type = &asn_DEF_INTEGER,
        .memb_offset = offsetof(TestStruct_t, primitiveField),
    },
    {
        .flags = ATF_POINTER,
        .optional = 0,
        .name = "nestedSeq",
        .type = &asn_DEF_InnerSeq,
        .memb_offset = offsetof(TestStruct_t, nestedSeq),
    },
    {
        .flags = ATF_POINTER,
        .optional = 1,
        .name = "emptyList",
        .type = &asn_DEF_IntList,
        .memb_offset = offsetof(TestStruct_t, emptyList),
    },
    {
        .flags = ATF_POINTER,
        .optional = 1,
        .name = "filledList",
        .type = &asn_DEF_IntList,
        .memb_offset = offsetof(TestStruct_t, filledList),
    },
};

static const ber_tlv_tag_t asn_DEF_TestStruct_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};

static const asn_TYPE_tag2member_t asn_MAP_TestStruct_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 0, 0, 0 },
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 1, 0, 2 },
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 2, -1, 1 },
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 3, -2, 0 }
};

static asn_SEQUENCE_specifics_t asn_SPC_TestStruct_specs_1 = {
    .struct_size = sizeof(TestStruct_t),
    .ctx_offset = 0,
    .tag2el = asn_MAP_TestStruct_tag2el_1,
    .tag2el_count = 4,
    .first_extension = -1
};

static asn_TYPE_descriptor_t asn_DEF_TestStruct = {
    .name = "TestStruct",
    .xml_tag = "TestStruct",
    .op = &asn_OP_SEQUENCE,
    .tags = asn_DEF_TestStruct_tags_1,
    .tags_count = 1,
    .elements = asn_MBR_TestStruct_1,
    .elements_count = 4,
    .specifics = &asn_SPC_TestStruct_specs_1
};

/* Buffer to capture XER output */
struct xer_buffer {
    char *buffer;
    size_t buffer_size;
    size_t allocated_size;
};

static int
xer_buffer_append(const void *buffer, size_t size, void *app_key) {
    struct xer_buffer *xb = app_key;
    
    while(xb->buffer_size + size + 1 > xb->allocated_size) {
        size_t new_size = 2 * (xb->allocated_size ? xb->allocated_size : 256);
        char *new_buf = MALLOC(new_size);
        if(!new_buf) return -1;
        if(xb->buffer) {
            memcpy(new_buf, xb->buffer, xb->buffer_size);
            FREEMEM(xb->buffer);
        }
        xb->buffer = new_buf;
        xb->allocated_size = new_size;
    }
    
    memcpy(xb->buffer + xb->buffer_size, buffer, size);
    xb->buffer_size += size;
    xb->buffer[xb->buffer_size] = '\0';
    return 0;
}

/* Test 1: Primitive field should have no spaces before closing tag */
static void
test_primitive_no_spaces(void) {
    printf("Test 1: Primitive field closing tag formatting...\n");
    
    TestStruct_t test;
    InnerSeq_t inner;
    struct xer_buffer xb = {0, 0, 0};
    asn_enc_rval_t er;
    
    memset(&test, 0, sizeof(test));
    memset(&inner, 0, sizeof(inner));
    
    asn_long2INTEGER(&test.primitiveField, 42);
    asn_long2INTEGER(&inner.innerField, 99);
    test.nestedSeq = &inner;
    
    er = xer_encode(&asn_DEF_TestStruct, &test, XER_F_BASIC, xer_buffer_append, &xb);
    assert(er.encoded > 0);
    
    printf("Output:\n%s\n", xb.buffer);
    
    /* Check that primitive field closing tag has no spaces before it */
    /* Looking for pattern: <primitiveField>42</primitiveField> (no spaces between 42 and </) */
    char *primitive = strstr(xb.buffer, "42</primitiveField>");
    if(!primitive) {
        fprintf(stderr, "FAIL: Primitive field has extra spaces before closing tag!\n");
        fprintf(stderr, "Expected: <primitiveField>42</primitiveField>\n");
        FREEMEM(xb.buffer);
        exit(1);
    }
    
    /* Also check that primitive closing tag is followed by newline */
    char *primitive_close = strstr(xb.buffer, "</primitiveField>");
    assert(primitive_close != NULL);
    if(primitive_close[strlen("</primitiveField>")] != '\n') {
        fprintf(stderr, "FAIL: Primitive closing tag not followed by newline!\n");
        FREEMEM(xb.buffer);
        exit(1);
    }
    
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_INTEGER, &test.primitiveField);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_INTEGER, &inner.innerField);
    FREEMEM(xb.buffer);
    
    printf("PASS: Primitive field correctly formatted\n\n");
}

/* Test 2: Nested SEQUENCE closing tag should be indented to align with opening tag */
static void
test_nested_indentation(void) {
    printf("Test 2: Nested SEQUENCE closing tag indentation...\n");
    
    TestStruct_t test;
    InnerSeq_t inner;
    struct xer_buffer xb = {0, 0, 0};
    asn_enc_rval_t er;
    
    memset(&test, 0, sizeof(test));
    memset(&inner, 0, sizeof(inner));
    
    asn_long2INTEGER(&test.primitiveField, 42);
    asn_long2INTEGER(&inner.innerField, 99);
    test.nestedSeq = &inner;
    
    er = xer_encode(&asn_DEF_TestStruct, &test, XER_F_BASIC, xer_buffer_append, &xb);
    assert(er.encoded > 0);
    
    printf("Output:\n%s\n", xb.buffer);
    
    /* Check that nested SEQUENCE closing tag is indented correctly */
    /* Should be:    <nestedSeq>\n        <innerField>99</innerField>\n    </nestedSeq> */
    /* NOT:          <nestedSeq>\n        <innerField>99</innerField>\n        </nestedSeq> */
    
    /* Find the nestedSeq closing tag */
    char *nested_close = strstr(xb.buffer, "</nestedSeq>");
    assert(nested_close != NULL);
    
    /* Check indentation: should have 4 spaces before </nestedSeq> (1 level) */
    /* The pattern should be: \n    </nestedSeq> */
    /* Find the newline before the closing tag */
    char *newline_before = nested_close - 1;
    while(newline_before > xb.buffer && *newline_before != '\n') {
        newline_before--;
    }
    
    if(*newline_before != '\n') {
        fprintf(stderr, "FAIL: No newline before nested SEQUENCE closing tag!\n");
        FREEMEM(xb.buffer);
        exit(1);
    }
    
    /* Count spaces between newline and closing tag */
    int spaces = nested_close - newline_before - 1;
    if(spaces != 4) {
        fprintf(stderr, "FAIL: Nested SEQUENCE closing tag has %d spaces, expected 4!\n", spaces);
        fprintf(stderr, "Got: '");
        for(char *p = newline_before; p < nested_close + 13; p++) {
            if(*p == '\n') fprintf(stderr, "\\n");
            else if(*p == ' ') fprintf(stderr, "_");
            else fprintf(stderr, "%c", *p);
        }
        fprintf(stderr, "'\n");
        FREEMEM(xb.buffer);
        exit(1);
    }
    
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_INTEGER, &test.primitiveField);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_INTEGER, &inner.innerField);
    FREEMEM(xb.buffer);
    
    printf("PASS: Nested SEQUENCE closing tag correctly indented\n\n");
}

/* Test 3: Empty SEQUENCE_OF should have no spaces between tags */
static void
test_empty_list_no_spaces(void) {
    printf("Test 3: Empty SEQUENCE_OF spacing...\n");
    
    TestStruct_t test;
    InnerSeq_t inner;
    IntList_t empty_list;
    struct xer_buffer xb = {0, 0, 0};
    asn_enc_rval_t er;
    
    memset(&test, 0, sizeof(test));
    memset(&inner, 0, sizeof(inner));
    memset(&empty_list, 0, sizeof(empty_list));
    
    asn_long2INTEGER(&test.primitiveField, 42);
    asn_long2INTEGER(&inner.innerField, 99);
    test.nestedSeq = &inner;
    
    /* Set empty list */
    empty_list.list.count = 0;
    empty_list.list.array = NULL;
    test.emptyList = &empty_list;
    
    er = xer_encode(&asn_DEF_TestStruct, &test, XER_F_BASIC, xer_buffer_append, &xb);
    assert(er.encoded > 0);
    
    printf("Output:\n%s\n", xb.buffer);
    
    /* Check that empty list has no spaces between tags */
    /* Should be: <emptyList></emptyList> */
    /* NOT: <emptyList>        </emptyList> or <emptyList>\n    </emptyList> */
    char *empty_tag = strstr(xb.buffer, "<emptyList></emptyList>");
    if(!empty_tag) {
        fprintf(stderr, "FAIL: Empty list has spaces between tags!\n");
        fprintf(stderr, "Expected: <emptyList></emptyList>\n");
        
        /* Show what we have */
        char *start = strstr(xb.buffer, "<emptyList>");
        if(start) {
            char *end = strstr(start, "</emptyList>");
            if(end) {
                fprintf(stderr, "Got: '");
                for(char *p = start; p <= end + strlen("</emptyList>") - 1; p++) {
                    if(*p == '\n') fprintf(stderr, "\\n");
                    else if(*p == ' ') fprintf(stderr, "_");
                    else fprintf(stderr, "%c", *p);
                }
                fprintf(stderr, "'\n");
            }
        }
        FREEMEM(xb.buffer);
        exit(1);
    }
    
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_INTEGER, &test.primitiveField);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_INTEGER, &inner.innerField);
    FREEMEM(xb.buffer);
    
    printf("PASS: Empty list has no spaces between tags\n\n");
}

/* Test 4: Filled SEQUENCE_OF should have proper indentation */
static void
test_filled_list_indentation(void) {
    printf("Test 4: Filled SEQUENCE_OF indentation...\n");
    
    TestStruct_t test;
    InnerSeq_t inner;
    IntList_t filled_list;
    INTEGER_t int1, int2;
    INTEGER_t *int_array[2];
    struct xer_buffer xb = {0, 0, 0};
    asn_enc_rval_t er;
    
    memset(&test, 0, sizeof(test));
    memset(&inner, 0, sizeof(inner));
    memset(&filled_list, 0, sizeof(filled_list));
    memset(&int1, 0, sizeof(int1));
    memset(&int2, 0, sizeof(int2));
    
    asn_long2INTEGER(&test.primitiveField, 42);
    asn_long2INTEGER(&inner.innerField, 99);
    test.nestedSeq = &inner;
    
    /* Set filled list */
    asn_long2INTEGER(&int1, 10);
    asn_long2INTEGER(&int2, 20);
    int_array[0] = &int1;
    int_array[1] = &int2;
    filled_list.list.count = 2;
    filled_list.list.array = int_array;
    test.filledList = &filled_list;
    
    er = xer_encode(&asn_DEF_TestStruct, &test, XER_F_BASIC, xer_buffer_append, &xb);
    assert(er.encoded > 0);
    
    printf("Output:\n%s\n", xb.buffer);
    
    /* Check that filled list closing tag is indented correctly */
    /* The pattern should be: \n    </filledList> (4 spaces) */
    char *filled_close = strstr(xb.buffer, "</filledList>");
    assert(filled_close != NULL);
    
    /* Find the newline before the closing tag */
    char *newline_before = filled_close - 1;
    while(newline_before > xb.buffer && *newline_before != '\n') {
        newline_before--;
    }
    
    if(*newline_before != '\n') {
        fprintf(stderr, "FAIL: No newline before filled list closing tag!\n");
        FREEMEM(xb.buffer);
        exit(1);
    }
    
    /* Count spaces between newline and closing tag */
    int spaces = filled_close - newline_before - 1;
    if(spaces != 4) {
        fprintf(stderr, "FAIL: Filled list closing tag has %d spaces, expected 4!\n", spaces);
        FREEMEM(xb.buffer);
        exit(1);
    }
    
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_INTEGER, &test.primitiveField);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_INTEGER, &inner.innerField);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_INTEGER, &int1);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_INTEGER, &int2);
    FREEMEM(xb.buffer);
    
    printf("PASS: Filled list closing tag correctly indented\n\n");
}

/* ======================================================================
 * Value-list XER formatting (as_XMLValueList), exact-byte assertions.
 *
 * as_XMLValueList == 1: SET OF / SEQUENCE OF of simple values (NULL,
 * ENUMERATED, ...), each encoded as an empty tag on its own line.
 * as_XMLValueList == 2: SET OF / SEQUENCE OF CHOICE, with blank
 * separator lines indented to the container's level.
 * ==================================================================== */

/*
 * Collection storage shared by all value-list descriptors below. The XER
 * encoder only reads list.array/list.count, so the exact element C type
 * does not matter for these tests.
 */
typedef struct ValueList {
    struct {
        void **array;
        int count;
        int size;
        void (*free)(void *);
    } list;
    asn_struct_ctx_t _asn_ctx;
} ValueList_t;

static void
value_list_init(ValueList_t *vl, void **array, int count) {
    memset(vl, 0, sizeof(*vl));
    vl->list.array = count ? array : NULL;
    vl->list.count = count;
}

/* --- SET OF NULL and SEQUENCE OF NULL (mode 1) ---------------------- */

static asn_TYPE_member_t asn_MBR_SetOfNullVL_1[] = {
    {
        .flags = 0,
        .name = "",
        .type = &asn_DEF_NULL,
    },
};

static asn_SET_OF_specifics_t asn_SPC_SetOfNullVL_specs = {
    .struct_size = sizeof(ValueList_t),
    .ctx_offset = offsetof(ValueList_t, _asn_ctx),
    .as_XMLValueList = 1,
};

static const ber_tlv_tag_t asn_DEF_SetOfNullVL_tags[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (17 << 2))
};

static asn_TYPE_descriptor_t asn_DEF_SetOfNullVL = {
    .name = "SetOfNullVL",
    .xml_tag = "SetOfNullVL",
    .op = &asn_OP_SET_OF,
    .tags = asn_DEF_SetOfNullVL_tags,
    .tags_count = 1,
    .elements = asn_MBR_SetOfNullVL_1,
    .elements_count = 1,
    .specifics = &asn_SPC_SetOfNullVL_specs,
};

static asn_TYPE_member_t asn_MBR_SeqOfNullVL_1[] = {
    {
        .flags = 0,
        .name = "",
        .type = &asn_DEF_NULL,
    },
};

static asn_SET_OF_specifics_t asn_SPC_SeqOfNullVL_specs = {
    .struct_size = sizeof(ValueList_t),
    .ctx_offset = offsetof(ValueList_t, _asn_ctx),
    .as_XMLValueList = 1,
};

static const ber_tlv_tag_t asn_DEF_SeqOfNullVL_tags[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};

static asn_TYPE_descriptor_t asn_DEF_SeqOfNullVL = {
    .name = "SeqOfNullVL",
    .xml_tag = "SeqOfNullVL",
    .op = &asn_OP_SEQUENCE_OF,
    .tags = asn_DEF_SeqOfNullVL_tags,
    .tags_count = 1,
    .elements = asn_MBR_SeqOfNullVL_1,
    .elements_count = 1,
    .specifics = &asn_SPC_SeqOfNullVL_specs,
};

/* --- SET OF ENUMERATED and SEQUENCE OF ENUMERATED (mode 1) ---------- */

static const asn_INTEGER_enum_map_t asn_MAP_TestEnumVL_value2enum[] = {
    { 0, 3, "one" },
    { 1, 7, "oneMore" },
};

static asn_INTEGER_specifics_t asn_SPC_TestEnumVL_specs = {
    .value2enum = asn_MAP_TestEnumVL_value2enum,
    .map_count = 2,
    .extension = 0,
    .strict_enumeration = 0,
};

static asn_TYPE_descriptor_t asn_DEF_TestEnumVL = {
    .name = "TestEnumVL",
    .xml_tag = "TestEnumVL",
    .op = &asn_OP_NativeEnumerated,
    .specifics = &asn_SPC_TestEnumVL_specs,
};

static asn_TYPE_member_t asn_MBR_SetOfEnumVL_1[] = {
    {
        .flags = 0,
        .name = "",
        .type = &asn_DEF_TestEnumVL,
    },
};

static asn_SET_OF_specifics_t asn_SPC_SetOfEnumVL_specs = {
    .struct_size = sizeof(ValueList_t),
    .ctx_offset = offsetof(ValueList_t, _asn_ctx),
    .as_XMLValueList = 1,
};

static const ber_tlv_tag_t asn_DEF_SetOfEnumVL_tags[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (17 << 2))
};

static asn_TYPE_descriptor_t asn_DEF_SetOfEnumVL = {
    .name = "SetOfEnumVL",
    .xml_tag = "SetOfEnumVL",
    .op = &asn_OP_SET_OF,
    .tags = asn_DEF_SetOfEnumVL_tags,
    .tags_count = 1,
    .elements = asn_MBR_SetOfEnumVL_1,
    .elements_count = 1,
    .specifics = &asn_SPC_SetOfEnumVL_specs,
};

static asn_TYPE_member_t asn_MBR_SeqOfEnumVL_1[] = {
    {
        .flags = 0,
        .name = "",
        .type = &asn_DEF_TestEnumVL,
    },
};

static asn_SET_OF_specifics_t asn_SPC_SeqOfEnumVL_specs = {
    .struct_size = sizeof(ValueList_t),
    .ctx_offset = offsetof(ValueList_t, _asn_ctx),
    .as_XMLValueList = 1,
};

static const ber_tlv_tag_t asn_DEF_SeqOfEnumVL_tags[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};

static asn_TYPE_descriptor_t asn_DEF_SeqOfEnumVL = {
    .name = "SeqOfEnumVL",
    .xml_tag = "SeqOfEnumVL",
    .op = &asn_OP_SEQUENCE_OF,
    .tags = asn_DEF_SeqOfEnumVL_tags,
    .tags_count = 1,
    .elements = asn_MBR_SeqOfEnumVL_1,
    .elements_count = 1,
    .specifics = &asn_SPC_SeqOfEnumVL_specs,
};

/* --- SET OF CHOICE and SEQUENCE OF CHOICE (mode 2) ------------------ */

typedef enum TestChoiceVL_PR {
    TestChoiceVL_PR_NOTHING,
    TestChoiceVL_PR_a,
    TestChoiceVL_PR_b
} TestChoiceVL_PR;

typedef struct TestChoiceVL {
    TestChoiceVL_PR present;
    union {
        NULL_t a;
        long b;
    } choice;
    asn_struct_ctx_t _asn_ctx;
} TestChoiceVL_t;

static asn_TYPE_member_t asn_MBR_TestChoiceVL_1[] = {
    {
        .flags = 0,
        .name = "a",
        .type = &asn_DEF_NULL,
        .memb_offset = offsetof(TestChoiceVL_t, choice.a),
    },
    {
        .flags = 0,
        .name = "b",
        .type = &asn_DEF_NativeInteger,
        .memb_offset = offsetof(TestChoiceVL_t, choice.b),
    },
};

static asn_CHOICE_specifics_t asn_SPC_TestChoiceVL_specs = {
    .struct_size = sizeof(TestChoiceVL_t),
    .ctx_offset = offsetof(TestChoiceVL_t, _asn_ctx),
    .pres_offset = offsetof(TestChoiceVL_t, present),
    .pres_size = sizeof(((TestChoiceVL_t *)0)->present),
    .ext_start = -1,
};

static asn_TYPE_descriptor_t asn_DEF_TestChoiceVL = {
    .name = "TestChoiceVL",
    .xml_tag = "TestChoiceVL",
    .op = &asn_OP_CHOICE,
    .elements = asn_MBR_TestChoiceVL_1,
    .elements_count = 2,
    .specifics = &asn_SPC_TestChoiceVL_specs,
};

static asn_TYPE_member_t asn_MBR_SetOfChoiceVL_1[] = {
    {
        .flags = 0,
        .name = "",
        .type = &asn_DEF_TestChoiceVL,
    },
};

static asn_SET_OF_specifics_t asn_SPC_SetOfChoiceVL_specs = {
    .struct_size = sizeof(ValueList_t),
    .ctx_offset = offsetof(ValueList_t, _asn_ctx),
    .as_XMLValueList = 2,
};

static const ber_tlv_tag_t asn_DEF_SetOfChoiceVL_tags[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (17 << 2))
};

static asn_TYPE_descriptor_t asn_DEF_SetOfChoiceVL = {
    .name = "SetOfChoiceVL",
    .xml_tag = "SetOfChoiceVL",
    .op = &asn_OP_SET_OF,
    .tags = asn_DEF_SetOfChoiceVL_tags,
    .tags_count = 1,
    .elements = asn_MBR_SetOfChoiceVL_1,
    .elements_count = 1,
    .specifics = &asn_SPC_SetOfChoiceVL_specs,
};

static asn_TYPE_member_t asn_MBR_SeqOfChoiceVL_1[] = {
    {
        .flags = 0,
        .name = "",
        .type = &asn_DEF_TestChoiceVL,
    },
};

static asn_SET_OF_specifics_t asn_SPC_SeqOfChoiceVL_specs = {
    .struct_size = sizeof(ValueList_t),
    .ctx_offset = offsetof(ValueList_t, _asn_ctx),
    .as_XMLValueList = 2,
};

static const ber_tlv_tag_t asn_DEF_SeqOfChoiceVL_tags[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};

static asn_TYPE_descriptor_t asn_DEF_SeqOfChoiceVL = {
    .name = "SeqOfChoiceVL",
    .xml_tag = "SeqOfChoiceVL",
    .op = &asn_OP_SEQUENCE_OF,
    .tags = asn_DEF_SeqOfChoiceVL_tags,
    .tags_count = 1,
    .elements = asn_MBR_SeqOfChoiceVL_1,
    .elements_count = 1,
    .specifics = &asn_SPC_SeqOfChoiceVL_specs,
};

/* --- PDU holding the value lists, plus one nested holder ------------ */

typedef struct NestedValueList {
    ValueList_t *innerSetOfNull;
    ValueList_t *innerSetOfChoice;
} NestedValueList_t;

static asn_TYPE_member_t asn_MBR_NestedValueList_1[] = {
    {
        .flags = ATF_POINTER,
        .optional = 1,
        .name = "innerSetOfNull",
        .type = &asn_DEF_SetOfNullVL,
        .memb_offset = offsetof(NestedValueList_t, innerSetOfNull),
    },
    {
        .flags = ATF_POINTER,
        .optional = 1,
        .name = "innerSetOfChoice",
        .type = &asn_DEF_SetOfChoiceVL,
        .memb_offset = offsetof(NestedValueList_t, innerSetOfChoice),
    },
};

static asn_SEQUENCE_specifics_t asn_SPC_NestedValueList_specs = {
    .struct_size = sizeof(NestedValueList_t),
    .ctx_offset = 0,
    .tag2el = 0,
    .tag2el_count = 0,
    .first_extension = -1,
};

static asn_TYPE_descriptor_t asn_DEF_NestedValueList = {
    .name = "NestedValueList",
    .xml_tag = "NestedValueList",
    .op = &asn_OP_SEQUENCE,
    .elements = asn_MBR_NestedValueList_1,
    .elements_count = 2,
    .specifics = &asn_SPC_NestedValueList_specs,
};

typedef struct VListPDU {
    ValueList_t *setOfNull;
    ValueList_t *seqOfNull;
    ValueList_t *setOfEnum;
    ValueList_t *seqOfEnum;
    ValueList_t *setOfChoice;
    ValueList_t *seqOfChoice;
    NestedValueList_t *nested;
} VListPDU_t;

static asn_TYPE_member_t asn_MBR_VListPDU_1[] = {
    {
        .flags = ATF_POINTER,
        .optional = 1,
        .name = "setOfNull",
        .type = &asn_DEF_SetOfNullVL,
        .memb_offset = offsetof(VListPDU_t, setOfNull),
    },
    {
        .flags = ATF_POINTER,
        .optional = 1,
        .name = "seqOfNull",
        .type = &asn_DEF_SeqOfNullVL,
        .memb_offset = offsetof(VListPDU_t, seqOfNull),
    },
    {
        .flags = ATF_POINTER,
        .optional = 1,
        .name = "setOfEnum",
        .type = &asn_DEF_SetOfEnumVL,
        .memb_offset = offsetof(VListPDU_t, setOfEnum),
    },
    {
        .flags = ATF_POINTER,
        .optional = 1,
        .name = "seqOfEnum",
        .type = &asn_DEF_SeqOfEnumVL,
        .memb_offset = offsetof(VListPDU_t, seqOfEnum),
    },
    {
        .flags = ATF_POINTER,
        .optional = 1,
        .name = "setOfChoice",
        .type = &asn_DEF_SetOfChoiceVL,
        .memb_offset = offsetof(VListPDU_t, setOfChoice),
    },
    {
        .flags = ATF_POINTER,
        .optional = 1,
        .name = "seqOfChoice",
        .type = &asn_DEF_SeqOfChoiceVL,
        .memb_offset = offsetof(VListPDU_t, seqOfChoice),
    },
    {
        .flags = ATF_POINTER,
        .optional = 1,
        .name = "nested",
        .type = &asn_DEF_NestedValueList,
        .memb_offset = offsetof(VListPDU_t, nested),
    },
};

static asn_SEQUENCE_specifics_t asn_SPC_VListPDU_specs = {
    .struct_size = sizeof(VListPDU_t),
    .ctx_offset = 0,
    .tag2el = 0,
    .tag2el_count = 0,
    .first_extension = -1,
};

static asn_TYPE_descriptor_t asn_DEF_VListPDU = {
    .name = "VListPDU",
    .xml_tag = "VListPDU",
    .op = &asn_OP_SEQUENCE,
    .elements = asn_MBR_VListPDU_1,
    .elements_count = 7,
    .specifics = &asn_SPC_VListPDU_specs,
};

/* Dump a string making spaces and line ends visible. */
static void
dump_value_list_bytes(const char *tag, const char *s) {
    fprintf(stderr, "%s (space='_', EOL='$'):\n", tag);
    for(; *s; s++) {
        if(*s == '\n') {
            fputs("$\n", stderr);
        } else if(*s == ' ') {
            fputc('_', stderr);
        } else if(*s == '\t') {
            fputs("\\t", stderr);
        } else {
            fputc(*s, stderr);
        }
    }
    fputc('\n', stderr);
}

static void
expect_value_list_xer(const asn_TYPE_descriptor_t *td, const void *sptr,
                      const char *label, const char *expected) {
    struct xer_buffer xb = {0, 0, 0};
    asn_enc_rval_t er;

    er = xer_encode(td, sptr, XER_F_BASIC, xer_buffer_append, &xb);
    if(er.encoded <= 0 || !xb.buffer) {
        fprintf(stderr, "FAIL [%s]: xer_encode() failed (%ld)\n",
                label, (long)er.encoded);
        FREEMEM(xb.buffer);
        exit(1);
    }

    if(strcmp(xb.buffer, expected) != 0) {
        fprintf(stderr, "FAIL [%s]: value-list XER bytes differ\n", label);
        dump_value_list_bytes("expected", expected);
        dump_value_list_bytes("actual", xb.buffer);
        FREEMEM(xb.buffer);
        exit(1);
    }

    FREEMEM(xb.buffer);
    printf("PASS: %s\n", label);
}

/* 4a: SET OF NULL, 0/1/2 elements */
static void
test_value_list_setof_null(void) {
    VListPDU_t pdu;
    ValueList_t list;
    NULL_t n1 = 0, n2 = 0;
    void *array[2] = { &n1, &n2 };

    memset(&pdu, 0, sizeof(pdu));
    pdu.setOfNull = &list;

    value_list_init(&list, NULL, 0);
    expect_value_list_xer(&asn_DEF_VListPDU, &pdu,
        "SET OF NULL, 0 elements",
        "<VListPDU>\n"
        "    <setOfNull></setOfNull>\n"
        "</VListPDU>\n");

    value_list_init(&list, array, 1);
    expect_value_list_xer(&asn_DEF_VListPDU, &pdu,
        "SET OF NULL, 1 element",
        "<VListPDU>\n"
        "    <setOfNull>\n"
        "            <NULL/>\n"
        "    </setOfNull>\n"
        "</VListPDU>\n");

    value_list_init(&list, array, 2);
    expect_value_list_xer(&asn_DEF_VListPDU, &pdu,
        "SET OF NULL, 2 elements",
        "<VListPDU>\n"
        "    <setOfNull>\n"
        "            <NULL/>\n"
        "            <NULL/>\n"
        "    </setOfNull>\n"
        "</VListPDU>\n");
}

/* 4b: SEQUENCE OF NULL, 0/1/2 elements */
static void
test_value_list_seqof_null(void) {
    VListPDU_t pdu;
    ValueList_t list;
    NULL_t n1 = 0, n2 = 0;
    void *array[2] = { &n1, &n2 };

    memset(&pdu, 0, sizeof(pdu));
    pdu.seqOfNull = &list;

    value_list_init(&list, NULL, 0);
    expect_value_list_xer(&asn_DEF_VListPDU, &pdu,
        "SEQUENCE OF NULL, 0 elements",
        "<VListPDU>\n"
        "    <seqOfNull></seqOfNull>\n"
        "</VListPDU>\n");

    value_list_init(&list, array, 1);
    expect_value_list_xer(&asn_DEF_VListPDU, &pdu,
        "SEQUENCE OF NULL, 1 element",
        "<VListPDU>\n"
        "    <seqOfNull>\n"
        "            <NULL/>\n"
        "    </seqOfNull>\n"
        "</VListPDU>\n");

    value_list_init(&list, array, 2);
    expect_value_list_xer(&asn_DEF_VListPDU, &pdu,
        "SEQUENCE OF NULL, 2 elements",
        "<VListPDU>\n"
        "    <seqOfNull>\n"
        "            <NULL/>\n"
        "            <NULL/>\n"
        "    </seqOfNull>\n"
        "</VListPDU>\n");
}

/* 4c: SET OF ENUMERATED and SEQUENCE OF ENUMERATED, 2 elements */
static void
test_value_list_enumerated(void) {
    VListPDU_t pdu;
    ValueList_t list;
    long e1 = 0, e2 = 1;
    void *array[2] = { &e1, &e2 };

    memset(&pdu, 0, sizeof(pdu));

    pdu.setOfEnum = &list;
    value_list_init(&list, array, 2);
    expect_value_list_xer(&asn_DEF_VListPDU, &pdu,
        "SET OF ENUMERATED, 2 elements",
        "<VListPDU>\n"
        "    <setOfEnum>\n"
        "            <one/>\n"
        "            <oneMore/>\n"
        "    </setOfEnum>\n"
        "</VListPDU>\n");
    pdu.setOfEnum = NULL;

    pdu.seqOfEnum = &list;
    value_list_init(&list, array, 2);
    expect_value_list_xer(&asn_DEF_VListPDU, &pdu,
        "SEQUENCE OF ENUMERATED, 2 elements",
        "<VListPDU>\n"
        "    <seqOfEnum>\n"
        "            <one/>\n"
        "            <oneMore/>\n"
        "    </seqOfEnum>\n"
        "</VListPDU>\n");
    pdu.seqOfEnum = NULL;
}

/* 4d: SET OF CHOICE (mode 2), 1 and 2 elements */
static void
test_value_list_setof_choice(void) {
    VListPDU_t pdu;
    ValueList_t list;
    TestChoiceVL_t c1, c2;
    void *array[2] = { &c1, &c2 };

    memset(&pdu, 0, sizeof(pdu));
    memset(&c1, 0, sizeof(c1));
    memset(&c2, 0, sizeof(c2));
    c1.present = TestChoiceVL_PR_a;
    c2.present = TestChoiceVL_PR_b;
    c2.choice.b = 1;

    pdu.setOfChoice = &list;

    value_list_init(&list, array, 1);
    expect_value_list_xer(&asn_DEF_VListPDU, &pdu,
        "SET OF CHOICE, 1 element",
        "<VListPDU>\n"
        "    <setOfChoice>\n"
        "        <a></a>\n"
        "    \n"
        "    </setOfChoice>\n"
        "</VListPDU>\n");

    value_list_init(&list, array, 2);
    expect_value_list_xer(&asn_DEF_VListPDU, &pdu,
        "SET OF CHOICE, 2 elements",
        "<VListPDU>\n"
        "    <setOfChoice>\n"
        "        <a></a>\n"
        "    \n"
        "        <b>1</b>\n"
        "    \n"
        "    </setOfChoice>\n"
        "</VListPDU>\n");
}

/* 4e: SEQUENCE OF CHOICE (mode 2), 2 elements */
static void
test_value_list_seqof_choice(void) {
    VListPDU_t pdu;
    ValueList_t list;
    TestChoiceVL_t c1, c2;
    void *array[2] = { &c1, &c2 };

    memset(&pdu, 0, sizeof(pdu));
    memset(&c1, 0, sizeof(c1));
    memset(&c2, 0, sizeof(c2));
    c1.present = TestChoiceVL_PR_a;
    c2.present = TestChoiceVL_PR_b;
    c2.choice.b = 1;

    pdu.seqOfChoice = &list;
    value_list_init(&list, array, 2);
    expect_value_list_xer(&asn_DEF_VListPDU, &pdu,
        "SEQUENCE OF CHOICE, 2 elements",
        "<VListPDU>\n"
        "    <seqOfChoice>\n"
        "        <a></a>\n"
        "    \n"
        "        <b>1</b>\n"
        "    \n"
        "    </seqOfChoice>\n"
        "</VListPDU>\n");
}

/*
 * 4f-2: SEQUENCE OF CHOICE whose alternative is a named SET OF.
 *
 * Models check-42's
 *     vparts SEQUENCE OF VariablePart
 *     VariablePart ::= CHOICE { vset SET OF VisibleString, ... }
 * The nested SET OF is a regular structured member of the CHOICE. Mode 2
 * passes the container's content level to the element encoder, so the
 * alternative and its member are nested one level below the container, and
 * a container-level blank separator line follows each element.
 */
typedef struct TestChoiceVSet {
    enum {
        TestChoiceVSet_PR_NOTHING,
        TestChoiceVSet_PR_vset
    } present;
    union TestChoiceVSet_u {
        ValueList_t vset;
    } choice;
    asn_struct_ctx_t _asn_ctx;
} TestChoiceVSet_t;

static asn_TYPE_member_t asn_MBR_VSet_1[] = {
    {
        .flags = 0,
        .name = "",
        .type = &asn_DEF_VisibleString,
        .memb_offset = 0,
    },
};

static asn_SET_OF_specifics_t asn_SPC_VSet_specs = {
    .struct_size = sizeof(ValueList_t),
    .ctx_offset = offsetof(ValueList_t, _asn_ctx),
    .as_XMLValueList = 0,
};

static asn_TYPE_descriptor_t asn_DEF_VSet = {
    .name = "VSet",
    .xml_tag = "VSet",
    .op = &asn_OP_SET_OF,
    .elements = asn_MBR_VSet_1,
    .elements_count = 1,
    .specifics = &asn_SPC_VSet_specs,
};

static asn_TYPE_member_t asn_MBR_TestChoiceVSet_1[] = {
    {
        .flags = 0,
        .name = "vset",
        .type = &asn_DEF_VSet,
        .memb_offset = offsetof(TestChoiceVSet_t, choice.vset),
    },
};

static asn_CHOICE_specifics_t asn_SPC_TestChoiceVSet_specs = {
    .struct_size = sizeof(TestChoiceVSet_t),
    .ctx_offset = offsetof(TestChoiceVSet_t, _asn_ctx),
    .pres_offset = offsetof(TestChoiceVSet_t, present),
    .pres_size = sizeof(((TestChoiceVSet_t *)0)->present),
    .ext_start = -1,
};

static asn_TYPE_descriptor_t asn_DEF_TestChoiceVSet = {
    .name = "TestChoiceVSet",
    .xml_tag = "TestChoiceVSet",
    .op = &asn_OP_CHOICE,
    .elements = asn_MBR_TestChoiceVSet_1,
    .elements_count = 1,
    .specifics = &asn_SPC_TestChoiceVSet_specs,
};

static asn_TYPE_member_t asn_MBR_SeqOfChoiceVSet_1[] = {
    {
        .flags = 0,
        .name = "",
        .type = &asn_DEF_TestChoiceVSet,
    },
};

static asn_SET_OF_specifics_t asn_SPC_SeqOfChoiceVSet_specs = {
    .struct_size = sizeof(ValueList_t),
    .ctx_offset = offsetof(ValueList_t, _asn_ctx),
    .as_XMLValueList = 2,
};

static const ber_tlv_tag_t asn_DEF_SeqOfChoiceVSet_tags[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};

static asn_TYPE_descriptor_t asn_DEF_SeqOfChoiceVSet = {
    .name = "SeqOfChoiceVSet",
    .xml_tag = "SeqOfChoiceVSet",
    .op = &asn_OP_SEQUENCE_OF,
    .tags = asn_DEF_SeqOfChoiceVSet_tags,
    .tags_count = 1,
    .elements = asn_MBR_SeqOfChoiceVSet_1,
    .elements_count = 1,
    .specifics = &asn_SPC_SeqOfChoiceVSet_specs,
};

typedef struct VSetPDU {
    ValueList_t *vparts;
    asn_struct_ctx_t _asn_ctx;
} VSetPDU_t;

static asn_TYPE_member_t asn_MBR_VSetPDU_1[] = {
    {
        .flags = ATF_POINTER,
        .name = "vparts",
        .type = &asn_DEF_SeqOfChoiceVSet,
        .memb_offset = offsetof(VSetPDU_t, vparts),
    },
};

static asn_SEQUENCE_specifics_t asn_SPC_VSetPDU_specs = {
    .struct_size = sizeof(VSetPDU_t),
    .ctx_offset = offsetof(VSetPDU_t, _asn_ctx),
};

static asn_TYPE_descriptor_t asn_DEF_VSetPDU = {
    .name = "VSetPDU",
    .xml_tag = "VSetPDU",
    .op = &asn_OP_SEQUENCE,
    .elements = asn_MBR_VSetPDU_1,
    .elements_count = 1,
    .specifics = &asn_SPC_VSetPDU_specs,
};

static void
test_value_list_seqof_choice_named_setof(void) {
    VSetPDU_t pdu;
    ValueList_t vparts;
    TestChoiceVSet_t choice;
    VisibleString_t value;
    void *vparts_array[1] = { &choice };
    void *vset_array[1] = { &value };

    memset(&pdu, 0, sizeof(pdu));
    memset(&choice, 0, sizeof(choice));
    memset(&value, 0, sizeof(value));

    value.buf = (uint8_t *)"123";
    value.size = 3;

    choice.present = TestChoiceVSet_PR_vset;
    value_list_init(&choice.choice.vset, vset_array, 1);

    pdu.vparts = &vparts;
    value_list_init(&vparts, vparts_array, 1);

    expect_value_list_xer(&asn_DEF_VSetPDU, &pdu,
        "SEQUENCE OF CHOICE with named SET OF",
        "<VSetPDU>\n"
        "    <vparts>\n"
        "        <vset>\n"
        "            <VisibleString>123</VisibleString>\n"
        "        </vset>\n"
        "    \n"
        "    </vparts>\n"
        "</VSetPDU>\n");
}

/*
 * 4f-3: SET OF CHOICE whose alternative is a named SET OF.
 *
 * SET OF counterpart of the shape above:
 *     setOfVSet SET OF VariablePart
 *     VariablePart ::= CHOICE { vset SET OF VisibleString, ... }
 * The SET OF mode-2 element is passed the container's content level, so the
 * named SET OF stays normally nested inside the alternative.
 */
static asn_TYPE_member_t asn_MBR_SetOfChoiceVSet_1[] = {
    {
        .flags = 0,
        .name = "",
        .type = &asn_DEF_TestChoiceVSet,
    },
};

static asn_SET_OF_specifics_t asn_SPC_SetOfChoiceVSet_specs = {
    .struct_size = sizeof(ValueList_t),
    .ctx_offset = offsetof(ValueList_t, _asn_ctx),
    .as_XMLValueList = 2,
};

static const ber_tlv_tag_t asn_DEF_SetOfChoiceVSet_tags[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (17 << 2))
};

static asn_TYPE_descriptor_t asn_DEF_SetOfChoiceVSet = {
    .name = "SetOfChoiceVSet",
    .xml_tag = "SetOfChoiceVSet",
    .op = &asn_OP_SET_OF,
    .tags = asn_DEF_SetOfChoiceVSet_tags,
    .tags_count = 1,
    .elements = asn_MBR_SetOfChoiceVSet_1,
    .elements_count = 1,
    .specifics = &asn_SPC_SetOfChoiceVSet_specs,
};

typedef struct SetVSetPDU {
    ValueList_t *setOfVSet;
    asn_struct_ctx_t _asn_ctx;
} SetVSetPDU_t;

static asn_TYPE_member_t asn_MBR_SetVSetPDU_1[] = {
    {
        .flags = ATF_POINTER,
        .name = "setOfVSet",
        .type = &asn_DEF_SetOfChoiceVSet,
        .memb_offset = offsetof(SetVSetPDU_t, setOfVSet),
    },
};

static asn_SEQUENCE_specifics_t asn_SPC_SetVSetPDU_specs = {
    .struct_size = sizeof(SetVSetPDU_t),
    .ctx_offset = offsetof(SetVSetPDU_t, _asn_ctx),
};

static asn_TYPE_descriptor_t asn_DEF_SetVSetPDU = {
    .name = "SetVSetPDU",
    .xml_tag = "SetVSetPDU",
    .op = &asn_OP_SEQUENCE,
    .elements = asn_MBR_SetVSetPDU_1,
    .elements_count = 1,
    .specifics = &asn_SPC_SetVSetPDU_specs,
};

static void
test_value_list_setof_choice_named_setof(void) {
    SetVSetPDU_t pdu;
    ValueList_t setOfVSet;
    TestChoiceVSet_t choice;
    VisibleString_t value;
    void *set_array[1] = { &choice };
    void *vset_array[1] = { &value };

    memset(&pdu, 0, sizeof(pdu));
    memset(&choice, 0, sizeof(choice));
    memset(&value, 0, sizeof(value));

    value.buf = (uint8_t *)"123";
    value.size = 3;

    choice.present = TestChoiceVSet_PR_vset;
    value_list_init(&choice.choice.vset, vset_array, 1);

    pdu.setOfVSet = &setOfVSet;
    value_list_init(&setOfVSet, set_array, 1);

    expect_value_list_xer(&asn_DEF_SetVSetPDU, &pdu,
        "SET OF CHOICE with named SET OF",
        "<SetVSetPDU>\n"
        "    <setOfVSet>\n"
        "        <vset>\n"
        "            <VisibleString>123</VisibleString>\n"
        "        </vset>\n"
        "    \n"
        "    </setOfVSet>\n"
        "</SetVSetPDU>\n");
}

/* 4f: nested value list (SET OF NULL inside a nested SEQUENCE) */
static void
test_value_list_nested(void) {
    VListPDU_t pdu;
    NestedValueList_t nested;
    ValueList_t list;
    NULL_t n1 = 0, n2 = 0;
    void *array[2] = { &n1, &n2 };

    memset(&pdu, 0, sizeof(pdu));
    memset(&nested, 0, sizeof(nested));

    value_list_init(&list, array, 2);
    nested.innerSetOfNull = &list;
    pdu.nested = &nested;

    expect_value_list_xer(&asn_DEF_VListPDU, &pdu,
        "nested SET OF NULL, 2 elements",
        "<VListPDU>\n"
        "    <nested>\n"
        "        <innerSetOfNull>\n"
        "                <NULL/>\n"
        "                <NULL/>\n"
        "        </innerSetOfNull>\n"
        "    </nested>\n"
        "</VListPDU>\n");
}

/* 4g: nested SET OF CHOICE (mode 2) pins the ilevel - 1 separator level */
static void
test_value_list_nested_choice(void) {
    VListPDU_t pdu;
    NestedValueList_t nested;
    ValueList_t list;
    TestChoiceVL_t c1, c2;
    void *array[2] = { &c1, &c2 };

    memset(&pdu, 0, sizeof(pdu));
    memset(&nested, 0, sizeof(nested));
    memset(&c1, 0, sizeof(c1));
    memset(&c2, 0, sizeof(c2));
    c1.present = TestChoiceVL_PR_a;
    c2.present = TestChoiceVL_PR_b;
    c2.choice.b = 1;

    value_list_init(&list, array, 2);
    nested.innerSetOfChoice = &list;
    pdu.nested = &nested;

    expect_value_list_xer(&asn_DEF_VListPDU, &pdu,
        "nested SET OF CHOICE, 2 elements (depth 2)",
        "<VListPDU>\n"
        "    <nested>\n"
        "        <innerSetOfChoice>\n"
        "            <a></a>\n"
        "        \n"
        "            <b>1</b>\n"
        "        \n"
        "        </innerSetOfChoice>\n"
        "    </nested>\n"
        "</VListPDU>\n");
}

int
main(void) {
    test_primitive_no_spaces();
    test_nested_indentation();
    test_empty_list_no_spaces();
    test_filled_list_indentation();
    test_value_list_setof_null();
    test_value_list_seqof_null();
    test_value_list_enumerated();
    test_value_list_setof_choice();
    test_value_list_seqof_choice();
    test_value_list_seqof_choice_named_setof();
    test_value_list_setof_choice_named_setof();
    test_value_list_nested();
    test_value_list_nested_choice();
    
    printf("========================================\n");
    printf("All XER formatting regression tests PASSED\n");
    printf("========================================\n");
    
    return 0;
}
