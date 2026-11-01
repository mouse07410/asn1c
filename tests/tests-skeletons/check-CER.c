/*
 * Exercise Canonical Encoding Rules against fixed X.690 wire vectors.
 * Original source: New asn1c skeleton regression suite.
 * Version/date: 1.1, 2026-10-12.
 * Inputs: Built-in primitive descriptors and generated-style local metadata.
 * Returns: EXIT_SUCCESS when all direct/generic encoder and decoder checks pass.
 * Exceptions: No C++ exceptions; failed assertions exit with EXIT_FAILURE.
 * Responsible party: asn1c maintainers.
 * History: Added for CER encoding, validation, sorting, and resource limits.
 * Example: Run `make -C tests/tests-skeletons check-CER`.
 */
#include <asn_application.h>
#include <asn_internal.h>
#include <cer_encoder.h>
#include <BOOLEAN.h>
#include <BIT_STRING.h>
#include <ANY.h>
#include <BMPString.h>
#include <GeneralString.h>
#include <GeneralizedTime.h>
#include <IA5String.h>
#include <INTEGER.h>
#include <NativeInteger.h>
#include <NativeReal.h>
#include <NULL.h>
#include <NumericString.h>
#include <OBJECT_IDENTIFIER.h>
#include <RELATIVE-OID.h>
#include <OCTET_STRING.h>
#include <PrintableString.h>
#include <REAL.h>
#include <UTCTime.h>
#include <UniversalString.h>
#include <UTF8String.h>
#include <VisibleString.h>
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>
#include <constr_SET.h>
#include <constr_SET_OF.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CER_UNIVERSAL_TAG(number) \
    (ASN_TAG_CLASS_UNIVERSAL | ((ber_tlv_tag_t)(number) << 2))
#define CER_CONTEXT_TAG(number) \
    (ASN_TAG_CLASS_CONTEXT | ((ber_tlv_tag_t)(number) << 2))

/* Fixed-capacity output ownership for callback-based public encoder tests. */
struct cer_capture {
    uint8_t *bytes; /* Caller-owned encoded output buffer. */
    size_t capacity; /* Maximum number of bytes accepted by the callback. */
    size_t length; /* state variable: bytes captured so far. */
    int reject; /* state variable: force callback failure when nonzero. */
};

/* Untagged CHOICE used to verify generated-style static minimum-tag metadata. */
typedef struct cer_test_choice_s {
    int present; /* state variable: one-based selected alternative index. */
    union {
        BOOLEAN_t boolean_value; /* Inline BOOLEAN alternative storage. */
        long integer_value; /* Inline native INTEGER alternative storage. */
    } choice; /* Storage shared by the selected alternative. */
} cer_test_choice_t;

/* Inner SEQUENCE used to verify recursive indefinite-length composition. */
typedef struct cer_test_inner_s {
    BOOLEAN_t value; /* Required BOOLEAN payload. */
} cer_test_inner_t;

/* Composite test value covers defaults, optionals, tags, CHOICE, and nesting. */
typedef struct cer_test_sequence_s {
    BOOLEAN_t required; /* Required first SEQUENCE member. */
    INTEGER_t *optional_integer; /* state variable: NULL means absent. */
    long default_integer; /* Native INTEGER omitted when the default is zero. */
    cer_test_choice_t choice; /* Untagged selected CHOICE member. */
    BOOLEAN_t implicit_boolean; /* BOOLEAN with a context-specific IMPLICIT tag. */
    BOOLEAN_t explicit_boolean; /* BOOLEAN with a context-specific EXPLICIT tag. */
    cer_test_inner_t nested; /* Inline nested constructed SEQUENCE. */
} cer_test_sequence_t;

/* SET value distinguishes declaration order from canonical tag ordering. */
typedef struct cer_test_set_s {
    cer_test_choice_t choice; /* Untagged CHOICE whose alternatives have tags 1/2. */
    BOOLEAN_t boolean_value; /* Universal BOOLEAN member with tag 1. */
    BOOLEAN_t explicit_boolean; /* Explicit context tag 0 member. */
} cer_test_set_t;

/* Generated-style SEQUENCE with required inline OID primitive values. */
typedef struct cer_oid_sequence_s {
    OBJECT_IDENTIFIER_t oid; /* state variable: required universal OID value. */
    RELATIVE_OID_t relative_oid; /* state variable: required relative OID value. */
} cer_oid_sequence_t;

/* Generated-style SET reverses OID declaration order to test canonical ordering. */
typedef struct cer_oid_set_s {
    RELATIVE_OID_t relative_oid; /* state variable: required relative OID value. */
    OBJECT_IDENTIFIER_t oid; /* state variable: required universal OID value. */
} cer_oid_set_t;

/* Explicit OCTET STRING SEQUENCE target for CER wrapper-decoding tests. */
typedef struct cer_test_explicit_octets_s {
    OCTET_STRING_t value; /* state variable: decoded wrapped OCTET STRING. */
    asn_struct_ctx_t _asn_ctx; /* state variable: incremental SEQUENCE context. */
} cer_test_explicit_octets_t;

/* Generated-style SEQUENCE with an absent required pointer for rejection tests. */
typedef struct cer_required_pointer_s {
    BOOLEAN_t *required; /* Required pointer member; NULL is malformed. */
} cer_required_pointer_t;

/* Generated-style SEQUENCE containing an unsupported ANY member. */
typedef struct cer_any_container_s {
    ANY_t *value; /* state variable: pointer to the dynamic ANY value. */
} cer_any_container_t;

/* Generated-style SET OF INTEGER storage for canonical encoded-byte ordering. */
typedef struct cer_integer_set_s {
    struct {
        long **array; /* Pointers to native INTEGER elements. */
        int count; /* state variable: number of initialized elements. */
        int size; /* Allocated pointer capacity. */
        void (*free)(long *); /* Element cleanup function, unused for stack values. */
    } list; /* Collection storage expected by the SET OF operation. */
    asn_struct_ctx_t _asn_ctx; /* Decoder context slot required by metadata. */
} cer_integer_set_t;

/* Self-referential SEQUENCE value used to prove depth limits stop cycles. */
typedef struct cer_cycle_s {
    struct cer_cycle_s *next; /* state variable: nested link back into the graph. */
} cer_cycle_t;

/* Choice alternatives preserve descriptor declaration order for stable ties. */
static asn_TYPE_member_t cer_test_choice_members[] = {
    {
        .flags = 0, /* The BOOLEAN payload is inline. */
        .name = "booleanValue", /* Diagnostic ASN.1 member name. */
        .type = &asn_DEF_BOOLEAN, /* BOOLEAN descriptor. */
        .memb_offset = offsetof(cer_test_choice_t, choice.boolean_value),
    },
    {
        .flags = 0, /* The INTEGER payload is inline. */
        .name = "integerValue", /* Diagnostic ASN.1 member name. */
        .type = &asn_DEF_NativeInteger, /* Native INTEGER descriptor. */
        .memb_offset = offsetof(cer_test_choice_t, choice.integer_value),
    },
};

/* Untagged CHOICE metadata lets CER compute the lowest alternative tag. */
static asn_CHOICE_specifics_t cer_test_choice_specifics = {
    .struct_size = sizeof(cer_test_choice_t), /* Containing value size. */
    .ctx_offset = 0, /* Test value has no decoder context member. */
    .pres_offset = offsetof(cer_test_choice_t, present), /* Presence field. */
    .pres_size = sizeof(((cer_test_choice_t *)0)->present), /* Presence width. */
    .tag2el = NULL, /* CER does not use the BER lookup table. */
    .tag2el_count = 0, /* No BER lookup entries. */
    .to_canonical_order = NULL, /* PER-only metadata is unused. */
    .from_canonical_order = NULL, /* PER-only metadata is unused. */
    .ext_start = -1, /* The test CHOICE is not extensible. */
};

/* Untagged descriptor intentionally has no static outer tag. */
static asn_TYPE_descriptor_t asn_DEF_CER_TestChoice = {
    .name = "CER-TestChoice", /* Descriptor name for diagnostics. */
    .xml_tag = "CER-TestChoice", /* Stable external display name. */
    .op = &asn_OP_CHOICE, /* CHOICE operation table. */
    .tags = NULL, /* Alternatives supply their own outer tags. */
    .tags_count = 0, /* This CHOICE is untagged. */
    .elements = cer_test_choice_members, /* Declared alternatives. */
    .elements_count = sizeof(cer_test_choice_members) /
                      sizeof(cer_test_choice_members[0]), /* Alternative count. */
    .specifics = &cer_test_choice_specifics, /* Generated-style CHOICE details. */
};

/* Static tag array is declared before all nested SEQUENCE descriptors. */
static const ber_tlv_tag_t cer_test_inner_tags[] = {
    CER_UNIVERSAL_TAG(16), /* SEQUENCE tag. */
};

/* Inner SEQUENCE has one required BOOLEAN component. */
static asn_TYPE_member_t cer_test_inner_members[] = {
    {
        .flags = 0, /* Inline member representation. */
        .name = "value", /* Diagnostic ASN.1 member name. */
        .type = &asn_DEF_BOOLEAN, /* BOOLEAN descriptor. */
        .memb_offset = offsetof(cer_test_inner_t, value),
    },
};

/* SEQUENCE specifics bounds every member offset against its C value. */
static asn_SEQUENCE_specifics_t cer_test_inner_specifics = {
    .struct_size = sizeof(cer_test_inner_t), /* Containing value size. */
    .ctx_offset = 0, /* Test value has no decoder context member. */
    .tag2el = NULL, /* CER does not use the BER lookup table. */
    .tag2el_count = 0, /* No BER lookup entries. */
    .oms = NULL, /* No optional-member map is needed for CER. */
    .roms_count = 0, /* No extension-root optionals. */
    .aoms_count = 0, /* No extension-addition optionals. */
    .first_extension = -1, /* The test SEQUENCE is not extensible. */
};

/* Descriptor for the nested constructed test value. */
static asn_TYPE_descriptor_t asn_DEF_CER_TestInner = {
    .name = "CER-TestInner", /* Descriptor name for diagnostics. */
    .xml_tag = "CER-TestInner", /* Stable external display name. */
    .op = &asn_OP_SEQUENCE, /* SEQUENCE operation table. */
    .tags = cer_test_inner_tags,
    .tags_count = 1, /* One universal outer tag. */
    .all_tags = cer_test_inner_tags,
    .all_tags_count = 1,
    .elements = cer_test_inner_members, /* Declared components. */
    .elements_count = 1, /* One required component. */
    .specifics = &cer_test_inner_specifics, /* Generated-style details. */
};

/*
 * Compare a native INTEGER member with its generated DEFAULT value.
 * Original source: New CER regression fixture, matching asn1c generated code.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: value points to the native INTEGER field being inspected.
 * Returns: Zero when the field equals DEFAULT zero, nonzero otherwise.
 * Errors: No errors or exceptions; value is a valid descriptor field address.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: assigned to default_value_cmp in cer_test_sequence_members.
 */
static int
cer_default_zero(const void *value) {
    const long *integer = (const long *)value;
    return *integer != 0;
}

/* SEQUENCE fields exercise required, optional, default, and explicit tags. */
static asn_TYPE_member_t cer_test_sequence_members[] = {
    {
        .flags = 0, /* Inline BOOLEAN. */
        .optional = 0, /* Required member. */
        .memb_offset = offsetof(cer_test_sequence_t, required),
        .tag_mode = 0, /* Use the type's universal tag. */
        .type = &asn_DEF_BOOLEAN,
        .name = "required",
    },
    {
        .flags = ATF_POINTER, /* Indirect INTEGER storage. */
        .optional = 1, /* Omit when the pointer is NULL. */
        .memb_offset = offsetof(cer_test_sequence_t, optional_integer),
        .tag_mode = 0,
        .type = &asn_DEF_INTEGER,
        .name = "optionalInteger",
    },
    {
        .flags = 0,
        .optional = 0,
        .memb_offset = offsetof(cer_test_sequence_t, default_integer),
        .tag_mode = 0,
        .type = &asn_DEF_NativeInteger,
        .default_value_cmp = cer_default_zero,
        .name = "defaultInteger",
    },
    {
        .flags = 0,
        .optional = 0,
        .memb_offset = offsetof(cer_test_sequence_t, choice),
        .tag_mode = 0,
        .type = &asn_DEF_CER_TestChoice,
        .name = "choice",
    },
    {
        .flags = 0,
        .optional = 0,
        .memb_offset = offsetof(cer_test_sequence_t, implicit_boolean),
        .tag = CER_CONTEXT_TAG(0),
        .tag_mode = -1, /* IMPLICIT context tag. */
        .type = &asn_DEF_BOOLEAN,
        .name = "implicitBoolean",
    },
    {
        .flags = 0,
        .optional = 0,
        .memb_offset = offsetof(cer_test_sequence_t, explicit_boolean),
        .tag = CER_CONTEXT_TAG(1),
        .tag_mode = 1, /* EXPLICIT context tag. */
        .type = &asn_DEF_BOOLEAN,
        .name = "explicitBoolean",
    },
    {
        .flags = 0,
        .optional = 0,
        .memb_offset = offsetof(cer_test_sequence_t, nested),
        .tag_mode = 0,
        .type = &asn_DEF_CER_TestInner,
        .name = "nested",
    },
};

/* SEQUENCE-specific metadata bounds all generated-style field offsets. */
static asn_SEQUENCE_specifics_t cer_test_sequence_specifics = {
    .struct_size = sizeof(cer_test_sequence_t), /* Containing value size. */
    .ctx_offset = 0, /* No decoder context is required by these encoder tests. */
    .tag2el = NULL, /* CER does not use the BER tag map. */
    .tag2el_count = 0,
    .oms = NULL, /* No PER optional-member map. */
    .roms_count = 0,
    .aoms_count = 0,
    .first_extension = -1, /* Not extensible. */
};

/* The test SEQUENCE is emitted with the universal constructed tag 16. */
static const ber_tlv_tag_t cer_test_sequence_tags[] = {
    CER_UNIVERSAL_TAG(16), /* SEQUENCE tag. */
};

/* Generated-style descriptor for nested, tagged SEQUENCE member tests. */
static asn_TYPE_descriptor_t asn_DEF_CER_TestSequence = {
    .name = "CER-TestSequence",
    .xml_tag = "CER-TestSequence",
    .op = &asn_OP_SEQUENCE,
    .tags = cer_test_sequence_tags,
    .tags_count = 1,
    .all_tags = cer_test_sequence_tags,
    .all_tags_count = 1,
    .elements = cer_test_sequence_members,
    .elements_count = sizeof(cer_test_sequence_members) /
                      sizeof(cer_test_sequence_members[0]),
    .specifics = &cer_test_sequence_specifics,
};

/* SET components test stable declaration ties and mixed tag classes. */
static asn_TYPE_member_t cer_test_set_members[] = {
    {
        .flags = 0,
        .optional = 0,
        .memb_offset = offsetof(cer_test_set_t, choice),
        .tag_mode = 0,
        .type = &asn_DEF_CER_TestChoice,
        .name = "choice",
    },
    {
        .flags = 0,
        .optional = 0,
        .memb_offset = offsetof(cer_test_set_t, boolean_value),
        .tag_mode = 0,
        .type = &asn_DEF_BOOLEAN,
        .name = "booleanValue",
    },
    {
        .flags = 0,
        .optional = 0,
        .memb_offset = offsetof(cer_test_set_t, explicit_boolean),
        .tag = CER_CONTEXT_TAG(0),
        .tag_mode = 1,
        .type = &asn_DEF_BOOLEAN,
        .name = "explicitBoolean",
    },
};

/* SET metadata records the generated C layout and mandatory members. */
static asn_SET_specifics_t cer_test_set_specifics = {
    .struct_size = sizeof(cer_test_set_t), /* Containing value size. */
    .ctx_offset = 0,
    .pres_offset = 0, /* No presence map is needed for required inline values. */
    .tag2el = NULL,
    .tag2el_count = 0,
    .tag2el_cxer = NULL,
    .tag2el_cxer_count = 0,
    .extensible = 0,
    ._mandatory_elements = NULL, /* CER validates member presence directly. */
};

/* The test SET is emitted with the universal constructed tag 17. */
static const ber_tlv_tag_t cer_test_set_tags[] = {
    CER_UNIVERSAL_TAG(17), /* SET tag. */
};

/* Generated-style descriptor for SET tag order and mixed-class cases. */
static asn_TYPE_descriptor_t asn_DEF_CER_TestSet = {
    .name = "CER-TestSet",
    .xml_tag = "CER-TestSet",
    .op = &asn_OP_SET,
    .tags = cer_test_set_tags,
    .tags_count = 1,
    .all_tags = cer_test_set_tags,
    .all_tags_count = 1,
    .elements = cer_test_set_members,
    .elements_count = sizeof(cer_test_set_members) /
                      sizeof(cer_test_set_members[0]),
    .specifics = &cer_test_set_specifics,
};

/* The inline OID SEQUENCE members use their primitive universal tags. */
static asn_TYPE_member_t cer_oid_sequence_members[] = {
    {
        .flags = 0,
        .optional = 0,
        .memb_offset = offsetof(cer_oid_sequence_t, oid),
        .tag_mode = 0,
        .type = &asn_DEF_OBJECT_IDENTIFIER,
        .name = "oid",
    },
    {
        .flags = 0,
        .optional = 0,
        .memb_offset = offsetof(cer_oid_sequence_t, relative_oid),
        .tag_mode = 0,
        .type = &asn_DEF_RELATIVE_OID,
        .name = "relativeOid",
    },
};

/* SEQUENCE specifics bound each inline OID member to the generated layout. */
static asn_SEQUENCE_specifics_t cer_oid_sequence_specifics = {
    .struct_size = sizeof(cer_oid_sequence_t),
    .ctx_offset = 0,
    .tag2el = NULL,
    .tag2el_count = 0,
    .oms = NULL,
    .roms_count = 0,
    .aoms_count = 0,
    .first_extension = -1,
};

/* Universal SEQUENCE descriptor for the generated-style inline OID value. */
static const ber_tlv_tag_t cer_oid_sequence_tags[] = {CER_UNIVERSAL_TAG(16)};
static asn_TYPE_descriptor_t asn_DEF_CER_OIDSequence = {
    .name = "CER-OIDSequence",
    .xml_tag = "CER-OIDSequence",
    .op = &asn_OP_SEQUENCE,
    .tags = cer_oid_sequence_tags,
    .tags_count = 1,
    .all_tags = cer_oid_sequence_tags,
    .all_tags_count = 1,
    .elements = cer_oid_sequence_members,
    .elements_count = sizeof(cer_oid_sequence_members) /
                      sizeof(cer_oid_sequence_members[0]),
    .specifics = &cer_oid_sequence_specifics,
};

/* SET declaration order is RELATIVE-OID then OID; CER sorts by tag number. */
static asn_TYPE_member_t cer_oid_set_members[] = {
    {
        .flags = 0,
        .optional = 0,
        .memb_offset = offsetof(cer_oid_set_t, relative_oid),
        .tag_mode = 0,
        .type = &asn_DEF_RELATIVE_OID,
        .name = "relativeOid",
    },
    {
        .flags = 0,
        .optional = 0,
        .memb_offset = offsetof(cer_oid_set_t, oid),
        .tag_mode = 0,
        .type = &asn_DEF_OBJECT_IDENTIFIER,
        .name = "oid",
    },
};

/* Required inline SET values need no presence-map storage. */
static asn_SET_specifics_t cer_oid_set_specifics = {
    .struct_size = sizeof(cer_oid_set_t),
    .ctx_offset = 0,
    .pres_offset = 0,
    .tag2el = NULL,
    .tag2el_count = 0,
    .tag2el_cxer = NULL,
    .tag2el_cxer_count = 0,
    .extensible = 0,
    ._mandatory_elements = NULL,
};

/* Universal SET descriptor for generated-style inline OID values. */
static const ber_tlv_tag_t cer_oid_set_tags[] = {CER_UNIVERSAL_TAG(17)};
static asn_TYPE_descriptor_t asn_DEF_CER_OIDSet = {
    .name = "CER-OIDSet",
    .xml_tag = "CER-OIDSet",
    .op = &asn_OP_SET,
    .tags = cer_oid_set_tags,
    .tags_count = 1,
    .all_tags = cer_oid_set_tags,
    .all_tags_count = 1,
    .elements = cer_oid_set_members,
    .elements_count = sizeof(cer_oid_set_members) /
                      sizeof(cer_oid_set_members[0]),
    .specifics = &cer_oid_set_specifics,
};

/* Required pointer metadata rejects absent non-optional components. */
static asn_TYPE_member_t cer_required_pointer_members[] = {
    {
        .flags = ATF_POINTER,
        .optional = 0,
        .memb_offset = offsetof(cer_required_pointer_t, required),
        .tag_mode = 0,
        .type = &asn_DEF_BOOLEAN,
        .name = "required",
    },
};

/* Specifics provide the containing size needed for robust offset validation. */
static asn_SEQUENCE_specifics_t cer_required_pointer_specifics = {
    .struct_size = sizeof(cer_required_pointer_t),
    .ctx_offset = 0,
    .tag2el = NULL,
    .tag2el_count = 0,
    .oms = NULL,
    .roms_count = 0,
    .aoms_count = 0,
    .first_extension = -1,
};

/* Required-pointer fixture uses a statically tagged SEQUENCE descriptor. */
static asn_TYPE_descriptor_t asn_DEF_CER_RequiredPointer = {
    .name = "CER-RequiredPointer",
    .xml_tag = "CER-RequiredPointer",
    .op = &asn_OP_SEQUENCE,
    .tags = cer_test_sequence_tags,
    .tags_count = 1,
    .all_tags = cer_test_sequence_tags,
    .all_tags_count = 1,
    .elements = cer_required_pointer_members,
    .elements_count = 1,
    .specifics = &cer_required_pointer_specifics,
};

/* ANY metadata reaches the encoder's explicit unsupported-type rejection. */
static asn_TYPE_member_t cer_any_container_members[] = {
    {
        .flags = ATF_POINTER | ATF_ANY_TYPE,
        .optional = 0,
        .memb_offset = offsetof(cer_any_container_t, value),
        .tag_mode = 0,
        .type = &asn_DEF_ANY,
        .name = "value",
    },
};

/* ANY fixture is structurally valid so ENOENT comes from the ANY contract. */
static asn_SEQUENCE_specifics_t cer_any_container_specifics = {
    .struct_size = sizeof(cer_any_container_t),
    .ctx_offset = 0,
    .tag2el = NULL,
    .tag2el_count = 0,
    .oms = NULL,
    .roms_count = 0,
    .aoms_count = 0,
    .first_extension = -1,
};

/* The unsupported ANY member is present to distinguish ENOENT from omission. */
static asn_TYPE_descriptor_t asn_DEF_CER_AnyContainer = {
    .name = "CER-AnyContainer",
    .xml_tag = "CER-AnyContainer",
    .op = &asn_OP_SEQUENCE,
    .tags = cer_test_sequence_tags,
    .tags_count = 1,
    .all_tags = cer_test_sequence_tags,
    .all_tags_count = 1,
    .elements = cer_any_container_members,
    .elements_count = 1,
    .specifics = &cer_any_container_specifics,
};

/* SET OF uses INTEGER encodings as its final canonical sort keys. */
static asn_TYPE_member_t cer_integer_set_members[] = {
    {
        .flags = 0,
        .optional = 0,
        .memb_offset = 0,
        .tag_mode = 0,
        .type = &asn_DEF_NativeInteger,
        .name = "element",
    },
};

/* SET OF metadata identifies its collection structure layout. */
static asn_SET_OF_specifics_t cer_integer_set_specifics = {
    .struct_size = sizeof(cer_integer_set_t),
    .ctx_offset = offsetof(cer_integer_set_t, _asn_ctx),
    .as_XMLValueList = 0,
};

/* The test collection uses universal constructed SET OF tag 17. */
static const ber_tlv_tag_t cer_integer_set_tags[] = {
    CER_UNIVERSAL_TAG(17),
};

/* Descriptor for sorting complete CER INTEGER TLVs in SET OF. */
static asn_TYPE_descriptor_t asn_DEF_CER_IntegerSet = {
    .name = "CER-IntegerSet",
    .xml_tag = "CER-IntegerSet",
    .op = &asn_OP_SET_OF,
    .tags = cer_integer_set_tags,
    .tags_count = 1,
    .all_tags = cer_integer_set_tags,
    .all_tags_count = 1,
    .elements = cer_integer_set_members,
    .elements_count = 1,
    .specifics = &cer_integer_set_specifics,
};

/* Type declaration allows the recursive generated-style member below. */
static asn_TYPE_descriptor_t asn_DEF_CER_Cycle;

/* The cycle member is required and intentionally points to the same type. */
static asn_TYPE_member_t cer_cycle_members[] = {
    {
        .flags = ATF_POINTER,
        .optional = 0,
        .memb_offset = offsetof(cer_cycle_t, next),
        .tag_mode = 0,
        .type = &asn_DEF_CER_Cycle,
        .name = "next",
    },
};

/* Recursive SEQUENCE metadata describes the fixed-size pointer node. */
static asn_SEQUENCE_specifics_t cer_cycle_specifics = {
    .struct_size = sizeof(cer_cycle_t),
    .ctx_offset = 0,
    .tag2el = NULL,
    .tag2el_count = 0,
    .oms = NULL,
    .roms_count = 0,
    .aoms_count = 0,
    .first_extension = -1,
};

/* Recursive descriptor enables bounded traversal of a deliberately cyclic value. */
static asn_TYPE_descriptor_t asn_DEF_CER_Cycle = {
    .name = "CER-Cycle",
    .xml_tag = "CER-Cycle",
    .op = &asn_OP_SEQUENCE,
    .tags = cer_test_sequence_tags,
    .tags_count = 1,
    .all_tags = cer_test_sequence_tags,
    .all_tags_count = 1,
    .elements = cer_cycle_members,
    .elements_count = 1,
    .specifics = &cer_cycle_specifics,
};

/*
 * Capture encoded bytes into bounded test storage or reject them on demand.
 * Original source: New asn1c CER regression fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: data/size identify a callback chunk; key points to capture state.
 * Returns: Zero after copying, or -1 for rejection or insufficient capacity.
 * Errors: No errno contract; no exceptions. Input is checked before copying.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_encode(NULL, td, value, cer_capture_cb, &capture).
 */
static int
cer_capture_cb(const void *data, size_t size, void *key) {
    struct cer_capture *capture = (struct cer_capture *)key;

    if(!capture || (size && !data) || capture->length > capture->capacity ||
       (size && !capture->bytes) || capture->reject ||
       size > capture->capacity - capture->length) {
        return -1;
    }
    memcpy(capture->bytes + capture->length, data, size);
    capture->length += size;
    return 0;
}

/*
 * Report one failed assertion while allowing later vectors to run.
 * Original source: New asn1c CER regression fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: condition is the assertion result; label names the expectation.
 * Returns: Zero for a true assertion, otherwise -1 after writing stderr.
 * Errors: No exceptions; fprintf failure does not change the test result.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: failed |= cer_require(encoded.encoded == expected_size, label).
 */
static int
cer_require(int condition, const char *label) {
    if(condition) return 0;
    fprintf(stderr, "CER test failed: %s\n", label);
    return -1;
}

/*
 * Compare callback, direct-buffer, and generic-buffer output with one vector.
 * Original source: New asn1c CER regression fixture, using X.690 golden bytes.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: td/value select the descriptor value; expected/size are golden
 *   output bytes; label identifies any mismatch.
 * Returns: Zero when all three public output paths match, otherwise -1.
 * Errors: No exceptions; test failures are reported through cer_require().
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_check_vector(&asn_DEF_BOOLEAN, &truth, tlv, sizeof(tlv), name).
 */
static int
cer_check_vector(const asn_TYPE_descriptor_t *td, const void *value,
                 const uint8_t *expected, size_t expected_size,
                 const char *label) {
    uint8_t actual[2048];
    struct cer_capture capture;
    asn_enc_rval_t encoded;
    int failed = 0;

    if(expected_size > sizeof(actual)) return cer_require(0, label);
    memset(&capture, 0, sizeof(capture));
    capture.bytes = actual;
    capture.capacity = sizeof(actual);
    encoded = cer_encode(NULL, td, value, cer_capture_cb, &capture);
    failed |= cer_require(encoded.encoded == (ssize_t)expected_size &&
                          capture.length == expected_size &&
                          memcmp(actual, expected, expected_size) == 0, label);
    memset(actual, 0, sizeof(actual));
    encoded = cer_encode_to_buffer(NULL, td, value, actual, sizeof(actual));
    failed |= cer_require(encoded.encoded == (ssize_t)expected_size &&
                          memcmp(actual, expected, expected_size) == 0, label);
    memset(actual, 0, sizeof(actual));
    encoded = asn_encode_to_buffer(NULL, ATS_CER, td, value, actual,
                                   sizeof(actual));
    failed |= cer_require(encoded.encoded == (ssize_t)expected_size &&
                          memcmp(actual, expected, expected_size) == 0, label);
    return failed;
}

/*
 * Verify direct and generic callbacks report the stable EIO failure contract.
 * Original source: New asn1c CER regression fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: td/value select the encoded type and value; label names the test.
 * Returns: Zero when both APIs report -1/EIO and identify the root descriptor.
 * Errors: No exceptions; failed assertions return -1 to the caller.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_check_callback_error(&asn_DEF_BOOLEAN, &truth, "callback EIO").
 */
static int
cer_check_callback_error(const asn_TYPE_descriptor_t *td, const void *value,
                         const char *label) {
    uint8_t output[32];
    struct cer_capture capture;
    asn_enc_rval_t encoded;

    memset(&capture, 0, sizeof(capture));
    capture.bytes = output;
    capture.capacity = sizeof(output);
    capture.reject = 1;
    errno = 0;
    encoded = cer_encode(NULL, td, value, cer_capture_cb, &capture);
    if(encoded.encoded != -1 || errno != EIO || encoded.failed_type != td) {
        return cer_require(0, label);
    }
    errno = 0;
    encoded = asn_encode(NULL, ATS_CER, td, value, cer_capture_cb, &capture);
    return cer_require(encoded.encoded == -1 && errno == EIO &&
                       encoded.failed_type == td, label);
}

/*
 * Check that malformed input fails with one expected errno-style result.
 * Original source: New asn1c CER regression fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: td/value identify the descriptor and input; expected_errno is
 *   the required errno; label describes the malformed case.
 * Returns: Zero for the expected failed result, otherwise -1.
 * Errors: No exceptions; failure diagnostics are emitted by cer_require().
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_check_error(&asn_DEF_INTEGER, &empty, EBADF, "empty integer").
 */
static int
cer_check_error(const asn_TYPE_descriptor_t *td, const void *value,
                int expected_errno, const char *label) {
    uint8_t output[128];
    asn_enc_rval_t encoded;

    errno = 0;
    encoded = cer_encode_to_buffer(NULL, td, value, output, sizeof(output));
    return cer_require(encoded.encoded == -1 && errno == expected_errno &&
                       encoded.failed_type != NULL, label);
}

/*
 * Check independent primitive, integer, REAL, OID, and time CER vectors.
 * Original source: New asn1c CER regression fixture, with manually fixed TLVs.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; values and expected bytes are local fixed fixtures.
 * Returns: Zero when all accepted vectors and rejection cases pass.
 * Errors: No exceptions; assertion failures return -1 after stderr reporting.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called by main() before fragmentation and constructed-value tests.
 */
static int
cer_check_small_primitive_vectors(void) {
    static const uint8_t true_bytes[] = {0x01, 0x01, 0xff};
    static const uint8_t false_bytes[] = {0x01, 0x01, 0x00};
    static const uint8_t null_bytes[] = {0x05, 0x00};
    static const uint8_t int_127[] = {0x02, 0x01, 0x7f};
    static const uint8_t int_128[] = {0x02, 0x02, 0x00, 0x80};
    static const uint8_t int_n128[] = {0x02, 0x01, 0x80};
    static const uint8_t int_n129[] = {0x02, 0x02, 0xff, 0x7f};
    static uint8_t int64_max[] = {
        0x02, 0x08, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    static uint8_t int64_min[] = {
        0x02, 0x08, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    static const uint8_t real_one[] = {0x09, 0x03, 0x80, 0x00, 0x01};
    static const uint8_t real_plus_inf[] = {0x09, 0x01, 0x40};
    static const uint8_t oid_bytes[] = {
        0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d
    };
    static const uint8_t utc_bytes[] = {
        0x17, 0x0d, '9', '9', '1', '2', '3', '1', '2', '3', '5', '9',
        '0', '0', 'Z'
    };
    static const uint8_t utc_offset_bytes[] = {
        0x17, 0x0d, '0', '0', '0', '1', '0', '1', '0', '0', '0', '0',
        '0', '0', 'Z'
    };
    static const uint8_t bmp_bytes[] = {0x1e, 0x02, 0x41, 0x41};
    static uint8_t bmp_content[] = {0x41, 0x41};
    static uint8_t real_decimal[] = {0x03, '1', '.', '0'};
    static uint8_t real_nonminimal[] = {0x81, 0x00, 0x01, 0x01};
    static uint8_t real_bad_special[] = {0x44};
    static uint8_t oid_bad[] = {0x80};
    static const asn_oid_arc_t arcs[] = {1, 2, 840, 113549};
    static uint8_t raw_127[] = {0x7f};
    static uint8_t raw_128[] = {0x00, 0x80};
    static uint8_t raw_n128[] = {0x80};
    static uint8_t raw_n129[] = {0xff, 0x7f};
    static uint8_t raw_one[] = {0x80, 0x00, 0x01};
    static uint8_t raw_inf[] = {0x40};
    static const double native_one = 1.0;
    static const double native_inf = INFINITY;
    BOOLEAN_t truth = 1;
    BOOLEAN_t falsity = 0;
    NULL_t null_value = 0;
    INTEGER_t integer = {0};
    long native_integer = 0;
    REAL_t real = {0};
    double native_real = native_one;
    OBJECT_IDENTIFIER_t oid = {0};
    UTCTime_t utc = {0};
    UTCTime_t utc_offset = {0};
    BMPString_t bmp = {0};
    int failed = 0;

    failed |= cer_check_vector(&asn_DEF_BOOLEAN, &truth, true_bytes,
                               sizeof(true_bytes), "BOOLEAN TRUE is FF");
    failed |= cer_check_vector(&asn_DEF_BOOLEAN, &falsity, false_bytes,
                               sizeof(false_bytes), "BOOLEAN FALSE is 00");
    failed |= cer_check_vector(&asn_DEF_NULL, &null_value, null_bytes,
                               sizeof(null_bytes), "NULL has empty content");
    integer.buf = raw_127;
    integer.size = sizeof(raw_127);
    failed |= cer_check_vector(&asn_DEF_INTEGER, &integer, int_127,
                               sizeof(int_127), "INTEGER positive 127");
    integer.buf = raw_128;
    integer.size = sizeof(raw_128);
    failed |= cer_check_vector(&asn_DEF_INTEGER, &integer, int_128,
                               sizeof(int_128), "INTEGER positive sign pad");
    integer.buf = raw_n128;
    integer.size = sizeof(raw_n128);
    failed |= cer_check_vector(&asn_DEF_INTEGER, &integer, int_n128,
                               sizeof(int_n128), "INTEGER negative 128");
    integer.buf = raw_n129;
    integer.size = sizeof(raw_n129);
    failed |= cer_check_vector(&asn_DEF_INTEGER, &integer, int_n129,
                               sizeof(int_n129), "INTEGER negative sign byte");
    native_integer = 127;
    failed |= cer_check_vector(&asn_DEF_NativeInteger, &native_integer,
                               int_127, sizeof(int_127), "NativeInteger 127");
    native_integer = 128;
    failed |= cer_check_vector(&asn_DEF_NativeInteger, &native_integer,
                               int_128, sizeof(int_128), "NativeInteger 128");
    native_integer = -128;
    failed |= cer_check_vector(&asn_DEF_NativeInteger, &native_integer,
                               int_n128, sizeof(int_n128), "NativeInteger -128");
    native_integer = -129;
    failed |= cer_check_vector(&asn_DEF_NativeInteger, &native_integer,
                               int_n129, sizeof(int_n129), "NativeInteger -129");
#if LONG_MAX == INT64_MAX && LONG_MIN == INT64_MIN
    native_integer = LONG_MAX;
    failed |= cer_check_vector(&asn_DEF_NativeInteger, &native_integer,
                               int64_max, sizeof(int64_max),
                               "NativeInteger signed 64-bit maximum");
    native_integer = LONG_MIN;
    failed |= cer_check_vector(&asn_DEF_NativeInteger, &native_integer,
                               int64_min, sizeof(int64_min),
                               "NativeInteger signed 64-bit minimum");
    integer.buf = int64_max + 2;
    integer.size = sizeof(int64_max) - 2;
    failed |= cer_check_vector(&asn_DEF_INTEGER, &integer, int64_max,
                               sizeof(int64_max), "INTEGER signed 64-bit maximum");
    integer.buf = int64_min + 2;
    integer.size = sizeof(int64_min) - 2;
    failed |= cer_check_vector(&asn_DEF_INTEGER, &integer, int64_min,
                               sizeof(int64_min), "INTEGER signed 64-bit minimum");
#endif
    real.buf = raw_one;
    real.size = sizeof(raw_one);
    failed |= cer_check_vector(&asn_DEF_REAL, &real, real_one,
                               sizeof(real_one), "REAL canonical binary one");
    real.buf = raw_inf;
    real.size = sizeof(raw_inf);
    failed |= cer_check_vector(&asn_DEF_REAL, &real, real_plus_inf,
                               sizeof(real_plus_inf), "REAL plus infinity");
    failed |= cer_check_vector(&asn_DEF_NativeReal, &native_real, real_one,
                               sizeof(real_one), "NativeReal one");
    native_real = native_inf;
    failed |= cer_check_vector(&asn_DEF_NativeReal, &native_real,
                               real_plus_inf, sizeof(real_plus_inf),
                               "NativeReal plus infinity");
    if(OBJECT_IDENTIFIER_set_arcs(&oid, arcs,
                                  sizeof(arcs) / sizeof(arcs[0])) != 0) {
        failed |= cer_require(0, "initialize OID arcs");
    } else {
        failed |= cer_check_vector(&asn_DEF_OBJECT_IDENTIFIER, &oid, oid_bytes,
                                   sizeof(oid_bytes), "OID canonical base-128");
    }
    utc.buf = (uint8_t *)"9912312359Z";
    utc.size = strlen((const char *)utc.buf);
    failed |= cer_check_vector(&asn_DEF_UTCTime, &utc, utc_bytes,
                               sizeof(utc_bytes), "UTCTime adds seconds");
    utc_offset.buf = (uint8_t *)"0001010100+0100";
    utc_offset.size = strlen((const char *)utc_offset.buf);
    failed |= cer_check_vector(&asn_DEF_UTCTime, &utc_offset,
                               utc_offset_bytes, sizeof(utc_offset_bytes),
                               "UTCTime normalizes offset to UTC");
    bmp.buf = bmp_content;
    bmp.size = sizeof(bmp_content);
    failed |= cer_check_vector(&asn_DEF_BMPString, &bmp, bmp_bytes,
                               sizeof(bmp_bytes), "BMPString intrinsic tag");
    real.buf = real_decimal;
    real.size = sizeof(real_decimal);
    failed |= cer_check_error(&asn_DEF_REAL, &real, ENOENT,
                              "REAL decimal form is unsupported");
    real.buf = real_nonminimal;
    real.size = sizeof(real_nonminimal);
    failed |= cer_check_error(&asn_DEF_REAL, &real, EBADF,
                              "REAL rejects nonminimal exponent");
    real.buf = real_bad_special;
    real.size = sizeof(real_bad_special);
    failed |= cer_check_error(&asn_DEF_REAL, &real, EBADF,
                              "REAL rejects unsupported special value");
    FREEMEM(oid.buf);
    oid.buf = NULL;
    oid.size = 0;
    oid.buf = oid_bad;
    oid.size = sizeof(oid_bad);
    failed |= cer_check_error(&asn_DEF_OBJECT_IDENTIFIER, &oid, EBADF,
                              "OID rejects unterminated base-128 arc");
    return failed;
}

/*
 * Re-decode a long wrapped integer and check its recovered native value.
 * Original source: New asn1c CER regression fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: td/value select the source; expected is the fixed CER TLV;
 *   native_value selects native-long or raw INTEGER comparison.
 * Returns: Zero when CER bytes and the BER-decoded value both match.
 * Errors: No exceptions; assertion failures are reported by cer_require().
 * Responsible party: asn1c maintainers. History: Added for long tag chains.
 * Example: used by cer_check_long_tag_chains() for NativeInteger and INTEGER.
 */
static int
cer_check_tag_chain_redecode(const asn_TYPE_descriptor_t *td,
                             const void *value, const uint8_t *expected,
                             size_t expected_size, int native_value,
                             const char *label) {
    uint8_t exact_buffer[2048];
    void *decoded = NULL;
    asn_dec_rval_t result;
    asn_enc_rval_t encoded;
    long decoded_value = 0;
    int value_valid = 0;
    int failed = cer_check_vector(td, value, expected, expected_size, label);

    encoded = cer_encode_to_buffer(NULL, td, value, exact_buffer,
                                   expected_size);
    failed |= cer_require(encoded.encoded == (ssize_t)expected_size &&
                          memcmp(exact_buffer, expected, expected_size) == 0,
                          "long explicit chain fits exact output size");
    result = ber_decode(NULL, td, &decoded, expected, expected_size);
    if(result.code == RC_OK && result.consumed == expected_size && decoded) {
        if(native_value) {
            decoded_value = *(const long *)decoded;
            value_valid = 1;
        } else if(asn_INTEGER2long((const INTEGER_t *)decoded,
                                   &decoded_value) == 0) {
            value_valid = 1;
        }
    }
    failed |= cer_require(value_valid && decoded_value == 127,
                          "long explicit chain BER re-decodes INTEGER value");
    if(decoded) td->op->free_struct(td, decoded, ASFM_FREE_EVERYTHING);
    return failed;
}

/*
 * Verify long string capture preserves its intrinsic CER fragment tag.
 * Original source: New asn1c CER regression fixture with independent TLV bytes.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; a 1001-octet value uses four descriptor wrappers.
 * Returns: Zero when exact expected fragments encode and BER-decode correctly.
 * Errors: No exceptions; mismatches return -1 through cer_require().
 * Responsible party: asn1c maintainers. History: Added for long tag chains.
 * Example: the inner fragments retain universal OCTET STRING tag 4.
 */
static int
cer_check_wrapped_string_fragments(void) {
    static const ber_tlv_tag_t tags[] = {
        CER_CONTEXT_TAG(5), CER_CONTEXT_TAG(6), CER_CONTEXT_TAG(7),
        CER_CONTEXT_TAG(8), CER_UNIVERSAL_TAG(4)
    };
    uint8_t content[1001];
    uint8_t expected[1100];
    asn_TYPE_descriptor_t td = asn_DEF_OCTET_STRING;
    OCTET_STRING_t value;
    OCTET_STRING_t *decoded_value;
    asn_dec_rval_t decoded;
    size_t offset = 0;
    size_t i; /* state variable: wrapper or EOC cursor while building bytes. */
    void *decoded_ptr = NULL;
    int failed;

    memset(content, 'X', sizeof(content));
    memset(&value, 0, sizeof(value));
    td.tags = tags;
    td.tags_count = sizeof(tags) / sizeof(tags[0]);
    td.all_tags = tags;
    td.all_tags_count = td.tags_count;
    value.buf = content;
    value.size = sizeof(content);
    for(i = 0; i < 4; i++) {
        expected[offset++] = (uint8_t)(0xa5 + i);
        expected[offset++] = 0x80;
    }
    expected[offset++] = 0x24;
    expected[offset++] = 0x80;
    expected[offset++] = 0x04;
    expected[offset++] = 0x82;
    expected[offset++] = 0x03;
    expected[offset++] = 0xe8;
    memcpy(expected + offset, content, 1000);
    offset += 1000;
    expected[offset++] = 0x04;
    expected[offset++] = 0x01;
    expected[offset++] = content[1000];
    for(i = 0; i < 5; i++) {
        expected[offset++] = 0x00;
        expected[offset++] = 0x00;
    }
    failed = cer_check_vector(&td, &value, expected, offset,
                              "long wrapped OCTET fragments use tag 4");
    decoded = ber_decode(NULL, &td, &decoded_ptr, expected, offset);
    decoded_value = (OCTET_STRING_t *)decoded_ptr;
    failed |= cer_require(decoded.code == RC_OK && decoded.consumed == offset &&
                          decoded_value && decoded_value->buf &&
                          decoded_value->size == sizeof(content) &&
                          memcmp(decoded_value->buf, content,
                                 sizeof(content)) == 0,
                          "long wrapped OCTET fragments BER-redecode");
    if(decoded_ptr) td.op->free_struct(&td, decoded_ptr, ASFM_FREE_EVERYTHING);
    return failed;
}

/*
 * Encode required inline OBJECT IDENTIFIER and RELATIVE-OID members.
 * Original source: Generated-style CER record descriptors and fixed X.690 TLVs.
 * Version/date: 1.0, 2026-11-01.
 * Parameters: None; stack records use fixed valid base-128 content octets.
 * Returns: Zero when SEQUENCE/SET vectors match and bad offsets fail with EBADF.
 * Errors: No exceptions; unexpected encoder results are reported by cer_require.
 * Responsible party: asn1c maintainers. History: Added for OID inline widths.
 * Example: the SET declares RELATIVE-OID first but encodes universal tag 6 first.
 */
static int
cer_check_inline_oid_records(void) {
    static uint8_t oid_content[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d};
    static uint8_t relative_content[] = {
        0x01, 0x02, 0x86, 0x48, 0x86, 0xf7, 0x0d
    };
    static const uint8_t sequence_bytes[] = {
        0x30, 0x80,
        0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
        0x0d, 0x07, 0x01, 0x02, 0x86, 0x48, 0x86, 0xf7, 0x0d,
        0x00, 0x00
    };
    static const uint8_t set_bytes[] = {
        0x31, 0x80,
        0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
        0x0d, 0x07, 0x01, 0x02, 0x86, 0x48, 0x86, 0xf7, 0x0d,
        0x00, 0x00
    };
    cer_oid_sequence_t sequence = {
        .oid = {oid_content, sizeof(oid_content)},
        .relative_oid = {relative_content, sizeof(relative_content)},
    };
    cer_oid_set_t set = {
        .relative_oid = {relative_content, sizeof(relative_content)},
        .oid = {oid_content, sizeof(oid_content)},
    };
    asn_TYPE_descriptor_t broken = asn_DEF_CER_OIDSequence;
    asn_TYPE_member_t broken_member = cer_oid_sequence_members[0];
    asn_SEQUENCE_specifics_t broken_specifics = cer_oid_sequence_specifics;
    asn_enc_rval_t encoded;
    int failed = 0;

    failed |= cer_check_vector(&asn_DEF_CER_OIDSequence, &sequence,
                               sequence_bytes, sizeof(sequence_bytes),
                               "required inline OIDs in SEQUENCE");
    failed |= cer_check_vector(&asn_DEF_CER_OIDSet, &set, set_bytes,
                               sizeof(set_bytes),
                               "required inline OIDs in canonical SET order");

    /* An offset leaving less than one OID value must fail before access. */
    broken_member.memb_offset = sizeof(sequence) - 1;
    broken.elements = &broken_member;
    broken_specifics.struct_size = sizeof(sequence);
    broken.specifics = &broken_specifics;
    errno = 0;
    encoded = cer_encode_to_buffer(NULL, &broken, &sequence,
                                   (uint8_t[64]){0}, 64);
    failed |= cer_require(encoded.encoded == -1 && errno == EBADF &&
                          encoded.failed_type == &broken,
                          "inline OID member rejects an out-of-bounds offset");
    return failed;
}

/*
 * Test long descriptor tag chains without relying on DER's fixed tag scratch.
 * Original source: New asn1c CER regression fixture with independent CER bytes.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; descriptors cover NativeInteger, raw INTEGER, and limits.
 * Returns: Zero when long chains encode/redecode and over-limit modes fail.
 * Errors: No exceptions; mismatches return -1 through cer_require().
 * Responsible party: asn1c maintainers. History: Added for CER tag-chain bounds.
 * Example: called by main() to exercise four explicit wrapper tags.
 */
static int
cer_check_long_tag_chains(void) {
    static const ber_tlv_tag_t four_wrappers[] = {
        CER_CONTEXT_TAG(5), CER_CONTEXT_TAG(6), CER_CONTEXT_TAG(7),
        CER_CONTEXT_TAG(8), CER_UNIVERSAL_TAG(2)
    };
    static const uint8_t four_wrapper_integer[] = {
        0xa5, 0x80, 0xa6, 0x80, 0xa7, 0x80, 0xa8, 0x80,
        0x02, 0x01, 0x7f,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    ber_tlv_tag_t boundary_tags[ASN_STACK_OVERFLOW_LIMIT];
    asn_TYPE_descriptor_t native_td = asn_DEF_NativeInteger;
    asn_TYPE_descriptor_t raw_td = asn_DEF_INTEGER;
    asn_TYPE_descriptor_t too_deep_td = asn_DEF_NativeInteger;
    asn_TYPE_descriptor_t parent_td = asn_DEF_CER_TestSequence;
    asn_TYPE_member_t member;
    cer_test_sequence_t parent_value;
    long native_value = 127;
    uint8_t raw_byte = 0x7f;
    INTEGER_t raw_value = {&raw_byte, 1};
    uint8_t output[1024];
    asn_enc_rval_t encoded;
    size_t i;
    int failed = 0;

    native_td.tags = four_wrappers;
    native_td.tags_count = sizeof(four_wrappers) / sizeof(four_wrappers[0]);
    native_td.all_tags = four_wrappers;
    native_td.all_tags_count = native_td.tags_count;
    raw_td.tags = four_wrappers;
    raw_td.tags_count = native_td.tags_count;
    raw_td.all_tags = four_wrappers;
    raw_td.all_tags_count = native_td.tags_count;
    failed |= cer_check_tag_chain_redecode(
        &native_td, &native_value, four_wrapper_integer,
        sizeof(four_wrapper_integer), 1, "NativeInteger four explicit layers");
    failed |= cer_check_tag_chain_redecode(
        &raw_td, &raw_value, four_wrapper_integer,
        sizeof(four_wrapper_integer), 0, "raw INTEGER four explicit layers");
    failed |= cer_check_wrapped_string_fragments();

    /* Oversized counts must fail before the short test array is dereferenced. */
    too_deep_td.tags = four_wrappers;
    too_deep_td.tags_count = ASN_STACK_OVERFLOW_LIMIT + 1u;
    too_deep_td.all_tags = four_wrappers;
    too_deep_td.all_tags_count = too_deep_td.tags_count;
    errno = 0;
    encoded = cer_encode_to_buffer(NULL, &too_deep_td, &native_value,
                                   output, sizeof(output));
    failed |= cer_require(encoded.encoded == -1 && errno == EOVERFLOW &&
                          encoded.failed_type == &too_deep_td,
                          "descriptor tag count exceeds depth bound");

    /* Construct one native-INTEGER member to test member-level tag accounting. */
    for(i = 0; i + 1 < ASN_STACK_OVERFLOW_LIMIT; i++) {
        boundary_tags[i] = CER_CONTEXT_TAG(i % 31);
    }
    boundary_tags[ASN_STACK_OVERFLOW_LIMIT - 1] = CER_UNIVERSAL_TAG(2);
    too_deep_td = asn_DEF_NativeInteger;
    too_deep_td.tags = boundary_tags;
    too_deep_td.tags_count = ASN_STACK_OVERFLOW_LIMIT;
    too_deep_td.all_tags = boundary_tags;
    too_deep_td.all_tags_count = ASN_STACK_OVERFLOW_LIMIT;
    memset(&member, 0, sizeof(member));
    member.memb_offset = offsetof(cer_test_sequence_t, default_integer);
    member.tag_mode = 1;
    member.tag = CER_CONTEXT_TAG(3);
    member.type = &too_deep_td;
    member.name = "boundaryExplicit";
    parent_td.elements = &member;
    parent_td.elements_count = 1;
    memset(&parent_value, 0, sizeof(parent_value));
    parent_value.default_integer = native_value;
    errno = 0;
    encoded = cer_encode_to_buffer(NULL, &parent_td, &parent_value,
                                   output, sizeof(output));
    failed |= cer_require(encoded.encoded == -1 && errno == EOVERFLOW &&
                          encoded.failed_type == &too_deep_td,
                          "explicit member tag adds one depth layer");

    /* IMPLICIT mode substitutes for the outer descriptor tag at the bound. */
    member.tag_mode = -1;
    errno = 0;
    encoded = cer_encode_to_buffer(NULL, &parent_td, &parent_value,
                                   output, sizeof(output));
    failed |= cer_require(encoded.encoded > 0 && errno == 0,
                          "implicit member tag replaces outer descriptor tag");
    return failed;
}

/*
 * Verify GeneralizedTime calendar, zone, and fraction canonicalization.
 * Original source: New asn1c CER regression fixture, with fixed X.690 TLVs.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; fixed time strings exercise valid and invalid forms.
 * Returns: Zero when canonical vectors match and unsupported time inputs fail.
 * Errors: No exceptions; malformed fields use EBADF and unsupported forms ENOENT.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: `20261011120000.123450000Z` canonicalizes to `.12345Z`.
 */
static int
cer_check_generalized_time_vectors(void) {
    static const uint8_t whole_seconds[] = {
        0x18, 0x0f, '2', '0', '2', '6', '1', '0', '1', '1', '1', '2',
        '0', '0', '0', '0', 'Z'
    };
    static const uint8_t fraction_nine[] = {
        0x18, 0x19, '2', '0', '2', '6', '1', '0', '1', '1', '1', '2',
        '0', '0', '0', '0', '.', '1', '2', '3', '4', '5', '6', '7', '8',
        '9', 'Z'
    };
    static const uint8_t fraction_trimmed[] = {
        0x18, 0x15, '2', '0', '2', '6', '1', '0', '1', '1', '1', '2',
        '0', '0', '0', '0', '.', '1', '2', '3', '4', '5', 'Z'
    };
    static const uint8_t timezone_normalized[] = {
        0x18, 0x0f, '2', '0', '2', '6', '1', '0', '1', '1', '1', '2',
        '0', '0', '0', '0', 'Z'
    };
    GeneralizedTime_t value = {0};
    int failed = 0;

    value.buf = (uint8_t *)"20261011120000Z";
    value.size = strlen((const char *)value.buf);
    failed |= cer_check_vector(&asn_DEF_GeneralizedTime, &value,
                               whole_seconds, sizeof(whole_seconds),
                               "GeneralizedTime canonical whole seconds");
    value.buf = (uint8_t *)"20261011120000.123456789Z";
    value.size = strlen((const char *)value.buf);
    failed |= cer_check_vector(&asn_DEF_GeneralizedTime, &value,
                               fraction_nine, sizeof(fraction_nine),
                               "GeneralizedTime preserves nine fraction digits");
    value.buf = (uint8_t *)"20261011120000.123450000Z";
    value.size = strlen((const char *)value.buf);
    failed |= cer_check_vector(&asn_DEF_GeneralizedTime, &value,
                               fraction_trimmed, sizeof(fraction_trimmed),
                               "GeneralizedTime trims fractional zeroes");
    value.buf = (uint8_t *)"20261011120000,123450000Z";
    value.size = strlen((const char *)value.buf);
    failed |= cer_check_vector(&asn_DEF_GeneralizedTime, &value,
                               fraction_trimmed, sizeof(fraction_trimmed),
                               "GeneralizedTime canonicalizes comma fraction");
    value.buf = (uint8_t *)"20261011140000+0200";
    value.size = strlen((const char *)value.buf);
    failed |= cer_check_vector(&asn_DEF_GeneralizedTime, &value,
                               timezone_normalized,
                               sizeof(timezone_normalized),
                               "GeneralizedTime normalizes numeric timezone");
    value.buf = (uint8_t *)"20261011140000+02";
    value.size = strlen((const char *)value.buf);
    failed |= cer_check_vector(&asn_DEF_GeneralizedTime, &value,
                               timezone_normalized,
                               sizeof(timezone_normalized),
                               "GeneralizedTime normalizes short timezone");
    value.buf = (uint8_t *)"20260230120000Z";
    value.size = strlen((const char *)value.buf);
    failed |= cer_check_error(&asn_DEF_GeneralizedTime, &value, EBADF,
                              "GeneralizedTime rejects invalid calendar date");
    value.buf = (uint8_t *)"20261011120000";
    value.size = strlen((const char *)value.buf);
    failed |= cer_check_error(&asn_DEF_GeneralizedTime, &value, ENOENT,
                              "GeneralizedTime rejects missing timezone");
    value.buf = (uint8_t *)"20261011120000.1234567890Z";
    value.size = strlen((const char *)value.buf);
    failed |= cer_check_error(&asn_DEF_GeneralizedTime, &value, ENOENT,
                              "GeneralizedTime rejects excess fraction precision");
    value.buf = (uint8_t *)"2026101112.5Z";
    value.size = strlen((const char *)value.buf);
    failed |= cer_check_error(&asn_DEF_GeneralizedTime, &value, ENOENT,
                              "GeneralizedTime rejects fractional hour support");
    value.buf = (uint8_t *)"202610111230.5Z";
    value.size = strlen((const char *)value.buf);
    failed |= cer_check_error(&asn_DEF_GeneralizedTime, &value, ENOENT,
                              "GeneralizedTime rejects fractional minute support");
    return failed;
}

/*
 * Compare one character/octet string at the 1000-octet CER boundary.
 * Original source: New asn1c CER regression fixture, following X.690 8.23.3/9.2.
 * Version/date: 1.1, 2026-10-12.
 * Parameters: td/tag_number/unit_size select the type; content_size chooses
 *   type-aligned lengths around 1000 octets; label identifies the expected form.
 * Returns: Zero if the generated primitive/fragment TLV matches the fixed form.
 * Errors: Invalid test widths/lengths fail through cer_require().
 * Responsible party: asn1c maintainers. History: Added BMP/Universal widths.
 * Example: cer_check_string_boundary(&asn_DEF_BMPString, 30, 2, 1002, "BMP").
 */
static int
cer_check_string_boundary(const asn_TYPE_descriptor_t *td, unsigned tag_number,
                          size_t unit_size, size_t content_size,
                          const char *label) {
    uint8_t content[1004];
    uint8_t expected[1100];
    size_t expected_size = 0; /* state variable: initialized TLV bytes. */
    size_t offset; /* state variable: code-unit fill position. */
    uint8_t fill_byte = tag_number == 18 ? (uint8_t)'1' : (uint8_t)'A';

    if(!td || tag_number == 0 || tag_number > 30
    || (unit_size != 1 && unit_size != 2 && unit_size != 4)
    || content_size < 128 || content_size > sizeof(content)
    || content_size % unit_size != 0
    || (content_size > 1000 && 1000 % unit_size != 0)) {
        return cer_require(0, label);
    }

    /* Encode ASCII code points as valid one-, two-, or four-octet units. */
    for(offset = 0; offset < content_size; offset += unit_size) {
        memset(content + offset, 0, unit_size);
        content[offset + unit_size - 1] = fill_byte;
    }
    if(content_size <= 1000) {
        expected[expected_size++] = (uint8_t)tag_number;
        expected[expected_size++] = 0x82;
        expected[expected_size++] = (uint8_t)(content_size >> 8);
        expected[expected_size++] = (uint8_t)content_size;
        memcpy(expected + expected_size, content, content_size);
        expected_size += content_size;
    } else {
        expected[expected_size++] = (uint8_t)(tag_number | 0x20);
        expected[expected_size++] = 0x80;
        expected[expected_size++] = 0x04;
        expected[expected_size++] = 0x82;
        expected[expected_size++] = 0x03;
        expected[expected_size++] = 0xe8;
        memcpy(expected + expected_size, content, 1000);
        expected_size += 1000;
        expected[expected_size++] = 0x04;
        expected[expected_size++] = (uint8_t)(content_size - 1000);
        memcpy(expected + expected_size, content + 1000,
               content_size - 1000);
        expected_size += content_size - 1000;
        expected[expected_size++] = 0x00;
        expected[expected_size++] = 0x00;
    }
    {
        OCTET_STRING_t value;
        memset(&value, 0, sizeof(value));
        value.buf = content;
        value.size = content_size;
        return cer_check_vector(td, &value, expected, expected_size, label);
    }
}

/*
 * Exercise CER boundaries for OCTET and representative character string types.
 * Original source: New asn1c CER regression fixture, following X.690 9.2.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; descriptors, character widths, and aligned lengths are fixed.
 * Returns: Zero when every primitive and constructed vector matches.
 * Errors: No exceptions; failed vectors return -1 and write diagnostics.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called by main() to check type-valid lengths around 1000 octets.
 */
static int
cer_check_string_boundaries(void) {
    static const struct {
        const asn_TYPE_descriptor_t *type; /* CER descriptor under test. */
        unsigned tag; /* Intrinsic universal primitive tag number. */
        size_t unit_size; /* Encoded width of each ASCII test character. */
        size_t sizes[3]; /* Type-valid payload lengths around 1000 octets. */
        const char *name; /* Human-readable boundary description. */
    } types[] = {
        {&asn_DEF_OCTET_STRING, 4, 1, {999, 1000, 1001}, "OCTET STRING"},
        {&asn_DEF_UTF8String, 12, 1, {999, 1000, 1001}, "UTF8String"},
        {&asn_DEF_NumericString, 18, 1, {999, 1000, 1001}, "NumericString"},
        {&asn_DEF_PrintableString, 19, 1, {999, 1000, 1001}, "PrintableString"},
        {&asn_DEF_IA5String, 22, 1, {999, 1000, 1001}, "IA5String"},
        {&asn_DEF_GeneralString, 27, 1, {999, 1000, 1001}, "GeneralString"},
        {&asn_DEF_VisibleString, 26, 1, {999, 1000, 1001}, "VisibleString"},
        {&asn_DEF_BMPString, 30, 2, {998, 1000, 1002}, "BMPString"},
        {&asn_DEF_UniversalString, 28, 4, {996, 1000, 1004}, "UniversalString"},
    };
    size_t type_index;
    size_t size_index;
    int failed = 0;

    for(type_index = 0;
        type_index < sizeof(types) / sizeof(types[0]); type_index++) {
        for(size_index = 0; size_index < 3; size_index++) {
            failed |= cer_check_string_boundary(
                types[type_index].type, types[type_index].tag,
                types[type_index].unit_size, types[type_index].sizes[size_index],
                types[type_index].name);
        }
    }
    return failed;
}

/*
 * Verify BIT STRING size thresholds and unused-bit octets in each fragment.
 * Original source: New asn1c CER regression fixture, following X.690 9.2.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; fixed all-one payloads cover 999 through 1001 data octets.
 * Returns: Zero when all primitive/constructed vectors match.
 * Errors: No exceptions; failed vectors return -1 through cer_require().
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called by main() for the BIT STRING fragmentation boundary suite.
 */
static int
cer_check_bit_boundaries(void) {
    uint8_t bits[1001];
    uint8_t expected[1100];
    size_t data_size;
    size_t expected_size;
    int failed = 0;

    memset(bits, 0xff, sizeof(bits));
    for(data_size = 999; data_size <= 1001; data_size++) {
        BIT_STRING_t value;
        expected_size = 0;
        if(data_size == 999) {
            expected[expected_size++] = 0x03;
            expected[expected_size++] = 0x82;
            expected[expected_size++] = 0x03;
            expected[expected_size++] = 0xe8;
            expected[expected_size++] = 0x00;
            memcpy(expected + expected_size, bits, data_size);
            expected_size += data_size;
        } else {
            size_t remainder = data_size - 999;
            expected[expected_size++] = 0x23;
            expected[expected_size++] = 0x80;
            expected[expected_size++] = 0x03;
            expected[expected_size++] = 0x82;
            expected[expected_size++] = 0x03;
            expected[expected_size++] = 0xe8;
            expected[expected_size++] = 0x00;
            memcpy(expected + expected_size, bits, 999);
            expected_size += 999;
            expected[expected_size++] = 0x03;
            expected[expected_size++] = (uint8_t)(1 + remainder);
            expected[expected_size++] = 0x00;
            memcpy(expected + expected_size, bits + 999, remainder);
            expected_size += remainder;
            expected[expected_size++] = 0x00;
            expected[expected_size++] = 0x00;
        }
        memset(&value, 0, sizeof(value));
        value.buf = bits;
        value.size = data_size;
        value.bits_unused = 0;
        failed |= cer_check_vector(&asn_DEF_BIT_STRING, &value, expected,
                                   expected_size,
                                   data_size == 999 ? "BIT STRING 999 bytes" :
                                   data_size == 1000 ? "BIT STRING 1000 bytes" :
                                   "BIT STRING 1001 bytes");
    }
    return failed;
}

/*
 * Verify NamedBitList trimming while ordinary BIT STRING storage is preserved.
 * Original source: New asn1c CER regression fixture, following X.690 11.2.2.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; local descriptor metadata marks one BIT STRING named.
 * Returns: Zero when named trim, ordinary preservation, and malformed cases pass.
 * Errors: No exceptions; assertion failures return -1 after diagnostics.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called by main() after the general BIT STRING fragmentation vectors.
 */
static int
cer_check_named_bit_strings(void) {
    static const uint8_t named_bytes[] = {0x03, 0x02, 0x00, 0xff};
    static const uint8_t ordinary_bytes[] = {0x03, 0x03, 0x00, 0xff, 0x00};
    static const uint8_t named_partial_bytes[] = {0x03, 0x02, 0x03, 0xf8};
    static uint8_t trailing_zero[] = {0xff, 0x00};
    static uint8_t partial_bits[] = {0xf8};
    BIT_STRING_t value;
    asn_OCTET_STRING_specifics_t named_specifics = asn_SPC_BIT_STRING_specs;
    asn_TYPE_descriptor_t named_descriptor = asn_DEF_BIT_STRING;
    int failed = 0;

    /* This local descriptor is the generated NamedBitList state for this call. */
    named_specifics.has_named_bits = 1;
    named_descriptor.specifics = &named_specifics;
    memset(&value, 0, sizeof(value));
    value.buf = trailing_zero;
    value.size = sizeof(trailing_zero);
    failed |= cer_check_vector(&named_descriptor, &value, named_bytes,
                               sizeof(named_bytes), "NamedBitList trims zero octet");
    failed |= cer_check_vector(&asn_DEF_BIT_STRING, &value, ordinary_bytes,
                               sizeof(ordinary_bytes), "ordinary BIT keeps zero octet");
    value.buf = partial_bits;
    value.size = sizeof(partial_bits);
    value.bits_unused = 0;
    failed |= cer_check_vector(&named_descriptor, &value, named_partial_bytes,
                               sizeof(named_partial_bytes),
                               "NamedBitList trims trailing zero bits");
    value.bits_unused = 8;
    failed |= cer_check_error(&asn_DEF_BIT_STRING, &value, EBADF,
                              "BIT STRING rejects unused count eight");
    value.buf = NULL;
    value.size = 1;
    value.bits_unused = 0;
    failed |= cer_check_error(&asn_DEF_BIT_STRING, &value, EBADF,
                              "BIT STRING rejects missing payload");
    return failed;
}

/*
 * Verify constructed CER, nested CHOICE, defaults, tags, SET, and SET OF order.
 * Original source: New generated-style asn1c CER regression descriptors.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; stack values use static generated-style descriptor tables.
 * Returns: Zero when independent sequence/set/set-of golden vectors match.
 * Errors: No exceptions; failed assertions return -1 after diagnostics.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called from main() to validate constructed descriptor dispatch.
 */
static int
cer_check_constructed_vectors(void) {
    static const uint8_t sequence_defaulted[] = {
        0x30, 0x80, 0x01, 0x01, 0xff, 0x01, 0x01, 0xff,
        0x80, 0x01, 0x00, 0xa1, 0x80, 0x01, 0x01, 0xff, 0x00, 0x00,
        0x30, 0x80, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    static const uint8_t sequence_present[] = {
        0x30, 0x80, 0x01, 0x01, 0xff, 0x02, 0x01, 0x07,
        0x02, 0x01, 0x09, 0x02, 0x01, 0x05, 0x80, 0x01,
        0x00, 0xa1, 0x80, 0x01, 0x01, 0xff, 0x00, 0x00,
        0x30, 0x80, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    static const uint8_t set_order[] = {
        0x31, 0x80, 0x02, 0x01, 0x05, 0x01, 0x01, 0xff,
        0xa0, 0x80, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    static const uint8_t set_of_order[] = {
        0x31, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0xff,
        0x02, 0x02, 0xff, 0x7f, 0x00, 0x00
    };
    static const uint8_t choice_boolean[] = {0x01, 0x01, 0xff};
    static const uint8_t choice_integer[] = {0x02, 0x01, 0x05};
    long set_values[] = {-129, 1, -1};
    long *set_pointers[] = {&set_values[0], &set_values[1], &set_values[2]};
    cer_test_sequence_t sequence;
    cer_test_set_t set_value;
    cer_integer_set_t set_of;
    int failed = 0;

    memset(&sequence, 0, sizeof(sequence));
    sequence.required = 1;
    sequence.choice.present = 1;
    sequence.choice.choice.boolean_value = 1;
    sequence.implicit_boolean = 0;
    sequence.explicit_boolean = 1;
    sequence.nested.value = 0;
    failed |= cer_check_vector(&asn_DEF_CER_TestSequence, &sequence,
                               sequence_defaulted, sizeof(sequence_defaulted),
                               "SEQUENCE defaults and nested tags");
    failed |= cer_check_vector(&asn_DEF_CER_TestChoice, &sequence.choice,
                               choice_boolean, sizeof(choice_boolean),
                               "standalone CHOICE BOOLEAN alternative");
    {
        static uint8_t optional_bytes[] = {0x07};
        INTEGER_t optional_integer = {optional_bytes, sizeof(optional_bytes)};
        sequence.optional_integer = &optional_integer;
        sequence.default_integer = 9;
        sequence.choice.present = 2;
        sequence.choice.choice.integer_value = 5;
        failed |= cer_check_vector(&asn_DEF_CER_TestChoice, &sequence.choice,
                                   choice_integer, sizeof(choice_integer),
                                   "standalone CHOICE INTEGER alternative");
        failed |= cer_check_vector(&asn_DEF_CER_TestSequence, &sequence,
                                   sequence_present, sizeof(sequence_present),
                                   "SEQUENCE optional and DEFAULT presence");
    }
    memset(&set_value, 0, sizeof(set_value));
    set_value.choice.present = 2;
    set_value.choice.choice.integer_value = 5;
    set_value.boolean_value = 1;
    set_value.explicit_boolean = 0;
    failed |= cer_check_vector(&asn_DEF_CER_TestSet, &set_value, set_order,
                               sizeof(set_order),
                               "SET minimum CHOICE tag and mixed class order");
    memset(&set_of, 0, sizeof(set_of));
    set_of.list.array = set_pointers;
    set_of.list.count = 3;
    set_of.list.size = 3;
    failed |= cer_check_vector(&asn_DEF_CER_IntegerSet, &set_of, set_of_order,
                               sizeof(set_of_order),
                               "SET OF sorts final encoded TLVs");
    return failed;
}

/*
 * Check that direct output is atomic but generic ATS_CER reports full size.
 * Original source: New asn1c CER regression fixture, based on public API rules.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; a TRUE BOOLEAN is encoded into two-byte prefixes.
 * Returns: Zero when direct and generic short-buffer contracts both hold.
 * Errors: No exceptions; failed assertions return -1 after diagnostics.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called by main() after CER golden-vector comparisons.
 */
static int
cer_check_short_buffers(void) {
    static const uint8_t prefix[] = {0x01, 0x01};
    uint8_t direct[4] = {0xa5, 0xa5, 0xa5, 0xa5};
    uint8_t generic[4] = {0xa5, 0xa5, 0xa5, 0xa5};
    BOOLEAN_t truth = 1;
    asn_enc_rval_t encoded;
    int failed = 0;

    errno = 0;
    encoded = cer_encode_to_buffer(NULL, &asn_DEF_BOOLEAN, &truth, direct, 2);
    failed |= cer_require(encoded.encoded == -1 && errno == ENOSPC &&
                          direct[0] == 0xa5 && direct[1] == 0xa5,
                          "direct short buffer remains untouched");
    errno = 0;
    encoded = asn_encode_to_buffer(NULL, ATS_CER, &asn_DEF_BOOLEAN, &truth,
                                   generic, 2);
    failed |= cer_require(encoded.encoded == 3 &&
                          memcmp(generic, prefix, sizeof(prefix)) == 0 &&
                          generic[2] == 0xa5 && generic[3] == 0xa5,
                          "generic short buffer copies prefix and returns full size");
    return failed;
}

/*
 * Purpose: verify absent OPTIONAL ANY members are omitted in CER composites.
 * Source: CER member-presence and unsupported opaque ANY contracts.
 * Version/date: 1.0, 2026-10-30. Inputs: none. Returns: zero or test failure.
 * Exceptions: none. Author: asn1c maintainers. History: added for OPTIONAL ANY.
 * Example: an empty SEQUENCE emits 30 80 00 00; a present ANY fails.
 */
static int
cer_check_optional_any(void) {
    static const uint8_t empty_sequence[] = {0x30, 0x80, 0x00, 0x00};
    static const uint8_t empty_set[] = {0x31, 0x80, 0x00, 0x00};
    asn_TYPE_member_t member = cer_any_container_members[0];
    asn_TYPE_descriptor_t sequence = asn_DEF_CER_AnyContainer;
    asn_TYPE_descriptor_t set = asn_DEF_CER_TestSet;
    asn_SET_specifics_t set_specifics = cer_test_set_specifics;
    cer_any_container_t value = {NULL};
    ANY_t present;
    int failed = 0;

    member.optional = 1;
    sequence.elements = &member;
    set.elements = &member;
    set.elements_count = 1;
    set_specifics.struct_size = sizeof(value);
    set.specifics = &set_specifics;
    failed |= cer_check_vector(&sequence, &value, empty_sequence,
                               sizeof(empty_sequence), "absent OPTIONAL ANY in SEQUENCE");
    failed |= cer_check_vector(&set, &value, empty_set,
                               sizeof(empty_set), "absent OPTIONAL ANY in SET");
    failed |= cer_check_callback_error(&sequence, &value,
                                       "absent OPTIONAL ANY callback failure in SEQUENCE");
    failed |= cer_check_callback_error(&set, &value,
                                       "absent OPTIONAL ANY callback failure in SET");
    memset(&present, 0, sizeof(present));
    value.value = &present;
    failed |= cer_check_error(&sequence, &value, ENOENT,
                              "present OPTIONAL ANY in SEQUENCE remains unsupported");
    failed |= cer_check_error(&set, &value, ENOENT,
                              "present OPTIONAL ANY in SET remains unsupported");
    return failed;
}

/*
 * Reject malformed metadata/values and stop excessive or cyclic recursion.
 * Original source: New asn1c CER regression fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; local broken descriptors and self-referential values are
 *   created solely for the duration of this test call.
 * Returns: Zero when each malformed input returns the specified public error.
 * Errors: No exceptions; failed assertions return -1 after diagnostics.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called by main() to verify EBADF, ENOENT, and EOVERFLOW paths.
 */
static int
cer_check_invalid_inputs(void) {
    uint8_t integer_byte = 0;
    uint8_t output[128];
    INTEGER_t empty_integer = {&integer_byte, 0};
    INTEGER_t null_integer = {NULL, 1};
    BOOLEAN_t truth = 1;
    cer_required_pointer_t missing = {NULL};
    cer_any_container_t any_container;
    ANY_t any_value;
    asn_TYPE_descriptor_t broken_descriptor = asn_DEF_CER_TestSequence;
    asn_TYPE_member_t broken_member = cer_test_sequence_members[0];
    asn_SEQUENCE_specifics_t broken_specifics = cer_test_sequence_specifics;
    asn_TYPE_descriptor_t broken_native_real = asn_DEF_NativeReal;
    asn_NativeReal_specifics_t broken_native_real_specifics = {3};
    double native_real = 1.0;
    cer_test_sequence_t sequence;
    cer_cycle_t cycle;
    long workspace_value = 1;
    long *workspace_element = &workspace_value;
    cer_integer_set_t malformed_workspace;
    asn_codec_ctx_t depth_limit;
    asn_enc_rval_t encoded;
    int failed = 0;

    failed |= cer_check_error(&asn_DEF_INTEGER, &empty_integer, EBADF,
                              "INTEGER rejects empty contents");
    failed |= cer_check_error(&asn_DEF_INTEGER, &null_integer, EBADF,
                              "INTEGER rejects null contents");
    broken_native_real.specifics = &broken_native_real_specifics;
    failed |= cer_check_error(&broken_native_real, &native_real, EBADF,
                              "NativeReal rejects unsupported float width");
    failed |= cer_check_error(&asn_DEF_CER_RequiredPointer, &missing, EBADF,
                              "required SEQUENCE pointer cannot be absent");
    memset(&any_value, 0, sizeof(any_value));
    any_container.value = &any_value;
    failed |= cer_check_error(&asn_DEF_CER_AnyContainer, &any_container,
                              ENOENT, "ANY has no CER encoder");
    broken_member.memb_offset = UINT_MAX;
    broken_specifics.struct_size = sizeof(cer_test_sequence_t);
    broken_descriptor.elements = &broken_member;
    broken_descriptor.elements_count = 1;
    broken_descriptor.specifics = &broken_specifics;
    memset(&sequence, 0, sizeof(sequence));
    failed |= cer_check_error(&broken_descriptor, &sequence, EBADF,
                              "descriptor rejects out-of-bounds member");
    broken_descriptor = asn_DEF_CER_TestSequence;
    broken_descriptor.elements = NULL;
    failed |= cer_check_error(&broken_descriptor, &sequence, EBADF,
                              "descriptor rejects missing member table");
    broken_descriptor = asn_DEF_CER_TestSequence;
    broken_descriptor.elements = &broken_member;
    broken_descriptor.elements_count = UINT_MAX;
    failed |= cer_check_error(&broken_descriptor, &sequence, EOVERFLOW,
                              "descriptor member count exceeds element cap");
    memset(&malformed_workspace, 0, sizeof(malformed_workspace));
    malformed_workspace.list.array = &workspace_element;
    malformed_workspace.list.count = 1;
    malformed_workspace.list.size = 0;
    failed |= cer_check_error(&asn_DEF_CER_IntegerSet, &malformed_workspace,
                              EBADF, "SET OF rejects count beyond workspace");
    errno = 0;
    encoded = cer_encode_to_buffer(NULL, NULL, &truth, output, sizeof(output));
    failed |= cer_require(encoded.encoded == -1 && errno == EINVAL,
                          "CER rejects null type descriptor");
    errno = 0;
    encoded = cer_encode_to_buffer(NULL, &asn_DEF_BOOLEAN, NULL, output,
                                   sizeof(output));
    failed |= cer_require(encoded.encoded == -1 && errno == EINVAL,
                          "CER rejects null value pointer");
    memset(&sequence, 0, sizeof(sequence));
    sequence.required = truth;
    sequence.choice.present = 1;
    sequence.choice.choice.boolean_value = truth;
    sequence.explicit_boolean = truth;
    sequence.nested.value = truth;
    cycle.next = &cycle;
    memset(&depth_limit, 0, sizeof(depth_limit));
    depth_limit.max_stack_size = 1;
    errno = 0;
    encoded = cer_encode(&depth_limit, &asn_DEF_CER_Cycle, &cycle,
                         cer_capture_cb, &(struct cer_capture){
                             output, sizeof(output), 0, 0
                         });
    failed |= cer_require(encoded.encoded == -1 && errno == EOVERFLOW,
                          "CER enforces caller stack-depth limit");
    errno = 0;
    encoded = cer_encode(NULL, &asn_DEF_CER_Cycle, &cycle,
                         cer_capture_cb, &(struct cer_capture){
                             output, sizeof(output), 0, 0
                         });
    failed |= cer_require(encoded.encoded == -1 && errno == EOVERFLOW,
                          "CER terminates cyclic value at depth cap");
    return failed;
}

/*
 * Run callback-failure checks for both direct CER and generic encoding APIs.
 * Original source: New asn1c CER regression fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; the local callback is configured to fail on its first call.
 * Returns: Zero when both APIs map callback failure to EIO.
 * Errors: No exceptions; check failures return -1 after writing diagnostics.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called by main() after short-buffer checks.
 */
static int
cer_check_callbacks(void) {
    BOOLEAN_t truth = 1;

    return cer_check_callback_error(&asn_DEF_BOOLEAN, &truth,
                                    "direct and generic callbacks map EIO");
}

/*
 * Decode one bounded test vector and verify only its status/consumption.
 * Original source: New CER explicit-wrapper decoder regression fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: td/input select the decoder and input; tag_mode mirrors the
 *   generated member decoder's tagging mode; expected names the result.
 * Returns: Zero when status and bounded consumption match the expectation.
 * Errors: No exceptions; invalid decoder metadata and mismatches return -1.
 * Responsible party: asn1c maintainers. History: Added for CER wrappers.
 * Example: cer_check_decode_status(&asn_DEF_BOOLEAN, 1, bytes, n, RC_OK, name).
 */
static int
cer_check_decode_status(const asn_TYPE_descriptor_t *td, int tag_mode,
                        const uint8_t *input, size_t input_size,
                        enum asn_dec_rval_code_e expected,
                        const char *label) {
    void *decoded = NULL;
    asn_dec_rval_t result;
    int failed = 0;

    if(!td || !td->op || !td->op->ber_decoder || !input) {
        return cer_require(0, label);
    }
    if(tag_mode == 0) {
        result = ber_decode(NULL, td, &decoded, input, input_size);
    } else {
        result = td->op->ber_decoder(NULL, td, &decoded, input, input_size,
                                     tag_mode);
    }
    failed |= cer_require(result.code == expected, label);
    failed |= cer_require(result.consumed <= input_size, label);
    if(result.code == RC_OK) {
        failed |= cer_require(result.consumed == input_size, label);
    }
    if(decoded && td->op->free_struct) {
        td->op->free_struct(td, decoded, ASFM_FREE_EVERYTHING);
    }
    return failed;
}

/*
 * Require a context-free primitive retry to leave the input unconsumed.
 * Original source: New CER explicit-wrapper decoder regression fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: td/input select the decoder/input; tag_mode selects descriptor
 *   handling; label identifies the missing value or EOC condition.
 * Returns: Zero when the decoder requests more bytes with consumed equal zero.
 * Errors: No exceptions; status/consumption mismatches return -1.
 * Responsible party: asn1c maintainers. History: Added for scalar EOC preflight.
 * Example: a BOOLEAN missing its final wrapper EOC must consume no input.
 */
static int
cer_check_primitive_no_progress(const asn_TYPE_descriptor_t *td, int tag_mode,
                                const uint8_t *input, size_t input_size,
                                const char *label) {
    void *decoded = NULL;
    asn_dec_rval_t result;
    int failed = 0;

    if(!td || !td->op || !td->op->ber_decoder || !input) {
        return cer_require(0, label);
    }
    if(tag_mode == 0) {
        result = ber_decode(NULL, td, &decoded, input, input_size);
    } else {
        result = td->op->ber_decoder(NULL, td, &decoded, input, input_size,
                                     tag_mode);
    }
    failed |= cer_require(result.code == RC_WMORE && result.consumed == 0,
                          label);
    if(decoded && td->op->free_struct) {
        td->op->free_struct(td, decoded, ASFM_FREE_EVERYTHING);
    }
    return failed;
}

/* Bytewise decoder fixture state retains the input not yet accepted. */
struct cer_bytewise_state {
    uint8_t pending[64]; /* state variable: unconsumed bytes awaiting decode. */
    void *decoded; /* state variable: partially or fully decoded value. */
    size_t pending_size; /* state variable: number of bytes in pending. */
    size_t input_size; /* state variable: total encoded bytes to deliver. */
    size_t input_index; /* state variable: next byte to deliver. */
    int complete; /* state variable: final TLV accepted by decoder. */
};

/*
 * Apply one decoder result and update the bytewise retry state.
 * Original source: New CER explicit-wrapper decoder regression fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: td/tag_mode select decoder behavior; state owns pending bytes;
 *   require_zero_more applies to context-free primitive retries; retry receives
 *   whether unconsumed buffered input should be tried again; label names errors.
 * Returns: Zero for a valid incremental result, otherwise -1.
 * Errors: Rejects overconsumption, failure, and unexpected result codes.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: a partial wrapper returns RC_WMORE and leaves scalar input pending.
 */
static int
cer_bytewise_apply_result(const asn_TYPE_descriptor_t *td, int tag_mode,
                          struct cer_bytewise_state *state,
                          int require_zero_more, int *retry,
                          const char *label) {
    asn_dec_rval_t result;
    size_t consumed;
    int failed = 0;

    result = td->op->ber_decoder(NULL, td, &state->decoded, state->pending,
                                 state->pending_size, tag_mode);
    if(result.consumed > state->pending_size)
        return cer_require(0, label);
    consumed = result.consumed;
    if(consumed) {
        state->pending_size -= consumed;
        memmove(state->pending, state->pending + consumed, state->pending_size);
    }
    if(result.code == RC_OK) {
        state->complete = 1;
        failed |= cer_require(state->input_index == state->input_size
                              && state->pending_size == 0, label);
    } else if(result.code == RC_FAIL) {
        failed |= cer_require(0, label);
    } else if(result.code == RC_WMORE) {
        if(require_zero_more) failed |= cer_require(consumed == 0, label);
        *retry = consumed && state->pending_size;
    } else {
        failed |= cer_require(0, label);
    }
    return failed;
}

/*
 * Feed a valid encoded value one byte at a time through a BER decoder.
 * Original source: New CER explicit-wrapper decoder regression fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: td selects the decoder; mode is tag mode; input/size are a TLV;
 *   require_zero_more applies only to context-free primitive retries; label
 *   identifies invalid status, consumption, or incomplete completion.
 * Returns: Zero when the decoder completes exactly at the final input byte.
 * Errors: No exceptions; bounded-buffer overflow or decoder errors return -1.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: bytewise feed of an indefinite explicit wrapper with split EOC.
 */
static int
cer_check_bytewise_decode(const asn_TYPE_descriptor_t *td, int tag_mode,
                          const uint8_t *input, size_t input_size,
                          int require_zero_more, const char *label) {
    struct cer_bytewise_state state; /* state variable: incremental decode. */
    int failed = 0;

    memset(&state, 0, sizeof(state));
    if(!td || !td->op || !td->op->ber_decoder || !input) {
        return cer_require(0, label);
    }
    state.input_size = input_size;
    while(state.input_index < input_size && !state.complete && !failed) {
        int retry = 1; /* state variable: process available buffered bytes. */

        if(state.pending_size == sizeof(state.pending)) {
            failed |= cer_require(0, label);
            break;
        }
        state.pending[state.pending_size++] = input[state.input_index++];
        while(retry && !state.complete && !failed) {
            failed |= cer_bytewise_apply_result(td, tag_mode, &state,
                                                require_zero_more, &retry, label);
        }
    }
    failed |= cer_require(state.complete && !failed, label);
    if(state.decoded && td->op->free_struct) {
        td->op->free_struct(td, state.decoded, ASFM_FREE_EVERYTHING);
    }
    return failed;
}

/*
 * Verify explicit BOOLEAN, INTEGER, and NULL scalar wrapper vectors.
 * Original source: New CER decoder regression fixture with independent TLVs.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; fixed tag_mode=1 vectors exercise scalar decoders.
 * Returns: Zero when scalar payloads and complete wrapper lengths match.
 * Errors: No exceptions; decoder mismatches are reported through cer_require.
 * Responsible party: asn1c maintainers. History: Added for explicit CER tags.
 * Example: [5] EXPLICIT BOOLEAN is encoded as A5 80 01 01 FF 00 00.
 */
static int
cer_check_explicit_scalar_vectors(void) {
    static const uint8_t boolean[] = {
        0xa5, 0x80, 0x01, 0x01, 0xff, 0x00, 0x00
    };
    static const uint8_t integer[] = {
        0xa5, 0x80, 0x02, 0x01, 0x7f, 0x00, 0x00
    };
    static const uint8_t null_value[] = {
        0xa5, 0x80, 0x05, 0x00, 0x00, 0x00
    };
    void *decoded = NULL;
    asn_dec_rval_t result;
    int failed = 0;

    result = asn_DEF_BOOLEAN.op->ber_decoder(NULL, &asn_DEF_BOOLEAN,
                                             &decoded, boolean, sizeof(boolean),
                                             1);
    failed |= cer_require(result.code == RC_OK
                          && result.consumed == sizeof(boolean)
                          && decoded && *(BOOLEAN_t *)decoded,
                          "explicit indefinite BOOLEAN");
    if(decoded) asn_DEF_BOOLEAN.op->free_struct(
        &asn_DEF_BOOLEAN, decoded, ASFM_FREE_EVERYTHING);
    decoded = NULL;
    result = asn_DEF_INTEGER.op->ber_decoder(NULL, &asn_DEF_INTEGER,
                                             &decoded, integer, sizeof(integer),
                                             1);
    failed |= cer_require(result.code == RC_OK
                          && result.consumed == sizeof(integer)
                          && decoded && ((INTEGER_t *)decoded)->size == 1
                          && ((INTEGER_t *)decoded)->buf[0] == 0x7f,
                          "explicit indefinite INTEGER");
    if(decoded) asn_DEF_INTEGER.op->free_struct(
        &asn_DEF_INTEGER, decoded, ASFM_FREE_EVERYTHING);
    failed |= cer_check_decode_status(&asn_DEF_NULL, 1, null_value,
                                      sizeof(null_value), RC_OK,
                                      "explicit indefinite NULL");
    return failed;
}

/*
 * Check definite EXPLICIT wrappers for raw and native INTEGER decoders.
 * Original source: New CER/BER primitive-wrapper regression vectors.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; tag_mode=1 vectors carry fixed INTEGER contents.
 * Returns: Zero when both INTEGER APIs decode and malformed chains reject.
 * Errors: No exceptions; status/value mismatches are reported via cer_require.
 * Responsible party: asn1c maintainers. History: Added for scalar chain audit.
 * Example: `[5] EXPLICIT INTEGER` is `A5 03 02 01 7F` in definite BER.
 */
static int
cer_check_definite_scalar_wrappers(void) {
    static const uint8_t definite_integer[] = {
        0xa5, 0x03, 0x02, 0x01, 0x7f
    };
    static const uint8_t constructed_integer[] = {
        0xa5, 0x03, 0x22, 0x01, 0x7f
    };
    static const uint8_t short_wrapper[] = {
        0xa5, 0x02, 0x02, 0x01, 0x7f
    };
    static const uint8_t duplicate_integer[] = {
        0xa5, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00, 0x00
    };
    void *raw_decoded = NULL;
    void *native_decoded = NULL;
    asn_dec_rval_t result;
    int failed = 0;

    result = asn_DEF_INTEGER.op->ber_decoder(
        NULL, &asn_DEF_INTEGER, &raw_decoded, definite_integer,
        sizeof(definite_integer), 1);
    failed |= cer_require(result.code == RC_OK
                          && result.consumed == sizeof(definite_integer)
                          && raw_decoded
                          && ((INTEGER_t *)raw_decoded)->size == 1
                          && ((INTEGER_t *)raw_decoded)->buf[0] == 0x7f,
                          "definite explicit raw INTEGER");
    if(raw_decoded) asn_DEF_INTEGER.op->free_struct(
        &asn_DEF_INTEGER, raw_decoded, ASFM_FREE_EVERYTHING);
    raw_decoded = NULL;

    result = asn_DEF_NativeInteger.op->ber_decoder(
        NULL, &asn_DEF_NativeInteger, &native_decoded, definite_integer,
        sizeof(definite_integer), 1);
    failed |= cer_require(result.code == RC_OK
                          && result.consumed == sizeof(definite_integer)
                          && native_decoded && *(long *)native_decoded == 127,
                          "definite explicit native INTEGER");
    if(native_decoded) asn_DEF_NativeInteger.op->free_struct(
        &asn_DEF_NativeInteger, native_decoded, ASFM_FREE_EVERYTHING);

    failed |= cer_check_decode_status(&asn_DEF_INTEGER, 1,
                                      constructed_integer,
                                      sizeof(constructed_integer), RC_FAIL,
                                      "explicit INTEGER final tag must be primitive");
    failed |= cer_check_decode_status(&asn_DEF_INTEGER, 1, short_wrapper,
                                      sizeof(short_wrapper), RC_FAIL,
                                      "explicit INTEGER wrapper length is exact");
    failed |= cer_check_decode_status(&asn_DEF_INTEGER, 1, duplicate_integer,
                                      sizeof(duplicate_integer), RC_FAIL,
                                      "explicit INTEGER rejects duplicate child");
    return failed;
}

/*
 * Decode one built-in NativeInteger vector and verify its native value.
 * Original source: New CER/BER decoder regression helper.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: input/input_size bound the TLV; tag_mode selects its tagging;
 *             expected_value is the decoded long; label names the assertion.
 * Returns: Zero when decoding, consumption, and native value all match.
 * Errors: No exceptions; status or value mismatches are reported via cer_require.
 * Responsible party: asn1c maintainers. History: Added for NULL specifics.
 * Example: decode `88 01 07` with tag_mode -1 and expect native value 7.
 */
static int
cer_check_builtin_native_integer_vector(const uint8_t *input,
                                        size_t input_size, int tag_mode,
                                        long expected_value,
                                        const char *label) {
    void *decoded = NULL; /* state variable: decoder-owned native result. */
    asn_dec_rval_t result;
    int failed = 0;

    result = asn_DEF_NativeInteger.op->ber_decoder(
        NULL, &asn_DEF_NativeInteger, &decoded, input, input_size, tag_mode);
    failed |= cer_require(result.code == RC_OK, label);
    failed |= cer_require(result.consumed == input_size, label);
    failed |= cer_require(decoded && *(long *)decoded == expected_value, label);
    if(decoded) asn_DEF_NativeInteger.op->free_struct(
        &asn_DEF_NativeInteger, decoded, ASFM_FREE_EVERYTHING);
    return failed;
}

/*
 * Exercise the built-in NativeInteger descriptor with absent specifics.
 * Original source: New CER/BER decoder regression vectors.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; fixed vectors cover natural, implicit, and explicit tags.
 * Returns: Zero when all built-in NativeInteger vectors decode as value 7.
 * Errors: No exceptions; decode mismatches are reported by the vector helper.
 * Responsible party: asn1c maintainers. History: Added for NULL specifics.
 * Example: `[5] EXPLICIT INTEGER` uses A5 80 02 01 07 00 00.
 */
static int
cer_check_builtin_native_integer_decoding(void) {
    static const uint8_t natural[] = {0x02, 0x01, 0x07};
    static const uint8_t implicit_context_8[] = {0x88, 0x01, 0x07};
    static const uint8_t explicit_context_5[] = {
        0xa5, 0x80, 0x02, 0x01, 0x07, 0x00, 0x00
    };
    int failed = 0;

    failed |= cer_check_builtin_native_integer_vector(
        natural, sizeof(natural), 0, 7, "built-in NativeInteger natural tag");
    failed |= cer_check_builtin_native_integer_vector(
        implicit_context_8, sizeof(implicit_context_8), -1, 7,
        "built-in NativeInteger implicit context tag");
    failed |= cer_check_builtin_native_integer_vector(
        explicit_context_5, sizeof(explicit_context_5), 1, 7,
        "built-in NativeInteger explicit context tag");
    return failed;
}

/*
 * Decode a value using a copied descriptor with one supported field width.
 * Original source: New NativeInteger metadata regression helper.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: td/specs are copied metadata; width selects native storage;
 *             input/input_size bound the TLV; label names the assertion.
 * Returns: Zero when the vector decodes to seven using the selected width.
 * Errors: No exceptions; decoder or value mismatches are reported via cer_require.
 * Responsible party: asn1c maintainers. History: Added for width validation.
 * Example: a one-byte NativeInteger descriptor decodes `02 01 07` as seven.
 */
static int
cer_check_native_integer_width_vector(asn_TYPE_descriptor_t *td,
                                      asn_INTEGER_specifics_t *specs,
                                      int width, const uint8_t *input,
                                      size_t input_size, const char *label) {
    void *decoded = NULL; /* state variable: decoder-owned native result. */
    asn_dec_rval_t result;
    int failed = 0;

    specs->field_width = width;
    td->specifics = specs;
    result = td->op->ber_decoder(NULL, td, &decoded, input, input_size, 0);
    failed |= cer_require(result.code == RC_OK, label);
    failed |= cer_require(result.consumed == input_size, label);
    failed |= cer_require(decoded
                          && NativeInteger_load_s(decoded, specs) == 7,
                          label);
    if(decoded) td->op->free_struct(td, decoded, ASFM_FREE_EVERYTHING);
    return failed;
}

/*
 * Reject malformed NativeInteger widths before allocation and accept valid ones.
 * Original source: New NativeInteger metadata regression vectors.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; a copied descriptor decodes the positive INTEGER TLV.
 * Returns: Zero when invalid widths fail safely and widths 1/2/4/8 decode.
 * Errors: No exceptions; result mismatches are reported through cer_require.
 * Responsible party: asn1c maintainers. History: Added for width validation.
 * Example: field_width 3 must fail with a null target and zero consumption.
 */
static int
cer_check_native_integer_width_metadata(void) {
    static const uint8_t positive_integer[] = {0x02, 0x01, 0x07};
    asn_TYPE_descriptor_t descriptor = asn_DEF_NativeInteger;
    asn_INTEGER_specifics_t specifics = {0};
    void *decoded = NULL; /* state variable: must remain null on invalid widths. */
    asn_dec_rval_t result;
    int failed = 0;

    descriptor.specifics = &specifics;
    specifics.field_width = 3;
    result = descriptor.op->ber_decoder(NULL, &descriptor, &decoded,
                                        positive_integer,
                                        sizeof(positive_integer), 0);
    failed |= cer_require(result.code == RC_FAIL && result.consumed == 0
                          && decoded == NULL,
                          "NativeInteger rejects width three before allocation");

    specifics.field_width = -1;
    result = descriptor.op->ber_decoder(NULL, &descriptor, &decoded,
                                        positive_integer,
                                        sizeof(positive_integer), 0);
    failed |= cer_require(result.code == RC_FAIL && result.consumed == 0
                          && decoded == NULL,
                          "NativeInteger rejects negative width before allocation");

    failed |= cer_check_native_integer_width_vector(
        &descriptor, &specifics, 1, positive_integer,
        sizeof(positive_integer), "NativeInteger accepts one-byte storage width");
    failed |= cer_check_native_integer_width_vector(
        &descriptor, &specifics, 2, positive_integer,
        sizeof(positive_integer), "NativeInteger accepts two-byte storage width");
    failed |= cer_check_native_integer_width_vector(
        &descriptor, &specifics, 4, positive_integer,
        sizeof(positive_integer), "NativeInteger accepts four-byte storage width");
    failed |= cer_check_native_integer_width_vector(
        &descriptor, &specifics, 8, positive_integer,
        sizeof(positive_integer), "NativeInteger accepts eight-byte storage width");
    return failed;
}

/*
 * Verify explicit OCTET and BIT STRING payloads and wrapper lengths.
 * Original source: New CER decoder regression fixture with independent TLVs.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; fixed tag_mode=1 vectors exercise string decoders.
 * Returns: Zero when both payload values and complete wrapper lengths match.
 * Errors: No exceptions; decoder mismatches are reported through cer_require.
 * Responsible party: asn1c maintainers. History: Added for explicit CER tags.
 * Example: [5] EXPLICIT OCTET STRING wraps a single `Z` octet.
 */
static int
cer_check_explicit_string_vectors(void) {
    static const uint8_t octets[] = {
        0xa5, 0x80, 0x04, 0x01, 'Z', 0x00, 0x00
    };
    static const uint8_t bits[] = {
        0xa5, 0x80, 0x03, 0x02, 0x03, 0xa8, 0x00, 0x00
    };
    void *decoded = NULL;
    asn_dec_rval_t result;
    int failed = 0;

    result = asn_DEF_OCTET_STRING.op->ber_decoder(
        NULL, &asn_DEF_OCTET_STRING, &decoded, octets, sizeof(octets), 1);
    failed |= cer_require(result.code == RC_OK
                          && result.consumed == sizeof(octets)
                          && decoded && ((OCTET_STRING_t *)decoded)->size == 1
                          && ((OCTET_STRING_t *)decoded)->buf[0] == 'Z',
                          "explicit indefinite OCTET STRING");
    if(decoded) asn_DEF_OCTET_STRING.op->free_struct(
        &asn_DEF_OCTET_STRING, decoded, ASFM_FREE_EVERYTHING);
    decoded = NULL;
    result = asn_DEF_BIT_STRING.op->ber_decoder(
        NULL, &asn_DEF_BIT_STRING, &decoded, bits, sizeof(bits), 1);
    failed |= cer_require(result.code == RC_OK
                          && result.consumed == sizeof(bits)
                          && decoded && ((BIT_STRING_t *)decoded)->size == 1
                          && ((BIT_STRING_t *)decoded)->bits_unused == 3
                          && ((BIT_STRING_t *)decoded)->buf[0] == 0xa8,
                          "explicit indefinite BIT STRING");
    if(decoded) asn_DEF_BIT_STRING.op->free_struct(
        &asn_DEF_BIT_STRING, decoded, ASFM_FREE_EVERYTHING);
    return failed;
}

/*
 * Exercise indefinite explicit wrappers for scalar and string decoders.
 * Original source: New CER decoder regression fixture with independent TLVs.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; all descriptors and expected bytes are local constants.
 * Returns: Zero when wrappers decode and malformed/truncated inputs reject.
 * Errors: No exceptions; decoder mismatches are reported through cer_require.
 * Responsible party: asn1c maintainers. History: Added for explicit CER tags.
 * Example: [5] EXPLICIT BOOLEAN is fed as A5 80 01 01 FF 00 00.
 */
static int
cer_check_explicit_primitive_decoding(void) {
    static const uint8_t explicit_boolean[] = {
        0xa5, 0x80, 0x01, 0x01, 0xff, 0x00, 0x00
    };
    static const uint8_t explicit_octets[] = {
        0xa5, 0x80, 0x04, 0x01, 'Z', 0x00, 0x00
    };
    static const uint8_t wrong_boolean_inner[] = {
        0xa5, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00
    };
    static const uint8_t wrong_octets_inner[] = {
        0xa5, 0x80, 0x03, 0x02, 0x00, 0xa0, 0x00, 0x00
    };
    static const uint8_t wrong_bits_inner[] = {
        0xa5, 0x80, 0x04, 0x01, 'Z', 0x00, 0x00
    };
    static const uint8_t missing_eoc[] = {
        0xa5, 0x80, 0x01, 0x01, 0xff
    };
    static const uint8_t partial_eoc[] = {
        0xa5, 0x80, 0x01, 0x01, 0xff, 0x00
    };
    static const uint8_t malformed_eoc[] = {
        0xa5, 0x80, 0x01, 0x01, 0xff, 0x00, 0x01, 0x00
    };
    static const uint8_t missing_octet_eoc[] = {
        0xa5, 0x80, 0x04, 0x01, 'Z'
    };
    static const uint8_t partial_octet_eoc[] = {
        0xa5, 0x80, 0x04, 0x01, 'Z', 0x00
    };
    static const uint8_t malformed_octet_eoc[] = {
        0xa5, 0x80, 0x04, 0x01, 'Z', 0x00, 0x01, 0x00
    };
    static const uint8_t two_inner_values[] = {
        0xa5, 0x80, 0x04, 0x01, 'A', 0x04, 0x01, 'Z', 0x00, 0x00
    };
    size_t prefix; /* state variable: byte prefix under incremental test. */
    int failed = cer_check_explicit_scalar_vectors();

    failed |= cer_check_definite_scalar_wrappers();
    failed |= cer_check_builtin_native_integer_decoding();
    failed |= cer_check_native_integer_width_metadata();
    failed |= cer_check_explicit_string_vectors();

    failed |= cer_check_decode_status(&asn_DEF_BOOLEAN, 1,
                                      wrong_boolean_inner,
                                      sizeof(wrong_boolean_inner), RC_FAIL,
                                      "explicit BOOLEAN rejects wrong inner tag");
    failed |= cer_check_decode_status(&asn_DEF_OCTET_STRING, 1,
                                      wrong_octets_inner,
                                      sizeof(wrong_octets_inner), RC_FAIL,
                                      "explicit OCTET STRING rejects wrong tag");
    failed |= cer_check_decode_status(&asn_DEF_BIT_STRING, 1,
                                      wrong_bits_inner,
                                      sizeof(wrong_bits_inner), RC_FAIL,
                                      "explicit BIT STRING rejects wrong tag");
    failed |= cer_check_primitive_no_progress(
        &asn_DEF_BOOLEAN, 1, missing_eoc, sizeof(missing_eoc),
        "explicit wrapper requires full EOC");
    failed |= cer_check_primitive_no_progress(
        &asn_DEF_BOOLEAN, 1, partial_eoc, sizeof(partial_eoc),
        "explicit wrapper rejects partial EOC");
    failed |= cer_check_decode_status(&asn_DEF_BOOLEAN, 1, malformed_eoc,
                                      sizeof(malformed_eoc), RC_FAIL,
                                      "explicit wrapper rejects malformed EOC");
    failed |= cer_check_decode_status(&asn_DEF_OCTET_STRING, 1,
                                      missing_octet_eoc,
                                      sizeof(missing_octet_eoc), RC_WMORE,
                                      "explicit OCTET STRING requires EOC");
    failed |= cer_check_decode_status(&asn_DEF_OCTET_STRING, 1,
                                      partial_octet_eoc,
                                      sizeof(partial_octet_eoc), RC_WMORE,
                                      "explicit OCTET STRING rejects partial EOC");
    failed |= cer_check_decode_status(&asn_DEF_OCTET_STRING, 1,
                                      malformed_octet_eoc,
                                      sizeof(malformed_octet_eoc), RC_FAIL,
                                      "explicit OCTET STRING rejects malformed EOC");
    failed |= cer_check_decode_status(&asn_DEF_OCTET_STRING, 1,
                                      two_inner_values,
                                      sizeof(two_inner_values), RC_FAIL,
                                      "explicit OCTET wrapper rejects two inner values");
    for(prefix = 1; prefix < sizeof(explicit_boolean); prefix++) {
        failed |= cer_check_primitive_no_progress(
            &asn_DEF_BOOLEAN, 1, explicit_boolean, prefix,
            "explicit BOOLEAN truncated header or EOC");
    }
    for(prefix = 1; prefix < sizeof(explicit_octets); prefix++) {
        failed |= cer_check_decode_status(&asn_DEF_OCTET_STRING, 1,
                                          explicit_octets, prefix, RC_WMORE,
                                          "explicit OCTET STRING truncated header or EOC");
    }
    failed |= cer_check_bytewise_decode(&asn_DEF_BOOLEAN, 1,
                                        explicit_boolean,
                                        sizeof(explicit_boolean),
                                        1,
                                        "explicit BOOLEAN bytewise feed");
    return failed;
}

/*
 * Decode a one-member SEQUENCE whose OCTET STRING has explicit tag layers.
 * Original source: New generated-style CER decoder regression descriptor.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: value_tags are named inner tags; input/size are the outer TLV;
 *   label names the case; stream requests one-byte incremental delivery.
 * Returns: Zero when the member payload and full wrapper consumption match.
 * Errors: No exceptions; malformed descriptors or test mismatches return -1.
 * Responsible party: asn1c maintainers. History: Added for explicit wrapper gaps.
 * Example: [5] EXPLICIT [6] EXPLICIT OCTET STRING in an indefinite SEQUENCE.
 */
static int
cer_check_explicit_octet_sequence(const ber_tlv_tag_t *value_tags,
                                  size_t value_tag_count,
                                  const uint8_t *input, size_t input_size,
                                  int stream, const char *label) {
    static const ber_tlv_tag_t sequence_tags[] = {CER_UNIVERSAL_TAG(16)};
    asn_TYPE_descriptor_t octets_td = asn_DEF_OCTET_STRING;
    asn_TYPE_member_t member;
    asn_SEQUENCE_specifics_t specifics;
    asn_TYPE_descriptor_t sequence_td;
    cer_test_explicit_octets_t *decoded = NULL;
    cer_test_explicit_octets_t *generic_decoded = NULL;
    asn_dec_rval_t result;
    asn_dec_rval_t generic_result;
    int failed = 0;

    if(!value_tags || !value_tag_count || !input || !input_size) {
        return cer_require(0, label);
    }
    octets_td.tags = value_tags;
    octets_td.tags_count = value_tag_count;
    octets_td.all_tags = value_tags;
    octets_td.all_tags_count = value_tag_count;
    memset(&member, 0, sizeof(member));
    member.flags = 0;
    member.optional = 0;
    member.memb_offset = offsetof(cer_test_explicit_octets_t, value);
    member.tag = CER_CONTEXT_TAG(5);
    member.tag_mode = 1;
    member.type = &octets_td;
    member.name = "wrappedValue";
    memset(&specifics, 0, sizeof(specifics));
    specifics.struct_size = sizeof(cer_test_explicit_octets_t);
    specifics.ctx_offset = offsetof(cer_test_explicit_octets_t, _asn_ctx);
    specifics.first_extension = -1;
    memset(&sequence_td, 0, sizeof(sequence_td));
    sequence_td.name = "CER-ExplicitOctetSequence";
    sequence_td.xml_tag = "CER-ExplicitOctetSequence";
    sequence_td.op = &asn_OP_SEQUENCE;
    sequence_td.tags = sequence_tags;
    sequence_td.tags_count = sizeof(sequence_tags) / sizeof(sequence_tags[0]);
    sequence_td.all_tags = sequence_tags;
    sequence_td.all_tags_count = sequence_td.tags_count;
    sequence_td.elements = &member;
    sequence_td.elements_count = 1;
    sequence_td.specifics = &specifics;

    result = ber_decode(NULL, &sequence_td, (void **)&decoded,
                        input, input_size);
    failed |= cer_require(result.code == RC_OK
                          && result.consumed == input_size && decoded
                          && decoded->value.size == 1
                          && decoded->value.buf[0] == 'Z', label);
    generic_result = asn_decode(NULL, ATS_CER, &sequence_td,
                                (void **)&generic_decoded, input, input_size);
    failed |= cer_require(generic_result.code == RC_OK
                          && generic_result.consumed == input_size
                          && generic_decoded
                          && generic_decoded->value.size == 1
                          && generic_decoded->value.buf[0] == 'Z', label);
    if(decoded) {
        sequence_td.op->free_struct(&sequence_td, decoded,
                                    ASFM_FREE_EVERYTHING);
    }
    if(generic_decoded) {
        sequence_td.op->free_struct(&sequence_td, generic_decoded,
                                    ASFM_FREE_EVERYTHING);
    }
    if(stream) {
        failed |= cer_check_bytewise_decode(&sequence_td, 0, input,
                                            input_size, 0, label);
    }
    return failed;
}

/*
 * Exercise top-level named EXPLICIT descriptors with mixed-length wrappers.
 * Original source: New CER decoder regression using descriptor tag chains.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; each descriptor and independent wire vector is local.
 * Returns: Zero when named wrappers, malformed cases, and bytewise feeds pass.
 * Errors: No exceptions; mismatches are reported through cer_require().
 * Responsible party: asn1c maintainers. History: Added for top-level aliases.
 * Example: `ber_decode` accepts `[5] EXPLICIT BOOLEAN` with an indefinite tag.
 */
static int
cer_check_named_explicit_decoding(void) {
    static const ber_tlv_tag_t boolean_tags[] = {
        CER_CONTEXT_TAG(5), CER_UNIVERSAL_TAG(1)
    };
    static const ber_tlv_tag_t integer_tags[] = {
        CER_CONTEXT_TAG(5), CER_UNIVERSAL_TAG(2)
    };
    static const ber_tlv_tag_t null_tags[] = {
        CER_CONTEXT_TAG(5), CER_UNIVERSAL_TAG(5)
    };
    static const ber_tlv_tag_t octet_tags[] = {
        CER_CONTEXT_TAG(5), CER_UNIVERSAL_TAG(4)
    };
    static const ber_tlv_tag_t bit_tags[] = {
        CER_CONTEXT_TAG(5), CER_UNIVERSAL_TAG(3)
    };
    static const ber_tlv_tag_t layered_octet_tags[] = {
        CER_CONTEXT_TAG(5), CER_CONTEXT_TAG(6), CER_UNIVERSAL_TAG(4)
    };
    static const ber_tlv_tag_t layered_boolean_tags[] = {
        CER_CONTEXT_TAG(5), CER_CONTEXT_TAG(6), CER_UNIVERSAL_TAG(1)
    };
    static const uint8_t named_boolean[] = {
        0xa5, 0x80, 0x01, 0x01, 0xff, 0x00, 0x00
    };
    static const uint8_t named_integer[] = {
        0xa5, 0x80, 0x02, 0x01, 0x7f, 0x00, 0x00
    };
    static const uint8_t named_null[] = {
        0xa5, 0x80, 0x05, 0x00, 0x00, 0x00
    };
    static const uint8_t named_octets[] = {
        0xa5, 0x80, 0x04, 0x01, 'Z', 0x00, 0x00
    };
    static const uint8_t named_bits[] = {
        0xa5, 0x80, 0x03, 0x02, 0x03, 0xa8, 0x00, 0x00
    };
    static const uint8_t layered_octets[] = {
        0xa5, 0x80, 0xa6, 0x80, 0x04, 0x01, 'Z',
        0x00, 0x00, 0x00, 0x00
    };
    static const uint8_t layered_boolean[] = {
        0xa5, 0x80, 0xa6, 0x80, 0x01, 0x01, 0xff,
        0x00, 0x00, 0x00, 0x00
    };
    static const uint8_t wrong_outer[] = {
        0xa6, 0x80, 0x01, 0x01, 0xff, 0x00, 0x00
    };
    static const uint8_t wrong_inner[] = {
        0xa5, 0x80, 0x02, 0x01, 0x7f, 0x00, 0x00
    };
    static const uint8_t wrong_second_layer[] = {
        0xa5, 0x80, 0xa7, 0x80, 0x04, 0x01, 'Z',
        0x00, 0x00, 0x00, 0x00
    };
    static const uint8_t primitive_second_layer[] = {
        0xa5, 0x80, 0x86, 0x01, 'Z', 0x00, 0x00
    };
    static const uint8_t no_boolean_eoc[] = {
        0xa5, 0x80, 0x01, 0x01, 0xff
    };
    static const uint8_t malformed_boolean_eoc[] = {
        0xa5, 0x80, 0x01, 0x01, 0xff, 0x00, 0x01, 0x00
    };
    static const uint8_t missing_layer_eoc[] = {
        0xa5, 0x80, 0xa6, 0x80, 0x01, 0x01, 0xff, 0x00, 0x00
    };
    static const uint8_t malformed_layer_eoc[] = {
        0xa5, 0x80, 0xa6, 0x80, 0x01, 0x01, 0xff,
        0x00, 0x00, 0x00, 0x01
    };
    asn_TYPE_descriptor_t boolean_td = asn_DEF_BOOLEAN;
    asn_TYPE_descriptor_t integer_td = asn_DEF_INTEGER;
    asn_TYPE_descriptor_t null_td = asn_DEF_NULL;
    asn_TYPE_descriptor_t octet_td = asn_DEF_OCTET_STRING;
    asn_TYPE_descriptor_t bit_td = asn_DEF_BIT_STRING;
    asn_TYPE_descriptor_t layered_octet_td = asn_DEF_OCTET_STRING;
    asn_TYPE_descriptor_t layered_boolean_td = asn_DEF_BOOLEAN;
    size_t prefix; /* state variable: byte prefix under truncation checks. */
    int failed = 0;

    boolean_td.tags = boolean_tags;
    boolean_td.tags_count = sizeof(boolean_tags) / sizeof(boolean_tags[0]);
    boolean_td.all_tags = boolean_tags;
    boolean_td.all_tags_count = boolean_td.tags_count;
    integer_td.tags = integer_tags;
    integer_td.tags_count = sizeof(integer_tags) / sizeof(integer_tags[0]);
    integer_td.all_tags = integer_tags;
    integer_td.all_tags_count = integer_td.tags_count;
    null_td.tags = null_tags;
    null_td.tags_count = sizeof(null_tags) / sizeof(null_tags[0]);
    null_td.all_tags = null_tags;
    null_td.all_tags_count = null_td.tags_count;
    octet_td.tags = octet_tags;
    octet_td.tags_count = sizeof(octet_tags) / sizeof(octet_tags[0]);
    octet_td.all_tags = octet_tags;
    octet_td.all_tags_count = octet_td.tags_count;
    bit_td.tags = bit_tags;
    bit_td.tags_count = sizeof(bit_tags) / sizeof(bit_tags[0]);
    bit_td.all_tags = bit_tags;
    bit_td.all_tags_count = bit_td.tags_count;
    layered_octet_td.tags = layered_octet_tags;
    layered_octet_td.tags_count =
        sizeof(layered_octet_tags) / sizeof(layered_octet_tags[0]);
    layered_octet_td.all_tags = layered_octet_tags;
    layered_octet_td.all_tags_count = layered_octet_td.tags_count;
    layered_boolean_td.tags = layered_boolean_tags;
    layered_boolean_td.tags_count =
        sizeof(layered_boolean_tags) / sizeof(layered_boolean_tags[0]);
    layered_boolean_td.all_tags = layered_boolean_tags;
    layered_boolean_td.all_tags_count = layered_boolean_td.tags_count;

    failed |= cer_check_decode_status(&boolean_td, 0, named_boolean,
                                      sizeof(named_boolean), RC_OK,
                                      "top-level explicit BOOLEAN");
    failed |= cer_check_decode_status(&integer_td, 0, named_integer,
                                      sizeof(named_integer), RC_OK,
                                      "top-level explicit INTEGER");
    failed |= cer_check_decode_status(&null_td, 0, named_null,
                                      sizeof(named_null), RC_OK,
                                      "top-level explicit NULL");
    failed |= cer_check_decode_status(&octet_td, 0, named_octets,
                                      sizeof(named_octets), RC_OK,
                                      "top-level explicit OCTET STRING");
    failed |= cer_check_decode_status(&bit_td, 0, named_bits,
                                      sizeof(named_bits), RC_OK,
                                      "top-level explicit BIT STRING");
    failed |= cer_check_decode_status(&layered_octet_td, 0, layered_octets,
                                      sizeof(layered_octets), RC_OK,
                                      "top-level multiple explicit OCTET layers");
    failed |= cer_check_decode_status(&layered_boolean_td, 0,
                                      layered_boolean,
                                      sizeof(layered_boolean), RC_OK,
                                      "top-level multiple explicit BOOLEAN layers");
    failed |= cer_check_decode_status(&layered_octet_td, 0,
                                      wrong_second_layer,
                                      sizeof(wrong_second_layer), RC_FAIL,
                                      "top-level explicit wrong second tag");
    failed |= cer_check_decode_status(&layered_octet_td, 0,
                                      primitive_second_layer,
                                      sizeof(primitive_second_layer), RC_FAIL,
                                      "explicit middle tag must be constructed");
    failed |= cer_check_decode_status(&boolean_td, 0, wrong_outer,
                                      sizeof(wrong_outer), RC_FAIL,
                                      "top-level explicit wrong outer tag");
    failed |= cer_check_decode_status(&boolean_td, 0, wrong_inner,
                                      sizeof(wrong_inner), RC_FAIL,
                                      "top-level explicit wrong inner tag");
    failed |= cer_check_primitive_no_progress(
        &boolean_td, 0, no_boolean_eoc, sizeof(no_boolean_eoc),
        "top-level explicit missing EOC");
    failed |= cer_check_decode_status(&boolean_td, 0, malformed_boolean_eoc,
                                      sizeof(malformed_boolean_eoc), RC_FAIL,
                                      "top-level explicit malformed EOC");
    failed |= cer_check_primitive_no_progress(
        &layered_boolean_td, 0, missing_layer_eoc,
        sizeof(missing_layer_eoc),
        "nested explicit wrapper missing outer EOC");
    failed |= cer_check_decode_status(&layered_boolean_td, 0,
                                      malformed_layer_eoc,
                                      sizeof(malformed_layer_eoc), RC_FAIL,
                                      "nested explicit wrapper malformed EOC");
    for(prefix = 1; prefix < sizeof(named_boolean); prefix++) {
        failed |= cer_check_primitive_no_progress(
            &boolean_td, 0, named_boolean, prefix,
            "top-level explicit truncated input");
    }
    for(prefix = 1; prefix < sizeof(layered_octets); prefix++) {
        failed |= cer_check_decode_status(&layered_octet_td, 0,
                                          layered_octets, prefix, RC_WMORE,
                                          "nested explicit truncated input");
    }
    failed |= cer_check_bytewise_decode(&boolean_td, 0, named_boolean,
                                        sizeof(named_boolean),
                                        1,
                                        "top-level explicit BOOLEAN bytewise");
    failed |= cer_check_bytewise_decode(&layered_octet_td, 0, layered_octets,
                                        sizeof(layered_octets),
                                        0,
                                        "top-level explicit OCTET bytewise");
    return failed;
}

/*
 * Decode an IMPLICIT alias whose inherited type contains an EXPLICIT layer.
 * Original source: New CER regression for ber_decode tag_mode == -1.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; local descriptor copies represent named alias tag chains.
 * Returns: Zero when valid aliases decode and wrong nested tags are rejected.
 * Errors: No exceptions; decoder mismatches return -1 through cer_require().
 * Responsible party: asn1c maintainers. History: Added for mixed CER tag modes.
 * Example: `[0] IMPLICIT [5] EXPLICIT INTEGER` starts with an indefinite [0].
 */
static int
cer_check_implicit_explicit_alias_decoding(void) {
    static const ber_tlv_tag_t integer_tags[] = {
        CER_CONTEXT_TAG(0), CER_CONTEXT_TAG(5), CER_UNIVERSAL_TAG(2)
    };
    static const ber_tlv_tag_t boolean_tags[] = {
        CER_CONTEXT_TAG(0), CER_CONTEXT_TAG(5), CER_UNIVERSAL_TAG(1)
    };
    static const ber_tlv_tag_t octet_tags[] = {
        CER_CONTEXT_TAG(0), CER_CONTEXT_TAG(5), CER_UNIVERSAL_TAG(4)
    };
    static const uint8_t integer_alias[] = {
        0xa0, 0x80, 0xa5, 0x80, 0x02, 0x01, 0x7f,
        0x00, 0x00, 0x00, 0x00
    };
    static const uint8_t boolean_alias[] = {
        0xa0, 0x80, 0xa5, 0x80, 0x01, 0x01, 0xff,
        0x00, 0x00, 0x00, 0x00
    };
    static const uint8_t wrong_inner_layer[] = {
        0xa0, 0x80, 0xa6, 0x80, 0x01, 0x01, 0xff,
        0x00, 0x00, 0x00, 0x00
    };
    static const uint8_t octet_alias[] = {
        0xa0, 0x80, 0xa5, 0x80, 0x04, 0x01, 'Z',
        0x00, 0x00, 0x00, 0x00
    };
    static const uint8_t primitive_explicit_layer[] = {
        0xa0, 0x80, 0x85, 0x03, 0x04, 0x01, 'Z', 0x00, 0x00
    };
    asn_TYPE_descriptor_t integer_td = asn_DEF_INTEGER;
    asn_TYPE_descriptor_t boolean_td = asn_DEF_BOOLEAN;
    asn_TYPE_descriptor_t octet_td = asn_DEF_OCTET_STRING;
    void *decoded = NULL;
    asn_dec_rval_t result;
    int failed = 0;

    integer_td.tags = integer_tags;
    integer_td.tags_count = sizeof(integer_tags) / sizeof(integer_tags[0]);
    integer_td.all_tags = integer_tags;
    integer_td.all_tags_count = integer_td.tags_count;
    boolean_td.tags = boolean_tags;
    boolean_td.tags_count = sizeof(boolean_tags) / sizeof(boolean_tags[0]);
    boolean_td.all_tags = boolean_tags;
    boolean_td.all_tags_count = boolean_td.tags_count;
    octet_td.tags = octet_tags;
    octet_td.tags_count = sizeof(octet_tags) / sizeof(octet_tags[0]);
    octet_td.all_tags = octet_tags;
    octet_td.all_tags_count = octet_td.tags_count;

    result = integer_td.op->ber_decoder(NULL, &integer_td, &decoded,
                                        integer_alias, sizeof(integer_alias),
                                        -1);
    failed |= cer_require(result.code == RC_OK
                          && result.consumed == sizeof(integer_alias)
                          && decoded && ((INTEGER_t *)decoded)->size == 1
                          && ((INTEGER_t *)decoded)->buf[0] == 0x7f,
                          "tag_mode -1 IMPLICIT EXPLICIT INTEGER alias");
    if(decoded) integer_td.op->free_struct(&integer_td, decoded,
                                           ASFM_FREE_EVERYTHING);
    decoded = NULL;
    failed |= cer_check_decode_status(&boolean_td, -1, boolean_alias,
                                      sizeof(boolean_alias), RC_OK,
                                      "tag_mode -1 IMPLICIT EXPLICIT BOOLEAN alias");
    failed |= cer_check_decode_status(&boolean_td, -1, wrong_inner_layer,
                                      sizeof(wrong_inner_layer), RC_FAIL,
                                      "tag_mode -1 validates inner explicit tag");
    result = octet_td.op->ber_decoder(NULL, &octet_td, &decoded, octet_alias,
                                      sizeof(octet_alias), -1);
    failed |= cer_require(result.code == RC_OK
                          && result.consumed == sizeof(octet_alias)
                          && decoded && ((OCTET_STRING_t *)decoded)->size == 1
                          && ((OCTET_STRING_t *)decoded)->buf[0] == 'Z',
                          "tag_mode -1 IMPLICIT EXPLICIT OCTET alias");
    if(decoded) octet_td.op->free_struct(&octet_td, decoded,
                                         ASFM_FREE_EVERYTHING);
    failed |= cer_check_decode_status(&octet_td, -1, primitive_explicit_layer,
                                      sizeof(primitive_explicit_layer), RC_FAIL,
                                      "tag_mode -1 requires inner explicit form");
    return failed;
}

/*
 * Verify ordinary top-level constructed OCTET and BIT STRING decoding.
 * Original source: New CER regression fixture with independent constructed TLVs.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; fixed vectors include an indefinite outer content frame.
 * Returns: Zero when both payloads, EOC handling, and incremental feeds pass.
 * Errors: No exceptions; status and value mismatches return -1.
 * Responsible party: asn1c maintainers. History: Added for top-level EOC frames.
 * Example: `24 80 04 01 5A 00 00` decodes to OCTET STRING `Z`.
 */
static int
cer_check_top_level_constructed_strings(void) {
    static const uint8_t constructed_octets[] = {
        0x24, 0x80, 0x04, 0x01, 'Z', 0x00, 0x00
    };
    static const uint8_t constructed_bits[] = {
        0x23, 0x80, 0x03, 0x02, 0x00, 0xa8, 0x00, 0x00
    };
    static const uint8_t malformed_eoc[] = {
        0x24, 0x80, 0x04, 0x01, 'Z', 0x00, 0x01
    };
    static const uint8_t oversized_child[] = {
        0x24, 0x03, 0x04, 0x05, 'A', 'B', 'C', 'D', 'E'
    };
    void *decoded = NULL;
    asn_dec_rval_t result;
    size_t prefix; /* state variable: truncated prefix length under test. */
    int failed = 0;

    result = ber_decode(NULL, &asn_DEF_OCTET_STRING, &decoded,
                        constructed_octets, sizeof(constructed_octets));
    failed |= cer_require(result.code == RC_OK
                          && result.consumed == sizeof(constructed_octets)
                          && decoded && ((OCTET_STRING_t *)decoded)->size == 1
                          && ((OCTET_STRING_t *)decoded)->buf[0] == 'Z',
                          "ordinary top-level constructed OCTET STRING");
    if(decoded) asn_DEF_OCTET_STRING.op->free_struct(
        &asn_DEF_OCTET_STRING, decoded, ASFM_FREE_EVERYTHING);
    decoded = NULL;

    /* Strict CER requires primitive form for strings of 1000 octets or less. */
    result = asn_decode(NULL, ATS_CER, &asn_DEF_OCTET_STRING, &decoded,
                        constructed_octets, sizeof(constructed_octets));
    failed |= cer_require(result.code == RC_FAIL && result.consumed == 0
                          && decoded == NULL,
                          "strict CER rejects short constructed OCTET STRING");
    if(decoded) asn_DEF_OCTET_STRING.op->free_struct(
        &asn_DEF_OCTET_STRING, decoded, ASFM_FREE_EVERYTHING);
    decoded = NULL;

    result = ber_decode(NULL, &asn_DEF_BIT_STRING, &decoded,
                        constructed_bits, sizeof(constructed_bits));
    failed |= cer_require(result.code == RC_OK
                          && result.consumed == sizeof(constructed_bits)
                          && decoded && ((BIT_STRING_t *)decoded)->size == 1
                          && ((BIT_STRING_t *)decoded)->bits_unused == 0
                          && ((BIT_STRING_t *)decoded)->buf[0] == 0xa8,
                          "ordinary top-level constructed BIT STRING");
    if(decoded) asn_DEF_BIT_STRING.op->free_struct(
        &asn_DEF_BIT_STRING, decoded, ASFM_FREE_EVERYTHING);

    failed |= cer_check_decode_status(&asn_DEF_OCTET_STRING, 0,
                                      malformed_eoc, sizeof(malformed_eoc),
                                      RC_FAIL,
                                      "constructed OCTET STRING rejects bad EOC");
    failed |= cer_check_decode_status(&asn_DEF_OCTET_STRING, 0,
                                      oversized_child,
                                      sizeof(oversized_child), RC_FAIL,
                                      "constructed child cannot exceed parent frame");
    for(prefix = 1; prefix < sizeof(constructed_octets); prefix++) {
        failed |= cer_check_decode_status(&asn_DEF_OCTET_STRING, 0,
                                          constructed_octets, prefix, RC_WMORE,
                                          "constructed OCTET STRING truncated feed");
    }
    failed |= cer_check_bytewise_decode(&asn_DEF_OCTET_STRING, 0,
                                        constructed_octets,
                                        sizeof(constructed_octets), 0,
                                        "constructed OCTET STRING bytewise feed");
    failed |= cer_check_bytewise_decode(&asn_DEF_BIT_STRING, 0,
                                        constructed_bits,
                                        sizeof(constructed_bits), 0,
                                        "constructed BIT STRING bytewise feed");
    return failed;
}

/*
 * Decode an OCTET STRING and verify its complete payload and consumption.
 * Original source: New CER regression helper for BER wrapper compatibility.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: td/mode select descriptor tags; input is the encoded TLV;
 *             expected/expected_size describe the decoded OCTET STRING.
 * Returns: Zero when decoding succeeds and exactly matches the expected value.
 * Errors: Invalid metadata, decoder failures, or byte mismatches return -1.
 * Responsible party: asn1c maintainers. History: Added for explicit wrappers.
 * Example: checks A5 05 24 03 04 01 5A as the one-byte string "Z".
 */
static int
cer_check_octet_payload(const asn_TYPE_descriptor_t *td, int mode,
                        const uint8_t *input, size_t input_size,
                        const uint8_t *expected, size_t expected_size,
                        const char *label) {
    void *decoded = NULL;
    asn_dec_rval_t result;
    OCTET_STRING_t *octets;
    int failed = 0;

    if(!td || !td->op || !td->op->ber_decoder || !input
    || (!expected && expected_size))
        return cer_require(0, label);
    result = td->op->ber_decoder(NULL, td, &decoded, input, input_size, mode);
    if(result.code != RC_OK || result.consumed != input_size || !decoded) {
        fprintf(stderr,
                "%s: status=%d consumed=%zu input=%zu expected_payload=%zu\n",
                label, (int)result.code, result.consumed, input_size,
                expected_size);
        failed |= cer_require(0, label);
    }
    if(decoded && result.code == RC_OK) {
        octets = (OCTET_STRING_t *)decoded;
        if(octets->size != expected_size
        || (expected_size && (!octets->buf
                              || memcmp(octets->buf, expected, expected_size)))) {
            fprintf(stderr, "%s: decoded_payload=%zu expected_payload=%zu\n",
                    label, octets->size, expected_size);
            failed |= cer_require(0, label);
        }
    }
    if(decoded && td->op->free_struct)
        td->op->free_struct(td, decoded, ASFM_FREE_EVERYTHING);
    return failed;
}

/*
 * Preserve definite BER wrappers and ordinary constructed OCTET STRINGs.
 * Original source: New CER regression vectors for BER decoder compatibility.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; vectors cover dynamic and descriptor-known EXPLICIT tags.
 * Returns: Zero when all valid wrapper and fragment layouts decode exactly.
 * Errors: No exceptions; decoder or payload mismatches return -1.
 * Responsible party: asn1c maintainers. History: Added for wrapper guard review.
 * Example: an indefinite `[5]` wrapper may contain a definite constructed value.
 */
static int
cer_check_ber_wrapper_compatibility(void) {
    static const ber_tlv_tag_t named_octet_tags[] = {
        CER_CONTEXT_TAG(5), CER_UNIVERSAL_TAG(4)
    };
    static const ber_tlv_tag_t utf8_outer_tags[] = {
        CER_UNIVERSAL_TAG(4)
    };
    static const ber_tlv_tag_t implicit_octet_tags[] = {
        CER_CONTEXT_TAG(7)
    };
    static const ber_tlv_tag_t implicit_octet_fragment_tags[] = {
        CER_CONTEXT_TAG(7), CER_UNIVERSAL_TAG(4)
    };
    static const uint8_t one_octet[] = {'Z'};
    static const uint8_t two_octets[] = {'A', 'Z'};
    static const uint8_t definite_wrapper[] = {
        0xa5, 0x05, 0x24, 0x03, 0x04, 0x01, 'Z'
    };
    static const uint8_t indefinite_wrapper[] = {
        0xa5, 0x80, 0x24, 0x03, 0x04, 0x01, 'Z', 0x00, 0x00
    };
    static const uint8_t ordinary_fragments[] = {
        0x24, 0x06, 0x04, 0x01, 'A', 0x04, 0x01, 'Z'
    };
    static const uint8_t named_definite_fragments[] = {
        0xa5, 0x08, 0x24, 0x06, 0x04, 0x01, 'A', 0x04, 0x01, 'Z'
    };
    static const uint8_t utf8_fragments[] = {
        0x24, 0x80, 0x04, 0x01, 'A', 0x04, 0x01, 'Z', 0x00, 0x00
    };
    static const uint8_t utf8_natural_fragments[] = {
        0x24, 0x80, 0x0c, 0x01, 'A', 0x0c, 0x01, 'Z', 0x00, 0x00
    };
    static const uint8_t implicit_octet_fragments[] = {
        0xa7, 0x80, 0x04, 0x01, 'A', 0x04, 0x01, 'Z', 0x00, 0x00
    };
    asn_TYPE_descriptor_t named_octets = asn_DEF_OCTET_STRING;
    asn_TYPE_descriptor_t utf8 = asn_DEF_UTF8String;
    asn_TYPE_descriptor_t implicit_octets = asn_DEF_OCTET_STRING;
    int failed = 0;

    named_octets.tags = named_octet_tags;
    named_octets.tags_count = sizeof(named_octet_tags)
                            / sizeof(named_octet_tags[0]);
    named_octets.all_tags = named_octet_tags;
    named_octets.all_tags_count = named_octets.tags_count;
    utf8.tags = utf8_outer_tags;
    utf8.tags_count = sizeof(utf8_outer_tags) / sizeof(utf8_outer_tags[0]);
    utf8.all_tags = utf8_outer_tags;
    utf8.all_tags_count = sizeof(utf8_outer_tags) / sizeof(utf8_outer_tags[0]);
    implicit_octets.tags = implicit_octet_tags;
    implicit_octets.tags_count =
        sizeof(implicit_octet_tags) / sizeof(implicit_octet_tags[0]);
    implicit_octets.all_tags = implicit_octet_fragment_tags;
    implicit_octets.all_tags_count = sizeof(implicit_octet_fragment_tags)
                                  / sizeof(implicit_octet_fragment_tags[0]);
    failed |= cer_check_octet_payload(&asn_DEF_OCTET_STRING, 1,
                                      definite_wrapper,
                                      sizeof(definite_wrapper), one_octet,
                                      sizeof(one_octet),
                                      "definite explicit wrapper with constructed BER value");
    failed |= cer_check_octet_payload(&asn_DEF_OCTET_STRING, 1,
                                      indefinite_wrapper,
                                      sizeof(indefinite_wrapper), one_octet,
                                      sizeof(one_octet),
                                      "indefinite wrapper with definite constructed value");
    failed |= cer_check_octet_payload(&named_octets, 0,
                                      definite_wrapper,
                                      sizeof(definite_wrapper), one_octet,
                                      sizeof(one_octet),
                                      "named explicit definite BER wrapper");
    failed |= cer_check_octet_payload(&named_octets, 0,
                                      named_definite_fragments,
                                      sizeof(named_definite_fragments),
                                      two_octets, sizeof(two_octets),
                                      "named wrapper preserves both string fragments");
    failed |= cer_check_octet_payload(&asn_DEF_OCTET_STRING, 0,
                                      ordinary_fragments,
                                      sizeof(ordinary_fragments), two_octets,
                                      sizeof(two_octets),
                                      "ordinary definite constructed multi-fragment string");
    failed |= cer_check_octet_payload(&utf8, 0, utf8_fragments,
                                      sizeof(utf8_fragments), two_octets,
                                      sizeof(two_octets),
                                      "UTF8String fragments use OCTET STRING tags");
    failed |= cer_check_decode_status(&utf8, 0, utf8_natural_fragments,
                                      sizeof(utf8_natural_fragments), RC_FAIL,
                                      "UTF8String rejects natural-tag fragments");
    failed |= cer_check_octet_payload(&implicit_octets, 0,
                                      implicit_octet_fragments,
                                      sizeof(implicit_octet_fragments),
                                      two_octets, sizeof(two_octets),
                                      "IMPLICIT OCTET STRING fragments use natural tags");
    return failed;
}

/*
 * Exercise explicit OCTET STRING wrappers inside indefinite SEQUENCE values.
 * Original source: New CER decoder regression vectors with fixed X.690 TLVs.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; one- and two-layer wrapper bytes are fixed locally.
 * Returns: Zero when both full-buffer and bytewise decoding pass.
 * Errors: No exceptions; assertion failures return -1 after stderr reporting.
 * Responsible party: asn1c maintainers. History: Added for CER wrappers.
 * Example: sequence member `[5] EXPLICIT OCTET STRING` ends before sequence EOC.
 */
static int
cer_check_explicit_sequence_decoding(void) {
    static const ber_tlv_tag_t universal_octets[] = {CER_UNIVERSAL_TAG(4)};
    static const ber_tlv_tag_t named_octet_layer[] = {
        CER_CONTEXT_TAG(6), CER_UNIVERSAL_TAG(4)
    };
    static const uint8_t one_explicit_layer[] = {
        0x30, 0x80, 0xa5, 0x80, 0x04, 0x01, 'Z',
        0x00, 0x00, 0x00, 0x00
    };
    static const uint8_t two_explicit_layers[] = {
        0x30, 0x80, 0xa5, 0x80, 0xa6, 0x80, 0x04, 0x01, 'Z',
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    int failed = 0;

    failed |= cer_check_explicit_octet_sequence(
        universal_octets, sizeof(universal_octets) / sizeof(universal_octets[0]),
        one_explicit_layer, sizeof(one_explicit_layer), 1,
        "explicit OCTET STRING in indefinite SEQUENCE");
    failed |= cer_check_explicit_octet_sequence(
        named_octet_layer,
        sizeof(named_octet_layer) / sizeof(named_octet_layer[0]),
        two_explicit_layers, sizeof(two_explicit_layers), 1,
        "multiple named explicit OCTET STRING layers");
    return failed;
}

/*
 * Check that the test target's configured encoded-byte ceiling is enforced.
 * Original source: New asn1c CER resource-limit regression fixture.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; a 4097-byte OCTET STRING exceeds this target's 4096 cap.
 * Returns: Zero when the limited build rejects the input with EOVERFLOW.
 * Errors: No exceptions; builds without the test cap skip this focused check.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called by main() in the `check-CER` target.
 */
static int
cer_check_output_cap(void) {
#if defined(ASN_CER_MAX_ENCODED_SIZE) && ASN_CER_MAX_ENCODED_SIZE == 4096
    uint8_t content[4097];
    OCTET_STRING_t value;

    memset(content, 'X', sizeof(content));
    memset(&value, 0, sizeof(value));
    value.buf = content;
    value.size = sizeof(content);
    return cer_check_error(&asn_DEF_OCTET_STRING, &value, EOVERFLOW,
                           "CER enforces the configured output cap");
#else
    return 0;
#endif
}

/*
 * Run the CER skeleton regression suite and return its process status.
 * Original source: New asn1c CER skeleton regression suite.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: None; all test inputs are fixed local values.
 * Returns: EXIT_SUCCESS when every encoder/decoder test passes, else failure.
 * Errors: No exceptions; detailed failures are reported by individual checks.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: `./check-CER` runs independent CER encoder and decoder tests.
 */
int
main(void) {
    int failed = 0;

    failed |= cer_check_small_primitive_vectors();
    failed |= cer_check_inline_oid_records();
    failed |= cer_check_long_tag_chains();
    failed |= cer_check_generalized_time_vectors();
    failed |= cer_check_string_boundaries();
    failed |= cer_check_bit_boundaries();
    failed |= cer_check_named_bit_strings();
    failed |= cer_check_constructed_vectors();
    failed |= cer_check_short_buffers();
    failed |= cer_check_invalid_inputs();
    failed |= cer_check_optional_any();
    failed |= cer_check_callbacks();
    failed |= cer_check_explicit_primitive_decoding();
    failed |= cer_check_named_explicit_decoding();
    failed |= cer_check_implicit_explicit_alias_decoding();
    failed |= cer_check_top_level_constructed_strings();
    failed |= cer_check_ber_wrapper_compatibility();
    failed |= cer_check_explicit_sequence_decoding();
    failed |= cer_check_output_cap();
    if(failed) return EXIT_FAILURE;
    puts("CER encoder and decoder tests passed");
    return EXIT_SUCCESS;
}
