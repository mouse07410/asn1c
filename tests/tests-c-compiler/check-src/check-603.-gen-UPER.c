/*
 * Verify generated descriptors for inline CONTAINING types.
 * Original source: contents-constraint compiler and check-569 regression.
 * Version: 2026-10-30. Author: asn1c maintainers.
 */
#undef NDEBUG
#include <assert.h>
#include <stdint.h>

#include "OctetInteger.h"
#include "BitInteger.h"
#include "OctetRecord.h"
#include "BitRecord.h"
#include <asn_application.h>

/*
 * Check inline INTEGER bounds and exact contained bits.
 * Source: generated CONTAINING constraints. Version: 2026-10-30.
 * Inputs: none. Returns nothing; assertions report regression.
 * Exceptions: none. Author: asn1c maintainers. History: inline type support.
 * Example: 2-bit PER value 2 succeeds while spare value 3 fails.
 */
static void
check_integer_containing(void) {
    static const uint8_t valid[] = {0x80};
    static const uint8_t spare[] = {0xc0};
    static const uint8_t padding[] = {0x81};
    static const uint8_t ber_valid[] = {0x02, 0x01, 0x02};
    static const uint8_t ber_bad[] = {0x02, 0x01, 0x03};
    static const uint8_t oer_valid[] = {0x02};
    static const uint8_t oer_bad[] = {0x03};
    OCTET_STRING_t octets = {0};
    BIT_STRING_t bits = {0};

    octets.buf = (uint8_t *)valid;
    octets.size = sizeof(valid);
    assert(asn_check_constraints_with_syntax(&asn_DEF_OctetInteger, &octets,
                                              ATS_UNALIGNED_BASIC_PER, 0, 0) == 0);
    octets.buf = (uint8_t *)spare;
    assert(asn_check_constraints_with_syntax(&asn_DEF_OctetInteger, &octets,
                                              ATS_UNALIGNED_BASIC_PER, 0, 0) != 0);
    octets.buf = (uint8_t *)padding;
    assert(asn_check_constraints_with_syntax(&asn_DEF_OctetInteger, &octets,
                                              ATS_UNALIGNED_BASIC_PER, 0, 0) != 0);

    octets.buf = (uint8_t *)valid;
    assert(asn_check_constraints_with_syntax(&asn_DEF_OctetInteger, &octets,
                                              ATS_ALIGNED_BASIC_PER, 0, 0) == 0);
    octets.buf = (uint8_t *)spare;
    assert(asn_check_constraints_with_syntax(&asn_DEF_OctetInteger, &octets,
                                              ATS_ALIGNED_BASIC_PER, 0, 0) != 0);

    octets.buf = (uint8_t *)oer_valid;
    assert(asn_check_constraints_with_syntax(&asn_DEF_OctetInteger, &octets,
                                              ATS_BASIC_OER, 0, 0) == 0);
    octets.buf = (uint8_t *)oer_bad;
    assert(asn_check_constraints_with_syntax(&asn_DEF_OctetInteger, &octets,
                                              ATS_BASIC_OER, 0, 0) != 0);

    octets.buf = (uint8_t *)ber_valid;
    octets.size = sizeof(ber_valid);
    assert(asn_check_constraints_with_syntax(&asn_DEF_OctetInteger, &octets,
                                              ATS_BER, 0, 0) == 0);
    octets.buf = (uint8_t *)ber_bad;
    assert(asn_check_constraints_with_syntax(&asn_DEF_OctetInteger, &octets,
                                              ATS_BER, 0, 0) != 0);

    bits.buf = (uint8_t *)valid;
    bits.size = sizeof(valid);
    bits.bits_unused = 6;
    assert(asn_check_constraints_with_syntax(&asn_DEF_BitInteger, &bits,
                                              ATS_UNALIGNED_BASIC_PER, 0, 0) == 0);
    bits.buf = (uint8_t *)spare;
    assert(asn_check_constraints_with_syntax(&asn_DEF_BitInteger, &bits,
                                              ATS_UNALIGNED_BASIC_PER, 0, 0) != 0);
}

/*
 * Check inline constructed contained type descriptors.
 * Source: contents-constraint AST promotion. Version: 2026-10-30.
 * Inputs: none. Returns nothing; assertions report regression.
 * Exceptions: none. Author: asn1c maintainers. History: inline type support.
 * Example: one embedded BOOLEAN bit succeeds with zero PER padding.
 */
static void
check_record_containing(void) {
    static const uint8_t valid[] = {0x80};
    static const uint8_t padding[] = {0x81};
    OCTET_STRING_t octets = {0};
    BIT_STRING_t bits = {0};

    octets.buf = (uint8_t *)valid;
    octets.size = sizeof(valid);
    assert(asn_check_constraints_with_syntax(&asn_DEF_OctetRecord, &octets,
                                              ATS_UNALIGNED_BASIC_PER, 0, 0) == 0);
    octets.buf = (uint8_t *)padding;
    assert(asn_check_constraints_with_syntax(&asn_DEF_OctetRecord, &octets,
                                              ATS_UNALIGNED_BASIC_PER, 0, 0) != 0);

    bits.buf = (uint8_t *)valid;
    bits.size = sizeof(valid);
    bits.bits_unused = 7;
    assert(asn_check_constraints_with_syntax(&asn_DEF_BitRecord, &bits,
                                              ATS_UNALIGNED_BASIC_PER, 0, 0) == 0);
    bits.bits_unused = 6;
    assert(asn_check_constraints_with_syntax(&asn_DEF_BitRecord, &bits,
                                              ATS_UNALIGNED_BASIC_PER, 0, 0) != 0);
}

/*
 * Run inline primitive and constructed CONTAINING conformance cases.
 * Source: generated C regression harness. Version: 2026-10-30.
 * Inputs: none. Returns zero after passing assertions.
 * Exceptions: assertion failure terminates the test.
 * Author: asn1c maintainers. History: initial inline CONTAINING test.
 * Example: ./check-program.
 */
int
main(void) {
    check_integer_containing();
    check_record_containing();
    return 0;
}
