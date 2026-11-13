/*-
 * Copyright (c) 2026 Contributors. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <cbor_support.h>

/*
 * Purpose: check RFC 8949 indefinite containers and invalid break/chunk forms.
 * Source: RFC 8949 section 3.2 examples. Version: 2026-11-12.
 * Inputs: none. Returns: none; assertion aborts on failure, no exceptions.
 * Author: asn1c maintainers. History: extension-value scanner regression.
 * Example: invoked by main().
 */
static void
check_indefinite(void) {
    const uint8_t array[] = {0x9f, 1, 0x82, 2, 3, 0x9f, 4, 5, 0xff, 0xff};
    const uint8_t map[] = {0xbf, 0x61, 'x', 0x9f, 0xf5, 0xff, 0xff};
    const uint8_t bytes[] = {0x5f, 0x42, 0xaa, 0xbb, 0x40, 0xff};
    const uint8_t text[] = {0x7f, 0x62, 0xc2, 0xa2, 0x61, 'a', 0xff};
    const uint8_t odd[] = {0xbf, 1, 0xff};
    const uint8_t wrong[] = {0x5f, 0x60, 0xff};
    const uint8_t nested[] = {0x7f, 0x7f, 0xff, 0xff};
    const uint8_t split[] = {0x7f, 0x61, 0xc2, 0x61, 0xa2, 0xff};
    const uint8_t tagged[] = {0xc0, 0x9f, 0xff};
    size_t i;

    /* Complete containers consume their terminator, leaving trailing input. */
    assert(cbor_skip_item(array, sizeof(array)) == sizeof(array));
    assert(cbor_skip_item(map, sizeof(map)) == sizeof(map));
    assert(cbor_skip_item(bytes, sizeof(bytes)) == sizeof(bytes));
    assert(cbor_skip_item(text, sizeof(text)) == sizeof(text));
    assert(cbor_skip_item(tagged, sizeof(tagged)) == sizeof(tagged));
    for(i = 0; i < sizeof(array); i++) assert(cbor_skip_item(array, i) == -1);
    for(i = 0; i < sizeof(map); i++) assert(cbor_skip_item(map, i) == -1);
    for(i = 0; i < sizeof(bytes); i++) assert(cbor_skip_item(bytes, i) == -1);
    for(i = 0; i < sizeof(text); i++) assert(cbor_skip_item(text, i) == -1);

    /* Wrong-type chunks and UTF-8 code points split across chunks are invalid. */
    assert(cbor_skip_item(odd, sizeof(odd)) == -1);
    assert(cbor_skip_item(wrong, sizeof(wrong)) == -1);
    assert(cbor_skip_item(nested, sizeof(nested)) == -1);
    assert(cbor_skip_item(split, sizeof(split)) == -1);
}

/*
 * Purpose: exhaustively check simple values and hard depth limits.
 * Source: RFC 8949 section 3.3. Version: 2026-11-12.
 * Inputs: none. Returns: none; assertion failure aborts, no exceptions.
 * Author: asn1c maintainers. History: malformed simple and stack regressions.
 * Example: invoked by main().
 */
static void
check_limits(void) {
    uint8_t item[2] = {0xf8, 0};
    uint8_t nested[4097];
    unsigned i;
    uint8_t major;
    uint64_t arg;

    /* AI=24 cannot encode simple values below 32, including true/null. */
    for(i = 0; i < 256; i++) {
        item[1] = (uint8_t)i;
        assert(cbor_skip_item(item, 2) == (i < 32 ? -1 : 2));
        assert(cbor_decode_head(item, 2, &major, &arg) == (i < 32 ? -1 : 2));
    }
    for(i = 0; i < 8; i++) {
        item[0] = (uint8_t)((i << 5) | 31);
        assert(cbor_skip_item(item, 1) == -1);
    }

    /* A hard bound is effective even when compiler stack checks are disabled. */
    memset(nested, 0x81, sizeof(nested));
    nested[128] = 0;
    assert(cbor_skip_item(nested, 129) == 129);
    nested[128] = 0x81;
    nested[129] = 0;
    assert(cbor_skip_item(nested, 130) == -1);
    memset(nested, 0xc0, sizeof(nested));
    nested[sizeof(nested) - 1] = 0;
    assert(cbor_skip_item(nested, sizeof(nested)) == -1);
    assert(cbor_skip_item(NULL, 0) == -1);
    assert(cbor_skip_item(NULL, 1) == -1);
}

/*
 * Purpose: run bounded scanner regression and exhaustive short-input checks.
 * Source: repository test harness. Version: 2026-11-12.
 * Inputs: none. Returns: zero on success; assertions abort, no exceptions.
 * Author: asn1c maintainers. History: initial tests.
 * Example: ./check-CBOR-wellformed.
 */
int
main(void) {
    unsigned value;
    uint8_t bytes[2];
    check_indefinite();
    check_limits();
    assert(cbor_encode_simple(CBOR_SV_TRUE, NULL, NULL) == -1);

    /* Exercise every two-byte prefix and assert returned lengths stay bounded. */
    for(value = 0; value <= 65535; value++) {
        ssize_t used;
        bytes[0] = (uint8_t)(value >> 8);
        bytes[1] = (uint8_t)value;
        used = cbor_skip_item(bytes, sizeof(bytes));
        assert(used == -1 || (used > 0 && used <= 2));
    }
    return 0;
}
