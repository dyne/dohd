/* dohd extended test unit for url64 decoding
 *
 * Tests edge cases, invalid inputs, and potential buffer issues
 *
 * Copyright (C) 2022 Dyne.org foundation
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with this program.  If not, see
 * <https://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

extern int dohd_url64_decode(const char *src, uint8_t *dest);
extern int dohd_url64_check(const char *in);
extern int dohd_url64_declen(int len);

static int tests_run = 0;
static int tests_passed = 0;

#define TEST_ASSERT(cond, msg) do { \
    tests_run++; \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", msg); \
        return 0; \
    } \
    tests_passed++; \
    fprintf(stderr, "PASS: %s\n", msg); \
} while(0)

/* Test empty string */
static int test_empty_string(void) {
    uint8_t out[16];
    int check = dohd_url64_check("");
    TEST_ASSERT(check == 0, "Empty string check returns 0");
    return 1;
}

/* Test NULL input */
static int test_null_input(void) {
    int check = dohd_url64_check(NULL);
    TEST_ASSERT(check == 0, "NULL input check returns 0");
    return 1;
}

/* Test single character inputs */
static int test_single_char(void) {
    uint8_t out[16];
    int len;

    /* Single valid char */
    int check = dohd_url64_check("A");
    TEST_ASSERT(check == 1, "Single valid char check returns 1");

    len = dohd_url64_decode("A", out);
    TEST_ASSERT(len == 0, "Single char decode returns 0 bytes");

    return 1;
}

/* Test invalid characters */
static int test_invalid_chars(void) {
    int check;

    check = dohd_url64_check("AAA=");  /* Standard base64 padding */
    TEST_ASSERT(check == 0, "Standard padding '=' is invalid for url64");

    check = dohd_url64_check("AAA+");  /* Standard base64 '+' */
    TEST_ASSERT(check == 0, "Standard '+' is invalid for url64");

    /* Note: This implementation accepts '/' (maps to 63) for compatibility */

    check = dohd_url64_check("AAA!");
    TEST_ASSERT(check == 0, "Invalid char '!' detected");

    check = dohd_url64_check("AAA ");
    TEST_ASSERT(check == 0, "Space char is invalid");

    check = dohd_url64_check("AAA\n");
    TEST_ASSERT(check == 0, "Newline char is invalid");

    return 1;
}

/* Test url64 specific characters */
static int test_url64_chars(void) {
    int check;

    check = dohd_url64_check("AAA-");  /* URL-safe minus */
    TEST_ASSERT(check == 4, "URL-safe '-' is valid");

    check = dohd_url64_check("AAA_");  /* URL-safe underscore */
    TEST_ASSERT(check == 4, "URL-safe '_' is valid");

    return 1;
}

/* Test length estimation */
static int test_declen(void) {
    int estimated;

    estimated = dohd_url64_declen(0);
    TEST_ASSERT(estimated == 0, "declen(0) == 0");

    estimated = dohd_url64_declen(4);
    TEST_ASSERT(estimated == 3, "declen(4) == 3");

    estimated = dohd_url64_declen(8);
    TEST_ASSERT(estimated == 6, "declen(8) == 6");

    /* Non-multiple of 4 */
    estimated = dohd_url64_declen(5);
    TEST_ASSERT(estimated == 6, "declen(5) == 6 (rounds up)");

    return 1;
}

/* Test known DNS query encoding */
static int test_dns_query(void) {
    /* DNS query for "example.com" A record */
    const char *dns_b64 = "AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE";
    uint8_t expected[] = {
        0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61,
        0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
        0x00, 0x00, 0x01, 0x00, 0x01
    };
    uint8_t out[64];
    int len;

    int check = dohd_url64_check(dns_b64);
    TEST_ASSERT(check == 39, "DNS query check returns correct length");

    len = dohd_url64_decode(dns_b64, out);
    TEST_ASSERT(len == 29, "DNS query decode returns 29 bytes");

    TEST_ASSERT(memcmp(out, expected, 29) == 0, "DNS query decode matches expected");

    return 1;
}

/* Test all alphanumeric characters */
static int test_all_valid_chars(void) {
    const char *all_valid = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    int check = dohd_url64_check(all_valid);
    TEST_ASSERT(check == 64, "All 64 valid characters accepted");
    return 1;
}

/* Test long input (stress test) */
static int test_long_input(void) {
    char long_input[2048];
    uint8_t out[2048];
    int i;

    /* Fill with valid chars */
    for (i = 0; i < 2000; i++) {
        long_input[i] = 'A' + (i % 26);
    }
    long_input[2000] = '\0';

    int check = dohd_url64_check(long_input);
    TEST_ASSERT(check == 2000, "Long input check returns correct length");

    int len = dohd_url64_decode(long_input, out);
    TEST_ASSERT(len > 0, "Long input decode succeeds");

    return 1;
}

/* Test various padding scenarios (url64 has no padding) */
static int test_padding_scenarios(void) {
    uint8_t out[32];
    int len;

    /* 2 chars = 1 byte output */
    len = dohd_url64_decode("QQ", out);
    TEST_ASSERT(len == 1, "2 char input -> 1 byte output");

    /* 3 chars = 2 bytes output */
    len = dohd_url64_decode("QUE", out);
    TEST_ASSERT(len == 2, "3 char input -> 2 bytes output");

    /* 4 chars = 3 bytes output */
    len = dohd_url64_decode("QUFB", out);
    TEST_ASSERT(len == 3, "4 char input -> 3 bytes output");

    return 1;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    fprintf(stderr, "=== URL64 Extended Tests ===\n\n");

    test_empty_string();
    test_null_input();
    test_single_char();
    test_invalid_chars();
    test_url64_chars();
    test_declen();
    test_dns_query();
    test_all_valid_chars();
    test_long_input();
    test_padding_scenarios();

    fprintf(stderr, "\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
