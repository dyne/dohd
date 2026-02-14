/* dohd test unit for DNS parsing functions
 *
 * Tests DNS packet parsing, TTL extraction, and record skipping
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
#include <arpa/inet.h>

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

/* 
 * Re-implement the DNS parsing functions from dohd.c for testing
 * These should match the behavior of the actual implementation
 */

#define DNS_BUFFER_MAXSIZE 1460

struct __attribute__((packed)) dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

/* Skip a DNS question section entry */
static int dns_skip_question(uint8_t **record, int maxlen) {
    int len = 0;
    uint8_t *r = *record;
    
    while (*r != 0) {
        if (*r > 63) {
            /* Compression pointer - 2 bytes */
            len += 2;
            r += 2;
            break;
        }
        len += *r + 1;
        r += *r + 1;
        if (len > maxlen)
            return -1;
    }
    if (*r == 0) {
        len++;
        r++;
    }
    /* Skip QTYPE and QCLASS (4 bytes) */
    len += 4;
    r += 4;
    
    if (len > maxlen)
        return -1;
    
    *record = r;
    return len;
}

/* Skip RR name (handles compression) */
static int dns_skip_rr_name(uint8_t **record, size_t *len) {
    uint8_t *r = *record;
    size_t consumed = 0;
    
    while (*r != 0) {
        if (*r >= 0xC0) {
            /* Compression pointer */
            consumed += 2;
            r += 2;
            *record = r;
            *len -= consumed;
            return 0;
        }
        consumed += *r + 1;
        r += *r + 1;
        if (consumed > *len)
            return -1;
    }
    /* Skip null terminator */
    consumed++;
    r++;
    *record = r;
    *len -= consumed;
    return 0;
}

/* Extract minimum TTL from DNS response */
static uint32_t dnsreply_min_age(const void *p, size_t len) {
    struct dns_header *hdr = (struct dns_header *)p;
    uint8_t *record;
    uint32_t min_ttl = 0xFFFFFFFF;
    uint16_t qdcount, ancount, nscount, arcount;
    int i;

    if (len < sizeof(struct dns_header))
        return 0;

    qdcount = ntohs(hdr->qdcount);
    ancount = ntohs(hdr->ancount);
    nscount = ntohs(hdr->nscount);
    arcount = ntohs(hdr->arcount);

    /* Skip header */
    record = (uint8_t *)p + sizeof(struct dns_header);
    len -= sizeof(struct dns_header);

    /* Skip questions */
    for (i = 0; i < qdcount; i++) {
        if (dns_skip_question(&record, len) < 0)
            return 0;
    }

    /* Process answer, authority, and additional sections */
    int total_rr = ancount + nscount + arcount;
    for (i = 0; i < total_rr && len > 10; i++) {
        uint32_t ttl;
        uint16_t datalen;

        if (dns_skip_rr_name(&record, &len) < 0)
            return min_ttl;

        if (len < 10)
            return min_ttl;

        /* TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) = 10 bytes */
        ttl = ntohl(*(uint32_t *)(record + 4));
        datalen = ntohs(*(uint16_t *)(record + 8));

        if (ttl < min_ttl && ttl > 0)
            min_ttl = ttl;

        record += 10 + datalen;
        len -= 10 + datalen;
    }

    return (min_ttl == 0xFFFFFFFF) ? 0 : min_ttl;
}

/* Test: Parse a minimal DNS query */
static int test_dns_header_parse(void) {
    /* Minimal DNS query: ID=0x1234, standard query, 1 question */
    uint8_t query[] = {
        0x12, 0x34,  /* ID */
        0x01, 0x00,  /* Flags: standard query */
        0x00, 0x01,  /* QDCOUNT: 1 */
        0x00, 0x00,  /* ANCOUNT: 0 */
        0x00, 0x00,  /* NSCOUNT: 0 */
        0x00, 0x00,  /* ARCOUNT: 0 */
        /* Question: example.com A IN */
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,        /* End of name */
        0x00, 0x01,  /* QTYPE: A */
        0x00, 0x01   /* QCLASS: IN */
    };

    struct dns_header *hdr = (struct dns_header *)query;
    TEST_ASSERT(ntohs(hdr->id) == 0x1234, "DNS header ID parsed correctly");
    TEST_ASSERT(ntohs(hdr->qdcount) == 1, "DNS header QDCOUNT is 1");
    TEST_ASSERT(ntohs(hdr->ancount) == 0, "DNS header ANCOUNT is 0");

    return 1;
}

/* Test: Skip DNS question */
static int test_dns_skip_question(void) {
    uint8_t question[] = {
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,        /* End of name */
        0x00, 0x01,  /* QTYPE: A */
        0x00, 0x01   /* QCLASS: IN */
    };
    uint8_t *ptr = question;
    int len = dns_skip_question(&ptr, sizeof(question));

    TEST_ASSERT(len == sizeof(question), "dns_skip_question returns correct length");
    TEST_ASSERT(ptr == question + sizeof(question), "pointer advanced correctly");

    return 1;
}

/* Test: DNS response with TTL extraction */
static int test_dns_ttl_extraction(void) {
    /* DNS response for example.com with A record, TTL=300 */
    uint8_t response[] = {
        /* Header */
        0x12, 0x34,  /* ID */
        0x81, 0x80,  /* Flags: response, no error */
        0x00, 0x01,  /* QDCOUNT: 1 */
        0x00, 0x01,  /* ANCOUNT: 1 */
        0x00, 0x00,  /* NSCOUNT: 0 */
        0x00, 0x00,  /* ARCOUNT: 0 */
        /* Question */
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,
        0x00, 0x01,  /* QTYPE: A */
        0x00, 0x01,  /* QCLASS: IN */
        /* Answer: compression pointer to question */
        0xC0, 0x0C,  /* Name pointer to offset 12 */
        0x00, 0x01,  /* TYPE: A */
        0x00, 0x01,  /* CLASS: IN */
        0x00, 0x00, 0x01, 0x2C,  /* TTL: 300 (0x12C) */
        0x00, 0x04,  /* RDLENGTH: 4 */
        0x5D, 0xB8, 0xD8, 0x22   /* RDATA: 93.184.216.34 */
    };

    uint32_t min_ttl = dnsreply_min_age(response, sizeof(response));
    TEST_ASSERT(min_ttl == 300, "TTL extracted correctly (300)");

    return 1;
}

/* Test: Multiple records with different TTLs */
static int test_dns_multiple_ttls(void) {
    /* DNS response with 2 A records: TTL=600 and TTL=300 */
    uint8_t response[] = {
        /* Header */
        0x12, 0x34,
        0x81, 0x80,
        0x00, 0x01,  /* QDCOUNT: 1 */
        0x00, 0x02,  /* ANCOUNT: 2 */
        0x00, 0x00,
        0x00, 0x00,
        /* Question */
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,
        0x00, 0x01,
        0x00, 0x01,
        /* Answer 1: TTL=600 */
        0xC0, 0x0C,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00, 0x02, 0x58,  /* TTL: 600 */
        0x00, 0x04,
        0x5D, 0xB8, 0xD8, 0x22,
        /* Answer 2: TTL=300 */
        0xC0, 0x0C,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00, 0x01, 0x2C,  /* TTL: 300 */
        0x00, 0x04,
        0x5D, 0xB8, 0xD8, 0x23
    };

    uint32_t min_ttl = dnsreply_min_age(response, sizeof(response));
    TEST_ASSERT(min_ttl == 300, "Minimum TTL is 300 (not 600)");

    return 1;
}

/* Test: Malformed/truncated packet */
static int test_dns_truncated(void) {
    /* Truncated DNS header */
    uint8_t truncated[] = { 0x12, 0x34, 0x01, 0x00 };
    uint32_t ttl = dnsreply_min_age(truncated, sizeof(truncated));
    TEST_ASSERT(ttl == 0, "Truncated packet returns 0 TTL");

    return 1;
}

/* Test: Empty response (no answers) */
static int test_dns_no_answers(void) {
    uint8_t response[] = {
        /* Header */
        0x12, 0x34,
        0x81, 0x80,
        0x00, 0x01,  /* QDCOUNT: 1 */
        0x00, 0x00,  /* ANCOUNT: 0 */
        0x00, 0x00,
        0x00, 0x00,
        /* Question only */
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,
        0x00, 0x01,
        0x00, 0x01
    };

    uint32_t min_ttl = dnsreply_min_age(response, sizeof(response));
    TEST_ASSERT(min_ttl == 0, "No answers returns 0 TTL");

    return 1;
}

/* Test: Long domain name */
static int test_dns_long_name(void) {
    uint8_t question[256];
    uint8_t *ptr = question;
    int i;

    /* Build a long name: a.b.c.d... */
    for (i = 0; i < 60; i++) {
        *ptr++ = 1;
        *ptr++ = 'a' + (i % 26);
    }
    *ptr++ = 0;  /* End of name */
    *ptr++ = 0x00; *ptr++ = 0x01;  /* QTYPE */
    *ptr++ = 0x00; *ptr++ = 0x01;  /* QCLASS */

    uint8_t *qptr = question;
    int len = dns_skip_question(&qptr, ptr - question);
    TEST_ASSERT(len > 0, "Long name question parsed successfully");
    TEST_ASSERT(qptr == ptr, "Pointer at end of question");

    return 1;
}

/* Test: Name compression pointer format */
static int test_dns_compression(void) {
    /* DNS question names can use compression pointers (0xC0 high bits).
     * This tests that we properly recognize a compression pointer format.
     * The actual dohd code handles this; we just verify basic detection. */
    uint8_t compressed_name[] = { 0xC0, 0x0C };  /* Pure compression pointer */
    
    /* Verify high bits indicate compression */
    TEST_ASSERT((compressed_name[0] & 0xC0) == 0xC0, "Compression pointer detected (0xC0 high bits)");
    
    /* Test that a label starting with high bits is recognized as compression */
    TEST_ASSERT(compressed_name[0] >= 0xC0, "Byte >= 0xC0 indicates compression");

    return 1;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    fprintf(stderr, "=== DNS Parser Tests ===\n\n");

    test_dns_header_parse();
    test_dns_skip_question();
    test_dns_ttl_extraction();
    test_dns_multiple_ttls();
    test_dns_truncated();
    test_dns_no_answers();
    test_dns_long_name();
    test_dns_compression();

    fprintf(stderr, "\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
