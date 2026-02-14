/* dohd test unit for heap implementation
 *
 * Tests the min-heap used for timer scheduling
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
#include <errno.h>

/* Define a simple timer struct to test the heap */
struct test_timer {
    unsigned long long expire;
    int value;
};
typedef struct test_timer test_timer;

/* Include the heap macro */
#include "../src/heap.h"

DECLARE_HEAP(test_timer, expire)

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

/* Test heap initialization */
static int test_heap_init(void) {
    heap_test_timer *h = heap_init();
    TEST_ASSERT(h != NULL, "heap_init returns non-NULL");
    TEST_ASSERT(h->n == 0, "heap_init: n == 0");
    TEST_ASSERT(h->size == 0, "heap_init: size == 0");
    heap_destroy(h);
    return 1;
}

/* Test heap first on empty heap */
static int test_heap_first_empty(void) {
    heap_test_timer *h = heap_init();
    test_timer *first = heap_first(h);
    TEST_ASSERT(first == NULL, "heap_first on empty heap returns NULL");
    heap_destroy(h);
    return 1;
}

/* Test heap peek on empty heap */
static int test_heap_peek_empty(void) {
    heap_test_timer *h = heap_init();
    test_timer t;
    int ret = heap_peek(h, &t);
    TEST_ASSERT(ret == -1, "heap_peek on empty heap returns -1");
    TEST_ASSERT(errno == ENOENT, "heap_peek sets errno to ENOENT");
    heap_destroy(h);
    return 1;
}

/* Test single insert and peek */
static int test_heap_single_insert(void) {
    heap_test_timer *h = heap_init();
    test_timer t = { .expire = 100, .value = 42 };
    test_timer out;

    int id = heap_insert(h, &t);
    TEST_ASSERT(id >= 0, "heap_insert returns valid id");
    TEST_ASSERT(h->n == 1, "heap has 1 element after insert");

    test_timer *first = heap_first(h);
    TEST_ASSERT(first != NULL, "heap_first returns non-NULL");
    TEST_ASSERT(first->expire == 100, "first element has correct expire");
    TEST_ASSERT(first->value == 42, "first element has correct value");

    int ret = heap_peek(h, &out);
    TEST_ASSERT(ret == 0, "heap_peek succeeds");
    TEST_ASSERT(out.expire == 100, "peeked element has correct expire");
    TEST_ASSERT(h->n == 0, "heap is empty after peek");

    heap_destroy(h);
    return 1;
}

/* Test min-heap ordering with multiple inserts */
static int test_heap_ordering(void) {
    heap_test_timer *h = heap_init();
    test_timer t, out;

    /* Insert in reverse order */
    t.expire = 300; t.value = 3; heap_insert(h, &t);
    t.expire = 100; t.value = 1; heap_insert(h, &t);
    t.expire = 200; t.value = 2; heap_insert(h, &t);

    TEST_ASSERT(h->n == 3, "heap has 3 elements");

    /* Should come out in sorted order (min first) */
    heap_peek(h, &out);
    TEST_ASSERT(out.expire == 100, "first peek returns min (100)");
    TEST_ASSERT(out.value == 1, "first peek returns value 1");

    heap_peek(h, &out);
    TEST_ASSERT(out.expire == 200, "second peek returns 200");
    TEST_ASSERT(out.value == 2, "second peek returns value 2");

    heap_peek(h, &out);
    TEST_ASSERT(out.expire == 300, "third peek returns max (300)");
    TEST_ASSERT(out.value == 3, "third peek returns value 3");

    TEST_ASSERT(h->n == 0, "heap is empty after all peeks");

    heap_destroy(h);
    return 1;
}

/* Test heap delete by id */
static int test_heap_delete(void) {
    heap_test_timer *h = heap_init();
    test_timer t, out;
    int id1, id2, id3;

    t.expire = 100; t.value = 1; id1 = heap_insert(h, &t);
    t.expire = 200; t.value = 2; id2 = heap_insert(h, &t);
    t.expire = 300; t.value = 3; id3 = heap_insert(h, &t);

    TEST_ASSERT(h->n == 3, "heap has 3 elements");

    /* Delete middle element */
    int ret = heap_delete(h, id2);
    TEST_ASSERT(ret == 0, "heap_delete succeeds");
    TEST_ASSERT(h->n == 2, "heap has 2 elements after delete");

    /* Verify min is still correct */
    test_timer *first = heap_first(h);
    TEST_ASSERT(first->expire == 100, "min is still 100 after deleting 200");

    heap_destroy(h);
    return 1;
}

/* Test delete non-existent id */
static int test_heap_delete_nonexistent(void) {
    heap_test_timer *h = heap_init();
    test_timer t;
    t.expire = 100; t.value = 1; heap_insert(h, &t);

    int ret = heap_delete(h, 99999);
    TEST_ASSERT(ret == -1, "heap_delete of non-existent id returns -1");
    TEST_ASSERT(errno == ENOENT, "heap_delete sets errno to ENOENT");
    TEST_ASSERT(h->n == 1, "heap still has 1 element");

    heap_destroy(h);
    return 1;
}

/* Test delete from empty heap */
static int test_heap_delete_empty(void) {
    heap_test_timer *h = heap_init();
    int ret = heap_delete(h, 0);
    TEST_ASSERT(ret == -1, "heap_delete on empty heap returns -1");
    TEST_ASSERT(errno == ENOENT, "heap_delete sets errno to ENOENT");
    heap_destroy(h);
    return 1;
}

/* Stress test: many inserts and peeks */
static int test_heap_stress(void) {
    heap_test_timer *h = heap_init();
    test_timer t, out;
    int i;
    const int count = 1000;

    /* Insert in pseudo-random order */
    for (i = 0; i < count; i++) {
        t.expire = (i * 7919) % 10000;  /* Use prime for pseudo-random */
        t.value = i;
        heap_insert(h, &t);
    }
    TEST_ASSERT(h->n == count, "heap has correct count after stress insert");

    /* Extract all and verify ordering */
    unsigned long long prev = 0;
    for (i = 0; i < count; i++) {
        heap_peek(h, &out);
        TEST_ASSERT(out.expire >= prev, "elements extracted in sorted order");
        prev = out.expire;
    }
    TEST_ASSERT(h->n == 0, "heap is empty after extracting all");

    heap_destroy(h);
    fprintf(stderr, "PASS: stress test with %d elements\n", count);
    tests_run++;
    tests_passed++;
    return 1;
}

/* Test heap growth (reallocation) */
static int test_heap_growth(void) {
    heap_test_timer *h = heap_init();
    test_timer t;
    int i;

    /* Insert enough to trigger multiple reallocations */
    for (i = 0; i < 100; i++) {
        t.expire = i;
        t.value = i;
        int id = heap_insert(h, &t);
        TEST_ASSERT(id >= 0, "insert during growth succeeds");
    }
    TEST_ASSERT(h->n == 100, "heap has 100 elements");
    TEST_ASSERT(h->size >= 100, "heap size grew appropriately");

    heap_destroy(h);
    return 1;
}

/* Test id wraparound */
static int test_heap_id_wrap(void) {
    heap_test_timer *h = heap_init();
    test_timer t, out;

    /* Force id near wraparound point */
    h->last_id = 0x7FFFFFF0;

    for (int i = 0; i < 20; i++) {
        t.expire = i;
        t.value = i;
        heap_insert(h, &t);
    }
    TEST_ASSERT(h->n == 20, "heap has 20 elements after id wrap");

    /* Verify all can be extracted */
    for (int i = 0; i < 20; i++) {
        int ret = heap_peek(h, &out);
        TEST_ASSERT(ret == 0, "peek succeeds after id wrap");
    }

    heap_destroy(h);
    return 1;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    fprintf(stderr, "=== Heap Tests ===\n\n");

    test_heap_init();
    test_heap_first_empty();
    test_heap_peek_empty();
    test_heap_single_insert();
    test_heap_ordering();
    test_heap_delete();
    test_heap_delete_nonexistent();
    test_heap_delete_empty();
    test_heap_stress();
    test_heap_growth();
    test_heap_id_wrap();

    fprintf(stderr, "\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
