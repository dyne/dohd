/*
 * test_mempool.c - Unit tests for memory pool
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../src/mempool.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("  %-50s ", #name); \
    test_##name(); \
    printf("PASS\n"); \
    tests_passed++; \
} while(0)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("FAIL\n    Assertion failed: %s\n    at %s:%d\n", \
               #cond, __FILE__, __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define ASSERT_EQ(a, b) ASSERT((a) == (b))
#define ASSERT_NE(a, b) ASSERT((a) != (b))
#define ASSERT_NULL(p) ASSERT((p) == NULL)
#define ASSERT_NOT_NULL(p) ASSERT((p) != NULL)

/* Test structure similar to dohd req_slot */
struct test_struct {
    int id;
    void *ptr;
    char data[64];
    struct test_struct *next;
};

/*
 * Basic Tests
 */

TEST(create_destroy)
{
    mempool_t *pool = mempool_create(sizeof(struct test_struct), 10);
    ASSERT_NOT_NULL(pool);
    mempool_destroy(pool);
}

TEST(create_zero_size_fails)
{
    mempool_t *pool = mempool_create(0, 10);
    ASSERT_NULL(pool);
}

TEST(create_zero_capacity_fails)
{
    mempool_t *pool = mempool_create(sizeof(int), 0);
    ASSERT_NULL(pool);
}

TEST(destroy_null_safe)
{
    mempool_destroy(NULL);  /* Should not crash */
}

/*
 * Allocation Tests
 */

TEST(alloc_single)
{
    mempool_t *pool = mempool_create(sizeof(struct test_struct), 10);
    ASSERT_NOT_NULL(pool);

    struct test_struct *s = mempool_alloc(pool);
    ASSERT_NOT_NULL(s);

    /* Should be zeroed */
    ASSERT_EQ(s->id, 0);
    ASSERT_NULL(s->ptr);
    ASSERT_NULL(s->next);

    mempool_destroy(pool);
}

TEST(alloc_fill_pool)
{
    const int capacity = 5;
    mempool_t *pool = mempool_create(sizeof(struct test_struct), capacity);
    ASSERT_NOT_NULL(pool);

    void *ptrs[5];
    for (int i = 0; i < capacity; i++) {
        ptrs[i] = mempool_alloc(pool);
        ASSERT_NOT_NULL(ptrs[i]);
    }

    /* All pointers should be different */
    for (int i = 0; i < capacity; i++) {
        for (int j = i + 1; j < capacity; j++) {
            ASSERT_NE(ptrs[i], ptrs[j]);
        }
    }

    mempool_destroy(pool);
}

TEST(alloc_exhausted_returns_null)
{
    mempool_t *pool = mempool_create(sizeof(int), 3);
    ASSERT_NOT_NULL(pool);

    void *p1 = mempool_alloc(pool);
    void *p2 = mempool_alloc(pool);
    void *p3 = mempool_alloc(pool);
    ASSERT_NOT_NULL(p1);
    ASSERT_NOT_NULL(p2);
    ASSERT_NOT_NULL(p3);

    /* Pool should be exhausted */
    void *p4 = mempool_alloc(pool);
    ASSERT_NULL(p4);

    mempool_destroy(pool);
}

TEST(alloc_from_null_pool)
{
    void *p = mempool_alloc(NULL);
    ASSERT_NULL(p);
}

/*
 * Free Tests
 */

TEST(free_and_realloc)
{
    mempool_t *pool = mempool_create(sizeof(int), 1);
    ASSERT_NOT_NULL(pool);

    int *p1 = mempool_alloc(pool);
    ASSERT_NOT_NULL(p1);
    *p1 = 42;

    /* Pool is full */
    ASSERT_NULL(mempool_alloc(pool));

    /* Free and reallocate */
    mempool_free(pool, p1);
    
    int *p2 = mempool_alloc(pool);
    ASSERT_NOT_NULL(p2);
    /* Should be same slot, zeroed */
    ASSERT_EQ(p1, p2);
    ASSERT_EQ(*p2, 0);

    mempool_destroy(pool);
}

TEST(free_null_safe)
{
    mempool_t *pool = mempool_create(sizeof(int), 10);
    ASSERT_NOT_NULL(pool);

    mempool_free(pool, NULL);  /* Should not crash */
    mempool_free(NULL, NULL);  /* Should not crash */

    mempool_destroy(pool);
}

TEST(free_invalid_pointer_ignored)
{
    mempool_t *pool = mempool_create(sizeof(int), 10);
    ASSERT_NOT_NULL(pool);

    int stack_var = 0;
    mempool_free(pool, &stack_var);  /* Should be ignored */

    /* Pool should still work */
    void *p = mempool_alloc(pool);
    ASSERT_NOT_NULL(p);

    mempool_destroy(pool);
}

TEST(free_order_lifo)
{
    mempool_t *pool = mempool_create(sizeof(int), 3);
    ASSERT_NOT_NULL(pool);

    void *p1 = mempool_alloc(pool);
    void *p2 = mempool_alloc(pool);
    void *p3 = mempool_alloc(pool);

    /* Free in order 1, 2, 3 */
    mempool_free(pool, p1);
    mempool_free(pool, p2);
    mempool_free(pool, p3);

    /* Realloc should be LIFO: 3, 2, 1 */
    ASSERT_EQ(mempool_alloc(pool), p3);
    ASSERT_EQ(mempool_alloc(pool), p2);
    ASSERT_EQ(mempool_alloc(pool), p1);

    mempool_destroy(pool);
}

/*
 * Stats Tests
 */

TEST(stats_initial)
{
    mempool_t *pool = mempool_create(sizeof(int), 10);
    ASSERT_NOT_NULL(pool);

    struct mempool_stats stats;
    mempool_stats(pool, &stats);

    ASSERT_EQ(stats.capacity, 10);
    ASSERT_EQ(stats.allocated, 0);
    ASSERT_EQ(stats.peak, 0);
    ASSERT_EQ(stats.alloc_count, 0);
    ASSERT_EQ(stats.free_count, 0);
    ASSERT_EQ(stats.exhausted, 0);

    mempool_destroy(pool);
}

TEST(stats_after_operations)
{
    mempool_t *pool = mempool_create(sizeof(int), 3);
    ASSERT_NOT_NULL(pool);

    struct mempool_stats stats;

    void *p1 = mempool_alloc(pool);
    void *p2 = mempool_alloc(pool);
    mempool_stats(pool, &stats);
    ASSERT_EQ(stats.allocated, 2);
    ASSERT_EQ(stats.alloc_count, 2);
    ASSERT_EQ(stats.peak, 2);

    mempool_free(pool, p1);
    mempool_stats(pool, &stats);
    ASSERT_EQ(stats.allocated, 1);
    ASSERT_EQ(stats.free_count, 1);
    ASSERT_EQ(stats.peak, 2);  /* Peak unchanged */

    void *p3 = mempool_alloc(pool);
    void *p4 = mempool_alloc(pool);
    mempool_stats(pool, &stats);
    ASSERT_EQ(stats.allocated, 3);
    ASSERT_EQ(stats.peak, 3);

    /* Try to exhaust */
    void *p5 = mempool_alloc(pool);
    ASSERT_NULL(p5);
    mempool_stats(pool, &stats);
    ASSERT_EQ(stats.exhausted, 1);

    (void)p2; (void)p3; (void)p4;
    mempool_destroy(pool);
}

TEST(stats_null_safe)
{
    struct mempool_stats stats;
    mempool_stats(NULL, &stats);  /* Should not crash */

    mempool_t *pool = mempool_create(sizeof(int), 10);
    mempool_stats(pool, NULL);    /* Should not crash */
    mempool_destroy(pool);
}

/*
 * Reset Tests
 */

TEST(reset_frees_all)
{
    mempool_t *pool = mempool_create(sizeof(int), 5);
    ASSERT_NOT_NULL(pool);

    /* Allocate all */
    for (int i = 0; i < 5; i++) {
        ASSERT_NOT_NULL(mempool_alloc(pool));
    }
    ASSERT_NULL(mempool_alloc(pool));

    /* Reset */
    mempool_reset(pool);

    /* Should be able to allocate all again */
    for (int i = 0; i < 5; i++) {
        ASSERT_NOT_NULL(mempool_alloc(pool));
    }

    struct mempool_stats stats;
    mempool_stats(pool, &stats);
    ASSERT_EQ(stats.allocated, 5);

    mempool_destroy(pool);
}

TEST(reset_null_safe)
{
    mempool_reset(NULL);  /* Should not crash */
}

/*
 * Edge Cases
 */

TEST(small_slot_size)
{
    /* Even 1-byte slots should work */
    mempool_t *pool = mempool_create(1, 10);
    ASSERT_NOT_NULL(pool);

    void *p = mempool_alloc(pool);
    ASSERT_NOT_NULL(p);

    mempool_free(pool, p);
    ASSERT_NOT_NULL(mempool_alloc(pool));

    mempool_destroy(pool);
}

TEST(single_slot_pool)
{
    mempool_t *pool = mempool_create(sizeof(int), 1);
    ASSERT_NOT_NULL(pool);

    void *p = mempool_alloc(pool);
    ASSERT_NOT_NULL(p);
    ASSERT_NULL(mempool_alloc(pool));

    mempool_free(pool, p);
    ASSERT_NOT_NULL(mempool_alloc(pool));

    mempool_destroy(pool);
}

TEST(large_slot_size)
{
    /* Large struct (simulating realistic usage) */
    mempool_t *pool = mempool_create(4096, 10);
    ASSERT_NOT_NULL(pool);

    void *ptrs[10];
    for (int i = 0; i < 10; i++) {
        ptrs[i] = mempool_alloc(pool);
        ASSERT_NOT_NULL(ptrs[i]);
        /* Write to verify memory is accessible */
        memset(ptrs[i], i, 4096);
    }

    /* Verify data integrity */
    for (int i = 0; i < 10; i++) {
        unsigned char *p = ptrs[i];
        ASSERT_EQ(p[0], i);
        ASSERT_EQ(p[4095], i);
    }

    mempool_destroy(pool);
}

TEST(alloc_free_cycles)
{
    /* Stress test alloc/free cycles */
    mempool_t *pool = mempool_create(sizeof(struct test_struct), 100);
    ASSERT_NOT_NULL(pool);

    void *ptrs[100];
    
    for (int cycle = 0; cycle < 10; cycle++) {
        /* Allocate all */
        for (int i = 0; i < 100; i++) {
            ptrs[i] = mempool_alloc(pool);
            ASSERT_NOT_NULL(ptrs[i]);
        }
        ASSERT_NULL(mempool_alloc(pool));

        /* Free half */
        for (int i = 0; i < 50; i++) {
            mempool_free(pool, ptrs[i * 2]);
        }

        /* Reallocate half */
        for (int i = 0; i < 50; i++) {
            ptrs[i * 2] = mempool_alloc(pool);
            ASSERT_NOT_NULL(ptrs[i * 2]);
        }

        /* Free all */
        for (int i = 0; i < 100; i++) {
            mempool_free(pool, ptrs[i]);
        }
    }

    struct mempool_stats stats;
    mempool_stats(pool, &stats);
    ASSERT_EQ(stats.allocated, 0);
    ASSERT_EQ(stats.alloc_count, 10 * (100 + 50));
    ASSERT_EQ(stats.free_count, 10 * (50 + 100));

    mempool_destroy(pool);
}

TEST(double_free_safe)
{
    mempool_t *pool = mempool_create(sizeof(int), 10);
    ASSERT_NOT_NULL(pool);

    void *p = mempool_alloc(pool);
    ASSERT_NOT_NULL(p);

    mempool_free(pool, p);
    
    /* Double free - should be detected and ignored via bitmap */
    mempool_free(pool, p);

    /* Verify double-free was detected */
    struct mempool_stats stats;
    mempool_stats(pool, &stats);
    ASSERT_EQ(stats.double_free, 1);
    ASSERT_EQ(stats.allocated, 0);
    ASSERT_EQ(stats.free_count, 1);  /* Only first free counted */

    /* Pool should still be usable and NOT corrupted */
    void *p2 = mempool_alloc(pool);
    ASSERT_NOT_NULL(p2);
    ASSERT_EQ(p2, p);  /* Same slot reused */

    mempool_destroy(pool);
}

/*
 * Main
 */

int main(void)
{
    printf("=== Memory Pool Tests ===\n\n");

    printf("Basic Tests:\n");
    RUN_TEST(create_destroy);
    RUN_TEST(create_zero_size_fails);
    RUN_TEST(create_zero_capacity_fails);
    RUN_TEST(destroy_null_safe);

    printf("\nAllocation Tests:\n");
    RUN_TEST(alloc_single);
    RUN_TEST(alloc_fill_pool);
    RUN_TEST(alloc_exhausted_returns_null);
    RUN_TEST(alloc_from_null_pool);

    printf("\nFree Tests:\n");
    RUN_TEST(free_and_realloc);
    RUN_TEST(free_null_safe);
    RUN_TEST(free_invalid_pointer_ignored);
    RUN_TEST(free_order_lifo);

    printf("\nStats Tests:\n");
    RUN_TEST(stats_initial);
    RUN_TEST(stats_after_operations);
    RUN_TEST(stats_null_safe);

    printf("\nReset Tests:\n");
    RUN_TEST(reset_frees_all);
    RUN_TEST(reset_null_safe);

    printf("\nEdge Cases:\n");
    RUN_TEST(small_slot_size);
    RUN_TEST(single_slot_pool);
    RUN_TEST(large_slot_size);
    RUN_TEST(alloc_free_cycles);
    RUN_TEST(double_free_safe);

    printf("\n=== Results: %d/%d tests passed ===\n",
           tests_passed, tests_passed + tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
