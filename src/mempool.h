/*
 * mempool.h - Fixed-size memory pool for dohd
 *
 * Thread-safe (single-threaded use) memory pool that pre-allocates
 * a fixed number of slots to avoid malloc/free overhead under load.
 */

#ifndef MEMPOOL_H
#define MEMPOOL_H

#include <stddef.h>
#include <stdint.h>

/* Pool statistics */
struct mempool_stats {
    uint32_t capacity;      /* Total slots in pool */
    uint32_t allocated;     /* Currently allocated */
    uint32_t peak;          /* High water mark */
    uint32_t alloc_count;   /* Total allocations */
    uint32_t free_count;    /* Total frees */
    uint32_t exhausted;     /* Times pool was full */
};

/* Opaque pool handle */
typedef struct mempool mempool_t;

/*
 * Create a new memory pool.
 *
 * @param slot_size  Size of each slot in bytes
 * @param capacity   Maximum number of slots
 * @return Pool handle, or NULL on failure
 */
mempool_t *mempool_create(size_t slot_size, uint32_t capacity);

/*
 * Destroy a memory pool and free all memory.
 *
 * @param pool  Pool to destroy (may be NULL)
 */
void mempool_destroy(mempool_t *pool);

/*
 * Allocate a slot from the pool.
 *
 * @param pool  Pool to allocate from
 * @return Pointer to slot, or NULL if pool exhausted
 */
void *mempool_alloc(mempool_t *pool);

/*
 * Return a slot to the pool.
 *
 * @param pool  Pool the slot belongs to
 * @param ptr   Slot to return (may be NULL)
 */
void mempool_free(mempool_t *pool, void *ptr);

/*
 * Get pool statistics.
 *
 * @param pool   Pool to query
 * @param stats  Output statistics structure
 */
void mempool_stats(mempool_t *pool, struct mempool_stats *stats);

/*
 * Reset pool (free all allocations without destroying).
 *
 * @param pool  Pool to reset
 */
void mempool_reset(mempool_t *pool);

#endif /* MEMPOOL_H */
