/*
 * mempool.c - Fixed-size memory pool implementation
 *
 * Uses a freelist for O(1) alloc/free. Each free slot stores
 * the index of the next free slot, forming a linked list.
 * A bitmap tracks allocation status to detect double-free attempts.
 */

#include "mempool.h"
#include <stdlib.h>
#include <string.h>

/* Slot header - stored at start of each slot when free */
struct slot_header {
    uint32_t next_free;   /* Index of next free slot (0xFFFFFFFF = end) */
};

#define SLOT_END 0xFFFFFFFF

struct mempool {
    uint8_t *data;              /* Pool memory */
    uint8_t *alloc_bitmap;      /* Bitmap: 1 = allocated, 0 = free */
    size_t slot_size;           /* Size of each slot (including header alignment) */
    size_t user_size;           /* User-requested slot size */
    uint32_t capacity;          /* Total number of slots */
    uint32_t free_head;         /* Index of first free slot */
    struct mempool_stats stats; /* Statistics */
};

/* Bitmap helpers */
static inline int bitmap_get(uint8_t *bitmap, uint32_t index)
{
    return (bitmap[index / 8] >> (index % 8)) & 1;
}

static inline void bitmap_set(uint8_t *bitmap, uint32_t index)
{
    bitmap[index / 8] |= (1 << (index % 8));
}

static inline void bitmap_clear(uint8_t *bitmap, uint32_t index)
{
    bitmap[index / 8] &= ~(1 << (index % 8));
}

/* Align slot size to at least hold the header and maintain alignment */
static size_t align_slot_size(size_t user_size)
{
    size_t min_size = sizeof(struct slot_header);
    size_t size = user_size > min_size ? user_size : min_size;
    /* Align to 8 bytes for safe struct access */
    return (size + 7) & ~(size_t)7;
}

mempool_t *mempool_create(size_t slot_size, uint32_t capacity)
{
    mempool_t *pool;
    uint32_t i;
    size_t aligned_size;
    size_t bitmap_size;

    if (slot_size == 0 || capacity == 0)
        return NULL;

    pool = malloc(sizeof(mempool_t));
    if (!pool)
        return NULL;

    aligned_size = align_slot_size(slot_size);
    pool->data = malloc(aligned_size * capacity);
    if (!pool->data) {
        free(pool);
        return NULL;
    }

    /* Allocate bitmap: 1 bit per slot, rounded up to bytes */
    bitmap_size = (capacity + 7) / 8;
    pool->alloc_bitmap = malloc(bitmap_size);
    if (!pool->alloc_bitmap) {
        free(pool->data);
        free(pool);
        return NULL;
    }
    memset(pool->alloc_bitmap, 0, bitmap_size);

    pool->slot_size = aligned_size;
    pool->user_size = slot_size;
    pool->capacity = capacity;

    /* Initialize freelist - each slot points to next */
    for (i = 0; i < capacity - 1; i++) {
        struct slot_header *h = (struct slot_header *)(pool->data + i * aligned_size);
        h->next_free = i + 1;
    }
    /* Last slot marks end */
    struct slot_header *last = (struct slot_header *)(pool->data + (capacity - 1) * aligned_size);
    last->next_free = SLOT_END;

    pool->free_head = 0;

    /* Initialize stats */
    memset(&pool->stats, 0, sizeof(pool->stats));
    pool->stats.capacity = capacity;

    return pool;
}

void mempool_destroy(mempool_t *pool)
{
    if (!pool)
        return;
    free(pool->alloc_bitmap);
    free(pool->data);
    free(pool);
}

void *mempool_alloc(mempool_t *pool)
{
    struct slot_header *slot;
    void *ptr;
    uint32_t index;

    if (!pool || pool->free_head == SLOT_END) {
        if (pool)
            pool->stats.exhausted++;
        return NULL;
    }

    /* Pop from freelist */
    index = pool->free_head;
    slot = (struct slot_header *)(pool->data + index * pool->slot_size);
    pool->free_head = slot->next_free;

    /* Mark as allocated in bitmap */
    bitmap_set(pool->alloc_bitmap, index);

    /* Zero the slot for safety */
    ptr = (void *)slot;
    memset(ptr, 0, pool->user_size);

    /* Update stats */
    pool->stats.allocated++;
    pool->stats.alloc_count++;
    if (pool->stats.allocated > pool->stats.peak)
        pool->stats.peak = pool->stats.allocated;

    return ptr;
}

void mempool_free(mempool_t *pool, void *ptr)
{
    struct slot_header *slot;
    uint32_t index;

    if (!pool || !ptr)
        return;

    /* Calculate slot index */
    if ((uint8_t *)ptr < pool->data)
        return; /* Invalid pointer */
    
    index = (uint32_t)(((uint8_t *)ptr - pool->data) / pool->slot_size);
    if (index >= pool->capacity)
        return; /* Out of range */

    /* Verify pointer is slot-aligned */
    if ((uint8_t *)ptr != pool->data + index * pool->slot_size)
        return; /* Misaligned pointer */

    /* Check for double-free using bitmap */
    if (!bitmap_get(pool->alloc_bitmap, index)) {
        pool->stats.double_free++;
        return; /* Already free - ignore to prevent corruption */
    }

    /* Mark as free in bitmap */
    bitmap_clear(pool->alloc_bitmap, index);

    /* Push onto freelist */
    slot = (struct slot_header *)ptr;
    slot->next_free = pool->free_head;
    pool->free_head = index;

    /* Update stats */
    if (pool->stats.allocated > 0)
        pool->stats.allocated--;
    pool->stats.free_count++;
}

void mempool_stats(mempool_t *pool, struct mempool_stats *stats)
{
    if (!pool || !stats)
        return;
    *stats = pool->stats;
}

void mempool_reset(mempool_t *pool)
{
    uint32_t i;
    size_t bitmap_size;

    if (!pool)
        return;

    /* Clear allocation bitmap */
    bitmap_size = (pool->capacity + 7) / 8;
    memset(pool->alloc_bitmap, 0, bitmap_size);

    /* Rebuild freelist */
    for (i = 0; i < pool->capacity - 1; i++) {
        struct slot_header *h = (struct slot_header *)(pool->data + i * pool->slot_size);
        h->next_free = i + 1;
    }
    struct slot_header *last = (struct slot_header *)(pool->data + (pool->capacity - 1) * pool->slot_size);
    last->next_free = SLOT_END;

    pool->free_head = 0;
    pool->stats.allocated = 0;
}
