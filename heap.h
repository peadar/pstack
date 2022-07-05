/* $Id: heap.h,v 1.5.2.1 2002/05/31 15:40:03 petere Exp $ */

#ifndef heap_h_guard
#define heap_h_guard
#include <sys/queue.h>

enum memstate {
    mem_ignore = 0,
    mem_allocated =  (int)0xa5a5a5a5,
    mem_free = (int)0x5a5a5a5a,
};

#define DBGH_STACKFRAMES 16

struct memdesc;

TAILQ_HEAD(memdesc_list, memdesc);
typedef TAILQ_ENTRY(memdesc) memdesc_node;

/*
 * Each block of memory is preceded by a "guard", and followed by a simple "memstate"
 * The memdesc structure pointed to by the guard is separated so any overruns are
 * less likely to eat into the state information
 */

struct guard {
    struct memdesc *desc;
    enum memstate state;
};

/*
 * Contains information about an allocated block of memory.
 */
struct memdesc {
    memdesc_node node; /* Links to allocated, recently free, or unused descriptor list */
    unsigned long serial; /* Incrementing serial number for alloc/free operation */
    size_t len; /* User-requested length of allocated block. */
    struct guard *data; /* Points to data for this descriptor */
    void *base;
    void * stack[1]; // array of instruction pointers.
};

struct stats {
    size_t alloc_total;
    size_t maxmem;
    unsigned malloc_calls;
    unsigned free_calls;
    unsigned calloc_calls;
    unsigned realloc_calls;
    unsigned aligned_alloc_calls;
};

/* This is the structure the post-processing tool grovels for. */
#define CRASHFRAMES 512
struct hdbg_info {
    struct memdesc_list heap; /* Active memory */
    struct memdesc_list freelist; /* Free memory */
    struct memdesc_list descriptors; /* Free memdescs */
    struct memdesc_list freebig; /* memdescs for big blocks that were free'd */
    int freelistmax;
    int freelistsize;
    struct stats stats;
    int level;
    unsigned long serial;
    int doFill;
    size_t maxframes;

    // store big frames
    size_t rememberbigger;
    size_t numbig;
    size_t maxbig;
    size_t alloc_limit;
    void *crashstack[CRASHFRAMES];
};
#endif
