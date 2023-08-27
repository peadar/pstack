/*
 * Wrapper for "malloc" that records stack information in a block header
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <link.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/queue.h>
#include "heap.h"
#include <dlfcn.h>
#include <assert.h>
#include <sys/types.h>
#include <stdbool.h>

// disable optimization.
// There are a number of problems optimization can cause in here. For example,
// folding calls to "malloc" + "memset" into calls to calloc, mucking with the
// layout of the stack, etc.
#pragma GCC optimize("O0")

// types of functions we'll interpose.
typedef void *(*malloc_t)(size_t);
typedef malloc_t valloc_t;

typedef void (*free_t)(void *);
typedef void *(*calloc_t)(size_t, size_t);
typedef void *(*realloc_t)(void *, size_t);
typedef void *(*aligned_alloc_t)(size_t align, size_t size);
typedef int(*posix_memalign_t)(void **, size_t align, size_t size);
typedef void *(*memalign_t)(size_t align, size_t size);

static void assertheap(void);
static void getstacktrace(void **ents, int max);
static void sanity_freenode(struct memdesc *desc);
static void *buffer_malloc(size_t amount);
static void *buffer_calloc(size_t members, size_t size);
static void buffer_free(void *unused) {
   (void)unused;
}

struct hdbg_info hdbg; // not static - "hdmp" finds this symbol.

static int startup = 2;
static pthread_mutex_t heap_lock;
static pthread_mutex_t descriptors_lock;

static malloc_t real_malloc = buffer_malloc;
static free_t real_free = buffer_free;
static calloc_t real_calloc = buffer_calloc;
static realloc_t real_realloc;
static malloc_t real_valloc;
static aligned_alloc_t real_aligned_alloc;
static posix_memalign_t real_posix_memalign;
static memalign_t real_memalign;

// This is a simple heap for bootstrapping things. Any call to "free" first
// checks if the allocation came from here, and if so, just ignores the attempt
// to free.
static char malloc_headroom[1024 * 64];
static int malloc_total = 0;

static void die(const char *msg, ...) {
    va_list args;
    va_start(args, msg);
    getstacktrace(hdbg.crashstack, CRASHFRAMES);
    fprintf(stderr, "hdmp: ");
    vfprintf(stderr, msg, args);
    fprintf(stderr, "\n");
    va_end(args);
    abort();
}

static inline void LOCK(pthread_mutex_t *lock) {
    int rc;
    if ((rc = pthread_mutex_lock(lock)) != 0)
        die("lock failed: %s", strerror(rc));
}

static inline void UNLOCK(pthread_mutex_t *lock) {
    int rc;
    if ((rc = pthread_mutex_unlock(lock)) != 0)
        die("unlock failed: %s", strerror(rc));
}

static inline void fill(void *basev, int len, unsigned long filler) {
    if (!hdbg.doFill)
        return;
    unsigned char *base = basev;
    const unsigned char *pad = (const unsigned char *)&filler;
    int i;
    for (i = 0; i < len; i++)
        base[i] = pad[i%4];
}

static void
set_state(struct memdesc *desc, enum memstate state)
{
    char *p = (char *)(desc->data + 1) + desc->len;
    char *q = (char *)&state;
    q = (char *)&state;
    for (size_t i = 0; i < sizeof state; i++)
        p[i] = q[i];
    desc->data->state = state;
}

// prepare a new allocation - guard each side with the magic for an allocated
// block, and create a descriptor for the allocation to hold its stack trace.
static inline void build_alloc(void *base, struct guard *guard, size_t size) {
    struct memdesc *desc;
    LOCK(&descriptors_lock);
    if (TAILQ_EMPTY(&hdbg.descriptors)) {
        UNLOCK(&descriptors_lock);
        desc = real_malloc(sizeof (struct memdesc) +
              sizeof (void *) * (hdbg.maxframes - 1));
    } else {
        desc = TAILQ_FIRST(&hdbg.descriptors);
        TAILQ_REMOVE(&hdbg.descriptors, desc, node);
        UNLOCK(&descriptors_lock);
    }
    guard->desc = desc;
    desc->data = guard;
    desc->len = size;
    desc->base = base;
    set_state(desc, mem_allocated);
    getstacktrace(desc->stack, hdbg.maxframes);

    LOCK(&heap_lock);
    desc->serial = hdbg.serial++;
    hdbg.stats.alloc_total += size;
    if (hdbg.stats.alloc_total > hdbg.stats.maxmem) {
        hdbg.stats.maxmem = hdbg.stats.alloc_total;
        if (hdbg.alloc_limit && hdbg.stats.alloc_total > hdbg.alloc_limit)
           die("exceeded set memory limit");
        hdbg.stats.maxmem = hdbg.stats.alloc_total;
    }
    TAILQ_INSERT_HEAD(&hdbg.heap, desc, node);
    UNLOCK(&heap_lock);
    fill(guard + 1, size, 0xbaadf00d);
}

// Free the descriptor assocated with an allocation. We don't actually free
// descriptors ever - just return them to a pool for efficiency. We hold on to
// the descriptors for the first few very large allocations so we can report
// them.
static void free_desc(struct memdesc *desc) {
    sanity_freenode(desc);
    LOCK(&descriptors_lock);
    if (desc->len >= hdbg.rememberbigger && hdbg.numbig < hdbg.maxbig) {
       TAILQ_INSERT_TAIL(&hdbg.freebig, desc, node);
       hdbg.numbig++;
    } else {
       TAILQ_INSERT_TAIL(&hdbg.descriptors, desc, node);
    }
    UNLOCK(&descriptors_lock);
}

// Read the state markers at the start and end of a block, and assert they are
// the same
static enum memstate get_state(struct memdesc *desc) {
    enum memstate state;
    char *p = (char *)(desc->data + 1) + desc->len;
    char *q = (char *)&state;
    for (size_t i = 0; i < sizeof state; i++)
        q[i] = p[i];
    if (state != desc->data->state)
        die("head state != tail state. memory over/underrun");
    return state;
}

static void sanity_freenode(struct memdesc *desc) {
    // Verify a "free" descriptor. It should be marked as free on each end.
    if (get_state(desc) != mem_free)
        die("free memory isn't");
    if (hdbg.doFill) {
        // Also, if we're filling memory, then we should be able to verify that
        // the 0xdeaddead pattern has been maintained while it was on the free
        // list
        for (size_t i = 0; i < desc->len / 4; i++)
            if (((unsigned long *)(desc->data + 1))[i] != 0xdeaddead)
                die("free memory modified");
    }
}

static void * buffer_malloc(size_t amount) {
    // Only use buffer_malloc before we can use proper malloc...
    if (startup == 0)
        die("unexpected buffer_malloc()");

    amount = (amount + 3) & ~3; // round up to 4-byte aligned value.

    // space in buffer?
    if (amount + malloc_total >= sizeof malloc_headroom)
        die("out of buffer space during initialisation");

    // consume and return that much of the malloc_headroom
    void *p = malloc_headroom + malloc_total;
    malloc_total += amount;
    return p;
}
static void * buffer_calloc(size_t members, size_t size) {
   size_t total = members * size;
   void *p = buffer_malloc(total);
   memset(p, 0, total);
   return p;
}

static bool use_hdmp() {
    // this is actually our initialization routine. The constructor below runs
    // far too late normally - so we rely on the first calls to malloc to get
    // us in here. Each heap function calls this functions to see if they
    // should do their extra work, or just punt to the "real" implementation.
    // We need the two-step startup process because this function itself may
    // invoke malloc indirectly, and we use our small malloc heap to provide
    // any memory required in here.
    switch (startup) {
        case 0:
            if (hdbg.level >= 2)
                assertheap();
            return true;
        case 1:
            return false;
        default:
            break; // continue below
    }
    assert(startup == 2);
    startup = 1;

    // default settings..
    hdbg.level = 1;
    hdbg.rememberbigger = 256 * 1024; // remember first 4k allocations > 256k
    hdbg.maxbig = 4096;
    hdbg.freelistmax = 1024;
    hdbg.doFill = hdbg.level >= 2;
    hdbg.maxframes = DBGH_STACKFRAMES;

    // update settings from environment.
    for (char **pp = environ; *pp; pp++) {
        static const char hdmp_big_thresh[] = "HDMP_BIG_THRESH=";
        static const char hdmp_big_max[] = "HDMP_BIG_COUNT=";
        static const char hdmp_freelistsize[] = "HDMP_FREELISTSIZE=";
        static const char hdmp_stackdepth[] = "HDMP_STACKDEPTH=";
        static const char hdmp_fill[] = "HDMP_FILL=";
        static const char hdmp_maxmem[] = "HDMP_MAXMEM=";
        static const char hdmp_level[] = "HDMP_LEVEL=";
#define INTSET(var, setting) \
        else if (strncmp(*pp, var, sizeof var - 1) == 0) \
            setting = atoi((*pp) + sizeof var - 1)
       if (0) ;
       INTSET(hdmp_freelistsize, hdbg.freelistmax);
       INTSET(hdmp_fill, hdbg.doFill);
       INTSET(hdmp_stackdepth, hdbg.maxframes);
       INTSET(hdmp_big_thresh, hdbg.rememberbigger);
       INTSET(hdmp_big_max, hdbg.maxbig);
       INTSET(hdmp_maxmem, hdbg.alloc_limit);
       INTSET(hdmp_level, hdbg.level);
    }

    // Initialize internal state.
    TAILQ_INIT(&hdbg.heap);
    TAILQ_INIT(&hdbg.freelist);
    TAILQ_INIT(&hdbg.descriptors);
    TAILQ_INIT(&hdbg.freebig);
    pthread_mutex_init(&descriptors_lock, 0);
    pthread_mutex_init(&heap_lock, 0);

    // Make sure we can lock/unlock mutexes without recursing on malloc (i.e.,
    // while startup != 0)
    LOCK(&descriptors_lock);
    UNLOCK(&descriptors_lock);
    LOCK(&heap_lock);
    UNLOCK(&heap_lock);

    // Find real implementations of heap allocation routines.
#define SYM(func) real_##func = (func ## _t)dlsym(RTLD_NEXT, #func)
    SYM(valloc);
    SYM(aligned_alloc);
    SYM(realloc);
    SYM(calloc);
    SYM(free);
    SYM(malloc);
    SYM(memalign);
    SYM(posix_memalign);
    startup = 0;
    return hdbg.level != 0;
}

__attribute__((constructor)) static void init() {
    use_hdmp(); // just in case it hasn't been called yet
    fprintf(stderr, "heap debugger enabled: "
            "use hdmp <executable> <core> to examine post-mortem output\n");
    fprintf(stderr, "debug level=%d, stack frames=%d, freelist size=%d, "
                    "fill memory? %d, keep %d larger than %jd, "
                    "buffer memory used=%d\n",
        hdbg.level,
        (int)hdbg.maxframes,
        hdbg.freelistmax,
        hdbg.doFill,
        (int)hdbg.maxbig,
        (intmax_t)hdbg.rememberbigger,
        malloc_total);
}

// On exit, grab a backtrace into the crash buffer, and ensure we dump core.
__attribute__((destructor)) static void dieOnExit() {
    die("normal termination: generating core");
}

static void assertheap() {
    // if we have debug level >= 2, then assert the heap is sane - walk
    // through the entire heap, and check that the headers and trailers are
    // intact.
    // Also check the last 64 free'd allocations are still ok.
    if (!hdbg.level || startup)
        return;

    LOCK(&heap_lock);
    struct memdesc *desc;
    TAILQ_FOREACH(desc, &hdbg.heap, node)
        if (get_state(desc) != mem_allocated)
            die("allocated memory isn't");
    int count = 0;
    TAILQ_FOREACH(desc, &hdbg.freelist, node) {
        sanity_freenode(desc);
        if (count++ > 64)
            break;
    }
    UNLOCK(&heap_lock);
}

// simple frame-pointer based stack unwind.
//
#if defined(__x86_64__)
static void __attribute__((naked,optimize("O0")))
getframe(void ***bp, void  ***ip) {
    asm( "mov (%rsp), %rax;"
         "mov %rax, (%rsi);"
         "mov %rbp, (%rdi);"
         "ret;"
    );
}
#elif defined(__aarch64__) || defined(__arm__)
void
getframe(void ***bp, void  ***ip) {
   //XXX: TODO: support aarch64
}
#else

static void __attribute__((naked,noinline,optimize("O0")))
getframe(void ***bp, void  ***ip) {
    asm("mov (%esp), %ecx;"
        "mov 8(%esp), %edx;"
        "mov %ecx, (%edx);"
        "mov 4(%esp), %edx;"
        "mov %ebp, (%edx);"
        "ret;");
}
#endif

static void getstacktrace(void **ents, int max_ents) {
    void **ip, **bp, **newBp;
    getframe(&bp, &ip);
    int frameno;
    for (frameno = 0; frameno < max_ents; ++frameno) {
        newBp = (void **)bp[0];
        ip = (void **)bp[1];
        /*
         * Make sure we are making progress, terminate on massive stack frames,
         * or when IP == 0
         */
        if (!newBp || newBp <= bp || newBp - bp > 65536 || ip == 0)
            break;
        bp = newBp;
        ents[frameno] = ip;
    }
    if (frameno < max_ents) // null terminate if less than full size.
       ents[frameno] = 0;
}

/*
 * The libc standard allocator functions - these interpose the ones from libc
 * when we're LD_PRELOAD'd
 */
void *valloc(size_t size) {
    if (!use_hdmp())
        return real_valloc(size);
    return aligned_alloc(4096, size);
}

int posix_memalign(void **ptr, size_t align, size_t size) {
    if (!use_hdmp())
        return real_posix_memalign(ptr, align, size);
    *ptr = aligned_alloc(align, size);
    return 0;
}

void *memalign(size_t align, size_t size) {
    if (!use_hdmp())
        return real_memalign(align, size);
    return aligned_alloc(align, size);
}

void *malloc(size_t size) {
    if (!use_hdmp())
        return real_malloc(size);
    /* Space for guard at the start, memstate at the end, and size in between */
    struct guard *guard = real_malloc(sizeof *guard + size + sizeof (enum memstate));
    hdbg.stats.malloc_calls++;
    build_alloc(guard, guard, size);
    return guard + 1;
}

void *aligned_alloc(size_t align, size_t size) {
    if (!use_hdmp())
        return real_aligned_alloc(align, size);
    hdbg.stats.calloc_calls++;
    /*
     * We need an aligned block with space for our guard before it. So, we need
     * to bump the size by the first multiple of align that will accomodate our
     * header.
     */
    size_t extra = sizeof (struct guard) % align != 0 ? 1 : 0;
    size_t internal_space = align * (sizeof (struct guard) / align + extra);
    /* Space for guard at the start, memstate at the end, and size in between */
    char *base = real_aligned_alloc(align,
          internal_space + size + sizeof (enum memstate));
    struct guard *guard = (struct guard *)(base + internal_space - sizeof *guard);
    build_alloc(base, guard, size);
    return guard + 1;
}

static inline int headroom(const void *p) {
    const char *cp = p;
    return cp >= malloc_headroom && cp < malloc_headroom + sizeof malloc_headroom;
}

void free(void *p) {
    if (p == 0)
        return;
    if (!use_hdmp()) {
        if (!headroom(p))
            real_free(p);
        return;
    }

    struct guard *guard = (struct guard *)p - 1;
    struct memdesc *desc = guard->desc;

    if (get_state(desc) != mem_allocated)
        die("free() passed non-allocated memory");
    if (desc->data != guard)
        die("internal integrity error");

    getstacktrace(desc->stack, hdbg.maxframes);
    fill(desc->data + 1, desc->len, 0xdeaddead);
    set_state(desc, mem_free);

    LOCK(&heap_lock);

    hdbg.stats.free_calls++;
    hdbg.stats.alloc_total -= desc->len;
    TAILQ_REMOVE(&hdbg.heap, desc, node);

    TAILQ_INSERT_HEAD(&hdbg.freelist, desc, node);
    // put this block on the freelist, and extract the oldest block if the list
    // is too big. We will actually free the oldest one now, so we have
    // maintained some hysteresis between the application calling free() and
    // actually freeing the memory.
    if (hdbg.freelistsize == hdbg.freelistmax) {
        desc = TAILQ_LAST(&hdbg.freelist, memdesc_list);
        TAILQ_REMOVE(&hdbg.freelist, desc, node);
    } else {
        hdbg.freelistsize++;
        desc = 0;
    }
    UNLOCK(&heap_lock);

    if (desc) {
        void *p = desc->base;
        free_desc(desc);
        if (!headroom(p))
            real_free(p);
    }
}

void *realloc(void *p, size_t size) {
    struct memdesc *olddesc;
    struct guard *guard;
    if (!use_hdmp())
        return real_realloc(p, size);
    hdbg.stats.realloc_calls++;
    if (p) {
        guard = (struct guard *)p - 1;
        olddesc = guard->desc;
        if (olddesc->len >= size)
            return p;
    }
    char *p2 = malloc(size);
    if (p2 && p) {
        memcpy(p2, p, olddesc->len < size ? olddesc->len : size);
        free(p);
    }
    return p2;
}

void *calloc(size_t numelem, size_t size) {
    if (!use_hdmp())
       return real_calloc(numelem, size);
    hdbg.stats.calloc_calls++;
    size *= numelem;
    void *p = malloc(size);
    memset(p, 0, size);
    return p;
}
