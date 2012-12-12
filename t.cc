#include <iostream>
#include <link.h>
#include <unistd.h>
#include <stdlib.h>
#include <err.h>
#ifndef NOTHREADS
#include <pthread.h>
#endif

r_debug rd;
static const size_t THREADCOUNT=3;
static int crash = 0;


int e(int (*cb)())
{
    return cb();
}

int
g()
{
    std::cerr << "pausing" << std::endl;
    if (crash)
        abort();
    dlopen("/tmp/pipe", RTLD_NOW);
    return pause();
}

int
f()
{
    return g();
}


static
void *threadent(void *)
{
    return (void *)(intptr_t)e(f);
}

int
main(int argc, char *argv[])
{
    std::clog << "pid: " << getpid() << "\n";

    int c;
    while ((c = getopt(argc, argv, "c")) != -1) {
        switch (c) {
            case -1:
                return -1;
            case 'c':
                crash = 1;
                break;
        }
    }
#ifndef NOTHREADS
    pthread_t threads[THREADCOUNT];
    for (size_t i = 0; i < THREADCOUNT; ++i) {
        int rc = pthread_create(&threads[i], 0, threadent, &rd);
        if (rc != 0)
            err(-1, "pthread_create");
    }
    for (size_t i = 0; i < THREADCOUNT; ++i) {
        void *rv;
        pthread_join(threads[i], &rv);
    }
#else
    threadent(0);
#endif


    return f();
}
