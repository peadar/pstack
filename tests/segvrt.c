#define _GNU_SOURCE
#include <features.h>
#include <stdlib.h>
#include <ucontext.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/user.h>

extern void my_abort();

void
sigsegv(int segv, siginfo_t *info, void *ctxv)
{
    (void)segv;
    (void)info;
    (void)ctxv;
    my_abort();
}

void g()
{
    *(int *)1 = 0;
    pause();
}

void f(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    g();
    pause();
}

int
main(int argc, char *argv[])
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = 0;
    sa.sa_sigaction = sigsegv;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, 0);
    f(argc, argv);
    return 0;
}
