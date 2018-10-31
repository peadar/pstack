#include <stdlib.h>
#include <ucontext.h>
#include <signal.h>
#include <unistd.h>

extern void my_abort();

void
sigsegv(int segv)
{
    (void)segv;
    my_abort();
}

void g(int a)
{
   (void)a;
    *(int *)1 = 0;
    pause();
}

void f(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    g(1);
    pause();
}

int
main(int argc, char *argv[])
{
    signal(SIGSEGV, sigsegv);
    f(argc, argv);
    return 0;
}
