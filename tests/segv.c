#include <stdlib.h>
#include <ucontext.h>
#include <signal.h>
#include <unistd.h>

extern void my_abort();

void
sigsegv(int segv)
{
    my_abort();
}

void g()
{
    *(int *)1 = 0;
    pause();
}

void f(int argc, char *argv[])
{
    g();
    pause();
}

int
main(int argc, char *argv[])
{
    signal(SIGSEGV, sigsegv);
    f(argc, argv);
    return 0;
}
