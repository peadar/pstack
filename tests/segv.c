#include <stdlib.h>
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

void f()
{
    g();
    pause();
}

int
main()
{
    signal(SIGSEGV, sigsegv);
    f();
    return 0;
}
