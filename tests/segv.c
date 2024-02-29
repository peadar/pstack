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

static void g(int a)
{
   (void)a;
    *(int *)1 = 0;
    pause();
}

static void f(int argc, char *argv[])
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
