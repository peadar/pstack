#include <stdlib.h>
#include <unistd.h>

extern void my_abort();

void g()
{
    abort();
}
void f()
{
    g();
}

int
main()
{
    f();
    return 0;
}
