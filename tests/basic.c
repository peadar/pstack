#include <stdlib.h>
#include <unistd.h>

extern void my_abort();

void g(int two)
{
    abort();
}
void f(int one)
{
    g(2);
}

int
main()
{
    f(1);
    return 0;
}
