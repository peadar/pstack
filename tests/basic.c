#include <stdlib.h>
#include <unistd.h>

extern void my_abort();

void g(int two)
{
    (void)two;
    abort();
}
void f(int one)
{
    (void)one;
    g(2);
}

int
main()
{
    f(1);
    return 0;
}
