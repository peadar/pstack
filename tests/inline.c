#include <unistd.h>
#include <stdio.h>

extern void my_abort();
static inline __attribute__((always_inline)) int x(int a, int b)
{
   my_abort();
   return a + b;
}

extern void my_abort();
static inline __attribute__((always_inline)) int y(int a, int b)
{
   return x(a, b) * x(b, a);
}


__attribute__((noinline)) int z(int fortytwo)
{
   return y(fortytwo * 2, fortytwo) + 9;
}

int main() {
   printf("%d\n", z(42));
}


