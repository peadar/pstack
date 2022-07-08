#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "noreturn.h"

// Because assert_fail is marked as noreturn, the call to it is not followed
// by another instruction in this function.
// This test ensures that "thisFunctionWontReturn is on the dumped stack.
__attribute__((noinline, weak)) // avoid inlining or IPO.
int thisFunctionWontReturn(int x)
{
    if (x) {
        for (int i = 0; i < 10; ++i) {
            printf("%d green bottles hanging on the wall\n", 10 - i);
        }
        thisFunctionTerminatesTheProcess();
    }
    return 0;
}

int
main()
{
    thisFunctionWontReturn(1);
}
