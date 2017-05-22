#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
void
my_abort()
{
    raise(SIGABRT);
    pause();
}
