#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
void
sighandle(int sig)
{
   (void)sig;
   abort();
}

int
main(int argc, char *argv[])
{
   int c;
   while ((c = getopt(argc, argv, "h")) != -1) {
      switch (c) {
         case 'h': // handle the fault with a signal handler.
            signal(SIGSEGV, sighandle);
            break;
         default:
            abort();
      }
   }

   void (*f)(void) = 0;
   f();
}
