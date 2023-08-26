#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
void
sighandle(int sig)
{
   (void)sig;
   printf("handled signal\n");
   abort();
}

int
main(int argc, char *argv[])
{
   int c;
   void *addr = 0;
   while ((c = getopt(argc, argv, "dh")) != -1) {
      switch (c) {
         case 'h': // handle the fault with a signal handler.
            signal(SIGSEGV, sighandle);
            break;
         case 'd': // handle the fault with a signal handler.
            addr = &addr;
            break;
         default:
            abort();
      }
   }

   void (*f)(void) = addr;
   f();
}
