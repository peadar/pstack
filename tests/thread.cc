#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <vector>
#include <iostream>

pthread_mutex_t l = PTHREAD_MUTEX_INITIALIZER;
int in_entry;
pthread_cond_t c = PTHREAD_COND_INITIALIZER;

void *
entry(void *arg)
{
   pthread_mutex_lock(&l);
   in_entry++;
   pthread_cond_signal(&c);
   pthread_mutex_unlock(&l);
   pause();
}

int
main(int argc, char *argv[])
{
   pthread_attr_t attrs;
   pthread_attr_init(&attrs);
   pthread_attr_setscope(&attrs, PTHREAD_SCOPE_SYSTEM);

   std::vector<pthread_t> thr;
   for (int i = 0; i < 10; i++) {
      pthread_t tid;
      pthread_create(&tid, &attrs, entry, &i);
   }
   for (;;) {
      pthread_mutex_lock(&l);
      if (in_entry == 10) {
         pthread_mutex_unlock(&l);
         break;
      }
      pthread_cond_wait(&c, &l);
      pthread_mutex_unlock(&l);
   }
   std::clog << "proc " << getpid() << std::endl;
   pause();
   raise(SIGBUS);
}
