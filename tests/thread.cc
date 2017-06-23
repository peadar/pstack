#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <vector>

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
   std::vector<pthread_t> thr;
   for (int i = 0; i < 10; i++) {
      pthread_t tid;
      pthread_create(&tid, 0, entry, &i);
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
   raise(SIGBUS);
}
