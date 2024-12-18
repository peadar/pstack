#include <pthread.h>
#include <assert.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <signal.h>
#include <vector>
#include "libpstack/json.h"

pthread_mutex_t l = PTHREAD_MUTEX_INITIALIZER;
int in_entry;
int assertline = 0;
pthread_cond_t c = PTHREAD_COND_INITIALIZER;

std::vector<pid_t> lwps; // all the LWPs in the process.
std::vector<pthread_t> threads; // all eht threads in the process.

extern "C" {
void *
entry(void *unused)
{
   (void)unused;
   pthread_mutex_lock(&l);
   in_entry++;
   lwps.push_back(syscall(SYS_gettid));
   // Once the lock is released, the thread can be killed, even before it gets
   // to pause(), so record the line number, release the lock, and sleep on the
   // same line.
   assertline = __LINE__; pthread_cond_signal(&c); pthread_mutex_unlock(&l); pause();
   return nullptr;
}
}

int
main(int /*unused*/, char ** /*unused*/)
{
   pthread_attr_t attrs;
   pthread_attr_init(&attrs);
   pthread_attr_setscope(&attrs, PTHREAD_SCOPE_SYSTEM);

   // the main thread will appear in the pstack output.
   lwps.push_back(syscall(SYS_gettid));
   threads.push_back(pthread_self());

   // Cretae 10 threads.
   for (int i = 0; i < 10; i++) {
      pthread_t tid;
      int rc = pthread_create(&tid, &attrs, entry, &i);
      assert(rc == 0);
      threads.push_back(tid);
   }

   // Make sure all threads have gotten to update in_entry.
   for (;;) {
      pthread_mutex_lock(&l);
      if (in_entry == 10) {
         pthread_mutex_unlock(&l);
         break;
      }
      pthread_cond_wait(&c, &l);
      pthread_mutex_unlock(&l);
   }
   {
      pstack::JObject(std::cout)
         .field("threads", threads)
         .field("lwps", lwps)
         .field("assert_at", assertline);
   }
   (std::cout << std::endl).flush();
   raise(SIGBUS);
}
