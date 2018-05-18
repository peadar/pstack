#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <vector>
#include <iostream>

// *******
// CHANGES TO THIS FILE AFFECTING LINE NUMBERS IN "entry" WILL REQUIRE CHANGES TO
// thread-test.py
// ********
pthread_mutex_t l = PTHREAD_MUTEX_INITIALIZER;
int in_entry;
pthread_cond_t c = PTHREAD_COND_INITIALIZER;

extern "C" {
void *
entry(void *unused)
{
   (void)unused;
   pthread_mutex_lock(&l);
   in_entry++;
   pthread_cond_signal(&c);
   pthread_mutex_unlock(&l);
   pause();
   return nullptr;
}
}

int
main(int /*unused*/, char ** /*unused*/)
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
   raise(SIGBUS);
}
