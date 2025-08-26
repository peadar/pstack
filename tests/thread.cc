#include <pthread.h>
#include <assert.h>
#include <sys/procfs.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <signal.h>
#include <vector>
#include <ranges>
#include <map>
#include <sys/types.h>
#include "libpstack/json.h"

pthread_mutex_t l = PTHREAD_MUTEX_INITIALIZER;
int in_entry;
int assertline = 0;
pthread_cond_t c = PTHREAD_COND_INITIALIZER;

std::vector<pthread_t> threads; // all eht threads in the process.
std::map<pthread_t, lwpid_t> lwps; // all the LWPs in the process.

const char *numbers[] = {
   "zero",
   "one",
   "two",
   "three",
   "four",
   "five",
   "six",
   "seven",
   "eight",
   "nine",
   "ten",
};

extern "C" {
void *
entry(void *threadId)
{
   auto idx = reinterpret_cast<uintptr_t>(threadId);
   pthread_setname_np( pthread_self(), numbers[ idx ] );
   pthread_mutex_lock(&l);
   in_entry++;
   lwps[pthread_self()] = syscall(SYS_gettid);
   // Once the lock is released, the thread can be killed, even before it gets
   // to pause(), so record the line number, release the lock, and sleep on the
   // same line.
   assertline = __LINE__; pthread_cond_signal(&c); pthread_mutex_unlock(&l); pause();
   return nullptr;
}
void
usage() {
   std::cerr
      << "usage: threads [-w]\n"
      << "\t -w: wait to be killed, instead of raising SIGBUS.\n"
      ;
}

}

struct ThreadInfo { pthread_t tid; };
std::ostream &operator << (std::ostream &os, const pstack::JSON<ThreadInfo> &j) {
   char buf[ 1024 ];
   int rc = pthread_getname_np(j.object.tid, buf, sizeof buf);

   return pstack::JObject( os ) 
      .field( "pthread_t", j.object.tid )
      .field( "name", rc != 0 ? "<unnamed>" : buf )
      .field( "lwp", lwps[j.object.tid] )
      ;
}

int
main(int argc, char *argv[])
{
   pthread_attr_t attrs;
   pthread_attr_init(&attrs);
   pthread_attr_setscope(&attrs, PTHREAD_SCOPE_SYSTEM);

   bool waitForKill = false;
   for (int c; (c = getopt(argc, argv, "w")) != -1; ) {
      switch (c) {
         case 'w':
            waitForKill = true;
            break;
         default:
            usage();
            break;
      }
   }

   // the main thread will appear in the pstack output.
   lwps[pthread_self()] = syscall(SYS_gettid);
   threads.push_back(pthread_self());

   // Create 10 threads.
   for (int i = 0; i < 10; i++) {
      pthread_t tid;
      int rc = pthread_create(&tid, &attrs, entry, reinterpret_cast<void *> ( i ) );
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

   auto threadOut = std::views::transform( threads, [](pthread_t tid)
         { return ThreadInfo{tid}; });

   pstack::JObject(std::cout)
      .field("pid", getpid())
      .field("threads", threadOut)
      .field("assert_at", assertline);
   std::cout << std::endl;
   close(1); // std::ostream does not define close.
   if (waitForKill) {
      pause();
   } else {
      raise(SIGBUS);
   }
}
