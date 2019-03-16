#ifndef PS_CALLBACK_H
#define PS_CALLBACK_H

extern "C" {
#include <thread_db.h>

typedef enum {
   PS_OK,
   PS_ERR
} ps_err_e;

struct ps_prochandle;
ps_err_e ps_lgetfpregs(struct ps_prochandle *p, lwpid_t pid, prfpregset_t *fpregsetp);
pid_t ps_getpid(struct ps_prochandle *);
}

#endif
