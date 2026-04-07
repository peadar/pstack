#ifndef LIBPSTACK_THREADDB_H
#define LIBPSTACK_THREADDB_H

struct ps_prochandle; // opaque - defined in proc.h

extern "C" {
#include <thread_db.h>
}

namespace pstack {

struct ThreadDb {
    td_err_e (*ta_new)(struct ps_prochandle *, td_thragent_t **);
    td_err_e (*ta_delete)(td_thragent_t *);
    td_err_e (*ta_thr_iter)(const td_thragent_t *, td_thr_iter_f *,
                void *, td_thr_state_e, int, sigset_t *, unsigned int);
    td_err_e (*thr_get_info)(const td_thrhandle_t *, td_thrinfo_t *);
};

const ThreadDb *loadThreadDb();
bool threaddbAvailable();

} // namespace pstack

#endif // LIBPSTACK_THREADDB_H
