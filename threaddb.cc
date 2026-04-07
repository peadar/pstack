#include "libpstack/threaddb.h"
#include <dlfcn.h>

namespace pstack {

const ThreadDb *loadThreadDb() {
    static ThreadDb tdb;
    static const ThreadDb *result = [] () -> const ThreadDb * {
        void *handle = dlopen("libthread_db.so.1", RTLD_LAZY | RTLD_GLOBAL);
        if (!handle)
            return nullptr;
#define LOAD(name) tdb.name = reinterpret_cast<decltype(tdb.name)>(dlsym(handle, "td_" #name))
        LOAD(ta_new);
        LOAD(ta_delete);
        LOAD(ta_thr_iter);
        LOAD(thr_get_info);
#undef LOAD
        if (!tdb.ta_new || !tdb.ta_delete || !tdb.ta_thr_iter || !tdb.thr_get_info) {
            dlclose(handle);
            return nullptr;
        }
        return &tdb;
    }();
    return result;
}

bool threaddbAvailable() {
    return loadThreadDb() != nullptr;
}

} // namespace pstack
