#include "libpstack/python.h"

// libpthread includes offsets for fields in various structures. We can use
// _thred_db_pthread_tid to work out the offset within a pthread structure of
// the "tid" in a pthread. This gives us a way to find an LWP for a given
// pthread_t. (In Linux's 1:1 modern threadding model, each pthread_t is associated
// with a single LWP, or Linux task.)
bool
pthreadTidOffset(const Process &proc, size_t *offsetp)
{
    static size_t offset;
    static enum { notDone, notFound, found } status;
    if (status == notDone) {
        try {
            auto addr = proc.findSymbol("_thread_db_pthread_tid", true);
            uint32_t desc[3];
            proc.io->readObj(addr, &desc[0], 3);
            offset = desc[2];
            status = found;
            if (verbose)
                *debug << "found thread offset " << offset <<  "\n";
        } catch (const std::exception &ex) {
           if (verbose)
               *debug << "failed to find offset of tid in pthread: " << ex.what();
            status = notFound;
        }
    }
    if (status == found) {
        *offsetp = offset;
        return true;
    }
    return false;
}
