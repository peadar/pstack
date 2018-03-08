#include "libpstack/ps_callback.h"
#include "libpstack/procdump.h"

extern "C" {
#include <thread_db.h>
}
#include <iostream>

#define T(a, b) case a: return os << #a " (" b ")";
std::ostream &operator << (std::ostream &os, td_err_e err)
{
switch (err) {
T(TD_OK, "No error.")
T(TD_ERR, "No further specified error.")
T(TD_NOTHR, "No matching thread found.")
T(TD_NOSV, "No matching synchronization handle found.")
T(TD_NOLWP, "No matching light-weighted process found.")
T(TD_BADPH, "Invalid process handle.")
T(TD_BADTH, "Invalid thread handle.")
T(TD_BADSH, "Invalid synchronization handle.")
T(TD_BADTA, "Invalid thread agent.")
T(TD_BADKEY, "Invalid key.")
T(TD_NOMSG, "No event available.")
T(TD_NOFPREGS, "No floating-point register content available.")
T(TD_NOLIBTHREAD, "Application not linked with thread library.")
T(TD_NOEVENT, "Requested event is not supported.")
T(TD_NOCAPAB, "Capability not available.")
T(TD_DBERR, "Internal debug library error.")
T(TD_NOAPLIC, "Operation is not applicable.")
T(TD_NOTSD, "No thread-specific data available.")
T(TD_MALLOC, "Out of memory.")
T(TD_PARTIALREG, "Not entire register set was read or written.")
T(TD_NOXREGS, "X register set not available for given thread.")
T(TD_TLSDEFER, "Thread has not yet allocated TLS for given module.")
T(TD_VERSION, "Version if libpthread and libthread_db do not match.")
T(TD_NOTLS, "There is no TLS segment in the given module.")
default: return os << "unknown TD error " << int(err);
}
}
#undef T
