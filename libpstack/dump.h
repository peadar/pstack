#include <libpstack/dwarf.h>
#include "json.h"
#include <iostream>
#include <tuple>
#include <functional>
#include <sys/procfs.h>

std::ostream &operator << (std::ostream &, const JSON<DwarfFileEntry> &);
std::ostream &operator << (std::ostream &, const JSON<DwarfForm> &o);
std::ostream &operator << (std::ostream &, const JSON<std::shared_ptr<DwarfUnit>> &);
std::ostream &operator << (std::ostream &os, const JSON<DwarfInfo> &jo);
