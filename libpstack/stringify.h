#ifndef pstack_stringify_h
#define pstack_stringify_h
#include <sstream>

namespace pstack {
template <typename... Stuff>
std::string
stringify(Stuff&&... things)
{
    std::ostringstream stream;
    ( stream <<  ... << things );
    return stream.str();
}
}

#endif
