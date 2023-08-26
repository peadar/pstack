#ifndef pstack_stringify_h
#define pstack_stringify_h
#include <sstream>

namespace pstack {
template <typename T>
void
stringifyImpl(std::ostringstream &os, const T&obj) { os << obj; }

template <typename T>
std::string
stringify(const T&obj) {
    std::ostringstream os;
    stringifyImpl(os, obj);
    return os.str();
}

template <typename T, typename... More>
void
stringifyImpl(std::ostringstream &os, const T&obj, More... more) {
    os << obj;
    stringifyImpl(os, more...);
}

template <typename T, typename... More>
std::string
stringify(const T&obj, More... more)
{
    std::ostringstream stream;
    stringifyImpl(stream, obj, more...);
    return stream.str();
}
}

#endif
