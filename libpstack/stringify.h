#ifndef pstack_stringify_h
#define pstack_stringify_h
#include <sstream>
#include <ranges>
#include <iomanip>

namespace pstack {
template <typename... Stuff>
std::string
stringify(Stuff&&... things)
{
    std::ostringstream stream;
    ( stream <<  ... << things );
    return stream.str();
}

template <typename I> struct AsHex { const I &item; };

template <typename I> std::ostream &
operator << (std::ostream &os, const AsHex<I> &ah) {
   return os << std::hex << std::setfill('0') << std::setw(2) << int(ah.item) << std::dec;
}

template <typename I> requires std::ranges::range<I> std::ostream &
operator << (std::ostream &os, const AsHex<I> &ah) {
   for (auto i : ah.item)
      os << AsHex<decltype(i)> (i);
   return os;
}

}

#endif
