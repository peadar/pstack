#pragma once
#include <exception>
#include <sstream>

namespace pstack {

class Exception : public std::exception {
    mutable std::ostringstream str;
    mutable std::string intermediate;
public:
    Exception() = default;
    // Keep the put position at the end so streaming onto a copy appends.
    Exception(const Exception &rhs) : str{ rhs.str.str(), std::ios::out | std::ios::ate } {}
    Exception(Exception &&rhs) = default;

    Exception &operator = (const Exception &rhs) {
       if (this != &rhs) {
           str = std::ostringstream{rhs.str.str(), std::ios::out | std::ios::ate};
           intermediate.clear();
       }
       return *this;
    };

    Exception &operator = (Exception &&rhs) = default;
    ~Exception() noexcept = default;

    const char *what() const noexcept override {
        try {
            intermediate = str.str();
            return intermediate.c_str();
        } catch (...) {
            return "pstack exception (message unavailable)";
        }
    }
    std::ostream &getStream() const { return str; }
    typedef void IsStreamable;
    template <typename T>
    const Exception &operator << (const T& o) const {
       getStream() << o;
       return *this;
    }
};

}
