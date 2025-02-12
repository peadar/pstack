#pragma once
#include <exception>
#include <sstream>

namespace pstack {

class Exception : public std::exception {
    mutable std::ostringstream str;
    mutable std::string intermediate;
public:
    Exception() noexcept = default;
    Exception(const Exception &rhs) noexcept : str{ rhs.str.str() } {}
    Exception(Exception &&rhs) noexcept : str{ std::move(rhs.str ) } {}

    Exception &operator = (const Exception &rhs) noexcept {
       str.clear();
       str << rhs.str.str();
       return *this;
    };

    Exception &operator = (Exception &&rhs) noexcept {
       str = std::move(rhs.str);
       return *this;
    };
    ~Exception() noexcept = default;

    const char *what() const noexcept {
        intermediate = str.str();
        return intermediate.c_str();
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
