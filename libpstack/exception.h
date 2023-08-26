#include <exception>
#include <sstream>

namespace pstack {

class Exception : public std::exception {
    mutable std::ostringstream str;
    mutable std::string intermediate;
public:
    Exception() throw() {
    }

    Exception(const Exception &rhs) throw() {
        str << rhs.str.str();
    }

    ~Exception() throw () = default;

    const char *what() const throw() {
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
