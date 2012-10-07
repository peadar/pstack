#include <exception>
#include <sstream>

class Exception : public std::exception {
    mutable std::ostringstream str;
    mutable std::string intermediate;
public:
    Exception() {
    }

    Exception(const Exception &rhs) {
        str << rhs.str.str();
    }

    ~Exception() throw () {
    }

    const char *what() const throw() {
        intermediate = str.str();
        return intermediate.c_str();
    }
    std::ostream &getStream() const { return str; }
    typedef void IsStreamable;
};

template <typename E, typename Object, typename Test = typename E::IsStreamable>
inline const E &operator << (const E &stream, const Object &o) {
    stream.getStream() << o;
    return stream;
}
