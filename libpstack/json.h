#ifndef _JSON_H_
#define _JSON_H_
#include <iostream>
#include <functional>
#include <type_traits>
#include <cstdlib>
#include <iomanip>
#include <filesystem>

namespace pstack {
/*
 * General purpose way of printing out JSON objects.
 * Given an std::ostream &s, we can do:
 * s << json(anytype)
 * And have it print out.
 * For your own structures, you define:
 * std::ostream &operator << (std::ostream &, const JSON<mytype, context> &)
 * This function can use "JObject" below to describe its fields, eg:
 *    std::ostream &operator << (std::ostream &os, const JSON<MyType> &json) {
 *       MyType &myObject = json.object;
 *       JObject o(os);
 *       o.field("foo", myObject.foo);
 *       return os;
 *    }
 * Calls to field return the JObject, so you can chain-call them, and it also
 * converts to an ostream, so you can do:
 *     return JObject(o).field("foo", myObject.foo).field("bar", myObject.bar());
 *
 * There are wrappers for arrays, and C++ containers to do the right thing.
 */

/*
 * A wrapper for objects so we can serialize them as JSON.
 * You can hold some context information in the printer to make life easier.
 */
template <typename T, typename C = char> class JSON {
public:
   const T& object;
   const C &context;
   JSON(const T &object_, const C &context_ = C()) : object(object_), context(context_) {}
   JSON() = delete;
};

/*
 * Easy way to create a JSON object, with a given context
 */
template <typename T, typename C = char>
JSON<T, C>
json(const T &object, const C &context = C()) {
   return JSON<T, C>(object, context);
}

/*
 * A field in a JSON object - arbitrary key and value.
 */
template <typename K, typename V>
struct Field {
   const K &k;
   const V &v;
   Field(const K &k_, const V &v_) : k(k_), v(v_) {}
   Field() = delete;
   Field(const Field<K, V> &) = delete;
};

/*
 * A printer for JSON integral types - just serialize directly from C type.
 */
template <typename C>
typename std::ostream &
operator << (std::ostream &os, const JSON<unsigned char, C>&json) {
   return os << int(json.object);
}

template <typename T, typename C>
typename std::enable_if<std::is_integral<T>::value && !std::is_same<T, unsigned char>::value, std::ostream>::type &
operator << (std::ostream &os, const JSON<T, C>&json) { return os << json.object; }

/*
 * A printer for JSON boolean types: print "true" or "false"
 */
template <typename C>
std::ostream &
operator << (std::ostream &os, const JSON<bool, C> &json)
   { return os << (json.object ? "true" : "false"); }

/*
 * printers for arrays. char[N] is special, we treat that as a string.
 */
template <typename C, size_t N>
std::ostream &
operator << (std::ostream &os, const JSON<char[N], C> &json)
    { return os << JSON<const char *, C>(&json.object[0], json.context); }

template <typename T, size_t N, typename C>
std::ostream &
operator << (std::ostream &os, const JSON<T[N], C> &j)
{
    os << "[";
    for (size_t i = 0; i < N; ++i) {
        os << (i ? ",\n" : "") << json(j.object[i], j.context);
    }
    return os << "]";
}

/*
 * Print a field of an object
 */
template <typename K, typename V, typename C>
std::ostream &
operator << (std::ostream &os, const JSON<Field<K,V>, C> &o)
{
   return os << json(o.object.k) << ":" << json(o.object.v, o.context);
}

/*
 * is_associative_container: returns true_type for containers with "mapped_type"
 */
constexpr std::false_type is_associative_container(...) {
    return std::false_type{};
}

template <typename C, typename = typename C::mapped_type>
constexpr std::true_type is_associative_container(const C *) {
    return std::true_type{};
}

/*
 * Print a non-associative container
 */
template <typename Container, typename Context>
void print_container(std::ostream &os, const Container &container, Context &&ctx, std::false_type)
{
   os << "[ ";
   const char *sep = "";
   for (const auto &field : container) {
      os << sep << json(field, ctx);
      sep = ",\n";
   }
   os << " ]";
}

/*
 * Print an associative container
 */
template <typename Container,
         typename Context,
         typename = std::true_type,
         typename K = typename Container::key_type,
         typename V = typename Container::mapped_type
         >
void
print_container(std::ostream &os, const Container &container, Context ctx, std::true_type)
{
   os << "{";
   const char *sep = "";
   for (const auto &field : container) {
      Field<K,V> jfield(field.first, field.second);
      os << sep << json(jfield, ctx);
      sep = ", ";
   }
   os << "}";
}

/*
 * Print any type of container
 */
template <class Container, typename Context, typename = typename Container::value_type>
std::ostream &
operator << (std::ostream &os, const JSON<Container, Context> &container) {
    print_container(os, container.object, container.context, is_associative_container(&container.object));
    return os;
}

struct Escape {
    std::string value;
    Escape(std::string value_) : value(value_) { }
};

struct JSONEncodingError : public std::exception {
   std::string msg;
   const char *what() const noexcept { return msg.c_str(); }
   JSONEncodingError(std::string &&rhs) : msg(std::move(rhs)) {}
};

inline std::ostream & operator << (std::ostream &o, const Escape &escape)
{
    auto flags(o.flags());
    for (auto i = escape.value.begin(); i != escape.value.end();) {
        int c;
        switch (c = (unsigned char)*i++) {
            case '\b': o << "\\b"; break;
            case '\f': o << "\\f"; break;
            case '\n': o << "\\n"; break;
            case '"': o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            default:
                if (unsigned(c) < 32) {
                    o << "\\u" << std::hex << unsigned(c);
                } else if (c & 0x80) {
                    // multibyte UTF-8: build up the unicode codepoint.
                    unsigned long v = c;
                    int count = 0;
                    for (int mask = 0x80; mask & v; mask >>= 1) {
                        if (mask == 0)
                            throw JSONEncodingError("malformed UTF-8 string");
                        count++;
                        v &= ~mask;
                    }
                    while (--count) {
                        c = (unsigned char)*i++;
                        if ((c & 0xc0) != 0x80)
                            throw JSONEncodingError("illegal character in multibyte sequence");
                        v = (v << 6) | (c & 0x3f);
                    }
                    o << "\\u" << std::hex << std::setfill('0') << std::setw(4) << v;
                } else {
                    o << (char)c;
                }
                break;
        }
    }
    o.flags(flags);
    return o;
}


/*
 * Print a JSON string (std::string, char *, etc)
 */
template <typename C>
std::ostream &
operator << (std::ostream &os, const JSON<std::string, C> &json) {
   return os << "\"" << Escape(json.object) << "\"";
}

/*
 * Print a JSON string (std::filesystem::path, char *, etc)
 */
template <typename C>
std::ostream &
operator << (std::ostream &os, const JSON<std::filesystem::path, C> &json) {
   return os << "\"" << Escape(json.object) << "\"";
}


template <typename C>
std::ostream &
operator << (std::ostream &os, const JSON<const char *, C> &json) {
   return os << "\"" << Escape(json.object) << "\"";
}

/*
 * A mapping type that converts the entries in a container to a different type
 * as you iterate over the original container.
 */
template <class NK, class V, class Container> class Mapper {
    const Container &container;
public:
    typedef typename Container::mapped_type mapped_type;
    typedef typename std::pair<NK, const mapped_type &> value_type;
    typedef NK key_type;
    struct iterator {
        typename Container::const_iterator realIterator;
        value_type operator *() {
            const auto &result = *realIterator;
            return std::make_pair(NK(result.first), std::cref(result.second));
        }
        bool operator == (const iterator &lhs) {
            return realIterator == lhs.realIterator;
        }
        bool operator != (const iterator &lhs) {
            return realIterator != lhs.realIterator;
        }
        void operator ++() {
            ++realIterator;
        }
        iterator(typename Container::const_iterator it_) : realIterator(it_) {}
    };
    typedef iterator const_iterator;

    iterator begin() const { return iterator(container.begin()); }
    iterator end() const { return iterator(container.end()); }
    Mapper(const Container &container_): container(container_) {}
};

/* Helper for rendering compound types. */
class JObject {
   std::ostream &os;
   const char *sep;
   public:
      JObject(std::ostream &os_) : os(os_), sep("") {
         os << "{ ";
      }
      ~JObject() {
         os << " }";
      }
      template <typename K, typename V, typename C = char> JObject &field(const K &k, const V&v, const C &c = C()) {
         Field<K,V> field(k, v);
         os << sep << json(field, c);
         sep = ", ";
         return *this;
      }
      operator std::ostream &() { return os; }
};

/*
 * Fallback printer for pairs.
 */
template <typename F, typename S, typename C>
std::ostream &
operator << (std::ostream &os, const JSON<std::pair<F, S>, C> &json) {
   return JObject(os)
       .field("first", json.object.first)
       .field("second", json.object.second);
}


class JsonNull {};

template <typename C>
std::ostream &
operator << (std::ostream &os, const JSON<JsonNull, C> &) {
   return os << "null";
}
}


#endif
