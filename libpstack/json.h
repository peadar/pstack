#ifndef _JSON_H_
#define _JSON_H_
#include <iostream>
#include <type_traits>
#include <cstdlib>
#include <iomanip>
#include <filesystem>
#include <ranges>

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
template <typename T, typename C>
JSON<T, C>
json(const T &object, const C &context) {
   return JSON<T, C>(object, context);
}

template <typename T>
JSON<T, char>
json(const T &object) {
   return JSON<T, char>(object, {});
}

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

// String-like things.
template <typename T> concept Stringish =
      std::convertible_to<const T, std::string_view>;

template <Stringish T>
struct Escape {
    const T &value;
    Escape(const T &value_) : value(value_) { }
};

/*
 * A field in a JSON object - "stringish" key, arbitrary value.
 */
template <Stringish K, typename V>
struct Field {
   const K &k;
   const V &v;
   Field(const K &k_, const V &v_) : k(k_), v(v_) {}
   Field() = delete;
   Field(const Field<K, V> &) = delete;
};

/*
 * Print a field of an object
 */
template <typename K, typename V, typename C>
std::ostream &
operator << (std::ostream &os, const JSON<Field<K,V>, C> &o)
{
   return os << json(o.object.k) << ":" << json(o.object.v, o.context);
}

// A range  - render as a JSON list (except for StringKeyedRange, see below)
// A string looks like a range, so special-case that.
template <typename T> concept NonStringRange = !Stringish<T> && std::ranges::range<T>;

// When printing containers, if the value_type is a pair of something
// stringish, we assume its a string-keyed container/range.
template <typename T>
struct IsPair : std::false_type {
};

template <typename T1, typename T2>
struct IsPair<std::pair<T1, T2>> : std::true_type {
};

// A range where the values are pairs, which have a stringish key. Render as a JSON object.
template <typename T> concept StringKeyedRange =
        NonStringRange<T> &&
        IsPair<std::ranges::range_value_t<T>>::value &&
        Stringish<typename std::ranges::range_value_t<T>::first_type> ;

// Print an associative container as a JSON "object"
template <StringKeyedRange Container, typename Context >
void
print_object_container(std::ostream &os, const Container &container, const Context &ctx)
{
   os << "{";
   const char *sep = "";
   for (const auto &field : container) {
      os << sep << json( Field(field.first, field.second), ctx);
      sep = ",\n";
   }
   os << "}";
}

// Print a non-associative container
template <NonStringRange Container, typename Context>
void print_list_container(std::ostream &os, const Container &container, const Context &ctx)
{
   os << "[ ";
   const char *sep = "";
   for (const auto &field : container) {
      os << sep << json(field, ctx);
      sep = ",\n";
   }
   os << " ]";
}

// Reasonable printing of any container that is not just a string.
template <NonStringRange Container, typename Context>
std::ostream &
operator << (std::ostream &os, const JSON<Container, Context> &container) {
    if constexpr (StringKeyedRange<Container>) {
        print_object_container(os, container.object, container.context);
    } else {
        print_list_container(os, container.object, container.context);
    }
    return os;
}

template <NonStringRange T>
struct NotAsObject {
   const T &t;
};

template <typename Container, typename Context>
std::ostream &
operator << (std::ostream &os, const JSON<NotAsObject<Container>, Context> &container) {
    print_list_container(os, container.object.t, container.context);
    return os;
}


struct JSONEncodingError : public std::exception {
   std::string msg;
   const char *what() const noexcept { return msg.c_str(); }
   JSONEncodingError(std::string &&rhs) : msg(std::move(rhs)) {}
};

template <typename T>
inline std::ostream & operator << (std::ostream &o, const Escape<T> &escape)
{
    auto flags(o.flags());
    std::string_view view{ escape.value };
    for (auto i = view.begin(); i != view.end();) {
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
 * Print a JSON string
 */
template <Stringish Str, typename C>
std::ostream &
operator << (std::ostream &os, const JSON<Str, C> &json) {
   return os << "\"" << Escape(json.object) << "\"";
}

template <typename C>
std::ostream &
operator << (std::ostream &os, const JSON<std::filesystem::path, C> &json) {
   std::string pathStr = json.object;
   return os << "\"" << Escape(pathStr) << "\"";
}


template <typename C>
std::ostream &
operator << (std::ostream &os, const JSON<const char *, C> &json) {
   return os << "\"" << Escape(json.object) << "\"";
}

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

      template <typename K, typename V, typename C> JObject &field(const K &k, const V&v, const C &c) {
         Field<K, V> field(k, v);
         os << sep << json(field, c);
         sep = ", ";
         return *this;
      }

      template <typename K, typename V> JObject &field(const K &k, const V&v) {
         return field(k, v, char(0));
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
       .field("first", json.object.first, json.context)
       .field("second", json.object.second, json.context);
}


class JsonNull {};

template <typename C>
std::ostream &
operator << (std::ostream &os, const JSON<JsonNull, C> &) {
   return os << "null";
}
}


#endif
