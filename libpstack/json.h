#ifndef _JSON_H_
#define _JSON_H_
#include <iostream>
#include <cmath>
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
   JSON(const T &object_, const C &context_) : object(object_), context(context_) {}
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
   static char defaultContext; // we need a non-temporary for this.
   return JSON<T, char>(object, defaultContext);
}

/*
 * A printer for JSON integral types - just serialize directly from C type.
 */
template <typename C>
typename std::ostream &
operator << (std::ostream &os, const JSON<unsigned char, C>&json) {
   return os << int(json.object);
}

// Print an integer
template <typename T, typename C>
std::ostream &
operator << (std::ostream &os, const JSON<T, C>&json)
   requires (std::is_integral_v<T> && !std::is_same_v<T, unsigned char>)
{
   return os << json.object;
}

/*
 * A printer for JSON boolean types: print "true" or "false"
 */
template <typename C>
std::ostream &
operator << (std::ostream &os, const JSON<bool, C> &json)
   { return os << (json.object ? "true" : "false"); }

// String-like things.
template <typename T> concept Stringish = std::convertible_to<const T, std::string_view>;

template <Stringish T>
struct Escape {
    const T &value;
    explicit Escape(const T &value_) : value(value_) { }
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
   Field(Field<K, V> &&) = delete;
   Field &operator = (const Field &) = delete;
   Field &operator = (Field &&) = delete;
   ~Field() = default;
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
template <typename T> struct IsPair : std::false_type { };
template <typename T1, typename T2> struct IsPair<std::pair<T1, T2>> : std::true_type { };

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

// If you have a container that just happens to be a container of pairs where
// the first thing is a string, then wrap it in this ...
template <NonStringRange T> struct NotAsObject { const T &t; };

// ... and it will print as a list always.
template <typename Container, typename Context>
std::ostream &
operator << (std::ostream &os, const JSON<NotAsObject<Container>, Context> &container) {
    print_list_container(os, container.object.t, container.context);
    return os;
}

// Exception thrown when encoding error happens.
struct JSONEncodingError : public std::exception {
   std::string msg;
   [[nodiscard]] const char *what() const noexcept override { return msg.c_str(); }
   explicit JSONEncodingError(std::string &&rhs) : msg(std::move(rhs)) {}
};

// Escape a string, and print it out.
template <typename T>
inline std::ostream & operator << (std::ostream &o, const Escape<T> &escape)
{
    auto flags(o.flags());
    std::string_view view{ escape.value };
    for (auto i = view.begin(); i != view.end();) {
        int c = (unsigned char)*i++;
        switch (c) {
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

// std::filesystem::path's don't implicitly convert to strings, but its useful
// to be able to jsonify them as if they do.
template <typename C>
std::ostream &
operator << (std::ostream &os, const JSON<std::filesystem::path, C> &json) {
   std::string pathStr = json.object;
   return os << "\"" << Escape(pathStr) << "\"";
}

/* Helper for rendering JSON objects */
class JObject {
   std::ostream &os;
   const char *sep{""};
   public:
      explicit JObject(std::ostream &os_) : os{os_} { os << "{ "; }
      ~JObject() { os << " }"; }
      JObject(const JObject &) = delete;
      JObject(JObject &&) = delete;
      auto operator = (const JObject &) = delete;
      auto operator = (JObject &&) = delete;

      template <typename K, typename V, typename C> JObject &field(const K &k, const V&v, const C &c) {
         Field<K, V> field(k, v);
         os << sep << json(field, c);
         sep = ", ";
         return *this;
      }

      template <typename K, typename V> JObject &field(const K &k, const V&v) {
         return field(k, v, char(0));
      }

      // implicit conversion to an std::ostream allows this to be returned from
      // an operator<< output streaming function
      operator std::ostream &() { return os; }
};

class JArray {
    std::ostream &os;
    const char *sep{""};
public:
    explicit JArray(std::ostream &os_) : os{os_} { os << "[ "; }

    template <typename V, typename C> JArray &element(const V&v, const C &c) {
        os << sep << json(v, c);
        sep = ", ";
        return *this;
    }

    template <typename V> JArray &element(const V&v) {
        return element(v, char(0));
    }

    ~JArray() { os << " ]"; }
};

/*
 * Fallback printer for pairs - just print them as "first" and "second"
 */
template <typename F, typename S, typename C>
std::ostream &
operator << (std::ostream &os, const JSON<std::pair<F, S>, C> &json) {
   return JObject(os)
       .field("first", json.object.first, json.context)
       .field("second", json.object.second, json.context);
}

// Our null type.
class JsonNull {};

template <typename C>
std::ostream &
operator << (std::ostream &os, [[maybe_unused]] const JSON<JsonNull, C> &null) {
   return os << "null";
}

template <typename T, typename C>
std::ostream &
operator << (std::ostream &os, [[maybe_unused]] const JSON<std::optional<T>, C> &optional) {
   if (optional.object) {
      return os << json(*optional.object, optional.context);
   }
   return os << json(JsonNull{}, optional.context);
}


// Rudimentary JSON parse.
//
class InvalidJSON : public std::exception {
    std::string err;
public:
    const char *what() const throw() { return err.c_str(); }
    InvalidJSON(const std::string &err_) throw() : err(err_) {}
    ~InvalidJSON() throw() {};
};

enum Type { Array, Boolean, Null, Number, Object, String, Eof, JSONTypeCount };

static inline int
skipSpace(std::istream &l)
{
    while (!l.eof() && isspace(l.peek()))
        l.ignore();
    return l.eof() ? -1 : l.peek();
}

static inline char
expectAfterSpace(std::istream &l, char expected)
{
    char c = skipSpace(l);
    if (c != expected)
        throw InvalidJSON(std::string("expected '") + expected + "', got '" + c + "'");
    l.ignore();
    return c;
}

static inline void
skipText(std::istream &l, const char *text)
{
    for (size_t i = 0; text[i]; ++i) {
        char c;
        l.get(c);
        if (c != text[i])
            throw InvalidJSON(std::string("expected '") + text +  "'");
    }
}

static inline Type
peekType(std::istream &l)
{
    char c = skipSpace(l);
    switch (c) {
        case '{': return Object;
        case '[': return Array;
        case '"': return String;
        case '-': return Number;
        case 't' : case 'f': return Boolean;
        case 'n' : return Null;
        case -1: return Eof;
        default: {
            if (c >= '0' && c <= '9')
                return Number;
            throw InvalidJSON(std::string("unexpected token '") + char(c) + "' at start of JSON object");
        }
    }
}

template <typename Context> void parseObject(std::istream &l, Context &&ctx);
template <typename Context> void parseArray(std::istream &l, Context &&ctx);

template <typename I> I
parseInt(std::istream &l)
{
    int sign;
    char c;
    if (skipSpace(l) == '-') {
        sign = -1;
        l.ignore();
    } else {
        sign = 1;
    }
    I rv = 0;
    if (l.peek() == '0') {
        l.ignore(); // leading zero.
    } else if (isdigit(l.peek())) {
        while (isdigit(c = l.peek())) {
            rv = rv * 10 + c - '0';
            l.ignore();
        }
    } else {
        throw InvalidJSON("expected digit");
    }
    return rv * sign;
}

/*
 * Note that you can use parseInt instead when you know the value will be
 * integral.
 */

template <typename FloatType> static inline FloatType
parseFloat(std::istream &l)
{
    FloatType rv = parseInt<FloatType>(l);
    if (l.peek() == '.') {
        l.ignore();
        FloatType scale = rv < 0 ? -1 : 1;
        char c;
        while (isdigit(c = l.peek())) {
            l.ignore();
            scale /= 10;
            rv = rv + scale * (c - '0');
        }
    }
    if (l.peek() == 'e' || l.peek() == 'E') {
        l.ignore();
        int sign;
        char c = l.peek();
        if (c == '+' || c == '-') {
            sign = c == '+' ? 1 : -1;
            l.ignore();
            c = l.peek();
        } else if (isdigit(c)) {
            sign = 1;
        } else {
            throw InvalidJSON("expected sign or numeric after exponent");
        }
        auto exponent = sign * parseInt<int>(l);
        rv *= std::pow(10.0, exponent);
    }
    return rv;
}

template <typename Integer> inline Integer parseNumber(std::istream &i) { return parseInt<long double>(i); }
template <> inline double parseNumber<double> (std::istream &i) { return parseFloat<double>(i); }
template <> inline float parseNumber<float> (std::istream &i) { return parseFloat<float>(i); }
template <> inline long double parseNumber<long double> (std::istream &i) { return parseFloat<long double>(i); }

static inline int hexval(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    throw InvalidJSON(std::string("not a hex char: ") + c);
}

struct UTF8 {
    unsigned long code;
    UTF8(unsigned long code_) : code(code_) {}
};

inline std::ostream &
operator<<(std::ostream &os, const UTF8 &utf)
{
    if ((utf.code & 0x7f) == utf.code) {
        os.put(char(utf.code));
        return os;
    }
    uint8_t prefixBits = 0x80; // start with 100xxxxx
    int byteCount = 0; // one less than entire bytecount of encoding.
    unsigned long value = utf.code;

    for (size_t mask = 0x7ff;; mask = mask << 5 | 0x1f) {
        prefixBits = prefixBits >> 1 | 0x80;
        byteCount++;
        if ((value & mask) == value)
            break;
    }
    os << char(value >> 6 * byteCount | prefixBits);
    while (byteCount--)
        os.put(char((value >> 6 * byteCount  & ~0xc0) | 0x80));
    return os;
}

static std::string
parseString(std::istream &l)
{
    expectAfterSpace(l, '"');
    std::ostringstream rv;
    for (;;) {
        char c;
        l.get(c);
        switch (c) {
            case '"':
                return rv.str();
            case '\\':
                l.get(c);
                switch (c) {
                    case '"':
                    case '\\':
                    case '/':
                        rv << c;
                        break;
                    case 'b':
                        rv << '\b';
                        break;
                    case 'f':
                        rv << '\f';
                        break;
                    case 'n':
                        rv << '\n';
                        break;
                    case 'r':
                        rv << '\r';
                        break;
                    case 't':
                        rv << '\t';
                        break;
                    default:
                        throw InvalidJSON(std::string("invalid quoted char '") + c + "'");
                    case 'u': {
                        // get unicode char.
                        int codePoint = 0;
                        for (size_t i = 0; i < 4; ++i) {
                            l.get(c);
                            codePoint = codePoint * 16 + hexval(c);
                        }
                        rv << UTF8(codePoint);
                    }
                    break;
                }
                break;
            default:
                rv << c;
                break;
        }
    }
}

static inline bool
parseBoolean(std::istream &l)
{
    char c = skipSpace(l);
    switch (c) {
        case 't': skipText(l, "true"); return true;
        case 'f': skipText(l, "false"); return false;
        default: throw InvalidJSON("expected 'true' or 'false'");
    }
}

static inline void
parseNull(std::istream &l)
{
    skipSpace(l);
    skipText(l, "null");
}

static inline void // Parse any value but discard the result.
parseValue(std::istream &l)
{
    switch (peekType(l)) {
        case Array: parseArray(l, parseValue); break;
        case Boolean: parseBoolean(l); break;
        case Null: parseNull(l); break;
        case Number: parseNumber<float>(l); break;
        case Object: parseObject(l, [](std::istream &l, std::string) -> void { parseValue(l); }); break;
        case String: parseString(l); break;
        default: throw InvalidJSON("unknown type for JSON construct");
    }
}

template <typename Context> void
parseObject(std::istream &l, Context &&ctx)
{
    expectAfterSpace(l, '{');
    for (;;) {
        std::string fieldName;
        char c;
        switch (c = skipSpace(l)) {
            case '"': // Name of next field.
                fieldName = parseString(l);
                expectAfterSpace(l, ':');
                ctx(l, fieldName);
                break;
            case '}': // End of this object
                l.ignore();
                return;
            case ',': // Separator to next field
                l.ignore();
                break;
            default: {
                throw InvalidJSON(std::string("unexpected character '") + char(c) + "' parsing object");
            }
        }
    }
}

template <typename Context> void
parseArray(std::istream &l, Context &&ctx)
{
    expectAfterSpace(l, '[');
    char c;
    if ((c = skipSpace(l)) == ']') {
        l.ignore();
        return; // empty array
    }
    for (;;) {
        skipSpace(l);
        ctx(l);
        c = skipSpace(l);
        switch (c) {
            case ']':
                l.ignore();
                return;
            case ',':
                l.ignore();
                break;
            default:
                throw InvalidJSON(std::string("expected ']' or ',', got '") + c + "'");
        }
    }
}

template <typename numtype, typename ... Args> inline void
skip(std::istream &i, [[maybe_unused]] Args... args)
{
    switch (peekType(i)) {
        case Array: parseArray(i, skip<numtype>); return;
        case Object: parseObject(i, skip<numtype, std::string_view>); return;
        case String: parseString(i); return;
        case Number: parseNumber<numtype>(i); return;
        case Boolean: parseBoolean(i); return;
        case Null: parseNull(i); return;

        case Eof:
        default:
            abort();
    }
}

template <typename Parsee> inline void parse(std::istream &is, Parsee &);
template <> inline void parse<int>(std::istream &is, int &parsee) { parsee = parseInt<int>(is); }
template <> inline void parse<long>(std::istream &is, long &parsee) { parsee = parseInt<long>(is); }
template <> inline void parse<float>(std::istream &is, float &parsee) { parsee = parseFloat<float>(is); }
template <> inline void parse<double>(std::istream &is, double &parsee) { parsee = parseFloat<double>(is); }
template <> inline void parse<std::string>(std::istream &is, std::string &parsee) { parsee = parseString(is); }
template <> inline void parse<bool>(std::istream &is, bool &parsee) { parsee = parseBoolean(is); }

}

#endif
