#ifndef _JSON_H_
#define _JSON_H_
#include <iostream>
#include <unordered_map>
#include <type_traits>
#include <cstdint>
#include <cstdlib>
#include <typeinfo>
#include <map>

template <typename> struct is_pair : std::false_type { };
template <typename T, typename U> struct is_pair<std::pair<T, U>> : std::true_type { };

template <typename> struct is_not_pair : std::true_type { };
template <typename T, typename U> struct is_not_pair<std::pair<T, U>> : std::false_type { };

template <typename T, typename C = char> class JSON {
public:
   const T& object;
   const C context;
   JSON(const T &object_, const C context_ = C()) : object(object_), context(context_) {}
   JSON() = delete;
};

template <typename K, typename V>
struct Field {
   const K &k;
   const V &v;
   Field(const K &k_, const V &v_) : k(k_), v(v_) {}
};

template <typename T, size_t N, typename C> std::ostream &
operator << (std::ostream &os, const JSON<T[N], C> &json);

template <template <typename, typename> class M, class K, class V, class C> std::ostream &
operator << (std::ostream &os, JSON<const M<K, V>, C> &json);

template <typename C>
std::ostream &
operator << (std::ostream &os, const JSON<std::string, C> &json);

template <typename C>
std::ostream &
operator << (std::ostream &os, const JSON<const char *, C> &json);

template <typename T, typename C>
typename std::enable_if<std::is_integral<T>::value, std::ostream>::type &
operator << (std::ostream &os, const JSON<T, C>&json) { return os << json.object; }

template <typename C>
std::ostream &
operator << (std::ostream &os, const JSON<bool, C> &json)
   { return os << (json.object ? "true" : "false"); }

template <typename K, typename V, typename C>
std::ostream &
operator << (std::ostream &os, const JSON<Field<K,V>, C> &o);

template <typename T, typename C>
JSON<T, C>
json(const T &object, const C context);

template <typename T>
JSON<T, char>
json(const T &object) { return json(object, '.'); }

template <typename C, size_t N>
std::ostream &
operator << (std::ostream &os, const JSON<char[N], C> &json);

template <typename T, size_t N, typename C>
std::ostream &
operator << (std::ostream &os, const JSON<T[N], C> &json)
{
   os << "[";
   for (size_t i = 0; i < N; ++i) {
      os << (i ? ",\n" : "") << json.object[i];
   }
   os << "]";
   return os;
}

template <typename K, typename V, typename C>
std::ostream &
operator << (std::ostream &os, const JSON<Field<K,V>, C> &o)
{
   return os << json(o.object.k) << ":" << json(o.object.v, o.context);
}

/*
 * Anything that has an iterator can be printed as an array.
 */
template <template <typename...> class Container,
         typename C,
         typename ...Args,
         typename = typename std::enable_if<
               is_not_pair<typename Container<Args...>::value_type>::value>::type>
std::ostream &
operator << (std::ostream &os, const JSON<Container<Args...>, C> &container) {
   os << "[ ";
   const char *sep = "";
   for (const auto &field : container.object) {
      os << sep << json(field, container.context);
      sep = ",\n";
   }
   return os << " ]";
}

/*
 * Anything that has an iterator can be printed as an array.
 */
template <typename Container, typename C,
         typename = std::enable_if<is_not_pair<typename Container::value_type>::value>>
std::ostream &
operator << (std::ostream &os, const JSON<Container, C> &container) {
   os << "[ ";
   const char *sep = "";
   for (const auto &field : container.object) {
      os << sep << json(field, container.context);
      sep = ",\n";
   }
   return os << " ]";
}


template <typename C>
std::ostream &
operator << (std::ostream &os, const JSON<std::string, C> &json) {
   return os << "\"" << json.object << "\"";
}

template <typename C>
std::ostream &
operator << (std::ostream &os, const JSON<const char *, C> &json) {
   return os << "\"" << json.object << "\"";
}

template <typename C, size_t N>
std::ostream &
operator << (std::ostream &os, const JSON<char[N], C> &json) {
   return os << JSON<const char *, C>(&json.object[0], json.context);
}

template <typename T, typename C = char>
JSON<T, C>
json(const T &object, const C context) {
   return JSON<T, C>(object, context);
}
/*
 * Print any container keyed by string as a map.
 */
template <template <typename...> class Container,
         typename Context,
         typename K,
         typename V,
         typename ...Args,
         typename = typename std::enable_if<is_pair<typename Container<K, V, Args...>::value_type>::value>::type>
std::ostream &
operator << (std::ostream &os, const JSON<Container<K, V, Args...>, Context> &container) {
   os << "{";
   const char *sep = "";
   for (const auto &field : container.object) {
      Field<K,V> jfield(field.first, field.second);
      os << sep << json(jfield, container.context);
      sep = ", ";
   }
   return os << "}";
}


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

#endif
