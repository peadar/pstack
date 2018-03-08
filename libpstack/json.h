#ifndef _JSON_H_
#define _JSON_H_
#include <iostream>
#include <functional>
#include <unordered_map>
#include <type_traits>
#include <cstdint>
#include <cstdlib>
#include <typeinfo>
#include <map>

template <typename T, typename C = char> class JSON {
public:
   const T& object;
   const C context;
   JSON(const T &object_, const C context_ = C()) : object(object_), context(context_) {}
   const T *operator -> () const { return &object; }
   JSON() = delete;
};

template <typename K, typename V>
struct Field {
   const K &k;
   const V &v;
   Field(const K &k_, const V &v_) : k(k_), v(v_) {}
   Field() = delete;
   Field(const Field<K, V> &) = delete;
};

template <template <typename, typename> class M, class K, class V, class C> std::ostream &
operator << (std::ostream &os, JSON<const M<K, V>, C> &json);

template <typename T, typename C>
typename std::enable_if<std::is_integral<T>::value, std::ostream>::type &
operator << (std::ostream &os, const JSON<T, C>&json) { return os << json.object; }

template <typename C>
std::ostream &
operator << (std::ostream &os, const JSON<bool, C> &json)
   { return os << (json.object ? "true" : "false"); }

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
   return os << "]";
}

template <typename K, typename V, typename C>
std::ostream &
operator << (std::ostream &os, const JSON<Field<K,V>, C> &o)
{
   return os << json(o.object.k) << ":" << json(o.object.v, o.context);
}

/*
 * Real arrays can be printed as a JSON array.
 */
template <template <typename...> class Container, typename C, typename ...Args, typename = typename Container<Args...>::value_type>
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
 * Iterable objects can be printed as an array.
 */
template <typename Container, typename C, typename = typename Container::value_type>
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
 * Print any container with a mapped type as a JSON object.
 */
template <template <typename...> class Container,
         typename Context,
         typename K,
         typename V,
         typename ...Args,
         typename = typename Container<K, V, Args...>::mapped_type>
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

template <typename F, typename S, typename C>
std::ostream &
operator << (std::ostream &os, const JSON<std::pair<F, S>, C> &json) {
   return JObject(os)
       .field("first", json.object.first)
       .field("second", json.object.second);
}
#endif
