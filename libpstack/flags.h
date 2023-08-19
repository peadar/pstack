#include <getopt.h>
#include <string>
#include <iostream>
#include <type_traits>
#include <vector>
#include <functional>
#include <map>
#include <cassert>
#include <unistd.h>

namespace {
template <typename T> void convert(const char *opt, T &to) {
   if constexpr (std::is_integral<T>::value)
      if constexpr (std::is_signed<T>::value)
          to = T(strtoll(opt, 0, 0));
      else
          to = T(strtoull(opt, 0, 0));

   else if constexpr (std::is_floating_point<T>::value)
      to = strtod(opt, 0);
   else
      to = opt;
}
}

/*
 * A wrapper for getopt_long that correlates long and short options together,
 * and allows for a functional interface for handling options.
 * Create a Flags object, and call "add" on it repeatedly. You can chain-call
 * add invocations, and then finally invoke "parse".
 */
class Flags {
    // the long-form options. The "val" field of each is the short option name.
    std::vector<option> longOptions;

    using Cb = std::function<void(const char *)>; // callback for a flag with an argument
    using VCb = std::function<void()>; // callback for a flag without an argument.

    // Data for a specific flag - it's help text, the name for its metavar if
    // it takes an argument, a callback to invoke when it's encountered.
    struct Data {
        const char *helptext;
        const char *metavar;
        Cb callback;
    };
    std::map<char, Data> data; // per-flag data, indexed by short-form option.
    std::string shortOptions; // String for short-form options, calculated from longOptions + data.

public:
    /**
     * Add a flag to the set of parsed flags.
     * name: the long-form name
     * flag: the short-form, single character version
     * metavar: if non-null, indicates this flag takes an argument, and provides
     *          a textual description of that argument in the help output.
     * help: descriptive text describing option
     * cb: callback invoked when the argument is encountered.
     */
    Flags & add(const char *name, char flag, const char *metavar, const char *help, Cb cb);

    /**
     * Add a flag to the set of parsed flags - shorter helper for flags that
     * take no arguments.
     */
    Flags & add(const char *name, char flag, const char *help, VCb cb) {
        return add(name, flag, nullptr, help, [cb](const char *) { cb(); });
    }

    /**
     * indicate we have added all arguments, and don't intend to modify the
     * flags further.
     */
    const Flags & done();

    /**
     * Dump information about invocation to passed stream
     */
    std::ostream & dump(std::ostream &os) const;


    // Allow move- but not copy-construction.
    Flags(Flags &&rhs) = default;
    Flags(const Flags &rhs) = delete;
    Flags() = default;

    // parse argc/argv, calling the correct callbacks. (non-const version will
    // call "done" before calling const version)
    const Flags & parse(int argc, char **argv) const;
    const Flags & parse(int argc, char **argv);

    // Helper to get a VCb to just set a bool to true/false.
    template <typename T> static VCb
    setf(T &val, T to=true) { return [&val, to] () { val = to; }; }


    // Helper to set a value from a string, using convert to convert from
    // string to whatever type is required.
    template <typename T> static Cb
    set(T &val) { return [&val] (const char *opt) { convert<T>(opt, val); }; }

    // Append to a container with push_back, with a converted value.
    template <typename T, typename C> static Cb
    append(C &val) { return [&val] (const char *opt) { val.push_back(convert<T>(opt)); }; }
};

// Stream a "Flags" to stdout - printing a formatted help text for the options.
inline std::ostream & operator << (std::ostream &os, const Flags &opts) { return opts.dump(os); }
