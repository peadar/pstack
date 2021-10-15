#include <getopt.h>
#include <iostream>
#include <type_traits>
#include <vector>
#include <functional>
#include <map>
#include <cassert>
#include <unistd.h>

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

    // String for short-form options, calculated from longOptions and data.
    std::string shortOptions;

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
    Flags & add(const char *name, char flag, const char *metavar, const char *help, Cb cb) {
        longOptions.push_back({name, metavar != nullptr, nullptr, int(flag)});
        assert(data.find(flag) == data.end());
        auto &datum = data[flag];
        datum.helptext = help;
        datum.metavar = metavar;
        datum.callback = cb;
        return *this;
    }

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
    const Flags & done() {
        shortOptions = "";
        for (auto &opt : longOptions) {
            shortOptions += char(opt.val);
            if (opt.has_arg)
                shortOptions += ':';
        }
        longOptions.push_back({0, false, nullptr, 0});
        return *this;
    }

    /**
     * Dump information about invocation to passed stream
     */
    std::ostream & dump(std::ostream &os) const {
        for (size_t i = 0; i < longOptions.size(); ++i) {
            const auto &opt = longOptions[i];
            if (opt.name == 0)
                continue;
            const auto &datum = data.at(opt.val);
            os << "    [-" << char(opt.val) << "|--" << opt.name;
            if (opt.has_arg)
                os << " <" << datum.metavar << ">";
            os << "]\n        " << datum.helptext << "\n";
        }
        return os;
    }

    // Allow move- but not copy-construction.
    Flags(Flags &&rhs) = default;
    Flags(const Flags &rhs) = delete;
    Flags() = default;

    // parse argc/argv, calling the correct callbacks.
    const Flags & parse(int argc, char **argv) const {
        int c, optidx;
        while ((c = getopt_long(argc, argv, shortOptions.c_str(), &longOptions[0], &optidx)) != -1)
            data.at(c).callback(optarg);
        return *this;
    }

    const Flags & parse(int argc, char **argv) {
        done();
        const Flags &f = *this;
        return f.parse(argc, argv);
    }

    template <typename T> static VCb
    setf(T &val, T to=true) { return [&val, to] () { val = to; }; }

    template <typename T> void
    convert(const char *opt, T& val) { opt = val; }

    template <typename T> static typename std::enable_if<std::is_integral<T>::value, T>::type
    convert(const char *opt) { return strtol(opt, 0, 0); }

    template <typename T> static typename std::enable_if<std::is_floating_point<T>::value, T>::type
    convert(const char *opt) { return strtod(opt, 0); }

    template <typename T> static Cb
    set(T &val) { return [&val] (const char *opt) { val = convert<T>(opt); }; }

    template <typename T, typename C> static Cb
    append(C &val) { return [&val] (const char *opt) { val.push_back(convert<T>(opt)); }; }
};

inline std::ostream & operator << (std::ostream &os, const Flags &opts) { return opts.dump(os); }
