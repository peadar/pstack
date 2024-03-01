#include "libpstack/flags.h"
#include <cassert>

namespace pstack {
Flags &
Flags::add(const char *name, char flag, const char *metavar, const char *help, Cb cb)
{
    longOptions.push_back({name, metavar != nullptr, nullptr, int(flag)});
    assert(data.find(flag) == data.end());
    auto &datum = data[flag];
    datum.helptext = help;
    datum.metavar = metavar;
    datum.callback = cb;
    return *this;
}

const Flags &
Flags::done()
{
    shortOptions = "";
    for (auto &opt : longOptions) {
        shortOptions += char(opt.val);
        if (opt.has_arg)
            shortOptions += ':';
    }
    longOptions.push_back({0, false, nullptr, 0});
    return *this;
}

std::ostream &
Flags::dump(std::ostream &os) const
{
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

const Flags &
Flags::parse(int argc, char **argv) const
{
    int c, optidx;
    while ((c = getopt_long(argc, argv, shortOptions.c_str(), &longOptions[0], &optidx)) != -1) {
        if (c == '?') {
           dump(std::clog);
           throw std::runtime_error(std::string("unknown command line option "));
        }
        data.at(c).callback(optarg);
    }
    return *this;
}

const Flags &
Flags::parse(int argc, char **argv)
{
    done();
    const Flags &f = *this;
    return f.parse(argc, argv);
}
}
