#include "libpstack/flags.h"
#include <cassert>

namespace pstack {
Flags &
Flags::add( const char *name, int flag, const char *metavar, const char *help, Cb cb) {
    if (flag == LONGONLY)
       flag = --longVal;
    longOptions.push_back({name, metavar != nullptr ? 0 : 1, nullptr, int(flag)});
    assert(data.find(flag) == data.end());
    auto &datum = data[flag];
    datum.helptext = help;
    datum.metavar = metavar;
    datum.callback = std::move(cb);
    return *this;
}

const Flags &
Flags::done()
{
    shortOptions = "";
    for (auto &opt : longOptions) {
        if (opt.val != '\0') {
           shortOptions += char(opt.val);
           if (opt.has_arg != 0)
               shortOptions += ':';
        }
    }
    longOptions.push_back({nullptr, 0, nullptr, 0});
    return *this;
}

std::ostream &
Flags::dump(std::ostream &os) const
{
    for (const auto &opt  : longOptions) {
        if (opt.name == nullptr)
            continue;
        const auto &datum = data.at(opt.val);
        os << "    [";
        if (opt.val > 0)
           os << "-" << char(opt.val) << "|";
        os << "--" << opt.name;
        if (opt.has_arg != 0)
            os << " <" << datum.metavar << ">";
        os << "]\n        " << datum.helptext << "\n";
    }
    return os;
}

const Flags &
Flags::parse(int argc, char **argv) const
{
    for (;;) {
       int optidx = 0;
       int c = getopt_long(argc, argv, shortOptions.c_str(), longOptions.data(), &optidx);
       if (c == -1)
          break;

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
