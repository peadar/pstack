#include <libpstack/util.h>
#include <iostream>
#include <sys/stat.h>
std::string
dirname(const std::string &in)
{
    auto it = in.rfind('/');
    if (it == std::string::npos)
        return ".";
    return in.substr(0, it);
}
