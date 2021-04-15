#include "libpstack/util.h"
#include <iostream>
#include <unistd.h>
#include <sys/stat.h>

std::string g_openPrefix;

std::string
dirname(const std::string &in)
{
    auto it = in.rfind('/');
    if (it == std::string::npos)
        return ".";
    return in.substr(0, it);
}

std::string
basename(const std::string &in)
{
    auto it = in.rfind('/');
    auto out =  it == std::string::npos ?  in : in.substr(it + 1);
    return out;
}

std::string
linkResolve(std::string name)
{
    char buf[1024];
    int rc;
    for (;;) {
        rc = readlink(name.c_str(), buf, sizeof buf - 1);
        if (rc == -1)
            break;
        buf[rc] = 0;
        if (buf[0] != '/') {
            auto lastSlash = name.rfind('/');
            name = lastSlash == std::string::npos
               ? std::string(buf)
               : name.substr(0, lastSlash + 1) + std::string(buf);
        } else {
            name = buf;
        }
    }
    return name;
}
