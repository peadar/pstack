#include <iostream>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "libpstack/global.h"
#include "libpstack/fs.h"
#include "libpstack/exception.h"

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

static int
openFileDirect(const std::string &name_, int mode, int mask)
{
    auto fd = open(name_.c_str(), mode, mask);
    if (verbose > 2) {
       if (fd != -1)
          *debug << "opened " << name_ << ", fd=" << fd << std::endl;
       else
          *debug << "failed to open " << name_ << ": " << strerror(errno) << std::endl;
    }
    return fd;
}

int
openfile(const std::string &name, int mode, int mask)
{
    int fd = -1;
    for (auto &r : pathReplacements) {
       if (name.compare(0, r.first.size(), r.first) == 0) {
          fd = openFileDirect(r.second + std::string(name, r.first.size()), mode, mask);
          if (fd != -1)
             return fd;
       }
    }
    fd = openFileDirect(name, mode, mask);
    if (fd != -1)
       return fd;
    throw (Exception() << "cannot open file '" << name << "': " << strerror(errno));
}


