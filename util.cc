#include "util.h"
std::string
dirname(std::string in)
{
    auto it = in.rfind('/');
    if (it == std::string::npos)
        return ".";
    return in.substr(0, it);

}
