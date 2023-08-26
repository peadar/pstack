#ifndef LIBPSTACK_UTIL_H
#define LIBPSTACK_UTIL_H

#include <vector>
#include <fcntl.h>
#include <memory>
#include <string>
#include <string.h>

namespace pstack {
std::string dirname(const std::string &);
std::string basename(const std::string &);
std::string linkResolve(std::string name);
int openfile(const std::string &filename, int mode = O_RDONLY, int umask = 0777);

extern std::vector<std::pair<std::string, std::string>> pathReplacements;
}
#endif // LIBPSTACK_UTIL_H
