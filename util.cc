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

off_t
FileReader::size() const
{
    struct stat buf;
    int rc = fstat(file, &buf);
    if (rc == -1)
        throw Exception() << "fstat failed: can't find size of file: " << strerror(errno);
    return buf.st_size;
}

void testme()
{
    std::cout << "cout\n";
    std::clog << "clog\n";
    std::cerr << "cerr\n";
}
