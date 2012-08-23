#include <sys/ptrace.h>
#include <string.h>
#include <errno.h>
#include <iostream>


int
main(int argc, char *argv[])
{
    int rc = ptrace(PT_ATTACH, atoi(argv[1]), 0, 0);
    std::clog << "ptrace returns " << rc << ", errno is " << strerror(errno) << std::endl;
}


