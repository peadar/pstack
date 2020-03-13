#include <stdlib.h>
#include <iostream>

extern "C" {

int aFunctionWithArgs(const char *msg, int value)
{
    std::cout <<"got " << msg << value << std::endl;
    abort();
}

int
main()
{
    aFunctionWithArgs("tweet", 42);
}

}
