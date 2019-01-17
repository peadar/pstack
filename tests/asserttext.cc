#include <assert.h>

extern "C" {

int thisFunctionWontReturn()
{
    assert(1 + 1 == 3); // this must be on line 5.
    static_assert(__LINE__ == 7 + 1,
            "test needs the assert above to be on line 7: change test or code");
    return 0;
}

int
main()
{
    thisFunctionWontReturn();
}

}
