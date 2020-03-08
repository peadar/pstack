#include <stdlib.h>
namespace Foo {
    class Bar {
        public:
            void baz() {
                abort();
            }
    };
}

int
main()
{
    Foo::Bar bar;
    bar.baz();
    return 0;
}
