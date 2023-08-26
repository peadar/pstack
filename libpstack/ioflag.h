#include <iostream>

namespace pstack {
// Save iostream formatting so we can restore them later.
class IOFlagSave {
    std::ios &target;
    std::ios saved;
public:
    IOFlagSave(std::ios &os)
        : target(os)
         , saved(0)
    {
        saved.copyfmt(target);
    }
    ~IOFlagSave() {
        target.copyfmt(saved);
    }
};
}
