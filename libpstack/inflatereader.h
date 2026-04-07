#ifndef LIBPSTACK_INFLATEREADER_H
#define LIBPSTACK_INFLATEREADER_H
#include "libpstack/reader.h"

namespace pstack {

bool zlibAvailable();

// A Reader that zlib inflates the underlying downstream reader.
// Currently requires knowing the resulting output size.
class InflateReader : public AbstractMemReader {
    std::vector<char> data_;
    InflateReader(const InflateReader &) = delete;
    InflateReader() = delete;
public:
    Off size() const override { return data_.size(); }
    const char *data() const override { return data_.data(); }
    InflateReader(size_t inflatedSize, const Reader &upstream);
};
}

#endif // LIBPSTACK_INFLATEREADER_H
