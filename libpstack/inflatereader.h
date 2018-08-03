#ifndef LIBPSTACK_INFLATEREADER_H
#define LIBPSTACK_INFLATEREADER_H
#include "libpstack/util.h"

// A Reader that zlib inflates the underlying downstream reader.
// Currently requires knowing the resulting output size.
class InflateReader : public MemReader {
    InflateReader(const InflateReader &) = delete;
    InflateReader() = delete;
public:
    InflateReader(size_t inflatedSize, const Reader &upstream);
    ~InflateReader();
};

#endif // LIBPSTACK_INFLATEREADER_H
