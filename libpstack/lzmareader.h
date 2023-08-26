#ifndef LIBPSTACK_LZMAREADER_H
#define LIBPSTACK_LZMAREADER_H

#include <map>
#include <vector>
#include <lzma.h>
#include "libpstack/reader.h"

namespace pstack {
/*
 * Provides an LZMA-decoded view of downstream. LZMA API allows random-access
 * to the data, and we cache each decompressed block as we decode it.
 */
class LzmaReader : public Reader {
    LzmaReader(const LzmaReader &) = delete;
    LzmaReader() = delete;
    lzma_index *index;
    uint64_t memlimit = std::numeric_limits<uint64_t>::max();
    size_t pos = 0;
    Reader::csptr upstream;
    mutable std::map<Off, std::vector<unsigned char>> lzBlocks;
public:
    LzmaReader(Reader::csptr upstream_);
    ~LzmaReader();
    size_t read(Off, size_t, char *) const override;
    void describe(std::ostream &) const override;
    Off size() const override;
    std::string filename() const override { return upstream->filename(); }
};
}

#endif
