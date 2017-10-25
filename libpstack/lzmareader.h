#ifndef LIBPSTACK_LZMAREADER_H
#define LIBPSTACK_LZMAREADER_H

#include <map>
#include <libpstack/util.h>
#include <lzma.h>

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
    std::shared_ptr<Reader> upstream;
    mutable std::map<off_t, std::vector<unsigned char>> lzBlocks;
public:
    LzmaReader(std::shared_ptr<Reader> downstream);
    ~LzmaReader();
    size_t read(off_t, size_t, char *) const override;
    void describe(std::ostream &) const override;
    off_t size() const override;
};

#endif
