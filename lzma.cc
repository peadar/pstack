#include "libpstack/lzmareader.h"
#include "libpstack/util.h"

#include <lzma.h>

static auto allocator() {
   static lzma_allocator alloc {
      [] ( void * /* unused */, size_t m, size_t s ) noexcept { return malloc(m * s); },
      [] ( void * /* unused */, void *p ) noexcept { free(p); },
      nullptr
   };
   return &alloc;
};

LzmaReader::LzmaReader(Reader::csptr upstream_)
    : index{}
    , upstream{std::move(upstream_)}
{
   lzma_stream_flags options{};

   // read the last LZMA_STREAM_HEADER_SIZE bytes into footer.
   uint8_t footer[LZMA_STREAM_HEADER_SIZE];
   size_t off = upstream->size() - sizeof footer;
   upstream->readObj(off, footer, sizeof footer);

   auto rc = lzma_stream_footer_decode(&options, footer);
   if (rc != LZMA_OK)
       throw (Exception() << "LZMA error reading footer: " << rc);
   off -= options.backward_size;
   uint8_t indexBuffer[options.backward_size];
   upstream->readObj(off, indexBuffer, options.backward_size);
   rc = lzma_index_buffer_decode(&index, &memlimit, allocator(), indexBuffer, &pos, options.backward_size);
   if (rc != LZMA_OK)
       throw (Exception() << "can't decode index buffer");
   if (verbose >= 2)
      *debug << "lzma inflate: " << *this << "\n";
}

off_t
LzmaReader::size() const
{
    return lzma_index_uncompressed_size(index);
}

size_t
LzmaReader::read(off_t offset, size_t size, char *data) const
{
    size_t startSize = size;
    while (size != 0) {
        lzma_index_iter iter{};
        lzma_index_iter_init(&iter, index);
        if (bool(lzma_index_iter_locate(&iter, offset)))
            throw (Exception() << "can't locate offset " << offset << " in index");
        auto &uncompressed = lzBlocks[iter.block.uncompressed_stream_offset];
        if (uncompressed.empty()) {
            std::vector<unsigned char>compressed(iter.block.total_size);
            upstream->readObj(iter.block.compressed_file_offset, &compressed[0], compressed.size());
            lzma_block block{};
            lzma_filter filters[LZMA_FILTERS_MAX + 1];
            block.filters = filters;
            block.header_size = lzma_block_header_size_decode(compressed[0]);
            int rc = lzma_block_header_decode(&block, allocator(), &compressed[0]);
            if (rc != LZMA_OK)
                throw (Exception() << "can't decode block header: " << rc);
            uncompressed.resize(iter.block.uncompressed_size);
            size_t compressed_pos = block.header_size;
            size_t uncompressed_pos = 0;
            rc = lzma_block_buffer_decode(&block, allocator(),
                    &compressed[0], &compressed_pos, compressed.size(),
                    &uncompressed[0], &uncompressed_pos, uncompressed.size());
            for (auto i = 0;  block.filters[i].id != LZMA_VLI_UNKNOWN; ++i)
                allocator()->free(allocator(), block.filters[i].options);
            if ( rc != LZMA_OK)
                throw (Exception() << "can't decode block buffer: " << rc);
        }
        size_t blockOff = offset - iter.block.uncompressed_stream_offset;
        auto amount = std::min(uncompressed.size() - blockOff, size);
        memcpy(data, &uncompressed[blockOff], amount);
        size -= amount;
        offset += amount;
        data += amount;
    }
    return startSize - size;
}

void
LzmaReader::describe(std::ostream &os) const
{
    os << "lzma compressed " << *upstream;
}

LzmaReader::~LzmaReader()
{
    lzma_index_end(index, allocator());
}
