#include "libpstack/lzmareader.h"
#include "libpstack/util.h"

#include <lzma.h>

static lzma_allocator allocator = {
   [] ( void *, size_t m, size_t s ) noexcept { return malloc(m * s); },
   [] ( void *, void *p ) noexcept { free(p); },
   nullptr
};

LzmaReader::LzmaReader(std::shared_ptr<const Reader> upstream_)
    : upstream(std::move(upstream_))
{
   lzma_stream_flags options;
   uint8_t footer[LZMA_STREAM_HEADER_SIZE];
   size_t off = upstream->size() - sizeof footer;
   upstream->read(off, sizeof footer, (char *)footer);

   auto rc = lzma_stream_footer_decode(&options, footer);
   if (rc != LZMA_OK)
       throw (Exception() << "LZMA error reading footer: " << rc);
   off -= options.backward_size;
   char indexBuffer[options.backward_size];
   if (upstream->read(off, options.backward_size, indexBuffer) != options.backward_size)
       throw (Exception() << "can't read index buffer");
   rc = lzma_index_buffer_decode(&index, &memlimit, &allocator, (uint8_t *)indexBuffer,
           &pos, options.backward_size);
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
        lzma_index_iter iter;
        lzma_index_iter_init(&iter, index);
        if (bool(lzma_index_iter_locate(&iter, offset)))
            throw (Exception() << "can't locate offset " << offset << " in index");
        auto &uncompressed = lzBlocks[iter.block.uncompressed_stream_offset];
        if (uncompressed.empty()) {
            std::vector<unsigned char>compressed(iter.block.total_size);
            upstream->read(iter.block.compressed_file_offset, compressed.size(),
                    (char *)&compressed[0]);
            lzma_block block;
            lzma_filter filters[LZMA_FILTERS_MAX + 1];
            memset(&block, 0, sizeof block);
            block.filters = filters;
            block.header_size = lzma_block_header_size_decode(compressed[0]);
            int rc = lzma_block_header_decode(&block, &allocator, &compressed[0]);
            if (rc != LZMA_OK)
                throw (Exception() << "can't decode block header: " << rc);
            uncompressed.resize(iter.block.uncompressed_size);
            size_t compressed_pos = block.header_size;
            size_t uncompressed_pos = 0;
            rc = lzma_block_buffer_decode(&block, &allocator,
                    &compressed[0], &compressed_pos, compressed.size(),
                    &uncompressed[0], &uncompressed_pos, uncompressed.size());
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
    lzma_index_end(index, &allocator);
}
