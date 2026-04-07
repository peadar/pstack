#include "libpstack/lzmareader.h"

#include <dlfcn.h>
#include <lzma.h>
#include <string.h>

namespace {

struct Lzma {
    lzma_ret    (*stream_footer_decode)(lzma_stream_flags *, const uint8_t *);
    lzma_ret    (*index_buffer_decode)(lzma_index **, uint64_t *, const lzma_allocator *,
                    const uint8_t *, size_t *, size_t);
    uint64_t    (*index_uncompressed_size)(const lzma_index *);
    void        (*index_iter_init)(lzma_index_iter *, const lzma_index *);
    lzma_bool   (*index_iter_locate)(lzma_index_iter *, lzma_vli);
    lzma_ret    (*block_header_decode)(lzma_block *, const lzma_allocator *, const uint8_t *);
    lzma_ret    (*block_buffer_decode)(lzma_block *, const lzma_allocator *,
                    const uint8_t *, size_t *, size_t, uint8_t *, size_t *, size_t);
    void        (*index_end)(lzma_index *, const lzma_allocator *);
};

const Lzma *loadLzma() {
    static Lzma lzma;
    static const Lzma *result = [] () -> const Lzma * {
        void *handle = dlopen("liblzma.so.5", RTLD_LAZY | RTLD_GLOBAL);
        if (!handle)
            return nullptr;
#define LOAD(name) lzma.name = reinterpret_cast<decltype(lzma.name)>(dlsym(handle, "lzma_" #name))
        LOAD(stream_footer_decode);
        LOAD(index_buffer_decode);
        LOAD(index_uncompressed_size);
        LOAD(index_iter_init);
        LOAD(index_iter_locate);
        LOAD(block_header_decode);
        LOAD(block_buffer_decode);
        LOAD(index_end);
#undef LOAD
        if (!lzma.stream_footer_decode || !lzma.index_buffer_decode ||
                !lzma.index_uncompressed_size || !lzma.index_iter_init ||
                !lzma.index_iter_locate || !lzma.block_header_decode ||
                !lzma.block_buffer_decode || !lzma.index_end) {
            dlclose(handle);
            return nullptr;
        }
        return &lzma;
    }();
    return result;
}

} // namespace

namespace pstack {

bool lzmaAvailable() {
    return loadLzma() != nullptr;
}

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
   auto *lzma = loadLzma();
   if (!lzma)
       throw (Exception() << "lzma not available at runtime");

   lzma_stream_flags options{};

   // read the last LZMA_STREAM_HEADER_SIZE bytes into footer.
   uint8_t footer[LZMA_STREAM_HEADER_SIZE];
   size_t off = upstream->size() - sizeof footer;
   upstream->readObj(off, footer, sizeof footer);

   auto rc = lzma->stream_footer_decode(&options, footer);
   if (rc != LZMA_OK)
       throw (Exception() << "LZMA error reading footer: " << rc);
   off -= options.backward_size;
   uint8_t indexBuffer[options.backward_size];
   upstream->readObj(off, indexBuffer, options.backward_size);
   rc = lzma->index_buffer_decode(&index, &memlimit, allocator(), indexBuffer, &pos,
         options.backward_size);
   if (rc != LZMA_OK)
       throw (Exception() << "can't decode index buffer");
}

Reader::Off
LzmaReader::size() const
{
    return loadLzma()->index_uncompressed_size(index);
}

size_t
LzmaReader::read(Off offset, size_t size, char *data) const
{
    auto *lzma = loadLzma();
    size_t startSize = size;
    while (size != 0) {
        lzma_index_iter iter{};
        lzma->index_iter_init(&iter, index);
        if (bool(lzma->index_iter_locate(&iter, offset)))
            throw (Exception() << "can't locate offset " << offset << " in index");
        auto &uncompressed = lzBlocks[iter.block.uncompressed_stream_offset];
        if (uncompressed.empty()) {
            std::vector<unsigned char>compressed(iter.block.total_size);
            upstream->readObj(iter.block.compressed_file_offset, &compressed[0], compressed.size());
            lzma_block block{};
            lzma_filter filters[LZMA_FILTERS_MAX + 1];
            block.filters = filters;
            block.header_size = lzma_block_header_size_decode(compressed[0]);
            int rc = lzma->block_header_decode(&block, allocator(), &compressed[0]);
            if (rc != LZMA_OK)
                throw (Exception() << "can't decode block header: " << rc);
            uncompressed.resize(iter.block.uncompressed_size);
            size_t compressed_pos = block.header_size;
            size_t uncompressed_pos = 0;
            rc = lzma->block_buffer_decode(&block, allocator(),
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
    loadLzma()->index_end(index, allocator());
}
}
