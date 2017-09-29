#include <libpstack/util.h>
#include <stdint.h>
#include <unistd.h>
#include <iostream>
#include <fcntl.h>
#include <assert.h>
#include <zlib.h>
#include <lzma.h>

using std::string;

string
linkResolve(string name)
{
    char buf[1024];
    int rc;
    for (;;) {
        rc = readlink(name.c_str(), buf, sizeof buf - 1);
        if (rc == -1)
            break;
        buf[rc] = 0;
        if (buf[0] != '/') {
            auto lastSlash = name.rfind('/');
            name = lastSlash == string::npos ? string(buf) : name.substr(0, lastSlash + 1) + string(buf);
        } else {
            name = buf;
        }
    }
    return name;
}

bool
FileReader::openfile(int &file, std::string name_)
{
    auto fd = open(name_.c_str(), O_RDONLY);
    if (fd != -1) {
        file = fd;
        name = name_;
        return true;
    }
    return false;
}

FileReader::FileReader(string name_, int file_)
    : name(name_)
    , file(file_)
{
    if (file == -1 && !openfile(file, name_))
        throw Exception() << "cannot open file '" << name_ << "': " << strerror(errno);
}

MemReader::MemReader(size_t len_, char *data_)
    : len(len_)
    , data(data_)
{
}

size_t
MemReader::read(off_t off, size_t count, char *ptr) const
{
    if (off > off_t(len))
        throw Exception() << "read past end of memory";
    size_t rc = std::min(count, len - size_t(off));
    memcpy(ptr, data + off, rc);
    return rc;
}

string
MemReader::describe() const
{
    return "from memory image";
}

string
Reader:: readString(off_t offset) const
{
    char c;
    string res;
    for (;;) {
        read(offset++, 1, &c);
        if (c == 0)
            break;
        res += c;
    }
    return res;
}

size_t
FileReader::read(off_t off, size_t count, char *ptr) const
{
    auto rc = pread(file, ptr, count, off);
    if (rc == -1)
        throw Exception()
            << "read " << count
            << " at " << off
            << " on " << describe()
            << " failed: " << strerror(errno);
    return rc;
}

CacheReader::Page::Page(Reader &r, off_t offset_)
    : offset(offset_)
{
    try {
        len = r.read(offset_, PAGESIZE, data);
    }
    catch (std::exception &ex) {
        len = 0;
    }
    assert(offset_ % PAGESIZE == 0);
}

CacheReader::CacheReader(std::shared_ptr<Reader> upstream_)
    : upstream(upstream_)
{
}

CacheReader::~CacheReader()
{
    for (auto i = pages.begin(); i != pages.end(); ++i)
        delete *i;
}

CacheReader::Page *
CacheReader::getPage(off_t pageoff) const
{
    Page *p;
    int first = true;
    for (auto i = pages.begin(); i != pages.end(); ++i) {
        p = *i;
        if (p->offset == pageoff) {
            // move page to front.
            if (!first) {
                pages.erase(i);
                pages.push_front(p);
            }
            return p;
        }
        first = false;
    }
    p = new Page(*upstream, pageoff);
    if (pages.size() == MAXPAGES) {
        delete pages.back();
        pages.pop_back();
    }
    pages.push_front(p);
    return p;
}

size_t
CacheReader::read(off_t absoff, size_t count, char *ptr) const
{
    off_t startoff = absoff;
    for (;;) {
        if (count == 0)
            break;
        size_t offsetOfDataInPage = absoff % PAGESIZE;
        off_t offsetOfPageInFile = absoff - offsetOfDataInPage;
        Page *page = getPage(offsetOfPageInFile);
        if (page == 0)
            break;
        size_t chunk = std::min(page->len - offsetOfDataInPage, count);
        memcpy(ptr, page->data + offsetOfDataInPage, chunk);
        absoff += chunk;
        count -= chunk;
        ptr += chunk;
        if (page->len != PAGESIZE)
            break;
    }
    return absoff - startoff;
}

string
CacheReader::readString(off_t offset) const
{
    auto &entry = stringCache[offset];
    if (entry.isNew) {
        entry.value = Reader::readString(offset);
        entry.isNew = false;
    }
    return entry.value;
}

std::shared_ptr<Reader>
loadFile(const std::string &path)
{
    return std::make_shared<CacheReader>(
        std::make_shared<FileReader>(path));
}

InflateReader::InflateReader(size_t inflatedSize, std::shared_ptr<Reader> inputBuf)
    : MemReader(inflatedSize, new char[inflatedSize])
{
    char xferbuf[32768];

    z_stream stream;
    memset(&stream, 0, sizeof stream);

    int window = 15;
    if (inflateInit2(&stream, window) != Z_OK)
        throw Exception() << "inflateInit2 failed";

    stream.avail_out = inflatedSize;
    stream.next_out = (Bytef *)data;
    bool eof = false;
    size_t inputOffset = 0;
    if (verbose >= 2)
        *debug << "inflating" << inputBuf->describe() << "...";
    for (bool done = false; !done; ) {
        if (stream.avail_in == 0 && !eof) {
            // keep the input buffer full
            stream.avail_in = inputBuf->read(inputOffset, sizeof xferbuf, xferbuf);
            inputOffset += stream.avail_in;
            stream.next_in = (Bytef *)xferbuf;
            if (stream.avail_in == 0)
                eof = true;
        }
        size_t writeChunk = stream.avail_out;
        switch (inflate(&stream, eof ? Z_FINISH : Z_SYNC_FLUSH)) {
            case Z_STREAM_END:
                done = true;
                // fallthrough
            case Z_OK:
                if (verbose >= 2)
                    *debug << " [" << writeChunk - stream.avail_out << "]";

                break;
            default:
                throw Exception() << "inflate failed";
        }
    }
    if (verbose >= 2)
        *debug << " total " << inflatedSize << "\n";
}



void *allocLzma(void *, size_t members, size_t size)
{
    return calloc(members, size);
}

void freeLzma(void *, void *p)
{
    free(p);
}

static lzma_allocator allocator = { allocLzma, freeLzma, 0 };

LzmaReader::LzmaReader(std::shared_ptr<Reader> inputBuf, size_t end)
    : upstream(inputBuf)
{
   lzma_stream_flags options;
   uint8_t footer[LZMA_STREAM_HEADER_SIZE];
   size_t off = end - sizeof footer;
   inputBuf->read(off, sizeof footer, (char *)footer);

   auto rc = lzma_stream_footer_decode(&options, footer);
   if (rc != LZMA_OK)
       throw Exception() << "LZMA error reading footer: " << rc;
   off -= options.backward_size;
   char indexBuffer[options.backward_size];
   if (inputBuf->read(off, options.backward_size, indexBuffer) != options.backward_size)
       throw Exception() << "can't read index buffer";
   rc = lzma_index_buffer_decode(&index, &memlimit, &allocator, (uint8_t *)indexBuffer, &pos, options.backward_size);
   if (rc != LZMA_OK)
       throw Exception() << "can't decode index buffer";
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
    while (size) {
        lzma_index_iter iter;
        lzma_index_iter_init(&iter, index);
        if (lzma_index_iter_locate(&iter, offset))
            throw Exception() << "can't locate offset " << offset << " in index";
        auto &uncompressed = lzBlocks[iter.block.uncompressed_stream_offset];
        if (uncompressed.size() == 0) {
            std::vector<unsigned char>compressed(iter.block.total_size);
            upstream->read(iter.block.compressed_file_offset, compressed.size(), (char *)&compressed[0]);
            lzma_block block;
            lzma_filter filters[LZMA_FILTERS_MAX + 1];
            memset(&block, 0, sizeof block);
            block.filters = filters;
            block.header_size = lzma_block_header_size_decode(compressed[0]);
            int rc = lzma_block_header_decode(&block, &allocator, &compressed[0]);
            if (rc != LZMA_OK)
                throw Exception() << "can't decode block header: " << rc;

            uncompressed.resize(iter.block.uncompressed_size);
            size_t compressed_pos = block.header_size;
            size_t uncompressed_pos = 0;
            rc = lzma_block_buffer_decode(&block, &allocator,
                    &compressed[0], &compressed_pos, compressed.size(),
                    &uncompressed[0], &uncompressed_pos, uncompressed.size());
            if ( rc != LZMA_OK)
                throw Exception() << "can't decode block buffer: " << rc;
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

std::string
LzmaReader::describe() const
{
    return "lzma compressed data";
}

LzmaReader::~LzmaReader() {
}
