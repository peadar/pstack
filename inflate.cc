#include "libpstack/inflatereader.h"
#include "libpstack/stringify.h"

#include <dlfcn.h>
#include <zlib.h>

namespace {

struct Zlib {
    int  (*inflateInit2_)(z_streamp, int, const char *, int);
    int  (*inflate)(z_streamp, int);
    int  (*inflateEnd)(z_streamp);
};

const Zlib *loadZlib() {
    static Zlib zlib;
    static const Zlib *result = [] () -> const Zlib * {
        void *handle = dlopen("libz.so.1", RTLD_LAZY | RTLD_GLOBAL);
        if (!handle)
            return nullptr;
        zlib.inflateInit2_ = reinterpret_cast<decltype(zlib.inflateInit2_)>(dlsym(handle, "inflateInit2_"));
        zlib.inflate       = reinterpret_cast<decltype(zlib.inflate)>      (dlsym(handle, "inflate"));
        zlib.inflateEnd    = reinterpret_cast<decltype(zlib.inflateEnd)>   (dlsym(handle, "inflateEnd"));
        if (!zlib.inflateInit2_ || !zlib.inflate || !zlib.inflateEnd) {
            dlclose(handle);
            return nullptr;
        }
        return &zlib;
    }();
    return result;
}

} // namespace

namespace pstack {

bool zlibAvailable() {
    return loadZlib() != nullptr;
}

InflateReader::InflateReader(size_t inflatedSize, const Reader &upstream)
    : AbstractMemReader(std::string("inflated content from ") + stringify(upstream))
    , data_(inflatedSize)
{
    auto *zlib = loadZlib();
    if (!zlib)
        throw (Exception() << "zlib not available at runtime");

    char xferbuf[32768];
    z_stream stream{};

    int window = 15;
    if (zlib->inflateInit2_(&stream, window, ZLIB_VERSION, (int)sizeof stream) != Z_OK)
        throw (Exception() << "inflateInit2 failed");

    stream.avail_out = inflatedSize;
    stream.next_out  = reinterpret_cast<Bytef *>(data_.data());
    bool eof = false;
    size_t inputOffset = 0;
    for (bool done = false; !done; ) {
        if (stream.avail_in == 0 && !eof) {
            stream.avail_in = upstream.read(inputOffset, sizeof xferbuf, xferbuf);
            inputOffset += stream.avail_in;
            stream.next_in = reinterpret_cast<Bytef *>(xferbuf);
            if (stream.avail_in == 0)
                eof = true;
        }
        switch (zlib->inflate(&stream, eof ? Z_FINISH : Z_SYNC_FLUSH)) {
            case Z_STREAM_END:
                done = true;
                [[fallthrough]];
            case Z_OK:
                break;
            default:
                throw (Exception() << "inflate failed");
        }
    }
    zlib->inflateEnd(&stream);
}

} // namespace pstack
