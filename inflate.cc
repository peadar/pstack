#include "libpstack/inflatereader.h"
#include "libpstack/stringify.h"

#include <zlib.h>
namespace pstack {

InflateReader::InflateReader(size_t inflatedSize, const Reader &upstream)
    : MemReader(std::string("inflated content from ") + stringify(upstream),
          inflatedSize, new char[inflatedSize])
{
    char xferbuf[32768];

    z_stream stream{};

    int window = 15;
    if (inflateInit2(&stream, window) != Z_OK)
        throw (Exception() << "inflateInit2 failed");

    stream.avail_out = inflatedSize;
    using bytep = Bytef *;
    stream.next_out = bytep(data);
    bool eof = false;
    size_t inputOffset = 0;
    for (bool done = false; !done; ) {
        if (stream.avail_in == 0 && !eof) {
            // keep the input buffer full
            stream.avail_in = upstream.read(inputOffset, sizeof xferbuf, xferbuf);
            inputOffset += stream.avail_in;
            stream.next_in = bytep(xferbuf);
            if (stream.avail_in == 0)
                eof = true;
        }
        switch (inflate(&stream, eof ? Z_FINISH : Z_SYNC_FLUSH)) {
            case Z_STREAM_END:
                done = true;
                // fallthrough
            case Z_OK:
                break;
            default:
                throw (Exception() << "inflate failed");
        }
    }
    inflateEnd(&stream);
}

InflateReader::~InflateReader()
{
   delete[] data;
}
}
