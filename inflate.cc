#include "libpstack/inflatereader.h"
#include "libpstack/util.h"

#include <zlib.h>

InflateReader::InflateReader(size_t inflatedSize, const Reader &upstream)
    : MemReader(inflatedSize, new char[inflatedSize])
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
    if (verbose >= 2)
        *debug << "inflating" << upstream << "...";
    for (bool done = false; !done; ) {
        if (stream.avail_in == 0 && !eof) {
            // keep the input buffer full
            stream.avail_in = upstream.read(inputOffset, sizeof xferbuf, xferbuf);
            inputOffset += stream.avail_in;
            stream.next_in = bytep(xferbuf);
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
                throw (Exception() << "inflate failed");
        }
    }
    inflateEnd(&stream);
    if (verbose >= 2)
        *debug << " total " << inflatedSize << "\n";
}

InflateReader::~InflateReader()
{
   delete[] data;
}
