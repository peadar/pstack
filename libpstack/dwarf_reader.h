#include <string>
#include <cassert>
#include "libpstack/elf.h"
#include "libpstack/reader.h"
#include <stdint.h>

namespace pstack::Dwarf {
/*
 * A DWARF Reader is a wrapper for a reader that keeps a current position in the
 * underlying reader, and provides operations to read values in DWARF standard
 * encodings, advancing the offset as it does so.
 */
class DWARFReader {
    Elf::Off off;
    Elf::Off end;
public:
    Reader::csptr io;
    unsigned addrLen;
    DWARFReader(Reader::csptr io_, Elf::Off off_ = 0, size_t end_ = std::numeric_limits<size_t>::max())
        : off(off_)
        , end(end_ == std::numeric_limits<size_t>::max() ? io_->size() : end_)
        , io(std::move(io_))
        , addrLen(ELF_BITS / 8)
        {
        }
    void getBytes(size_t size, unsigned char *to) {
       io->readObj(off, to, size);
       off += size;
    }
    uint32_t getu32() {
        unsigned char q[4];
        io->readObj(off, q, 4);
        off += sizeof q;
        return q[0] | q[1] << 8 | q[2] << 16 | uint32_t(q[3] << 24);
    }
    uint16_t getu16() {
        unsigned char q[2];
        io->readObj(off, q, 2);
        off += sizeof q;
        return q[0] | q[1] << 8;
    }
    uint8_t getu8() {
        unsigned char q;
        io->readObj(off, &q, 1);
        off++;
        return q;
    }
    int8_t gets8() {
        int8_t q;
        io->readObj(off, &q, 1);
        off += 1;
        return q;
    }
    uintmax_t getuint(size_t len) {
        uintmax_t rc = 0;
        uint8_t bytes[16];
        if (len > 16)
            throw Exception() << "can't deal with ints of size " << len;
        io->readObj(off, bytes, len);
        off += len;
        uint8_t *p = bytes + len;
        for (size_t i = 1; i <= len; i++)
            rc = rc << 8 | p[-i];
        return rc;
    }
    intmax_t getint(size_t len) {
        intmax_t rc;
        uint8_t bytes[16];
        if (len > 16 || len < 1)
            throw Exception() << "can't deal with ints of size " << len;
        io->readObj(off, bytes, len);
        off += len;
        uint8_t *p = bytes + len;
        rc = (p[-1] & 0x80) ? -1 : 0;
        for (size_t i = 1; i <= len; i++)
            rc = rc << 8 | p[-i];
        return rc;
    }

    uintmax_t getuleb128() {
        auto v = io->readULEB128(off);
        skip(v.second);
        return v.first;
    }
    intmax_t getsleb128() {
        auto v = io->readSLEB128(off);
        skip(v.second);
        return v.first;
    }

    std::string readFormString(const Info &, Unit &, Form f);
    void readForm(const Info &, Unit &, Form f);
    uintmax_t readFormUnsigned(Form f);
    intmax_t readFormSigned(Form f);

    std::string getstring() {
        std::string s = io->readString(off);
        off += s.size() + 1;
        return s;
    }
    Elf::Off getOffset() const { return off; }
    Elf::Off getLimit() const { return end; }
    void setOffset(Elf::Off off_) {
       assert(end >= off_);
       off = off_;
    }
    bool empty() const {
       return off == end;
    }
    std::pair<Elf::Off, Elf::Off> getlength(); // sets "dwarfLen"
    void skip(Elf::Off amount) { off += amount; }
};

}
