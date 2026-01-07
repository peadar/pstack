#include "libpstack/pyrdb.h"
#include <charconv>
#include <fstream>
#include <string_view>

namespace pstack::Py {
struct Header {
    char cookie[8];
    static std::string_view expectedCookie;
    uint64_t version;
    auto operator <=> (const Header &rhs) const = default;
};
std::string_view Header::expectedCookie { "xdebugpy" };

template <typename T> struct Offset {
    size_t off;
};

struct PyInterpreterState;
struct PyThreadState;
struct PyObject;
struct _PyInterpreterFrame;
struct _PyStackRef;

struct Offsets {

    bool free_threaded;
    struct runtime_state {
        // offsets inside _PyRuntime
        Offset<PyInterpreterState *> interpreters_head;
    };
    runtime_state runtime_state;

    struct interpreter_state {
        // Offsets inside PyInterpreterState
        Offset<PyInterpreterState*> next;
        Offset<PyThreadState*> threads_head;
        Offset<PyThreadState*> threads_main;
        Offset<PyObject *> sysdict;
    };
    interpreter_state interpreter_state;

    struct thread_state {
        Offset<PyThreadState *> next;
        Offset<PyThreadState *> prev;
        Offset<_PyInterpreterFrame *> current_frame;
    };
    thread_state thread_state;

    struct interpreter_frame {
        Offset<_PyStackRef *> stackpointer;
    };
    interpreter_frame interpreter_frame;


    Offsets(uint64_t version, Reader::csptr io) {
        std::array<char, 16> chars;
        auto [ end, ec ] = std::to_chars(chars.begin(), chars.end(), version, 16);
        std::string name = std::string(chars.begin(), end) + ".pydbg";
        std::cout << "reading offsets from " << name << "\n";
        std::ifstream in(name);

        auto readfield = [&](std::istream &is, auto &field) {
            auto off = pstack::parseInt<uint64_t>(is);
            io->readObj(off, &field);
            std::cerr << "read field "  << json(field) << "\n";
        };

        auto skipfield = [&] (std::istream &is, std::string_view field) {
            std::cerr << "skip field "  << json(field) << "\n";
            skip<size_t>(is);
        };

        if (!in.good())
            throw (Exception() << "failed to open offsets file for " << name);

        parseObject(in, [&](std::istream &is, std::string_view field) {
            if (field == "cookie") {
                skipfield(in, field);
            } else if (field == "version") {
                uint64_t checkVersion;
                readfield(in, checkVersion);
            } else if (field == "runtime_state") {
                auto &state = this->runtime_state;
                parseObject(in, [&](std::istream &is, std::string_view field) {
                    if (field == "interpreters_head")
                        readfield(is, state.interpreters_head.off);
                    else
                        skipfield(is, field);
                });
            } else if (field == "interpreter_frame") {
                auto &state = this->interpreter_frame;
                parseObject(in, [&](std::istream &is, std::string_view field) {
                    if (field == "stackpointer") {
                        readfield(is, state.stackpointer.off);
                    } else {
                        skipfield(is, field);
                    }
                });
            } else {
                skipfield(is, field);
            }
        });

    }

};


Remote::Remote(Procman::Process &proc_) : proc{proc_} {
    // First find a python interpreter. The first thing with the right section will do.
    pstack::Context &ctx = proc.context;

    for (auto &[addr, mapped] : proc.objects) {
        auto &sec = mapped.object(ctx)->getSection(".PyRuntime", SHT_PROGBITS);
        if (!sec) {
            continue;
        }
        auto io = sec.io();
        auto h = io->readObj<Header>(0);

        debugOffsetsAddr = addr + sec.shdr.sh_addr;
        *ctx.debug << "found python runtime in " << mapped.name() << "\n";

        auto proch = proc.io->readObj<Header>(debugOffsetsAddr);
        if (proch != h) {
            *ctx.debug << "note - in memory offsets != on-disk offsets\n";
        }
        auto offsets = Offsets(proch.version, proc.io->view("debug offsets", debugOffsetsAddr));


    }

} }
