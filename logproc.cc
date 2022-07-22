#include <fstream>
#include "libpstack/dwarf.h"
#include "libpstack/global.h"
#include "libpstack/elf.h"
#include "libpstack/proc.h"

#define REGMAP(a, b)
#include "libpstack/dwarf/archreg.h"
#undef REGMAP

#include <iostream>

LogProcess::LogProcess(Elf::Object::sptr exec, const std::vector<std::string> &logs_, const PstackOptions &options, Dwarf::ImageCache &imageCache)
    : Process(std::move(exec), std::make_shared<CoreReader>(this, nullptr), options, imageCache)
    , logs( logs_ )
{
}

void
LogProcess::load() {
    Process::load();
}

bool
LogProcess::getRegs(lwpid_t, Elf::CoreRegisters *) {
   return false;
}

void
LogProcess::resume(pid_t /* unused */) {
    // can't resume post-mortem debugger.
}

void
LogProcess::stop(lwpid_t /* unused */) {
    // can't stop a dead process.
}

void
LogProcess::stopProcess() {
    // Find LWPs when we attempt to "stop" the process.
}

void
LogProcess::resumeProcess() {
    // Find LWPs when we attempt to "stop" the process.
}

pid_t
LogProcess::getPID() const
{
    return -1;
}

std::vector<AddressRange>
LogProcess::addressSpace() const {
   abort();
}

std::list<ThreadStack>
LogProcess::getStacks(const PstackOptions &, unsigned) {
   return stacks;
}

bool
LogProcess::loadSharedObjectsFromFileNote() {
    std::set<std::string> addedObjects;

    for (auto &file : logs) {
        std::ifstream in{file};
        std::string buf;
        std::vector<Elf::Addr> ipStack;

        while (std::getline(in, buf)) {
            std::string lib = "";
            std::string offsetStr = "";
            std::string function = "";
            std::string vaStr = "";
            std::string *current = &lib;

            for (auto c : buf) {
                switch (c) {
                    case '[':
                        current = &vaStr;
                        break;
                    case '(':
                        current = &function;
                        break;
                    case '+':
                        current = &offsetStr;
                        break;
                    case ']':
                        break;
                    default:
                        current->push_back(c);
                }
            }
            Elf::Addr va = stoul(vaStr, 0, 0);
            ipStack.push_back(va);

            Elf::Off offset;
            if (offsetStr != "") {
               offset = stoul(offsetStr, 0, 0);
               auto result = addedObjects.insert(lib);
               if (!result.second) {
                   // file already loaded. go again.
                   continue;
               }
            } else {
               *debug << "no offset for " << lib << ",it's probably the executable\n";
               continue;
            }

            auto object = imageCache.getImageForName(lib);
            if (object == nullptr) {
                *debug << "no image for " << lib << "\n";
                continue;
            }

            Elf::Addr funcOffset;
            if (function != "") {
                Elf::Sym sym;
                sym = object->findDynamicSymbol(function);
                if (sym.st_shndx == SHN_UNDEF) {
                    sym = object->findDebugSymbol(function);
                    if (sym.st_shndx == SHN_UNDEF) {
                       *debug << "no symbol for " << function << " in " << lib << "\n";
                       continue;
                    }
                }
                funcOffset = sym.st_value;
            } else {
               funcOffset = 0;
            }
            Elf::Addr loadAddr = va - funcOffset - offset;
            addElfObject(object, loadAddr);
        }
        addElfObject(execImage, 0);
        // Add the stack of virtual addresses to the core.
        stacks.push_back(ThreadStack());
        auto &procstack = stacks.back();
        for (auto addr : ipStack) {
           procstack.stack.emplace_back(Dwarf::UnwindMechanism::LOGFILE);
           procstack.stack.back().setReg(IPREG, addr);
           procstack.stack.back().findObjectCode(*this);
        }
    }
    return true;
}
