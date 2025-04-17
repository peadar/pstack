#include <libpstack/context.h>
#include <libpstack/proc.h>
#include <libpstack/elf.h>
#include <span>

void
processImage( pstack::Elf::Object::sptr &obj, pstack::Dwarf::Info::sptr &dwarf, const std::set<std::string_view> &funcs)
{
   auto *syms = obj->debugSymbols();
   for (const auto &sym : *syms) {
      if (sym.st_size == 0)
         continue;
      const pstack::Elf::Phdr * seg = obj->getSegmentForAddress( sym.st_value );
      if ((seg->p_flags & pstack::Elf::Word(PF_X)) == 0)
         continue;
      auto name = syms->name(sym);
      if (!funcs.empty() && funcs.count(name) == 0)
         continue;
      pstack::Procman::CodeLocation loc(dwarf, seg, sym.st_value);
      const auto *fde = loc.fde();
      // Get the default frame
      intmax_t maxoff = 0;
      uintptr_t end = sym.st_value;
      fde->cie.execInsns( fde->defaultFrame(), fde->instructions, fde->end, sym.st_value,
            // Find the register with the furthest offset from the CFA. IF the
            // code is compiled with frame pointer omission, then that's almost
            // certainly the stack pointer, and the data will be in the
            // cfaValue should be our stack pointer. With frame pointers, this
            // is less useful, as the stack pointer itself is not tracked by
            // the call frame information (that would be redundant), and
            // spilled registers etc are likely close to the frame pointer
            [&](uintptr_t addr, const pstack::Dwarf::CallFrame &cf) {
               for (const auto &reg : cf.registers)
                  if (reg.second.type == pstack::Dwarf::OFFSET)
                     maxoff = std::max(maxoff, reg.second.u.offset);
               if (cf.cfaValue.type == pstack::Dwarf::OFFSET)
                  maxoff = std::max(maxoff, cf.cfaValue.u.offset );
               end = addr;
               return false;
            });
      // show the max offset from the CFA + the size, as calculated by the
      // offset of the last Call Frame Instruction, and from the symbol (they
      // should generally match)
      std::cout << maxoff << "\t" << end - sym.st_value + 1 << "\t"
         << sym.st_size << "\t" << syms->name( sym ) << "\n";
   }
}

int
main(int argc, char *argv[]) {
   pstack::Context ctx;
   std::span<char *> args{ argv, size_t( argc ) };
   auto elf = ctx.getImage(args[1]);
   auto dwarf = ctx.getDwarf(elf);
   std::set<std::string_view> funcs;
   for (int i = 2; i < argc; ++i)
      funcs.insert(args[i]);
   processImage(elf, dwarf, funcs);
   return 0;
}
