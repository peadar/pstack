#include <libpstack/context.h>
#include <libpstack/proc.h>
#include <libpstack/elf.h>
#include <libpstack/dwarf_reader.h>
#include <dwarf_frame.tcc>
#include <span>

void
processImage(
      [[maybe_unused]] pstack::Context &ctx,
      [[maybe_unused]] std::shared_ptr<pstack::Elf::Object> &obj,
      [[maybe_unused]] std::shared_ptr<pstack::Dwarf::Info> &dwarf,
      [[maybe_unused]] const std::set<std::string_view> &funcs)
{
   auto *syms = obj->debugSymbols();

   for (const auto &sym : *syms) {
      if (sym.st_size == 0)
         continue;
      const pstack::Elf::Phdr * seg = obj->getSegmentForAddress( sym.st_value );
      if ((seg->p_flags & pstack::Elf::Word(PF_X)) == 0)
         continue;

      auto name = syms->name(sym);
      if (!funcs.empty() && !funcs.count(name) == 0)
         continue;

      pstack::Procman::CodeLocation loc(dwarf, seg, sym.st_value);
      const auto *fde = loc.fde();

      // Get the default frame
      intmax_t maxoff = 0;
      intmax_t minoff = 0;
      int insns = 0;
      fde->cie.execInsns( fde->defaultFrame(), fde->instructions, fde->end, sym.st_value,
            // Find the register with the furthest offset from the CFA. IF
            // we're using FPO, then that's actually almost certainly the stack
            // pointer, and the data will be in the cfaValue
            // should be our stack pointer
            [&](uintptr_t, const pstack::Dwarf::CallFrame &cf) {
               ++insns;
               for (auto &reg : cf.registers) {
                  if (reg.second.type == pstack::Dwarf::OFFSET) {
                     maxoff = std::max(maxoff, reg.second.u.offset);
                     minoff = std::min(minoff, reg.second.u.offset);
                  }
               }

               if (cf.cfaValue.type == pstack::Dwarf::OFFSET) {
                  maxoff = std::max(maxoff, cf.cfaValue.u.offset );
                  minoff = std::min(minoff, cf.cfaValue.u.offset );
               }
               return false;
            });
      std::cout << maxoff << "\t" << minoff << "\t" << insns << "\t" << syms->name( sym ) << "\n";
   }
}

int
main(int argc, char *argv[]) {
   pstack::Context ctx;
   auto elf = ctx.getImageForName(argv[1]);
   auto dwarf = ctx.getDwarf(elf);
   std::set<std::string_view> funcs;
   for (int i = 2; i < argc; ++i)
      funcs.insert(argv[i]);
   processImage(ctx, elf, dwarf, funcs);
}
