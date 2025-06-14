// Copyright (c) 2022 Arista Networks, Inc.  All rights reserved.
// Arista Networks, Inc. Confidential and Proprietary.

#include "libpstack/proc.h"
#include "heap.h"
#include <unistd.h>
#include <set>
#include <cassert>

using namespace pstack;

enum printoption {
   heap_allocated, heap_recentfree, heap_historicbig
};

std::set<printoption> options;

void printStack(std::ostream &os, std::shared_ptr<Procman::Process> &proc, const hdbg_info &info, void **frames) {
   for (size_t i = 0; i < info.maxframes && frames[i] != nullptr; ++i) {
      uintptr_t frameip = uintptr_t(frames[i]);
      if (i != 0)
         frameip--;

      // find the segment containing the instruction pointer.
      auto &&[elfReloc, elf, phdr] = proc->findSegment(frameip);

      os << "\t" << frames[i];
      if (elf) {
         auto found = elf->findSymbolByAddress(frameip - elfReloc, STT_FUNC);
         if (found) {
            auto &[ sym, name ] = *found;
            os << "\t" << name << "+" << uintptr_t(frames[i]) - elfReloc - sym.st_value;
         }

         auto dwarf = proc->context.findDwarf(elf);
         if (dwarf) {
            auto sep = "in";
            for (auto &&[file, line] : dwarf->sourceFromAddr(frameip - elfReloc)) {
               os << " " << sep << " " << file << ":" << line;
               sep = ",";
            }
         }

      }
      os << "\n";
   }
   os << "\n";
}

void printBlocks(std::ostream &os, std::shared_ptr<Procman::Process> proc, const hdbg_info &info, const memdesc_list &list, enum memstate state) {

   size_t sz = sizeof (struct memdesc) + info.maxframes * sizeof (void *);
   struct memdesc *hdr = (memdesc *)malloc(sz);

   for (Elf::Addr addr = (Elf::Addr)list.tqh_first; addr; addr = (Elf::Addr)hdr->node.tqe_next) {
      if (proc->io->read((uintptr_t)addr, sz, (char *)hdr) != sz)
         break;
      os << "ptr=" << hdr->data + 1;
      memstate head = proc->io->readObj<memstate>((Elf::Addr)&hdr->data->state);
      memstate tail = proc->io->readObj<memstate>((Elf::Addr)(hdr->data + 1) + hdr->len);
      if (head != state) {
         std::cout << " BADHEAD";
      }
      if (tail != state) {
         std::cout << " BADTAIL";
      }
      os << " size=" << hdr->len << "\n";
      printStack(os, proc, info, hdr->stack);

   }
   free(hdr);
}

void dumpHeap(std::shared_ptr<Procman::Process> proc)
{

   Procman::StopProcess here(proc.get());
   Elf::Addr sym = proc->resolveSymbol("hdbg", false);
   assert(sym);

   auto &os = *proc->context.output;
   auto info = proc->io->readObj<hdbg_info>(sym);
   os << "Allocator usage statistics:\n\n"
   << "Calls to malloc:               " << info.stats.malloc_calls << "\n"
   << "Calls to free:                 " << info.stats.free_calls << "\n"
   << "Calls to calloc:               " << info.stats.calloc_calls << "\n"
   << "Calls to realloc:              " << info.stats.realloc_calls << "\n"
   << "Calls to aligned_alloc et al:  " << info.stats.aligned_alloc_calls << "\n"
   ;

   os << "\nStack at termination:\n\n";
   printStack(os, proc, info, info.crashstack);
   if (options.find(heap_allocated) != options.end()) {
      os << "\nCurrently allocated memory:\n\n";
      printBlocks(os, proc, info, info.heap, mem_allocated);
   }
   if (options.find(heap_recentfree) != options.end()) {
      os << "\nRecently freed memory:\n\n";
      printBlocks(os, proc, info, info.freelist, mem_free);
   }
   if (options.find(heap_historicbig) != options.end()) {
      os << "\nHistoric large allocations:\n\n";
      printBlocks(os, proc, info, info.freebig, mem_free);
   }
}

int
main(int argc, char *argv[])
{
   Context context;
   std::shared_ptr<Elf::Object> exec;

   for (int c; (c = getopt(argc, argv, "e:fab")) != -1; ) {
      switch (c) {
         case 'e':
            exec = context.openImage(optarg);
            break;
         case 'f':
            options.insert(heap_recentfree);
            break;
         case 'a':
            options.insert(heap_allocated);
            break;
         case 'b':
            options.insert(heap_historicbig);
            break;
      }
   }
   if (options.empty()) {
      options = { heap_recentfree, heap_allocated, heap_historicbig };
   }

   for (int i = optind; i < argc; ++i)
      dumpHeap(Procman::Process::load(context, exec, argv[i]));
}
