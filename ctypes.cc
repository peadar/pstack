#include <sysexits.h>
#include <assert.h>
#include <unistd.h>
#include <iostream>

#include "dwarf.h"
#include "dump.h"
#include "elfinfo.h"
#include "procinfo.h"

static int usage(void);


DwarfEntry *
findStruct(ElfObject *o, DwarfUnit *u, DwarfEntry *ent, const char *name)
{

  if (strcmp(ent->name(), name) == 0) {
     return ent;
  }
  for (auto &child : ent->children) {
     auto v = findStruct(o, u, child.second.get(), name);
     if (v) {
        return v;
     }
  }
  return 0;
}

int
emain(int argc, char **argv)
{
    int error, i, c;
    pid_t pid;
    const char *structName;

    noDebugLibs = true;

    while ((c = getopt(argc, argv, "ns:")) != -1) {
       switch (c) {
          case 's': structName = optarg; break;
          case 'n': noDebugLibs = false; break;
       }
    }

    if (optind == argc)
        return usage();

    for (error = 0, i = optind; i < argc; i++) {
         auto obj = std::make_shared<ElfObject>(std::make_shared<FileReader>(argv[i]));
         DwarfInfo dwarf(obj);

         for (auto unitKey : dwarf.units()) {
            auto unit = unitKey.second.get();
            for (auto &entry : unit->entries) {
               auto v = findStruct(obj.get(), unit, entry.second.get(), structName);
               if (v) {
                  std::cout << *v;
                  return 0;
               }
            }
         }
    }
    return (error);
}

int
main(int argc, char **argv)
{
    try {
        emain(argc, argv);
    }
    catch (std::exception &ex) {
        std::clog << "error: " << ex.what() << std::endl;
    }
}

static int
usage(void)
{
    std::clog << "not like that\n" ;
    return (EX_USAGE);
}
