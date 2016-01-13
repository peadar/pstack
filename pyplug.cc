#include <Python.h>
#include <iostream>
#include <memory>
#include "elfinfo.h"
#include "dwarf.h"
#include "dump.h"

extern "C" {

typedef struct {
   PyObject_HEAD
   std::shared_ptr<ElfObject> obj;
   std::shared_ptr<DwarfInfo> dwarf;
} PyElfObject;

static void
pyElfObjectFree(PyObject *o)
{
   PyElfObject *pye = (PyElfObject *)o;
   pye->obj.std::shared_ptr<ElfObject>::~shared_ptr<ElfObject>();
   pye->dwarf.std::shared_ptr<DwarfInfo>::~shared_ptr<DwarfInfo>();
   std::clog << "reset ELF object\n";
}

static PyTypeObject elfObjectType = {
   PyObject_HEAD_INIT(0)
};

static PyObject *
open(PyObject *self, PyObject *args)
{
   const char *image;
   if (!PyArg_ParseTuple(args, "s", &image))
         return 0;
   PyElfObject *val = PyObject_New(PyElfObject, &elfObjectType);
   new (&val->obj) std::shared_ptr<ElfObject>();
   val->obj.reset(new ElfObject(image));
   val->dwarf.reset(new DwarfInfo(val->obj));
   std::clog << "created ELF object " << val->obj.get() << "\n";
   return (PyObject *)val;
}

DwarfEntry *
findStruct(DwarfUnit *u, DwarfEntry *ent, const char *name)
{

  if (strcmp(ent->name(), name) == 0) {
     return ent;
  }
  for (auto &child : ent->children) {
     auto v = findStruct(u, child.second.get(), name);
     if (v) {
        return v;
     }
  }
  return 0;
}

static PyObject *
typedesc(PyObject *self, PyObject *args)
{
   PyElfObject *pye = (PyElfObject *)self;
   const char *name;

   if (!PyArg_ParseTuple(args, "s", &name))
      return 0;

   for (auto unitKey : pye->dwarf->units()) {
      auto unit = unitKey.second.get();
      for (auto &entry : unit->entries) {
         auto v = findStruct(unit, entry.second.get(), name);
         if (v) {
            std::cout << *v;
            break;
         }
      }
   }
   return Py_None;
}

static PyMethodDef GenTypeMethods[] = {
   { "open", open, METH_VARARGS, "open an ELF file to process" },
   { 0, 0, 0, 0 }
};

static PyMethodDef elfMethods[] = {
   { "typedesc", typedesc, METH_VARARGS, "open an ELF file to process" },
   { 0, 0, 0, 0 }
};

PyMODINIT_FUNC
initlibgentypes(void)
{
   PyObject *module = Py_InitModule3("libgentypes", GenTypeMethods, "ELF helpers");
   elfObjectType.tp_name = "libgentypes.ElfObject";
   elfObjectType.tp_flags = Py_TPFLAGS_DEFAULT;
   elfObjectType.tp_basicsize = sizeof(PyElfObject);
   elfObjectType.tp_methods = elfMethods;
   elfObjectType.tp_doc = "GenericIfIterator object";
   elfObjectType.tp_dealloc = pyElfObjectFree;
   elfObjectType.tp_new = PyType_GenericNew;
   if (PyType_Ready(&elfObjectType) < 0)
      return;
   Py_INCREF(&elfObjectType);
   PyModule_AddObject(module, "ElfObject", (PyObject *)&elfObjectType);
}
}
