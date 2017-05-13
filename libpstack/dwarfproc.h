#ifndef PSTACK_DWARFPROC_H
#define PSTACK_DWARFPROC_H

#include <stack>
typedef std::stack<Elf_Addr> DwarfExpressionStack;

Elf_Addr dwarfEvalExpr(DwarfInfo *, const Process &proc, DWARFReader &r, const StackFrame *frame, DwarfExpressionStack *stack);
Elf_Addr dwarfEvalExpr(const Process &, const DwarfAttribute *, const StackFrame *, DwarfExpressionStack *stack);

#endif // PSTACK_DWARFPROC_H

