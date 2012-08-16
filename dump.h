#include "dwarf.h"
#include <iostream>
#include <tuple>
#include <functional>

template <typename T> std::ostream &operator << (std::ostream &os, const std::list<T> &entries) {
    os << "[ ";
    std::string sep = "";
    for (auto &entry : entries) {
        os << sep << entry;
        sep = ", ";
    }
    return os << " ]";
}

template <typename T> std::ostream &operator << (std::ostream &os, const std::list<T *> &entries) {
    os << "[ ";
    std::string sep = "";
    for (auto entry : entries) {
        os << sep << *entry;
        sep = ", ";
    }
    return os << " ]";
}

template <typename T> std::ostream &operator << (std::ostream &os, const std::vector<T> &entries) {
    os << "[ ";
    std::string sep = "";
    for (auto &entry : entries) {
        os << sep << entry;
        sep = ", ";
    }
    return os << " ]";
}

template <typename T> std::ostream &operator << (std::ostream &os, const std::vector<T *> &entries) {
    os << "[ ";
    const char *sep = "";
    for (auto entry : entries) {
        os << sep << *entry;
        sep = ", ";
    }
    return os << " ]";
}

template <typename K, typename V> std::ostream &operator << (std::ostream &os, const std::map<K, V> &entries) {
    os << "{ ";
    std::string sep = "";
    for (auto &entry : entries) {
        os << sep << " \"" << entry.first << "\": " << entry.second;
        sep = ", ";
    }
    return os << " }";
}

template <typename K, typename V> std::ostream &operator << (std::ostream &os, const std::map<K, V *> &entries) {
    os << "{ ";
    std::string sep = "";
    for (auto &entry : entries) {
        const V &v = *entry.second;
        os << sep << " \"" << entry.first << "\": " << v;
        sep = ", ";
    }
    return os << " }";
}


std::ostream &operator << (std::ostream &os, const DwarfAbbreviation &abbr);
std::ostream &operator << (std::ostream &os, const DwarfARange &range);
std::ostream &operator << (std::ostream &os, const DwarfARangeSet &ranges);
std::ostream &operator << (std::ostream &os, const DwarfAttribute &attr);
std::ostream &operator << (std::ostream &os, const DwarfAttributeSpec &spec);
std::ostream &operator << (std::ostream &os, const DwarfBlock &b);
std::ostream &operator << (std::ostream &os, const DwarfEntry &entry);
std::ostream &operator << (std::ostream &os, const DwarfExpressionOp);
std::ostream &operator << (std::ostream &os, const DwarfFileEntry &fe);
std::ostream &operator << (std::ostream &os, const DwarfFrameInfo &info);
std::ostream &operator << (std::ostream &os, const DwarfInfo &dwarf);
std::ostream &operator << (std::ostream &os, const DwarfLineInfo &lines);
std::ostream &operator << (std::ostream &os, const DwarfLineState &ls);
std::ostream &operator << (std::ostream &os, const DwarfPubname &name);
std::ostream &operator << (std::ostream &os, const DwarfPubnameUnit &unit);
std::ostream &operator << (std::ostream &os, const DwarfUnit &unit);
std::ostream &operator << (std::ostream &os, const Elf_Phdr &);
std::ostream &operator << (std::ostream &os, const std::pair<const DwarfInfo &, const DwarfCIE &> &dcie);
std::ostream &operator << (std::ostream &os, const std::pair<const DwarfInfo &, const DwarfFDE &> &dfde );
std::ostream &operator << (std::ostream &os, const std::pair<const ElfObject *, const Elf_Shdr *> &);
std::ostream &operator << (std::ostream &os, std::tuple<const ElfObject *, const Elf_Shdr *, const Elf_Sym *> &t);
std::ostream &operator << (std::ostream &os, DwarfAttrName code);
std::ostream &operator << (std::ostream &os, DwarfForm code);
std::ostream &operator << (std::ostream &os, DwarfLineEOpcode code);
std::ostream &operator << (std::ostream &os, DwarfTag tag);
std::ostream &operator << (std::ostream &os, const prstatus_t &prstat);

std::ostream &operator << (std::ostream &os, const prstatus_t &);
std::ostream &operator << (std::ostream &os, const Elf_auxv_t &);
