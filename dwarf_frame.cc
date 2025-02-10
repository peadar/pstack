#include "libpstack/dwarf.h"
#include "libpstack/dwarf_reader.h"
#include <algorithm>
#include <stack>

namespace pstack::Dwarf {
std::pair<uintmax_t, bool>
CFI::decodeAddress(DWARFReader &f, uint8_t encoding, uintptr_t sectionVa) const
{
    intmax_t base;
    Elf::Off offset = f.getOffset();
    switch (encoding & 0xfU) {
    case DW_EH_PE_sdata2:
        base = f.getint(2);
        break;
    case DW_EH_PE_sdata4:
        base = f.getint(4);
        break;
    case DW_EH_PE_sdata8:
        base = f.getint(8);
        break;
    case DW_EH_PE_udata2:
        base = f.getuint(2);
        break;
    case DW_EH_PE_udata4:
        base = f.getuint(4);
        break;
    case DW_EH_PE_udata8:
        base = f.getuint(8);
        break;
    case DW_EH_PE_sleb128:
        base = f.getsleb128();
        break;
    case DW_EH_PE_uleb128:
        base = f.getuleb128();
        break;
    case DW_EH_PE_absptr:
        base = f.getint(sizeof (Elf::Word));
        break;
    default:
        throw (Exception() << "unhandled encoding " << (encoding & 0xfU) << " while decoding CFI address");
    }

    switch (encoding & 0xf0U & ~unsigned(DW_EH_PE_indirect)) {
    case 0:
        break;
    case DW_EH_PE_pcrel: {
        // relative to location of the base indicator itself. So, add the
        // offset inside the eh_frame section + the VA of the eh_frame section.
        base += offset + sectionAddr;
        break;
    }
    case DW_EH_PE_textrel: {
        base += sectionVa;
        break;
    }
    case DW_EH_PE_datarel: {
        base += sectionVa;
        break;
    }

    default:
        throw (Exception() << "unhandled base encoding inforation " << (encoding & 0xf0U) << " while decoding CFI address");
    }
    return { base, (encoding & DW_EH_PE_indirect ) != 0 };
}

Elf::Off
CFI::decodeCIEFDEHdr(DWARFReader &r, enum FIType type, Elf::Off *cieOff) const
{
    auto [ length, addrLen ] = r.getlength();
    if (length == 0)
        return 0;
    Elf::Off idoff = r.getOffset();
    auto id = r.getuint(addrLen);
    if (!isCIE(id))
        *cieOff = type == FI_EH_FRAME ? idoff - id : id;
    else
        *cieOff = -1;
    return idoff + length;
}

bool
CFI::isCIE(Elf::Addr cieid) const noexcept
{
    return (type == FI_DEBUG_FRAME && cieid == 0xffffffff) || (type == FI_EH_FRAME && cieid == 0);
}

static size_t sizeForEncoding( ExceptionHandlingEncoding ehe ) {
   switch ( ehe & 0xf ) {
      case DW_EH_PE_udata2: case DW_EH_PE_sdata2: return 2;
      case DW_EH_PE_udata4: case DW_EH_PE_sdata4: return 4;
      case DW_EH_PE_udata8: case DW_EH_PE_sdata8: return 8;
      default: return 0;
   }
}

void
CFI::putCIE(Elf::Addr offset, DWARFReader &r, Elf::Addr end) const {
   cies.emplace(std::piecewise_construct,
         std::forward_as_tuple(offset),
         std::forward_as_tuple(this, r, end));
}

// Insert a CIE or FDE from a dwarf reader, positioned at the header of the
// CIE/FDE The header indicates if its a CIE or FDE - an FDE starts with a
// reference to the CIE, while a CIE starts with a reference of "-1"
std::pair<bool, std::unique_ptr<FDE>>
CFI::putFDEorCIE( DWARFReader &reader ) const {
   size_t startOffset = reader.getOffset();
   Elf::Off associatedCIE;
   Elf::Off nextoff = decodeCIEFDEHdr(reader, type, &associatedCIE);
   if (nextoff == 0)
      return { false, nullptr };
   if (associatedCIE == Elf::Off(-1)) {
      putCIE(startOffset, reader, nextoff);
      reader.setOffset( nextoff );
      return { true, nullptr };
   } else {
      if (cies.find(associatedCIE) == cies.end()) {
         DWARFReader r2( io, associatedCIE );
         auto [ success, notAnFde ] = putFDEorCIE(r2);
         assert(success && notAnFde == nullptr);
      }
      std::unique_ptr<FDE> fde = std::make_unique<FDE>(*this, reader, associatedCIE, nextoff);
      reader.setOffset( nextoff );
      return {true, std::move(fde) };
   }
}

const std::vector<std::unique_ptr<FDE>> &CFI::getFDEs() const {
   ensureFDEs();
   return fdes;
}

const std::map<Elf::Addr,CIE> &CFI::getCIEs() const {
   return cies;
}

CFI::CFI(const Info *info, FIType type_)
    : dwarf(info)
    , type(type_)
{
    auto &elf = info->elf;
    const Elf::Section &ehFrameSec = elf->getDebugSection(".eh_frame", SHT_PROGBITS);
    const Elf::Section &ehFrameHdrSec = elf->getDebugSection(".eh_frame_hdr", SHT_PROGBITS);
    const Elf::Section &debugFrameSec = elf->getSection(".debug_frame", SHT_PROGBITS);

    if (info->elf->context.verbose)
       *info->elf->context.debug << "construct CFI for " << *info->elf->io << "\n";

    const auto &cfiFrame = type != FI_DEBUG_FRAME && ehFrameSec ? ehFrameSec : debugFrameSec;
    type = type != FI_DEBUG_FRAME && ehFrameSec ? FI_EH_FRAME : FI_DEBUG_FRAME;
    sectionAddr = cfiFrame.shdr.sh_addr;

    if (!cfiFrame)
        return;
    io = cfiFrame.io();

    do {

       // If we are using .eh_frame and have .eh_frame_hdr, we can use
       // the sorted header later to read the FDEs lazily.
       if ( type != FI_EH_FRAME )
          break;
       if (!ehFrameHdrSec)
           break;
       if (getenv("NO_EH_FRAME_HDR"))
          break;
       DWARFReader hdr( ehFrameHdrSec.io() );

       /* auto version = */ hdr.getu8();
       auto ptrEnc = hdr.getu8();
       auto fdeCountEnc = hdr.getu8();
       fdeTableEnc = ExceptionHandlingEncoding(hdr.getu8());

       // We are mostly interested in the FDE search table. return if it's not there.
       auto enc = fdeTableEnc & 0x0f;
       if ( enc == DW_EH_PE_omit || (0xf & fdeCountEnc ) == DW_EH_PE_omit )
          break;

       if (sizeForEncoding(fdeTableEnc) == 0) {
          // table needs to use a fixed-size encoding so we can binary search it.
          break;
       }

       // datarel encodings are relative to this VA.
       ehFrameHdrAddr = ehFrameHdrSec.shdr.sh_addr;

       // We don't really care about this - it should be just a pointer to the
       // eh_frame section we already got by name from the ELF object.
       decodeAddress( hdr, ptrEnc, ehFrameHdrSec.shdr.sh_addr );
       auto [fdeTableSize, indirectTable]= decodeAddress( hdr, fdeCountEnc, 0);

       fdeTable = ehFrameHdrSec.io()->view("FDE search table", hdr.getOffset(),
               ehFrameHdrSec.io()->size() - hdr.getOffset());
       // empty pointers will be filled when searching from fdeTable
       fdes.resize(fdeTableSize);
       return;

    } while( false );

    // No usable eh_frame_hdr found. Read everything now so we can search it.

    if (info->elf->context.verbose)
       *info->elf->context.debug << "fall back to full-FDE decoding for " << *dwarf->elf->io << "\n";

    // Walk the entire CIE/FDE sequence, populating the fdes and cies sets as
    // we go. This really only happens for the VDSO on arm.
    DWARFReader reader(io);
    while (!reader.empty()) {
       auto [success, fde] = putFDEorCIE(reader);
       if (!success)
          break;
       if (fde != nullptr) // skip CIEs.
          fdes.push_back(std::move(fde));
    }
    std::sort(fdes.begin(), fdes.end(),
          [](std::unique_ptr<FDE> &l, std::unique_ptr<FDE> &r) {
          return l->iloc < r->iloc; });
}


void
CFI::ensureFDE(size_t idx) const {
   auto &entry = fdes[idx];
   if (entry != nullptr)
      return;
   size_t encodingSize = sizeForEncoding( ExceptionHandlingEncoding(fdeTableEnc) );
   DWARFReader tableReader( fdeTable, encodingSize * 2 * idx );
   auto [fdeAddr,indirectAddr] = decodeAddress(tableReader, fdeTableEnc, ehFrameHdrAddr);
   (void)fdeAddr;
   (void)indirectAddr;
   auto [fdeOff,indirectOff] = decodeAddress(tableReader, fdeTableEnc, ehFrameHdrAddr);
   DWARFReader fdeReader( io, fdeOff - sectionAddr );
   auto [ success, newEntry ] = putFDEorCIE( fdeReader );
   entry = std::move(newEntry);
   assert(fdeAddr == entry->iloc);
}

void
CFI::ensureFDEs() const {
   if (fdeTable == nullptr)
      return;
   for (size_t i = 0; i < fdes.size(); ++i)
      ensureFDE(i);
   fdeTable.reset(); // We don't need this anymore, as we've read all the FDEs.
}

const FDE *
CFI::findFDE(Elf::Addr addr) const {

   // No FDE found. Check the lookup table.
   uintptr_t start = 0;
   uintptr_t end = fdes.size();

   while (start < end) {
      auto mid = start + (end - start) / 2;
      ensureFDE(mid);
      auto &entry = fdes[mid];
      if (entry->iloc <= addr) {
         start = mid + 1;
         if (addr < entry->iloc + entry->irange)
            return entry.get();
      } else {
         end = mid;
      }
   }
   return nullptr;
}

CallFrame::CallFrame()
    : cfaReg(0)
    , cfaValue{ .type = UNDEF, .u = { .arch = 0  } }
{
    cfaReg = 0;
    cfaValue.type = UNDEF;
#define REGMAP(number, field) registers[number].type = ARCH;
#include "libpstack/archreg.h"
#undef REGMAP
#ifdef CFA_RESTORE_REGNO
#endif
}

CallFrame
FDE::defaultFrame() const {
   CallFrame dframe;
   // Execute all of the initial_instructions in the CIE, creating the starting
   // point for a frame. XXX: It might be worth caching this in the CIE, but
   // there's rarely a huge number of instructions here .
   // The initial instructions extend from the given point in the CIE to the
   // end of its extent.
   return cie.execInsns(dframe, cie.initial_instructions, cie.end, 0,
         [](uintmax_t, CallFrame &) { return false; });
}

CallFrame
FDE::execInsns(uintmax_t addr) const {
   // Starting with the default frame state, execute the code for this FDE
   // until we reach the given address.
   return cie.execInsns(defaultFrame(), instructions, end, iloc,
         [addr](uintmax_t insnAddr, CallFrame &) { return addr < insnAddr; });
}

FDE::FDE(const CFI &fi, DWARFReader &reader, Elf::Off cieOff, Elf::Off endOff_)
    : end(endOff_)
    , cie(fi.cies.at( cieOff ))
{
    bool indirect;
    std::tie(iloc, indirect) = fi.decodeAddress(reader, cie.addressEncoding, fi.sectionAddr);
    if (indirect)
        throw (Exception() << "FDE has indirect encoding for location");
    std::tie(irange, indirect) = fi.decodeAddress(reader, cie.addressEncoding & 0xf, fi.sectionAddr);
    assert(!indirect); // we've anded out the indirect encoding flag.
    if (!cie.augmentation.empty() && cie.augmentation[0] == 'z') {
        size_t alen = reader.getuleb128();
        while (alen-- != 0)
            augmentation.push_back(reader.getu8());
    }
    instructions = reader.getOffset();
}

CIE::CIE(const CFI *fi, DWARFReader &r, Elf::Off end_)
    : frameInfo(fi)
    , addressEncoding(0)
    , addressSize(ELF_BYTES)
    , segmentSize(0)
    , lsdaEncoding(0)
    , isSignalHandler(false)
    , initial_instructions(0)
    , end(end_)
    , personality{}
{
    version = r.getu8();
    augmentation = r.getstring();
    if (version >= 4) {
        addressSize = r.getu8();
        segmentSize = r.getu8();
    }
    codeAlign = r.getuleb128();
    dataAlign = r.getsleb128();
    rar = r.getu8();

#if ELF_BITS == 32
    addressEncoding = DW_EH_PE_udata4;
#elif ELF_BITS == 64
    addressEncoding = DW_EH_PE_udata8;
#else
    #error "no default address encoding"
#endif

    bool earlyExit = false;
    Elf::Off endaugdata = r.getOffset();
    for (auto aug : augmentation) {
        switch (aug) {
            case 'z':
                endaugdata = r.getuleb128();
                endaugdata += r.getOffset();
                break;
            case 'P':
                personality = fi->decodeAddress(r, r.getu8(), fi->sectionAddr );
                break;
            case 'L':
                lsdaEncoding = r.getu8();
                break;
            case 'R':
                addressEncoding = r.getu8();
                break;
            case 'S':
                isSignalHandler = true;
                break;
            case '\0':
                break;
            default:
                *fi->dwarf->elf->context.debug << "unknown augmentation '" << aug << "' in " << augmentation << std::endl;
                // The augmentations are in order, so we can't make any sense
                // of the remaining data in the augmentation block
                earlyExit = true;
                break;
        }
        if (earlyExit)
            break;
    }
    if (r.getOffset() != endaugdata) {
        *fi->dwarf->elf->context.debug << "warning: " << endaugdata - r.getOffset() << " bytes of augmentation ignored" << std::endl;
        r.setOffset(endaugdata);
    }
    initial_instructions = r.getOffset();
}

}

#include "dwarf_frame.tcc"
