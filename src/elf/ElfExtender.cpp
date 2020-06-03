/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include <fstream>
#include "easylogging/easylogging++.h"
#include "core/FileLoader.hpp"
#include "core/Region.hpp"
#include "libelfin/elf/elf++.hh"
#include "ElfExtender.hpp"

#define MEM_PAGE_SIZE (0x1000U)

namespace bcov {

static inline addr_t
align_lower(addr_t addr, uint64_t align)
{
    // assume align is power of 2
    return (addr & ~(align - 1));
}

static inline addr_t
align_higher(addr_t addr, uint64_t align)
{
    return align_lower(addr + align - 1, align);
}

static inline uint64_t
page_align_high(uint64_t value, uint64_t align = MEM_PAGE_SIZE)
{
    return align + ((value - 1) & ~((align) - 1));
}

static uint64_t
get_next_alloc_vaddr(const elf::elf &elf_file)
{
    const elf::segment *last_loadable_seg = nullptr;
    for (const auto &seg : elf_file.segments()) {
        if (elf::is_loadable(seg)) {
            last_loadable_seg = &seg;
        }
    }
    auto &hdr = last_loadable_seg->get_hdr();
    return align_higher(hdr.vaddr + hdr.memsz, hdr.align);
}

static std::pair<unsigned, const elf::segment *>
get_first_loadable_segment(const elf::elf &elf_file)
{
    using namespace elf;
    int idx = 0;
    for (const auto &segment : elf_file.segments()) {
        if (is_loadable(segment)) {
            return {idx, &segment};
        }
        ++idx;
    }
    return {0, nullptr};
}

static std::pair<unsigned, const elf::segment *>
get_patchable_segment(const elf::elf &elf_file)
{
    using namespace elf;
    unsigned idx;
    const segment *fst_seg;
    std::tie(idx, fst_seg) = get_first_loadable_segment(elf_file);
    const segment *snd_seg = &(elf_file.segments()[idx + 1]);
    DCHECK(snd_seg->get_hdr().type == pt::load);
    auto required_phdrs_size =
        (elf_file.get_hdr().phnum + 2) * elf_file.get_hdr().phentsize;

    // check if enough space for 2 PHDR is available to extend current PHDR segment
    if (fst_seg->get_hdr().offset + fst_seg->get_hdr().filesz +
        required_phdrs_size < snd_seg->get_hdr().offset) {
        return {idx, fst_seg};
    }
    return {0, nullptr};
}

static bool
has_phdr_segment(const elf::elf &elf_file)
{
    return elf_file.segments().front().get_hdr().type == elf::pt::phdr;
}

static inline void
init_region(FileRegion &region, const elf::elf &elf_file, off64_t offset,
            size_t size)
{
    region.size = size;
    region.base_pos = (const char *) elf_file.get_loader()->load(offset, size);
}

static bool
can_patch_existing_phdrs(const elf::elf &elf_file)
{
    using namespace elf;
    if (!has_phdr_segment(elf_file)) {
        // without a phdr segment we can not safely overwrite existing
        // data with new headers.
        return false;
    }
    // check if enough space for 2 PHDR is available to extend current PHDR segment
    auto ehdr_p = (Ehdr<> *) (elf_file.get_loader()->load(0, sizeof(Ehdr<>)));

    auto fst_hdr =
        (Phdr<> *) (elf_file.get_loader()->load(ehdr_p->phoff, sizeof(Phdr<>)));

    auto snd_hdr =
        (Phdr<> *) (elf_file.get_loader()->load(ehdr_p->phoff + sizeof(Phdr<>),
                                                sizeof(Phdr<>)));
    return fst_hdr->offset + fst_hdr->filesz + 2 * sizeof(Phdr<>) < snd_hdr->offset;
}

static bool
can_relocate_phdrs_to_middle(const elf::elf &elf_file)
{
    using namespace elf;
    const segment *seg;
    unsigned idx;
    std::tie(idx, seg) = get_patchable_segment(elf_file);
    return seg != nullptr;
}

static bool
can_eliminate_phdrs_segment(const elf::elf &elf_file)
{
    DCHECK(has_phdr_segment(elf_file));
    using namespace elf;
    auto interp_seg = std::find_if(elf_file.segments().begin(),
                                   elf_file.segments().end(),
                                   [](const segment &seg) {
                                       return seg.get_hdr().type == pt::interp;
                                   });
    return interp_seg == elf_file.segments().end();
}

static bool
can_relocate_phdrs_to_end(const elf::elf &elf_file)
{
    if (!has_phdr_segment(elf_file)) {
        // without a phdr segment we can not safely overwrite existing
        // data with new headers.
        return true;
    }

    using namespace elf;
    const segment *fst_seg = nullptr;
    const segment *snd_seg = nullptr;
    for (const auto &seg : elf_file.segments()) {
        if (!is_loadable(seg)) {
            continue;
        }
        if (fst_seg == nullptr) {
            fst_seg = &seg;
            continue;
        }
        snd_seg = &seg;
        break;
    }

    if (fst_seg == nullptr || snd_seg == nullptr) {
        LOG(WARNING) << "malformed elf file";
        return false;
    }
    // check if enough space is available to overlay data segment with PHDRS
    auto required_phdrs_size =
        (elf_file.get_hdr().phnum + 2) * elf_file.get_hdr().phentsize;

    return fst_seg->get_hdr().vaddr + required_phdrs_size +
           (elf_file.get_hdr().shoff - fst_seg->get_hdr().offset) <
           snd_seg->get_hdr().vaddr;
}

static void
fill_with_zeros(std::ofstream &output, size_t begin_off, size_t end_off)
{
    if (begin_off >= end_off) {
        return;
    }
    output.seekp(begin_off);
    size_t pad_size = end_off - begin_off;
    std::vector<char> zero_buf(pad_size, 0);
    output.write(zero_buf.data(), pad_size);
}

struct ElfExtender::Impl {

    using EhdrType = elf::Ehdr<elf::Elf64, elf::byte_order::native>;
    using PhdrType = elf::Phdr<elf::Elf64, elf::byte_order::native>;

    void
    extend_and_patch_existing_phdrs(const elf::elf &infile,
                                    std::ofstream &outfile);

    void
    extend_relocating_phdrs_to_middle(const elf::elf &infile,
                                      std::ofstream &outfile);

    void
    extend_relocating_phdrs_to_end(const elf::elf &infile, std::ofstream &outfile);

    void
    extend_removing_phdrs_segment(std::ofstream &outfile);

    static bool validate_input_file(const elf::elf &elf_file);

    void init(const ElfExtender *patcher, const elf::elf &infile);

    EhdrType *m_orig_ehdr = nullptr;
    FileRegion m_orig_phdrs_region;
    FileRegion m_orig_main_region;
    FileRegion m_orig_shdrs_region;
    PhdrType m_code_seg_hdr;
    PhdrType m_data_seg_hdr;
};

void
ElfExtender::Impl::init(const ElfExtender *patcher, const elf::elf &infile)
{
    using namespace elf;
    m_orig_ehdr = (EhdrType *) (infile.get_loader()->load(0, sizeof(EhdrType)));
    init_region(m_orig_main_region, infile, 0, m_orig_ehdr->shoff);
    init_region(m_orig_phdrs_region, infile, m_orig_ehdr->phoff,
                m_orig_ehdr->phnum * m_orig_ehdr->phentsize);
    init_region(m_orig_shdrs_region, infile, m_orig_ehdr->shoff,
                m_orig_ehdr->shnum * m_orig_ehdr->shentsize);

    m_code_seg_hdr.type = pt::load;
    m_code_seg_hdr.flags = pf::r | pf::x;
    m_code_seg_hdr.filesz = patcher->m_code_seg_size;
    m_code_seg_hdr.memsz = m_code_seg_hdr.filesz;
    m_code_seg_hdr.align = MEM_PAGE_SIZE;
    m_code_seg_hdr.vaddr = get_next_alloc_vaddr(infile);

    // XXX: system V abi ignores physical addressing. Under Linux it seems
    // that vaddr == paddr as a convention. However, under BSD paddr is not used
    // and must be zero.
    m_code_seg_hdr.paddr = m_code_seg_hdr.vaddr;
    // new segments will be written after section data and before shdrs
    m_code_seg_hdr.offset = align_higher(m_orig_main_region.size,
                                         m_code_seg_hdr.align);

    m_data_seg_hdr.type = pt::load;
    m_data_seg_hdr.flags = pf::r | pf::w;
    m_data_seg_hdr.filesz = patcher->m_data_seg_size;
    m_data_seg_hdr.memsz = m_data_seg_hdr.filesz;
    m_data_seg_hdr.align = MEM_PAGE_SIZE;
    m_data_seg_hdr.vaddr =
        align_higher(m_code_seg_hdr.vaddr + m_code_seg_hdr.memsz,
                     m_data_seg_hdr.align);

    m_data_seg_hdr.paddr = m_data_seg_hdr.vaddr;
    m_data_seg_hdr.offset =
        align_higher(m_code_seg_hdr.offset + m_code_seg_hdr.filesz,
                     m_data_seg_hdr.align);
}

bool
ElfExtender::Impl::validate_input_file(const elf::elf &elf_file)
{
    using namespace elf;
    auto ehdr = (EhdrType *) (elf_file.get_loader()->load(0, sizeof(EhdrType)));

    if (elf_file.get_hdr().type != et::dyn && elf_file.get_hdr().type != et::exec) {
        return false;
    }

    if (ehdr->phoff != sizeof(EhdrType)) {
        // program headers are expected to follow elf header
        return false;
    }

    if (elf_file.segments().empty()) {
        return false;
    }

    if (!elf_file.sections().empty() &&
        ehdr->shoff < elf_file.sections().back().get_hdr().offset) {
        // section headers are at end of file
        return false;
    }
    for (const auto &segment : elf_file.segments()) {
        if (segment.get_hdr().type == pt::phdr &&
            elf_file.segments().front().data() != segment.data()) {
            // phdr segment, if exists should be the first
            LOG(ERROR) << "elf: phdr segment is not the first segment";
            return false;
        }
    }

    LOG_IF(!has_phdr_segment(elf_file), INFO)
        << "elf: input file does not have phdr segment. ";

    auto loadable_seg_count = 0;
    for (const auto &seg : elf_file.segments()) {
        if (is_loadable(seg)) {
            ++loadable_seg_count;
        }
    }
    return loadable_seg_count >= 2;
}

void
ElfExtender::Impl::extend_and_patch_existing_phdrs(const elf::elf &infile,
                                                   std::ofstream &outfile)
{
    // extend PHDRS for extra code and data segments. Assumes that linker
    // has left enough space after existing PHDRS.
    using namespace elf;
    DCHECK(infile.segments().front().get_hdr().type == pt::phdr);

    // copy everything till original shdr
    outfile.write(m_orig_main_region.base_pos, m_orig_main_region.size);

    // append extension phdrs
    outfile.seekp(m_orig_ehdr->phoff + m_orig_phdrs_region.size);
    outfile.write((const char *) &m_code_seg_hdr, sizeof(m_code_seg_hdr));
    outfile.write((const char *) &m_data_seg_hdr, sizeof(m_data_seg_hdr));
    // set to zero from current position to end of segments
    auto ext_end_offset = align_higher(m_data_seg_hdr.offset + m_data_seg_hdr.filesz,
                                       m_data_seg_hdr.align);
    fill_with_zeros(outfile, m_code_seg_hdr.offset, ext_end_offset);

    // now copy the original shdrs after patched data segment
    outfile.write(m_orig_shdrs_region.base_pos, m_orig_shdrs_region.size);

    // fixup ehdr
    Ehdr<> fixed_ehdr = *m_orig_ehdr;
    fixed_ehdr.shoff = ext_end_offset;
    fixed_ehdr.phnum += 2;
    outfile.seekp(0);
    outfile.write((const char *) &fixed_ehdr, sizeof(fixed_ehdr));

    // fixup phdr segment, assumes that it is the first header in phdrs
    PhdrType phdr_seg_hdr =
        *(PhdrType *) (infile.get_loader()->load(m_orig_ehdr->phoff,
                                                 sizeof(PhdrType)));
    phdr_seg_hdr.filesz = phdr_seg_hdr.filesz + 2 * sizeof(PhdrType);
    phdr_seg_hdr.memsz = phdr_seg_hdr.filesz;
    outfile.seekp(m_orig_ehdr->phoff);
    outfile.write((const char *) &phdr_seg_hdr, sizeof(PhdrType));
}

void
ElfExtender::Impl::extend_relocating_phdrs_to_middle(const elf::elf &infile,
                                                     std::ofstream &outfile)
{
    // place PHDRS in the space between first two loadable segments
    using namespace elf;
    unsigned load_seg_idx;
    const segment *load_seg_p;
    std::tie(load_seg_idx, load_seg_p) = get_patchable_segment(infile);
    // copy everything till original shdr
    outfile.write(m_orig_main_region.base_pos, m_orig_main_region.size);
    uoffset_t updated_phdr_offset =
        load_seg_p->get_hdr().offset + load_seg_p->get_hdr().filesz;
    outfile.seekp(updated_phdr_offset);
    outfile.write(m_orig_phdrs_region.base_pos, m_orig_phdrs_region.size);
    // append extension phdrs
    outfile.write((const char *) &m_code_seg_hdr, sizeof(PhdrType));
    outfile.write((const char *) &m_data_seg_hdr, sizeof(PhdrType));
    // set to zero from current position to end of segments
    auto updated_shdr_offset =
        align_higher(m_data_seg_hdr.offset + m_data_seg_hdr.filesz,
                     m_data_seg_hdr.align);
    fill_with_zeros(outfile, m_code_seg_hdr.offset, updated_shdr_offset);

    // now copy the original shdrs
    outfile.write(m_orig_shdrs_region.base_pos, m_orig_shdrs_region.size);

    // fixup ehdr
    EhdrType fixed_ehdr = *m_orig_ehdr;
    fixed_ehdr.phoff = updated_phdr_offset;
    fixed_ehdr.shoff = updated_shdr_offset;
    fixed_ehdr.phnum += 2;
    outfile.seekp(0);
    outfile.write((const char *) &fixed_ehdr, sizeof(EhdrType));

    size_t phdrs_region_size = m_orig_phdrs_region.size + 2 * sizeof(PhdrType);

    PhdrType fixed_load_seg_hdr = *((PhdrType *) (infile.get_loader()->load(
        m_orig_ehdr->phoff + load_seg_idx * sizeof(PhdrType), sizeof(PhdrType))));

    fixed_load_seg_hdr.filesz += phdrs_region_size;
    fixed_load_seg_hdr.memsz += phdrs_region_size;

    outfile.seekp(fixed_ehdr.phoff + load_seg_idx * sizeof(PhdrType));
    outfile.write((const char *) &fixed_load_seg_hdr, sizeof(fixed_load_seg_hdr));

    if (!has_phdr_segment(infile)) {
        return;
    }
    // fixup phdr segment, assumes that it is the first header in phdrs
    PhdrType phdr_seg_hdr =
        *(Phdr<> *) (infile.get_loader()->load(m_orig_ehdr->phoff,
                                               sizeof(PhdrType)));
    DCHECK(phdr_seg_hdr.type == pt::phdr);
    phdr_seg_hdr.filesz = phdr_seg_hdr.filesz + 2 * sizeof(PhdrType);
    phdr_seg_hdr.memsz = phdr_seg_hdr.filesz;
    phdr_seg_hdr.offset = fixed_ehdr.phoff;
    phdr_seg_hdr.vaddr =
        fixed_load_seg_hdr.vaddr + fixed_load_seg_hdr.memsz - phdr_seg_hdr.memsz;
    phdr_seg_hdr.paddr = phdr_seg_hdr.vaddr;

    outfile.seekp(fixed_ehdr.phoff);
    outfile.write((const char *) &phdr_seg_hdr, sizeof(PhdrType));
}

void
ElfExtender::Impl::extend_relocating_phdrs_to_end(const elf::elf &infile,
                                                  std::ofstream &outfile)
{
    // place PHDRS to end of file (before SHDRS) and add extra code and
    // data segments.
    using namespace elf;

    size_t phdrs_region_size = m_orig_phdrs_region.size + 2 * sizeof(PhdrType);

    // new segments will be written in place of original shdrs
    m_code_seg_hdr.offset =
        align_higher(m_orig_main_region.size + phdrs_region_size,
                     m_code_seg_hdr.align);

    m_data_seg_hdr.offset =
        align_higher(m_code_seg_hdr.offset + m_code_seg_hdr.filesz,
                     m_data_seg_hdr.align);

    // copy everything till original shdr
    outfile.write(m_orig_main_region.base_pos, m_orig_main_region.size);

    // write original phdrs to new place
    outfile.write(m_orig_phdrs_region.base_pos, m_orig_phdrs_region.size);
    // append extension phdrs
    outfile.write((const char *) &m_code_seg_hdr, sizeof(PhdrType));
    outfile.write((const char *) &m_data_seg_hdr, sizeof(PhdrType));

    auto updated_shdr_offset =
        align_higher(m_data_seg_hdr.offset + m_data_seg_hdr.filesz,
                     m_data_seg_hdr.align);
    fill_with_zeros(outfile, m_code_seg_hdr.offset, updated_shdr_offset);

    // now copy the original shdrs
    outfile.write(m_orig_shdrs_region.base_pos, m_orig_shdrs_region.size);

    // fixup ehdr
    EhdrType fixed_ehdr = *m_orig_ehdr;
    fixed_ehdr.phoff = m_orig_ehdr->shoff;
    fixed_ehdr.shoff = updated_shdr_offset;
    fixed_ehdr.phnum += 2;
    outfile.seekp(0);
    outfile.write((const char *) &fixed_ehdr, sizeof(EhdrType));

    if (!has_phdr_segment(infile)) {
        return;
    }

    unsigned seg_idx;
    const segment *seg_p;
    std::tie(seg_idx, seg_p) = get_first_loadable_segment(infile);

    // fixup phdr segment, assumes that it is the first header in phdrs
    auto phdr_seg_hdr =
        *(PhdrType *) (infile.get_loader()->load(m_orig_ehdr->phoff,
                                                 sizeof(PhdrType)));
    DCHECK(phdr_seg_hdr.type == pt::phdr);
    phdr_seg_hdr.offset = m_orig_ehdr->shoff;
    phdr_seg_hdr.filesz = phdrs_region_size;
    phdr_seg_hdr.memsz = phdr_seg_hdr.filesz;
    phdr_seg_hdr.vaddr =
        phdr_seg_hdr.offset - seg_p->get_hdr().offset + seg_p->get_hdr().vaddr;

    phdr_seg_hdr.paddr = phdr_seg_hdr.vaddr;

    outfile.seekp(phdr_seg_hdr.offset);
    outfile.write((const char *) &phdr_seg_hdr, sizeof(PhdrType));

    // fixup header of first load segment
    auto fixup_seg_hdr =
        *(PhdrType *) (infile.get_loader()->load(
            m_orig_ehdr->phoff + seg_idx * sizeof(PhdrType), sizeof(PhdrType)));
    fixup_seg_hdr.filesz =
        phdr_seg_hdr.offset - fixup_seg_hdr.offset + phdrs_region_size;
    fixup_seg_hdr.memsz = fixup_seg_hdr.filesz;

    outfile.seekp(phdr_seg_hdr.offset + seg_idx * sizeof(PhdrType));
    outfile.write((const char *) &fixup_seg_hdr, sizeof(fixup_seg_hdr));
}

void
ElfExtender::Impl::extend_removing_phdrs_segment(std::ofstream &outfile)
{
    using namespace elf;

    size_t phdrs_region_size = m_orig_phdrs_region.size + sizeof(PhdrType);

    // new segments will be written in place of original shdrs
    m_code_seg_hdr.offset =
        align_higher(m_orig_main_region.size + phdrs_region_size,
                     m_code_seg_hdr.align);

    m_data_seg_hdr.offset =
        align_higher(m_code_seg_hdr.offset + m_code_seg_hdr.filesz,
                     m_data_seg_hdr.align);

    // copy everything till original shdr
    outfile.write(m_orig_main_region.base_pos, m_orig_main_region.size);

    // write original phdrs to new place (except for PHDR segment)
    outfile.write(m_orig_phdrs_region.base_pos + sizeof(PhdrType),
                  m_orig_phdrs_region.size - sizeof(PhdrType));

    // append extension phdrs
    outfile.write((const char *) &m_code_seg_hdr, sizeof(PhdrType));
    outfile.write((const char *) &m_data_seg_hdr, sizeof(PhdrType));

    auto updated_shdr_offset =
        align_higher(m_data_seg_hdr.offset + m_data_seg_hdr.filesz,
                     m_data_seg_hdr.align);
    fill_with_zeros(outfile, m_code_seg_hdr.offset, updated_shdr_offset);

    // now copy the original shdrs
    outfile.write(m_orig_shdrs_region.base_pos, m_orig_shdrs_region.size);

    // fixup ehdr
    EhdrType fixed_ehdr = *m_orig_ehdr;
    fixed_ehdr.phoff = m_orig_ehdr->shoff;
    fixed_ehdr.shoff = updated_shdr_offset;
    fixed_ehdr.phnum += 1;
    outfile.seekp(0);
    outfile.write((const char *) &fixed_ehdr, sizeof(EhdrType));
}

//==============================================================================

ElfExtender::ElfExtender() : m_code_seg_size(0), m_data_seg_size(0)
{ }

ElfExtender::ElfExtender(size_t code_seg_size, size_t data_seg_size)
    : m_code_seg_size(code_seg_size), m_data_seg_size(data_seg_size)
{ }

void
ElfExtender::code_segment_size(size_t size)
{
    m_code_seg_size = size;
}

void
ElfExtender::data_segment_size(size_t size)
{
    m_data_seg_size = size;
}

bool
ElfExtender::extend(sstring_view input_file, sstring_view output_file)
{
    using namespace elf;
    using namespace std;

    FileAccessor reader;
    reader.open(input_file.data(), FileAccess::kRO);

    ::elf::elf elf_file(create_mmap_loader(reader.fd()));

    if (!Impl::validate_input_file(elf_file)) {
        throw ElfExtenderException("malformed or unsupported elf file");
    }

    if (m_code_seg_size == 0 || m_data_seg_size == 0) {
        throw ElfExtenderException("elf: invalid segment size");
    }

    ofstream out_file;
    out_file.open(output_file.data(), ios::binary | ios::out);

    Impl impl;
    impl.init(this, elf_file);

    if (can_patch_existing_phdrs(elf_file)) {
        LOG(INFO) << "elf: proceeding with assisted patching (begin) ...";
        impl.extend_and_patch_existing_phdrs(elf_file, out_file);
    } else if (can_relocate_phdrs_to_middle(elf_file)) {
        LOG(INFO) << "elf: proceeding with generic patching (middle)...";
        impl.extend_relocating_phdrs_to_middle(elf_file, out_file);
    } else if (can_relocate_phdrs_to_end(elf_file)) {
        LOG(INFO) << "elf: proceeding with generic patching (end) ...";
        impl.extend_relocating_phdrs_to_end(elf_file, out_file);
    } else if (can_eliminate_phdrs_segment(elf_file)) {
        LOG(INFO) << "elf: eliminating phdr segment and proceeding with "
                  << "generic patching (end) ...";
        impl.extend_removing_phdrs_segment(out_file);
    } else {
        LOG(WARNING) << "elf: file could not be extended!";
        return false;
    }
    LOG(INFO) << "elf: file extended successfully";
    return true;
}

//===============================================

ElfExtenderException::ElfExtenderException(const std::string &what_arg) :
    std::logic_error(what_arg)
{ }

ElfExtenderException::ElfExtenderException(const char *what_arg) :
    std::logic_error(what_arg)
{ }

} // bcov
