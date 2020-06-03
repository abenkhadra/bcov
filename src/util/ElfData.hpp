/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#pragma once

#include "libelfin/elf/data.hh"

// info needed to parse relocation symbols

#define R_X86_64_GLOB_DAT   6       /* Create GOT entry */
#define R_X86_64_JUMP_SLOT  7       /* Create PLT entry */

#define ELF64_R_SYM(i)((i) >> 32U)
#define ELF64_R_TYPE(i)((i) & 0xffffffffUL)

// info needed to parse the dynamic segment
#define DT_NULL        0
#define DT_NEEDED    1
#define DT_PLTRELSZ    2
#define DT_PLTGOT    3
#define DT_HASH        4
#define DT_STRTAB    5
#define DT_SYMTAB    6
#define DT_RELA        7
#define DT_RELASZ    8
#define DT_RELAENT    9
#define DT_STRSZ    10
#define DT_SYMENT    11
#define DT_INIT        12
#define DT_FINI        13
#define DT_SONAME    14
#define DT_RPATH    15
#define DT_SYMBOLIC    16
#define DT_REL            17
#define DT_RELSZ    18
#define DT_RELENT    19
#define DT_PLTREL    20
#define DT_DEBUG    21
#define DT_TEXTREL    22
#define DT_JMPREL    23
#define DT_ENCODING    32
#define OLD_DT_LOOS    0x60000000
#define DT_LOOS        0x6000000d
#define DT_HIOS        0x6ffff000
#define DT_VALRNGLO    0x6ffffd00
#define DT_VALRNGHI    0x6ffffdff
#define DT_ADDRRNGLO    0x6ffffe00
#define DT_ADDRRNGHI    0x6ffffeff
#define DT_VERSYM    0x6ffffff0
#define DT_RELACOUNT    0x6ffffff9
#define DT_RELCOUNT    0x6ffffffa
#define DT_FLAGS_1    0x6ffffffb
#define DT_VERDEF    0x6ffffffc
#define    DT_VERDEFNUM    0x6ffffffd
#define DT_VERNEED    0x6ffffffe
#define    DT_VERNEEDNUM    0x6fffffff
#define OLD_DT_HIOS     0x6fffffff
#define DT_LOPROC    0x70000000
#define DT_HIPROC    0x7fffffff

#define GOT_SEC_NAME ".got"
#define GOT_PLT_SEC_NAME ".got.plt"
#define RELA_PLT_SEC_NAME ".rela.plt"
#define RELA_DYN_SEC_NAME ".rela.dyn"

typedef struct {
    elf::Elf64::Addr r_offset;
    uint64_t r_info;
    int64_t r_addend;
} Elf64_Rela;

typedef struct {
    elf::Elf64::Sxword d_tag;        /* entry tag value */
    union {
        elf::Elf64::Xword d_val;
        elf::Elf64::Addr d_ptr;
    } d_un;
} Elf64_Dyn;

const char *to_string(elf::Elf64::Sxword d_tag);
