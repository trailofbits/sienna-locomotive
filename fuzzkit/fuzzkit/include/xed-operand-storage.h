/*BEGIN_LEGAL 
Copyright 2004-2016 Intel Corporation. Use of this code is subject to
the terms and conditions of the What If Pre-Release License Agreement,
which is available here:
https://software.intel.com/en-us/articles/what-if-pre-release-license-agreement
or refer to the LICENSE.txt file.
END_LEGAL */
/// @file xed-operand-storage.h

// This file was automatically generated.
// Do not edit this file.

#if !defined(_XED_OPERAND_STORAGE_H_)
# define _XED_OPERAND_STORAGE_H_
#include "xed-chip-enum.h"
#include "xed-error-enum.h"
#include "xed-iclass-enum.h"
#include "xed-reg-enum.h"
#include "xed-operand-element-type-enum.h"
typedef struct xed_operand_storage_s {
    xed_uint64_t disp;
    xed_uint64_t uimm0;
    xed_uint16_t mem_width;
    xed_uint16_t iclass;
    xed_uint16_t base0;
    xed_uint16_t base1;
    xed_uint16_t element_size;
    xed_uint16_t index;
    xed_uint16_t outreg;
    xed_uint16_t reg0;
    xed_uint16_t reg1;
    xed_uint16_t reg2;
    xed_uint16_t reg3;
    xed_uint16_t reg4;
    xed_uint16_t reg5;
    xed_uint16_t reg6;
    xed_uint16_t reg7;
    xed_uint16_t reg8;
    xed_uint16_t seg0;
    xed_uint16_t seg1;
    xed_uint8_t brdisp_width;
    xed_uint8_t disp_width;
    xed_uint8_t ild_seg;
    xed_uint8_t imm1_bytes;
    xed_uint8_t imm_width;
    xed_uint8_t max_bytes;
    xed_uint8_t modrm_byte;
    xed_uint8_t nominal_opcode;
    xed_uint8_t nprefixes;
    xed_uint8_t nrexes;
    xed_uint8_t nseg_prefixes;
    xed_uint8_t pos_disp;
    xed_uint8_t pos_imm;
    xed_uint8_t pos_imm1;
    xed_uint8_t pos_modrm;
    xed_uint8_t pos_nominal_opcode;
    xed_uint8_t pos_sib;
    xed_uint8_t uimm1;
    xed_uint8_t chip;
    xed_uint8_t need_memdisp;
    xed_uint8_t bcast;
    xed_uint8_t error;
    xed_uint8_t esrc;
    xed_uint8_t map;
    xed_uint8_t nelem;
    xed_uint8_t scale;
    xed_uint8_t type;
    xed_uint8_t hint;
    xed_uint8_t mask;
    xed_uint8_t reg;
    xed_uint8_t rm;
    xed_uint8_t roundc;
    xed_uint8_t seg_ovd;
    xed_uint8_t sibbase;
    xed_uint8_t sibindex;
    xed_uint8_t srm;
    xed_uint8_t vexdest210;
    xed_uint8_t vexvalid;
    xed_uint8_t default_seg;
    xed_uint8_t easz;
    xed_uint8_t eosz;
    xed_uint8_t first_f2f3;
    xed_uint8_t has_modrm;
    xed_uint8_t last_f2f3;
    xed_uint8_t llrc;
    xed_uint8_t mod;
    xed_uint8_t mode;
    xed_uint8_t rep;
    xed_uint8_t sibscale;
    xed_uint8_t smode;
    xed_uint8_t vex_prefix;
    xed_uint8_t vl;
    xed_uint8_t agen;
    xed_uint8_t amd3dnow;
    xed_uint8_t asz;
    xed_uint8_t bcrc;
    xed_uint8_t df32;
    xed_uint8_t df64;
    xed_uint8_t dummy;
    xed_uint8_t encoder_preferred;
    xed_uint8_t esrc3;
    xed_uint8_t evexrr;
    xed_uint8_t has_sib;
    xed_uint8_t ild_f2;
    xed_uint8_t ild_f3;
    xed_uint8_t imm0;
    xed_uint8_t imm0signed;
    xed_uint8_t imm1;
    xed_uint8_t lock;
    xed_uint8_t lzcnt;
    xed_uint8_t mem0;
    xed_uint8_t mem1;
    xed_uint8_t modep5;
    xed_uint8_t modep55c;
    xed_uint8_t mode_first_prefix;
    xed_uint8_t modrm;
    xed_uint8_t mpxmode;
    xed_uint8_t needrex;
    xed_uint8_t norex;
    xed_uint8_t no_scale_disp8;
    xed_uint8_t osz;
    xed_uint8_t out_of_bytes;
    xed_uint8_t p4;
    xed_uint8_t prefix66;
    xed_uint8_t ptr;
    xed_uint8_t realmode;
    xed_uint8_t relbr;
    xed_uint8_t rex;
    xed_uint8_t rexb;
    xed_uint8_t rexr;
    xed_uint8_t rexrr;
    xed_uint8_t rexw;
    xed_uint8_t rexx;
    xed_uint8_t sae;
    xed_uint8_t sib;
    xed_uint8_t skip_osz;
    xed_uint8_t tzcnt;
    xed_uint8_t ubit;
    xed_uint8_t using_default_segment0;
    xed_uint8_t using_default_segment1;
    xed_uint8_t vexdest3;
    xed_uint8_t vexdest4;
    xed_uint8_t vex_c4;
    xed_uint8_t zeroing;
} xed_operand_storage_t;
#endif
