//===-- RegisterContextHaiku_x86_64.cpp -----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "RegisterContextHaiku_x86_64.h"
#include "RegisterContextHaiku_i386.h"
#include "RegisterContextPOSIX_x86.h"
#include "llvm/ADT/Triple.h"
#include "llvm/Support/Compiler.h"
#include <cassert>
#include <cstddef>

using namespace lldb_private;
using namespace lldb;

namespace {

// headers/posix/arch/x86_64/signal.h
/*
 * Architecture-specific structure passed to signal handlers
 */


struct x86_64_fp_register {
	unsigned char value[10];
	unsigned char reserved[6];
};


struct x86_64_xmm_register {
	unsigned char value[16];
};


// The layout of this struct matches the one used by the FXSAVE instruction
struct fpu_state {
	unsigned short		control;
	unsigned short		status;
	unsigned short		tag;
	unsigned short		opcode;
	unsigned long		rip;
	unsigned long		rdp;
	unsigned int		mxcsr;
	unsigned int		mscsr_mask;

	union {
		struct x86_64_fp_register fp[8];
		struct x86_64_fp_register mmx[8];
	};

	struct x86_64_xmm_register		xmm[16];
	unsigned char		_reserved_416_511[96];
};


struct xstate_hdr {
	unsigned long		bv;
	unsigned long		xcomp_bv;
	unsigned char		_reserved[48];
};


// The layout of this struct matches the one used by the FXSAVE instruction on
// an AVX CPU
struct savefpu {
	struct fpu_state			fp_fxsave;
	struct xstate_hdr			fp_xstate;
	struct x86_64_xmm_register	fp_ymm[16];
		// The high half of the YMM registers, to combine with the low half
		// found in fp_fxsave.xmm
};


// headers/os/arch/x86_64/arch_debugger.h
typedef struct x86_64_debug_cpu_state {
	struct savefpu	extended_registers;

	uint64_t	gs;
	uint64_t	fs;
	uint64_t	es;
	uint64_t	ds;
	uint64_t	r15;
	uint64_t	r14;
	uint64_t	r13;
	uint64_t	r12;
	uint64_t	r11;
	uint64_t	r10;
	uint64_t	r9;
	uint64_t	r8;
	uint64_t	rbp;
	uint64_t	rsi;
	uint64_t	rdi;
	uint64_t	rdx;
	uint64_t	rcx;
	uint64_t	rbx;
	uint64_t	rax;
	uint64_t	vector;
	uint64_t	error_code;
	uint64_t	rip;
	uint64_t	cs;
	uint64_t	rflags;
	uint64_t	rsp;
	uint64_t	ss;
} __attribute__((aligned(16))) GPR;

#define GPR_OFFSET(regname) (LLVM_EXTENSION offsetof(GPR, regname))
#define DEFINE_GPR(reg, alt, kind1, kind2, kind3, kind4)                       \
  {                                                                            \
#reg, alt, sizeof(((GPR *)nullptr)->reg), GPR_OFFSET(reg), eEncodingUint,  \
        eFormatHex,                                                            \
        {kind1, kind2, kind3, kind4, lldb_##reg##_x86_64 }, nullptr, nullptr,  \
         nullptr, 0                                                            \
  }

// clang-format off
static RegisterInfo g_register_infos_x86_64[] = {
// General purpose registers     EH_Frame              DWARF                 Generic                     Process Plugin
//  ===========================  ==================    ================      =========================   ====================
    DEFINE_GPR(rax,    nullptr,  dwarf_rax_x86_64,     dwarf_rax_x86_64,     LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(rbx,    nullptr,  dwarf_rbx_x86_64,     dwarf_rbx_x86_64,     LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(rcx,    "arg4",   dwarf_rcx_x86_64,     dwarf_rcx_x86_64,     LLDB_REGNUM_GENERIC_ARG4,   LLDB_INVALID_REGNUM),
    DEFINE_GPR(rdx,    "arg3",   dwarf_rdx_x86_64,     dwarf_rdx_x86_64,     LLDB_REGNUM_GENERIC_ARG3,   LLDB_INVALID_REGNUM),
    DEFINE_GPR(rdi,    "arg1",   dwarf_rdi_x86_64,     dwarf_rdi_x86_64,     LLDB_REGNUM_GENERIC_ARG1,   LLDB_INVALID_REGNUM),
    DEFINE_GPR(rsi,    "arg2",   dwarf_rsi_x86_64,     dwarf_rsi_x86_64,     LLDB_REGNUM_GENERIC_ARG2,   LLDB_INVALID_REGNUM),
    DEFINE_GPR(rbp,    "fp",     dwarf_rbp_x86_64,     dwarf_rbp_x86_64,     LLDB_REGNUM_GENERIC_FP,     LLDB_INVALID_REGNUM),
    DEFINE_GPR(rsp,    "sp",     dwarf_rsp_x86_64,     dwarf_rsp_x86_64,     LLDB_REGNUM_GENERIC_SP,     LLDB_INVALID_REGNUM),
    DEFINE_GPR(r8,     "arg5",   dwarf_r8_x86_64,      dwarf_r8_x86_64,      LLDB_REGNUM_GENERIC_ARG5,   LLDB_INVALID_REGNUM),
    DEFINE_GPR(r9,     "arg6",   dwarf_r9_x86_64,      dwarf_r9_x86_64,      LLDB_REGNUM_GENERIC_ARG6,   LLDB_INVALID_REGNUM),
    DEFINE_GPR(r10,    nullptr,  dwarf_r10_x86_64,     dwarf_r10_x86_64,     LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(r11,    nullptr,  dwarf_r11_x86_64,     dwarf_r11_x86_64,     LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(r12,    nullptr,  dwarf_r12_x86_64,     dwarf_r12_x86_64,     LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(r13,    nullptr,  dwarf_r13_x86_64,     dwarf_r13_x86_64,     LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(r14,    nullptr,  dwarf_r14_x86_64,     dwarf_r14_x86_64,     LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(r15,    nullptr,  dwarf_r15_x86_64,     dwarf_r15_x86_64,     LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(rip,    "pc",     dwarf_rip_x86_64,     dwarf_rip_x86_64,     LLDB_REGNUM_GENERIC_PC,     LLDB_INVALID_REGNUM),
    DEFINE_GPR(rflags, "flags",  dwarf_rflags_x86_64,  dwarf_rflags_x86_64,  LLDB_REGNUM_GENERIC_FLAGS,  LLDB_INVALID_REGNUM),
    DEFINE_GPR(cs,     nullptr,  dwarf_cs_x86_64,      dwarf_cs_x86_64,      LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(fs,     nullptr,  dwarf_fs_x86_64,      dwarf_fs_x86_64,      LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(gs,     nullptr,  dwarf_gs_x86_64,      dwarf_gs_x86_64,      LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(ss,     nullptr,  dwarf_ss_x86_64,      dwarf_ss_x86_64,      LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(ds,     nullptr,  dwarf_ds_x86_64,      dwarf_ds_x86_64,      LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM),
    DEFINE_GPR(es,     nullptr,  dwarf_es_x86_64,      dwarf_es_x86_64,      LLDB_INVALID_REGNUM,        LLDB_INVALID_REGNUM)
};

// clang-format on

} // namespace

// Include RegisterInfos_x86_64 to declare our g_register_infos_x86_64
// structure.
//#define DECLARE_REGISTER_INFOS_X86_64_STRUCT
//#include "RegisterInfos_x86_64.h"
//#undef DECLARE_REGISTER_INFOS_X86_64_STRUCT

static std::vector<lldb_private::RegisterInfo> &GetPrivateRegisterInfoVector() {
  static std::vector<lldb_private::RegisterInfo> g_register_infos;
  return g_register_infos;
}

static const RegisterInfo *
GetRegisterInfo_i386(const lldb_private::ArchSpec &arch) {
  std::vector<lldb_private::RegisterInfo> &g_register_infos =
      GetPrivateRegisterInfoVector();

  // Allocate RegisterInfo only once
  if (g_register_infos.empty()) {
    // Copy the register information from base class
    std::unique_ptr<RegisterContextHaiku_i386> reg_interface(
        new RegisterContextHaiku_i386(arch));
    const RegisterInfo *base_info = reg_interface->GetRegisterInfo();
    g_register_infos.insert(g_register_infos.end(), &base_info[0],
                            &base_info[k_num_registers_i386]);

// Include RegisterInfos_x86_64 to update the g_register_infos structure
//  with x86_64 offsets.
//#define UPDATE_REGISTER_INFOS_I386_STRUCT_WITH_X86_64_OFFSETS
//#include "RegisterInfos_x86_64.h"
//#undef UPDATE_REGISTER_INFOS_I386_STRUCT_WITH_X86_64_OFFSETS
  }

  return &g_register_infos[0];
}

static const RegisterInfo *
PrivateGetRegisterInfoPtr(const lldb_private::ArchSpec &target_arch) {
  switch (target_arch.GetMachine()) {
  case llvm::Triple::x86:
    return GetRegisterInfo_i386(target_arch);
  case llvm::Triple::x86_64:
    return g_register_infos_x86_64;
  default:
    assert(false && "Unhandled target architecture.");
    return nullptr;
  }
}

static uint32_t
PrivateGetRegisterCount(const lldb_private::ArchSpec &target_arch) {
  switch (target_arch.GetMachine()) {
  case llvm::Triple::x86: {
    assert(!GetPrivateRegisterInfoVector().empty() &&
           "i386 register info not yet filled.");
    return static_cast<uint32_t>(GetPrivateRegisterInfoVector().size());
  }
  case llvm::Triple::x86_64:
    return static_cast<uint32_t>(sizeof(g_register_infos_x86_64) /
                                 sizeof(g_register_infos_x86_64[0]));
  default:
    assert(false && "Unhandled target architecture.");
    return 0;
  }
}

static uint32_t
PrivateGetUserRegisterCount(const lldb_private::ArchSpec &target_arch) {
  switch (target_arch.GetMachine()) {
  case llvm::Triple::x86:
    return static_cast<uint32_t>(k_num_user_registers_i386);
  case llvm::Triple::x86_64:
    return static_cast<uint32_t>(k_num_user_registers_x86_64);
  default:
    assert(false && "Unhandled target architecture.");
    return 0;
  }
}

RegisterContextHaiku_x86_64::RegisterContextHaiku_x86_64(
    const ArchSpec &target_arch)
    : lldb_private::RegisterInfoInterface(target_arch),
      m_register_info_p(PrivateGetRegisterInfoPtr(target_arch)),
      m_register_count(PrivateGetRegisterCount(target_arch)),
      m_user_register_count(PrivateGetUserRegisterCount(target_arch)) {}

size_t RegisterContextHaiku_x86_64::GetGPRSize() const { return sizeof(GPR); }

const RegisterInfo *RegisterContextHaiku_x86_64::GetRegisterInfo() const {
  return m_register_info_p;
}

uint32_t RegisterContextHaiku_x86_64::GetRegisterCount() const {
  return m_register_count;
}

uint32_t RegisterContextHaiku_x86_64::GetUserRegisterCount() const {
  return m_user_register_count;
}
