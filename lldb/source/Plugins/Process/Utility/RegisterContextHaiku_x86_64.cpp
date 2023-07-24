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

// headers/os/arch/x86_64/arch_debugger.h
#include <posix/arch/x86_64/signal.h>


struct x86_64_debug_cpu_state {
	struct savefpu	extended_registers;

	uint64	gs;
	uint64	fs;
	uint64	es;
	uint64	ds;
	uint64	r15;
	uint64	r14;
	uint64	r13;
	uint64	r12;
	uint64	r11;
	uint64	r10;
	uint64	r9;
	uint64	r8;
	uint64	rbp;
	uint64	rsi;
	uint64	rdi;
	uint64	rdx;
	uint64	rcx;
	uint64	rbx;
	uint64	rax;
	uint64	vector;
	uint64	error_code;
	uint64	rip;
	uint64	cs;
	uint64	rflags;
	uint64	rsp;
	uint64	ss;
} __attribute__((aligned(16)));


// Include RegisterInfos_x86_64 to declare our g_register_infos_x86_64
// structure.
#define DECLARE_REGISTER_INFOS_X86_64_STRUCT
#include "RegisterInfos_x86_64.h"
#undef DECLARE_REGISTER_INFOS_X86_64_STRUCT

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
#define UPDATE_REGISTER_INFOS_I386_STRUCT_WITH_X86_64_OFFSETS
#include "RegisterInfos_x86_64.h"
#undef UPDATE_REGISTER_INFOS_I386_STRUCT_WITH_X86_64_OFFSETS
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
