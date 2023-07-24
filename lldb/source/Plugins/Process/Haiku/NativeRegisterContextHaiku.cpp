//===-- NativeRegisterContextHaiku.cpp ------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "NativeRegisterContextHaiku.h"

#include "Plugins/Process/Haiku/NativeProcessHaiku.h"

#include "lldb/Host/common/NativeProcessProtocol.h"

using namespace lldb_private;
using namespace lldb_private::process_haiku;

// clang-format off
#include <sys/types.h>
#ifndef __HAIKU__
#include <sys/ptrace.h>
#endif
// clang-format on

NativeProcessHaiku &NativeRegisterContextHaiku::GetProcess() {
  return static_cast<NativeProcessHaiku &>(m_thread.GetProcess());
}

::pid_t NativeRegisterContextHaiku::GetProcessPid() {
  return GetProcess().GetID();
}
