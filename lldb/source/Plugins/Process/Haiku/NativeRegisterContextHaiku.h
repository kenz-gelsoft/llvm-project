//===-- NativeRegisterContextHaiku.h ----------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef lldb_NativeRegisterContextHaiku_h
#define lldb_NativeRegisterContextHaiku_h

#include "lldb/Host/common/NativeThreadProtocol.h"

#include "Plugins/Process/Utility/NativeRegisterContextRegisterInfo.h"

namespace lldb_private {
namespace process_haiku {

class NativeProcessHaiku;

class NativeRegisterContextHaiku
    : public virtual NativeRegisterContextRegisterInfo {
public:
  // This function is implemented in the NativeRegisterContextHaiku_*
  // subclasses to create a new instance of the host specific
  // NativeRegisterContextHaiku. The implementations can't collide as only one
  // NativeRegisterContextHaiku_* variant should be compiled into the final
  // executable.
  static NativeRegisterContextHaiku *
  CreateHostNativeRegisterContextHaiku(const ArchSpec &target_arch,
                                        NativeThreadProtocol &native_thread);
  virtual llvm::Error
  CopyHardwareWatchpointsFrom(NativeRegisterContextHaiku &source) = 0;

protected:
  virtual NativeProcessHaiku &GetProcess();
  virtual ::pid_t GetProcessPid();
};

} // namespace process_haiku
} // namespace lldb_private

#endif // #ifndef lldb_NativeRegisterContextHaiku_h
