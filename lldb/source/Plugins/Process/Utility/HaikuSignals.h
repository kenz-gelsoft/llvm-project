//===-- HaikuSignals.h ------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_SOURCE_PLUGINS_PROCESS_UTILITY_HAIKUSIGNALS_H
#define LLDB_SOURCE_PLUGINS_PROCESS_UTILITY_HAIKUSIGNALS_H

#include "lldb/Target/UnixSignals.h"

namespace lldb_private {

/// Haiku specific set of Unix signals.
class HaikuSignals : public UnixSignals {
public:
  HaikuSignals();

private:
  void Reset() override;
};

} // namespace lldb_private

#endif // LLDB_SOURCE_PLUGINS_PROCESS_UTILITY_HAIKUSIGNALS_H
