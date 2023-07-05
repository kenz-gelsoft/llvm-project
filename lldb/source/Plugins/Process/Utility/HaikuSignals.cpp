//===-- HaikuSignals.cpp --------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "HaikuSignals.h"

using namespace lldb_private;

HaikuSignals::HaikuSignals() : UnixSignals() { Reset(); }

void HaikuSignals::Reset() {
  m_signals.clear();
  // clang-format off
  //        SIGNO   NAME            SUPPRESS  STOP    NOTIFY  DESCRIPTION
  //        ======  ==============  ========  ======  ======  ===================================================
  AddSignal(1,      "SIGHUP",       false,    true,   true,   "hangup -- tty is gone!");
  AddSignal(2,      "SIGINT",       true,     true,   true,   "interrupt");
  AddSignal(3,      "SIGQUIT",      false,    true,   true,   "`quit' special character typed in tty");
  AddSignal(4,      "SIGILL",       false,    true,   true,   "illegal instruction");
  AddSignal(5,      "SIGCHLD",      false,    false,  true,   "child process exited", "SIGCLD");
  AddSignal(6,      "SIGABRT",      false,    true,   true,   "abort() called, dont' catch", "SIGIOT");
  AddSignal(7,      "SIGPIPE",      false,    true,   true,   "write to a pipe w/no readers");
  AddSignal(8,      "SIGFPE",       false,    true,   true,   "floating point exception");
  AddSignal(9,      "SIGKILL",      false,    true,   true,   "kill a team (not catchable)");
  AddSignal(10,     "SIGSTOP",      true,     true,   true,   "suspend a thread (not catchable)");
  AddSignal(11,     "SIGSEGV",      false,    true,   true,   "segmentation violation (read: invalid pointer)");
  AddSignal(12,     "SIGCONT",      false,    false,  true,   "continue execution if suspended");
  AddSignal(13,     "SIGTSTP",      false,    true,   true,   "`stop' special character typed in tty");
  AddSignal(14,     "SIGALRM",      false,    false,  false,  "an alarm has gone off (see alarm())");
  AddSignal(15,     "SIGTERM",      false,    true,   true,   "termination requested");
  AddSignal(16,     "SIGTTIN",      false,    true,   true,   "read of tty from bg process");
  AddSignal(17,     "SIGTTOU",      false,    true,   true,   "write to tty from bg process");
  AddSignal(18,     "SIGUSR1",      false,    true,   true,   "app defined signal 1");
  AddSignal(19,     "SIGUSR2",      false,    true,   true,   "app defined signal 2");
  AddSignal(20,     "SIGWINCH",     false,    true,   true,   "tty window size changed");
  AddSignal(21,     "SIGKILLTHR",   false,    true,   true,   "be specific: kill just the thread, not team");
  AddSignal(22,     "SIGTRAP",      true,     true,   true,   "Trace/breakpoint trap");
  AddSignal(23,     "SIGPOLL",      false,    true,   true,   "Pollable event", "SIGIO");
  AddSignal(24,     "SIGPROF",      false,    false,  false,  "Profiling timer expired");
  AddSignal(25,     "SIGSYS",       false,    true,   true,   "Bad system call");
  AddSignal(26,     "SIGURG",       false,    true,   true,   "High bandwidth data is available at socket");
  AddSignal(27,     "SIGVTALRM",    false,    true,   true,   "Virtual timer expired");
  AddSignal(28,     "SIGXCPU",      false,    true,   true,   "CPU time limit exceeded");
  AddSignal(29,     "SIGXFSZ",      false,    true,   true,   "File size limit exceeded");
  AddSignal(30,     "SIGBUS",       false,    true,   true,   "access to undefined portion of a memory object");
  AddSignal(31,     "SIGRESERVED1", false,    false,  false,  "reserved for future use");
  AddSignal(32,     "SIGRESERVED2", false,    false,  false,  "reserved for future use");
  // clang-format on
}
