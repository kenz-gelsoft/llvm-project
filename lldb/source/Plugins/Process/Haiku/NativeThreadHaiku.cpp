//===-- NativeThreadHaiku.cpp ---------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "NativeThreadHaiku.h"
#include "NativeRegisterContextHaiku.h"

#include "NativeProcessHaiku.h"

#include "Plugins/Process/POSIX/CrashReason.h"
#include "Plugins/Process/POSIX/ProcessPOSIXLog.h"
#include "lldb/Utility/LLDBAssert.h"
#include "lldb/Utility/RegisterValue.h"
#include "lldb/Utility/State.h"
#include "llvm/Support/Errno.h"

// clang-format off
#include <sys/types.h>
#ifdef __HAIKU__
#include <TeamDebugger.h>
#else
#include <sys/ptrace.h>
#endif
// clang-format on

#include <sstream>

// clang-format off
#include <sys/types.h>
#ifndef __HAIKU__
#include <sys/sysctl.h>
#endif
// clang-format on

using namespace lldb;
using namespace lldb_private;
using namespace lldb_private::process_haiku;

NativeThreadHaiku::NativeThreadHaiku(NativeProcessHaiku &process,
                                       lldb::tid_t tid)
    : NativeThreadProtocol(process, tid), m_state(StateType::eStateInvalid),
      m_stop_info(), m_reg_context_up(
NativeRegisterContextHaiku::CreateHostNativeRegisterContextHaiku(process.GetArchitecture(), *this)
), m_stop_description() {}

Status NativeThreadHaiku::Resume() {
  Status ret;
  status_t error = team_debugger->ContinueThread(GetID());
  if (error != B_OK)
    ret.SetErrorStringWithFormat("Could not ContinueThread: %d", error);
  if (ret.Success())
    SetRunning();
  return ret;
}

Status NativeThreadHaiku::SingleStep() {
  Status ret;
  bool single_step = true;
  status_t error = team_debugger->ContinueThread(GetID(), single_step);
  if (error != B_OK)
    ret.SetErrorStringWithFormat("Could not ContinueThread: %d", error);
  if (ret.Success())
    SetStepping();
  return ret;
}

Status NativeThreadHaiku::Suspend() {
  assert(false);
  Status ret;// = NativeProcessHaiku::PtraceWrapper(PT_SUSPEND, m_process.GetID(),
//                                                  nullptr, GetID());
  if (ret.Success())
    SetStopped();
  return ret;
}

void NativeThreadHaiku::SetStoppedBySignal(uint32_t signo,
                                            const siginfo_t *info) {
  Log *log(ProcessPOSIXLog::GetLogIfAllCategoriesSet(POSIX_LOG_THREAD));
  LLDB_LOG(log, "tid = {0} in called with signal {1}", GetID(), signo);

  SetStopped();

  m_stop_info.reason = StopReason::eStopReasonSignal;
  m_stop_info.details.signal.signo = signo;

  m_stop_description.clear();
  if (info) {
    switch (signo) {
    case SIGSEGV:
    case SIGBUS:
    case SIGFPE:
    case SIGILL:
      const auto reason = GetCrashReason(*info);
      m_stop_description = GetCrashReasonString(reason, *info);
      break;
    }
  }
}

void NativeThreadHaiku::SetStoppedByBreakpoint() {
  SetStopped();
  m_stop_info.reason = StopReason::eStopReasonBreakpoint;
  m_stop_info.details.signal.signo = SIGTRAP;
}

void NativeThreadHaiku::SetStoppedByTrace() {
  SetStopped();
  m_stop_info.reason = StopReason::eStopReasonTrace;
  m_stop_info.details.signal.signo = SIGTRAP;
}

void NativeThreadHaiku::SetStoppedByExec() {
  SetStopped();
  m_stop_info.reason = StopReason::eStopReasonExec;
  m_stop_info.details.signal.signo = SIGTRAP;
}

void NativeThreadHaiku::SetStoppedByWatchpoint(uint32_t wp_index) {
  lldbassert(wp_index != LLDB_INVALID_INDEX32 && "wp_index cannot be invalid");

  std::ostringstream ostr;
  ostr << GetRegisterContext().GetWatchpointAddress(wp_index) << " ";
  ostr << wp_index;

  ostr << " " << GetRegisterContext().GetWatchpointHitAddress(wp_index);

  SetStopped();
  m_stop_description = ostr.str();
  m_stop_info.reason = StopReason::eStopReasonWatchpoint;
  m_stop_info.details.signal.signo = SIGTRAP;
}

void NativeThreadHaiku::SetStoppedWithNoReason() {
  SetStopped();

  m_stop_info.reason = StopReason::eStopReasonNone;
  m_stop_info.details.signal.signo = 0;
}

void NativeThreadHaiku::SetStopped() {
  const StateType new_state = StateType::eStateStopped;
  m_state = new_state;
  m_stop_description.clear();
}

void NativeThreadHaiku::SetRunning() {
  m_state = StateType::eStateRunning;
  m_stop_info.reason = StopReason::eStopReasonNone;
}

void NativeThreadHaiku::SetStepping() {
  m_state = StateType::eStateStepping;
  m_stop_info.reason = StopReason::eStopReasonNone;
}

std::string NativeThreadHaiku::GetName() {
  Log *log(ProcessPOSIXLog::GetLogIfAllCategoriesSet(POSIX_LOG_THREAD));

  int32 cookie = 0;
  thread_info info;
  while (get_next_thread_info(m_process.GetID(), &cookie, &info) == B_OK) {
    if (info.thread == m_tid) {
      return info.name;
    }
  }
  
  LLDB_LOG(log, "unable to find lwp {0} in LWP infos", m_tid);
  return "";
}

lldb::StateType NativeThreadHaiku::GetState() { return m_state; }

bool NativeThreadHaiku::GetStopReason(ThreadStopInfo &stop_info,
                                       std::string &description) {
  Log *log(ProcessPOSIXLog::GetLogIfAllCategoriesSet(POSIX_LOG_THREAD));
  description.clear();

  switch (m_state) {
  case eStateStopped:
  case eStateCrashed:
  case eStateExited:
  case eStateSuspended:
  case eStateUnloaded:
    stop_info = m_stop_info;
    description = m_stop_description;

    return true;

  case eStateInvalid:
  case eStateConnected:
  case eStateAttaching:
  case eStateLaunching:
  case eStateRunning:
  case eStateStepping:
  case eStateDetached:
    LLDB_LOG(log, "tid = {0} in state {1} cannot answer stop reason", GetID(),
             StateAsCString(m_state));
    return false;
  }
  llvm_unreachable("unhandled StateType!");
}

NativeRegisterContextHaiku &NativeThreadHaiku::GetRegisterContext() {
  assert(m_reg_context_up);
  return *m_reg_context_up;
}

Status NativeThreadHaiku::SetWatchpoint(lldb::addr_t addr, size_t size,
                                         uint32_t watch_flags, bool hardware) {
  assert(m_state == eStateStopped);
  if (!hardware)
    return Status("not implemented");
  Status error = RemoveWatchpoint(addr);
  if (error.Fail())
    return error;
  uint32_t wp_index =
      GetRegisterContext().SetHardwareWatchpoint(addr, size, watch_flags);
  if (wp_index == LLDB_INVALID_INDEX32)
    return Status("Setting hardware watchpoint failed.");
  m_watchpoint_index_map.insert({addr, wp_index});
  return Status();
}

Status NativeThreadHaiku::RemoveWatchpoint(lldb::addr_t addr) {
  auto wp = m_watchpoint_index_map.find(addr);
  if (wp == m_watchpoint_index_map.end())
    return Status();
  uint32_t wp_index = wp->second;
  m_watchpoint_index_map.erase(wp);
  if (GetRegisterContext().ClearHardwareWatchpoint(wp_index))
    return Status();
  return Status("Clearing hardware watchpoint failed.");
}

Status NativeThreadHaiku::SetHardwareBreakpoint(lldb::addr_t addr,
                                                 size_t size) {
  assert(m_state == eStateStopped);
  Status error = RemoveHardwareBreakpoint(addr);
  if (error.Fail())
    return error;

  uint32_t bp_index = GetRegisterContext().SetHardwareBreakpoint(addr, size);

  if (bp_index == LLDB_INVALID_INDEX32)
    return Status("Setting hardware breakpoint failed.");

  m_hw_break_index_map.insert({addr, bp_index});
  return Status();
}

Status NativeThreadHaiku::RemoveHardwareBreakpoint(lldb::addr_t addr) {
  auto bp = m_hw_break_index_map.find(addr);
  if (bp == m_hw_break_index_map.end())
    return Status();

  uint32_t bp_index = bp->second;
  if (GetRegisterContext().ClearHardwareBreakpoint(bp_index)) {
    m_hw_break_index_map.erase(bp);
    return Status();
  }

  return Status("Clearing hardware breakpoint failed.");
}

llvm::Error
NativeThreadHaiku::CopyWatchpointsFrom(NativeThreadHaiku &source) {
  llvm::Error s = GetRegisterContext().CopyHardwareWatchpointsFrom(
      source.GetRegisterContext());
  if (!s) {
    m_watchpoint_index_map = source.m_watchpoint_index_map;
    m_hw_break_index_map = source.m_hw_break_index_map;
  }
  return s;
}
