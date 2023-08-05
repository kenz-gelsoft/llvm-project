//===-- NativeProcessHaiku.cpp --------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "NativeProcessHaiku.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>

#include "NativeThreadHaiku.h"
#include "Plugins/Process/POSIX/ProcessPOSIXLog.h"
#include "lldb/Core/ModuleSpec.h"
#include "lldb/Host/Host.h"
#include "lldb/Host/HostProcess.h"
#include "lldb/Host/ProcessLaunchInfo.h"
#include "lldb/Host/PseudoTerminal.h"
#include "lldb/Host/ThreadLauncher.h"
#include "lldb/Host/common/NativeRegisterContext.h"
#include "lldb/Host/posix/ProcessLauncherPosixFork.h"
#include "lldb/Symbol/ObjectFile.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/Target.h"
#include "lldb/Utility/LLDBAssert.h"
#include "lldb/Utility/RegisterValue.h"
#include "lldb/Utility/State.h"
#include "lldb/Utility/Status.h"
#include "lldb/Utility/StringExtractor.h"
#include "llvm/ADT/ScopeExit.h"
#include "llvm/Support/Errno.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Threading.h"

#include <TeamDebugger.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

using namespace lldb;
using namespace lldb_private;
using namespace lldb_private::process_haiku;
using namespace llvm;

// Private bits we only need internally.


namespace {

void MaybeLogLaunchInfo(const ProcessLaunchInfo &info) {
  Log *log(ProcessPOSIXLog::GetLogIfAllCategoriesSet(POSIX_LOG_PROCESS));
  if (!log)
    return;

  if (const FileAction *action = info.GetFileActionForFD(STDIN_FILENO))
    LLDB_LOG(log, "setting STDIN to '{0}'", action->GetFileSpec());
  else
    LLDB_LOG(log, "leaving STDIN as is");

  if (const FileAction *action = info.GetFileActionForFD(STDOUT_FILENO))
    LLDB_LOG(log, "setting STDOUT to '{0}'", action->GetFileSpec());
  else
    LLDB_LOG(log, "leaving STDOUT as is");

  if (const FileAction *action = info.GetFileActionForFD(STDERR_FILENO))
    LLDB_LOG(log, "setting STDERR to '{0}'", action->GetFileSpec());
  else
    LLDB_LOG(log, "leaving STDERR as is");

  int i = 0;
  for (const char **args = info.GetArguments().GetConstArgumentVector(); *args;
       ++args, ++i)
    LLDB_LOG(log, "arg {0}: '{1}'", i, *args);
}

void DisplayBytes(StreamString &s, void *bytes, uint32_t count) {
  uint8_t *ptr = (uint8_t *)bytes;
  assert(false);
#if 0
  const uint32_t loop_count = std::min<uint32_t>(DEBUG_PTRACE_MAXBYTES, count);
  for (uint32_t i = 0; i < loop_count; i++) {
    s.Printf("[%x]", *ptr);
    ptr++;
  }
#endif
}

static constexpr unsigned k_ptrace_word_size = sizeof(void *);
static_assert(sizeof(long) >= k_ptrace_word_size,
              "Size of long must be larger than ptrace word size");
} // end of anonymous namespace

// Simple helper function to ensure flags are enabled on the given file
// descriptor.
static Status EnsureFDFlags(int fd, int flags) {
  Status error;

  int status = fcntl(fd, F_GETFL);
  if (status == -1) {
    error.SetErrorToErrno();
    return error;
  }

  if (fcntl(fd, F_SETFL, status | flags) == -1) {
    error.SetErrorToErrno();
    return error;
  }

  return error;
}

std::shared_ptr<BTeamDebugger> lldb_private::process_haiku::team_debugger;

void *NativeProcessHaiku::PortReadThread(void *arg) {
  auto self = reinterpret_cast<NativeProcessHaiku *>(arg);

  lldb::pid_t pid = self->GetID();
  int i = 0;
  while (1) {
    self->MonitorPort(pid, i);
    ++i;
  }
  return nullptr;
}

// Public Static Methods

llvm::Expected<std::unique_ptr<NativeProcessProtocol>>
NativeProcessHaiku::Factory::Launch(ProcessLaunchInfo &launch_info,
                                    NativeDelegate &native_delegate,
                                    MainLoop &mainloop) const {
  Log *log(ProcessPOSIXLog::GetLogIfAllCategoriesSet(POSIX_LOG_PROCESS));

  MaybeLogLaunchInfo(launch_info);

  Status status;
  ::pid_t pid = ProcessLauncherPosixFork()
                    .LaunchProcess(launch_info, status)
                    .GetProcessId();
  LLDB_LOG(log, "pid = {0:x}", pid);
  if (status.Fail()) {
    LLDB_LOG(log, "failed to launch process: {0}", status);
    return status.ToError();
  }

  // Wait for the child process to trap on its call to execve.
  team_debugger = std::make_shared<BTeamDebugger>();
  status_t error = team_debugger->Install(pid);
  if (error != B_OK) {
    LLDB_LOG(log, "Could not install team debugger: error={1}",
             error);
    return llvm::make_error<StringError>("Could not install team debugger",
                                         llvm::inconvertibleErrorCode());
  }
  int32 flags =
      B_TEAM_DEBUG_THREADS |
//      B_TEAM_DEBUG_IMAGES |
//      B_TEAM_DEBUG_POST_SYSCALL |
//      B_TEAM_DEBUG_SIGNALS |
      B_TEAM_DEBUG_TEAM_CREATION;
  error = team_debugger->SetTeamDebuggingFlags(flags);
  if (error < 0) {
    LLDB_LOG(log, "Cloud not set team debugging flags: error={1}",
             error);
    return llvm::make_error<StringError>("Cloud not set team debugging flags",
                                         llvm::inconvertibleErrorCode());
  }
  LLDB_LOG(log, "inferior started, now in stopped state");

  ProcessInstanceInfo Info;
  if (!Host::GetProcessInfo(pid, Info)) {
    return llvm::make_error<StringError>("Cannot get process architecture",
                                         llvm::inconvertibleErrorCode());
  }

  // Set the architecture to the exe architecture.
  LLDB_LOG(log, "pid = {0:x}, detected architecture {1}", pid,
           Info.GetArchitecture().GetArchitectureName());

  return std::unique_ptr<NativeProcessHaiku>(new NativeProcessHaiku(
      pid, launch_info.GetPTY().ReleasePrimaryFileDescriptor(), native_delegate,
      Info.GetArchitecture(), mainloop));
}

llvm::Expected<std::unique_ptr<NativeProcessProtocol>>
NativeProcessHaiku::Factory::Attach(
    lldb::pid_t pid, NativeProcessProtocol::NativeDelegate &native_delegate,
    MainLoop &mainloop) const {
  Log *log(ProcessPOSIXLog::GetLogIfAllCategoriesSet(POSIX_LOG_PROCESS));
  LLDB_LOG(log, "pid = {0:x}", pid);

  // Retrieve the architecture for the running process.
  ProcessInstanceInfo Info;
  if (!Host::GetProcessInfo(pid, Info)) {
    return llvm::make_error<StringError>("Cannot get process architecture",
                                         llvm::inconvertibleErrorCode());
  }

  auto tids_or = NativeProcessHaiku::Attach(pid);

  return std::unique_ptr<NativeProcessHaiku>(new NativeProcessHaiku(
      pid, -1, native_delegate, Info.GetArchitecture(), mainloop));
}

// Public Instance Methods

NativeProcessHaiku::NativeProcessHaiku(::pid_t pid, int terminal_fd,
                                       NativeDelegate &delegate,
                                       const ArchSpec &arch, MainLoop &mainloop)
    : NativeProcessELF(pid, terminal_fd, delegate), m_arch(arch) {
  if (m_terminal_fd != -1) {
    Status status = EnsureFDFlags(m_terminal_fd, O_NONBLOCK);
    assert(status.Success());
  }

  auto maybe_thread = ThreadLauncher::LaunchThread(
      "HaikuPortReader", NativeProcessHaiku::PortReadThread, this);
  assert(maybe_thread);
  m_port_thread = *maybe_thread;

  int32 cookie = 0;
  thread_info info;
  while (get_next_thread_info(GetID(), &cookie, &info) == B_OK) {
    NativeThreadHaiku &thread = AddThread(info.thread);
    thread.SetStoppedBySignal(SIGSTOP);
    ThreadWasCreated(thread);
  }

  // Let our process instance know the thread has stopped.
  SetCurrentThreadID(pid);
  SetState(StateType::eStateStopped, false);
}

llvm::Expected<std::vector<::pid_t>> NativeProcessHaiku::Attach(::pid_t pid) {
  Log *log(ProcessPOSIXLog::GetLogIfAllCategoriesSet(POSIX_LOG_PROCESS));

  Status status;
  // Use a map to keep track of the threads which we have attached/need to
  // attach.
  Host::TidMap tids_to_attach;
  assert(false);
  while (Host::FindProcessThreads(pid, tids_to_attach)) {
    for (Host::TidMap::iterator it = tids_to_attach.begin();
         it != tids_to_attach.end();) {
      if (it->second == false) {
        lldb::tid_t tid = it->first;

        // Attach to the requested process.
        // An attach will cause the thread to stop with a SIGSTOP.
#if 0
        if ((status = PtraceWrapper(PTRACE_ATTACH, tid)).Fail()) {
          // No such thread. The thread may have exited. More error handling
          // may be needed.
          if (status.GetError() == ESRCH) {
            it = tids_to_attach.erase(it);
            continue;
          }
          return status.ToError();
        }

        int wpid =
            llvm::sys::RetryAfterSignal(-1, ::waitpid, tid, nullptr, __WALL);
        // Need to use __WALL otherwise we receive an error with errno=ECHLD At
        // this point we should have a thread stopped if waitpid succeeds.
        if (wpid < 0) {
          // No such thread. The thread may have exited. More error handling
          // may be needed.
          if (errno == ESRCH) {
            it = tids_to_attach.erase(it);
            continue;
          }
          return llvm::errorCodeToError(
              std::error_code(errno, std::generic_category()));
        }
#endif

        LLDB_LOG(log, "adding tid = {0}", tid);
        it->second = true;
      }

      // move the loop forward
      ++it;
    }
  }

  size_t tid_count = tids_to_attach.size();
  if (tid_count == 0)
    return llvm::make_error<StringError>("No such process",
                                         llvm::inconvertibleErrorCode());

  std::vector<::pid_t> tids;
  tids.reserve(tid_count);
  for (const auto &p : tids_to_attach)
    tids.push_back(p.first);
  return std::move(tids);
}

// Handles all waitpid events from the inferior process.
void NativeProcessHaiku::MonitorPort(lldb::pid_t pid, int i) {
  Log *log(ProcessPOSIXLog::GetLogIfAllCategoriesSet(POSIX_LOG_PROCESS));

  auto thread_sp = GetThreadByID(pid);
  NativeThreadHaiku &thread = *thread_sp;

  int32 code;
  debug_debugger_message_data message;

  status_t error = team_debugger->ReadDebugMessage(code, message);
  assert(error == B_OK);
  const bool is_main_thread = (message.origin.thread == GetID());
  switch (code) {
  // TODO: these two cases are required if we want to support tracing of the
  // inferiors' children.  We'd need this to debug a monitor. case (SIGTRAP |
  // (PTRACE_EVENT_FORK << 8)): case (SIGTRAP | (PTRACE_EVENT_VFORK << 8)):

  case B_DEBUGGER_MESSAGE_THREAD_CREATED: {
    lldb::tid_t tid = message.thread_created.new_thread;
    LLDB_LOG(log, "pid = {0}: tracking new thread tid {1}", GetID(), tid);
    NativeThreadHaiku &new_thread = AddThread(tid);

    ResumeThread(new_thread, eStateRunning, LLDB_INVALID_SIGNAL_NUMBER);
    ThreadWasCreated(new_thread);
    break;
  }

  case B_DEBUGGER_MESSAGE_TEAM_EXEC: {
    LLDB_LOG(log, "received exec event, code = {0}", code);

    // Exec clears any pending notifications.
    m_pending_notification_tid = LLDB_INVALID_THREAD_ID;

    // Remove all but the main thread here.  Haiku fork creates a new process
    // which only copies the main thread.
    LLDB_LOG(log, "exec received, stop tracking all but main thread");

    llvm::erase_if(m_threads, [&](std::unique_ptr<NativeThreadProtocol> &t) {
      return t->GetID() != GetID();
    });
    assert(m_threads.size() == 1);
    auto *main_thread = static_cast<NativeThreadHaiku *>(m_threads[0].get());

    SetCurrentThreadID(main_thread->GetID());
    main_thread->SetStoppedByExec();

    // Tell coordinator about about the "new" (since exec) stopped main thread.
    ThreadWasCreated(*main_thread);

    // Let our delegate know we have just exec'd.
    NotifyDidExec();

    // Let the process know we're stopped.
    StopRunningThreads(main_thread->GetID());

    break;
  }

  case B_DEBUGGER_MESSAGE_THREAD_DELETED: {
  	WaitStatus status(WaitStatus::Exit, 0); // TODO: exit_code
    LLDB_LOG(log,
             "got exit status({0}) , tid = {1} ({2} main thread), process "
             "state = {3}",
             status, pid, is_main_thread ? "is" : "is not", GetState());

    // This is a thread that exited.  Ensure we're not tracking it anymore.
    StopTrackingThread(pid);

    if (is_main_thread) {
      // The main thread exited.  We're done monitoring.  Report to delegate.
      SetExitStatus(status, true);

      // Notify delegate that our process has exited.
      SetState(StateType::eStateExited, true);
    }
    break;
  }

  case B_DEBUGGER_MESSAGE_SINGLE_STEP:  // We receive this on single stepping.
  // case TRAP_HWBKPT: // We receive this on watchpoint hit
  {
    // If a watchpoint was hit, report it
    uint32_t wp_index;
    Status error = thread.GetRegisterContext().GetWatchpointHitIndex(
        wp_index, LLDB_INVALID_ADDRESS);
    if (error.Fail())
      LLDB_LOG(log,
               "received error while checking for watchpoint hits, pid = "
               "{0}, error = {1}",
               thread.GetID(), error);
    if (wp_index != LLDB_INVALID_INDEX32) {
      MonitorWatchpoint(thread, wp_index);
      break;
    }

    // Otherwise, report step over
    MonitorTrace(thread);
    break;
  }

  case B_DEBUGGER_MESSAGE_BREAKPOINT_HIT:
    MonitorBreakpoint(thread);
    break;

  case B_DEBUGGER_MESSAGE_SIGNAL_RECEIVED: {
    siginfo_t info = message.signal_received.info;
    LLDB_LOG(log, "received unknown SIGTRAP stop event ({0}, pid {1} tid {2}",
             info.si_code, GetID(), thread.GetID());
//    MonitorSignal(info, thread, false);
    break;
  }

  default:
    LLDB_LOG(
        log,
        "received unknown SIGTRAP stop event ({0}, pid {1} tid {2}, resuming",
        code, GetID(), thread.GetID());

    // Ignore these signals until we know more about them.
    ResumeThread(thread, thread.GetState(), LLDB_INVALID_SIGNAL_NUMBER);
    break;
  }
}

void NativeProcessHaiku::MonitorTrace(NativeThreadHaiku &thread) {
  Log *log(ProcessPOSIXLog::GetLogIfAllCategoriesSet(POSIX_LOG_PROCESS));
  LLDB_LOG(log, "received trace event, pid = {0}", thread.GetID());

  // This thread is currently stopped.
  thread.SetStoppedByTrace();

  StopRunningThreads(thread.GetID());
}

void NativeProcessHaiku::MonitorBreakpoint(NativeThreadHaiku &thread) {
  Log *log(
      GetLogIfAnyCategoriesSet(LIBLLDB_LOG_PROCESS | LIBLLDB_LOG_BREAKPOINTS));
  LLDB_LOG(log, "received breakpoint event, pid = {0}", thread.GetID());

  // Mark the thread as stopped at breakpoint.
  thread.SetStoppedByBreakpoint();
  FixupBreakpointPCAsNeeded(thread);

  StopRunningThreads(thread.GetID());
}

void NativeProcessHaiku::MonitorWatchpoint(NativeThreadHaiku &thread,
                                           uint32_t wp_index) {
  Log *log(
      GetLogIfAnyCategoriesSet(LIBLLDB_LOG_PROCESS | LIBLLDB_LOG_WATCHPOINTS));
  LLDB_LOG(log, "received watchpoint event, pid = {0}, wp_index = {1}",
           thread.GetID(), wp_index);

  // Mark the thread as stopped at watchpoint. The address is at
  // (lldb::addr_t)info->si_addr if we need it.
  thread.SetStoppedByWatchpoint(wp_index);

  // We need to tell all other running threads before we notify the delegate
  // about this stop.
  StopRunningThreads(thread.GetID());
}

void NativeProcessHaiku::MonitorSignal(const siginfo_t &info,
                                       NativeThreadHaiku &thread, bool exited) {
  const int signo = info.si_signo;
  const bool is_from_llgs = info.si_pid == getpid();

  Log *log(ProcessPOSIXLog::GetLogIfAllCategoriesSet(POSIX_LOG_PROCESS));

  // POSIX says that process behaviour is undefined after it ignores a SIGFPE,
  // SIGILL, SIGSEGV, or SIGBUS *unless* that signal was generated by a kill(2)
  // or raise(3).  Similarly for tgkill(2) on Haiku.
  //
  // IOW, user generated signals never generate what we consider to be a
  // "crash".
  //
  // Similarly, ACK signals generated by this monitor.

  // Handle the signal.
  LLDB_LOG(log,
           "received signal {0} ({1}) with code {2}, (siginfo pid = {3}, "
           "waitpid pid = {4})",
           Host::GetSignalAsCString(signo), signo, info.si_code,
           thread.GetID());

  // Check for thread stop notification.
  assert(false);
#if 0
  if (is_from_llgs && (info.si_code == SI_TKILL) && (signo == SIGSTOP)) {
    // This is a tgkill()-based stop.
    LLDB_LOG(log, "pid {0} tid {1}, thread stopped", GetID(), thread.GetID());

    // Check that we're not already marked with a stop reason. Note this thread
    // really shouldn't already be marked as stopped - if we were, that would
    // imply that the kernel signaled us with the thread stopping which we
    // handled and marked as stopped, and that, without an intervening resume,
    // we received another stop.  It is more likely that we are missing the
    // marking of a run state somewhere if we find that the thread was marked
    // as stopped.
    const StateType thread_state = thread.GetState();
    if (!StateIsStoppedState(thread_state, false)) {
      // An inferior thread has stopped because of a SIGSTOP we have sent it.
      // Generally, these are not important stops and we don't want to report
      // them as they are just used to stop other threads when one thread (the
      // one with the *real* stop reason) hits a breakpoint (watchpoint,
      // etc...). However, in the case of an asynchronous Interrupt(), this
      // *is* the real stop reason, so we leave the signal intact if this is
      // the thread that was chosen as the triggering thread.
      if (m_pending_notification_tid != LLDB_INVALID_THREAD_ID) {
        if (m_pending_notification_tid == thread.GetID())
          thread.SetStoppedBySignal(SIGSTOP, &info);
        else
          thread.SetStoppedWithNoReason();

        SetCurrentThreadID(thread.GetID());
        SignalIfAllThreadsStopped();
      } else {
        // We can end up here if stop was initiated by LLGS but by this time a
        // thread stop has occurred - maybe initiated by another event.
        Status error = ResumeThread(thread, thread.GetState(), 0);
        if (error.Fail())
          LLDB_LOG(log, "failed to resume thread {0}: {1}", thread.GetID(),
                   error);
      }
    } else {
      LLDB_LOG(log,
               "pid {0} tid {1}, thread was already marked as a stopped "
               "state (state={2}), leaving stop signal as is",
               GetID(), thread.GetID(), thread_state);
      SignalIfAllThreadsStopped();
    }

    // Done handling.
    return;
  }
#endif

  // Check if debugger should stop at this signal or just ignore it and resume
  // the inferior.
  if (m_signals_to_ignore.find(signo) != m_signals_to_ignore.end()) {
     ResumeThread(thread, thread.GetState(), signo);
     return;
  }

  // This thread is stopped.
  LLDB_LOG(log, "received signal {0}", Host::GetSignalAsCString(signo));
  thread.SetStoppedBySignal(signo, &info);

  // Send a stop to the debugger after we get all other threads to stop.
  StopRunningThreads(thread.GetID());
}

Status NativeProcessHaiku::Resume(const ResumeActionList &resume_actions) {
  Log *log(ProcessPOSIXLog::GetLogIfAllCategoriesSet(POSIX_LOG_PROCESS));
  LLDB_LOG(log, "pid {0}", GetID());

  for (const auto &thread : m_threads) {
    assert(thread && "thread list should not contain NULL threads");

    const ResumeAction *const action =
        resume_actions.GetActionForThread(thread->GetID(), true);

    if (action == nullptr) {
      LLDB_LOG(log, "no action specified for pid {0} tid {1}", GetID(),
               thread->GetID());
      continue;
    }

    LLDB_LOG(log, "processing resume action state {0} for pid {1} tid {2}",
             action->state, GetID(), thread->GetID());

    switch (action->state) {
    case eStateRunning:
    case eStateStepping: {
      // Run the thread, possibly feeding it the signal.
      const int signo = action->signal;
      ResumeThread(static_cast<NativeThreadHaiku &>(*thread), action->state,
                   signo);
      break;
    }

    case eStateSuspended:
    case eStateStopped:
      llvm_unreachable("Unexpected state");

    default:
      return Status("NativeProcessHaiku::%s (): unexpected state %s specified "
                    "for pid %" PRIu64 ", tid %" PRIu64,
                    __FUNCTION__, StateAsCString(action->state), GetID(),
                    thread->GetID());
    }
  }

  return Status();
}

Status NativeProcessHaiku::Halt() {
  Status error;

  if (kill(GetID(), SIGSTOP) != 0)
    error.SetErrorToErrno();

  return error;
}

Status NativeProcessHaiku::Detach() {
  Status error;

  // Tell ptrace to detach from the process.
  if (GetID() == LLDB_INVALID_PROCESS_ID)
    return error;

  for (const auto &thread : m_threads) {
    Status e = Detach(thread->GetID());
    if (e.Fail())
      error =
          e; // Save the error, but still attempt to detach from other threads.
  }

  return error;
}

Status NativeProcessHaiku::Signal(int signo) {
  Status error;

  Log *log(ProcessPOSIXLog::GetLogIfAllCategoriesSet(POSIX_LOG_PROCESS));
  LLDB_LOG(log, "sending signal {0} ({1}) to pid {1}", signo,
           Host::GetSignalAsCString(signo), GetID());

  if (kill(GetID(), signo))
    error.SetErrorToErrno();

  return error;
}

Status NativeProcessHaiku::Interrupt() {
  // Pick a running thread (or if none, a not-dead stopped thread) as the
  // chosen thread that will be the stop-reason thread.
  Log *log(ProcessPOSIXLog::GetLogIfAllCategoriesSet(POSIX_LOG_PROCESS));

  NativeThreadProtocol *running_thread = nullptr;
  NativeThreadProtocol *stopped_thread = nullptr;

  LLDB_LOG(log, "selecting running thread for interrupt target");
  for (const auto &thread : m_threads) {
    // If we have a running or stepping thread, we'll call that the target of
    // the interrupt.
    const auto thread_state = thread->GetState();
    if (thread_state == eStateRunning || thread_state == eStateStepping) {
      running_thread = thread.get();
      break;
    } else if (!stopped_thread && StateIsStoppedState(thread_state, true)) {
      // Remember the first non-dead stopped thread.  We'll use that as a
      // backup if there are no running threads.
      stopped_thread = thread.get();
    }
  }

  if (!running_thread && !stopped_thread) {
    Status error("found no running/stepping or live stopped threads as target "
                 "for interrupt");
    LLDB_LOG(log, "skipping due to error: {0}", error);

    return error;
  }

  NativeThreadProtocol *deferred_signal_thread =
      running_thread ? running_thread : stopped_thread;

  LLDB_LOG(log, "pid {0} {1} tid {2} chosen for interrupt target", GetID(),
           running_thread ? "running" : "stopped",
           deferred_signal_thread->GetID());

  StopRunningThreads(deferred_signal_thread->GetID());

  return Status();
}

Status NativeProcessHaiku::Kill() {
  Log *log(ProcessPOSIXLog::GetLogIfAllCategoriesSet(POSIX_LOG_PROCESS));
  LLDB_LOG(log, "pid {0}", GetID());

  Status error;

  switch (m_state) {
  case StateType::eStateInvalid:
  case StateType::eStateExited:
  case StateType::eStateCrashed:
  case StateType::eStateDetached:
  case StateType::eStateUnloaded:
    // Nothing to do - the process is already dead.
    LLDB_LOG(log, "ignored for PID {0} due to current state: {1}", GetID(),
             m_state);
    return error;

  case StateType::eStateConnected:
  case StateType::eStateAttaching:
  case StateType::eStateLaunching:
  case StateType::eStateStopped:
  case StateType::eStateRunning:
  case StateType::eStateStepping:
  case StateType::eStateSuspended:
    // We can try to kill a process in these states.
    break;
  }

  if (kill(GetID(), SIGKILL) != 0) {
    error.SetErrorToErrno();
    return error;
  }

  return error;
}

Status NativeProcessHaiku::GetMemoryRegionInfo(lldb::addr_t load_addr,
                                               MemoryRegionInfo &range_info) {
  return Status("unsupported");

  // FIXME review that the final memory region returned extends to the end of
  // the virtual address space,
  // with no perms if it is not mapped.

  // Use an approach that reads memory regions from /proc/{pid}/maps. Assume
  // proc maps entries are in ascending order.
  // FIXME assert if we find differently.

  if (m_supports_mem_region == LazyBool::eLazyBoolNo) {
    // We're done.
    return Status("unsupported");
  }

  Status error = PopulateMemoryRegionCache();
  if (error.Fail()) {
    return error;
  }

  lldb::addr_t prev_base_address = 0;

  // FIXME start by finding the last region that is <= target address using
  // binary search.  Data is sorted.
  // There can be a ton of regions on pthreads apps with lots of threads.
  for (auto it = m_mem_region_cache.begin(); it != m_mem_region_cache.end();
       ++it) {
    MemoryRegionInfo &proc_entry_info = it->first;

    // Sanity check assumption that /proc/{pid}/maps entries are ascending.
    assert((proc_entry_info.GetRange().GetRangeBase() >= prev_base_address) &&
           "descending /proc/pid/maps entries detected, unexpected");
    prev_base_address = proc_entry_info.GetRange().GetRangeBase();
    UNUSED_IF_ASSERT_DISABLED(prev_base_address);

    // If the target address comes before this entry, indicate distance to next
    // region.
    if (load_addr < proc_entry_info.GetRange().GetRangeBase()) {
      range_info.GetRange().SetRangeBase(load_addr);
      range_info.GetRange().SetByteSize(
          proc_entry_info.GetRange().GetRangeBase() - load_addr);
      range_info.SetReadable(MemoryRegionInfo::OptionalBool::eNo);
      range_info.SetWritable(MemoryRegionInfo::OptionalBool::eNo);
      range_info.SetExecutable(MemoryRegionInfo::OptionalBool::eNo);
      range_info.SetMapped(MemoryRegionInfo::OptionalBool::eNo);

      return error;
    } else if (proc_entry_info.GetRange().Contains(load_addr)) {
      // The target address is within the memory region we're processing here.
      range_info = proc_entry_info;
      return error;
    }

    // The target memory address comes somewhere after the region we just
    // parsed.
  }

  // If we made it here, we didn't find an entry that contained the given
  // address. Return the load_addr as start and the amount of bytes betwwen
  // load address and the end of the memory as size.
  range_info.GetRange().SetRangeBase(load_addr);
  range_info.GetRange().SetRangeEnd(LLDB_INVALID_ADDRESS);
  range_info.SetReadable(MemoryRegionInfo::OptionalBool::eNo);
  range_info.SetWritable(MemoryRegionInfo::OptionalBool::eNo);
  range_info.SetExecutable(MemoryRegionInfo::OptionalBool::eNo);
  range_info.SetMapped(MemoryRegionInfo::OptionalBool::eNo);
  return error;
}

Status NativeProcessHaiku::PopulateMemoryRegionCache() {
  Log *log(ProcessPOSIXLog::GetLogIfAllCategoriesSet(POSIX_LOG_PROCESS));

  // If our cache is empty, pull the latest.  There should always be at least
  // one memory region if memory region handling is supported.
  if (!m_mem_region_cache.empty()) {
    LLDB_LOG(log, "reusing {0} cached memory region entries",
             m_mem_region_cache.size());
    return Status();
  }

  Status Result;
  assert(false);
#if 0
  LinuxMapCallback callback = [&](llvm::Expected<MemoryRegionInfo> Info) {
    if (Info) {
      FileSpec file_spec(Info->GetName().GetCString());
      FileSystem::Instance().Resolve(file_spec);
      m_mem_region_cache.emplace_back(*Info, file_spec);
      return true;
    }

    Result = Info.takeError();
    m_supports_mem_region = LazyBool::eLazyBoolNo;
    LLDB_LOG(log, "failed to parse proc maps: {0}", Result);
    return false;
  };

  // Linux kernel since 2.6.14 has /proc/{pid}/smaps
  // if CONFIG_PROC_PAGE_MONITOR is enabled
  auto BufferOrError = getProcFile(GetID(), "smaps");
  if (BufferOrError)
    ParseLinuxSMapRegions(BufferOrError.get()->getBuffer(), callback);
  else {
    BufferOrError = getProcFile(GetID(), "maps");
    if (!BufferOrError) {
      m_supports_mem_region = LazyBool::eLazyBoolNo;
      return BufferOrError.getError();
    }

    ParseLinuxMapRegions(BufferOrError.get()->getBuffer(), callback);
  }
#endif

  if (Result.Fail())
    return Result;

  if (m_mem_region_cache.empty()) {
    // No entries after attempting to read them.  This shouldn't happen if
    // /proc/{pid}/maps is supported. Assume we don't support map entries via
    // procfs.
    m_supports_mem_region = LazyBool::eLazyBoolNo;
    LLDB_LOG(log,
             "failed to find any procfs maps entries, assuming no support "
             "for memory region metadata retrieval");
    return Status("not supported");
  }

  LLDB_LOG(log, "read {0} memory region entries from /proc/{1}/maps",
           m_mem_region_cache.size(), GetID());

  // We support memory retrieval, remember that.
  m_supports_mem_region = LazyBool::eLazyBoolYes;
  return Status();
}

void NativeProcessHaiku::DoStopIDBumped(uint32_t newBumpId) {
  Log *log(ProcessPOSIXLog::GetLogIfAllCategoriesSet(POSIX_LOG_PROCESS));
  LLDB_LOG(log, "newBumpId={0}", newBumpId);
  LLDB_LOG(log, "clearing {0} entries from memory region cache",
           m_mem_region_cache.size());
  m_mem_region_cache.clear();
}

size_t NativeProcessHaiku::UpdateThreads() {
  // The NativeProcessHaiku monitoring threads are always up to date with
  // respect to thread state and they keep the thread list populated properly.
  // All this method needs to do is return the thread count.
  return m_threads.size();
}

Status NativeProcessHaiku::SetBreakpoint(lldb::addr_t addr, uint32_t size,
                                         bool hardware) {
  if (hardware)
    return Status("NativeProcessHaiku does not support hardware breakpoints");
  else
    return SetSoftwareBreakpoint(addr, size);
}

Status NativeProcessHaiku::RemoveBreakpoint(lldb::addr_t addr, bool hardware) {
  if (hardware)
    return Status("NativeProcessHaiku does not support hardware breakpoints");
  else
    return NativeProcessProtocol::RemoveBreakpoint(addr);
}

Status NativeProcessHaiku::ReadMemory(lldb::addr_t addr, void *buf, size_t size,
                                      size_t &bytes_read) {
  unsigned char *dst = static_cast<unsigned char *>(buf);
  size_t remainder;
  long data;

  Log *log(ProcessPOSIXLog::GetLogIfAllCategoriesSet(POSIX_LOG_MEMORY));
  LLDB_LOG(log, "addr = {0}, buf = {1}, size = {2}", addr, buf, size);

  for (bytes_read = 0; bytes_read < size; bytes_read += remainder) {
    assert(false);
#if 0
    Status error = NativeProcessHaiku::PtraceWrapper(
        PTRACE_PEEKDATA, GetID(), (void *)addr, nullptr, 0, &data);
    if (error.Fail())
      return error;
#endif

    remainder = size - bytes_read;
    remainder = remainder > k_ptrace_word_size ? k_ptrace_word_size : remainder;

    // Copy the data into our buffer
    memcpy(dst, &data, remainder);

    LLDB_LOG(log, "[{0:x}]:{1:x}", addr, data);
    addr += k_ptrace_word_size;
    dst += k_ptrace_word_size;
  }
  return Status();
}

llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>>
NativeProcessHaiku::GetAuxvData() const {
  return llvm::errc::not_supported;
}

Status NativeProcessHaiku::WriteMemory(lldb::addr_t addr, const void *buf,
                                       size_t size, size_t &bytes_written) {
  const unsigned char *src = static_cast<const unsigned char *>(buf);
  size_t remainder;
  Status error;

  Log *log(ProcessPOSIXLog::GetLogIfAllCategoriesSet(POSIX_LOG_MEMORY));
  LLDB_LOG(log, "addr = {0}, buf = {1}, size = {2}", addr, buf, size);

  for (bytes_written = 0; bytes_written < size; bytes_written += remainder) {
    remainder = size - bytes_written;
    remainder = remainder > k_ptrace_word_size ? k_ptrace_word_size : remainder;

    if (remainder == k_ptrace_word_size) {
      unsigned long data = 0;
      memcpy(&data, src, k_ptrace_word_size);

      LLDB_LOG(log, "[{0:x}]:{1:x}", addr, data);
      assert(false);
#if 0
      error = NativeProcessHaiku::PtraceWrapper(PTRACE_POKEDATA, GetID(),
                                                (void *)addr, (void *)data);
      if (error.Fail())
        return error;
#endif
    } else {
      unsigned char buff[8];
      size_t bytes_read;
      error = ReadMemory(addr, buff, k_ptrace_word_size, bytes_read);
      if (error.Fail())
        return error;

      memcpy(buff, src, remainder);

      size_t bytes_written_rec;
      error = WriteMemory(addr, buff, k_ptrace_word_size, bytes_written_rec);
      if (error.Fail())
        return error;

      LLDB_LOG(log, "[{0:x}]:{1:x} ({2:x})", addr, *(const unsigned long *)src,
               *(unsigned long *)buff);
    }

    addr += k_ptrace_word_size;
    src += k_ptrace_word_size;
  }
  return error;
}

Status NativeProcessHaiku::GetSignalInfo(lldb::tid_t tid, void *siginfo) {
#if 0
  return PtraceWrapper(PTRACE_GETSIGINFO, tid, nullptr, siginfo);
#endif
  assert(false);
  return Status();
}

Status NativeProcessHaiku::GetEventMessage(lldb::tid_t tid,
                                           unsigned long *message) {
#if 0
  return PtraceWrapper(PTRACE_GETEVENTMSG, tid, nullptr, message);
#endif
  assert(false);
  return Status();
}

Status NativeProcessHaiku::Detach(lldb::tid_t tid) {
  if (tid == LLDB_INVALID_THREAD_ID)
    return Status();

#if 0
  return PtraceWrapper(PTRACE_DETACH, tid);
#endif
  assert(false);
  return Status();
}

bool NativeProcessHaiku::HasThreadNoLock(lldb::tid_t thread_id) {
  for (const auto &thread : m_threads) {
    assert(thread && "thread list should not contain NULL threads");
    if (thread->GetID() == thread_id) {
      // We have this thread.
      return true;
    }
  }

  // We don't have this thread.
  return false;
}

bool NativeProcessHaiku::StopTrackingThread(lldb::tid_t thread_id) {
  Log *const log = ProcessPOSIXLog::GetLogIfAllCategoriesSet(POSIX_LOG_THREAD);
  LLDB_LOG(log, "tid: {0})", thread_id);

  bool found = false;
  for (auto it = m_threads.begin(); it != m_threads.end(); ++it) {
    if (*it && ((*it)->GetID() == thread_id)) {
      m_threads.erase(it);
      found = true;
      break;
    }
  }

  SignalIfAllThreadsStopped();
  return found;
}

NativeThreadHaiku &NativeProcessHaiku::AddThread(lldb::tid_t thread_id) {
  Log *log(ProcessPOSIXLog::GetLogIfAllCategoriesSet(POSIX_LOG_THREAD));
  LLDB_LOG(log, "pid {0} adding thread with tid {1}", GetID(), thread_id);

  assert(!HasThreadNoLock(thread_id) &&
         "attempted to add a thread by id that already exists");

  // If this is the first thread, save it as the current thread
  if (m_threads.empty())
    SetCurrentThreadID(thread_id);

  m_threads.push_back(std::make_unique<NativeThreadHaiku>(*this, thread_id));

  return static_cast<NativeThreadHaiku &>(*m_threads.back());
}

Status NativeProcessHaiku::GetLoadedModuleFileSpec(const char *module_path,
                                                   FileSpec &file_spec) {
  Status error = PopulateMemoryRegionCache();
  if (error.Fail())
    return error;

  FileSpec module_file_spec(module_path);
  FileSystem::Instance().Resolve(module_file_spec);

  file_spec.Clear();
  for (const auto &it : m_mem_region_cache) {
    if (it.second.GetFilename() == module_file_spec.GetFilename()) {
      file_spec = it.second;
      return Status();
    }
  }
  return Status("Module file (%s) not found in /proc/%" PRIu64 "/maps file!",
                module_file_spec.GetFilename().AsCString(), GetID());
}

Status NativeProcessHaiku::GetFileLoadAddress(const llvm::StringRef &file_name,
                                              lldb::addr_t &load_addr) {
  load_addr = LLDB_INVALID_ADDRESS;
  Status error = PopulateMemoryRegionCache();
  if (error.Fail())
    return error;

  FileSpec file(file_name);
  for (const auto &it : m_mem_region_cache) {
    if (it.second == file) {
      load_addr = it.first.GetRange().GetRangeBase();
      return Status();
    }
  }
  return Status("No load address found for specified file.");
}

NativeThreadHaiku *NativeProcessHaiku::GetThreadByID(lldb::tid_t tid) {
  return static_cast<NativeThreadHaiku *>(
      NativeProcessProtocol::GetThreadByID(tid));
}

NativeThreadHaiku *NativeProcessHaiku::GetCurrentThread() {
  return static_cast<NativeThreadHaiku *>(
      NativeProcessProtocol::GetCurrentThread());
}

Status NativeProcessHaiku::ResumeThread(NativeThreadHaiku &thread,
                                        lldb::StateType state, int signo) {
  Log *const log = ProcessPOSIXLog::GetLogIfAllCategoriesSet(POSIX_LOG_THREAD);
  LLDB_LOG(log, "tid: {0}", thread.GetID());

  // Before we do the resume below, first check if we have a pending stop
  // notification that is currently waiting for all threads to stop.  This is
  // potentially a buggy situation since we're ostensibly waiting for threads
  // to stop before we send out the pending notification, and here we are
  // resuming one before we send out the pending stop notification.
  if (m_pending_notification_tid != LLDB_INVALID_THREAD_ID) {
    LLDB_LOG(log,
             "about to resume tid {0} per explicit request but we have a "
             "pending stop notification (tid {1}) that is actively "
             "waiting for this thread to stop. Valid sequence of events?",
             thread.GetID(), m_pending_notification_tid);
  }

  // Request a resume.  We expect this to be synchronous and the system to
  // reflect it is running after this completes.
  switch (state) {
  case eStateRunning: {
    const auto resume_result = thread.Resume();
    if (resume_result.Success())
      SetState(eStateRunning, true);
    return resume_result;
  }
  case eStateStepping: {
    const auto step_result = thread.SingleStep();
    if (step_result.Success())
      SetState(eStateRunning, true);
    return step_result;
  }
  default:
    LLDB_LOG(log, "Unhandled state {0}.", state);
    llvm_unreachable("Unhandled state for resume");
  }
}

//===----------------------------------------------------------------------===//

void NativeProcessHaiku::StopRunningThreads(const lldb::tid_t triggering_tid) {
  Log *const log = ProcessPOSIXLog::GetLogIfAllCategoriesSet(POSIX_LOG_THREAD);
  LLDB_LOG(log, "about to process event: (triggering_tid: {0})",
           triggering_tid);

  m_pending_notification_tid = triggering_tid;

  // Request a stop for all the thread stops that need to be stopped and are
  // not already known to be stopped.
  for (const auto &thread : m_threads) {
    if (StateIsRunningState(thread->GetState()))
      static_cast<NativeThreadHaiku *>(thread.get())->Suspend();
  }

  SignalIfAllThreadsStopped();
  LLDB_LOG(log, "event processing done");
}

void NativeProcessHaiku::SignalIfAllThreadsStopped() {
  if (m_pending_notification_tid == LLDB_INVALID_THREAD_ID)
    return; // No pending notification. Nothing to do.

  for (const auto &thread_sp : m_threads) {
    if (StateIsRunningState(thread_sp->GetState()))
      return; // Some threads are still running. Don't signal yet.
  }

  // We have a pending notification and all threads have stopped.
  Log *log(
      GetLogIfAnyCategoriesSet(LIBLLDB_LOG_PROCESS | LIBLLDB_LOG_BREAKPOINTS));

  // Notify the delegate about the stop
  SetCurrentThreadID(m_pending_notification_tid);
  SetState(StateType::eStateStopped, true);
  m_pending_notification_tid = LLDB_INVALID_THREAD_ID;
}

void NativeProcessHaiku::ThreadWasCreated(NativeThreadHaiku &thread) {
  Log *const log = ProcessPOSIXLog::GetLogIfAllCategoriesSet(POSIX_LOG_THREAD);
  LLDB_LOG(log, "tid: {0}", thread.GetID());

  if (m_pending_notification_tid != LLDB_INVALID_THREAD_ID &&
      StateIsRunningState(thread.GetState())) {
    // We will need to wait for this new thread to stop as well before firing
    // the notification.
    thread.Suspend();
  }
}

// Wrapper for ptrace to catch errors and log calls. Note that ptrace sets
// errno on error because -1 can be a valid result (i.e. for PTRACE_PEEK*)
Status NativeProcessHaiku::PtraceWrapper(int req, lldb::pid_t pid, void *addr,
                                         void *data, size_t data_size,
                                         long *result) {
  Status error;
  long int ret;

  Log *log(ProcessPOSIXLog::GetLogIfAllCategoriesSet(POSIX_LOG_PTRACE));

  errno = 0;
  assert(false);
#if 0
  if (req == PTRACE_GETREGSET || req == PTRACE_SETREGSET)
    ret = ptrace(static_cast<__ptrace_request>(req), static_cast<::pid_t>(pid),
                 *(unsigned int *)addr, data);
  else
    ret = ptrace(static_cast<__ptrace_request>(req), static_cast<::pid_t>(pid),
                 addr, data);
#endif

  if (ret == -1)
    error.SetErrorToErrno();

  if (result)
    *result = ret;

  LLDB_LOG(log, "ptrace({0}, {1}, {2}, {3}, {4})={5:x}", req, pid, addr, data,
           data_size, ret);

  if (error.Fail())
    LLDB_LOG(log, "ptrace() failed: {0}", error);

  return error;
}
