//===-- source/Host/haiku/Host.cpp --------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include <sys/types.h>

//#include <sys/signal.h>
//#include <sys/exec.h>
//#include <sys/proc.h>
//#include <sys/ptrace.h>
//#include <sys/sysctl.h>
//#include <sys/user.h>
#include <OS.h>

#include <stdio.h>

#include "lldb/Host/Host.h"
#include "lldb/Host/HostInfo.h"
#include "lldb/Utility/DataBufferHeap.h"
#include "lldb/Utility/DataExtractor.h"
#include "lldb/Utility/Endian.h"
#include "lldb/Utility/Log.h"
#include "lldb/Utility/NameMatches.h"
#include "lldb/Utility/ProcessInfo.h"
#include "lldb/Utility/Status.h"
#include "lldb/Utility/StreamString.h"

#include "llvm/Support/Host.h"

extern "C" {
extern char **environ;
}

using namespace lldb;
using namespace lldb_private;

namespace lldb_private {
class ProcessLaunchInfo;
}

Environment Host::GetEnvironment() { return Environment(environ); }

static bool
GetHaikuProcessArgs(const ProcessInstanceInfoMatch *match_info_ptr,
                      ProcessInstanceInfo &process_info) {
  if (process_info.ProcessIDIsValid()) {
    // FIXME: team_info.args hold just 64 bytes only.
    team_info team;
    size_t arg_data_size = sizeof(team.args);
    if (::get_team_info(process_info.GetProcessID(), &team) == B_OK) {
      DataExtractor data(team.args, arg_data_size, endian::InlHostByteOrder(),
                         sizeof(void *));
      lldb::offset_t offset = 0;
      const char *cstr;

      cstr = data.GetCStr(&offset);
      if (cstr) {
        process_info.GetExecutableFile().SetFile(cstr, FileSpec::Style::native);

        if (!(match_info_ptr == NULL ||
              NameMatches(
                  process_info.GetExecutableFile().GetFilename().GetCString(),
                  match_info_ptr->GetNameMatchType(),
                  match_info_ptr->GetProcessInfo().GetName())))
          return false;

        Args &proc_args = process_info.GetArguments();
        while (1) {
          const uint8_t *p = data.PeekData(offset, 1);
          while ((p != NULL) && (*p == '\0') && offset < arg_data_size) {
            ++offset;
            p = data.PeekData(offset, 1);
          }
          if (p == NULL || offset >= arg_data_size)
            return true;

          cstr = data.GetCStr(&offset);
          if (cstr)
            proc_args.AppendArgument(llvm::StringRef(cstr));
          else
            return true;
        }
      }
    }
  }
  return false;
}

static bool GetHaikuProcessCPUType(ProcessInstanceInfo &process_info) {
  if (process_info.ProcessIDIsValid()) {
    process_info.GetArchitecture() =
        HostInfo::GetArchitecture(HostInfo::eArchKindDefault);
    return true;
  }
  process_info.GetArchitecture().Clear();
  return false;
}

static bool GetHaikuProcessUserAndGroup(ProcessInstanceInfo &process_info) {
  if (process_info.ProcessIDIsValid()) {
    team_info team;
    if (::get_team_info(process_info.GetProcessID(), &team) == B_OK) {
        process_info.SetParentProcessID(team.parent);
        process_info.SetUserID(team.real_uid);
        process_info.SetGroupID(team.real_gid);
        process_info.SetEffectiveUserID(team.uid);
        process_info.SetEffectiveGroupID(team.gid);
        return true;
    }
  }
  process_info.SetParentProcessID(LLDB_INVALID_PROCESS_ID);
  process_info.SetUserID(UINT32_MAX);
  process_info.SetGroupID(UINT32_MAX);
  process_info.SetEffectiveUserID(UINT32_MAX);
  process_info.SetEffectiveGroupID(UINT32_MAX);
  return false;
}

uint32_t Host::FindProcessesImpl(const ProcessInstanceInfoMatch &match_info,
                                 ProcessInstanceInfoList &process_infos) {
  size_t pid_data_size = 0;
  // Add a few extra in case a few more show up
  bool all_users = match_info.GetMatchAllUsers();
  const ::pid_t our_pid = getpid();
  const uid_t our_uid = getuid();
  int32 cookie = 0;
  team_info tinfo;
  while (get_next_team_info(&cookie, &tinfo) == B_OK) {
   const bool tinfo_user_matches = (all_users || (tinfo.real_uid == our_uid) ||
                                    // Special case, if lldb is being run as
                                    // root we can attach to anything.
                                    (our_uid == 0));

   if (tinfo_user_matches == false || // Make sure the user is acceptable
       tinfo.team == our_pid ||       // Skip this process
       tinfo.team == 0 ||             // Skip kernel (kernel pid is zero)
       tinfo.nub_port != -1)          // Being debugged?
     continue;

    ProcessInstanceInfo process_info;
   process_info.SetProcessID(tinfo.team);
   process_info.SetParentProcessID(tinfo.parent);
   process_info.SetUserID(kinfo.real_uid);
   process_info.SetGroupID(kinfo.real_gid);
   process_info.SetEffectiveUserID(kinfo.uid);
   process_info.SetEffectiveGroupID(kinfo.gid);

    // Make sure our info matches before we go fetch the name and cpu type
    if (match_info.Matches(process_info) &&
        GetHaikuProcessArgs(&match_info, process_info)) {
      GetHaikuProcessCPUType(process_info);
      if (match_info.Matches(process_info))
        process_infos.push_back(process_info);
    }
 }

  return process_infos.size();
}

bool Host::GetProcessInfo(lldb::pid_t pid, ProcessInstanceInfo &process_info) {
  process_info.SetProcessID(pid);

  if (GetHaikuProcessArgs(NULL, process_info)) {
    // should use libprocstat instead of going right into sysctl?
    GetHaikuProcessCPUType(process_info);
    GetHaikuProcessUserAndGroup(process_info);
    return true;
  }

  process_info.Clear();
  return false;
}

Status Host::ShellExpandArguments(ProcessLaunchInfo &launch_info) {
  return Status("unimplemented");
}
