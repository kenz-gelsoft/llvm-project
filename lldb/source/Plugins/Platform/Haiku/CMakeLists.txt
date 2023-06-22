add_lldb_library(lldbPluginPlatformHaiku PLUGIN
  PlatformHaiku.cpp

   LINK_LIBS
    lldbBreakpoint
    lldbCore
    lldbHost
    lldbTarget
  )
