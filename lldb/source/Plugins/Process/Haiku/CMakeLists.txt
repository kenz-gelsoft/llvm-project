add_lldb_library(lldbPluginProcessHaiku
  NativeProcessHaiku.cpp
  NativeRegisterContextHaiku.cpp
  NativeRegisterContextHaiku_x86_64.cpp
  NativeThreadHaiku.cpp

  LINK_LIBS
    lldbHost
    lldbSymbol
    lldbTarget
    lldbUtility
    lldbPluginProcessPOSIX
    lldbPluginProcessUtility
    #util
  LINK_COMPONENTS
    Support
  )
