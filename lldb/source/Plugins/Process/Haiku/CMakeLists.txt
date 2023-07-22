find_path(HAIKU_DEBUG_INCLUDE_DIRS debug_support.h
  PATHS ${CMAKE_SYSTEM_INCLUDE_PATH}
  PATH_SUFFIXES /private/debug
  NO_DEFAULT_PATH
  REQUIRED
)
target_include_directories(lldbPluginProcessHaiku SYSTEM PRIVATE
  ${HAIKU_DEBUG_INCLUDE_DIRS}
)

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
    debug
  LINK_COMPONENTS
    Support
  )
