add_lldb_library(lldbPluginObjCRuntime PLUGIN
  ObjCLanguageRuntime.cpp

  LINK_LIBS
    lldbCore
    lldbSymbol
    lldbTarget
    lldbUtility
)
add_subdirectory(AppleObjCRuntime)
# @mulle-objc@ >
add_subdirectory(MulleObjCRuntime)
# @mulle-objc@ <
