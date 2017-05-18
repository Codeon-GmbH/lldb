add_lldb_library(lldbPluginMulleObjCRuntime PLUGIN
  MulleObjCRuntime.cpp
  MulleObjCRuntimeV1.cpp
  MulleObjCTrampolineHandler.cpp
  MulleObjCDeclVendor.cpp
  MulleThreadPlanStepThroughObjCTrampoline.cpp
  MulleObjCTypeEncodingParser.cpp

  LINK_LIBS
    clangAST
    lldbBreakpoint
    lldbCore
    lldbExpression
    lldbHost
    lldbInterpreter
    lldbSymbol
    lldbTarget
    lldbUtility
    lldbPluginExpressionParserClang
  LINK_COMPONENTS
    Support
  )
