//===-- MulleObjCRuntime.cpp -------------------------------------*- C++
//-*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "MulleObjCRuntime.h"
#include "MulleObjCTrampolineHandler.h"

#include "clang/AST/Type.h"

#include "lldb/Breakpoint/BreakpointLocation.h"
#include "lldb/Core/Module.h"
#include "lldb/Core/ModuleList.h"
#include "lldb/Core/PluginManager.h"
#include "lldb/Core/Scalar.h"
#include "lldb/Core/Section.h"
#include "lldb/Core/ValueObject.h"
#include "lldb/Expression/DiagnosticManager.h"
#include "lldb/Expression/FunctionCaller.h"
#include "lldb/Symbol/ClangASTContext.h"
#include "lldb/Symbol/ObjectFile.h"
#include "lldb/Target/ExecutionContext.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/RegisterContext.h"
#include "lldb/Target/StopInfo.h"
#include "lldb/Target/Target.h"
#include "lldb/Target/Thread.h"
#include "lldb/Utility/ConstString.h"
#include "lldb/Utility/Log.h"
#include "lldb/Utility/Status.h"
#include "lldb/Utility/StreamString.h"

#include <vector>

using namespace lldb;
using namespace lldb_private;

static constexpr std::chrono::seconds g_po_function_timeout(15);

MulleObjCRuntime::~MulleObjCRuntime() {}

MulleObjCRuntime::MulleObjCRuntime(Process *process)
    : ObjCLanguageRuntime(process), m_read_objc_library(false),
      m_objc_trampoline_handler_ap(), m_Foundation_major() {
  ReadObjCLibraryIfNeeded(process->GetTarget().GetImages());
}

bool MulleObjCRuntime::GetObjectDescription(Stream &str, ValueObject &valobj) {
  CompilerType compiler_type(valobj.GetCompilerType());
  bool is_signed;
  // ObjC objects can only be pointers (or numbers that actually represents
  // pointers
  // but haven't been typecast, because reasons..)
  if (!compiler_type.IsIntegerType(is_signed) && !compiler_type.IsPointerType())
    return false;

  // Make the argument list: we pass one arg, the address of our pointer, to the
  // print function.
  Value val;

  if (!valobj.ResolveValue(val.GetScalar()))
    return false;

  // Value Objects may not have a process in their ExecutionContextRef.  But we
  // need to have one
  // in the ref we pass down to eventually call description.  Get it from the
  // target if it isn't
  // present.
  ExecutionContext exe_ctx;
  if (valobj.GetProcessSP()) {
    exe_ctx = ExecutionContext(valobj.GetExecutionContextRef());
  } else {
    exe_ctx.SetContext(valobj.GetTargetSP(), true);
    if (!exe_ctx.HasProcessScope())
      return false;
  }
  return GetObjectDescription(str, val, exe_ctx.GetBestExecutionContextScope());
}
bool MulleObjCRuntime::GetObjectDescription(Stream &strm, Value &value,
                                            ExecutionContextScope *exe_scope) {
  if (!m_read_objc_library)
    return false;

  ExecutionContext exe_ctx;
  exe_scope->CalculateExecutionContext(exe_ctx);
  Process *process = exe_ctx.GetProcessPtr();
  if (!process)
    return false;

  // We need other parts of the exe_ctx, but the processes have to match.
  assert(m_process == process);

  // Get the function address for the print function.
  const Address *function_address = GetPrintForDebuggerAddr();
  if (!function_address)
    return false;

  Target *target = exe_ctx.GetTargetPtr();
  CompilerType compiler_type = value.GetCompilerType();
  if (compiler_type) {
    if (!ClangASTContext::IsObjCObjectPointerType(compiler_type)) {
      strm.Printf("Value doesn't point to an ObjC object.\n");
      return false;
    }
  } else {
    // If it is not a pointer, see if we can make it into a pointer.
    ClangASTContext *ast_context = target->GetScratchClangASTContext();
    CompilerType opaque_type = ast_context->GetBasicType(eBasicTypeObjCID);
    if (!opaque_type)
      opaque_type = ast_context->GetBasicType(eBasicTypeVoid).GetPointerType();
    // value.SetContext(Value::eContextTypeClangType, opaque_type_ptr);
    value.SetCompilerType(opaque_type);
  }

  ValueList arg_value_list;
  arg_value_list.PushValue(value);

  // This is the return value:
  ClangASTContext *ast_context = target->GetScratchClangASTContext();

  CompilerType return_compiler_type = ast_context->GetCStringType(true);
  Value ret;
  //    ret.SetContext(Value::eContextTypeClangType, return_compiler_type);
  ret.SetCompilerType(return_compiler_type);

  if (exe_ctx.GetFramePtr() == NULL) {
    Thread *thread = exe_ctx.GetThreadPtr();
    if (thread == NULL) {
      exe_ctx.SetThreadSP(process->GetThreadList().GetSelectedThread());
      thread = exe_ctx.GetThreadPtr();
    }
    if (thread) {
      exe_ctx.SetFrameSP(thread->GetSelectedFrame());
    }
  }

  // Now we're ready to call the function:

  DiagnosticManager diagnostics;
  lldb::addr_t wrapper_struct_addr = LLDB_INVALID_ADDRESS;

  if (!m_print_object_caller_up) {
    Status error;
    m_print_object_caller_up.reset(
        exe_scope->CalculateTarget()->GetFunctionCallerForLanguage(
            eLanguageTypeObjC, return_compiler_type, *function_address,
            arg_value_list, "objc-object-description", error));
    if (error.Fail()) {
      m_print_object_caller_up.reset();
      strm.Printf("Could not get function runner to call print for debugger "
                  "function: %s.",
                  error.AsCString());
      return false;
    }
    m_print_object_caller_up->InsertFunction(exe_ctx, wrapper_struct_addr,
                                             diagnostics);
  } else {
    m_print_object_caller_up->WriteFunctionArguments(
        exe_ctx, wrapper_struct_addr, arg_value_list, diagnostics);
  }

  EvaluateExpressionOptions options;
  options.SetUnwindOnError(true);
  options.SetTryAllThreads(true);
  options.SetStopOthers(true);
  options.SetIgnoreBreakpoints(true);
  options.SetTimeout(g_po_function_timeout);

  ExpressionResults results = m_print_object_caller_up->ExecuteFunction(
      exe_ctx, &wrapper_struct_addr, options, diagnostics, ret);
  if (results != eExpressionCompleted) {
    strm.Printf("Error evaluating Print Object function: %d.\n", results);
    return false;
  }

  addr_t result_ptr = ret.GetScalar().ULongLong(LLDB_INVALID_ADDRESS);

  char buf[512];
  size_t cstr_len = 0;
  size_t full_buffer_len = sizeof(buf) - 1;
  size_t curr_len = full_buffer_len;
  while (curr_len == full_buffer_len) {
    Status error;
    curr_len = process->ReadCStringFromMemory(result_ptr + cstr_len, buf,
                                              sizeof(buf), error);
    strm.Write(buf, curr_len);
    cstr_len += curr_len;
  }
  return cstr_len > 0;
}

// why this again ???
lldb::ModuleSP MulleObjCRuntime::GetMulleObjCRuntimeModule() {
  ModuleSP module_sp(m_objc_module_wp.lock());
  if (module_sp)
    return module_sp;

  Process *process = GetProcess();
  if (process) {
    const ModuleList &modules = process->GetTarget().GetImages();
    for (uint32_t idx = 0; idx < modules.GetSize(); idx++) {
      module_sp = modules.GetModuleAtIndex(idx);
      if (MulleObjCRuntime::IsMulleObjCRuntimeModule(module_sp)) {
        m_objc_module_wp = module_sp;
        return module_sp;
      }
    }
  }
  return ModuleSP();
}

Address *MulleObjCRuntime::GetPrintForDebuggerAddr() {
  if (!m_PrintForDebugger_addr.get()) {
    const ModuleList &modules = m_process->GetTarget().GetImages();

    SymbolContextList contexts;
    SymbolContext context;

    if ((!modules.FindSymbolsWithNameAndType(ConstString("_NSPrintForDebugger"),
                                             eSymbolTypeCode, contexts)) &&
        (!modules.FindSymbolsWithNameAndType(ConstString("_CFPrintForDebugger"),
                                             eSymbolTypeCode, contexts)))
      return NULL;

    contexts.GetContextAtIndex(0, context);

    m_PrintForDebugger_addr.reset(new Address(context.symbol->GetAddress()));
  }

  return m_PrintForDebugger_addr.get();
}

bool MulleObjCRuntime::CouldHaveDynamicValue(ValueObject &in_value) {
  return in_value.GetCompilerType().IsPossibleDynamicType(
      NULL,
      false, // do not check C++
      true); // check ObjC
}

bool MulleObjCRuntime::GetDynamicTypeAndAddress(
    ValueObject &in_value, lldb::DynamicValueType use_dynamic,
    TypeAndOrName &class_type_or_name, Address &address,
    Value::ValueType &value_type) {
  return false;
}

TypeAndOrName
MulleObjCRuntime::FixUpDynamicType(const TypeAndOrName &type_and_or_name,
                                   ValueObject &static_value) {
  CompilerType static_type(static_value.GetCompilerType());
  Flags static_type_flags(static_type.GetTypeInfo());

  TypeAndOrName ret(type_and_or_name);
  if (type_and_or_name.HasType()) {
    // The type will always be the type of the dynamic object.  If our parent's
    // type was a pointer,
    // then our type should be a pointer to the type of the dynamic object.  If
    // a reference, then the original type
    // should be okay...
    CompilerType orig_type = type_and_or_name.GetCompilerType();
    CompilerType corrected_type = orig_type;
    if (static_type_flags.AllSet(eTypeIsPointer))
      corrected_type = orig_type.GetPointerType();
    ret.SetCompilerType(corrected_type);
  } else {
    // If we are here we need to adjust our dynamic type name to include the
    // correct & or * symbol
    std::string corrected_name(type_and_or_name.GetName().GetCString());
    if (static_type_flags.AllSet(eTypeIsPointer))
      corrected_name.append(" *");
    // the parent type should be a correctly pointer'ed or referenc'ed type
    ret.SetCompilerType(static_type);
    ret.SetName(corrected_name.c_str());
  }
  return ret;
}

bool MulleObjCRuntime::IsMulleObjCRuntimeModule(const ModuleSP &module_sp) {
   if (! module_sp)
      return false;

   SymbolContextList contexts;

   //
   // if mulle_objc_lldb_lookup_implementation then this module
   // contains the mulle_objc_runtime lldb code
   //
   if( module_sp->FindSymbolsWithNameAndType(
                                             ConstString( "mulle_objc_lldb_lookup_implementation"),
                                             eSymbolTypeCode, contexts))
   {
      //fprintf( stderr, "MulleObjC runtime IN DA HOUSE at \"%s\"!!\n",
      //        module_sp->GetFileSpec().GetFilename().AsCString());
      return true;
   }
   return false;
}


static bool _IsSymbolARuntimeThunk(const Symbol &symbol) {

// *** object calls ***

  static ConstString g_c_01 = ConstString( "mulle_objc_object_call");
  static ConstString g_c_02 = ConstString( "mulle_objc_object_inline_constant_methodid_call");
  static ConstString g_c_03 = ConstString( "mulle_objc_object_constant_methodid_call");
  static ConstString g_c_04 = ConstString( "mulle_objc_object_inline_variable_methodid_call");
  static ConstString g_c_05 = ConstString( "mulle_objc_objects_call");

// *** internal calls ***

  static ConstString g_c_06 = ConstString( "_mulle_objc_object_call2");
  static ConstString g_c_07 = ConstString( "_mulle_objc_object_call2_empty_cache");
  static ConstString g_c_08 = ConstString( "_mulle_objc_object_call2_needs_cache");
  static ConstString g_c_09 = ConstString( "_mulle_objc_object_call_class");
  static ConstString g_c_10 = ConstString( "_mulle_objc_object_call_class_needs_cache");
  static ConstString g_c_11 = ConstString( "_mulle_objc_object_call_class");
  static ConstString g_c_12 = ConstString( "_mulle_objc_object_noncachingcall_class");


// *** super calls ***
  static ConstString g_c_13 = ConstString( "_mulle_objc_object_supercall");
  static ConstString g_c_14 = ConstString( "_mulle_objc_object_inline_supercall");
  static ConstString g_c_15 = ConstString( "_mulle_objc_object_partialinline_supercall");

  ConstString symbol_name = symbol.GetName();

  if( ConstString::Equals( symbol_name, g_c_01, true))
    return( true);
  if( ConstString::Equals( symbol_name, g_c_02, true))
    return( true);
  if( ConstString::Equals( symbol_name, g_c_03, true))
    return( true);
  if( ConstString::Equals( symbol_name, g_c_04, true))
    return( true);
  if( ConstString::Equals( symbol_name, g_c_05, true))
    return( true);
  if( ConstString::Equals( symbol_name, g_c_06, true))
    return( true);
  if( ConstString::Equals( symbol_name, g_c_07, true))
    return( true);
  if( ConstString::Equals( symbol_name, g_c_08, true))
    return( true);
  if( ConstString::Equals( symbol_name, g_c_09, true))
    return( true);
  if( ConstString::Equals( symbol_name, g_c_10, true))
    return( true);
  if( ConstString::Equals( symbol_name, g_c_11, true))
    return( true);
  if( ConstString::Equals( symbol_name, g_c_12, true))
    return( true);
  if( ConstString::Equals( symbol_name, g_c_13, true))
    return( true);
  if( ConstString::Equals( symbol_name, g_c_14, true))
    return( true);
  if( ConstString::Equals( symbol_name, g_c_15, true))
    return( true);

  return( false);
}


bool MulleObjCRuntime::IsSymbolARuntimeThunk(const Symbol &symbol) {

  bool   flag;

  flag = _IsSymbolARuntimeThunk( symbol);
//  fprintf( stderr, "\"%s\" is %s Thunk", symbol.GetName().GetCString(),
//   flag ? "a" : "not a");
  return( flag);
}


void MulleObjCRuntime::GetValuesForGlobalCFBooleans(lldb::addr_t &cf_true,
                                                    lldb::addr_t &cf_false) {
  cf_true = cf_false = LLDB_INVALID_ADDRESS;
}

bool MulleObjCRuntime::IsModuleObjCLibrary(const ModuleSP &module_sp) {
  return IsMulleObjCRuntimeModule(module_sp);
}

bool MulleObjCRuntime::ReadObjCLibrary(const ModuleSP &module_sp) {
  // Maybe check here and if we have a handler already, and the UUID of this
  // module is the same as the one in the
  // current module, then we don't have to reread it?
  m_objc_trampoline_handler_ap.reset(
      new MulleObjCTrampolineHandler(m_process->shared_from_this(), module_sp));
  if (m_objc_trampoline_handler_ap.get() != NULL && m_objc_trampoline_handler_ap.get()->CanStepThrough()) {
    m_read_objc_library = true;
     // fprintf( stderr, "ReadObjCLibrary succeeds\n");
    return true;
  }

   //  fprintf( stderr, "ReadObjCLibrary fails\n");
  m_read_objc_library = false; // pedantically reset
  return false;
}

ThreadPlanSP MulleObjCRuntime::GetStepThroughTrampolinePlan(Thread &thread,
                                                            StackID &return_stack_id,
                                                            bool stop_others) {
  ThreadPlanSP thread_plan_sp;

  if (m_objc_trampoline_handler_ap.get())
    thread_plan_sp = m_objc_trampoline_handler_ap->GetStepThroughDispatchPlan(
        thread, return_stack_id, stop_others);
  return thread_plan_sp;
}

//------------------------------------------------------------------
// Static Functions
//------------------------------------------------------------------
ObjCLanguageRuntime::ObjCRuntimeVersions
MulleObjCRuntime::GetObjCVersion(Process *process, ModuleSP &objc_module_sp) {
  if (!process)
    return ObjCRuntimeVersions::eObjC_VersionUnknown;

  Target &target = process->GetTarget();

  const ModuleList &target_modules = target.GetImages();
  std::lock_guard<std::recursive_mutex> gaurd(target_modules.GetMutex());

  size_t num_images = target_modules.GetSize();
  for (size_t i = 0; i < num_images; i++) {
    ModuleSP module_sp = target_modules.GetModuleAtIndexUnlocked(i);

     // isLoadedInTarget doesn't work for me, since we get called
     // _while_ loading apparently so main f.e. will be found as
     // a symbol, but the module itself is not loaded yet
     // (or so it seems, as we are statically linking ?)

     if ( // module_sp->IsLoadedInTarget(&target) &&
        IsMulleObjCRuntimeModule(module_sp)
        ) {
      return ObjCRuntimeVersions::eMulleObjC_V1;
    }
  }

  return ObjCRuntimeVersions::eObjC_VersionUnknown;
}

void MulleObjCRuntime::SetExceptionBreakpoints() {
  const bool catch_bp = false;
  const bool throw_bp = true;
  const bool is_internal = true;

  if (!m_objc_exception_bp_sp) {
    m_objc_exception_bp_sp = LanguageRuntime::CreateExceptionBreakpoint(
        m_process->GetTarget(), GetLanguageType(), catch_bp, throw_bp,
        is_internal);
    if (m_objc_exception_bp_sp)
      m_objc_exception_bp_sp->SetBreakpointKind("ObjC exception");
  } else
    m_objc_exception_bp_sp->SetEnabled(true);
}

void MulleObjCRuntime::ClearExceptionBreakpoints() {
  if (!m_process)
    return;

  if (m_objc_exception_bp_sp.get()) {
    m_objc_exception_bp_sp->SetEnabled(false);
  }
}

bool MulleObjCRuntime::ExceptionBreakpointsAreSet() {
  return m_objc_exception_bp_sp && m_objc_exception_bp_sp->IsEnabled();
}

bool MulleObjCRuntime::ExceptionBreakpointsExplainStop(
    lldb::StopInfoSP stop_reason) {
  if (!m_process)
    return false;

  if (!stop_reason || stop_reason->GetStopReason() != eStopReasonBreakpoint)
    return false;

  uint64_t break_site_id = stop_reason->GetValue();
  return m_process->GetBreakpointSiteList().BreakpointSiteContainsBreakpoint(
      break_site_id, m_objc_exception_bp_sp->GetID());
}

bool MulleObjCRuntime::CalculateHasNewLiteralsAndIndexing() {
    return false;
}

lldb::SearchFilterSP MulleObjCRuntime::CreateExceptionSearchFilter() {
    return LanguageRuntime::CreateExceptionSearchFilter();
}

void MulleObjCRuntime::ReadObjCLibraryIfNeeded(const ModuleList &module_list) {
   // it seems, that when you run again ModulesDidLoad gets called
   // and this "caching" fcks things up
   //if (!HasReadObjCLibrary())
  {
    std::lock_guard<std::recursive_mutex> guard(module_list.GetMutex());

    size_t num_modules = module_list.GetSize();
    for (size_t i = 0; i < num_modules; i++) {
      auto mod = module_list.GetModuleAtIndex(i);
      if(IsModuleObjCLibrary(mod)) {
        ReadObjCLibrary(mod);
        break;
      }
    }
  }
}

void MulleObjCRuntime::ModulesDidLoad(const ModuleList &module_list) {
  ReadObjCLibraryIfNeeded(module_list);
}
