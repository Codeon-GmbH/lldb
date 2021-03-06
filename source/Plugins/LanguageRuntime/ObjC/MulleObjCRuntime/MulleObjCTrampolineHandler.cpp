//===-- MulleObjCTrampolineHandler.cpp ----------------------------*- C++
//-*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "MulleObjCTrampolineHandler.h"

// C Includes
// C++ Includes
// Other libraries and framework includes
// Project includes
#include "MulleThreadPlanStepThroughObjCTrampoline.h"

#include "lldb/Breakpoint/StoppointCallbackContext.h"
#include "lldb/Core/Debugger.h"
#include "lldb/Core/Module.h"
#include "lldb/Core/StreamFile.h"
#include "lldb/Core/Value.h"
#include "lldb/Expression/DiagnosticManager.h"
#include "lldb/Expression/FunctionCaller.h"
#include "lldb/Expression/UserExpression.h"
#include "lldb/Expression/UtilityFunction.h"
#include "lldb/Symbol/ClangASTContext.h"
#include "lldb/Symbol/Symbol.h"
#include "lldb/Target/ABI.h"
#include "lldb/Target/ExecutionContext.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/RegisterContext.h"
#include "lldb/Target/Target.h"
#include "lldb/Target/Thread.h"
#include "lldb/Target/ThreadPlanRunToAddress.h"
#include "lldb/Target/ThreadPlanStepOut.h"
#include "lldb/Utility/ConstString.h"
#include "lldb/Utility/FileSpec.h"
#include "lldb/Utility/Log.h"
#include "lldb/Utility/Status.h"

#include "llvm/ADT/STLExtras.h"

#include "Plugins/LanguageRuntime/ObjC/ObjCLanguageRuntime.h"

#define MULLE_LOG   LIBLLDB_LOG_LANGUAGE
//#define MULLE_LOG   LIBLLDB_LOG_STEP


using namespace lldb;
using namespace lldb_private;

static const char *g_lookup_implementation_function_name =
    "__lldb_objc_find_implementation_for_selector";

static const char g_lookup_implementation_function_code[] =

#include "mulle-objc-lookup-imp.inc"
;


MulleObjCTrampolineHandler::~MulleObjCTrampolineHandler() {}

// what should we step through anyway ?
// I would say "front" facing function calls emitted by -O0
// which are:
//
//   mulle_objc_object_call
//   _mulle_objc_object_supercall
//
// We should also step through
//   mulle_objc_fastlookup_infraclass_nofail
// but we can't for now. (Why not ?)
//
const MulleObjCTrampolineHandler::DispatchFunction
    MulleObjCTrampolineHandler::g_dispatch_functions[] = {
        // NAME                              HAS_CLASS_ARG  HAS_SUPERID_ARG
       { "mulle_objc_object_call",            false,  false, true  },
       // super calls, where we have a classid as fourth parameter
       { "_mulle_objc_object_supercall",      false, true, true  }
       // optimized calls, where we have a class as fourth parameter

       // maybe these second stages too ?
       // { "_mulle_objc_object_call2",          false,  false, false },
       // { "_mulle_objc_object_call_class",     true, false, false }
    };


lldb::addr_t  MulleObjCTrampolineHandler::LookupFunctionSymbol( const lldb::ProcessSP &process_sp,
                                                                const char *name,
                                                                bool warn_if_missing)
{
   // Look up the addresses for the objc dispatch functions and cache them.  For
   // now I'm inspecting the symbol
   // names dynamically to figure out how to dispatch to them.  If it becomes
   // more complicated than this we can
   // turn the g_dispatch_functions char * array into a template table, and
   // populate the DispatchFunction map
   // from there.

   ConstString name_const_str( name);
   const Symbol *msgSend_symbol =
      m_objc_module_sp->FindFirstSymbolWithNameAndType(name_const_str,
                                                    eSymbolTypeCode);
   Target *target = process_sp ? &process_sp->GetTarget() : NULL;

   if (msgSend_symbol && msgSend_symbol->ValueIsAddress()) {
      // FixMe: Make g_dispatch_functions static table of DispatchFunctions, and
      // have the map be address->index.
      // Problem is we also need to lookup the dispatch function.  For now we
      // could have a side table of stret & non-stret
      // dispatch functions.  If that's as complex as it gets, we're fine.

      lldb::addr_t sym_addr =
      msgSend_symbol->GetAddressRef().GetOpcodeLoadAddress(target);
      return( sym_addr);
   }
   else
   {
      Log *log(lldb_private::GetLogIfAllCategoriesSet(MULLE_LOG));

      if( log)
        log->Printf("Could not find implementation for function \"%s\"\n",
                                                        name_const_str.AsCString());
      if( warn_if_missing)
      {
         if( target) {
            target->GetDebugger().GetErrorFile()->Printf( "Could not find implementation for function \"%s\"\n",
                                                         name_const_str.AsCString());
         }
      }
   }
   return( LLDB_INVALID_ADDRESS);
}

static const struct {
   const char   *name;
   bool         required;
} lookup_functions[ 13] =
{
  { "mulle_objc_object_lookup_infraclass_nofail", true },              // first one MUST be present
  { "mulle_objc_object_lookup_infraclass_nofail_nofast", true },
  { "mulle_objc_global_lookup_infraclass_nofail_nofast", true },
  { "mulle_objc_global_lookup_infraclass_nofail", true },

  { "_mulle_objc_universe_lookup_infraclass_nocache_nofail_nofast", true },
  { "_mulle_objc_universe_lookup_infraclass_nocache_nofast", true },
  { "_mulle_objc_universe_lookup_infraclass_nofail_nofast", true },

  { "_mulle_objc_universe_inlinelookup_infraclass_nocache_nofast", false },
  { "_mulle_objc_universe_inlinelookup_infraclass_nofail", false },
  { "_mulle_objc_universe_inlinelookup_infraclass", false },

  { "mulle_objc_global_inlinelookup_infraclass_nofail_nofast", false },
  { "mulle_objc_global_inlinelookup_infraclass_nofail", false },
  { "mulle_objc_object_inlinelookup_infraclass_nofail", false }
};

MulleObjCTrampolineHandler::MulleObjCTrampolineHandler(
    const ProcessSP &process_sp, const ModuleSP &objc_module_sp)
    : m_process_wp(), m_objc_module_sp(objc_module_sp),
      m_lookup_implementation_function_code(nullptr),
      m_impl_fn_addr(LLDB_INVALID_ADDRESS),
      m_msg_forward_addr(LLDB_INVALID_ADDRESS) {
  if (process_sp)
    m_process_wp = process_sp;
  // Look up the known resolution functions:

  lldb::addr_t sym_addr;

  for (size_t i = 0; i != llvm::array_lengthof(g_dispatch_functions); i++) {
     sym_addr = LookupFunctionSymbol( process_sp,
                                      g_dispatch_functions[ i].name,
                                      g_dispatch_functions[ i].required);
     if( sym_addr != LLDB_INVALID_ADDRESS)
        m_msgSend_map.insert(std::pair<lldb::addr_t, int>(sym_addr, i));
  }

  for (size_t i = 0; i != llvm::array_lengthof(m_classlookup_addr); i++) {
    m_classlookup_addr[ i] = LookupFunctionSymbol( process_sp,
                                                   lookup_functions[ i].name,
                                                   lookup_functions[ i].required);
  }

  ConstString get_impl_name( "mulle_objc_lldb_lookup_implementation");
  Target *target = process_sp ? &process_sp->GetTarget() : NULL;

  const Symbol *class_getMethodImplementation =
      m_objc_module_sp->FindFirstSymbolWithNameAndType(get_impl_name,
                                                       eSymbolTypeCode);
  if (class_getMethodImplementation)
    m_impl_fn_addr =
        class_getMethodImplementation->GetAddress().GetOpcodeLoadAddress(
            target);
  // == mulle-objc has no global forward vector ==
  // ConstString msg_forward_name("__forward_mulle_objc_object_call");
  // const Symbol *msg_forward = m_objc_module_sp->FindFirstSymbolWithNameAndType(
  //     msg_forward_name, eSymbolTypeCode);
  //
  //if (msg_forward)
  //  m_msg_forward_addr = msg_forward->GetAddress().GetOpcodeLoadAddress(target);

  // FIXME: Do some kind of logging here.
  if (m_impl_fn_addr == LLDB_INVALID_ADDRESS) {
    // If we can't even find the ordinary get method implementation function,
    // then we aren't going to be able to
    // step through any method dispatches.  Warn to that effect and get out of
    // here.
    if (target) {
      target->GetDebugger().GetErrorFile()->Printf(
          "Could not find implementation lookup function \"%s\""
          " in \"%s\" (%s)"
          " stepping through ObjC method dispatch will not work.\n",
          get_impl_name.AsCString(),
          m_objc_module_sp->GetFileSpec().GetCString(),
          class_getMethodImplementation ? "process failure" : "symbol not found");
    }
    Log *log(lldb_private::GetLogIfAllCategoriesSet(MULLE_LOG));

    if (log)
      log->Printf(
        "Could not find implementation lookup function \"%s\""
        " in \"%s\" (%s)"
        " stepping through ObjC method dispatch will not work.\n",
        get_impl_name.AsCString(),
        m_objc_module_sp->GetFileSpec().GetCString(),
        class_getMethodImplementation ? "process failure" : "symbol not found");
  } else  {
    m_lookup_implementation_function_code =
        g_lookup_implementation_function_code;
  }
}


lldb::addr_t
MulleObjCTrampolineHandler::SetupDispatchFunction(Thread &thread,
                                                  ValueList &dispatch_values) {
  ThreadSP thread_sp(thread.shared_from_this());
  ExecutionContext exe_ctx(thread_sp);
  DiagnosticManager diagnostics;
  Log *log(lldb_private::GetLogIfAllCategoriesSet(MULLE_LOG));

  lldb::addr_t args_addr = LLDB_INVALID_ADDRESS;
  FunctionCaller *impl_function_caller = nullptr;

  // Scope for mutex locker:
  {
    std::lock_guard<std::mutex> guard(m_impl_function_mutex);

    // First stage is to make the ClangUtility to hold our injected function:

    if (!m_impl_code) {
      if (m_lookup_implementation_function_code != nullptr) {
        Status error;
        m_impl_code.reset(exe_ctx.GetTargetRef().GetUtilityFunctionForLanguage(
            m_lookup_implementation_function_code, eLanguageTypeObjC,
            g_lookup_implementation_function_name, error));
        if (error.Fail()) {
          if (log)
            log->Printf(
                "Failed to get Utility Function for implementation lookup: %s.",
                error.AsCString());
          m_impl_code.reset();
          return args_addr;
        }

        if (!m_impl_code->Install(diagnostics, exe_ctx)) {
          if (log) {
            log->Printf("Failed to install implementation lookup \"%s\".", g_lookup_implementation_function_name);
            log->Printf( "Source code: ------\n%s\n------\n", m_lookup_implementation_function_code);
            diagnostics.Dump(log);
          }
          m_impl_code.reset();
          return args_addr;
        }
      } else {
        if (log)
          log->Printf("No method lookup implementation code.");
        return LLDB_INVALID_ADDRESS;
      }

      // Next make the runner function for our implementation utility function.
      ClangASTContext *clang_ast_context =
          thread.GetProcess()->GetTarget().GetScratchClangASTContext();
      CompilerType clang_void_ptr_type =
          clang_ast_context->GetBasicType(eBasicTypeVoid).GetPointerType();
      Status error;

      impl_function_caller = m_impl_code->MakeFunctionCaller(
          clang_void_ptr_type, dispatch_values, thread_sp, error);
      if (error.Fail()) {
        if (log)
          log->Printf(
              "Error getting function caller for dispatch lookup: \"%s\".",
              error.AsCString());
        return args_addr;
      }
    } else {
      impl_function_caller = m_impl_code->GetFunctionCaller();
    }
  }

  diagnostics.Clear();

  // Now write down the argument values for this particular call.
  // This looks like it might be a race condition if other threads
  // were calling into here, but actually it isn't because we allocate
  // a new args structure for this call by passing args_addr =
  // LLDB_INVALID_ADDRESS...

  if (!impl_function_caller->WriteFunctionArguments(
          exe_ctx, args_addr, dispatch_values, diagnostics)) {
    if (log) {
      log->Printf("Error writing function arguments.");
      diagnostics.Dump(log);
    }
    return args_addr;
  }

  return args_addr;
}

bool
MulleObjCTrampolineHandler::GetDispatchFunctionForPCViaMap( lldb::addr_t curr_pc, DispatchFunction &this_dispatch)
{
   MsgsendMap::iterator pos;

   // fprintf( stderr, "%s PC: 0x%llx\n", __PRETTY_FUNCTION__, (unsigned long long) curr_pc);

   pos = m_msgSend_map.find( curr_pc);
   if (pos != m_msgSend_map.end())
   {
      this_dispatch = g_dispatch_functions[(*pos).second];
      // fprintf( stderr, "known dispatch pc\n");
      return( true);
   }
   return( false);
}


lldb::addr_t
MulleObjCTrampolineHandler::ReadIndirectJMPQ_X86_64( lldb::addr_t curr_pc)
{
#pragma pack( push, 1)
#pragma pack( 2)
   struct
   {
      uint16_t   opcode;
      int32_t    offset;
   } instruction;
#pragma pack( pop)

   Status         error;
   size_t         bytes_read;
   void           *f;
   lldb::addr_t   table_adr;

   // fprintf( stderr, "%s PC: 0x%llx\n", __PRETTY_FUNCTION__, (unsigned long long) curr_pc);

   ProcessSP process_sp = m_process_wp.lock();
   if( ! process_sp)
   {
      // fprintf( stderr, "fail process\n");
      return( LLDB_INVALID_ADDRESS);
   }

   bytes_read = process_sp->ReadMemory( curr_pc, &instruction, sizeof( instruction), error);
   if( bytes_read != sizeof( instruction))
   {
      // fprintf( stderr, "fail instruction read\n");
      return( LLDB_INVALID_ADDRESS);
   }
   if( instruction.opcode != 0x25FF)  // jmpq rel a
   {
      // fprintf( stderr, "fail opcode: %x\n", instruction.opcode);
      return( LLDB_INVALID_ADDRESS);
   }

   // fprintf( stderr, "offset, 0x%x\n", instruction.offset);
   table_adr  = curr_pc + sizeof( instruction) + instruction.offset;
   bytes_read = process_sp->ReadMemory( table_adr, &f, sizeof( f), error);
   if( bytes_read != sizeof( f))
   {
      // fprintf( stderr, "fail f read\n");
      return( LLDB_INVALID_ADDRESS);
   }
   return( (lldb::addr_t) f);
}


ThreadPlanSP
MulleObjCTrampolineHandler::GetStepOutDispatchPlan( Thread &thread,
                                                    bool stop_others)
{
   Status status;
   return( thread.QueueThreadPlanForStepOut( false, nullptr, false, stop_others,
                                            eVoteYes, eVoteNoOpinion,
                                            thread.GetSelectedFrameIndex(),
                                            status));
}


ThreadPlanSP
MulleObjCTrampolineHandler::GetStepThroughDispatchPlan( Thread &thread,
                                                        bool stop_others)
{
   ThreadPlanSP ret_plan_sp;
   lldb::addr_t curr_pc = thread.GetRegisterContext()->GetPC();
   lldb::addr_t indirect_pc;
   DispatchFunction this_dispatch;
   bool found_it;

   Log *log(lldb_private::GetLogIfAllCategoriesSet( MULLE_LOG));

   if( CanStepOver())
   {
      for( size_t i = 0; i < llvm::array_lengthof(m_classlookup_addr); i++)
         if( curr_pc == m_classlookup_addr[ i])
         {
            if (log)
               log->Printf( "Mulle: Return with \"step out of class-lookup\" plan.");

            ret_plan_sp.reset( new ThreadPlanStepOut(
                     thread,
                     nullptr,
                     false, stop_others, eVoteYes,
                     eVoteNoOpinion, thread.GetSelectedFrameIndex(),
                     eLazyBoolNo));
            return( ret_plan_sp);
         }
   }

   // First step is to look and see if we are in one of the known ObjC dispatch functions.  We've already compiled
   // a table of same, so consult it.
   found_it = GetDispatchFunctionForPCViaMap( curr_pc, this_dispatch);

   // figure out the indirect address if PC is pointing to
   // a jump vector

   if( ! found_it)
   {
      indirect_pc = ReadIndirectJMPQ_X86_64( curr_pc);

      // fprintf( stderr, "indirect PC: 0x%llx\n", (unsigned long long) indirect_pc);

      if( indirect_pc != LLDB_INVALID_ADDRESS)
      {
         // and consult again for indirect_pc
         found_it = GetDispatchFunctionForPCViaMap( indirect_pc, this_dispatch);
      }
   }

   if( ! found_it)
   {
      if (log)
         log->Printf( "Mulle: Unknown dispatch address 0x%llx. Returning empty plan.", (unsigned long long) curr_pc);
      // fprintf( stderr, "*unknown dispatch*\n");
      return ret_plan_sp;
   }

   // We are decoding a method dispatch.
   // First job is to pull the arguments out:

   lldb::StackFrameSP thread_cur_frame = thread.GetStackFrameAtIndex(0);

   const ABI *abi = NULL;
   ProcessSP process_sp (thread.CalculateProcess());
   if (process_sp)
      abi = process_sp->GetABI().get();
   if (abi == NULL)
   {
      if (log)
         log->Printf( "Mulle: Unknown ABI. Returning empty plan.");
      return ret_plan_sp;
   }
   TargetSP target_sp (thread.CalculateTarget());

   ClangASTContext *clang_ast_context = target_sp->GetScratchClangASTContext();
   ValueList argument_values;

   Value void_ptr_value;
   CompilerType clang_void_ptr_type = clang_ast_context->GetBasicType(eBasicTypeVoid).GetPointerType();
   void_ptr_value.SetValueType (Value::eValueTypeScalar);
   //void_ptr_value.SetContext (Value::eContextTypeClangType, clang_void_ptr_type);
   void_ptr_value.SetCompilerType (clang_void_ptr_type);

   Value uint32_t_value;
   CompilerType clang_uint32_type = clang_ast_context->GetBuiltinTypeForEncodingAndBitSize(lldb::eEncodingUint, 32);
   uint32_t_value.SetValueType (Value::eValueTypeScalar);
   //void_ptr_value.SetContext (Value::eContextTypeClangType, clang_void_ptr_type);
   uint32_t_value.SetCompilerType(clang_uint32_type);

   Value int_value;
   CompilerType clang_int_type = clang_ast_context->GetBuiltinTypeForEncodingAndBitSize(lldb::eEncodingSint, 32);
   int_value.SetValueType (Value::eValueTypeScalar);
   //flag_value.SetContext (Value::eContextTypeClangType, clang_int_type);
   int_value.SetCompilerType (clang_int_type);

   argument_values.PushValue(void_ptr_value);   // self
   argument_values.PushValue(uint32_t_value);   // _cmd
   argument_values.PushValue(void_ptr_value);   // _param
   if( this_dispatch.has_superid_argument)
      argument_values.PushValue(uint32_t_value);   // superid
   else
   if( this_dispatch.has_superid_argument)
      argument_values.PushValue(void_ptr_value);   // class

   /*
    * read from the registers and stack the actual values for
    * the method call we are "intercepting"
    */
   bool success = abi->GetArgumentValues (thread, argument_values);
   if( ! success)
   {
      // fprintf( stderr, "fail getting argument values\n");
      if (log)
         log->Printf( "Mulle: Problem getting argument values. Returning empty plan.");
      return ret_plan_sp;
   }

   lldb::addr_t obj_addr   = argument_values.GetValueAtIndex(0)->GetScalar().ULongLong();
   lldb::addr_t sel_addr   = argument_values.GetValueAtIndex(1)->GetScalar().ULongLong();
   // lldb::addr_t param_addr = argument_values.GetValueAtIndex(2)->GetScalar().ULongLong();

   if( obj_addr == 0x0)
   {
      if (log)
         log->Printf("Mulle: Asked to step to dispatch to nil object. Returning empty plan.");
      return ret_plan_sp;
   }

   ExecutionContext exe_ctx (thread.shared_from_this());
   Process *process = exe_ctx.GetProcessPtr();

   // Figure out the class this is being dispatched to and see if we've already cached this method call,
   // If so we can push a run-to-address plan directly.  Otherwise we have to figure out where
   // the implementation lives.

   // isa_addr will store the class pointer that the method is being dispatched to - so either the class
   // directly or the super class if this is one of the objc_msgSendSuper flavors.  That's mostly used to
   // look up the class/selector pair in our cache.

   lldb::addr_t isa_addr   = LLDB_INVALID_ADDRESS;

   // has cls
   if( this_dispatch.has_class_argument)
   {
      Value cls_value( *(argument_values.GetValueAtIndex(3)));

      cls_value.SetCompilerType( clang_void_ptr_type);
      cls_value.SetValueType( Value::eValueTypeLoadAddress);
      cls_value.ResolveValue( &exe_ctx);
      // fprintf( stderr, "super2\n");
      if ( ! cls_value.GetScalar().IsValid())
      {
         if (log)
            log->Printf("Mulle: Supplied class is invalid. Returning empty plan.");
         return ret_plan_sp;
      }
      // fprintf( stderr, "get isa\n");
      isa_addr = cls_value.GetScalar().ULongLong();
   }
   else
   {
      // In the direct dispatch case, the object->isa is the class pointer we want.

      // This is a little cheesy, but since object->isa is the first field,
      // making the object value a load address value and resolving it will get
      // the pointer sized data pointed to by that value...

      // Note, it isn't a fatal error not to be able to get the address from the object, since this might
      // be a "tagged pointer" which isn't a real object, but rather some word length encoded dingus.

      // figure out isa from object argument. If its a tagged pointer, we can't use the isa lookup
      // cache but run the lookup function every time

      if( (obj_addr & 0x7) == 0)  // quick tagged pointer check
      {
         Value isa_value( obj_addr - (int) process->GetAddressByteSize());
         // fprintf( stderr, "super: 0x%llx\n", isa_value.GetScalar().ULongLong());
         isa_value.SetCompilerType(clang_void_ptr_type);
         isa_value.SetValueType(Value::eValueTypeLoadAddress);
         isa_value.ResolveValue(&exe_ctx);

         if (isa_value.GetScalar().IsValid())
         {
            // fprintf( stderr, "get isa\n");
            isa_addr = isa_value.GetScalar().ULongLong();
         }
         else
         {
            if (log)
               log->Printf("Mulle: Supplied class is invalid. Returning empty plan.");
            return ret_plan_sp;
         }
      }
   }
   // in the case of obj, _cmd, _param, clsid: isa_addr is still unknown

   // Okay, we've may have got the address of the class for which we're resolving this, let's see if it's in our cache:
   lldb::addr_t impl_addr = LLDB_INVALID_ADDRESS;

   if( log)
   {
      log->Printf("Mulle: obj     = 0x%llx\n", (unsigned long long) obj_addr);
      log->Printf("Mulle: _cmd    = 0x%llx\n", (unsigned long long) sel_addr);
      // log->Printf("Mulle: _param : 0x%llx\n", (unsigned long long) param_addr);
      log->Printf("Mulle: isa     = 0x%llx\n", (unsigned long long) isa_addr);
   }

   if (isa_addr != LLDB_INVALID_ADDRESS)
   {
      if (log)
      {
         log->Printf("Mulle: Resolving call for class - 0x%" PRIx64 " and selector - 0x%" PRIx64,
                     isa_addr, sel_addr);
      }
      ObjCLanguageRuntime *objc_runtime = ObjCLanguageRuntime::Get(*thread.GetProcess());
      assert(objc_runtime != NULL);

      impl_addr = objc_runtime->LookupInMethodCache (isa_addr, sel_addr);
      // fprintf( stderr, "impl: 0x%llx\n", (unsigned long long)impl_addr);
   }

   if (impl_addr != LLDB_INVALID_ADDRESS)
   {
      // Yup, it was in the cache, so we can run to that address directly.

      if (log)
         log->Printf ("Mulle: Found implementation address in cache: 0x%" PRIx64 ". Return run to address plan.", impl_addr);

      ret_plan_sp.reset (new ThreadPlanRunToAddress (thread, impl_addr, stop_others));
      // fprintf( stderr, "cached return\n");
      return ret_plan_sp;
   }

   // We haven't seen this class/selector pair yet.  Look it up.
   if (log)
      log->Printf( "Mulle: Lookup implementation for method");

   ValueList dispatch_values;

   // We've will inject a little function in the target that takes the object, selector and some flags,
   // and figures out the implementation.  Looks like:
   //      void *__lldb_objc_find_implementation_for_selector (void *object,
   //                                                          uint32_t sel,
   //                                                          void *cls_or_superid,
   //                                                          int calltype,
   //                                                          int debug,
   //
   // So set up the arguments for that call.
   dispatch_values.PushValue (*(argument_values.GetValueAtIndex(0)));
   dispatch_values.PushValue (*(argument_values.GetValueAtIndex(1)));

   if( this_dispatch.has_superid_argument || this_dispatch.has_class_argument)
   {
      Value  value( *(argument_values.GetValueAtIndex( 3)));

      value.SetCompilerType( clang_void_ptr_type);
      dispatch_values.PushValue( value); // just push it
   }

   if( this_dispatch.has_superid_argument)
      int_value.GetScalar() = 2;
   else
      if( this_dispatch.has_class_argument)
         int_value.GetScalar() = 1;
      else
         int_value.GetScalar() = 0;
   dispatch_values.PushValue(int_value);

   if (log && log->GetVerbose())
      int_value.GetScalar() = 1;
   else
      int_value.GetScalar() = 0;
   dispatch_values.PushValue( int_value);

   // The step through code might have to fill in the cache, so it is not safe to run only one thread.
   // So we override the stop_others value passed in to us here:

   const bool trampoline_stop_others = false;
   ret_plan_sp.reset (new MulleThreadPlanStepThroughObjCTrampoline (thread,
                                                                    this,
                                                                    dispatch_values,
                                                                    isa_addr,
                                                                    sel_addr,
                                                                    trampoline_stop_others));
   if (log)
   {
      StreamString s;
      ret_plan_sp->GetDescription(&s, eDescriptionLevelFull);
      log->Printf( "Mulle: Using ObjC step through plan: %s.\n", s.GetData());
   }
   //  fprintf( stderr, "trampoline return\n");

   return ret_plan_sp;
}


FunctionCaller *
MulleObjCTrampolineHandler::GetLookupImplementationFunctionCaller() {
  return m_impl_code->GetFunctionCaller();
}
