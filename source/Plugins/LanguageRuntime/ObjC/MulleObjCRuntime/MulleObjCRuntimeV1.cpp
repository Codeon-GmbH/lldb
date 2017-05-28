//===-- MulleObjCRuntimeV1.cpp --------------------------------------*- C++
//-*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "MulleObjCRuntimeV1.h"
#include "MulleObjCTrampolineHandler.h"

#include "clang/AST/Type.h"

#include "lldb/Breakpoint/BreakpointLocation.h"
#include "lldb/Core/Module.h"
#include "lldb/Core/PluginManager.h"
#include "lldb/Core/Scalar.h"
#include "lldb/Expression/DiagnosticManager.h"
#include "lldb/Expression/FunctionCaller.h"
#include "lldb/Expression/UtilityFunction.h"
#include "lldb/Symbol/ClangASTContext.h"
#include "lldb/Symbol/Symbol.h"
#include "lldb/Target/ExecutionContext.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/RegisterContext.h"
#include "lldb/Target/Target.h"
#include "lldb/Target/Thread.h"
#include "lldb/Utility/ConstString.h"
#include "lldb/Utility/Log.h"
#include "lldb/Utility/Status.h"
#include "lldb/Utility/StreamString.h"

#include <vector>

using namespace lldb;
using namespace lldb_private;


static const char *g_dangerous_function_name =
"__lldb_objc_get_dangerous_class_storage";

static const char *g_dangerous_function_code =
"extern \"C\"\n"
"{\n"
#include "mulle-objc-dangerous-class-storage.inc"
"}\n";


MulleObjCRuntimeV1::MulleObjCRuntimeV1(Process *process)
    : MulleObjCRuntime(process), m_hash_signature(),
      m_isa_hash_table_ptr(LLDB_INVALID_ADDRESS) {}

// for V1 runtime we just try to return a class name as that is the minimum
// level of support
// required for the data formatters to work
bool MulleObjCRuntimeV1::GetDynamicTypeAndAddress(
    ValueObject &in_value, lldb::DynamicValueType use_dynamic,
    TypeAndOrName &class_type_or_name, Address &address,
    Value::ValueType &value_type) {
  class_type_or_name.Clear();
  value_type = Value::ValueType::eValueTypeScalar;
  if (CouldHaveDynamicValue(in_value)) {
    auto class_descriptor(GetClassDescriptor(in_value));
    if (class_descriptor && class_descriptor->IsValid() &&
        class_descriptor->GetClassName()) {
      const addr_t object_ptr = in_value.GetPointerValue();
      address.SetRawAddress(object_ptr);
      class_type_or_name.SetName(class_descriptor->GetClassName());
    }
  }
  return class_type_or_name.IsEmpty() == false;
}

//------------------------------------------------------------------
// Static Functions
//------------------------------------------------------------------
lldb_private::LanguageRuntime *
MulleObjCRuntimeV1::CreateInstance(Process *process,
                                   lldb::LanguageType language) {
  if (language == eLanguageTypeObjC) {
    ModuleSP objc_module_sp;

    if (MulleObjCRuntime::GetObjCVersion(process, objc_module_sp) ==
        ObjCRuntimeVersions::eMulleObjC_V1)
      return new MulleObjCRuntimeV1(process);
    else
      return NULL;
  } else
    return NULL;
}

void MulleObjCRuntimeV1::Initialize() {
  PluginManager::RegisterPlugin(
      GetPluginNameStatic(), "Mulle Objective C Language Runtime - Version 1",
      CreateInstance);
}

void MulleObjCRuntimeV1::Terminate() {
  PluginManager::UnregisterPlugin(CreateInstance);
}

lldb_private::ConstString MulleObjCRuntimeV1::GetPluginNameStatic() {
  static ConstString g_name("mulle-objc-v1");
  return g_name;
}

//------------------------------------------------------------------
// PluginInterface protocol
//------------------------------------------------------------------
ConstString MulleObjCRuntimeV1::GetPluginName() {
  return GetPluginNameStatic();
}

uint32_t MulleObjCRuntimeV1::GetPluginVersion() { return 1; }

BreakpointResolverSP
MulleObjCRuntimeV1::CreateExceptionResolver(Breakpoint *bkpt, bool catch_bp,
                                            bool throw_bp) {
  BreakpointResolverSP resolver_sp;

  if (throw_bp)
    resolver_sp.reset(new BreakpointResolverName(
        bkpt, "mulle_objc_exception_throw", eFunctionNameTypeBase,
        eLanguageTypeUnknown, Breakpoint::Exact, 0, eLazyBoolNo));
  // FIXME: don't do catch yet.
  return resolver_sp;
}

struct BufStruct {
  char contents[2048];
};

UtilityFunction *MulleObjCRuntimeV1::CreateObjectChecker(const char *name) {
  std::unique_ptr<BufStruct> buf(new BufStruct);

  int strformatsize = snprintf(&buf->contents[0], sizeof(buf->contents),
"extern \"C\"\n"
"{\n"
#include "mulle-objc-object-checker.inc"
"}",
                  name);
  assert(strformatsize < (int)sizeof(buf->contents));

  Status error;
  return GetTargetRef().GetUtilityFunctionForLanguage(
      buf->contents, eLanguageTypeObjC, name, error);
}

MulleObjCRuntimeV1::ClassDescriptorV1::ClassDescriptorV1(
    ValueObject &isa_pointer) {
  Initialize(isa_pointer.GetValueAsUnsigned(0), isa_pointer.GetProcessSP());
}

MulleObjCRuntimeV1::ClassDescriptorV1::ClassDescriptorV1(
    ObjCISA isa, lldb::ProcessSP process_sp) {
  Initialize(isa, process_sp);
}

void MulleObjCRuntimeV1::ClassDescriptorV1::Initialize(ObjCISA isa,
                                                       lldb::ProcessSP process_sp)
{
   if (!isa || !process_sp)
   {
      // fprintf( stderr, "fail isa\n");
      m_valid = false;
      return;
   }
   
   
   m_valid = true;
   
   Status error;
   
   uint32_t ptr_size = process_sp->GetAddressByteSize();
   
   // get isa of class
   m_isa = process_sp->ReadPointerFromMemory( isa - ptr_size, error);
   
   if (error.Fail())
   {
      // fprintf( stderr, "fail m_isa 0x%llx, isa 0x%llx\n", (long long) m_isa, (long long) isa);
      m_valid = false;
      return;
   }
   
   
   if (!IsPointerValid(m_isa,ptr_size))
   {
      // fprintf( stderr, "fail isa\n");
      m_valid = false;
      return;
   }
   
   // get superclass or what ?
   m_parent_isa = process_sp->ReadPointerFromMemory( isa + 5 * ptr_size, error);
   
   if (error.Fail())
   {
      // fprintf( stderr, "fail superclass\n");
      m_valid = false;
      return;
   }
   
   if (!IsPointerValid(m_parent_isa,ptr_size,true))
   {
      // fprintf( stderr, "fail superclass 2\n");
      m_valid = false;
      return;
   }
   
   // get name
   lldb::addr_t name_ptr = process_sp->ReadPointerFromMemory( isa + 3 * ptr_size,error);
   
   if (error.Fail())
   {
      // fprintf( stderr, "fail name offset\n");
      m_valid = false;
      return;
   }
   
   lldb::DataBufferSP buffer_sp(new DataBufferHeap(1024, 0));
   
   size_t count = process_sp->ReadCStringFromMemory(name_ptr, (char*)buffer_sp->GetBytes(), 1024, error);
   
   if (error.Fail())
   {
      // fprintf( stderr, "fail name read: 0x%llx\n", (unsigned long long) name_ptr);
      m_valid = false;
      return;
   }
   
   if (count)
      m_name = ConstString((char*)buffer_sp->GetBytes());
   else
      m_name = ConstString();
   
   // @mulle-objc@ : get instance_and_header_size
   m_instance_size = (size_t) process_sp->ReadPointerFromMemory( isa + 8 * ptr_size, error);
   if (error.Fail())
   {
      // fprintf( stderr, "fail instance size\n");
      m_valid = false;
      return;
   }
   
   // @mulle-objc@ : subtract header size
   m_instance_size -= ptr_size * 2;
   
   // fprintf( stderr, "Add class \"%s\" for isa=0x%llx with m_isa=0x%llx, m_parent_isa=0x%llx\n", m_name.AsCString(), (long long) isa, (long long) m_isa, (long long) m_parent_isa);
   
   m_process_wp = lldb::ProcessWP(process_sp);
}


MulleObjCRuntime::ClassDescriptorSP
MulleObjCRuntimeV1::ClassDescriptorV1::GetSuperclass() {
  if (!m_valid)
    return MulleObjCRuntime::ClassDescriptorSP();
  ProcessSP process_sp = m_process_wp.lock();
  if (!process_sp)
    return MulleObjCRuntime::ClassDescriptorSP();
  return ObjCLanguageRuntime::ClassDescriptorSP(
      new MulleObjCRuntimeV1::ClassDescriptorV1(m_parent_isa, process_sp));
}

MulleObjCRuntime::ClassDescriptorSP
MulleObjCRuntimeV1::ClassDescriptorV1::GetMetaclass() const {
  return ClassDescriptorSP();
}

bool MulleObjCRuntimeV1::ClassDescriptorV1::Describe(
    std::function<void(ObjCLanguageRuntime::ObjCISA)> const &superclass_func,
    std::function<bool(const char *, const char *)> const &instance_method_func,
    std::function<bool(const char *, const char *)> const &class_method_func,
    std::function<bool(const char *, const char *, lldb::addr_t,
                       uint64_t)> const &ivar_func) const {
  return false;
}


//
// how often is basically the same code copied throught lldb ?
//

lldb::addr_t MulleObjCRuntimeV1::CallDangerousGetClassTableFunction( Process *process) {
   DiagnosticManager diagnostics;
   ValueList emptyList;
   lldb::addr_t args_addr = LLDB_INVALID_ADDRESS;
   FunctionCaller *impl_function_caller = nullptr;
   ExecutionContext exe_ctx;
   EvaluateExpressionOptions options;
   std::unique_ptr<UtilityFunction> dangerous_function;

   Log *log(lldb_private::GetLogIfAllCategoriesSet(LIBLLDB_LOG_LANGUAGE));

   options.SetUnwindOnError(true);
   options.SetIgnoreBreakpoints(true);
   options.SetStopOthers(true);  // placebo...
   
   ThreadSP thread_sp = m_process->GetThreadList().GetExpressionExecutionThread();
   if (!thread_sp)
   {
      if (log)
      {
         log->Printf( "Failed to acquire expression execution thread");
         diagnostics.Dump(log);
      }
      return( LLDB_INVALID_ADDRESS);
   }
   TargetSP target_sp( thread_sp->CalculateTarget());
   thread_sp->CalculateExecutionContext(exe_ctx);
   
   ClangASTContext *clang_ast_context = target_sp->GetScratchClangASTContext();
   
   Value return_value;
   CompilerType clang_void_ptr_type =  clang_ast_context->GetBasicType(eBasicTypeVoid).GetPointerType();
   return_value.SetValueType(Value::eValueTypeScalar);
   return_value.SetCompilerType( clang_void_ptr_type);

   
   Status error;
   dangerous_function.reset(exe_ctx.GetTargetRef().GetUtilityFunctionForLanguage(
                                                                                 g_dangerous_function_code,  eLanguageTypeObjC,
                                                                                 g_dangerous_function_name, error));
   if (error.Fail()) {
      if (log)
      {
         log->Printf(
                     "Failed to get Utility Function for class walks: %s.",
                     error.AsCString());
         diagnostics.Dump(log);
      }
      dangerous_function.reset();
      return( LLDB_INVALID_ADDRESS);
   }
   
   if (!dangerous_function->Install(diagnostics, exe_ctx)) {
      if (log) {
         log->Printf("Failed to install get_dangerous_class_storage function.");
         diagnostics.Dump(log);
      }
      dangerous_function.reset();
      return( LLDB_INVALID_ADDRESS);
   }
   
   // Next make the runner function for our implementation utility function.
   impl_function_caller = dangerous_function->MakeFunctionCaller(
                                                                 clang_void_ptr_type, emptyList, thread_sp, error);
   if (error.Fail()) {
      if (log)
      {
         log->Printf(
                     "Error getting function caller for dispatch lookup: \"%s\".",
                     error.AsCString());
         diagnostics.Dump(log);
      }
      return( LLDB_INVALID_ADDRESS);
   }

   diagnostics.Clear();

   // Now write down the argument values for this particular call.  This looks
   // like it might be a race condition
   // if other threads were calling into here, but actually it isn't because we
   // allocate a new args structure for
   // this call by passing args_addr = LLDB_INVALID_ADDRESS...
   
   if (!impl_function_caller->WriteFunctionArguments(
                                                     exe_ctx, args_addr, emptyList, diagnostics)) {
      if (log) {
         log->Printf("Error writing function arguments.");
         diagnostics.Dump(log);
      }
      return( LLDB_INVALID_ADDRESS);
   }
   
   
   impl_function_caller = dangerous_function->GetFunctionCaller();
   // Run the function
   ExpressionResults results =
   impl_function_caller->ExecuteFunction( exe_ctx,
                                          &args_addr,
                                          options,
                                          diagnostics,
                                          return_value);
   
   if (results != eExpressionCompleted) {
      if (log) {
         log->Printf("Error calling dangerous mulle functions.");
         diagnostics.Dump(log);
      }
      return 0;
   }
   
   return( return_value.GetScalar().ULongLong());
}


lldb::addr_t MulleObjCRuntimeV1::GetISAHashTablePointer( Process *process) {
   ModuleSP objc_module_sp(GetMulleObjCRuntimeModule());
      
   if (!objc_module_sp)
      return LLDB_INVALID_ADDRESS;
   
   // that pointer is fluctuating!
   return CallDangerousGetClassTableFunction( process);
}

//
// sadly need to read the mulle-concurrent-hashtable like this too
// OBVIOUSLY!! not optimal
//
void MulleObjCRuntimeV1::UpdateISAToDescriptorMapIfNeeded() {
   // TODO: implement HashTableSignature...
   Process *process = GetProcess();
   
   if (process) {
      // Update the process stop ID that indicates the last time we updated the
      // map, whether it was successful or not.
      m_isa_to_descriptor_stop_id = process->GetStopID();
      Log *log(GetLogIfAllCategoriesSet(LIBLLDB_LOG_LANGUAGE));
      
      ProcessSP process_sp = process->shared_from_this();
      
      // reread images for Objective-C library, I don't know why
      ModuleSP objc_module_sp(GetMulleObjCRuntimeModule());
      
      if (!objc_module_sp)
         return;
      
      lldb::addr_t hash_table_ptr = GetISAHashTablePointer( process);
      if (hash_table_ptr == LLDB_INVALID_ADDRESS) {
         m_isa_to_descriptor_stop_id = UINT32_MAX;
      }
      
      // Read the mulle_concurrent_hashtable struct:
      // __lldb_objc_get_dangerous_class_storage gives us
      //
      // struct _mulle_concurrent_hashmapstorage
      // {
      //    mulle_atomic_pointer_t   n_hashs;  // with possibly empty values
      //    uintptr_t                mask;     // easier to read from debugger if void * size
      //
      //    struct _mulle_concurrent_hashvaluepair  entries[ 1];
      // };
      // struct _mulle_concurrent_hashvaluepair
      // {
      //    intptr_t                 hash;
      //    mulle_atomic_pointer_t   value;
      // };
      
      Status error;
      DataBufferHeap buffer(1024, 0);
      
      // assume 64 bit max for now...
      // why use m_process here, process up there ? and process_sp ???
      
      const uint32_t addr_size   = m_process->GetAddressByteSize();
      const ByteOrder byte_order = m_process->GetByteOrder();
      lldb::addr_t  invalid;
      
      switch( addr_size)
      {
         case 4 : invalid = (lldb::addr_t) INT32_MIN; break;
         case 8 : invalid = (lldb::addr_t) INT64_MIN; break;
         default : return;
      }
      
      if (process->ReadMemory( hash_table_ptr, buffer.GetBytes(), addr_size * 2, error) !=
          addr_size * 2)
         return;
      
      DataExtractor data(buffer.GetBytes(), buffer.GetByteSize(), byte_order,
                         addr_size);
      
      // now read the storage structure first two fields
      lldb::offset_t  offset = addr_size;                // Skip n_hashs field
      uint64_t  size = data.GetPointer(&offset) + 1; // get mask add 1 for size
      uint64_t  data_size = size * (2 * addr_size);  // size + sizeof( entries)
      buffer.SetByteSize( data_size);
      
      // read in entries en block, skip over n_hashs and mask
      if( process->ReadMemory( hash_table_ptr + 2 * addr_size , buffer.GetBytes(), data_size,
                              error) != data_size)
         return;
      
      data.SetData( buffer.GetBytes(), buffer.GetByteSize(), byte_order);
      
      offset = 0;
      for (uint32_t bucket_idx = 0; bucket_idx < size; ++bucket_idx)
      {
         const lldb::addr_t classid = data.GetPointer(&offset);
         const lldb::addr_t isa     = data.GetPointer(&offset);
         
         if( classid == 0 || classid == invalid || isa == 0)
            continue;
         
         if (!ISAIsCached(isa)) {
            ClassDescriptorSP descriptor_sp(
                                            new ClassDescriptorV1(isa, process_sp));
            
            if (log && log->GetVerbose())
               log->Printf("MulleObjCRuntimeV1 added (ObjCISA)0x%" PRIx64
                           " from mulle-objc-runtime to "
                           "isa->descriptor cache",
                           isa);
            
            AddClass(isa, descriptor_sp);
         }
      }
   }
}

DeclVendor *MulleObjCRuntimeV1::GetDeclVendor() {
  return nullptr;
}
