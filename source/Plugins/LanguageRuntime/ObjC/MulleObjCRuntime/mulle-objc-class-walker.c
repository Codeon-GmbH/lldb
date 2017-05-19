void   *__lldb_objc_walk_classes( void (*callback)( void *cls, void *userinfo),
                                  void *userinfo)
{
   mulle_objc_lldb_walk_classes( callback, userinfo);
}


//DUMME IDEE


lldb::addr_t
MulleObjCRuntimeV1::SetupClassWalkerFunction(Thread &thread,
                                             ValueList &dispatch_values) {
   ThreadSP thread_sp(thread.shared_from_this());
   ExecutionContext exe_ctx(thread_sp);
   DiagnosticManager diagnostics;
   Log *log(lldb_private::GetLogIfAllCategoriesSet(LIBLLDB_LOG_STEP));

   lldb::addr_t args_addr = LLDB_INVALID_ADDRESS;
   FunctionCaller *impl_function_caller = nullptr;

   // Scope for mutex locker:
   {
      std::lock_guard<std::mutex> guard(m_impl_function_mutex);

      // First stage is to make the ClangUtility to hold our injected function:

      if (!m_impl_code.get()) {
            Status error;
            m_impl_code.reset(exe_ctx.GetTargetRef().GetUtilityFunctionForLanguage(
                                                                               g_class_walker_function_code, eLanguageTypeObjC,
                                                                               g_class_walker_function_name, error));
            if (error.Fail()) {
               if (log)
                  log->Printf(
                              "Failed to get Utility Function for class walks: %s.",
                              error.AsCString());
               m_impl_code.reset();
               return args_addr;
            }

            if (!m_impl_code->Install(diagnostics, exe_ctx)) {
               if (log) {
                  log->Printf("Failed to install class walker function.");
                  diagnostics.Dump(log);
               }
               m_impl_code.reset();
               return args_addr;
            }

         // Next make the runner function for our implementation utility function.
         ClangASTContext *clang_ast_context =
         thread.GetProcess()->GetTarget().GetScratchClangASTContext();
         CompilerType clang_void_type =
         clang_ast_context->GetBasicType(eBasicTypeVoid);

         impl_function_caller = m_impl_code->MakeFunctionCaller(
                                                                clang_void_type, dispatch_values, thread_sp, error);
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

   // Now write down the argument values for this particular call.  This looks
   // like it might be a race condition
   // if other threads were calling into here, but actually it isn't because we
   // allocate a new args structure for
   // this call by passing args_addr = LLDB_INVALID_ADDRESS...

   if (!impl_function_caller->WriteFunctionArguments(
                                                     exe_ctx, args_addr, dispatch_values, diagnostics)) {
      if (log) {
         log->Printf("Error writing function arguments.");
         diagnostics.Dump(log);
      }
   }

   return args_addr;
}


struct walker_callback
{
   MulleObjCRuntimeV1  *runtime;
   ProcessSP           process_sp;
   Log                 *log;
};


void MulleObjCRuntimeV1::C_ClassWalkerCallback( void *cls, void *userinfo)
{
   struct walker_callback   *info = (struct walker_callback *) userinfo;

   info->runtime->ClassWalkerCallback( (lldb::addr_t) (uintptr_t) cls, info->process_sp, info->log);
}


void MulleObjCRuntimeV1::ClassWalkerCallback( lldb::addr_t isa, lldb::ProcessSP process_sp, Log *log)
{
   ClassDescriptorSP descriptor_sp(
                                   new ClassDescriptorV1( isa, process_sp));

   if (log && log->GetVerbose())
      log->Printf("AppleObjCRuntimeV1 added (ObjCISA)0x%" PRIx64
                  " from _objc_debug_class_hash to "
                  "isa->descriptor cache",
                  isa);

   AddClass( isa, descriptor_sp);
}



bool MulleObjCRuntimeV1::CallClassWalker( Thread &thread) {
   DiagnosticManager diagnostics;

   ValueList argument_values;
   Value  callbackFunctionPointer;
   Value  userInfoPointer;

   return_buffer_ptr_value.GetScalar() = m_get_pending_items_return_buffer_addr;
   argument_values.PushValue(return_buffer_ptr_value);

   debug_value.GetScalar() = 0;
   argument_values.PushValue(debug_value);

   queue_value.GetScalar() = queue;
   argument_values.PushValue(queue_value);

   if (page_to_free != LLDB_INVALID_ADDRESS)
      page_to_free_value.GetScalar() = page_to_free;
   else
      page_to_free_value.GetScalar() = 0;
   argument_values.PushValue(page_to_free_value);

   page_to_free_size_value.GetScalar() = page_to_free_size;
   argument_values.PushValue(page_to_free_size_value);

   addr_t args_addr = SetupGetPendingItemsFunction(thread, argument_values);


   if (!m_impl_function) {
      lldb::addr_t args_addr =
      SetupClassWalkerFunction( thread, argument_values);

      if (args_addr == LLDB_INVALID_ADDRESS) {
         return false;
      }
      m_impl_function =  m_impl_code->GetFunctionCaller();
   }
   ExecutionContext exe_ctx;
   EvaluateExpressionOptions options;
   options.SetUnwindOnError(true);
   options.SetIgnoreBreakpoints(true);
   options.SetStopOthers(true);  // guess so...

   Value return_value;
   return_value.SetValueType(Value::eValueTypeScalar);

   // Run the function
   ExpressionResults results =
         m_impl_function->ExecuteFunction( exe_ctx,
                                           dispatch_values,
                                           options,
                                           diagnostics,
                                           return_value);

   if (results == eExpressionCompleted) {
      return true;
   }
   return false;
}

