//===-- MulleThreadPlanStepThroughObjCTrampoline.cpp
//--------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

// C Includes
// C++ Includes
// Other libraries and framework includes
// Project includes
#include "MulleThreadPlanStepThroughObjCTrampoline.h"
#include "MulleObjCTrampolineHandler.h"
#include "lldb/Expression/DiagnosticManager.h"
#include "lldb/Expression/FunctionCaller.h"
#include "lldb/Expression/UtilityFunction.h"
#include "lldb/Target/ExecutionContext.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/Thread.h"
#include "lldb/Target/ThreadPlanRunToAddress.h"
#include "lldb/Target/ThreadPlanStepOut.h"
#include "lldb/Utility/Log.h"

#include "Plugins/LanguageRuntime/ObjC/ObjCLanguageRuntime.h"

using namespace lldb;
using namespace lldb_private;

#define MULLE_LOG   LIBLLDB_LOG_LANGUAGE
//#define MULLE_LOG   LIBLLDB_LOG_STEP
//----------------------------------------------------------------------
// ThreadPlanStepThroughObjCTrampoline constructor
//----------------------------------------------------------------------
MulleThreadPlanStepThroughObjCTrampoline::
    MulleThreadPlanStepThroughObjCTrampoline(
        Thread &thread, MulleObjCTrampolineHandler *trampoline_handler,
        ValueList &input_values, lldb::addr_t isa_addr, lldb::addr_t sel_addr,
        bool stop_others)
    : ThreadPlan(ThreadPlan::eKindGeneric,
                 "Step through MulleObjC trampoline", thread, eVoteNoOpinion,
                 eVoteNoOpinion),
      m_trampoline_handler(trampoline_handler),
      m_args_addr(LLDB_INVALID_ADDRESS), m_input_values(input_values),
      m_isa_addr(isa_addr), m_sel_addr(sel_addr), m_impl_function(NULL),
      m_stop_others(stop_others) {}

//----------------------------------------------------------------------
// Destructor
//----------------------------------------------------------------------
MulleThreadPlanStepThroughObjCTrampoline::
    ~MulleThreadPlanStepThroughObjCTrampoline() {}

void MulleThreadPlanStepThroughObjCTrampoline::DidPush() {
  // Setting up the memory space for the called function text might require
  // allocations, i.e. a nested function call.  This needs to be done as a
  // PreResumeAction.
  m_thread.GetProcess()->AddPreResumeAction(PreResumeInitializeFunctionCaller,
                                            (void *)this);
}

bool MulleThreadPlanStepThroughObjCTrampoline::InitializeFunctionCaller() {
   Log *log(lldb_private::GetLogIfAllCategoriesSet(MULLE_LOG));
  if (!m_func_sp) {
    DiagnosticManager diagnostics;

     m_args_addr =
        m_trampoline_handler->SetupDispatchFunction(m_thread, m_input_values);

    if (m_args_addr == LLDB_INVALID_ADDRESS) {
       if (log)
          log->Printf("Mulle: SetupDispatchFunction failed.");
      return false;
    }
    m_impl_function =
        m_trampoline_handler->GetLookupImplementationFunctionCaller();
    ExecutionContext exc_ctx;
    EvaluateExpressionOptions options;
    options.SetUnwindOnError(true);
    options.SetIgnoreBreakpoints(true);
    options.SetStopOthers(m_stop_others);
    m_thread.CalculateExecutionContext(exc_ctx);
    m_func_sp = m_impl_function->GetThreadPlanToCallFunction(
        exc_ctx, m_args_addr, options, diagnostics);
    m_func_sp->SetOkayToDiscard(true);

    if (log)
       log->Printf("Mulle: thread plan queued");

    m_thread.QueueThreadPlan(m_func_sp, false);
  }
  else
    if (log)
       log->Printf("Mulle: m_func_sp not set");
  return true;
}

bool MulleThreadPlanStepThroughObjCTrampoline::
    PreResumeInitializeFunctionCaller(void *void_myself) {
  MulleThreadPlanStepThroughObjCTrampoline *myself =
      static_cast<MulleThreadPlanStepThroughObjCTrampoline *>(void_myself);
  return myself->InitializeFunctionCaller();
}

void MulleThreadPlanStepThroughObjCTrampoline::GetDescription(
    Stream *s, lldb::DescriptionLevel level) {
  if (level == lldb::eDescriptionLevelBrief)
    s->Printf("Mulle: Step through ObjC trampoline");
  else {
    s->Printf("Mulle: Stepping to implementation of ObjC method - obj: 0x%llx, isa: "
              "0x%" PRIx64 ", sel: 0x%" PRIx64,
              m_input_values.GetValueAtIndex(0)->GetScalar().ULongLong(),
              m_isa_addr, m_sel_addr);
  }
}

bool MulleThreadPlanStepThroughObjCTrampoline::ValidatePlan(Stream *error) {
  return true;
}

bool MulleThreadPlanStepThroughObjCTrampoline::DoPlanExplainsStop(
    Event *event_ptr) {
  // If we get asked to explain the stop it will be because something went
  // wrong (like the implementation for selector function crashed...  We're
  // going
  // to figure out what to do about that, so we do explain the stop.
  return true;
}

lldb::StateType MulleThreadPlanStepThroughObjCTrampoline::GetPlanRunState() {
  return eStateRunning;
}

bool MulleThreadPlanStepThroughObjCTrampoline::ShouldStop(Event *event_ptr) {
  // First stage: we are still handling the "call a function to get the target
  // of the dispatch"
  Log *log(lldb_private::GetLogIfAllCategoriesSet(MULLE_LOG));

   if (log)
      log->Printf("Mulle: should stop is called (asked)");

  if (m_func_sp) {
    if (!m_func_sp->IsPlanComplete()) {
       if (log)
          log->Printf("Mulle: plan is complete");
      return false;
    } else {
      if (!m_func_sp->PlanSucceeded()) {
        SetPlanComplete(false);
        if (log)
           log->Printf("Mulle: plan failed (done)");
        return true;
      }
      m_func_sp.reset();
    }
  }

  // Second stage, if all went well with the function calling, then fetch the
  // target address, and queue up a "run to that address" plan.
  if (!m_run_to_sp) {
    Value target_addr_value;
    ExecutionContext exc_ctx;
    m_thread.CalculateExecutionContext(exc_ctx);
    m_impl_function->FetchFunctionResults(exc_ctx, m_args_addr,
                                          target_addr_value);
    m_impl_function->DeallocateFunctionResults(exc_ctx, m_args_addr);
    lldb::addr_t target_addr = target_addr_value.GetScalar().ULongLong();
    Address target_so_addr;
    target_so_addr.SetOpcodeLoadAddress(target_addr, exc_ctx.GetTargetPtr());
    if (target_addr == 0) {
      if (log)
        log->Printf("Mulle: Got target implementation of 0x0, stopping.");
      SetPlanComplete( false);
      return true;
    }
    if (m_trampoline_handler->AddrIsMsgForward(target_addr)) {
      if (log)
        log->Printf(
            "Mulle: Implementation lookup returned msgForward function: 0x%" PRIx64
            ", stopping.",
            target_addr);

      SymbolContext sc = m_thread.GetStackFrameAtIndex(0)->GetSymbolContext(
          eSymbolContextEverything);
      Status status;
      const bool abort_other_plans = false;
      const bool first_insn = true;
      const uint32_t frame_idx = 0;
      m_run_to_sp = m_thread.QueueThreadPlanForStepOutNoShouldStop(
          abort_other_plans, &sc, first_insn, m_stop_others, eVoteNoOpinion,
          eVoteNoOpinion, frame_idx, status);
      if (m_run_to_sp && status.Success())
        m_run_to_sp->SetPrivate(true);
      return false;
    }

    if (log)
      log->Printf("Mulle: Running to ObjC method implementation: 0x%" PRIx64,
                  target_addr);

    // can't cache if isa is unknown (TPS)
    if( m_isa_addr != LLDB_INVALID_ADDRESS)
    {
      ObjCLanguageRuntime *objc_runtime =
         ObjCLanguageRuntime::Get(*GetThread().GetProcess());
      assert(objc_runtime != NULL);
      objc_runtime->AddToMethodCache(m_isa_addr, m_sel_addr, target_addr);
      if (log)
         log->Printf("Mulle: Added {isa-addr=0x%" PRIx64 ", sel-addr=0x%" PRIx64
                     "} = addr=0x%" PRIx64 " to cache.",
                     m_isa_addr, m_sel_addr, target_addr);
    }
    // Extract the target address from the value:

    m_run_to_sp = std::make_shared<ThreadPlanRunToAddress>(
        m_thread, target_so_addr, m_stop_others);
    m_thread.QueueThreadPlan(m_run_to_sp, false);
    m_run_to_sp->SetPrivate(true);
    return false;
  } else if (m_thread.IsThreadPlanDone(m_run_to_sp.get())) {
    // Third stage, work the run to target plan.
     if (log)
        log->Printf("Mulle: thread plan is done");
    SetPlanComplete( true);
    return true;
  }

   if (log)
      log->Printf("Mulle: should stop says no");
  return false;
}

// The base class MischiefManaged does some cleanup - so you have to call it
// in your MischiefManaged derived class.
bool MulleThreadPlanStepThroughObjCTrampoline::MischiefManaged() {
  if (IsPlanComplete())
    return true;
  else
    return false;
}

bool MulleThreadPlanStepThroughObjCTrampoline::WillStop() { return true; }
