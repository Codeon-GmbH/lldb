//===-- MulleObjCTrampolineHandler.h ----------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef lldb_MulleObjCTrampolineHandler_h_
#define lldb_MulleObjCTrampolineHandler_h_

// C Includes
// C++ Includes
#include <map>
#include <mutex>
#include <vector>

// Other libraries and framework includes
// Project includes
#include "lldb/Expression/UtilityFunction.h"
#include "lldb/lldb-public.h"

namespace lldb_private {

class MulleObjCTrampolineHandler {
public:
  MulleObjCTrampolineHandler(const lldb::ProcessSP &process_sp,
                             const lldb::ModuleSP &objc_module_sp);

  ~MulleObjCTrampolineHandler();

  lldb::ThreadPlanSP GetStepThroughDispatchPlan( Thread &thread,
                                                 bool stop_others);
  lldb::ThreadPlanSP GetStepOutDispatchPlan(Thread &thread,
                                             bool stop_others);


  FunctionCaller *GetLookupImplementationFunctionCaller();

  bool AddrIsMsgForward(lldb::addr_t addr) const {
    return (addr == m_msg_forward_addr);
  }

  struct DispatchFunction {
  public:
    const char *name;
    bool has_class_argument;
    bool has_superid_argument;
  };

  lldb::addr_t SetupDispatchFunction(Thread &thread,
                                     ValueList &dispatch_values);

protected:
   lldb::addr_t    ReadIndirectJMPQ_X86_64( lldb::addr_t curr_pc);
   bool            GetDispatchFunctionForPCViaMap( lldb::addr_t curr_pc, DispatchFunction &this_dispatch);
   void            SetBreakpointForReturn( Thread &thread, const StackID &m_stack_id);

private:
  lldb::addr_t  LookupFunctionSymbol( const lldb::ProcessSP &process_sp,
                                      const char *name);

  static const DispatchFunction g_dispatch_functions[];

  typedef std::map<lldb::addr_t, int> MsgsendMap; // This table maps an dispatch
                                                  // fn address to the index in
                                                  // g_dispatch_functions
  MsgsendMap m_msgSend_map;

  lldb::ProcessWP m_process_wp;
  lldb::ModuleSP m_objc_module_sp;
  const char *m_lookup_implementation_function_code;
  std::unique_ptr<UtilityFunction> m_impl_code;
  std::mutex m_impl_function_mutex;
  lldb::addr_t m_classlookup_addr[ 4];
  lldb::addr_t m_impl_fn_addr;
  lldb::addr_t m_msg_forward_addr; // this is the function to "get" the forward method from the class

public:
   bool  CanStepThrough()
   {
      return( m_impl_fn_addr != LLDB_INVALID_ADDRESS);
   }
   bool  CanStepOver()
   {
      return( m_classlookup_addr[ 0] != LLDB_INVALID_ADDRESS);
   }
};

} // namespace lldb_private

#endif // lldb_MulleObjCTrampolineHandler_h_
