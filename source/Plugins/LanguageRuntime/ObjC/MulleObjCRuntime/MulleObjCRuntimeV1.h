//===-- MulleObjCRuntimeV1.h ------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_MulleObjCRuntimeV1_h_
#define liblldb_MulleObjCRuntimeV1_h_

// C Includes
// C++ Includes
// Other libraries and framework includes
// Project includes
#include "MulleObjCRuntime.h"
#include "lldb/lldb-private.h"

#include "Plugins/LanguageRuntime/ObjC/ObjCLanguageRuntime.h"

namespace lldb_private {

//
// The non-trampoline code uses LIBLLDB_LOG_LANGUAGE logging, which
// kinda fits by meaning and it is a relatively quiet channel.
//
// Enable verbose logging in lldb with `log enable -v lldb language`
//
class MulleObjCRuntimeV1 : public MulleObjCRuntime {
public:
  ~MulleObjCRuntimeV1() override = default;

  //------------------------------------------------------------------
  // Static Functions
  //------------------------------------------------------------------
  static void Initialize();

  static void Terminate();

  static lldb_private::LanguageRuntime *
  CreateInstance(Process *process, lldb::LanguageType language);

  static lldb_private::ConstString GetPluginNameStatic();

  static bool classof(const ObjCLanguageRuntime *runtime) {
    switch (runtime->GetRuntimeVersion()) {
    case ObjCRuntimeVersions::eMulleObjC_V1:
      return true;
    default:
      return false;
    }
  }

  class ClassDescriptorV1 : public ObjCLanguageRuntime::ClassDescriptor {
  public:
    ClassDescriptorV1(ValueObject &isa_pointer);
    ClassDescriptorV1(ObjCISA isa, lldb::ProcessSP process_sp);

    ~ClassDescriptorV1() override = default;

    ConstString GetClassName() override { return m_name; }

    ClassDescriptorSP GetSuperclass() override;

    ClassDescriptorSP GetMetaclass() const override;

    bool IsValid() override { return m_valid; }

    //
    // TODO: should get on with this...
    //
    bool GetTaggedPointerInfo(uint64_t *info_bits = nullptr,
                              uint64_t *value_bits = nullptr,
                              uint64_t *payload = nullptr) override {
      return false;
    }

    uint64_t GetInstanceSize() override { return m_instance_size; }

    ObjCISA GetISA() override { return m_isa; }

    bool
    Describe(std::function<void(ObjCLanguageRuntime::ObjCISA)> const
                 &superclass_func,
             std::function<bool(const char *, const char *)> const
                 &instance_method_func,
             std::function<bool(const char *, const char *)> const
                 &class_method_func,
             std::function<bool(const char *, const char *, lldb::addr_t,
                                uint64_t)> const &ivar_func) const override;

  protected:
    void Initialize(ObjCISA isa, lldb::ProcessSP process_sp);

  private:
    ConstString m_name;
    ObjCISA m_isa;
    ObjCISA m_parent_isa;
    bool m_valid;
    lldb::ProcessWP m_process_wp;
    uint64_t m_instance_size;
  };

  // These are generic runtime functions:
  bool GetDynamicTypeAndAddress(ValueObject &in_value,
                                lldb::DynamicValueType use_dynamic,
                                TypeAndOrName &class_type_or_name,
                                Address &address,
                                Value::ValueType &value_type) override;

  UtilityFunction *CreateObjectChecker(const char *) override;

  //------------------------------------------------------------------
  // PluginInterface protocol
  //------------------------------------------------------------------
  ConstString GetPluginName() override;

  uint32_t GetPluginVersion() override;

  ObjCRuntimeVersions GetRuntimeVersion() const override {
    return ObjCRuntimeVersions::eMulleObjC_V1;
  }

  void UpdateISAToDescriptorMapIfNeeded() override;

  DeclVendor *GetDeclVendor() override;

protected:
  lldb::BreakpointResolverSP CreateExceptionResolver(Breakpoint *bkpt,
                                                     bool catch_bp,
                                                     bool throw_bp) override;

  class HashTableSignature {
  public:
    HashTableSignature()
        : m_count(0), m_num_buckets(0), m_buckets_ptr(LLDB_INVALID_ADDRESS) {}

    bool NeedsUpdate(uint32_t count, uint32_t num_buckets,
                     lldb::addr_t buckets_ptr) {
      return m_count != count || m_num_buckets != num_buckets ||
             m_buckets_ptr != buckets_ptr;
    }

    void UpdateSignature(uint32_t count, uint32_t num_buckets,
                         lldb::addr_t buckets_ptr) {
      m_count = count;
      m_num_buckets = num_buckets;
      m_buckets_ptr = buckets_ptr;
    }

  protected:
    uint32_t m_count;
    uint32_t m_num_buckets;
    lldb::addr_t m_buckets_ptr;
  };

  lldb::addr_t CallDangerousGetClassTableFunction( Process *process);
  lldb::addr_t GetISAHashTablePointer( Process *process);

  HashTableSignature m_hash_signature;
  lldb::addr_t m_isa_hash_table_ptr;
  std::unique_ptr<DeclVendor> m_decl_vendor_ap;
  
private:
  MulleObjCRuntimeV1(Process *process);
};

} // namespace lldb_private

#endif // liblldb_MulleObjCRuntimeV1_h_
