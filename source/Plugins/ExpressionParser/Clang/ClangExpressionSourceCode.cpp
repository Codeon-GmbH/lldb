//===-- ClangExpressionSourceCode.cpp ---------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "ClangExpressionSourceCode.h"

#include "clang/Basic/CharInfo.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/StringRef.h"

#include "Plugins/ExpressionParser/Clang/ClangModulesDeclVendor.h"
#include "Plugins/ExpressionParser/Clang/ClangPersistentVariables.h"
#include "lldb/Symbol/Block.h"
#include "lldb/Symbol/CompileUnit.h"
#include "lldb/Symbol/DebugMacros.h"
#include "lldb/Symbol/TypeSystem.h"
#include "lldb/Symbol/VariableList.h"
#include "lldb/Target/ExecutionContext.h"
#include "lldb/Target/Language.h"
#include "lldb/Target/Platform.h"
#include "lldb/Target/StackFrame.h"
#include "lldb/Target/Target.h"
#include "lldb/Utility/StreamString.h"

using namespace lldb_private;

#define PREFIX_NAME "<lldb wrapper prefix>"

const llvm::StringRef ClangExpressionSourceCode::g_prefix_file_name = PREFIX_NAME;

const char *ClangExpressionSourceCode::g_expression_prefix =
"#line 1 \"" PREFIX_NAME R"("
#ifndef offsetof
#define offsetof(t, d) __builtin_offsetof(t, d)
#endif
#ifndef NULL
#define NULL (__null)
#endif
#ifndef Nil
#define Nil (__null)
#endif
#ifndef nil
#define nil (__null)
#endif
#ifndef YES
#define YES ((BOOL)1)
#endif
#ifndef NO
#define NO ((BOOL)0)
#endif
typedef __INT8_TYPE__ int8_t;
typedef __UINT8_TYPE__ uint8_t;
typedef __INT16_TYPE__ int16_t;
typedef __UINT16_TYPE__ uint16_t;
typedef __INT32_TYPE__ int32_t;
typedef __UINT32_TYPE__ uint32_t;
typedef __INT64_TYPE__ int64_t;
typedef __UINT64_TYPE__ uint64_t;
typedef __INTPTR_TYPE__ intptr_t;
typedef __UINTPTR_TYPE__ uintptr_t;
typedef __SIZE_TYPE__ size_t;
typedef __PTRDIFF_TYPE__ ptrdiff_t;
typedef unsigned short unichar;
extern "C"
{
    int printf(const char * __restrict, ...);
}
)";

namespace {

class AddMacroState {
  enum State {
    CURRENT_FILE_NOT_YET_PUSHED,
    CURRENT_FILE_PUSHED,
    CURRENT_FILE_POPPED
  };

public:
  AddMacroState(const FileSpec &current_file, const uint32_t current_file_line)
      : m_state(CURRENT_FILE_NOT_YET_PUSHED), m_current_file(current_file),
        m_current_file_line(current_file_line) {}

  void StartFile(const FileSpec &file) {
    m_file_stack.push_back(file);
    if (file == m_current_file)
      m_state = CURRENT_FILE_PUSHED;
  }

  void EndFile() {
    if (m_file_stack.size() == 0)
      return;

    FileSpec old_top = m_file_stack.back();
    m_file_stack.pop_back();
    if (old_top == m_current_file)
      m_state = CURRENT_FILE_POPPED;
  }

  // An entry is valid if it occurs before the current line in the current
  // file.
  bool IsValidEntry(uint32_t line) {
    switch (m_state) {
    case CURRENT_FILE_NOT_YET_PUSHED:
      return true;
    case CURRENT_FILE_PUSHED:
      // If we are in file included in the current file, the entry should be
      // added.
      if (m_file_stack.back() != m_current_file)
        return true;

      return line < m_current_file_line;
    default:
      return false;
    }
  }

private:
  std::vector<FileSpec> m_file_stack;
  State m_state;
  FileSpec m_current_file;
  uint32_t m_current_file_line;
};

} // anonymous namespace

static void AddMacros(const DebugMacros *dm, CompileUnit *comp_unit,
                      AddMacroState &state, StreamString &stream) {
  if (dm == nullptr)
    return;

  for (size_t i = 0; i < dm->GetNumMacroEntries(); i++) {
    const DebugMacroEntry &entry = dm->GetMacroEntryAtIndex(i);
    uint32_t line;

    switch (entry.GetType()) {
    case DebugMacroEntry::DEFINE:
      if (state.IsValidEntry(entry.GetLineNumber()))
        stream.Printf("#define %s\n", entry.GetMacroString().AsCString());
      else
        return;
      break;
    case DebugMacroEntry::UNDEF:
      if (state.IsValidEntry(entry.GetLineNumber()))
        stream.Printf("#undef %s\n", entry.GetMacroString().AsCString());
      else
        return;
      break;
    case DebugMacroEntry::START_FILE:
      line = entry.GetLineNumber();
      if (state.IsValidEntry(line))
        state.StartFile(entry.GetFileSpec(comp_unit));
      else
        return;
      break;
    case DebugMacroEntry::END_FILE:
      state.EndFile();
      break;
    case DebugMacroEntry::INDIRECT:
      AddMacros(entry.GetIndirectDebugMacros(), comp_unit, state, stream);
      break;
    default:
      // This is an unknown/invalid entry. Ignore.
      break;
    }
  }
}

lldb_private::ClangExpressionSourceCode::ClangExpressionSourceCode(
    llvm::StringRef filename, llvm::StringRef name, llvm::StringRef prefix,
    llvm::StringRef body, Wrapping wrap)
    : ExpressionSourceCode(name, prefix, body, wrap) {
  // Use #line markers to pretend that we have a single-line source file
  // containing only the user expression. This will hide our wrapper code
  // from the user when we render diagnostics with Clang.
  m_start_marker = "#line 1 \"" + filename.str() + "\"\n";
  m_end_marker = "\n;\n#line 1 \"<lldb wrapper suffix>\"\n";
}

namespace {
/// Allows checking if a token is contained in a given expression.
class TokenVerifier {
  /// The tokens we found in the expression.
  llvm::StringSet<> m_tokens;

public:
  TokenVerifier(std::string body);
  /// Returns true iff the given expression body contained a token with the
  /// given content.
  bool hasToken(llvm::StringRef token) const {
    return m_tokens.find(token) != m_tokens.end();
  }
};
} // namespace

TokenVerifier::TokenVerifier(std::string body) {
  using namespace clang;

  // We only care about tokens and not their original source locations. If we
  // move the whole expression to only be in one line we can simplify the
  // following code that extracts the token contents.
  std::replace(body.begin(), body.end(), '\n', ' ');
  std::replace(body.begin(), body.end(), '\r', ' ');

  FileSystemOptions file_opts;
  FileManager file_mgr(file_opts,
                       FileSystem::Instance().GetVirtualFileSystem());

  // Let's build the actual source code Clang needs and setup some utility
  // objects.
  llvm::IntrusiveRefCntPtr<DiagnosticIDs> diag_ids(new DiagnosticIDs());
  llvm::IntrusiveRefCntPtr<DiagnosticOptions> diags_opts(
      new DiagnosticOptions());
  DiagnosticsEngine diags(diag_ids, diags_opts);
  clang::SourceManager SM(diags, file_mgr);
  auto buf = llvm::MemoryBuffer::getMemBuffer(body);

  FileID FID = SM.createFileID(clang::SourceManager::Unowned, buf.get());

  // Let's just enable the latest ObjC and C++ which should get most tokens
  // right.
  LangOptions Opts;
  Opts.ObjC = true;
  Opts.DollarIdents = true;
  Opts.CPlusPlus17 = true;
  Opts.LineComment = true;

  Lexer lex(FID, buf.get(), SM, Opts);

  Token token;
  bool exit = false;
  while (!exit) {
    // Returns true if this is the last token we get from the lexer.
    exit = lex.LexFromRawLexer(token);

    // Extract the column number which we need to extract the token content.
    // Our expression is just one line, so we don't need to handle any line
    // numbers here.
    bool invalid = false;
    unsigned start = SM.getSpellingColumnNumber(token.getLocation(), &invalid);
    if (invalid)
      continue;
    // Column numbers start at 1, but indexes in our string start at 0.
    --start;

    // Annotations don't have a length, so let's skip them.
    if (token.isAnnotation())
      continue;

    // Extract the token string from our source code and store it.
    std::string token_str = body.substr(start, token.getLength());
    if (token_str.empty())
      continue;
    m_tokens.insert(token_str);
  }
}

static void AddLocalVariableDecls(const lldb::VariableListSP &var_list_sp,
                                  StreamString &stream,
                                  const std::string &expr,
                                  lldb::LanguageType wrapping_language) {
  TokenVerifier tokens(expr);

  for (size_t i = 0; i < var_list_sp->GetSize(); i++) {
    lldb::VariableSP var_sp = var_list_sp->GetVariableAtIndex(i);

    ConstString var_name = var_sp->GetName();


    // We can check for .block_descriptor w/o checking for langauge since this
    // is not a valid identifier in either C or C++.
    if (!var_name || var_name == ".block_descriptor")
      continue;

    if (!expr.empty() && !tokens.hasToken(var_name.GetStringRef()))
      continue;

    if ((var_name == "self" || var_name == "_cmd") &&
        (wrapping_language == lldb::eLanguageTypeObjC ||
         wrapping_language == lldb::eLanguageTypeObjC_plus_plus))
      continue;

    if (var_name == "this" &&
        wrapping_language == lldb::eLanguageTypeC_plus_plus)
      continue;

    stream.Printf("using $__lldb_local_vars::%s;\n", var_name.AsCString());
  }
}

bool ClangExpressionSourceCode::GetText(
    std::string &text, lldb::LanguageType wrapping_language, bool static_method,
    ExecutionContext &exe_ctx, bool add_locals, bool force_add_all_locals,
    llvm::ArrayRef<std::string> modules) const {
  const char *target_specific_defines = "typedef signed char BOOL;\n";
  std::string module_macros;

  Target *target = exe_ctx.GetTargetPtr();
  if (target) {
    if (target->GetArchitecture().GetMachine() == llvm::Triple::aarch64 ||
        target->GetArchitecture().GetMachine() == llvm::Triple::aarch64_32) {
      target_specific_defines = "typedef bool BOOL;\n";
    }
    if (target->GetArchitecture().GetMachine() == llvm::Triple::x86_64) {
      if (lldb::PlatformSP platform_sp = target->GetPlatform()) {
        static ConstString g_platform_ios_simulator("ios-simulator");
        if (platform_sp->GetPluginName() == g_platform_ios_simulator) {
          target_specific_defines = "typedef bool BOOL;\n";
        }
      }
    }

    ClangModulesDeclVendor *decl_vendor = target->GetClangModulesDeclVendor();
    auto *persistent_vars = llvm::cast<ClangPersistentVariables>(
        target->GetPersistentExpressionStateForLanguage(lldb::eLanguageTypeC));
    if (decl_vendor && persistent_vars) {
      const ClangModulesDeclVendor::ModuleVector &hand_imported_modules =
          persistent_vars->GetHandLoadedClangModules();
      ClangModulesDeclVendor::ModuleVector modules_for_macros;

      for (ClangModulesDeclVendor::ModuleID module : hand_imported_modules) {
        modules_for_macros.push_back(module);
      }

      if (target->GetEnableAutoImportClangModules()) {
        if (StackFrame *frame = exe_ctx.GetFramePtr()) {
          if (Block *block = frame->GetFrameBlock()) {
            SymbolContext sc;

            block->CalculateSymbolContext(&sc);

            if (sc.comp_unit) {
              StreamString error_stream;

              decl_vendor->AddModulesForCompileUnit(
                  *sc.comp_unit, modules_for_macros, error_stream);
            }
          }
        }
      }

      decl_vendor->ForEachMacro(
          modules_for_macros,
          [&module_macros](const std::string &expansion) -> bool {
            module_macros.append(expansion);
            module_macros.append("\n");
            return false;
          });
    }
  }

  StreamString debug_macros_stream;
  StreamString lldb_local_var_decls;
  if (StackFrame *frame = exe_ctx.GetFramePtr()) {
    const SymbolContext &sc = frame->GetSymbolContext(
        lldb::eSymbolContextCompUnit | lldb::eSymbolContextLineEntry);

    if (sc.comp_unit && sc.line_entry.IsValid()) {
      DebugMacros *dm = sc.comp_unit->GetDebugMacros();
      if (dm) {
        AddMacroState state(sc.line_entry.file, sc.line_entry.line);
        AddMacros(dm, sc.comp_unit, state, debug_macros_stream);
      }
    }

    if (add_locals)
      if (target->GetInjectLocalVariables(&exe_ctx)) {
        lldb::VariableListSP var_list_sp =
            frame->GetInScopeVariableList(false, true);
        AddLocalVariableDecls(var_list_sp, lldb_local_var_decls,
                              force_add_all_locals ? "" : m_body,
                              wrapping_language);
      }
  }

  if (m_wrap) {
    switch (wrapping_language) {
    default:
      return false;
    case lldb::eLanguageTypeC:
    case lldb::eLanguageTypeC_plus_plus:
    case lldb::eLanguageTypeObjC:
      break;
    }

    // Generate a list of @import statements that will import the specified
    // module into our expression.
    std::string module_imports;
    for (const std::string &module : modules) {
      module_imports.append("@import ");
      module_imports.append(module);
      module_imports.append(";\n");
    }

    StreamString wrap_stream;

    wrap_stream.Printf("%s\n%s\n%s\n%s\n%s\n", module_macros.c_str(),
                       debug_macros_stream.GetData(), g_expression_prefix,
                       target_specific_defines, m_prefix.c_str());

    /// @mulle-objc@ hack some mulle-objc-runtime stuff into the expression >
    /// @mulle-objc@ MUST CHANGE VERSION FOR EACH LLDB RELEASE!!
    wrap_stream.Printf("\
static const struct   mulle_clang_objccompilerinfo\n\
{\n\
  unsigned int   load_version;\n\
  unsigned int   runtime_version;\n\
} __mulle_objc_objccompilerinfo =\n\
{\n\
  16, // @mulle-objc@ load version must match \n\
  0   // 0 to not emit __load_mulle_objc\n\
};\n\
");

    /// @mulle-objc@ hack some mulle-objc-runtime stuff into the expression <

    // First construct a tagged form of the user expression so we can find it
    // later:
    std::string tagged_body;
    switch (wrapping_language) {
    default:
      tagged_body = m_body;
      break;
    case lldb::eLanguageTypeC:
    case lldb::eLanguageTypeC_plus_plus:
    case lldb::eLanguageTypeObjC:
      tagged_body.append(m_start_marker);
      tagged_body.append(m_body);
      tagged_body.append(m_end_marker);
      break;
    }
    switch (wrapping_language) {
    default:
      break;
    case lldb::eLanguageTypeC:
      wrap_stream.Printf("%s"
                         "void                           \n"
                         "%s(void *$__lldb_arg)          \n"
                         "{                              \n"
                         "    %s;                        \n"
                         "%s"
                         "}                              \n",
                         module_imports.c_str(), m_name.c_str(),
                         lldb_local_var_decls.GetData(), tagged_body.c_str());
      break;
    case lldb::eLanguageTypeC_plus_plus:
      wrap_stream.Printf("%s"
                         "void                                   \n"
                         "$__lldb_class::%s(void *$__lldb_arg)   \n"
                         "{                                      \n"
                         "    %s;                                \n"
                         "%s"
                         "}                                      \n",
                         module_imports.c_str(), m_name.c_str(),
                         lldb_local_var_decls.GetData(), tagged_body.c_str());
      break;
    case lldb::eLanguageTypeObjC:
      if (static_method) {
        wrap_stream.Printf(
            "%s"
            "@interface $__lldb_objc_class ($__lldb_category)        \n"
            "+(void)%s:(void *)$__lldb_arg;                          \n"
            "@end                                                    \n"
            "@implementation $__lldb_objc_class ($__lldb_category)   \n"
            "+(void)%s:(void *)$__lldb_arg                           \n"
            "{                                                       \n"
            "    %s;                                                 \n"
            "%s"
            "}                                                       \n"
            "@end                                                    \n",
            module_imports.c_str(), m_name.c_str(), m_name.c_str(),
            lldb_local_var_decls.GetData(), tagged_body.c_str());
      } else {
        wrap_stream.Printf(
            "%s"
            "@interface $__lldb_objc_class ($__lldb_category)       \n"
            "-(void)%s:(void *)$__lldb_arg;                         \n"
            "@end                                                   \n"
            "@implementation $__lldb_objc_class ($__lldb_category)  \n"
            "-(void)%s:(void *)$__lldb_arg                          \n"
            "{                                                      \n"
            "    %s;                                                \n"
            "%s"
            "}                                                      \n"
            "@end                                                   \n",
            module_imports.c_str(), m_name.c_str(), m_name.c_str(),
            lldb_local_var_decls.GetData(), tagged_body.c_str());
      }
      break;
    }

    text = wrap_stream.GetString();
  } else {
    text.append(m_body);
  }

  return true;
}

bool ClangExpressionSourceCode::GetOriginalBodyBounds(
    std::string transformed_text, lldb::LanguageType wrapping_language,
    size_t &start_loc, size_t &end_loc) {
  switch (wrapping_language) {
  default:
    return false;
  case lldb::eLanguageTypeC:
  case lldb::eLanguageTypeC_plus_plus:
  case lldb::eLanguageTypeObjC:
    break;
  }

  start_loc = transformed_text.find(m_start_marker);
  if (start_loc == std::string::npos)
    return false;
  start_loc += m_start_marker.size();
  end_loc = transformed_text.find(m_end_marker);
  return end_loc != std::string::npos;
}
