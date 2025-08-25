// Copyright 2024 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "tools/nvidia_driver_differ/driver_ast_parser.h"

#include <stdlib.h>

#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>

#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_cat.h"
#include "nlohmann/json.hpp"
#include "clang/include/clang/AST/ASTContext.h"
#include "clang/include/clang/AST/Decl.h"
#include "clang/include/clang/AST/Expr.h"
#include "clang/include/clang/AST/Type.h"
#include "clang/include/clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/include/clang/ASTMatchers/ASTMatchers.h"
#include "clang/include/clang/Tooling/CommonOptionsParser.h"
#include "clang/include/clang/Tooling/Tooling.h"
#include "llvm/include/llvm/Support/Casting.h"
#include "llvm/include/llvm/Support/CommandLine.h"
#include "llvm/include/llvm/Support/raw_ostream.h"

using clang::ast_matchers::allOf;
using clang::ast_matchers::hasDeclaration;
using clang::ast_matchers::hasName;
using clang::ast_matchers::hasType;
using clang::ast_matchers::recordDecl;
using clang::ast_matchers::recordType;
using clang::ast_matchers::typedefDecl;
using clang::ast_matchers::typedefType;
using clang::ast_matchers::varDecl;

using clang::ast_matchers::MatchFinder;

using json = nlohmann::json;

struct DriverStructReporter : public MatchFinder::MatchCallback {
  json RecordDefinitions;
  json TypeAliases;
  json Constants;
  absl::flat_hash_set<std::string> ParsedTypes;

  // This matches the case where a struct is being defined.
  // E.g.
  // typedef struct {
  //   int a;
  //   int b;
  // } TestStruct;
  auto get_struct_definition_matcher(std::string struct_name) {
    // Nvidia's driver typedefs all their struct. We search for the
    // typedef declaration, and go from there to find the struct definition.
    return typedefDecl(allOf(hasName(struct_name),
                             // Match and bind to the struct declaration.
                             hasType(recordType(hasDeclaration(
                                 recordDecl().bind("struct_decl"))))))
        .bind("typedef_decl");
  }

  // In some cases, a struct name is typedef'd to an existing struct.
  // E.g.
  // typedef TestStructA TestStructB;
  auto get_struct_typedef_matcher(std::string struct_name) {
    // Nvidia's driver typedefs all their struct. We search for the
    // typedef declaration, and go from there to find the struct definition.
    return typedefDecl(
               allOf(hasName(struct_name),
                     // Match and bind to the struct declaration.
                     hasType(typedefType(hasDeclaration(typedefDecl())))))
        .bind("typedef_decl");
  }

  auto get_constant_matcher(std::string constant_name) {
    return varDecl(hasName(constant_name)).bind("constant_decl");
  }

  void run(const MatchFinder::MatchResult &result) override {
    const auto *ctx = result.Context;

    const auto *constant_decl =
        result.Nodes.getNodeAs<clang::VarDecl>("constant_decl");
    if (constant_decl) {
      std::string name = constant_decl->getNameAsString();
      if (!constant_decl->hasInit()) {
        std::cerr << "Constant " << name << " has no initializer\n";
        exit(1);
      }
      clang::Expr::EvalResult value;
      if (!constant_decl->getInit()->EvaluateAsInt(value, *ctx)) {
        std::cerr << "Unable to evaluate constant " << name << "\n";
        exit(1);
      }
      Constants[name] = value.Val.getInt().getZExtValue();
      return;
    }

    const auto *typedef_decl =
        result.Nodes.getNodeAs<clang::TypedefDecl>("typedef_decl");
    if (typedef_decl == nullptr) {
      std::cerr << "Unable to find a matched declaration\n";
      exit(1);
    }
    std::string name = typedef_decl->getNameAsString();

    // If struct_decl doesn't exist, then we know it's a typedef to an existing
    // struct.
    const auto *struct_decl =
        result.Nodes.getNodeAs<clang::RecordDecl>("struct_decl");
    if (struct_decl == nullptr) {
      // Generate the definition for the underlying type, then copy it for
      // this struct.
      const auto type = typedef_decl->getUnderlyingType();
      const auto type_name = type.getAsString();
      add_type_definition(type, type_name, ctx);

      if (type->isRecordType()) {
        RecordDefinitions[name] = RecordDefinitions[type_name];
      } else {
        TypeAliases[name] = TypeAliases[type_name];
      }
      return;
    }

    add_type_definition(ctx->getCanonicalTagType(struct_decl), name, ctx);
  }

  // Adds the type definition of `type` to either `RecordDefinitions` or
  // `TypeAliases`, mapped to `name`. Recursively adds the type definitions
  // of any nested types.
  void add_type_definition(const clang::QualType &type, const std::string &name,
                           const clang::ASTContext *ctx) {
    // We've already handled this type.
    if (ParsedTypes.contains(name)) {
      return;
    }
    ParsedTypes.insert(name);

    // We use the canonical type to get past any typedefs.
    const auto canonical_type = type.getCanonicalType();

    if (canonical_type->isRecordType()) {
      const auto record_decl = canonical_type->getAsRecordDecl();

      add_record_definition(record_decl, name, ctx);
    } else {
      // getTypeSize returns the size in bits, so we divide by 8 to get bytes.
      uint64_t size = ctx->getTypeSize(canonical_type) / 8;
      TypeAliases[name] = json::object(
          {{"size", size}, {"type", canonical_type.getAsString()}});
    }
  }

  // Adds the type definition of `record_decl` to `RecordDefinitions`, mapped
  // to `name`. Recursively adds the type definitions of any nested types.
  void add_record_definition(const clang::RecordDecl *record_decl,
                             const std::string &name,
                             const clang::ASTContext *ctx) {
    json fields;
    for (const auto *field : record_decl->fields()) {
      auto field_type = field->getType();

      // If this is an array type, save the array size then get the underlying
      // element type to recurse on later.
      uint64_t array_size = 0;
      if (field_type->isConstantArrayType()) {
        const auto *CAT = llvm::dyn_cast<clang::ConstantArrayType>(
            field_type->castAsArrayTypeUnsafe());
        if (CAT == nullptr) {
          std::cerr << "Unable to cast to ConstantArrayType\n";
          exit(1);
        }
        array_size = CAT->getSize().getZExtValue();
        field_type = CAT->getElementType();
      }

      // Get the type name. If the type is not named, we use the record name
      // and field name to create a fake type name.
      std::string base_type_name;
      if (field_type->hasUnnamedOrLocalType()) {
        base_type_name =
            absl::StrCat(name, "::", field->getNameAsString(), "_t");
      } else {
        base_type_name = field_type.getAsString();
      }

      // If this is an array type, add the array size to the type name.
      std::string field_type_name = base_type_name;
      if (array_size > 0) {
        absl::StrAppend(&field_type_name, "[", array_size, "]");
      }

      // getFieldOffset returns the size in bits, so we divide by 8 to get
      // bytes.
      uint64_t offset = ctx->getFieldOffset(field) / 8;

      // Add field to json.
      fields.push_back(json::object({{"name", field->getNameAsString()},
                                     {"type", field_type_name},
                                     {"offset", offset}}));

      // Recurse on the field type.
      add_type_definition(field_type, base_type_name, ctx);
    }

    std::string source =
        record_decl->getLocation().printToString(ctx->getSourceManager());
    // getTypeSize returns the size in bits, so we divide by 8 to get bytes.
    uint64_t size =
        ctx->getTypeSize(
            record_decl->getASTContext().getCanonicalTagType(record_decl)) /
        8;
    bool is_union = record_decl->isUnion();
    RecordDefinitions[name] = json::object({{"source", source},
                                            {"fields", fields},
                                            {"size", size},
                                            {"is_union", is_union}});
  }
};

static llvm::cl::OptionCategory DriverASTParserCategory("Driver AST Parser");

static llvm::cl::extrahelp CommonHelp(
    clang::tooling::CommonOptionsParser::HelpMessage);
static llvm::cl::extrahelp MoreHelp(ToolHelpDescription);

static llvm::cl::opt<std::string> InputFile(
    "input",
    llvm::cl::desc("Path to the input file containing the struct and constant "
                   "names to parse."),
    llvm::cl::cat(DriverASTParserCategory), llvm::cl::Required);

static llvm::cl::opt<std::string> OutputFile(
    "output", "o",
    llvm::cl::desc("Path to the output file for the parsed type definitions. "
                   "By default, will print to stdout."),
    llvm::cl::cat(DriverASTParserCategory));

int main(int argc, const char **argv) {
  auto ExpectedParser = clang::tooling::CommonOptionsParser::create(
      argc, argv, DriverASTParserCategory);
  if (!ExpectedParser) {
    // Fail gracefully for unsupported options.
    llvm::errs() << ExpectedParser.takeError();
    return 1;
  }

  clang::tooling::CommonOptionsParser &OptionsParser = ExpectedParser.get();
  clang::tooling::ClangTool Tool(OptionsParser.getCompilations(),
                                 OptionsParser.getSourcePathList());

  DriverStructReporter reporter;
  MatchFinder finder;

  // Read from StructNames file.
  std::ifstream InputFileIS(InputFile);
  if (!InputFileIS) {
    std::cerr << "Unable to open struct names file: " << InputFile << "\n";
    return 1;
  }
  json input;
  InputFileIS >> input;
  for (json::iterator it = input["structs"].begin();
       it != input["structs"].end(); ++it) {
    finder.addMatcher(reporter.get_struct_definition_matcher(*it), &reporter);
    finder.addMatcher(reporter.get_struct_typedef_matcher(*it), &reporter);
  }

  if (input.contains("constants")) {
    for (json::iterator it = input["constants"].begin();
         it != input["constants"].end(); ++it) {
      finder.addMatcher(reporter.get_constant_matcher(*it), &reporter);
    }
  }

  // Run tool
  int ret = Tool.run(clang::tooling::newFrontendActionFactory(&finder).get());

  // Print output.
  json output = json::object({{"records", reporter.RecordDefinitions},
                              {"aliases", reporter.TypeAliases},
                              {"constants", reporter.Constants}});
  if (OutputFile.empty()) {
    std::cout << output.dump() << "\n";
  } else {
    std::ofstream OutputFileOS(OutputFile);
    if (!OutputFileOS) {
      std::cerr << "Unable to open output file: " << OutputFile << "\n";
      return 1;
    }
    OutputFileOS << output.dump() << "\n";
  }

  return ret;
}
