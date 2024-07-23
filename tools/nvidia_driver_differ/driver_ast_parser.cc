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

#include <fstream>
#include <iostream>
#include <string>

#include "nlohmann/json.hpp"
#include "clang/include/clang/AST/Decl.h"
#include "clang/include/clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/include/clang/ASTMatchers/ASTMatchers.h"
#include "clang/include/clang/Tooling/CommonOptionsParser.h"
#include "clang/include/clang/Tooling/Tooling.h"
#include "llvm/include/llvm/Support/CommandLine.h"
#include "llvm/include/llvm/Support/raw_ostream.h"

using clang::ast_matchers::allOf;
using clang::ast_matchers::elaboratedType;
using clang::ast_matchers::hasDeclaration;
using clang::ast_matchers::hasName;
using clang::ast_matchers::hasType;
using clang::ast_matchers::recordDecl;
using clang::ast_matchers::typedefDecl;

using clang::ast_matchers::MatchFinder;

using json = nlohmann::json;

struct DriverStructReporter : public MatchFinder::MatchCallback {
  json StructDefinitions;

  auto get_struct_matcher(std::string struct_name) {
    // Nvidia's driver typedefs all their struct. We search for the
    // typedef declaration, and go from there to find the struct definition.
    return typedefDecl(
               allOf(hasName(struct_name),
                     // Match and bind to the struct declaration.
                     hasType(
                         // Need to specify elaboratedType, otherwise hasType
                         // will complain that the type is ambiguous.
                         elaboratedType(hasDeclaration(
                             recordDecl().bind("struct_decl"))))))
        .bind("typedef_decl");
  }

  void run(const MatchFinder::MatchResult &result) override {
    const auto *typedef_decl =
        result.Nodes.getNodeAs<clang::TypedefDecl>("typedef_decl");
    if (typedef_decl == nullptr) {
      std::cerr << "Unable to find typedef decl\n";
      return;
    }

    const auto *struct_decl =
        result.Nodes.getNodeAs<clang::RecordDecl>("struct_decl");
    if (struct_decl == nullptr) {
      std::cerr << "Unable to find struct decl for "
                << typedef_decl->getNameAsString() << "\n";
      return;
    }

    // Add struct definition to json.
    // TODO(b/347796680): Consider improvements:
    //  Store alignment attributes as well?
    //  Make recursive? Relevant for recursive structs not defined in nvproxy,
    //    or unnamed structs/unions.
    //  Handle anonymous names?
    json fields = json::array();
    for (const auto *field : struct_decl->fields()) {
      fields.push_back(
          json::object({{"name", field->getNameAsString()},
                        {"type", field->getType().getAsString()}}));
    }

    std::string name = typedef_decl->getNameAsString();
    std::string source = typedef_decl->getLocation().printToString(
        result.Context->getSourceManager());

    StructDefinitions[name] =
        json::object({{"fields", fields}, {"source", source}});
  }
};

static llvm::cl::OptionCategory DriverASTParserCategory("Driver AST Parser");

static llvm::cl::extrahelp CommonHelp(
    clang::tooling::CommonOptionsParser::HelpMessage);
static llvm::cl::extrahelp MoreHelp(ToolHelpDescription);

static llvm::cl::opt<std::string> StructNames(
    "structs",
    llvm::cl::desc(
        "Path to the input file containing the struct names to parse."),
    llvm::cl::cat(DriverASTParserCategory), llvm::cl::Required);

static llvm::cl::opt<std::string> OutputFile(
    "output", "o",
    llvm::cl::desc("Path to the output file for the parsed structs. "
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
  std::ifstream StructNamesIS(StructNames);
  if (!StructNamesIS) {
    std::cerr << "Unable to open struct names file: " << StructNames << "\n";
    return 1;
  }
  json StructNamesJSON;
  StructNamesIS >> StructNamesJSON;
  for (json::iterator it = StructNamesJSON["structs"].begin();
       it != StructNamesJSON["structs"].end(); ++it) {
    finder.addMatcher(reporter.get_struct_matcher(*it), &reporter);
  }

  // Run tool
  int ret = Tool.run(clang::tooling::newFrontendActionFactory(&finder).get());

  // Print output.
  json output = json::object({{"structs", reporter.StructDefinitions}});
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
