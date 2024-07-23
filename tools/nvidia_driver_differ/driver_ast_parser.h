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

#ifndef TOOLS_NVIDIA_DRIVER_DIFFER_DRIVER_AST_PARSER_H_
#define TOOLS_NVIDIA_DRIVER_DIFFER_DRIVER_AST_PARSER_H_

const char ToolHelpDescription[] =
    R"a(This tool parses a given C++ source file and outputs the struct definitions
for a list of provided struct names. To parse structs defined in multiple files,
it is easier to create a C++ file that includes all the files to be parsed. You
will also need a compile_commands.json file that contains a compile command with
the relevant include directories.

The struct names should be specified in a JSON file containing a JSON object,
which has a "structs" key that maps to a list of strings. The tool will search
for the struct definition in the given source files, and output the struct
definition to the specified output file.

This output file will contain a JSON object with a "structs" field mapping each
struct name to its struct definition. Each struct definition will be a JSON
array of fields, where each field is a JSON object with a "name" and a "type"
key. The fields will be ordered in the same order as they appear in the struct

Example usage:
    driver_ast_parser --structs=structs.json -o=output.json driver_source_files.h

The structs.json file should contain an array of struct names to parse:
    {
        "structs": [
            "TestStruct",
            "TestStruct2"
        ]
    }
)a";

#endif  // TOOLS_NVIDIA_DRIVER_DIFFER_DRIVER_AST_PARSER_H_
