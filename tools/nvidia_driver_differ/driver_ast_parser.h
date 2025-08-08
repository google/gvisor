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
    R"a(This tool parses a given C++ source file and outputs relevant definitions
for a list of provided struct names and constant names. It finds the definitions
for each struct given by the names provided, as well as any nested structs or
types that they depend on.

This tool is intended to be used to parse the NVIDIA driver source code; as
such, there are some assumptions made about how structs are defined and what
types are used.

To parse structs defined in multiple files, it is easier to create a C++ file
that includes all the files to be parsed. You will also need a
compile_commands.json file that contains a compile command with the relevant
include directories.

The struct and constant names should be specified in a JSON file containing a
JSON object, which has "structs" and "constants" keys that map to a list of
strings. The tool will search for their definition in the given source files,
and output their definition to the specified output file.

This output file will contain a JSON object with a "records" (structs or unions)
field mapping each name to its definition, a "aliases" field for any aliases
that were found, as well as a "constants" field mapping each name to its value.
A variety of information is outputted:
- For records, the fields are given as a JSON array of objects with "name",
  "type", and "offset" keys. The record also has a "size" key indicating the
  size of the struct in bytes, an "is_union" key indicating whether it is a
  union or not, and a "source" key containing the file name and line number
  where it was defined.
- For aliases, the type is given as a JSON object with a "type" and "size" key

Example usage:
    driver_ast_parser --input=input.json -o=output.json driver_source_files.h

input.json:
    {
        "structs": [
            "TestStruct",
            "TestStruct2"
        ],
        "constants": [
            "TEST_CONSTANT",
            "ANOTHER_CONSTANT"
        ]
    }
)a";

#endif  // TOOLS_NVIDIA_DRIVER_DIFFER_DRIVER_AST_PARSER_H_
