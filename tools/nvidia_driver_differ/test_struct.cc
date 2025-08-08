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

// This is a test file for the driver_ast_parser. It contains a simple struct
// definition that we can use to test the parser.

typedef int OtherInt;

typedef union {
  int u_a;
  int u_b;
} TestUnion;

typedef struct TestStruct {
  int a;
  int b;
  struct {
    OtherInt c;
    OtherInt d;
  } e[4];
  TestUnion f;
} TestStruct;

typedef TestStruct TestStruct2;

#define CONSTANT_MACRO 0x1469
#define ADDITION_MACRO (CONSTANT_MACRO + 7)
#define UNSIGNED_HEX_MACRO 0x279U
#define PARENTHESIZED_HEX_MACRO (0x000050a0) /* Comment to test parsing */
#define FUNCTION_MACRO(i) i
#define USES_FUNCTION_MACRO FUNCTION_MACRO(1)

const unsigned int VAR_CONSTANT_MACRO = CONSTANT_MACRO;
const unsigned int VAR_ADDITION_MACRO = ADDITION_MACRO;
const unsigned int VAR_UNSIGNED_HEX_MACRO = UNSIGNED_HEX_MACRO;
const unsigned int VAR_PARENTHESIZED_HEX_MACRO = PARENTHESIZED_HEX_MACRO;
const unsigned int VAR_USES_FUNCTION_MACRO = USES_FUNCTION_MACRO;
