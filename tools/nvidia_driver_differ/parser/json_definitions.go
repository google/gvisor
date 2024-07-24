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

// Package parser contains functions for interfacing with driver_ast_parser.
package parser

import (
	"fmt"
	"slices"
	"strings"

	"github.com/google/go-cmp/cmp"
)

// InputJSON is the format for the structs.json file that driver_ast_parser takes as input.
type InputJSON struct {
	Structs []string `json:"structs"`
}

// OutputJSON is the format for the output of driver_ast_parser.
type OutputJSON struct {
	Structs StructDefs `json:"structs"`
}

// StructField represents a field in a struct.
type StructField struct {
	Name string
	Type string
}

func (s StructField) String() string {
	return fmt.Sprintf("%s %s", s.Type, s.Name)
}

// StructDef represents a struct definition.
type StructDef struct {
	Fields []StructField
	Source string
}

// Equals returns true if the two struct definitions are equal. We only
// compare the fields, not the source.
func (s StructDef) Equals(other StructDef) bool {
	return slices.Equal(s.Fields, other.Fields)
}

// StructDefs is a map of struct name to struct definition.
type StructDefs map[string]StructDef

// GetStructDiff prints a diff between two struct definitions.
func GetStructDiff(name string, s1, s2 StructDef) string {
	var b strings.Builder
	fmt.Fprintf(&b, "--- A: %s\n", s1.Source)
	fmt.Fprintf(&b, "+++ B: %s\n", s2.Source)

	fmt.Fprintf(&b, "struct %s\n", name)
	fmt.Fprint(&b, cmp.Diff(s1.Fields, s2.Fields))

	return b.String()
}
