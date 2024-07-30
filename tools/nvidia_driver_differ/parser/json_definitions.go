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
	Records RecordDefs  `json:"records"`
	Aliases TypeAliases `json:"aliases"`
}

// RecordField represents a field in a record (struct or union).
type RecordField struct {
	Name string
	Type string
}

func (s RecordField) String() string {
	return fmt.Sprintf("%s %s", s.Type, s.Name)
}

// RecordDef represents the definition of a record (struct or union).
type RecordDef struct {
	Fields []RecordField
	Source string
}

// Equals returns true if the two record definitions are equal. We only
// compare the fields, not the source.
func (s RecordDef) Equals(other RecordDef) bool {
	return slices.Equal(s.Fields, other.Fields)
}

// RecordDefs is a map of type names to definitions.
type RecordDefs map[string]RecordDef

// TypeAliases is a map of type aliases to their underlying type.
type TypeAliases map[string]string

// GetRecordDiff prints a diff between two records.
func GetRecordDiff(name string, s1, s2 RecordDef) string {
	var b strings.Builder
	fmt.Fprintf(&b, "--- A: %s\n", s1.Source)
	fmt.Fprintf(&b, "+++ B: %s\n", s2.Source)

	fmt.Fprintf(&b, "struct %s\n", name)
	fmt.Fprint(&b, cmp.Diff(s1.Fields, s2.Fields))

	return b.String()
}
