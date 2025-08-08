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
	"maps"
	"slices"
	"strings"

	"github.com/google/go-cmp/cmp"
)

// InputJSON is the format for the input.json file that driver_ast_parser takes as input.
type InputJSON struct {
	Structs   []string `json:"structs"`
	Constants []string `json:"constants"`
}

// OutputJSON is the format for the output of driver_ast_parser.
type OutputJSON struct {
	Records   RecordDefs
	Aliases   TypeAliases
	Constants map[string]uint64
}

// Merge merges the struct definitions from b into this OutputJSON.
func (a *OutputJSON) Merge(b OutputJSON) {
	if a.Records == nil {
		a.Records = make(RecordDefs)
	}
	if a.Aliases == nil {
		a.Aliases = make(TypeAliases)
	}
	if a.Constants == nil {
		a.Constants = make(map[string]uint64)
	}
	maps.Copy(a.Records, b.Records)
	maps.Copy(a.Aliases, b.Aliases)
	maps.Copy(a.Constants, b.Constants)
}

// RecordField represents a field in a record (struct or union).
type RecordField struct {
	Name   string
	Type   string
	Offset uint64
}

func (s RecordField) String() string {
	return fmt.Sprintf("%s %s", s.Type, s.Name)
}

// RecordDef represents the definition of a record (struct or union).
type RecordDef struct {
	Fields  []RecordField
	Size    uint64
	IsUnion bool `json:"is_union"`
	Source  string
}

// Equals returns true if the two record definitions are equal. We ignore the source of the records.
func (s RecordDef) Equals(other RecordDef) bool {
	return s.IsUnion == other.IsUnion && s.Size == other.Size && slices.Equal(s.Fields, other.Fields)
}

// TypeDef represents the definition of a type.
type TypeDef struct {
	Type string
	Size uint64
}

// RecordDefs is a map of type names to definitions.
type RecordDefs map[string]RecordDef

// TypeAliases is a map of type aliases to their underlying type.
type TypeAliases map[string]TypeDef

// GetRecordDiff prints a diff between two records.
func GetRecordDiff(name string, a, b RecordDef) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "--- A: %s\n", a.Source)
	fmt.Fprintf(&sb, "+++ B: %s\n", b.Source)

	switch {
	case a.IsUnion && !b.IsUnion:
		fmt.Fprintf(&sb, "- union %s\n", name)
		fmt.Fprintf(&sb, "+ struct %s\n", name)
	case !a.IsUnion && b.IsUnion:
		fmt.Fprintf(&sb, "- struct %s\n", name)
		fmt.Fprintf(&sb, "+ union %s\n", name)
	case a.IsUnion && b.IsUnion:
		fmt.Fprintf(&sb, "union %s\n", name)
	case !a.IsUnion && !b.IsUnion:
		fmt.Fprintf(&sb, "struct %s\n", name)
	}
	if a.Size != b.Size {
		fmt.Fprintf(&sb, "  size: %d -> %d (bytes)\n", a.Size, b.Size)
	}
	fmt.Fprint(&sb, cmp.Diff(a.Fields, b.Fields))

	return sb.String()
}
