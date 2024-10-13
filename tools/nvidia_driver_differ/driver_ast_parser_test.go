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

// Package driver_ast_parser_test contains tests for the driver_ast_parser.
package driver_ast_parser_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/tools/nvidia_driver_differ/parser"
)

// TestParser runs driver_ast_parser on test_struct.cc and compares the output to the expected json.
func TestParser(t *testing.T) {
	driverParser, err := testutil.FindFile("tools/nvidia_driver_differ/driver_ast_parser")
	if err != nil {
		t.Fatalf("failed to find driver_ast_parser: %v", err)
	}

	testStructFile, err := testutil.FindFile("tools/nvidia_driver_differ/test_struct.cc")
	if err != nil {
		t.Fatalf("failed to find test_struct.cc: %v", err)
	}

	// Write a file containing the struct name we want to parse.
	structsFile, err := os.CreateTemp(os.TempDir(), "structs.*.json")
	if err != nil {
		t.Fatalf("failed to create structs file: %v", err)
	}
	defer func() {
		if err := structsFile.Close(); err != nil {
			t.Fatalf("failed to close structs file: %v", err)
		}
		if err := os.Remove(structsFile.Name()); err != nil {
			t.Fatalf("failed to remove structs file: %v", err)
		}
	}()

	input := parser.InputJSON{
		Structs: []string{"TestStruct", "TestStruct2"},
	}
	if err := json.NewEncoder(structsFile).Encode(&input); err != nil {
		t.Fatalf("failed to write input structs file: %v", err)
	}
	structsFile.Sync()

	cmd := exec.Command(driverParser, "--structs", structsFile.Name(), testStructFile)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("failed to run driver_ast_parser: %v\n%s", err, stderr.String())
	}

	outputJSON := parser.OutputJSON{}
	if err := json.Unmarshal(out, &outputJSON); err != nil {
		t.Fatalf("failed to unmarshal output %s: %v", string(out), err)
	}
	expectedOutput := parser.OutputJSON{
		Records: parser.RecordDefs{
			"TestStruct": parser.RecordDef{
				Fields: []parser.RecordField{
					{Name: "a", Type: "int", Offset: 0},
					{Name: "b", Type: "int", Offset: 4},
					{Name: "e", Type: "TestStruct::e_t[4]", Offset: 8},
					{Name: "f", Type: "TestUnion", Offset: 40},
				},
				Size:    44,
				IsUnion: false,
				Source:  "test_struct.cc:25:16",
			},
			"TestStruct2": parser.RecordDef{
				Fields: []parser.RecordField{
					{Name: "a", Type: "int", Offset: 0},
					{Name: "b", Type: "int", Offset: 4},
					{Name: "e", Type: "TestStruct::e_t[4]", Offset: 8},
					{Name: "f", Type: "TestUnion", Offset: 40},
				},
				Size:    44,
				IsUnion: false,
				Source:  "test_struct.cc:25:16",
			},
			"TestStruct::e_t": parser.RecordDef{
				Fields: []parser.RecordField{
					{Name: "c", Type: "OtherInt", Offset: 0},
					{Name: "d", Type: "OtherInt", Offset: 4},
				},
				Size:    8,
				IsUnion: false,
				Source:  "test_struct.cc:28:3",
			},
			"TestUnion": parser.RecordDef{
				Fields: []parser.RecordField{
					{Name: "u_a", Type: "int", Offset: 0},
					{Name: "u_b", Type: "int", Offset: 0},
				},
				Size:    4,
				IsUnion: true,
				Source:  "test_struct.cc:20:9",
			},
		},
		Aliases: parser.TypeAliases{
			"OtherInt": parser.TypeDef{Type: "int", Size: 4},
			"int":      parser.TypeDef{Type: "int", Size: 4},
		},
	}

	if diff := cmp.Diff(expectedOutput, outputJSON, cmpopts.IgnoreFields(parser.RecordDef{}, "Source")); diff != "" {
		t.Fatalf("output mismatch (-want +got):\n%s", diff)
	}

	// Only check the source suffix since the absolute path will be different every run.
	for name, structDef := range outputJSON.Records {
		if !strings.HasSuffix(structDef.Source, expectedOutput.Records[name].Source) {
			t.Fatalf("source mismatch for %s: should end with %s, got %s", name, expectedOutput.Records[name].Source, structDef.Source)
		}
	}
}
