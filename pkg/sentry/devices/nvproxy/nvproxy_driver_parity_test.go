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

//go:build !false
// +build !false

// Package nvproxy_driver_parity_test tests that the nvproxy driver ABI
// is kept up to date with the NVIDIA driver.
package nvproxy_driver_parity_test

import (
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/test/testutil"

	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy"
	"gvisor.dev/gvisor/tools/nvidia_driver_differ/parser"
)

// TestSupportedStructNames tests that all the structs listed in nvproxy are found in the driver
// source code.
func TestSupportedStructNames(t *testing.T) {
	// Find the parser binary
	parserPath, err := testutil.FindFile("tools/nvidia_driver_differ/driver_ast_parser")
	if err != nil {
		t.Fatalf("Failed to find driver_ast_parser: %v", err)
	}
	parserFile, err := os.Open(parserPath)
	if err != nil {
		t.Fatalf("Failed to open driver_ast_parser: %v", err)
	}
	defer func() {
		if err := parserFile.Close(); err != nil {
			t.Fatalf("Failed to close driver_ast_parser: %v", err)
		}
	}()

	runner, err := parser.NewRunner((*parser.ParserFile)(parserFile))
	if err != nil {
		t.Fatalf("Failed to create parser runner: %v", err)
	}

	nvproxy.Init()
	// Run the parser on all supported driver versions
	nvproxy.ForEachSupportDriver(func(version nvproxy.DriverVersion, checksum string) {
		t.Run(version.String(), func(t *testing.T) {
			structNames, ok := nvproxy.SupportedStructNames(version)
			if !ok {
				t.Fatalf("failed to get struct names for driver %q", version.String())
			}

			// Create structs file for parser
			if err := runner.CreateStructsFile(structNames); err != nil {
				t.Fatalf("failed to create temporary structs list: %v", err)
			}

			// Run parser
			defs, err := runner.ParseDriver(version)
			if err != nil {
				t.Fatalf("failed to run driver_ast_parser: %v", err)
			}

			// Check that every struct is found in the parser output.
			for _, name := range structNames {
				_, isRecord := defs.Records[string(name)]
				_, isAlias := defs.Aliases[string(name)]
				if !isRecord && !isAlias {
					t.Errorf("struct %q not found in parser output for version %q", name, version.String())
				}
			}
		})
	})
}
