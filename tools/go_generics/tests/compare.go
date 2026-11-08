// Copyright 2026 The gVisor Authors.
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

// Binary compare checks a generated Go file against its golden file.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func readLines(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	// Keep newlines so a missing final newline remains visible.
	return strings.SplitAfter(string(data), "\n")
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: compare golden.go generated.go")
		os.Exit(2)
	}
	golden, generated := os.Args[1], os.Args[2]
	ignore := cmpopts.IgnoreSliceElements(func(line string) bool {
		return line == "" || line == "\n" || strings.HasPrefix(strings.TrimLeft(line, " \t\r\v\f"), "//")
	})
	if diff := cmp.Diff(readLines(golden), readLines(generated), ignore); diff != "" {
		fmt.Fprintf(os.Stderr, "generated file differs (-%s +%s):\n%s", golden, generated, diff)
		os.Exit(1)
	}
}
