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

package lib

import (
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
	"path/filepath"
	"strings"
)

type mobyRunner struct{}

var _ TestRunner = mobyRunner{}

const mobyDir = "/moby"

// testFiles is a list of test files to run.
var testFiles = [...]string{
	"integration/network/network_linux_test.go",
	"integration/network/dns_test.go",
	"integration/network/network_test.go",
}

// ListTests implements TestRunner.ListTests.
func (mobyRunner) ListTests() ([]string, error) {
	files := make([]string, len(testFiles))
	for i, file := range testFiles {
		files[i] = filepath.Join(mobyDir, file)
	}

	var tests []string
	fset := token.NewFileSet()

	// Parse each test file and extract the test function names.
	for _, file := range files {
		relPath, err := filepath.Rel(mobyDir, file)
		if err != nil {
			return nil, err
		}
		relPath = strings.TrimSuffix(relPath, ".go")

		node, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			return nil, err
		}

		for _, decl := range node.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if strings.HasPrefix(fn.Name.Name, "Test") {
				tests = append(tests, relPath+"/"+fn.Name.Name)
			}
		}
	}

	return tests, nil
}

// TestCmds implements TestRunner.TestCmds.
func (mobyRunner) TestCmds(tests []string) []*exec.Cmd {
	if len(tests) == 0 {
		return nil
	}

	// Join the test names with spaces into to split and iterate over
	// in run_moby_tests.sh.
	testList := strings.Join(tests, " ")
	// Generate a unique name for the batch of tests.
	hash := sha256.Sum256([]byte(testList))
	batchName := fmt.Sprintf("batch_%x", hash[:4])

	cmd := exec.Command("/usr/local/bin/run_moby_tests.sh", batchName, testList)
	return []*exec.Cmd{cmd}
}
