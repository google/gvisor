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

package gtest

import (
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"gvisor.dev/gvisor/pkg/test/testutil"
)

func TestDiscoveryDoesNotWriteResults(t *testing.T) {
	binary, err := testutil.FindFile("test/util/posix_error_test")
	if err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(t.TempDir(), "test.xml")
	t.Setenv("XML_OUTPUT_FILE", report)
	t.Setenv("GTEST_OUTPUT", "xml:"+report)
	t.Setenv("GUNIT_OUTPUT", "xml:"+report)

	cases, err := ParseTestCases(binary, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 || cases[0].all || cases[0].benchmark {
		t.Fatalf("ParseTestCases(%q) returned no gtest cases: %+v", binary, cases)
	}
	if _, err := os.Stat(report); !os.IsNotExist(err) {
		t.Fatalf("discovery created a test report; Stat(%q) = %v, want not-exist", report, err)
	}

	// A real execution must still inherit the parent's report destination.
	cmd := exec.Command(binary, cases[0].Args()...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("test execution failed: %v\n%s", err, out)
	}
	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Cases []struct {
			Name   string `xml:"name,attr"`
			Status string `xml:"status,attr"`
			Result string `xml:"result,attr"`
		} `xml:"testsuite>testcase"`
	}
	if err := xml.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Cases) != 1 || result.Cases[0].Name != cases[0].Name || result.Cases[0].Status != "run" || result.Cases[0].Result != "completed" {
		t.Fatalf("test report did not contain the completed case %q: %+v", cases[0].FullName(), result.Cases)
	}
}
