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

package maintainers_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"gvisor.dev/gvisor/pkg/test/testutil"
)

// checkInSync verifies that the checked-in file at path matches what
// `maintainers_gen` generates.
func checkInSync(t *testing.T, path string) {
	t.Helper()
	format := filepath.Base(path)
	genBin, err := testutil.FindFile("governance/tools/maintainers/maintainers_gen")
	if err != nil {
		t.Fatalf("cannot find maintainers_gen: %v", err)
	}
	yamlPath, err := testutil.FindFile("governance/maintainers.yaml")
	if err != nil {
		t.Fatalf("cannot find maintainers.yaml: %v", err)
	}
	wantPath, err := testutil.FindFile(path)
	if err != nil {
		t.Fatalf("cannot find %s: %v", path, err)
	}
	cmd := exec.Command(genBin, "-input", yamlPath, "-format", format)
	cmd.Stderr = os.Stderr
	got, err := cmd.Output()
	if err != nil {
		t.Fatalf("cannot run maintainers_gen: %v", err)
	}
	want, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s is out of sync with governance/maintainers.yaml; regenerate with:\n"+
			"  make run TARGETS=//governance/tools/maintainers:maintainers_gen ARGS=\"-input governance/maintainers.yaml -format %s -output %s\"\n"+
			"got:\n%swant:\n%s", path, format, path, got, want)
	}
}

func TestReviewerJSONInSync(t *testing.T) {
	checkInSync(t, ".github/reviewer.json")
}

func TestMaintainersMDInSync(t *testing.T) {
	checkInSync(t, "MAINTAINERS.md")
}
