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

package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/bazelbuild/rules_go/go/runfiles"
)

var changelogTool = flag.String("changelog-tool", "", "path to the changelog binary")

func TestChangelog(t *testing.T) {
	tool, err := runfiles.Rlocation(*changelogTool)
	if err != nil {
		t.Fatal(err)
	}
	for _, tz := range []string{"UTC", "Pacific/Honolulu"} {
		for _, tc := range []struct {
			name, version, date string
		}{
			{"release", "20260203.1", "Tue, 03 Feb 2026 00:00:00 +0000"},
			{"unreleased", "abcdef123456", "Thu, 01 Jan 1970 00:00:00 +0000"},
			{"invalid", "20260230.1", ""},
		} {
			t.Run(tz+"/"+tc.name, func(t *testing.T) {
				dir := t.TempDir()
				version, output := filepath.Join(dir, "version"), filepath.Join(dir, "changelog")
				if err := os.WriteFile(version, []byte(tc.version+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(tool, version, output)
				cmd.Env = append(os.Environ(), "TZ="+tz)
				log, err := cmd.CombinedOutput()
				if tc.date == "" {
					if _, ok := err.(*exec.ExitError); !ok {
						t.Fatalf("invalid date: error = %v, want nonzero exit; output: %s", err, log)
					}
					if _, err := os.Stat(output); !os.IsNotExist(err) {
						t.Fatalf("invalid date output: stat error = %v, want nonexistent", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("changelog: %v; output: %s", err, log)
				}
				got, err := os.ReadFile(output)
				if err != nil {
					t.Fatal(err)
				}
				want := fmt.Sprintf("runsc (%s) unstable; urgency=medium\n\n  * See https://gvisor.dev/docs/ for release details.\n\n -- The gVisor Authors <gvisor-dev@googlegroups.com>  %s\n", tc.version, tc.date)
				if string(got) != want {
					t.Errorf("changelog = %q, want %q", got, want)
				}
			})
		}
	}
}
