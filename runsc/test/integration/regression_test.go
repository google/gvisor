// Copyright 2019 The gVisor Authors.
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

package integration

import (
	"strings"
	"testing"

	"gvisor.dev/gvisor/runsc/test/testutil"
)

// Test that UDS can be created using overlay when parent directory is in lower
// layer only (b/134090485).
//
// Prerequisite: the directory where the socket file is created must not have
// been open for write before bind(2) is called.
func TestBindOverlay(t *testing.T) {
	if err := testutil.Pull("ubuntu:trusty"); err != nil {
		t.Fatal("docker pull failed:", err)
	}
	d := testutil.MakeDocker("bind-overlay-test")

	cmd := "nc -l -U /var/run/sock& sleep 1 && echo foobar-asdf | nc -U /var/run/sock"
	got, err := d.RunFg("ubuntu:trusty", "bash", "-c", cmd)
	if err != nil {
		t.Fatal("docker run failed:", err)
	}

	if want := "foobar-asdf"; !strings.Contains(got, want) {
		t.Fatalf("docker run output is missing %q: %s", want, got)
	}
	defer d.CleanUp()
}
