// Copyright 2022 The gVisor Authors.
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

package coretag

import (
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/hostos"
)

func TestEnable(t *testing.T) {
	version, err := hostos.KernelVersion()
	if err != nil {
		t.Fatalf("Unable to parse kernel version: %v", err)
	}
	// Skip running test when running on Linux kernel < 5.14 because core tagging
	// is not available.
	if version.LessThan(5, 14) {
		t.Skipf("Running on Linux kernel: %s < 5.14. Core tagging not available. Skipping test.", version)
		return
	}
	if err := Enable(); err != nil {
		t.Fatalf("Enable() got error %v, wanted nil", err)
	}

	coreTags, err := GetAllCoreTags(os.Getpid())
	if err != nil {
		t.Fatalf("GetAllCoreTags() got error %v, wanted nil", err)
	}
	if len(coreTags) != 1 {
		t.Fatalf("Got coreTags %v, wanted len(coreTags)=1", coreTags)
	}
}
