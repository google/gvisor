// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package container

import (
	"slices"
	"strings"
	"testing"
)

func TestParseDeviceMajors(t *testing.T) {
	const procDevices = `Character devices:
  1 mem
195 nvidia
235 nvidia-caps
510 nvidia-uvm

Block devices:
  8 sd
`
	got, err := parseDeviceMajors(strings.NewReader(procDevices), []string{"nvidia-uvm", "nvidia-caps"})
	if err != nil {
		t.Fatalf("parseDeviceMajors(): %v", err)
	}
	if want := []int64{235, 510}; !slices.Equal(got, want) {
		t.Errorf("parseDeviceMajors() = %v, want %v", got, want)
	}
}
