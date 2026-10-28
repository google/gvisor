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

package coretagprime

import (
	"strings"
	"testing"
)

func TestIsCoreTagsCreate(t *testing.T) {
	for _, tc := range []struct {
		args string
		want bool
	}{
		{"--root=/run/x --enable-core-tags=true create --bundle /b id", true},
		{"--enable-core-tags create id", true},
		{"-enable-core-tags create id", true},

		// Note that this is illegal in Go flag parsing, so actually the
		// `runsc create` command would refuse to run with this, so it's
		// OK that we incorrectly identify it as `true` here.
		{"--enable-core-tags false create id", true},
		{"-enable-core-tags false create id", true},

		{"--root=/run/x create --bundle /b id", false},
		{"--enable-core-tags=false create id", false},
		{"--enable-core-tags=true start id", false},
		{"--enable-core-tags=true boot --bundle /b id", false},
	} {
		if got := isCoreTagsCreate(strings.Fields(tc.args)); got != tc.want {
			t.Errorf("isCoreTagsCreate(%q) = %t, want %t", tc.args, got, tc.want)
		}
	}
}
