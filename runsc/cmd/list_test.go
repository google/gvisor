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

package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/container"
)

func TestList(t *testing.T) {
	dir, err := os.MkdirTemp(testutil.TmpDir(), "list")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	for _, tc := range []struct {
		name string
		list List
		ids  []container.FullID
		want []string
	}{
		{
			name: "single",
			list: List{quiet: true},
			ids: []container.FullID{
				{SandboxID: "abc", ContainerID: "123"},
			},
			want: []string{"123"},
		},
		{
			name: "multiple",
			list: List{quiet: true},
			ids: []container.FullID{
				{SandboxID: "abc", ContainerID: "123"},
				{SandboxID: "def", ContainerID: "123"},
			},
			want: []string{"123", "123"},
		},
		{
			name: "multicontainer",
			list: List{quiet: true},
			ids: []container.FullID{
				{SandboxID: "abc", ContainerID: "123"},
				{SandboxID: "abc", ContainerID: "456"},
			},
			want: []string{"123", "456"},
		},
		{
			name: "multiple-multicontainer",
			list: List{quiet: true},
			ids: []container.FullID{
				{SandboxID: "abc", ContainerID: "123"},
				{SandboxID: "abc", ContainerID: "456"},
				{SandboxID: "def", ContainerID: "123"},
				{SandboxID: "def", ContainerID: "789"},
				{SandboxID: "ghi", ContainerID: "012"},
			},
			want: []string{"123", "456", "123", "789", "012"},
		},
		{
			name: "sandbox-single",
			list: List{quiet: true, sandbox: true},
			ids: []container.FullID{
				{SandboxID: "abc", ContainerID: "123"},
			},
			want: []string{"abc"},
		},
		{
			name: "sandbox-multiple",
			list: List{quiet: true, sandbox: true},
			ids: []container.FullID{
				{SandboxID: "abc", ContainerID: "123"},
				{SandboxID: "def", ContainerID: "123"},
			},
			want: []string{"abc", "def"},
		},
		{
			name: "sandbox-multicontainer",
			list: List{quiet: true, sandbox: true},
			ids: []container.FullID{
				{SandboxID: "abc", ContainerID: "123"},
				{SandboxID: "abc", ContainerID: "456"},
			},
			want: []string{"abc"},
		},
		{
			name: "sandbox-multiple-multicontainer",
			list: List{quiet: true, sandbox: true},
			ids: []container.FullID{
				{SandboxID: "abc", ContainerID: "123"},
				{SandboxID: "abc", ContainerID: "456"},
				{SandboxID: "def", ContainerID: "123"},
				{SandboxID: "def", ContainerID: "789"},
				{SandboxID: "ghi", ContainerID: "012"},
			},
			want: []string{"abc", "def", "ghi"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, id := range tc.ids {
				saver := container.StateFile{RootDir: dir, ID: id}
				if err := saver.LockForNew(); err != nil {
					t.Fatal(err)
				}
				defer saver.Destroy()
				defer saver.UnlockOrDie()

				if err := saver.SaveLocked(nil); err != nil {
					t.Fatal(err)
				}
			}

			out := &bytes.Buffer{}
			if err := tc.list.execute(dir, out); err != nil {
				t.Fatal(err)
			}

			// Handle IDs returned out of order.
			got := make(map[string]struct{})
			for _, id := range strings.Split(out.String(), "\n") {
				got[id] = struct{}{}
			}
			for _, want := range tc.want {
				if _, ok := got[want]; !ok {
					t.Errorf("container ID not found in result want: %q, got: %q", want, out)
				}
			}
		})
	}
}
