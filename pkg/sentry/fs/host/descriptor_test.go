// Copyright 2018 The gVisor Authors.
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

package host

import (
	"io/ioutil"
	"path/filepath"
	"syscall"
	"testing"

	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestDescriptorRelease(t *testing.T) {
	for _, tc := range []struct {
		name       string
		saveable   bool
		wouldBlock bool
	}{
		{name: "all false"},
		{name: "saveable", saveable: true},
		{name: "wouldBlock", wouldBlock: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := ioutil.TempDir("", "descriptor_test")
			if err != nil {
				t.Fatal("ioutil.TempDir() failed:", err)
			}

			fd, err := syscall.Open(filepath.Join(dir, "file"), syscall.O_RDWR|syscall.O_CREAT, 0666)
			if err != nil {
				t.Fatal("failed to open temp file:", err)
			}

			// FD ownership is transferred to the descritor.
			queue := &waiter.Queue{}
			d, err := newDescriptor(fd, false /* donated*/, tc.saveable, tc.wouldBlock, queue)
			if err != nil {
				syscall.Close(fd)
				t.Fatalf("newDescriptor(%d, %t, false, %t, queue) failed, err: %v", fd, tc.saveable, tc.wouldBlock, err)
			}
			if tc.saveable {
				if d.origFD < 0 {
					t.Errorf("saveable descriptor must preserve origFD, desc: %+v", d)
				}
			}
			if tc.wouldBlock {
				if !fdnotifier.HasFD(int32(d.value)) {
					t.Errorf("FD not registered with notifier, desc: %+v", d)
				}
			}

			oldVal := d.value
			d.Release()
			if d.value != -1 {
				t.Errorf("d.value want: -1, got: %d", d.value)
			}
			if tc.wouldBlock {
				if fdnotifier.HasFD(int32(oldVal)) {
					t.Errorf("FD not unregistered with notifier, desc: %+v", d)
				}
			}
		})
	}
}
