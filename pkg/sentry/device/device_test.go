// Copyright 2018 Google LLC
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

package device

import (
	"testing"
)

func TestMultiDevice(t *testing.T) {
	device := &MultiDevice{}

	// Check that Load fails to install virtual inodes that are
	// uninitialized.
	if device.Load(MultiDeviceKey{}, 0) {
		t.Fatalf("got load of invalid virtual inode 0, want unsuccessful")
	}

	inode := device.Map(MultiDeviceKey{})

	// Assert that the same raw device and inode map to
	// a consistent virtual inode.
	if i := device.Map(MultiDeviceKey{}); i != inode {
		t.Fatalf("got inode %d, want %d in %s", i, inode, device)
	}

	// Assert that a new inode or new device does not conflict.
	if i := device.Map(MultiDeviceKey{Device: 0, Inode: 1}); i == inode {
		t.Fatalf("got reused inode %d, want new distinct inode in %s", i, device)
	}
	last := device.Map(MultiDeviceKey{Device: 1, Inode: 0})
	if last == inode {
		t.Fatalf("got reused inode %d, want new distinct inode in %s", last, device)
	}

	// Virtual is the virtual inode we want to load.
	virtual := last + 1

	// Assert that we can load a virtual inode at a new place.
	if !device.Load(MultiDeviceKey{Device: 0, Inode: 2}, virtual) {
		t.Fatalf("got load of virtual inode %d failed, want success in %s", virtual, device)
	}

	// Assert that the next inode skips over the loaded one.
	if i := device.Map(MultiDeviceKey{Device: 0, Inode: 3}); i != virtual+1 {
		t.Fatalf("got inode %d, want %d in %s", i, virtual+1, device)
	}
}
