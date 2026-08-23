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

package host

import (
	"sync"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func TestVirtualOwnerConcurrentStat(t *testing.T) {
	ctx := auth.ContextWithCredentials(
		context.Background(),
		auth.NewRootCredentials(auth.NewRootUserNamespace()),
	)
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatal(err)
	}
	defer vfsObj.Release(ctx)
	fs, err := NewFilesystem(vfsObj)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.DecRef(ctx)
	mnt := vfsObj.NewDisconnectedMount(fs, nil, &vfs.MountOptions{})
	defer mnt.DecRef(ctx)

	rawFD, err := memutil.CreateMemFD("virtual-owner-test", 0)
	if err != nil {
		t.Fatal(err)
	}
	hostFD := fd.New(rawFD)
	defer hostFD.Close()
	file, err := NewFD(ctx, mnt, hostFD.FD(), &NewFDOptions{
		VirtualOwner: true,
		UID:          100,
		GID:          200,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = hostFD.Release()
	defer file.DecRef(ctx)

	statOpts := vfs.StatOptions{Mask: linux.STATX_TYPE | virtualOwnerModes}
	initial, err := file.Stat(ctx, statOpts)
	if err != nil {
		t.Fatal(err)
	}
	if initial.UID != 100 || initial.GID != 200 ||
		initial.Mode&linux.S_IFMT != linux.S_IFREG {
		t.Fatalf("initial metadata = %+v, want UID 100, GID 200, regular file", initial)
	}

	want := linux.Statx{
		Mask: virtualOwnerModes,
		Mode: 0o640,
		UID:  1001,
		GID:  1002,
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		<-start
		if err := file.SetStat(ctx, vfs.SetStatOptions{Stat: want}); err != nil {
			t.Errorf("SetStat: %v", err)
		}
	})
	wg.Go(func() {
		<-start
		if _, err := file.Stat(ctx, statOpts); err != nil {
			t.Errorf("Stat: %v", err)
		}
	})
	close(start)
	wg.Wait()

	got, err := file.Stat(ctx, statOpts)
	if err != nil {
		t.Fatal(err)
	}
	if wantMode := uint16(linux.S_IFREG) | want.Mode; got.Mode != wantMode {
		t.Errorf("mode = %#o, want %#o", got.Mode, wantMode)
	}
	if got.UID != want.UID {
		t.Errorf("UID = %d, want %d", got.UID, want.UID)
	}
	if got.GID != want.GID {
		t.Errorf("GID = %d, want %d", got.GID, want.GID)
	}
}
