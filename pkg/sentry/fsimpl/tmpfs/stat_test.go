// Copyright 2020 The gVisor Authors.
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

package tmpfs

import (
	"fmt"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func TestStatAfterCreate(t *testing.T) {
	ctx := contexttest.Context(t)
	mode := linux.FileMode(0644)

	// Run with different file types.
	for _, typ := range []string{"file", "dir", "pipe"} {
		t.Run(fmt.Sprintf("type=%q", typ), func(t *testing.T) {
			var (
				fd      *vfs.FileDescription
				cleanup func()
				err     error
			)
			switch typ {
			case "file":
				fd, cleanup, err = newFileFD(ctx, mode)
			case "dir":
				fd, cleanup, err = newDirFD(ctx, mode)
			case "pipe":
				fd, cleanup, err = newPipeFD(ctx, mode)
			default:
				panic(fmt.Sprintf("unknown typ %q", typ))
			}
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()

			got, err := fd.Stat(ctx, vfs.StatOptions{})
			if err != nil {
				t.Fatalf("Stat failed: %v", err)
			}

			// Atime, Ctime, Mtime should all be current time (non-zero).
			atime, ctime, mtime := got.Atime.ToNsec(), got.Ctime.ToNsec(), got.Mtime.ToNsec()
			if atime != ctime || ctime != mtime {
				t.Errorf("got atime=%d ctime=%d mtime=%d, wanted equal values", atime, ctime, mtime)
			}
			if atime == 0 {
				t.Errorf("got atime=%d, want non-zero", atime)
			}

			// Btime should be 0, as it is not set by tmpfs.
			if btime := got.Btime.ToNsec(); btime != 0 {
				t.Errorf("got btime %d, want 0", got.Btime.ToNsec())
			}

			// Size should be 0 (except for directories, which make up a size
			// of 20 per entry, including the "." and ".." entries present in
			// otherwise-empty directories).
			wantSize := uint64(0)
			if typ == "dir" {
				wantSize = 40
			}
			if got.Size != wantSize {
				t.Errorf("got size %d, want %d", got.Size, wantSize)
			}

			// Nlink should be 1 for files, 2 for dirs.
			wantNlink := uint32(1)
			if typ == "dir" {
				wantNlink = 2
			}
			if got.Nlink != wantNlink {
				t.Errorf("got nlink %d, want %d", got.Nlink, wantNlink)
			}

			// UID and GID are set from context creds.
			creds := auth.CredentialsFromContext(ctx)
			if got.UID != uint32(creds.EffectiveKUID) {
				t.Errorf("got uid %d, want %d", got.UID, uint32(creds.EffectiveKUID))
			}
			if got.GID != uint32(creds.EffectiveKGID) {
				t.Errorf("got gid %d, want %d", got.GID, uint32(creds.EffectiveKGID))
			}

			// Mode.
			wantMode := uint16(mode)
			switch typ {
			case "file":
				wantMode |= linux.S_IFREG
			case "dir":
				wantMode |= linux.S_IFDIR
			case "pipe":
				wantMode |= linux.S_IFIFO
			default:
				panic(fmt.Sprintf("unknown typ %q", typ))
			}

			if got.Mode != wantMode {
				t.Errorf("got mode %x, want %x", got.Mode, wantMode)
			}

			// Ino.
			if got.Ino == 0 {
				t.Errorf("got ino %d, want not 0", got.Ino)
			}
		})
	}
}

func TestSetStatAtime(t *testing.T) {
	ctx := contexttest.Context(t)
	fd, cleanup, err := newFileFD(ctx, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	allStatOptions := vfs.StatOptions{Mask: linux.STATX_ALL}

	// Get initial stat.
	initialStat, err := fd.Stat(ctx, allStatOptions)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}

	// Set atime, but without the mask.
	if err := fd.SetStat(ctx, vfs.SetStatOptions{Stat: linux.Statx{
		Mask:  0,
		Atime: linux.NsecToStatxTimestamp(100),
	}}); err != nil {
		t.Errorf("SetStat atime without mask failed: %v", err)
	}
	// Atime should be unchanged.
	if gotStat, err := fd.Stat(ctx, allStatOptions); err != nil {
		t.Errorf("Stat got error: %v", err)
	} else if gotStat.Atime != initialStat.Atime {
		t.Errorf("Stat got atime %d, want %d", gotStat.Atime, initialStat.Atime)
	}

	// Set atime, this time included in the mask.
	setStat := linux.Statx{
		Mask:  linux.STATX_ATIME,
		Atime: linux.NsecToStatxTimestamp(100),
	}
	if err := fd.SetStat(ctx, vfs.SetStatOptions{Stat: setStat}); err != nil {
		t.Errorf("SetStat atime with mask failed: %v", err)
	}
	if gotStat, err := fd.Stat(ctx, allStatOptions); err != nil {
		t.Errorf("Stat got error: %v", err)
	} else if gotStat.Atime != setStat.Atime {
		t.Errorf("Stat got atime %d, want %d", gotStat.Atime, setStat.Atime)
	}
}

func TestSetStat(t *testing.T) {
	ctx := contexttest.Context(t)
	mode := linux.FileMode(0644)

	// Run with different file types.
	for _, typ := range []string{"file", "dir", "pipe"} {
		t.Run(fmt.Sprintf("type=%q", typ), func(t *testing.T) {
			var (
				fd      *vfs.FileDescription
				cleanup func()
				err     error
			)
			switch typ {
			case "file":
				fd, cleanup, err = newFileFD(ctx, mode)
			case "dir":
				fd, cleanup, err = newDirFD(ctx, mode)
			case "pipe":
				fd, cleanup, err = newPipeFD(ctx, mode)
			default:
				panic(fmt.Sprintf("unknown typ %q", typ))
			}
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()

			allStatOptions := vfs.StatOptions{Mask: linux.STATX_ALL}

			// Get initial stat.
			initialStat, err := fd.Stat(ctx, allStatOptions)
			if err != nil {
				t.Fatalf("Stat failed: %v", err)
			}

			// Set atime, but without the mask.
			if err := fd.SetStat(ctx, vfs.SetStatOptions{Stat: linux.Statx{
				Mask:  0,
				Atime: linux.NsecToStatxTimestamp(100),
			}}); err != nil {
				t.Errorf("SetStat atime without mask failed: %v", err)
			}
			// Atime should be unchanged.
			if gotStat, err := fd.Stat(ctx, allStatOptions); err != nil {
				t.Errorf("Stat got error: %v", err)
			} else if gotStat.Atime != initialStat.Atime {
				t.Errorf("Stat got atime %d, want %d", gotStat.Atime, initialStat.Atime)
			}

			// Set atime, this time included in the mask.
			setStat := linux.Statx{
				Mask:  linux.STATX_ATIME,
				Atime: linux.NsecToStatxTimestamp(100),
			}
			if err := fd.SetStat(ctx, vfs.SetStatOptions{Stat: setStat}); err != nil {
				t.Errorf("SetStat atime with mask failed: %v", err)
			}
			if gotStat, err := fd.Stat(ctx, allStatOptions); err != nil {
				t.Errorf("Stat got error: %v", err)
			} else if gotStat.Atime != setStat.Atime {
				t.Errorf("Stat got atime %d, want %d", gotStat.Atime, setStat.Atime)
			}
		})
	}
}
