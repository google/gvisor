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

package forwardcmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/subcommands"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/state/statefile"
	"gvisor.dev/gvisor/runsc/flag"
)

func TestCheckStickyDirOwnership(t *testing.T) {
	stickyWorld := &unix.Stat_t{Mode: unix.S_IFDIR | unix.S_ISVTX | 0777, Uid: 0}
	stickyNotWorld := &unix.Stat_t{Mode: unix.S_IFDIR | unix.S_ISVTX | 0775, Uid: 0}
	nonStickyWorld := &unix.Stat_t{Mode: unix.S_IFDIR | 0777, Uid: 0}

	if err := checkStickyDirOwnership(stickyWorld, 1000, 0); !errors.Is(err, unix.EACCES) {
		t.Errorf("root following uid=1000 entry in root-owned 1777 dir: got %v, want EACCES", err)
	}
	if err := checkStickyDirOwnership(stickyWorld, 1000, 2000); !errors.Is(err, unix.EACCES) {
		t.Errorf("uid=2000 following uid=1000 entry in root-owned 1777 dir: got %v, want EACCES", err)
	}
	if err := checkStickyDirOwnership(stickyWorld, 1000, 1000); err != nil {
		t.Errorf("owner following own entry in 1777 dir: got %v, want nil", err)
	}
	if err := checkStickyDirOwnership(stickyWorld, 0, 1000); err != nil {
		t.Errorf("following dir-owner entry in 1777 dir: got %v, want nil", err)
	}
	if err := checkStickyDirOwnership(stickyNotWorld, 1000, 0); err != nil {
		t.Errorf("following entry in non-world-writable sticky dir: got %v, want nil", err)
	}
	if err := checkStickyDirOwnership(nonStickyWorld, 1000, 0); err != nil {
		t.Errorf("following entry in non-sticky dir: got %v, want nil", err)
	}
}

func TestSplitParentAndBase(t *testing.T) {
	for _, tc := range []struct {
		in            string
		wantParent    string
		wantBase      string
		wantHasParent bool
		wantTrailing  bool
	}{
		{in: "file.txt", wantParent: "", wantBase: "file.txt", wantHasParent: false, wantTrailing: false},
		{in: "/file.txt", wantParent: "/", wantBase: "file.txt", wantHasParent: true, wantTrailing: false},
		{in: "link/../checkpoint", wantParent: "link/..", wantBase: "checkpoint", wantHasParent: true, wantTrailing: false},
		{in: "../checkpoint", wantParent: "..", wantBase: "checkpoint", wantHasParent: true, wantTrailing: false},
		{in: "dir/", wantParent: "", wantBase: "", wantHasParent: false, wantTrailing: true},
		{in: "/", wantParent: "", wantBase: "", wantHasParent: false, wantTrailing: true},
	} {
		parent, base, hasParent, trailing := splitParentAndBase(tc.in)
		if parent != tc.wantParent || base != tc.wantBase || hasParent != tc.wantHasParent || trailing != tc.wantTrailing {
			t.Errorf("splitParentAndBase(%q) = (%q, %q, %v, %v), want (%q, %q, %v, %v)",
				tc.in, parent, base, hasParent, trailing,
				tc.wantParent, tc.wantBase, tc.wantHasParent, tc.wantTrailing)
		}
	}
}

func TestWriteOutputFileSymlinkDotDotTraversal(t *testing.T) {
	root := t.TempDir()
	workDir := filepath.Join(root, "work")
	otherChild := filepath.Join(root, "other", "child")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		t.Fatalf("MkdirAll(workDir): %v", err)
	}
	if err := os.MkdirAll(otherChild, 0755); err != nil {
		t.Fatalf("MkdirAll(otherChild): %v", err)
	}
	// work/link -> ../other/child, so work/link/../checkpoint resolves in the
	// kernel to root/other/checkpoint, NOT work/checkpoint.
	if err := os.Symlink(filepath.Join("..", "other", "child"), filepath.Join(workDir, "link")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	inputPath := filepath.Join(workDir, "checkpoint")
	wantInput := []byte("original-input-checkpoint")
	if err := os.WriteFile(inputPath, wantInput, 0644); err != nil {
		t.Fatalf("WriteFile(input): %v", err)
	}
	inFile, err := os.Open(inputPath)
	if err != nil {
		t.Fatalf("Open(input): %v", err)
	}
	defer inFile.Close()
	var inStat unix.Stat_t
	if err := unix.Fstat(int(inFile.Fd()), &inStat); err != nil {
		t.Fatalf("Fstat(input): %v", err)
	}

	outExpr := filepath.Join(workDir, "link") + "/../checkpoint"
	if err := writeOutputFile(outExpr, &inStat, func(f *os.File) error {
		_, werr := f.WriteString("decoded-output\n")
		return werr
	}); err != nil {
		t.Fatalf("writeOutputFile(%q) failed: %v", outExpr, err)
	}

	gotInput, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatalf("ReadFile(input): %v", err)
	}
	if string(gotInput) != string(wantInput) {
		t.Errorf("input file %s was clobbered: got %q, want %q", inputPath, gotInput, wantInput)
	}

	resolvedOut := filepath.Join(root, "other", "checkpoint")
	gotOut, err := os.ReadFile(resolvedOut)
	if err != nil {
		t.Fatalf("ReadFile(resolvedOut): %v", err)
	}
	if string(gotOut) != "decoded-output\n" {
		t.Errorf("resolved output %s = %q, want %q", resolvedOut, gotOut, "decoded-output\n")
	}
}

func TestStatefileExecuteDirectoryWithoutReadPerm(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses DAC directory read permission check")
	}

	root := t.TempDir()
	imgPath := filepath.Join(root, "meta.img")
	f, err := os.Create(imgPath)
	if err != nil {
		t.Fatalf("Create(imgPath): %v", err)
	}
	w, err := statefile.NewWriter(f, nil, map[string]string{"k": "v"})
	if err != nil {
		f.Close()
		t.Fatalf("NewWriter: %v", err)
	}
	if _, err := w.Write([]byte("unused")); err != nil {
		w.Close()
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	runStatefile := func(args ...string) subcommands.ExitStatus {
		var cmd Statefile
		fs := flag.NewFlagSet("statefile", flag.ContinueOnError)
		cmd.SetFlags(fs)
		if err := fs.Parse(args); err != nil {
			t.Fatalf("fs.Parse(%v): %v", args, err)
		}
		return cmd.Execute(context.Background(), fs)
	}

	wxDir := filepath.Join(root, "wx_only")
	if err := os.Mkdir(wxDir, 0700); err != nil {
		t.Fatalf("Mkdir(wxDir): %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(wxDir, 0700) })
	if err := os.Chmod(wxDir, 0300); err != nil {
		t.Fatalf("Chmod(wxDir, 0300): %v", err)
	}

	wxOut := filepath.Join(wxDir, "out.txt")
	if status := runStatefile("-get=k", "-output="+wxOut, imgPath); status != subcommands.ExitSuccess {
		t.Errorf("Statefile.Execute in 0300 dir = %v, want ExitSuccess", status)
	} else if got, err := os.ReadFile(wxOut); err != nil {
		t.Fatalf("ReadFile(%s): %v", wxOut, err)
	} else if string(got) != "v\n" {
		t.Errorf("ReadFile(%s) = %q, want %q", wxOut, got, "v\n")
	}

	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(wxDir); err != nil {
		t.Fatalf("Chdir(wxDir): %v", err)
	}
	defer func() { _ = os.Chdir(origWD) }()
	if status := runStatefile("-get=k", "-output=cwd_out.txt", imgPath); status != subcommands.ExitSuccess {
		t.Errorf("Statefile.Execute in 0300 cwd = %v, want ExitSuccess", status)
	} else if got, err := os.ReadFile(filepath.Join(wxDir, "cwd_out.txt")); err != nil {
		t.Fatalf("ReadFile(cwd_out.txt): %v", err)
	} else if string(got) != "v\n" {
		t.Errorf("ReadFile(cwd_out.txt) = %q, want %q", got, "v\n")
	}
	if err := os.Chdir(origWD); err != nil {
		t.Fatalf("Chdir(origWD): %v", err)
	}

	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0700); err != nil {
		t.Fatalf("Mkdir(realDir): %v", err)
	}
	xDir := filepath.Join(root, "x_only")
	if err := os.Mkdir(xDir, 0700); err != nil {
		t.Fatalf("Mkdir(xDir): %v", err)
	}
	linkPath := filepath.Join(xDir, "outlink")
	targetPath := filepath.Join(realDir, "linked.txt")
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(xDir, 0700) })
	if err := os.Chmod(xDir, 0100); err != nil {
		t.Fatalf("Chmod(xDir, 0100): %v", err)
	}

	if status := runStatefile("-get=k", "-output="+linkPath, imgPath); status != subcommands.ExitSuccess {
		t.Errorf("Statefile.Execute through 0100 dir symlink = %v, want ExitSuccess", status)
	} else if got, err := os.ReadFile(targetPath); err != nil {
		t.Fatalf("ReadFile(%s): %v", targetPath, err)
	} else if string(got) != "v\n" {
		t.Errorf("ReadFile(%s) = %q, want %q", targetPath, got, "v\n")
	}
}
