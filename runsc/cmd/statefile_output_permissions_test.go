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

package cmd

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/specutils"
)

func TestStatefileOutputPermissions(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatal(err)
	}
	imgDir := t.TempDir()
	img := filepath.Join(imgDir, "meta.img")
	writeSyntheticStatefile(t, img, map[string]string{"k": "v"}, []byte("unused"))

	t.Run("readonly_existing_file_rejected_when_unprivileged", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses 0444 DAC write permission check")
		}
		dir := t.TempDir()
		roFile := filepath.Join(dir, "readonly.txt")
		want := []byte("immutable-to-owner")
		if err := os.WriteFile(roFile, want, 0444); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if out, err := exec.Command(specutils.ExePath, "statefile", "-get=k", "-output="+roFile, img).CombinedOutput(); err == nil {
			t.Fatalf("statefile -output=<0444 file> unexpectedly succeeded:\n%s", out)
		}
		got, err := os.ReadFile(roFile)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("readonly file modified: got %q, want %q", got, want)
		}
	})

	t.Run("dirs_without_read_perm_succeed_when_unprivileged", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses DAC directory read permission check")
		}
		root := t.TempDir()

		wxDir := filepath.Join(root, "wx_only")
		if err := os.Mkdir(wxDir, 0700); err != nil {
			t.Fatalf("Mkdir(wxDir): %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(wxDir, 0700) })
		if err := os.Chmod(wxDir, 0300); err != nil {
			t.Fatalf("Chmod(wxDir, 0300): %v", err)
		}

		wxOut := filepath.Join(wxDir, "out.txt")
		if out, err := exec.Command(specutils.ExePath, "statefile", "-get=k", "-output="+wxOut, img).CombinedOutput(); err != nil {
			t.Fatalf("statefile -output in 0300 dir failed: %v\n%s", err, out)
		}
		if got, err := os.ReadFile(wxOut); err != nil {
			t.Fatalf("ReadFile(%s): %v", wxOut, err)
		} else if string(got) != "v\n" {
			t.Errorf("ReadFile(%s) = %q, want %q", wxOut, got, "v\n")
		}

		cwdCmd := exec.Command(specutils.ExePath, "statefile", "-get=k", "-output=cwd_out.txt", img)
		cwdCmd.Dir = wxDir
		if out, err := cwdCmd.CombinedOutput(); err != nil {
			t.Fatalf("statefile relative -output in 0300 cwd failed: %v\n%s", err, out)
		}
		cwdOut := filepath.Join(wxDir, "cwd_out.txt")
		if got, err := os.ReadFile(cwdOut); err != nil {
			t.Fatalf("ReadFile(%s): %v", cwdOut, err)
		} else if string(got) != "v\n" {
			t.Errorf("ReadFile(%s) = %q, want %q", cwdOut, got, "v\n")
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

		if out, err := exec.Command(specutils.ExePath, "statefile", "-get=k", "-output="+linkPath, img).CombinedOutput(); err != nil {
			t.Fatalf("statefile -output through 0100 dir symlink failed: %v\n%s", err, out)
		}
		if got, err := os.ReadFile(targetPath); err != nil {
			t.Fatalf("ReadFile(%s): %v", targetPath, err)
		} else if string(got) != "v\n" {
			t.Errorf("ReadFile(%s) = %q, want %q", targetPath, got, "v\n")
		}
	})
}
