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
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/state/statefile"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/specutils"
)

func writeSyntheticStatefile(t *testing.T, path string, metadata map[string]string, payload []byte) []byte {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("os.Create(%s): %v", path, err)
	}
	w, err := statefile.NewWriter(f, nil, metadata)
	if err != nil {
		f.Close()
		t.Fatalf("statefile.NewWriter: %v", err)
	}
	if _, err := w.Write(payload); err != nil {
		w.Close()
		t.Fatalf("statefile write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("statefile close: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%s): %v", path, err)
	}
	return raw
}

func TestStatefileEdgeCases(t *testing.T) {
	t.Run("missing_input_arg_after_output_preserves_existing_file", func(t *testing.T) {
		dir := t.TempDir()
		victim := filepath.Join(dir, "checkpoint.img")
		want := []byte("do not clobber")
		if err := os.WriteFile(victim, want, 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		// "-output checkpoint.img" consumes checkpoint.img as the output path and
		// leaves zero positional arguments.
		if out, err := exec.Command(specutils.ExePath, "statefile", "-output", victim).CombinedOutput(); err == nil {
			t.Fatalf("statefile with missing positional arg unexpectedly succeeded:\n%s", out)
		}
		got, err := os.ReadFile(victim)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", victim, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("victim file modified: got %q, want %q", got, want)
		}
	})

	t.Run("nonexistent_input_preserves_existing_output", func(t *testing.T) {
		dir := t.TempDir()
		victim := filepath.Join(dir, "existing.txt")
		want := []byte("keep existing output")
		if err := os.WriteFile(victim, want, 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		missing := filepath.Join(dir, "does_not_exist.img")

		for _, args := range [][]string{
			{"statefile", "-list", "-output=" + victim, missing},
			{"statefile", "-output=" + victim, missing},
		} {
			if out, err := exec.Command(specutils.ExePath, args...).CombinedOutput(); err == nil {
				t.Fatalf("statefile %v unexpectedly succeeded:\n%s", args, out)
			}
			got, err := os.ReadFile(victim)
			if err != nil {
				t.Fatalf("ReadFile(%s): %v", victim, err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("after %v: output file modified: got %q, want %q", args, got, want)
			}
		}
	})

	t.Run("same_input_and_output_rejected_without_truncating_input", func(t *testing.T) {
		dir := t.TempDir()
		same := filepath.Join(dir, "checkpoint.img")
		want := writeSyntheticStatefile(t, same, map[string]string{"k": "v"}, []byte("corrupt-or-valid-stream"))

		for _, args := range [][]string{
			{"statefile", "-list", "-output=" + same, same},
			{"statefile", "-output=" + same, same},
		} {
			if out, err := exec.Command(specutils.ExePath, args...).CombinedOutput(); err == nil {
				t.Fatalf("statefile %v unexpectedly succeeded:\n%s", args, out)
			}
			got, err := os.ReadFile(same)
			if err != nil {
				t.Fatalf("ReadFile(%s): %v", same, err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("after %v: statefile clobbered (len=%d, want len=%d)", args, len(got), len(want))
			}
		}
	})

	t.Run("corrupt_input_or_missing_metadata_key_does_not_leave_or_clobber_output", func(t *testing.T) {
		dir := t.TempDir()
		corruptImg := filepath.Join(dir, "corrupt.img")
		// Varint header for (1<<63)|(1<<62)|1 (Object=true, Graph=true, Length=1)
		// followed by an invalid 1-byte graph payload 'x', causing state.PrintGraph
		// to fail after statefile.NewReader succeeds.
		corruptGraphPayload := []byte{0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xc0, 0x01, 'x'}
		writeSyntheticStatefile(t, corruptImg, map[string]string{"present": "1"}, corruptGraphPayload)

		badMagicImg := filepath.Join(dir, "badmagic.img")
		if err := os.WriteFile(badMagicImg, []byte("not-a-statefile"), 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		for _, tc := range []struct {
			name string
			args []string
			out  string
		}{
			{
				name: "html_corrupt_payload",
				out:  filepath.Join(dir, "out.html"),
				args: []string{"statefile", "-html", "-output=" + filepath.Join(dir, "out.html"), corruptImg},
			},
			{
				name: "text_corrupt_payload",
				out:  filepath.Join(dir, "out.txt"),
				args: []string{"statefile", "-output=" + filepath.Join(dir, "out.txt"), corruptImg},
			},
			{
				name: "bad_magic_header",
				out:  filepath.Join(dir, "badmagic.txt"),
				args: []string{"statefile", "-output=" + filepath.Join(dir, "badmagic.txt"), badMagicImg},
			},
			{
				name: "missing_metadata_key",
				out:  filepath.Join(dir, "meta.txt"),
				args: []string{"statefile", "-get=nonexistent_key", "-output=" + filepath.Join(dir, "meta.txt"), corruptImg},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if out, err := exec.Command(specutils.ExePath, tc.args...).CombinedOutput(); err == nil {
					t.Fatalf("statefile %v unexpectedly succeeded:\n%s", tc.args, out)
				}
				if _, err := os.Stat(tc.out); !os.IsNotExist(err) {
					data, _ := os.ReadFile(tc.out)
					t.Errorf("failed command %v left output file %s behind (err=%v, content=%q)", tc.args, tc.out, err, data)
				}
			})
		}

		existingOut := filepath.Join(dir, "existing.html")
		want := []byte("<html><body>previous valid dump</body></html>\n")
		if err := os.WriteFile(existingOut, want, 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if out, err := exec.Command(specutils.ExePath, "statefile", "-html", "-output="+existingOut, corruptImg).CombinedOutput(); err == nil {
			t.Fatalf("statefile -html on corrupt input unexpectedly succeeded:\n%s", out)
		}
		got, err := os.ReadFile(existingOut)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", existingOut, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("failed -html dump clobbered pre-existing output: got %q, want %q", got, want)
		}
	})

	t.Run("metadata_and_flag_validation_do_not_require_sidecar", func(t *testing.T) {
		dir := t.TempDir()
		img := filepath.Join(dir, "meta.img")
		writeSyntheticStatefile(t, img, map[string]string{
			sentryapi.CPUFeaturesKey: "",
			"custom":                 "val",
		}, []byte("unused"))

		emptySidecarDir := t.TempDir()
		withNoSidecars := func(args ...string) ([]byte, error) {
			cmd := exec.Command(specutils.ExePath, args...)
			env := make([]string, 0, len(os.Environ())+1)
			for _, kv := range os.Environ() {
				if !strings.HasPrefix(kv, "GVISOR_SIDECAR_BINARIES_DIR=") {
					env = append(env, kv)
				}
			}
			cmd.Env = append(env, "GVISOR_SIDECAR_BINARIES_DIR="+emptySidecarDir)
			return cmd.CombinedOutput()
		}

		if out, err := withNoSidecars("statefile", "-get", sentryapi.CPUFeaturesKey, "-bitmask", img); err != nil {
			t.Fatalf("statefile -get %s -bitmask failed without sidecars: %v\n%s", sentryapi.CPUFeaturesKey, err, out)
		} else if !strings.Contains(string(out), "0x00000000") {
			t.Errorf("unexpected bitmask output: %q", out)
		}

		out, err := withNoSidecars("statefile", "-bitmask", img)
		if err == nil {
			t.Fatalf("statefile -bitmask without -get unexpectedly succeeded:\n%s", out)
		}
		if !strings.Contains(string(out), "-bitmask requires -get") {
			t.Errorf("statefile -bitmask failed for wrong reason (attempted sidecar exec?): %s", out)
		}
	})
}

func TestStatefileOutputSymlinks(t *testing.T) {
	imgDir := t.TempDir()
	img := filepath.Join(imgDir, "meta.img")
	writeSyntheticStatefile(t, img, map[string]string{"k": "v"}, []byte("unused"))

	t.Run("dangling_symlink_creates_target_and_preserves_symlink", func(t *testing.T) {
		targetDir := t.TempDir()
		linkDir := t.TempDir()
		realOut := filepath.Join(targetDir, "dump.txt")
		linkOut := filepath.Join(linkDir, "dump_link.txt")
		if err := os.Symlink(realOut, linkOut); err != nil {
			t.Fatalf("Symlink: %v", err)
		}

		if out, err := exec.Command(specutils.ExePath, "statefile", "-get=k", "-output="+linkOut, img).CombinedOutput(); err != nil {
			t.Fatalf("statefile -output=<dangling symlink> failed: %v\n%s", err, out)
		}
		linfo, err := os.Lstat(linkOut)
		if err != nil {
			t.Fatalf("Lstat(%s): %v", linkOut, err)
		}
		if linfo.Mode()&os.ModeSymlink == 0 {
			t.Errorf("symlink %s was replaced with mode %v; want symlink preserved", linkOut, linfo.Mode())
		}
		got, err := os.ReadFile(realOut)
		if err != nil {
			t.Errorf("target %s was not created: %v", realOut, err)
		} else if string(got) != "v\n" {
			t.Errorf("target content = %q, want %q", got, "v\n")
		}
	})

	t.Run("symlink_into_nonexistent_dir_fails_and_preserves_symlink", func(t *testing.T) {
		linkDir := t.TempDir()
		brokenLink := filepath.Join(linkDir, "broken_link.txt")
		missingTarget := filepath.Join(t.TempDir(), "no_such_dir", "dump.txt")
		if err := os.Symlink(missingTarget, brokenLink); err != nil {
			t.Fatalf("Symlink: %v", err)
		}

		if out, err := exec.Command(specutils.ExePath, "statefile", "-get=k", "-output="+brokenLink, img).CombinedOutput(); err == nil {
			t.Errorf("statefile -output=<symlink into missing dir> unexpectedly succeeded:\n%s", out)
		}
		linfo, err := os.Lstat(brokenLink)
		if err != nil {
			t.Fatalf("Lstat(%s): %v", brokenLink, err)
		}
		if linfo.Mode()&os.ModeSymlink == 0 {
			t.Errorf("broken symlink %s was replaced with mode %v; want symlink preserved", brokenLink, linfo.Mode())
		}
	})

	t.Run("dev_stdout_with_unlinked_regular_file", func(t *testing.T) {
		unlinked, err := os.CreateTemp(t.TempDir(), "unlinked-*")
		if err != nil {
			t.Fatalf("CreateTemp: %v", err)
		}
		defer unlinked.Close()
		if err := os.Remove(unlinked.Name()); err != nil {
			t.Fatalf("Remove: %v", err)
		}

		var stderr bytes.Buffer
		cmd := exec.Command(specutils.ExePath, "statefile", "-get=k", "-output=/dev/stdout", img)
		cmd.Stdout = unlinked
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("statefile -output=/dev/stdout failed: %v (%s)", err, bytes.TrimSpace(stderr.Bytes()))
		}
		if _, err := unlinked.Seek(0, io.SeekStart); err != nil {
			t.Fatalf("Seek: %v", err)
		}
		got, err := io.ReadAll(unlinked)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		if string(got) != "v\n" {
			t.Errorf("stdout content = %q, want %q", got, "v\n")
		}
	})

	t.Run("proc_fd_symlink_in_writable_dir_not_clobbered", func(t *testing.T) {
		unlinked, err := os.CreateTemp(t.TempDir(), "unlinked-*")
		if err != nil {
			t.Fatalf("CreateTemp: %v", err)
		}
		defer unlinked.Close()
		if err := os.Remove(unlinked.Name()); err != nil {
			t.Fatalf("Remove: %v", err)
		}

		stdoutLink := filepath.Join(t.TempDir(), "stdout")
		if err := os.Symlink("/proc/self/fd/1", stdoutLink); err != nil {
			t.Fatalf("Symlink: %v", err)
		}

		var stderr bytes.Buffer
		cmd := exec.Command(specutils.ExePath, "statefile", "-get=k", "-output="+stdoutLink, img)
		cmd.Stdout = unlinked
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("statefile -output=%s failed: %v (%s)", stdoutLink, err, bytes.TrimSpace(stderr.Bytes()))
		}
		linfo, err := os.Lstat(stdoutLink)
		if err != nil {
			t.Fatalf("Lstat(%s): %v", stdoutLink, err)
		}
		if linfo.Mode()&os.ModeSymlink == 0 {
			t.Errorf("symlink %s was replaced with mode %v; want symlink preserved", stdoutLink, linfo.Mode())
		}
		if _, err := unlinked.Seek(0, io.SeekStart); err != nil {
			t.Fatalf("Seek: %v", err)
		}
		got, err := io.ReadAll(unlinked)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		if string(got) != "v\n" {
			t.Errorf("stdout content = %q, want %q", got, "v\n")
		}
	})
}

func TestStatefileOutputRespectsUmask(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "meta.img")
	writeSyntheticStatefile(t, img, map[string]string{"k": "v"}, []byte("unused"))

	existing := filepath.Join(dir, "existing.txt")
	if err := os.WriteFile(existing, []byte("old"), 0640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(existing, 0640); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	oldMask := unix.Umask(0077)
	t.Cleanup(func() { unix.Umask(oldMask) })

	out := filepath.Join(dir, "out.txt")
	if b, err := exec.Command(specutils.ExePath, "statefile", "-list", "-output="+out, img).CombinedOutput(); err != nil {
		t.Fatalf("statefile -list -output failed: %v\n%s", err, b)
	}
	fi, err := os.Stat(out)
	if err != nil {
		t.Fatalf("Stat(%s): %v", out, err)
	}
	if got, want := fi.Mode().Perm(), os.FileMode(0600); got != want {
		t.Errorf("new output mode with umask 077 = %#o, want %#o", got, want)
	}

	if b, err := exec.Command(specutils.ExePath, "statefile", "-list", "-output="+existing, img).CombinedOutput(); err != nil {
		t.Fatalf("statefile -list -output=<existing> failed: %v\n%s", err, b)
	}
	efi, err := os.Stat(existing)
	if err != nil {
		t.Fatalf("Stat(%s): %v", existing, err)
	}
	if got, want := efi.Mode().Perm(), os.FileMode(0640); got != want {
		t.Errorf("existing output mode = %#o, want preserved %#o", got, want)
	}
}
