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

package container

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/runsc/config"
)

func TestFilestoreArtifactAdoption(t *testing.T) {
	for _, tc := range []struct {
		name        string
		saved       string
		artifact    string
		fingerprint string
		legacy      bool
		wantErr     string
	}{
		{name: "empty"},
		{name: "nonempty", saved: "contents", artifact: "contents"},
		{name: "truncated", saved: "contents", wantErr: "size"},
		{name: "unexpected_contents", artifact: "contents", wantErr: "size"},
		{name: "diverged", saved: "original", artifact: "modified", wantErr: "fingerprint mismatch"},
		{name: "short_fingerprint", saved: "contents", artifact: "contents", fingerprint: "x", wantErr: "fingerprint mismatch"},
		{name: "legacy_empty", legacy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			artifactPath := filepath.Join(dir, "filestore-0")
			if err := os.WriteFile(artifactPath, []byte(tc.saved), 0600); err != nil {
				t.Fatal(err)
			}
			c := &Container{Spec: &specs.Spec{}}
			if !tc.legacy {
				f, err := os.Open(artifactPath)
				if err != nil {
					t.Fatal(err)
				}
				fp, err := checkpoint.FingerprintFile(f)
				f.Close()
				if err != nil {
					t.Fatal(err)
				}
				if tc.fingerprint != "" {
					fp = tc.fingerprint
				}
				rid := c.filestoreResourceID("/")
				sidecar, err := os.Create(filepath.Join(dir, filestoresSidecarName))
				if err != nil {
					t.Fatal(err)
				}
				err = checkpoint.WriteFilestoreSidecar(sidecar, []checkpoint.FilestoreSidecarEntry{{
					File:              "filestore-0",
					ResourceContainer: rid.ContainerName,
					ResourcePath:      rid.Path,
					SizeBytes:         uint64(len(tc.saved)),
					Fingerprint:       fp,
				}})
				sidecar.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(artifactPath, []byte(tc.artifact), 0600); err != nil {
				t.Fatal(err)
			}
			// Consuming adoption exercises validation on filesystems without
			// reflink support. Clone-on-adopt uses the same validation.
			a, err := newFilestoreAdopter(&config.Config{FilestoreAdoptDir: dir, FilestoreAdoptMode: config.FilestoreAdoptConsume}, c)
			if err != nil {
				t.Fatal(err)
			}
			f, err := a.adopt(c, "/")
			if f != nil {
				defer f.Close()
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("adopt: got %v, want error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("adopt: %v", err)
			}
			info, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Size(); got != int64(len(tc.artifact)) {
				t.Errorf("adopted file size = %d, want %d", got, len(tc.artifact))
			}
		})
	}
}

func TestFilestoreArtifactRejectsSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("unrelated file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "filestore-0")); err != nil {
		t.Fatal(err)
	}
	c := &Container{Spec: &specs.Spec{}}
	a, err := newFilestoreAdopter(&config.Config{FilestoreAdoptDir: dir, FilestoreAdoptMode: config.FilestoreAdoptConsume}, c)
	if err != nil {
		t.Fatal(err)
	}
	if file, err := a.adopt(c, "/"); err == nil {
		file.Close()
		t.Fatal("adoption followed a symlink")
	}
}

func TestFilestoreArtifactRejectsPathTraversal(t *testing.T) {
	for _, name := range []string{"", ".", "..", "../outside", "/absolute", "subdir/file"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			sidecar, err := os.Create(filepath.Join(dir, filestoresSidecarName))
			if err != nil {
				t.Fatal(err)
			}
			if err := checkpoint.WriteFilestoreSidecar(sidecar, []checkpoint.FilestoreSidecarEntry{{File: name}}); err != nil {
				t.Fatal(err)
			}
			sidecar.Close()
			if _, err := newFilestoreAdopter(&config.Config{FilestoreAdoptDir: dir}, &Container{}); err == nil {
				t.Fatal("accepted an artifact path outside the snapshot directory")
			}
		})
	}
}
