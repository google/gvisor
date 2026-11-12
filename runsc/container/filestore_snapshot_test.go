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
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

func TestFilestoreSnapshotMountIdentity(t *testing.T) {
	disk := specutils.GoferMountConf{Upper: specutils.AnonOverlay}
	noDisk := specutils.GoferMountConf{}
	c := &Container{
		Spec: &specs.Spec{Mounts: []specs.Mount{
			{Type: "bind", Source: "/source-a", Destination: "/var/run/a"},
			{Type: "tmpfs", Destination: "/memory"},
			{Type: "bind", Source: "/source", Destination: "/read-only"},
			{Type: "bind", Source: "/source-b", Destination: "/b"},
		}},
		GoferMountConfs: []specutils.GoferMountConf{disk, disk, noDisk, disk},
	}
	saved, err := c.filestoreSnapshotNames()
	if err != nil {
		t.Fatal(err)
	}
	if len(saved) != 3 || saved[0] == saved[1] || saved[0] == saved[2] || saved[1] == saved[2] {
		t.Fatalf("expected three distinct identities, got %v", saved)
	}
	c.Spec.Mounts[0], c.Spec.Mounts[3] = c.Spec.Mounts[3], c.Spec.Mounts[0]
	c.Spec.Mounts[0].Source, c.Spec.Mounts[3].Source = "/relocated-b", "/relocated-a"
	restored, err := c.filestoreSnapshotNames()
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != 3 || restored[0] != saved[0] || restored[1] != saved[2] || restored[2] != saved[1] {
		t.Fatalf("mount identities changed: saved=%v restored=%v", saved, restored)
	}
	c.GoferMountConfs[0] = noDisk
	withoutRoot, err := c.filestoreSnapshotNames()
	if err != nil {
		t.Fatal(err)
	}
	if len(withoutRoot) != 2 || withoutRoot[0] != saved[2] || withoutRoot[1] != saved[1] {
		t.Fatalf("read-only root shifted mount identities: %v", withoutRoot)
	}
}

func TestFilestoreSnapshotInvalidLayout(t *testing.T) {
	disk := specutils.GoferMountConf{Upper: specutils.AnonOverlay}
	for _, tc := range []struct {
		name  string
		spec  *specs.Spec
		confs []specutils.GoferMountConf
	}{
		{name: "missing-spec", confs: []specutils.GoferMountConf{disk}},
		{name: "missing-root", spec: &specs.Spec{}},
		{name: "no-filestores", spec: &specs.Spec{}, confs: []specutils.GoferMountConf{{}}},
		{name: "extra-config", spec: &specs.Spec{}, confs: []specutils.GoferMountConf{disk, disk}},
		{name: "missing-config", spec: &specs.Spec{Mounts: []specs.Mount{{Type: "bind", Source: "/source", Destination: "/a"}}}, confs: []specutils.GoferMountConf{disk}},
		{name: "relative-destination", spec: &specs.Spec{Mounts: []specs.Mount{{Type: "bind", Source: "/source", Destination: "a"}}}, confs: []specutils.GoferMountConf{disk, disk}},
		{name: "duplicate-destination", spec: &specs.Spec{Mounts: []specs.Mount{{Type: "bind", Source: "/source", Destination: "/a"}, {Type: "bind", Source: "/source", Destination: "/a"}}}, confs: []specutils.GoferMountConf{disk, disk, disk}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Container{Spec: tc.spec, GoferMountConfs: tc.confs}
			dir := filepath.Join(t.TempDir(), "snapshots")
			if files, err := c.prepareFilestoreSnapshot(dir); err == nil || len(files) != 0 {
				t.Fatalf("prepare invalid layout: files=%v err=%v", files, err)
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatalf("invalid layout created artifacts: %v", err)
			}
			if _, err := c.newFilestoreAdopter(&config.Config{FilestoreAdoptDir: dir}); err == nil {
				t.Fatal("restore accepted invalid layout")
			}
		})
	}
}

func TestFilestoreSnapshotRejectPositionalArtifact(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "filestore-0")
	if err := os.WriteFile(legacy, []byte("unidentified contents"), 0600); err != nil {
		t.Fatal(err)
	}
	c := &Container{Spec: &specs.Spec{}, GoferMountConfs: []specutils.GoferMountConf{{Upper: specutils.AnonOverlay}}}
	a, err := c.newFilestoreAdopter(&config.Config{FilestoreAdoptDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if f, err := a.clone("/", dir); !os.IsNotExist(err) || f != nil {
		if f != nil {
			f.Close()
		}
		t.Fatalf("expected missing identified artifact, got file=%v err=%v", f, err)
	}
	if data, err := os.ReadFile(legacy); err != nil || string(data) != "unidentified contents" {
		t.Fatalf("input artifact changed: %q, %v", data, err)
	}
}
