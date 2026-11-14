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
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/specutils"
)

func TestDestroySelfFilestore(t *testing.T) {
	for _, mount := range []string{"rootfs", "bind"} {
		for _, state := range []string{"present", "missing_file", "nonempty_directory"} {
			t.Run(mount+"/"+state, func(t *testing.T) {
				mountDir := t.TempDir()
				c := &Container{
					ID:         "container",
					Spec:       &specs.Spec{Root: &specs.Root{Path: mountDir}},
					Status:     Stopped,
					Saver:      StateFile{RootDir: t.TempDir(), ID: FullID{SandboxID: "sandbox", ContainerID: "container"}},
					allowWrite: true,
					GoferMountConfs: specutils.GoferMountConfFlags{
						{Lower: specutils.Lisafs, Upper: specutils.SelfOverlay},
					},
				}
				if mount == "bind" {
					c.Spec.Root.Path = t.TempDir()
					c.Spec.Mounts = []specs.Mount{{Type: "bind", Source: mountDir, Destination: "/mnt"}}
					c.GoferMountConfs[0].Upper = specutils.NoOverlay
					c.GoferMountConfs = append(c.GoferMountConfs, specutils.GoferMountConf{Lower: specutils.Lisafs, Upper: specutils.SelfOverlay})
				}
				filestore := sentryapi.SelfFilestorePath(mountDir, c.sandboxID())
				switch state {
				case "present":
					if err := os.WriteFile(filestore, nil, 0600); err != nil {
						t.Fatal(err)
					}
				case "nonempty_directory":
					// A nonempty directory makes removal fail even when run as root.
					if err := os.Mkdir(filestore, 0755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(filestore, "child"), nil, 0600); err != nil {
						t.Fatal(err)
					}
				}

				err := c.Destroy()
				if state == "nonempty_directory" {
					if err == nil || !strings.Contains(err.Error(), "failed to delete filestore file") {
						t.Fatalf("Destroy() = %v, want filestore removal error", err)
					}
				} else {
					if err != nil {
						t.Fatalf("Destroy() failed: %v", err)
					}
					if _, err := os.Stat(filestore); !os.IsNotExist(err) {
						t.Errorf("Stat(%q) = %v, want not exist", filestore, err)
					}
				}
			})
		}
	}
}
