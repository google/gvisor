// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runsc

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestResolvConf(t *testing.T) {
	got := resolvConf(&podDNSConfig{
		servers:  []string{"10.96.0.10", "10.96.0.11"},
		searches: []string{"default.svc.cluster.local", "cluster.local"},
		options:  []string{"ndots:5"},
	})
	want := "search default.svc.cluster.local cluster.local\n" +
		"nameserver 10.96.0.10\n" +
		"nameserver 10.96.0.11\n" +
		"options ndots:5\n"
	if got != want {
		t.Errorf("resolvConf = %q, want %q", got, want)
	}
}

func TestWriteSandboxFiles(t *testing.T) {
	bundle := t.TempDir()
	config := &podSandboxConfig{
		hostname: "pod",
		dns:      &podDNSConfig{servers: []string{"10.96.0.10"}},
	}
	if err := writeSandboxFiles(bundle, config); err != nil {
		t.Fatalf("writeSandboxFiles: %v", err)
	}
	for name, want := range map[string]string{
		"hostname":    "pod\n",
		"resolv.conf": "nameserver 10.96.0.10\n",
	} {
		got, err := os.ReadFile(filepath.Join(bundle, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if _, err := os.Stat(filepath.Join(bundle, "hosts")); err != nil {
		t.Errorf("hosts: %v", err)
	}
}

func TestAddSandboxFileMounts(t *testing.T) {
	bundle := t.TempDir()
	for _, name := range []string{"hosts", "resolv.conf"} {
		if err := os.WriteFile(filepath.Join(bundle, name), nil, 0644); err != nil {
			t.Fatal(err)
		}
	}
	own := specs.Mount{Destination: "/etc/hosts", Type: "bind", Source: "/own/hosts"}
	s := &specs.Spec{
		Root:   &specs.Root{Readonly: true},
		Mounts: []specs.Mount{own},
	}

	if !addSandboxFileMounts(s, bundle) {
		t.Errorf("addSandboxFileMounts = false, want true")
	}
	// The container's own /etc/hosts stays. /etc/hostname has no file in the
	// bundle, so it is not mounted.
	want := []specs.Mount{own, {
		Destination: "/etc/resolv.conf",
		Type:        "bind",
		Source:      filepath.Join(bundle, "resolv.conf"),
		Options:     []string{"rbind", "rprivate", "ro"},
	}}
	if diff := cmp.Diff(want, s.Mounts); diff != "" {
		t.Errorf("mounts mismatch (-want +got):\n%s", diff)
	}
	if addSandboxFileMounts(s, bundle) {
		t.Errorf("second addSandboxFileMounts = true, want false")
	}
}
