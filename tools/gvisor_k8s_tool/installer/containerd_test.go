// Copyright The Isola Authors
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

package installer

import (
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// kindStyleConfig mirrors the shape of a kind node's config.toml: an explicit
// version = 2 header, comments, and an existing runc runtime.
const kindStyleConfig = `# explicitly use v2 config format
version = 2

[plugins."io.containerd.grpc.v1.cri"]
  sandbox_image = "registry.k8s.io/pause:3.10"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
  SystemdCgroup = true
`

func TestConfigSchemaVersion(t *testing.T) {
	tests := []struct {
		name string
		data string
		want int
	}{
		{"kind style v2", kindStyleConfig, 2},
		{"v3", "version = 3\n[plugins]\n", 3},
		{"no version", "[plugins]\n", 0},
		{"empty", "", 0},
		{"version only inside table is not root", "[grpc]\nversion = 2\n", 0},
		{"comment before version", "# hello\nversion = 2\n", 2},
		{"version with trailing comment", "version = 2 # v2 format\n", 2},
		{"indented version", "  version = 4\n", 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := configSchemaVersion([]byte(tt.data)); got != tt.want {
				t.Errorf("configSchemaVersion() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestCriPluginID(t *testing.T) {
	if id, err := criPluginID(2); err != nil || id != criPluginIDV2 {
		t.Errorf("v2: got (%q, %v)", id, err)
	}
	if id, err := criPluginID(3); err != nil || id != criPluginIDV3 {
		t.Errorf("v3: got (%q, %v)", id, err)
	}
	if id, err := criPluginID(4); err == nil {
		t.Errorf("v4: got (%q, %v)", id, err)
	}
	for _, v := range []int{0, 1} {
		if _, err := criPluginID(v); err == nil {
			t.Errorf("version %d: expected error", v)
		}
	}
}

func TestRenderManagedBlockIsValidTOML(t *testing.T) {
	block := renderManagedBlock(criPluginIDV2, "runsc", "/opt/gvisor/containerd-shim-runsc-v1", "/etc/containerd/gvisor-runsc.toml")
	var doc map[string]any
	if err := toml.Unmarshal([]byte(block), &doc); err != nil {
		t.Fatalf("rendered block is not valid TOML: %v\n%s", err, block)
	}
	rt, ok := tomlLookup(doc, "plugins", criPluginIDV2, "containerd", "runtimes", "runsc")
	if !ok {
		t.Fatalf("runtime table missing in rendered block:\n%s", block)
	}
	m := rt.(map[string]any)
	if m["runtime_type"] != runscRuntimeType {
		t.Errorf("runtime_type = %v", m["runtime_type"])
	}
	if m["runtime_path"] != "/opt/gvisor/containerd-shim-runsc-v1" {
		t.Errorf("runtime_path = %v", m["runtime_path"])
	}
	opts, ok := tomlLookup(doc, "plugins", criPluginIDV2, "containerd", "runtimes", "runsc", "options")
	if !ok {
		t.Fatal("options table missing")
	}
	if opts.(map[string]any)["ConfigPath"] != "/etc/containerd/gvisor-runsc.toml" {
		t.Errorf("ConfigPath = %v", opts.(map[string]any)["ConfigPath"])
	}
	if opts.(map[string]any)["TypeUrl"] != runscOptionsTypeURL {
		t.Errorf("TypeUrl = %v", opts.(map[string]any)["TypeUrl"])
	}
}

func TestSpliceManagedBlock(t *testing.T) {
	block := renderManagedBlock(criPluginIDV2, "runsc", "/opt/gvisor/containerd-shim-runsc-v1", "/etc/containerd/gvisor-runsc.toml")

	// Append to a file without markers.
	spliced, err := spliceManagedBlock([]byte(kindStyleConfig), block)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(spliced), kindStyleConfig) {
		t.Error("original content was modified")
	}
	got, found, err := managedBlock(spliced)
	if err != nil || !found || got != block {
		t.Fatalf("managedBlock after splice: found=%v err=%v\ngot:  %q\nwant: %q", found, err, got, block)
	}
	// Whole file must remain valid TOML and contain both runtimes.
	var doc map[string]any
	if err := toml.Unmarshal(spliced, &doc); err != nil {
		t.Fatalf("spliced config is not valid TOML: %v\n%s", err, spliced)
	}
	if _, ok := tomlLookup(doc, "plugins", criPluginIDV2, "containerd", "runtimes", "runc"); !ok {
		t.Error("pre-existing runc runtime lost")
	}
	if _, ok := tomlLookup(doc, "plugins", criPluginIDV2, "containerd", "runtimes", "runsc"); !ok {
		t.Error("runsc runtime not added")
	}

	// Splicing the same block again is a no-op (idempotent).
	again, err := spliceManagedBlock(spliced, block)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(spliced) {
		t.Errorf("re-splice not idempotent:\n%s\nvs\n%s", again, spliced)
	}

	// Replacing with different content swaps only the managed section.
	v3block := renderManagedBlock(criPluginIDV3, "runsc", "/x/shim", "/x/runsc.toml")
	replaced, err := spliceManagedBlock(spliced, v3block)
	if err != nil {
		t.Fatal(err)
	}
	got, found, err = managedBlock(replaced)
	if err != nil || !found || got != v3block {
		t.Fatalf("replace failed: found=%v err=%v got=%q", found, err, got)
	}
	if !strings.HasPrefix(string(replaced), kindStyleConfig) {
		t.Error("replace touched content outside the managed section")
	}
	if strings.Count(string(replaced), beginMarker) != 1 || strings.Count(string(replaced), endMarker) != 1 {
		t.Error("markers duplicated on replace")
	}
}

func TestSpliceManagedBlockCorruptMarkers(t *testing.T) {
	corrupt := kindStyleConfig + "\n" + beginMarker + "\nstuff\n" // no end marker
	if _, err := spliceManagedBlock([]byte(corrupt), "x"); err == nil {
		t.Error("expected error for begin marker without end marker")
	}
	if _, _, err := managedBlock([]byte(corrupt)); err == nil {
		t.Error("expected error from managedBlock for corrupt markers")
	}
}

func TestManagedBlockAbsent(t *testing.T) {
	_, found, err := managedBlock([]byte(kindStyleConfig))
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Error("unexpectedly found managed block")
	}
}

// v3-shaped dump as containerd 2.x produces (migrated to the new CRI plugin
// split regardless of the on-disk config version).
const v3Dump = `version = 3
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runc.options]
  SystemdCgroup = true
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
`

func TestRuntimeFromDump(t *testing.T) {
	rt, found := runtimeFromDump([]byte(v3Dump), "runsc")
	if !found {
		t.Fatal("runsc not found in v3 dump")
	}
	if rt["runtime_type"] != runscRuntimeType {
		t.Errorf("runtime_type = %v", rt["runtime_type"])
	}

	if _, found := runtimeFromDump([]byte(v3Dump), "kata"); found {
		t.Error("unexpectedly found kata")
	}

	// v2-shaped dump (containerd 1.7).
	v2dump := kindStyleConfig + `[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
`
	if _, found := runtimeFromDump([]byte(v2dump), "runsc"); !found {
		t.Error("runsc not found in v2 dump")
	}

	if _, found := runtimeFromDump([]byte("not toml ["), "runsc"); found {
		t.Error("found runtime in invalid TOML")
	}
}

func TestSystemdCgroupFromDump(t *testing.T) {
	// A node whose default runtime is not named "runc": the cgroup driver has
	// to be read from whatever default_runtime_name points at, or gVisor ends
	// up on a different driver than the rest of the node.
	const customDefaultDump = `version = 2
[plugins."io.containerd.grpc.v1.cri".containerd]
  default_runtime_name = "custom-runc"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.custom-runc]
  runtime_type = "io.containerd.runc.v2"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.custom-runc.options]
  SystemdCgroup = true
`
	// The nvidia shape: default_runtime_name points at a runc wrapper that
	// omits SystemdCgroup while runc carries the node's real driver.
	const wrapperDefaultDump = `version = 3
[plugins."io.containerd.cri.v1.runtime".containerd]
  default_runtime_name = "custom-runc"
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.custom-runc]
  runtime_type = "io.containerd.runc.v2"
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runc.options]
  SystemdCgroup = true
`
	tests := []struct {
		name string
		dump string
		want bool
	}{
		{"v3 dump, default_runtime_name absent", v3Dump, true},
		{"v2 config, default_runtime_name absent", kindStyleConfig, true},
		{"non-runc default runtime with SystemdCgroup", customDefaultDump, true},
		{"wrapper default runtime falls back to runc", wrapperDefaultDump, true},
		{"runtimes absent", "version = 2\n", false},
		{"invalid TOML", "not toml [", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := systemdCgroupFromDump([]byte(tt.dump)); got != tt.want {
				t.Errorf("systemdCgroupFromDump() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMergedEntryOverride(t *testing.T) {
	want := runtimeTarget{
		ShimPath:   "/opt/gvisor/releases/20260101.0-abc/containerd-shim-runsc-v1",
		ConfigPath: "/opt/gvisor/runsc-configs/deadbeef.toml",
	}

	// The merged view a drop-in produces, keyed by the field it clobbers.
	// Each entry keeps every other pinned field intact, which is exactly what
	// makes the handler still show up in CRI's handler list.
	tests := []struct {
		name      string
		entry     string
		wantField string
		wantGot   string
	}{
		{
			name: "intact",
			entry: `  runtime_type = "io.containerd.runsc.v1"
  runtime_path = "/opt/gvisor/releases/20260101.0-abc/containerd-shim-runsc-v1"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc.options]
  TypeUrl = "io.containerd.runsc.v1.options"
  ConfigPath = "/opt/gvisor/runsc-configs/deadbeef.toml"
`,
		},
		{
			name: "runtime_path overridden",
			entry: `  runtime_type = "io.containerd.runsc.v1"
  runtime_path = "/usr/local/bin/rogue-shim"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc.options]
  TypeUrl = "io.containerd.runsc.v1.options"
  ConfigPath = "/opt/gvisor/runsc-configs/deadbeef.toml"
`,
			wantField: "runtime_path",
			wantGot:   "/usr/local/bin/rogue-shim",
		},
		{
			name: "TypeUrl overridden",
			entry: `  runtime_type = "io.containerd.runsc.v1"
  runtime_path = "/opt/gvisor/releases/20260101.0-abc/containerd-shim-runsc-v1"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc.options]
  TypeUrl = "io.containerd.runc.v1.options"
  ConfigPath = "/opt/gvisor/runsc-configs/deadbeef.toml"
`,
			wantField: "options.TypeUrl",
			wantGot:   "io.containerd.runc.v1.options",
		},
		{
			name: "options table dropped entirely",
			entry: `  runtime_type = "io.containerd.runsc.v1"
  runtime_path = "/opt/gvisor/releases/20260101.0-abc/containerd-shim-runsc-v1"
`,
			wantField: "options.TypeUrl",
		},
		{
			name: "ConfigPath overridden",
			entry: `  runtime_type = "io.containerd.runsc.v1"
  runtime_path = "/opt/gvisor/releases/20260101.0-abc/containerd-shim-runsc-v1"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc.options]
  TypeUrl = "io.containerd.runsc.v1.options"
  ConfigPath = "/etc/containerd/rogue-runsc.toml"
`,
			wantField: "options.ConfigPath",
			wantGot:   "/etc/containerd/rogue-runsc.toml",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dump := `[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]` + "\n" + tt.entry
			rt, found := runtimeFromDump([]byte(dump), "runsc")
			if !found {
				t.Fatalf("runsc entry not found in dump:\n%s", dump)
			}
			field, got := mergedEntryOverride(rt, want)
			if field != tt.wantField || got != tt.wantGot {
				t.Errorf("mergedEntryOverride() = (%q, %q), want (%q, %q)", field, got, tt.wantField, tt.wantGot)
			}
		})
	}
}

func TestRemoveManagedBlock(t *testing.T) {
	block := renderManagedBlock(criPluginIDV2, "runsc", "/x/shim", "/x/runsc.toml")
	spliced, err := spliceManagedBlock([]byte(kindStyleConfig), block)
	if err != nil {
		t.Fatal(err)
	}
	removed, err := removeManagedBlock(spliced)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(removed), beginMarker) || strings.Contains(string(removed), endMarker) {
		t.Errorf("markers survived removal:\n%s", removed)
	}
	if !strings.HasPrefix(string(removed), kindStyleConfig) {
		t.Errorf("content outside the managed section changed:\n%s", removed)
	}
	unchanged, err := removeManagedBlock([]byte(kindStyleConfig))
	if err != nil || string(unchanged) != kindStyleConfig {
		t.Errorf("removal without markers must be a no-op (err %v)", err)
	}
	if _, err := removeManagedBlock([]byte(kindStyleConfig + beginMarker + "\nstuff\n")); err == nil {
		t.Error("expected error for begin marker without end marker")
	}
}
