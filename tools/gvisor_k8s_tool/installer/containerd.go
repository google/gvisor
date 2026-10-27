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
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// Only the text between these markers is ours. Splicing text rather than
// round-tripping through a TOML library keeps the user's table order and
// comments intact.
const (
	beginMarker = "# BEGIN gvisor-managed gVisor runtime (managed by gVisor node installer, do not edit)"
	endMarker   = "# END gvisor-managed gVisor runtime"
)

const (
	// Config version 2 (containerd 1.x, still auto-migrated by 2.x) vs version
	// 3+ (containerd 2.x, where the CRI plugin was split).
	criPluginIDV2 = "io.containerd.grpc.v1.cri"
	criPluginIDV3 = "io.containerd.cri.v1.runtime"

	runscRuntimeType = "io.containerd.runsc.v1"
	// The gVisor shim rejects any other options type at task creation, long
	// after CRI has already listed the handler as available.
	runscOptionsTypeURL = runscRuntimeType + ".options"

	// containerd's own default when default_runtime_name is unset.
	defaultRuntimeName = "runc"
)

var versionLineRe = regexp.MustCompile(`^\s*version\s*=\s*([0-9]+)`)

// configSchemaVersion reads the root-level `version = N`. Only lines before
// the first table header count, since a `version` inside a table is that
// table's. 0 means absent, which containerd treats as a legacy v1 config.
func configSchemaVersion(data []byte) int {
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			break
		}
		if m := versionLineRe.FindStringSubmatch(line); m != nil {
			v, err := strconv.Atoi(m[1])
			if err != nil {
				return 0
			}
			return v
		}
	}
	return 0
}

func criPluginID(schemaVersion int) (string, error) {
	switch schemaVersion {
	case 2:
		return criPluginIDV2, nil
	case 3:
		return criPluginIDV3, nil
	default:
		return "", fmt.Errorf("containerd config declares unsupported schema version %d: "+
			"only version 2 (containerd 1.x+) and version 3 (containerd 2.x) are supported. "+
			"a missing version field means a legacy v1 config", schemaVersion)
	}
}

// renderManagedBlock pins runtime_path so the shim need not be on
// containerd's $PATH.
func renderManagedBlock(pluginID, handler, shimPath, shimConfigPath string) string {
	return fmt.Sprintf(`[plugins.%q.containerd.runtimes.%q]
  runtime_type = %q
  runtime_path = %q
  # Allow gVisor annotations (e.g. dev.gvisor.flag.*, mount hints) to reach runsc.
  pod_annotations = ["dev.gvisor.*"]
[plugins.%q.containerd.runtimes.%q.options]
  TypeUrl = %q
  ConfigPath = %q`,
		pluginID, handler, runscRuntimeType, shimPath,
		pluginID, handler, runscOptionsTypeURL, shimConfigPath)
}

// managedBlock treats a begin marker without an end marker as an error
// rather than guessing where the section ends.
func managedBlock(data []byte) (block string, found bool, err error) {
	s := string(data)
	begins, ends := strings.Count(s, beginMarker), strings.Count(s, endMarker)
	if begins == 0 && ends == 0 {
		return "", false, nil
	}
	if begins != 1 || ends != 1 {
		return "", false, fmt.Errorf("containerd config has incomplete or duplicate installer markers")
	}
	bi, ei := strings.Index(s, beginMarker), strings.Index(s, endMarker)
	if ei <= bi || (bi > 0 && s[bi-1] != '\n') || (ei > 0 && s[ei-1] != '\n') {
		return "", false, fmt.Errorf("containerd installer markers are not separate ordered lines")
	}
	beginEnd, endEnd := bi+len(beginMarker), ei+len(endMarker)
	if beginEnd >= len(s) || s[beginEnd] != '\n' || (endEnd < len(s) && s[endEnd] != '\n') {
		return "", false, fmt.Errorf("containerd installer markers have unexpected suffixes")
	}
	return strings.Trim(s[beginEnd:ei], "\n"), true, nil
}

// spliceManagedBlock preserves everything outside the markers byte-for-byte.
func spliceManagedBlock(data []byte, block string) ([]byte, error) {
	if _, _, err := managedBlock(data); err != nil {
		return nil, err
	}
	s := string(data)
	section := beginMarker + "\n" + block + "\n" + endMarker

	bi := strings.Index(s, beginMarker)
	if bi < 0 {
		if !strings.HasSuffix(s, "\n") && s != "" {
			s += "\n"
		}
		return []byte(s + "\n" + section + "\n"), nil
	}
	rest := s[bi:]
	ei := strings.Index(rest, endMarker)
	if ei < 0 {
		return nil, fmt.Errorf("%s: begin marker present but end marker missing, refusing to touch the file", containerdConfigPath)
	}
	return []byte(s[:bi] + section + s[bi+ei+len(endMarker):]), nil
}

func removeManagedBlock(data []byte) ([]byte, error) {
	if _, _, err := managedBlock(data); err != nil {
		return nil, err
	}
	s := string(data)
	bi := strings.Index(s, beginMarker)
	if bi < 0 {
		return data, nil
	}
	rest := s[bi:]
	ei := strings.Index(rest, endMarker)
	if ei < 0 {
		return nil, fmt.Errorf("%s: begin marker present but end marker missing, refusing to touch the file", containerdConfigPath)
	}
	return []byte(s[:bi] + s[bi+ei+len(endMarker):]), nil
}

func tomlLookup(doc map[string]any, keys ...string) (any, bool) {
	var cur any = doc
	for _, k := range keys {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[k]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// runtimeFromDump looks up a runtime handler entry in `containerd config
// dump` output. Both plugin IDs are checked: containerd 2.x migrates the
// dumped config to the newest schema regardless of the on-disk version.
func runtimeFromDump(dump []byte, handler string) (map[string]any, bool) {
	var doc map[string]any
	if err := toml.Unmarshal(dump, &doc); err != nil {
		return nil, false
	}
	for _, pluginID := range []string{criPluginIDV2, criPluginIDV3} {
		if v, ok := tomlLookup(doc, "plugins", pluginID, "containerd", "runtimes", handler); ok {
			if m, ok := v.(map[string]any); ok {
				return m, true
			}
		}
	}
	return nil, false
}

// What a managed block registers.
type runtimeTarget struct {
	ShimPath   string
	ConfigPath string
}

// mergedEntryOverride catches a drop-in import repointing our handler at
// another shim while keeping runtime_type intact. Such a node must never
// count as gVisor-ready.
func mergedEntryOverride(rt map[string]any, want runtimeTarget) (field, got string) {
	if p, _ := rt["runtime_path"].(string); p != want.ShimPath {
		return "runtime_path", p
	}
	opts, _ := rt["options"].(map[string]any)
	if tu, _ := opts["TypeUrl"].(string); tu != runscOptionsTypeURL {
		return "options.TypeUrl", tu
	}
	if cp, _ := opts["ConfigPath"].(string); cp != want.ConfigPath {
		return "options.ConfigPath", cp
	}
	return "", ""
}

func defaultRuntimeFromDump(doc map[string]any, pluginID string) string {
	if v, ok := tomlLookup(doc, "plugins", pluginID, "containerd", "default_runtime_name"); ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return defaultRuntimeName
}

// systemdCgroupFromDump reports whether the node uses the systemd cgroup
// driver, which gVisor must match. Only the default runtime and runc are
// authoritative: a wrapper set as default (nvidia's) often omits the key while
// runc carries the node's real value. Other handlers are not evidence about
// the node. Defaults to false, runc's own default.
func systemdCgroupFromDump(dump []byte) bool {
	var doc map[string]any
	if err := toml.Unmarshal(dump, &doc); err != nil {
		return false
	}
	for _, pluginID := range []string{criPluginIDV2, criPluginIDV3} {
		for _, handler := range []string{defaultRuntimeFromDump(doc, pluginID), defaultRuntimeName} {
			if b, ok := systemdCgroupForRuntime(doc, pluginID, handler); ok {
				return b
			}
		}
	}
	return false
}

func systemdCgroupForRuntime(doc map[string]any, pluginID, handler string) (value, found bool) {
	v, ok := tomlLookup(doc, "plugins", pluginID, "containerd", "runtimes", handler, "options", "SystemdCgroup")
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}
