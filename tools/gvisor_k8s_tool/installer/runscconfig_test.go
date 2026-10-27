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
	"testing"

	"github.com/BurntSushi/toml"
)

func decodeShimConfig(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := toml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("shim config is not valid TOML: %v\n%s", err, data)
	}
	return doc
}

func TestRenderRunscShimConfig(t *testing.T) {
	base := []byte("[runsc_config]\n  allow-rootfs-tar-annotation = \"true\"\n")

	out, err := renderRunscShimConfig(base, "/opt/gvisor/bin/runsc", true)
	if err != nil {
		t.Fatal(err)
	}
	doc := decodeShimConfig(t, out)
	if doc["binary_name"] != "/opt/gvisor/bin/runsc" {
		t.Errorf("binary_name = %v", doc["binary_name"])
	}
	flags := doc["runsc_config"].(map[string]any)
	if flags["allow-rootfs-tar-annotation"] != "true" {
		t.Errorf("user flag lost: %v", flags)
	}
	if flags["systemd-cgroup"] != "true" {
		t.Errorf("systemd-cgroup not injected: %v", flags)
	}

	// Detection disabled -> "false" injected.
	out, err = renderRunscShimConfig(base, "/opt/gvisor/bin/runsc", false)
	if err != nil {
		t.Fatal(err)
	}
	flags = decodeShimConfig(t, out)["runsc_config"].(map[string]any)
	if flags["systemd-cgroup"] != "false" {
		t.Errorf("systemd-cgroup = %v, want false", flags["systemd-cgroup"])
	}
}

func TestRenderRunscShimConfigExplicitOverridesWin(t *testing.T) {
	// An explicit chart-provided systemd-cgroup beats auto-detection.
	base := []byte("[runsc_config]\n  systemd-cgroup = \"false\"\n")
	out, err := renderRunscShimConfig(base, "/opt/gvisor/bin/runsc", true)
	if err != nil {
		t.Fatal(err)
	}
	flags := decodeShimConfig(t, out)["runsc_config"].(map[string]any)
	if flags["systemd-cgroup"] != "false" {
		t.Errorf("explicit systemd-cgroup overridden: %v", flags["systemd-cgroup"])
	}
}

func TestRenderRunscShimConfigEmptyBase(t *testing.T) {
	out, err := renderRunscShimConfig(nil, "/opt/gvisor/bin/runsc", true)
	if err != nil {
		t.Fatal(err)
	}
	doc := decodeShimConfig(t, out)
	if doc["binary_name"] != "/opt/gvisor/bin/runsc" {
		t.Errorf("binary_name = %v", doc["binary_name"])
	}
	if _, ok := doc["runsc_config"].(map[string]any); !ok {
		t.Errorf("runsc_config table missing: %v", doc)
	}
}

func TestRenderRunscShimConfigDeterministic(t *testing.T) {
	base := []byte("[runsc_config]\n  b = \"1\"\n  a = \"2\"\n  c = \"3\"\n")
	first, err := renderRunscShimConfig(base, "/opt/gvisor/bin/runsc", true)
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		next, err := renderRunscShimConfig(base, "/opt/gvisor/bin/runsc", true)
		if err != nil {
			t.Fatal(err)
		}
		if string(next) != string(first) {
			t.Fatalf("non-deterministic rendering breaks change detection:\n%s\nvs\n%s", first, next)
		}
	}
}

func TestRenderRunscShimConfigInvalidBase(t *testing.T) {
	if _, err := renderRunscShimConfig([]byte("not toml ["), "/r", true); err == nil {
		t.Error("expected error for invalid base config")
	}
}

func TestRenderRunscShimConfigRejectsInvalidOptionTypes(t *testing.T) {
	for _, base := range []string{"runsc_config = 1\n", "[runsc_config]\ndebug = true\n", "io_uid = -1\n", "io_gid = 4294967296\n", "log_level = true\n", "grouping = \"true\"\n"} {
		if _, err := renderRunscShimConfig([]byte(base), "/runsc", false); err == nil {
			t.Fatalf("accepted invalid shim options %q", base)
		}
	}
}
