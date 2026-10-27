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

import "testing"

func TestConfigFromEnvBindsIdentityAndFixedState(t *testing.T) {
	t.Setenv("NODE_NAME", "worker")
	t.Setenv("POD_UID", "installer-uid")
	t.Setenv("POD_NAMESPACE", "system")
	t.Setenv("POD_NAME", "installer-pod")
	t.Setenv("STATE_DIR", "/other-state")
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StateDir != "/var/lib/gvisor-installer" || cfg.Namespace != "system" || cfg.PayloadDir != "/opt/gvisor/release" {
		t.Fatalf("unexpected configuration %+v", cfg)
	}
	for key, value := range map[string]string{"GVISOR_HANDLER": "bad.handler", "CONTAINERD_CONFIG": "relative", "CONTAINERD_SOCKET": "/run/../socket", "INSTALL_DIR": "/", "CONTAINERD_SERVICE": "--other", "RECONCILE_TIMEOUT": "0s"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, value)
			if _, err := ConfigFromEnv(); err == nil {
				t.Fatalf("accepted invalid %s", key)
			}
		})
	}
}

func TestConfigRequiresPodIdentity(t *testing.T) {
	t.Setenv("NODE_NAME", "")
	t.Setenv("POD_UID", "")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("accepted missing pod identity")
	}
}
