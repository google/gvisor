// Copyright 2018 Google LLC
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

// Package testdata contains data required for root tests.
package testdata

import "fmt"

// containerdConfigTemplate is a .toml config for containerd. It contains a
// formatting verb so the runtime field can be set via fmt.Sprintf.
const containerdConfigTemplate = `
disabled_plugins = ["restart"]
[plugins.linux]
  runtime = "%s"
  runtime_root = "/tmp/test-containerd/runsc"
  shim = "/usr/local/bin/gvisor-containerd-shim"
  shim_debug = true

[plugins.cri.containerd.runtimes.runsc]
  runtime_type = "io.containerd.runtime.v1.linux"
  runtime_engine = "%s"
`

// ContainerdConfig returns a containerd config file with the specified
// runtime.
func ContainerdConfig(runtime string) string {
	return fmt.Sprintf(containerdConfigTemplate, runtime, runtime)
}
