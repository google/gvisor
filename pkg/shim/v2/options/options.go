// Copyright 2018 The gVisor Authors.
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

package options

const OptionType = "io.containerd.runsc.v1.options"

// Options is runtime options for io.containerd.runsc.v1.
type Options struct {
	// ShimCgroup is the cgroup the shim should be in.
	ShimCgroup string `toml:"shim_cgroup"`
	// IoUid is the I/O's pipes uid.
	IoUid uint32 `toml:"io_uid"`
	// IoUid is the I/O's pipes gid.
	IoGid uint32 `toml:"io_gid"`
	// BinaryName is the binary name of the runsc binary.
	BinaryName string `toml:"binary_name"`
	// Root is the runsc root directory.
	Root string `toml:"root"`
	// RunscConfig is a key/value map of all runsc flags.
	RunscConfig map[string]string `toml:"runsc_config"`
}
