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

package shim

const optionsType = "io.containerd.runsc.v1.options"

// options is runtime options for io.containerd.runsc.v1.
type options struct {
	// ShimCgroup is the cgroup the shim should be in.
	ShimCgroup string `toml:"shim_cgroup" json:"shimCgroup"`

	// IoUID is the I/O's pipes uid.
	IoUID uint32 `toml:"io_uid" json:"ioUid"`

	// IoGID is the I/O's pipes gid.
	IoGID uint32 `toml:"io_gid" json:"ioGid"`

	// BinaryName is the binary name of the runsc binary.
	BinaryName string `toml:"binary_name" json:"binaryName"`

	// Root is the runsc root directory.
	Root string `toml:"root" json:"root"`

	// LogLevel sets the logging level. Some of the possible values are: debug,
	// info, warning.
	//
	// This configuration only applies when the shim is running as a service.
	LogLevel string `toml:"log_level" json:"logLevel"`

	// LogPath is the path to log directory. %ID% tags inside the string are
	// replaced with the container ID.
	//
	// This configuration only applies when the shim is running as a service.
	LogPath string `toml:"log_path" json:"logPath"`

	// RunscConfig is a key/value map of all runsc flags.
	RunscConfig map[string]string `toml:"runsc_config" json:"runscConfig"`
}
