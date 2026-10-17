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

package runsc

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
	runctypes "github.com/containerd/containerd/api/types/runc/options"
	"github.com/containerd/log"
	typeurl "github.com/containerd/typeurl/v2"
	"google.golang.org/protobuf/types/known/anypb"

	"gvisor.dev/gvisor/pkg/shim/v1/runtimeoptions"
)

const optionsType = "io.containerd.runsc.v1.options"

// resolveOptions returns the runsc options for the runtime options containerd
// passed.
//
// A sandboxer = "shim" handler cannot declare a runsc options section:
// containerd's WithTaskAPIEndpoint unmarshals them into runc options and fails
// container start (client/task.go getRuncOptions in containerd v2.1). Without
// the section, the handler's containers get runc options and its sandbox gets
// none. Both then read the config file (GetRuntimeOptions), so they agree on
// Root and BinaryName. sandbox selects that fallback for missing options.
func resolveOptions(a *anypb.Any, sandbox bool) (*Options, error) {
	if a == nil {
		if sandbox {
			return GetRuntimeOptions(), nil
		}
		return &Options{}, nil
	}
	if typeurl.Is(a, &runctypes.Options{}) {
		return GetRuntimeOptions(), nil
	}
	runtimeOptions := &runtimeoptions.Options{}
	if err := typeurl.UnmarshalTo(a, runtimeOptions); err != nil {
		return nil, fmt.Errorf("unmarshal runtime options: %w", err)
	}
	// An empty ConfigPath means defaults.
	opts := &Options{}
	if path := runtimeOptions.GetConfigPath(); path != "" {
		if _, err := toml.DecodeFile(path, opts); err != nil {
			return nil, fmt.Errorf("decode config file %q: %w", path, err)
		}
	}
	return opts, nil
}

// shimConfigPaths are searched in order by GetRuntimeOptions.
var shimConfigPaths = []string{
	"/run/containerd/runsc/config.toml",
	"/etc/containerd/runsc/config.toml",
	"config.toml",
}

// GetRuntimeOptions returns the runtime options from the global config file.
func GetRuntimeOptions() *Options {
	opts := &Options{}

	tomlPath := ""
	for _, path := range shimConfigPaths {
		if _, err := os.Stat(path); err == nil {
			log.L.Debugf("Found shim config file %q", path)
			tomlPath = path
			break
		}
	}
	if len(tomlPath) == 0 {
		log.L.Debugf("Failed to find shim config file")
		return opts
	}

	if _, err := toml.DecodeFile(tomlPath, opts); err != nil {
		log.L.Debugf("Failed to decode shim config file %q: %v", tomlPath, err)
		return opts
	}

	return opts
}

// Options is runtime options for io.containerd.runsc.v1.
type Options struct {
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

	// Grouping indicates if shim grouping should be enabled.
	Grouping bool `toml:"grouping" json:"grouping"`

	// EnableHibernateServer indicates if the hibernate server should be started.
	EnableHibernateServer bool `toml:"enable_hibernate_server" json:"enableHibernateServer"`

	// RunscConfig is a key/value map of all runsc flags.
	RunscConfig map[string]string `toml:"runsc_config" json:"runscConfig"`
}
