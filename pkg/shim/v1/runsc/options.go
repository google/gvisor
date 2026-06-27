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
	"os"

	"github.com/BurntSushi/toml"
	"github.com/containerd/log"
)

const optionsType = "io.containerd.runsc.v1.options"

// GetRuntimeOptions returns the runtime options from the global config file.
func GetRuntimeOptions() *Options {
	opts := &Options{}
	shimConfigPaths := []string{
		"/run/containerd/runsc/config.toml",
		"/etc/containerd/runsc/config.toml",
		"config.toml",
	}

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

	// EnableUserNamespaceAnnotation is the operator-side gate that allows
	// pods to opt into shim-side user namespace injection via the pod
	// annotation "dev.gvisor.spec.user-namespace": "true" (see
	// utils.UserNamespaceRequestAnnotation). When true, sandbox containers
	// whose pod annotations contain that key get a user namespace plus
	// contiguous, non-overlapping uid/gid mappings injected into their OCI
	// spec before runsc is invoked. Application/exec containers within the
	// same pod inherit the sandbox's user namespace.
	//
	// This exists to let runsc workloads run inside a user namespace on
	// nodes whose kubelet+containerd stack does not yet plumb pod.spec.
	// hostUsers (KEP-127) through to runsc. When that path lands upstream,
	// drop the annotation and use hostUsers: false on the pod spec instead.
	// See https://github.com/google/gvisor/issues/13303.
	//
	// The shim respects caller-supplied user namespaces and uid/gid
	// mappings: if the OCI spec already declares them (e.g. via
	// hostUsers: false), the shim leaves the spec untouched and does not
	// allocate a slot.
	//
	// Pods can only request the userns when this option is true, so a
	// misconfigured workload cannot unilaterally enable it.
	EnableUserNamespaceAnnotation bool `toml:"enable_user_namespace_annotation" json:"enableUserNamespaceAnnotation"`

	// UserNamespaceHostUIDBase is the lowest host UID used by the
	// per-node UID pool. Each sandbox that opts in receives a contiguous
	// block of UserNamespaceRangeSize UIDs starting at
	// UserNamespaceHostUIDBase + slot*UserNamespaceRangeSize.
	UserNamespaceHostUIDBase uint32 `toml:"user_namespace_host_uid_base" json:"userNamespaceHostUidBase"`

	// UserNamespaceHostGIDBase is the GID equivalent of
	// UserNamespaceHostUIDBase.
	UserNamespaceHostGIDBase uint32 `toml:"user_namespace_host_gid_base" json:"userNamespaceHostGidBase"`

	// UserNamespaceRangeSize is the number of UIDs/GIDs each sandbox
	// receives. Defaults to 65536 when the annotation gate is enabled and
	// this field is unset.
	UserNamespaceRangeSize uint32 `toml:"user_namespace_range_size" json:"userNamespaceRangeSize"`

	// UserNamespacePoolSize is the maximum number of concurrent sandboxes
	// that can hold non-overlapping UID/GID ranges on this node. Defaults
	// to 1000 when the annotation gate is enabled and this field is unset.
	UserNamespacePoolSize uint32 `toml:"user_namespace_pool_size" json:"userNamespacePoolSize"`

	// UserNamespaceStateDir is the directory used to persist slot
	// allocations across shim restarts. Defaults to /run/runsc/userns-pool.
	UserNamespaceStateDir string `toml:"user_namespace_state_dir" json:"userNamespaceStateDir"`

	// RunscConfig is a key/value map of all runsc flags.
	RunscConfig map[string]string `toml:"runsc_config" json:"runscConfig"`
}
