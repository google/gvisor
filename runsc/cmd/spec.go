// Copyright 2018 The gVisor Authors.
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

package cmd

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path"
	"path/filepath"
	"syscall"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/flag"
)

func major(dev uint64) uint32 {
	return uint32((dev >> 8) & 0xfff)
}

func minor(dev uint64) uint32 {
	return uint32((dev & 0xff) | ((dev >> 12) & 0xfff00))
}

func findAllTPUs(testDevicePrefix string) []specs.LinuxDevice {
	vfioGlob := path.Join(testDevicePrefix, "/dev/vfio/*")
	paths, err := filepath.Glob(vfioGlob)
	if err != nil {
		util.Errorf("failed to list %q: %v", vfioGlob, err)
		return nil
	}
	accelGlob := path.Join(testDevicePrefix, "/dev/accel*")
	accelPaths, err := filepath.Glob(accelGlob)
	if err != nil {
		util.Errorf("failed to list %q: %v", accelGlob, err)
		return nil
	}
	paths = append(paths, accelPaths...)

	var devs []specs.LinuxDevice
	for _, path := range paths {
		st, err := os.Stat(path)
		if err != nil {
			util.Errorf("failed to stat %q: %v", path, err)
			continue
		}
		if st.Mode()&os.ModeDevice == 0 || st.Mode()&os.ModeCharDevice == 0 {
			util.Infof("Skipping non-character device file %q", path)
			continue
		}
		stat, ok := st.Sys().(*syscall.Stat_t)
		if !ok {
			util.Errorf("failed to get syscall.Stat_t for %q", path)
			continue
		}
		mode := os.FileMode(0666)
		devs = append(devs, specs.LinuxDevice{
			Path:     path,
			Type:     "c",
			Major:    int64(major(stat.Rdev)),
			Minor:    int64(minor(stat.Rdev)),
			FileMode: &mode,
			UID:      proto.Uint32(0),
			GID:      proto.Uint32(0),
		})
	}
	return devs
}

func writeSpec(w io.Writer, cwd string, netns string, args []string, tpu bool) error {
	spec := &specs.Spec{
		Version: "1.0.0",
		Process: &specs.Process{
			User: specs.User{
				UID: 0,
				GID: 0,
			},
			Args: args,
			Env: []string{
				"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				"TERM=xterm",
			},
			Cwd: cwd,
			Capabilities: &specs.LinuxCapabilities{
				Bounding: []string{
					"CAP_AUDIT_WRITE",
					"CAP_KILL",
					"CAP_NET_BIND_SERVICE",
				},
				Effective: []string{
					"CAP_AUDIT_WRITE",
					"CAP_KILL",
					"CAP_NET_BIND_SERVICE",
				},
				Inheritable: []string{
					"CAP_AUDIT_WRITE",
					"CAP_KILL",
					"CAP_NET_BIND_SERVICE",
				},
				Permitted: []string{
					"CAP_AUDIT_WRITE",
					"CAP_KILL",
					"CAP_NET_BIND_SERVICE",
				},
				// TODO(gvisor.dev/issue/3166): support ambient capabilities
			},
			Rlimits: []specs.POSIXRlimit{
				{
					Type: "RLIMIT_NOFILE",
					Hard: 1024,
					Soft: 1024,
				},
			},
		},
		Root: &specs.Root{
			Path:     "rootfs",
			Readonly: true,
		},
		Hostname: "runsc",
		Mounts: []specs.Mount{
			{
				Destination: "/proc",
				Type:        "proc",
				Source:      "proc",
			},
			{
				Destination: "/dev",
				Type:        "tmpfs",
				Source:      "tmpfs",
			},
			{
				Destination: "/sys",
				Type:        "sysfs",
				Source:      "sysfs",
				Options: []string{
					"nosuid",
					"noexec",
					"nodev",
					"ro",
				},
			},
		},
		Linux: &specs.Linux{
			Namespaces: []specs.LinuxNamespace{
				{
					Type: "pid",
				},
				{
					Type: "network",
					Path: netns,
				},
				{
					Type: "ipc",
				},
				{
					Type: "uts",
				},
				{
					Type: "mount",
				},
			},
		},
	}

	if tpu {
		spec.Linux.Devices = append(spec.Linux.Devices, findAllTPUs( /*testDevicePrefix= */ "")...)
	}

	e := json.NewEncoder(w)
	e.SetIndent("", "    ")
	return e.Encode(spec)
}

// Spec implements subcommands.Command for the "spec" command.
type Spec struct {
	bundle string
	cwd    string
	netns  string
	tpu    bool
}

// Name implements subcommands.Command.Name.
func (*Spec) Name() string {
	return "spec"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Spec) Synopsis() string {
	return "create a new OCI bundle specification file"
}

// Usage implements subcommands.Command.Usage.
func (*Spec) Usage() string {
	return `spec [options] [-- args...] - create a new OCI bundle specification file.

The spec command creates a new specification file (config.json) for a new OCI
bundle.

The specification file is a starter file that runs the command specified by
'args' in the container. If 'args' is not specified the default is to run the
'sh' program.

While a number of flags are provided to change values in the specification, you
can examine the file and edit it to suit your needs after this command runs.
You can find out more about the format of the specification file by visiting
the OCI runtime spec repository:
https://github.com/opencontainers/runtime-spec/

EXAMPLE:
    $ mkdir -p bundle/rootfs
    $ cd bundle
    $ runsc spec -- /hello
    $ docker export $(docker create hello-world) | tar -xf - -C rootfs
    $ sudo runsc run hello

`
}

// SetFlags implements subcommands.Command.SetFlags.
func (s *Spec) SetFlags(f *flag.FlagSet) {
	f.StringVar(&s.bundle, "bundle", ".", "path to the root of the OCI bundle")
	f.StringVar(&s.cwd, "cwd", "/", "working directory that will be set for the executable, "+
		"this value MUST be an absolute path")
	f.StringVar(&s.netns, "netns", "", "network namespace path")
	f.BoolVar(&s.tpu, "tpu", false, "whether to configure the container with access to TPU devices")
}

// Execute implements subcommands.Command.Execute.
func (s *Spec) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	// Grab the arguments.
	containerArgs := f.Args()
	if len(containerArgs) == 0 {
		containerArgs = []string{"sh"}
	}

	confPath := filepath.Join(s.bundle, "config.json")
	if _, err := os.Stat(confPath); !os.IsNotExist(err) {
		util.Fatalf("file %q already exists", confPath)
	}

	configFile, err := os.OpenFile(confPath, os.O_WRONLY|os.O_CREATE, 0664)
	if err != nil {
		util.Fatalf("opening file %q: %v", confPath, err)
	}

	err = writeSpec(configFile, s.cwd, s.netns, containerArgs, s.tpu)
	if err != nil {
		util.Fatalf("writing to %q: %v", confPath, err)
	}

	return subcommands.ExitSuccess
}
