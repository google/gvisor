// Copyright 2026 The gVisor Authors.
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
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"

	sandboxexecpb "gvisor.dev/gvisor/sandboxexec/proto/sandbox_options_go_proto"
)

// SandboxExec implements subcommands.Command for the "sandboxexec" command.
type SandboxExec struct {
	optionsFile string
}

// Name implements subcommands.Command.Name.
func (*SandboxExec) Name() string {
	return "sandboxexec"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*SandboxExec) Synopsis() string {
	return "Run a command in a sandbox with options defined in a proto."
}

// Usage implements subcommands.Command.Usage.
func (*SandboxExec) Usage() string {
	return `sandboxexec [flags] <cmd> [args...] - runs a command in a sandbox.

This command starts a sandbox using configuration options provided via a
SandboxOptions proto message.
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *SandboxExec) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.optionsFile, "options", "", "path to the SandboxOptions proto file (binary or textproto)")
}

// FetchSpec implements util.SubCommand.FetchSpec.
func (c *SandboxExec) FetchSpec(conf *config.Config, f *flag.FlagSet) (string, *specs.Spec, error) {
	// We don't use a pre-existing spec, we build it in Execute.
	// But FetchSpec is called by cli.Run. We can return a dummy ID and nil spec,
	// or build it here.
	// If we return nil spec, cli.Run will skip FixConfig.
	// Let's return a dummy ID and nil spec, and do the real work in Execute.
	return "sandboxexec-dummy", nil, nil
}

// Execute implements subcommands.Command.Execute.
func (c *SandboxExec) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if len(f.Args()) == 0 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	conf := args[0].(*config.Config)

	var opts sandboxexecpb.SandboxOptions
	if c.optionsFile != "" {
		data, err := os.ReadFile(c.optionsFile)
		if err != nil {
			return util.Errorf("reading options file: %v", err)
		}
		if err := prototext.Unmarshal(data, &opts); err != nil {
			// Try binary
			if err := proto.Unmarshal(data, &opts); err != nil {
				return util.Errorf("parsing proto (tried textproto and binary): %v", err)
			}
		}
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			data, err := io.ReadAll(os.Stdin)
			if err == nil && len(data) > 0 {
				if err := prototext.Unmarshal(data, &opts); err != nil {
					if err := proto.Unmarshal(data, &opts); err != nil {
						return util.Errorf("parsing proto from stdin: %v", err)
					}
				}
			}
		}
	}

	// Construct Spec
	cid := fmt.Sprintf("runsc-%06d", rand.Int31n(1000000))
	spec, err := createSpec(&opts, f.Args(), conf)
	if err != nil {
		return util.Errorf("creating spec: %v", err)
	}

	// Start Container
	tmpDir, err := os.MkdirTemp("", "runsc-sandboxexec")
	if err != nil {
		return util.Errorf("creating tmp dir: %v", err)
	}

	// Write spec to bundle dir
	out, err := json.Marshal(spec)
	if err != nil {
		return util.Errorf("marshaling spec: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "config.json"), out, 0644); err != nil {
		return util.Errorf("writing config.json: %v", err)
	}

	devNull, err := os.OpenFile("/dev/null", os.O_RDWR, 0644)
	if err != nil {
		return util.Errorf("opening /dev/null: %v", err)
	}
	defer devNull.Close()

	passFiles := make(map[int]*os.File)
	if opts.GetStdoutFile() != "" {
		f, err := os.OpenFile(opts.GetStdoutFile(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return util.Errorf("opening stdout file: %v", err)
		}
		passFiles[1] = f
		defer f.Close()
	} else {
		passFiles[1] = devNull
	}

	if opts.GetStderrFile() != "" {
		f, err := os.OpenFile(opts.GetStderrFile(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return util.Errorf("opening stderr file: %v", err)
		}
		passFiles[2] = f
		defer f.Close()
	} else {
		passFiles[2] = devNull
	}

	containerArgs := container.Args{
		ID:        cid,
		Spec:      spec,
		BundleDir: tmpDir,
		Attached:  false, // Run in background
		PassFiles: passFiles,
	}

	cont, err := container.New(conf, containerArgs)
	if err != nil {
		return util.Errorf("creating container: %v", err)
	}

	if err := cont.Start(conf); err != nil {
		cont.Destroy()
		return util.Errorf("starting container: %v", err)
	}

	// Return PID and Control Socket Path
	fmt.Printf("PID: %d\n", cont.SandboxPid())
	fmt.Printf("Control Socket: %s\n", cont.Sandbox.GetControlSocketPath())

	return subcommands.ExitSuccess
}

func createSpec(opts *sandboxexecpb.SandboxOptions, args []string, conf *config.Config) (*specs.Spec, error) {
	spec := &specs.Spec{
		Root: &specs.Root{
			Path: "/",
		},
		Process: &specs.Process{
			Cwd:          ".",
			Args:         args,
			Env:          os.Environ(),
			Capabilities: specutils.AllCapabilities(),
		},
	}

	if conf.Rootless {
		if spec.Linux == nil {
			spec.Linux = &specs.Linux{}
		}
		spec.Linux.Namespaces = append(spec.Linux.Namespaces, specs.LinuxNamespace{Type: specs.UserNamespace})
		spec.Linux.UIDMappings = []specs.LinuxIDMapping{
			{ContainerID: 0, HostID: uint32(os.Getuid()), Size: 1},
		}
		spec.Linux.GIDMappings = []specs.LinuxIDMapping{
			{ContainerID: 0, HostID: uint32(os.Getgid()), Size: 1},
		}
	}

	for _, ev := range opts.GetEnvVars() {
		name := ev.GetName()
		switch x := ev.GetPolicyOrValue().(type) {
		case *sandboxexecpb.EnvVar_Value:
			spec.Process.Env = append(spec.Process.Env, fmt.Sprintf("%s=%s", name, x.Value))
		case *sandboxexecpb.EnvVar_Policy:
			if x.Policy == sandboxexecpb.EnvVar_ENV_VAR_POLICY_FORWARD {
				if val, ok := os.LookupEnv(name); ok {
					spec.Process.Env = append(spec.Process.Env, fmt.Sprintf("%s=%s", name, val))
				}
			}
		}
	}

	spec.Mounts = append(spec.Mounts, specs.Mount{
		Destination: "/proc",
		Type:        "proc",
	}, specs.Mount{
		Destination: "/sys",
		Type:        "sysfs",
	}, specs.Mount{
		Destination: "/dev",
		Type:        "devtmpfs",
	}, specs.Mount{
		Destination: "/dev/pts",
		Type:        "devpts",
	}, specs.Mount{
		Destination: "/sys/fs/cgroup",
		Type:        "cgroupfs",
	}, specs.Mount{
		Destination: "/tmp",
		Type:        "tmpfs",
	})

	for _, m := range opts.GetMounts() {
		specMount := specs.Mount{
			Destination: m.GetTarget(),
		}
		switch x := m.GetMount().(type) {
		case *sandboxexecpb.Mount_HostMount:
			specMount.Type = "bind"
			specMount.Source = x.HostMount.GetHostPath()

		case *sandboxexecpb.Mount_SandboxTmpfsMount:
			specMount.Type = "tmpfs"
			specMount.Source = "tmpfs"
		}
		spec.Mounts = append(spec.Mounts, specMount)
	}

	if opts.GetNetworkingOptions() != nil {
		netOpts := opts.GetNetworkingOptions()
		if netOpts.GetEnableExternalNetworking() {
			conf.Network = config.NetworkSandbox
		} else {
			conf.Network = config.NetworkNone
		}
	}

	// Use memory overlay for root to avoid permission denied on host root,
	// but allow submounts to be writable if they are bind mounts.
	if err := conf.Overlay2.Set("root:memory"); err != nil {
		return nil, fmt.Errorf("failed to set Overlay2 to root:memory: %v", err)
	}

	return spec, nil
}
