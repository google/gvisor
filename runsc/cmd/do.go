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

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"syscall"

	"flag"
	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/runsc/boot"
	"gvisor.googlesource.com/gvisor/runsc/container"
	"gvisor.googlesource.com/gvisor/runsc/specutils"
)

// Do implements subcommands.Command for the "do" command. It sets up a simple
// sandbox and executes the command inside it. See Usage() for more details.
type Do struct {
	root string
	cwd  string
}

// Name implements subcommands.Command.Name.
func (*Do) Name() string {
	return "do"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Do) Synopsis() string {
	return "Simplistic way to execute a command inside the sandbox. It's to be used for testing only."
}

// Usage implements subcommands.Command.Usage.
func (*Do) Usage() string {
	return `do [flags] <cmd> - runs a command.

This command starts a sandbox with host filesystem mounted inside as readonly,
with a writable tmpfs overlay on top of it. The given command is executed inside
the sandbox. It's to be used to quickly test applications without having to
install or run docker. It doesn't give nearly as many options and it's to be
used for testing only.
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *Do) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.root, "root", "/", `path to the root directory, defaults to "/"`)
	f.StringVar(&c.cwd, "cwd", ".", `path to the current directory, defaults to the current directory`)
}

// Execute implements subcommands.Command.Execute.
func (c *Do) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if len(f.Args()) == 0 {
		c.Usage()
		return subcommands.ExitUsageError
	}

	conf := args[0].(*boot.Config)
	waitStatus := args[1].(*syscall.WaitStatus)

	// Map the entire host file system, but make it readonly with a writable
	// overlay on top (ignore --overlay option).
	conf.Overlay = true

	hostname, err := os.Hostname()
	if err != nil {
		Fatalf("Error to retrieve hostname: %v", err)
	}

	absRoot, err := resolvePath(c.root)
	if err != nil {
		Fatalf("Error resolving root: %v", err)
	}
	absCwd, err := resolvePath(c.cwd)
	if err != nil {
		Fatalf("Error resolving current directory: %v", err)
	}

	spec := &specs.Spec{
		Root: &specs.Root{
			Path:     absRoot,
			Readonly: true,
		},
		Process: &specs.Process{
			Cwd:          absCwd,
			Args:         f.Args(),
			Env:          os.Environ(),
			Capabilities: specutils.AllCapabilities(),
		},
		Hostname: hostname,
	}

	specutils.LogSpec(spec)

	out, err := json.Marshal(spec)
	if err != nil {
		Fatalf("Error to marshal spec: %v", err)
	}
	tmpDir, err := ioutil.TempDir("", "runsc-do")
	if err != nil {
		Fatalf("Error to create tmp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	log.Infof("Changing configuration RootDir to %q", tmpDir)
	conf.RootDir = tmpDir

	cfgPath := filepath.Join(tmpDir, "config.json")
	if err := ioutil.WriteFile(cfgPath, out, 0755); err != nil {
		Fatalf("Error write spec: %v", err)
	}

	// No network support yet.
	conf.Network = boot.NetworkNone

	id := fmt.Sprintf("runcs-do-%06d", rand.Int31n(1000000))
	ws, err := container.Run(id, spec, conf, tmpDir, "", "", "")
	if err != nil {
		Fatalf("running container: %v", err)
	}

	*waitStatus = ws
	return subcommands.ExitSuccess
}

func resolvePath(path string) (string, error) {
	var err error
	path, err = filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolving %q: %v", path, err)
	}
	path = filepath.Clean(path)
	if err := syscall.Access(path, 0); err != nil {
		return "", fmt.Errorf("unable to access %q: %v", path, err)
	}
	return path, nil
}
