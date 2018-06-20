// Copyright 2018 Google Inc.
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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"context"
	"flag"
	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/control"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	"gvisor.googlesource.com/gvisor/pkg/urpc"
	"gvisor.googlesource.com/gvisor/runsc/boot"
	"gvisor.googlesource.com/gvisor/runsc/container"
	"gvisor.googlesource.com/gvisor/runsc/specutils"
)

// Exec implements subcommands.Command for the "exec" command.
type Exec struct {
	cwd string
	env stringSlice
	// user contains the UID and GID with which to run the new process.
	user        user
	extraKGIDs  stringSlice
	caps        stringSlice
	detach      bool
	processPath string
	pidFile     string
}

// Name implements subcommands.Command.Name.
func (*Exec) Name() string {
	return "exec"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Exec) Synopsis() string {
	return "execute new process inside the container"
}

// Usage implements subcommands.Command.Usage.
func (*Exec) Usage() string {
	return `exec [command options] <container-id> <command> [command options] || --process process.json <container-id>


Where "<container-id>" is the name for the instance of the container and
"<command>" is the command to be executed in the container.
"<command>" can't be empty unless a "-process" flag provided.

EXAMPLE:
If the container is configured to run /bin/ps the following will
output a list of processes running in the container:

       # runc exec <container-id> ps

OPTIONS:
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (ex *Exec) SetFlags(f *flag.FlagSet) {
	f.StringVar(&ex.cwd, "cwd", "", "current working directory")
	f.Var(&ex.env, "env", "set environment variables (e.g. '-env PATH=/bin -env TERM=xterm')")
	f.Var(&ex.user, "user", "UID (format: <uid>[:<gid>])")
	f.Var(&ex.extraKGIDs, "additional-gids", "additional gids")
	f.Var(&ex.caps, "cap", "add a capability to the bounding set for the process")
	f.BoolVar(&ex.detach, "detach", false, "detach from the container's process")
	f.StringVar(&ex.processPath, "process", "", "path to the process.json")
	f.StringVar(&ex.pidFile, "pid-file", "", "filename that the container pid will be written to")
}

// Execute implements subcommands.Command.Execute. It starts a process in an
// already created container.
func (ex *Exec) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	e, id, err := ex.parseArgs(f)
	if err != nil {
		Fatalf("error parsing process spec: %v", err)
	}
	conf := args[0].(*boot.Config)
	waitStatus := args[1].(*syscall.WaitStatus)

	c, err := container.Load(conf.RootDir, id)
	if err != nil {
		Fatalf("error loading sandbox: %v", err)
	}

	if e.WorkingDirectory == "" {
		e.WorkingDirectory = c.Spec.Process.Cwd
	}

	if e.Envv == nil {
		e.Envv, err = resolveEnvs(c.Spec.Process.Env, ex.env)
		if err != nil {
			Fatalf("error getting environment variables: %v", err)
		}
	}

	// containerd expects an actual process to represent the container being
	// executed. If detach was specified, starts a child in non-detach mode,
	// write the child's PID to the pid file. So when the container returns, the
	// child process will also return and signal containerd.
	if ex.detach {
		return ex.execAndWait(waitStatus)
	}

	if ex.pidFile != "" {
		if err := ioutil.WriteFile(ex.pidFile, []byte(strconv.Itoa(os.Getpid())), 0644); err != nil {
			Fatalf("error writing pid file: %v", err)
		}
	}

	// Get the executable path, which is a bit tricky because we have to
	// inspect the environment PATH which is relative to the root path.
	// If the user is overriding environment variables, PATH may have been
	// overwritten.
	rootPath := c.Spec.Root.Path
	e.Filename, err = specutils.GetExecutablePath(e.Argv[0], rootPath, e.Envv)
	if err != nil {
		Fatalf("error getting executable path: %v", err)
	}

	ws, err := c.Execute(e)
	if err != nil {
		Fatalf("error getting processes for container: %v", err)
	}
	*waitStatus = ws
	return subcommands.ExitSuccess
}

func (ex *Exec) execAndWait(waitStatus *syscall.WaitStatus) subcommands.ExitStatus {
	binPath, err := specutils.BinPath()
	if err != nil {
		Fatalf("error getting bin path: %v", err)
	}
	var args []string
	for _, a := range os.Args[1:] {
		if !strings.Contains(a, "detach") {
			args = append(args, a)
		}
	}
	cmd := exec.Command(binPath, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		Fatalf("failure to start child exec process, err: %v", err)
	}

	log.Infof("Started child (PID: %d) to exec and wait: %s %s", cmd.Process.Pid, binPath, args)

	// Wait for PID file to ensure that child process has started. Otherwise,
	// '--process' file is deleted as soon as this process returns and the child
	// may fail to read it.
	ready := func() (bool, error) {
		_, err := os.Stat(ex.pidFile)
		if err == nil {
			// File appeared, we're done!
			return true, nil
		}
		if pe, ok := err.(*os.PathError); !ok || pe.Err != syscall.ENOENT {
			return false, err
		}
		// No file yet, continue to wait...
		return false, nil
	}
	if err := specutils.WaitForReady(cmd.Process.Pid, 10*time.Second, ready); err != nil {
		Fatalf("unexpected error waiting for PID file, err: %v", err)
	}

	*waitStatus = 0
	return subcommands.ExitSuccess
}

// parseArgs parses exec information from the command line or a JSON file
// depending on whether the --process flag was used. Returns an ExecArgs and
// the ID of the container to be used.
func (ex *Exec) parseArgs(f *flag.FlagSet) (*control.ExecArgs, string, error) {
	if ex.processPath == "" {
		// Requires at least a container ID and command.
		if f.NArg() < 2 {
			f.Usage()
			return nil, "", fmt.Errorf("both a container-id and command are required")
		}
		e, err := ex.argsFromCLI(f.Args()[1:])
		return e, f.Arg(0), err
	}
	// Requires only the container ID.
	if f.NArg() != 1 {
		f.Usage()
		return nil, "", fmt.Errorf("a container-id is required")
	}
	e, err := ex.argsFromProcessFile()
	return e, f.Arg(0), err
}

func (ex *Exec) argsFromCLI(argv []string) (*control.ExecArgs, error) {
	extraKGIDs := make([]auth.KGID, 0, len(ex.extraKGIDs))
	for _, s := range ex.extraKGIDs {
		kgid, err := strconv.Atoi(s)
		if err != nil {
			Fatalf("error parsing GID: %s, %v", s, err)
		}
		extraKGIDs = append(extraKGIDs, auth.KGID(kgid))
	}

	caps, err := capabilities(ex.caps)
	if err != nil {
		return nil, fmt.Errorf("capabilities error: %v", err)
	}

	return &control.ExecArgs{
		Argv:             argv,
		WorkingDirectory: ex.cwd,
		FilePayload:      urpc.FilePayload{Files: []*os.File{os.Stdin, os.Stdout, os.Stderr}},
		KUID:             ex.user.kuid,
		KGID:             ex.user.kgid,
		ExtraKGIDs:       extraKGIDs,
		Capabilities:     caps,
	}, nil
}

func (ex *Exec) argsFromProcessFile() (*control.ExecArgs, error) {
	f, err := os.Open(ex.processPath)
	if err != nil {
		return nil, fmt.Errorf("error opening process file: %s, %v", ex.processPath, err)
	}
	defer f.Close()
	var p specs.Process
	if err := json.NewDecoder(f).Decode(&p); err != nil {
		return nil, fmt.Errorf("error parsing process file: %s, %v", ex.processPath, err)
	}
	return argsFromProcess(&p)
}

// argsFromProcess performs all the non-IO conversion from the Process struct
// to ExecArgs.
func argsFromProcess(p *specs.Process) (*control.ExecArgs, error) {
	// Create capabilities.
	caps, err := specutils.Capabilities(p.Capabilities)
	if err != nil {
		return nil, fmt.Errorf("error creating capabilities: %v", err)
	}

	// Convert the spec's additional GIDs to KGIDs.
	extraKGIDs := make([]auth.KGID, 0, len(p.User.AdditionalGids))
	for _, GID := range p.User.AdditionalGids {
		extraKGIDs = append(extraKGIDs, auth.KGID(GID))
	}

	return &control.ExecArgs{
		Argv:             p.Args,
		Envv:             p.Env,
		WorkingDirectory: p.Cwd,
		FilePayload:      urpc.FilePayload{Files: []*os.File{os.Stdin, os.Stdout, os.Stderr}},
		KUID:             auth.KUID(p.User.UID),
		KGID:             auth.KGID(p.User.GID),
		ExtraKGIDs:       extraKGIDs,
		Capabilities:     caps,
	}, nil
}

// resolveEnvs transforms lists of environment variables into a single list of
// environment variables. If a variable is defined multiple times, the last
// value is used.
func resolveEnvs(envs ...[]string) ([]string, error) {
	// First create a map of variable names to values. This removes any
	// duplicates.
	envMap := make(map[string]string)
	for _, env := range envs {
		for _, str := range env {
			parts := strings.SplitN(str, "=", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid variable: %s", str)
			}
			envMap[parts[0]] = parts[1]
		}
	}
	// Reassemble envMap into a list of environment variables of the form
	// NAME=VALUE.
	env := make([]string, 0, len(envMap))
	for k, v := range envMap {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	return env, nil
}

// capabilities takes a list of capabilities as strings and returns an
// auth.TaskCapabilities struct with those capabilities in every capability set.
// This mimics runc's behavior.
func capabilities(cs []string) (*auth.TaskCapabilities, error) {
	var specCaps specs.LinuxCapabilities
	for _, cap := range cs {
		specCaps.Ambient = append(specCaps.Ambient, cap)
		specCaps.Bounding = append(specCaps.Bounding, cap)
		specCaps.Effective = append(specCaps.Effective, cap)
		specCaps.Inheritable = append(specCaps.Inheritable, cap)
		specCaps.Permitted = append(specCaps.Permitted, cap)
	}
	return specutils.Capabilities(&specCaps)
}

// stringSlice allows a flag to be used multiple times, where each occurrence
// adds a value to the flag. For example, a flag called "x" could be invoked
// via "runsc exec -x foo -x bar", and the corresponding stringSlice would be
// {"x", "y"}.
type stringSlice []string

// String implements flag.Value.String.
func (ss *stringSlice) String() string {
	return fmt.Sprintf("%v", *ss)
}

// Get implements flag.Value.Get.
func (ss *stringSlice) Get() interface{} {
	return ss
}

// Set implements flag.Value.Set.
func (ss *stringSlice) Set(s string) error {
	*ss = append(*ss, s)
	return nil
}

// user allows -user to convey a UID and, optionally, a GID separated by a
// colon.
type user struct {
	kuid auth.KUID
	kgid auth.KGID
}

func (u *user) String() string {
	return fmt.Sprintf("%+v", *u)
}

func (u *user) Get() interface{} {
	return u
}

func (u *user) Set(s string) error {
	parts := strings.SplitN(s, ":", 2)
	kuid, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("couldn't parse UID: %s", parts[0])
	}
	u.kuid = auth.KUID(kuid)
	if len(parts) > 1 {
		kgid, err := strconv.Atoi(parts[1])
		if err != nil {
			return fmt.Errorf("couldn't parse GID: %s", parts[1])
		}
		u.kgid = auth.KGID(kgid)
	}
	return nil
}
