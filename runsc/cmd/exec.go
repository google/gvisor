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
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/console"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

// Exec implements subcommands.Command for the "exec" command.
type Exec struct {
	cwd string
	env stringSlice
	// user contains the UID and GID with which to run the new process.
	user            user
	extraKGIDs      stringSlice
	caps            stringSlice
	detach          bool
	processPath     string
	pidFile         string
	internalPidFile string

	// consoleSocket is the path to an AF_UNIX socket which will receive a
	// file descriptor referencing the master end of the console's
	// pseudoterminal.
	consoleSocket string
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
	f.StringVar(&ex.internalPidFile, "internal-pid-file", "", "filename that the container-internal pid will be written to")
	f.StringVar(&ex.consoleSocket, "console-socket", "", "path to an AF_UNIX socket which will receive a file descriptor referencing the master end of the console's pseudoterminal")
}

// Execute implements subcommands.Command.Execute. It starts a process in an
// already created container.
func (ex *Exec) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	conf := args[0].(*config.Config)
	e, id, err := ex.parseArgs(f, conf.EnableRaw)
	if err != nil {
		Fatalf("parsing process spec: %v", err)
	}
	waitStatus := args[1].(*unix.WaitStatus)

	c, err := container.Load(conf.RootDir, container.FullID{ContainerID: id}, container.LoadOpts{})
	if err != nil {
		Fatalf("loading sandbox: %v", err)
	}

	log.Debugf("Exec arguments: %+v", e)
	log.Debugf("Exec capabilities: %+v", e.Capabilities)

	// Replace empty settings with defaults from container.
	if e.WorkingDirectory == "" {
		e.WorkingDirectory = c.Spec.Process.Cwd
	}
	if e.Envv == nil {
		e.Envv, err = specutils.ResolveEnvs(c.Spec.Process.Env, ex.env)
		if err != nil {
			Fatalf("getting environment variables: %v", err)
		}
	}

	if e.Capabilities == nil {
		e.Capabilities, err = specutils.Capabilities(conf.EnableRaw, c.Spec.Process.Capabilities)
		if err != nil {
			Fatalf("creating capabilities: %v", err)
		}
		log.Infof("Using exec capabilities from container: %+v", e.Capabilities)
	}

	// containerd expects an actual process to represent the container being
	// executed. If detach was specified, starts a child in non-detach mode,
	// write the child's PID to the pid file. So when the container returns, the
	// child process will also return and signal containerd.
	if ex.detach {
		return ex.execChildAndWait(waitStatus)
	}
	return ex.exec(conf, c, e, waitStatus)
}

func (ex *Exec) exec(conf *config.Config, c *container.Container, e *control.ExecArgs, waitStatus *unix.WaitStatus) subcommands.ExitStatus {
	// Start the new process and get its pid.
	pid, err := c.Execute(conf, e)
	if err != nil {
		return Errorf("executing processes for container: %v", err)
	}

	if e.StdioIsPty {
		// Forward signals sent to this process to the foreground
		// process in the sandbox.
		stopForwarding := c.ForwardSignals(pid, true /* fgProcess */)
		defer stopForwarding()
	}

	// Write the sandbox-internal pid if required.
	if ex.internalPidFile != "" {
		pidStr := []byte(strconv.Itoa(int(pid)))
		if err := ioutil.WriteFile(ex.internalPidFile, pidStr, 0644); err != nil {
			return Errorf("writing internal pid file %q: %v", ex.internalPidFile, err)
		}
	}

	// Generate the pid file after the internal pid file is generated, so that
	// users can safely assume that the internal pid file is ready after
	// `runsc exec -d` returns.
	if ex.pidFile != "" {
		if err := ioutil.WriteFile(ex.pidFile, []byte(strconv.Itoa(os.Getpid())), 0644); err != nil {
			return Errorf("writing pid file: %v", err)
		}
	}

	// Wait for the process to exit.
	ws, err := c.WaitPID(pid)
	if err != nil {
		return Errorf("waiting on pid %d: %v", pid, err)
	}
	*waitStatus = ws
	return subcommands.ExitSuccess
}

func (ex *Exec) execChildAndWait(waitStatus *unix.WaitStatus) subcommands.ExitStatus {
	var args []string
	for _, a := range os.Args[1:] {
		if !strings.Contains(a, "detach") {
			args = append(args, a)
		}
	}

	// The command needs to write a pid file so that execChildAndWait can tell
	// when it has started. If no pid-file was provided, we should use a
	// filename in a temp directory.
	pidFile := ex.pidFile
	if pidFile == "" {
		tmpDir, err := ioutil.TempDir("", "exec-pid-")
		if err != nil {
			Fatalf("creating TempDir: %v", err)
		}
		defer os.RemoveAll(tmpDir)
		pidFile = filepath.Join(tmpDir, "pid")
		args = append(args, "--pid-file="+pidFile)
	}

	cmd := exec.Command(specutils.ExePath, args...)
	cmd.Args[0] = "runsc-exec"

	// Exec stdio defaults to current process stdio.
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// If the console control socket file is provided, then create a new
	// pty master/replica pair and set the TTY on the sandbox process.
	if ex.consoleSocket != "" {
		// Create a new TTY pair and send the master on the provided socket.
		tty, err := console.NewWithSocket(ex.consoleSocket)
		if err != nil {
			Fatalf("setting up console with socket %q: %v", ex.consoleSocket, err)
		}
		defer tty.Close()

		// Set stdio to the new TTY replica.
		cmd.Stdin = tty
		cmd.Stdout = tty
		cmd.Stderr = tty
		cmd.SysProcAttr = &unix.SysProcAttr{
			Setsid:  true,
			Setctty: true,
			// The Ctty FD must be the FD in the child process's FD
			// table. Since we set cmd.Stdin/Stdout/Stderr to the
			// tty FD, we can use any of 0, 1, or 2 here.
			// See https://github.com/golang/go/issues/29458.
			Ctty: 0,
		}
	}

	if err := cmd.Start(); err != nil {
		Fatalf("failure to start child exec process, err: %v", err)
	}

	log.Infof("Started child (PID: %d) to exec and wait: %s %s", cmd.Process.Pid, specutils.ExePath, args)

	// Wait for PID file to ensure that child process has started. Otherwise,
	// '--process' file is deleted as soon as this process returns and the child
	// may fail to read it.
	ready := func() (bool, error) {
		pidb, err := ioutil.ReadFile(pidFile)
		if err == nil {
			// File appeared, check whether pid is fully written.
			pid, err := strconv.Atoi(string(pidb))
			if err != nil {
				return false, nil
			}
			return pid == cmd.Process.Pid, nil
		}
		if pe, ok := err.(*os.PathError); !ok || pe.Err != unix.ENOENT {
			return false, err
		}
		// No file yet, continue to wait...
		return false, nil
	}
	if err := specutils.WaitForReady(cmd.Process.Pid, 10*time.Second, ready); err != nil {
		// Don't log fatal error here, otherwise it will override the error logged
		// by the child process that has failed to start.
		log.Warningf("Unexpected error waiting for PID file, err: %v", err)
		return subcommands.ExitFailure
	}

	*waitStatus = 0
	return subcommands.ExitSuccess
}

// parseArgs parses exec information from the command line or a JSON file
// depending on whether the --process flag was used. Returns an ExecArgs and
// the ID of the container to be used.
func (ex *Exec) parseArgs(f *flag.FlagSet, enableRaw bool) (*control.ExecArgs, string, error) {
	if ex.processPath == "" {
		// Requires at least a container ID and command.
		if f.NArg() < 2 {
			f.Usage()
			return nil, "", fmt.Errorf("both a container-id and command are required")
		}
		e, err := ex.argsFromCLI(f.Args()[1:], enableRaw)
		return e, f.Arg(0), err
	}
	// Requires only the container ID.
	if f.NArg() != 1 {
		f.Usage()
		return nil, "", fmt.Errorf("a container-id is required")
	}
	e, err := ex.argsFromProcessFile(enableRaw)
	return e, f.Arg(0), err
}

func (ex *Exec) argsFromCLI(argv []string, enableRaw bool) (*control.ExecArgs, error) {
	extraKGIDs := make([]auth.KGID, 0, len(ex.extraKGIDs))
	for _, s := range ex.extraKGIDs {
		kgid, err := strconv.Atoi(s)
		if err != nil {
			Fatalf("parsing GID: %s, %v", s, err)
		}
		extraKGIDs = append(extraKGIDs, auth.KGID(kgid))
	}

	var caps *auth.TaskCapabilities
	if len(ex.caps) > 0 {
		var err error
		caps, err = capabilities(ex.caps, enableRaw)
		if err != nil {
			return nil, fmt.Errorf("capabilities error: %v", err)
		}
	}

	return &control.ExecArgs{
		Argv:             argv,
		WorkingDirectory: ex.cwd,
		KUID:             ex.user.kuid,
		KGID:             ex.user.kgid,
		ExtraKGIDs:       extraKGIDs,
		Capabilities:     caps,
		StdioIsPty:       ex.consoleSocket != "",
		FilePayload:      urpc.FilePayload{[]*os.File{os.Stdin, os.Stdout, os.Stderr}},
	}, nil
}

func (ex *Exec) argsFromProcessFile(enableRaw bool) (*control.ExecArgs, error) {
	f, err := os.Open(ex.processPath)
	if err != nil {
		return nil, fmt.Errorf("error opening process file: %s, %v", ex.processPath, err)
	}
	defer f.Close()
	var p specs.Process
	if err := json.NewDecoder(f).Decode(&p); err != nil {
		return nil, fmt.Errorf("error parsing process file: %s, %v", ex.processPath, err)
	}
	return argsFromProcess(&p, enableRaw)
}

// argsFromProcess performs all the non-IO conversion from the Process struct
// to ExecArgs.
func argsFromProcess(p *specs.Process, enableRaw bool) (*control.ExecArgs, error) {
	// Create capabilities.
	var caps *auth.TaskCapabilities
	if p.Capabilities != nil {
		var err error
		// Starting from Docker 19, capabilities are explicitly set for exec (instead
		// of nil like before). So we can't distinguish 'exec' from
		// 'exec --privileged', as both specify CAP_NET_RAW. Therefore, filter
		// CAP_NET_RAW in the same way as container start.
		caps, err = specutils.Capabilities(enableRaw, p.Capabilities)
		if err != nil {
			return nil, fmt.Errorf("error creating capabilities: %v", err)
		}
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
		KUID:             auth.KUID(p.User.UID),
		KGID:             auth.KGID(p.User.GID),
		ExtraKGIDs:       extraKGIDs,
		Capabilities:     caps,
		StdioIsPty:       p.Terminal,
		FilePayload:      urpc.FilePayload{Files: []*os.File{os.Stdin, os.Stdout, os.Stderr}},
	}, nil
}

// capabilities takes a list of capabilities as strings and returns an
// auth.TaskCapabilities struct with those capabilities in every capability set.
// This mimics runc's behavior.
func capabilities(cs []string, enableRaw bool) (*auth.TaskCapabilities, error) {
	var specCaps specs.LinuxCapabilities
	for _, cap := range cs {
		specCaps.Ambient = append(specCaps.Ambient, cap)
		specCaps.Bounding = append(specCaps.Bounding, cap)
		specCaps.Effective = append(specCaps.Effective, cap)
		specCaps.Inheritable = append(specCaps.Inheritable, cap)
		specCaps.Permitted = append(specCaps.Permitted, cap)
	}
	// Starting from Docker 19, capabilities are explicitly set for exec (instead
	// of nil like before). So we can't distinguish 'exec' from
	// 'exec --privileged', as both specify CAP_NET_RAW. Therefore, filter
	// CAP_NET_RAW in the same way as container start.
	return specutils.Capabilities(enableRaw, &specCaps)
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
