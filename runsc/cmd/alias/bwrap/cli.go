// Copyright 2025 The gVisor Authors.
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

package bwrap

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
)

const (
	flagBind          = "bind"
	flagRoBind        = "ro-bind"
	flagTmpfs         = "tmpfs"
	flagUnshareNet    = "unshare-net"
	flagChdir         = "chdir"
	flagHelp          = "help"
	flagSetEnv        = "setenv"
	flagClearEnv      = "clearenv"
	flagUnsetEnv      = "unsetenv"
	flagUID           = "uid"
	flagGID           = "gid"
	flagUnshareUser   = "unshare-user"
	flagUserns        = "userns"
	flagUnshareIPC    = "unshare-ipc"
	flagUnsharePID    = "unshare-pid"
	flagUnshareUTS    = "unshare-uts"
	flagHostname      = "hostname"
	flagProc          = "proc"
	flagUnshareCgroup = "unshare-cgroup"
	flagUnshareAll    = "unshare-all"
	flagShareNet      = "share-net"
	flagCapDrop       = "cap-drop"
	flagCapAdd        = "cap-add"
)

// Cli implements subcommands.Command for the "bwrap" command.
type Cli struct {
	// Placeholders for bwrap flags.
	bind          string
	roBind        string
	tmpfs         string
	unshareNet    bool
	shareNet      bool
	chdir         string
	setEnv        string
	clearEnv      bool
	unsetEnv      string
	uid           int
	gid           int
	unshareUser   bool
	unshareIPC    bool
	unsharePID    bool
	unshareUTS    bool
	unshareCgroup bool
	unshareAll    bool
	hostname      string
	proc          string
	capDrop       string
	capAdd        string
}

// Name implements subcommands.Command.Name.
func (*Cli) Name() string {
	return "bwrap"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Cli) Synopsis() string {
	return "Bubblewrap-compatible sandboxing command."
}

// Usage implements subcommands.Command.Usage.
func (*Cli) Usage() string {
	return "bwrap [flags] <cmd> - runs command in gVisor sandbox with a bubblewrap-like cli.\n"
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *Cli) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.bind, flagBind, "", "Bind mount SRC to DEST.")
	f.StringVar(&c.roBind, flagRoBind, "", "Read-only bind mount SRC to DEST.")
	f.StringVar(&c.tmpfs, flagTmpfs, "", "Mount tmpfs at DEST.")
	f.BoolVar(&c.unshareNet, flagUnshareNet, false, "Unshare network namespace.")
	f.BoolVar(&c.shareNet, flagShareNet, false, "Share network namespace.")
	f.StringVar(&c.chdir, flagChdir, "", "Change directory to DIR.")
	f.StringVar(&c.setEnv, flagSetEnv, "", "Set an environment variable")
	f.BoolVar(&c.clearEnv, flagClearEnv, false, "Unset all environment variables")
	f.StringVar(&c.unsetEnv, flagUnsetEnv, "", "Unset an environment variable")
	f.IntVar(&c.uid, flagUID, -1, "Custom uid in the sandbox (requires --unshare-user or --userns)")
	f.IntVar(&c.gid, flagGID, -1, "Custom gid in the sandbox (requires --unshare-user or --userns)")
	f.BoolVar(&c.unshareUser, flagUnshareUser, false, "Create new user namespace (may be automatically implied if not root)")
	f.BoolVar(&c.unshareIPC, flagUnshareIPC, false, "Create new ipc namespace")
	f.BoolVar(&c.unsharePID, flagUnsharePID, false, "Create new pid namespace")
	f.BoolVar(&c.unshareUTS, flagUnshareUTS, false, "Create new uts namespace")
	f.StringVar(&c.hostname, flagHostname, "", "Custom hostname in the sandbox")
	f.StringVar(&c.proc, flagProc, "", "Mount new procfs on DEST")
	f.BoolVar(&c.unshareCgroup, flagUnshareCgroup, false, "Create new cgroup namespace")
	f.BoolVar(&c.unshareAll, flagUnshareAll, false, "Unshare every namespace we support by default")
	f.StringVar(&c.capDrop, flagCapDrop, "", "Drop capabilities when running as privileged user")
	f.StringVar(&c.capAdd, flagCapAdd, "", "Add capabilities when running as privileged user")

	// Override the default usage function to print the custom usage message.
	f.Usage = func() {
		fmt.Fprint(f.Output(), c.Usage())
		fmt.Fprint(f.Output(), "\nSupported flags:\n")
		f.VisitAll(func(fl *flag.Flag) {
			fmt.Fprintf(f.Output(), "  --%-20s %s\n", fl.Name, fl.Usage)
		})
	}
}

// FetchSpec implements util.SubCommand.FetchSpec.
func (c *Cli) FetchSpec(_ *config.Config, _ *flag.FlagSet) (string, *specs.Spec, error) {
	return "", nil, nil
}

// parseBwrapArgs parses the bwrap arguments and returns a bwrapConfig struct.
func parseBwrapArgs(bwrapArgs []string) (*bwrapConfig, error) {
	cfg := &bwrapConfig{
		Env: os.Environ(),
		UID: -1,
		GID: -1,
	}
	var err error
	for i := 0; i < len(bwrapArgs); {
		arg := bwrapArgs[i]
		// Bwrap passes the rest of the arguments to the command.
		if arg == "--" {
			cfg.Args = bwrapArgs[i+1:]
			break
		}
		if !strings.HasPrefix(arg, "--") {
			// Bwrap does not allow flags with `-` prefix.
			if strings.HasPrefix(arg, "-") {
				return nil, fmt.Errorf("bwrap: Unknown option: %s", arg)
			}
			// If the argument is not a flag, pass the rest of the args as application arguments.
			cfg.Args = bwrapArgs[i:]
			break
		}
		// Parse the flags.
		strippedArg := strings.TrimPrefix(arg, "--")
		switch strippedArg {
		case flagBind:
			i, err = cfg.parseBind(bwrapArgs, i)
		case flagRoBind:
			i, err = cfg.parseRoBind(bwrapArgs, i)
		case flagTmpfs:
			i, err = cfg.parseTmpfs(bwrapArgs, i)
		case flagUnshareNet:
			i, err = cfg.parseUnshareNet(bwrapArgs, i)
		case flagShareNet:
			i, err = cfg.parseShareNet(bwrapArgs, i)
		case flagChdir:
			i, err = cfg.parseChdir(bwrapArgs, i)
		case flagSetEnv:
			i, err = cfg.parseSetEnv(bwrapArgs, i)
		case flagClearEnv:
			i, err = cfg.parseClearEnv(bwrapArgs, i)
		case flagUnsetEnv:
			i, err = cfg.parseUnsetEnv(bwrapArgs, i)
		case flagUID:
			i, err = cfg.parseUID(bwrapArgs, i)
		case flagGID:
			i, err = cfg.parseGID(bwrapArgs, i)
		case flagUnshareUser:
			i, err = cfg.parseUnshareUser(bwrapArgs, i)
		case flagUserns:
			i, err = cfg.parseUserns(bwrapArgs, i)
		case flagHostname:
			i, err = cfg.parseHostname(bwrapArgs, i)
		case flagUnshareIPC, flagUnsharePID, flagUnshareUTS, flagUnshareCgroup:
			i, err = cfg.parseNoopZeroArg(bwrapArgs, i)
		case flagProc:
			i, err = cfg.parseProc(bwrapArgs, i)
		case flagUnshareAll:
			i, err = cfg.parseUnshareAll(bwrapArgs, i)
		case flagCapDrop:
			i, err = cfg.parseCapDrop(bwrapArgs, i)
		case flagCapAdd:
			i, err = cfg.parseCapAdd(bwrapArgs, i)
		default:
			return nil, fmt.Errorf("bwrap: Unknown option: %s", arg)
		}
		if err != nil {
			return nil, err
		}
	}

	cfg.resolveEnv()

	if len(cfg.Args) == 0 || cfg.Args[0] == "" {
		return nil, fmt.Errorf("bwrap: no command specified")
	}
	return cfg, nil
}

func (c *Cli) getBwrapArgs(args []string) []string {
	delimiter := c.Name()
	// Skip all arguments until the delimiter.
	for i, arg := range args {
		if arg == delimiter {
			return args[i+1:]
		}
	}
	return nil
}

// Execute implements subcommands.Command.Execute.
func (c *Cli) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	conf := args[0].(*config.Config)
	waitStatus := args[1].(*unix.WaitStatus)

	// Parse bwrap arguments.
	bwrapArgs := c.getBwrapArgs(os.Args)
	cfg, err := parseBwrapArgs(bwrapArgs)
	if err != nil {
		return util.Errorf("bwrap: %v", err)
	}
	cfg.runscConfig = conf
	// When called as `runsc bwrap`, arguments start at index 2.
	return do(cfg, waitStatus)
}

/*
Flags parsing functions below.
*/

func (c *bwrapConfig) parseBind(args []string, i int) (int, error) {
	if i+2 >= len(args) {
		return i, fmt.Errorf("bwrap: --%s takes 2 arguments", flagBind)
	}
	mnt, err := c.newMountOp(args[i+1], args[i+2], MountOpBind)
	if err != nil {
		return i, err
	}
	c.Mounts = append(c.Mounts, mnt)
	return i + 3, nil
}

func (c *bwrapConfig) parseRoBind(args []string, i int) (int, error) {
	if i+2 >= len(args) {
		return i, fmt.Errorf("bwrap: --%s takes 2 arguments", flagRoBind)
	}
	mnt, err := c.newMountOp(args[i+1], args[i+2], MountOpRoBind)
	if err != nil {
		return i, err
	}
	c.Mounts = append(c.Mounts, mnt)
	return i + 3, nil
}

func (c *bwrapConfig) parseTmpfs(args []string, i int) (int, error) {
	if i+1 >= len(args) {
		return i, fmt.Errorf("bwrap: --%s takes 1 argument", flagTmpfs)
	}
	mnt, err := c.newMountOp("", args[i+1], MountOpTmpfs)
	if err != nil {
		return i, err
	}
	c.Mounts = append(c.Mounts, mnt)
	return i + 2, nil
}

func (c *bwrapConfig) parseUnshareNet(args []string, i int) (int, error) {
	c.UnshareNet = true
	return i + 1, nil
}

func (c *bwrapConfig) parseChdir(args []string, i int) (int, error) {
	if i+1 >= len(args) {
		return i, fmt.Errorf("--%s takes 1 argument", flagChdir)
	}
	c.Chdir = args[i+1]
	return i + 2, nil
}

func (c *bwrapConfig) parseSetEnv(args []string, i int) (int, error) {
	if i+2 >= len(args) {
		return i, fmt.Errorf("bwrap: --%s takes 2 arguments", flagSetEnv)
	}
	c.Env = append(c.Env, args[i+1]+"="+args[i+2])
	return i + 3, nil
}

func (c *bwrapConfig) parseClearEnv(args []string, i int) (int, error) {
	pwd, err := c.mapCWD()
	if err != nil {
		return i, fmt.Errorf("bwrap: failed to get current working directory: %v", err)
	}
	c.Env = nil
	if pwd != "" {
		c.Env = []string{"PWD=" + pwd}
	}
	c.UnsetEnv = nil
	return i + 1, nil
}

func (c *bwrapConfig) parseUnsetEnv(args []string, i int) (int, error) {
	if i+1 >= len(args) {
		return i, fmt.Errorf("bwrap: --%s takes 1 argument", flagUnsetEnv)
	}
	c.UnsetEnv = append(c.UnsetEnv, args[i+1])
	return i + 2, nil
}

func (c *bwrapConfig) parseUID(args []string, i int) (int, error) {
	if i+1 >= len(args) {
		return i, fmt.Errorf("bwrap: --%s takes 1 argument", flagUID)
	}
	uid, err := strconv.ParseUint(args[i+1], 10, 32)
	if err != nil {
		return i, fmt.Errorf("bwrap: Invalid uid %v: %v", args[i+1], err)
	}
	c.UID = int(uid)

	return i + 2, nil
}

func (c *bwrapConfig) parseGID(args []string, i int) (int, error) {
	if i+1 >= len(args) {
		return i, fmt.Errorf("bwrap: --%s takes 1 argument", flagGID)
	}
	gid, err := strconv.ParseUint(args[i+1], 10, 32)
	if err != nil {
		return i, fmt.Errorf("bwrap: Invalid gid %v: %v", args[i+1], err)
	}
	c.GID = int(gid)

	return i + 2, nil
}

func (c *bwrapConfig) parseUnshareUser(args []string, i int) (int, error) {
	c.UnshareUser = true
	return i + 1, nil
}

func (c *bwrapConfig) parseHostname(args []string, i int) (int, error) {
	if i+1 >= len(args) {
		return i, fmt.Errorf("bwrap: --%s takes 1 argument", flagHostname)
	}
	c.Hostname = args[i+1]
	return i + 2, nil
}

func (c *bwrapConfig) parseProc(args []string, i int) (int, error) {
	if i+1 >= len(args) {
		return i, fmt.Errorf("--%s takes 1 argument", flagProc)
	}

	dst := filepath.Clean(args[i+1])
	for _, m := range c.Mounts {
		if m.Type == MountOpProc && m.Dst == dst {
			return i + 2, nil
		}
	}
	mnt, err := c.newMountOp("", dst, MountOpProc)
	if err != nil {
		return i, err
	}
	c.Mounts = append(c.Mounts, mnt)

	return i + 2, nil
}

// TODO: b/518882196 - Support joining existing user namespaces.
// Currently, runsc cannot join an existing user namespace (specs.UserNamespace with Path != "").
func (c *bwrapConfig) parseUserns(args []string, i int) (int, error) {
	return i + 2, fmt.Errorf("bwrap: --userns is currently not supported by runsc")
}

// parseNoopZeroArg parses flags that are treated as no-ops.
// gVisor's Sentry kernel inherently virtualizes and isolates IPC, PID, UTS, and Cgroup
// namespaces by default. These flags are parsed solely for CLI compatibility
func (c *bwrapConfig) parseNoopZeroArg(args []string, i int) (int, error) {
	return i + 1, nil
}

func (c *bwrapConfig) parseShareNet(args []string, i int) (int, error) {
	c.UnshareNet = false
	return i + 1, nil
}

// Todo: - set unshare-user-try to true also after implementing it.
func (c *bwrapConfig) parseUnshareAll(args []string, i int) (int, error) {
	c.UnshareUser = true
	c.UnshareNet = true
	return i + 1, nil
}

func (c *bwrapConfig) parseCapDrop(args []string, i int) (int, error) {
	if i+1 >= len(args) {
		return i, fmt.Errorf("--%s takes 1 argument", flagCapDrop)
	}
	c.CapOps = append(c.CapOps, &CapOp{Type: CapOpDrop, Cap: args[i+1]})
	return i + 2, nil
}

func (c *bwrapConfig) parseCapAdd(args []string, i int) (int, error) {
	if i+1 >= len(args) {
		return i, fmt.Errorf("--%s takes 1 argument", flagCapAdd)
	}
	c.CapOps = append(c.CapOps, &CapOp{Type: CapOpAdd, Cap: args[i+1]})
	return i + 2, nil
}
