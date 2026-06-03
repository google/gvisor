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
	"strings"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
)

const (
	flagBind       = "bind"
	flagRoBind     = "ro-bind"
	flagTmpfs      = "tmpfs"
	flagUnshareNet = "unshare-net"
	flagChdir      = "chdir"
	flagHelp       = "help"
)

// Cli implements subcommands.Command for the "bwrap" command.
type Cli struct {
	// Placeholders for bwrap flags.
	bind       string
	roBind     string
	tmpfs      string
	unshareNet bool
	chdir      string
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
	f.StringVar(&c.chdir, flagChdir, "", "Change directory to DIR.")

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
	cfg := &bwrapConfig{}
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
		case flagChdir:
			i, err = cfg.parseChdir(bwrapArgs, i)
		default:
			return nil, fmt.Errorf("bwrap: Unknown option: %s", arg)
		}
		if err != nil {
			return nil, err
		}
	}
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
