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
	"fmt"
	"strconv"
	"strings"
	"syscall"

	"context"
	"flag"
	"github.com/google/subcommands"
	"golang.org/x/sys/unix"
	"gvisor.googlesource.com/gvisor/runsc/boot"
	"gvisor.googlesource.com/gvisor/runsc/container"
)

// Kill implements subcommands.Command for the "kill" command.
type Kill struct{}

// Name implements subcommands.Command.Name.
func (*Kill) Name() string {
	return "kill"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Kill) Synopsis() string {
	return "sends a signal to the container"
}

// Usage implements subcommands.Command.Usage.
func (*Kill) Usage() string {
	return `kill <container id> [signal]`
}

// SetFlags implements subcommands.Command.SetFlags.
func (*Kill) SetFlags(f *flag.FlagSet) {
	// TODO: Implement this flag.  It is defined here just to
	// prevent runsc from crashing if it is passed.
	var all bool
	f.BoolVar(&all, "all", false, "send the specified signal to all processes inside the container")
}

// Execute implements subcommands.Command.Execute.
func (*Kill) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if f.NArg() == 0 || f.NArg() > 2 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	id := f.Arg(0)
	conf := args[0].(*boot.Config)

	c, err := container.Load(conf.RootDir, id)
	if err != nil {
		Fatalf("error loading container: %v", err)
	}

	// The OCI command-line spec says that the signal should be specified
	// via a flag, but runc (and things that call runc) pass it as an
	// argument.
	signal := f.Arg(2)
	if signal == "" {
		signal = "TERM"
	}

	sig, err := parseSignal(signal)
	if err != nil {
		Fatalf("%v", err)
	}
	if err := c.Signal(sig); err != nil {
		Fatalf("%v", err)
	}
	return subcommands.ExitSuccess
}

func parseSignal(s string) (syscall.Signal, error) {
	n, err := strconv.Atoi(s)
	if err == nil {
		sig := syscall.Signal(n)
		for _, msig := range signalMap {
			if sig == msig {
				return sig, nil
			}
		}
		return -1, fmt.Errorf("unknown signal %q", s)
	}
	if sig, ok := signalMap[strings.TrimPrefix(strings.ToUpper(s), "SIG")]; ok {
		return sig, nil
	}
	return -1, fmt.Errorf("unknown signal %q", s)
}

var signalMap = map[string]syscall.Signal{
	"ABRT":   unix.SIGABRT,
	"ALRM":   unix.SIGALRM,
	"BUS":    unix.SIGBUS,
	"CHLD":   unix.SIGCHLD,
	"CLD":    unix.SIGCLD,
	"CONT":   unix.SIGCONT,
	"FPE":    unix.SIGFPE,
	"HUP":    unix.SIGHUP,
	"ILL":    unix.SIGILL,
	"INT":    unix.SIGINT,
	"IO":     unix.SIGIO,
	"IOT":    unix.SIGIOT,
	"KILL":   unix.SIGKILL,
	"PIPE":   unix.SIGPIPE,
	"POLL":   unix.SIGPOLL,
	"PROF":   unix.SIGPROF,
	"PWR":    unix.SIGPWR,
	"QUIT":   unix.SIGQUIT,
	"SEGV":   unix.SIGSEGV,
	"STKFLT": unix.SIGSTKFLT,
	"STOP":   unix.SIGSTOP,
	"SYS":    unix.SIGSYS,
	"TERM":   unix.SIGTERM,
	"TRAP":   unix.SIGTRAP,
	"TSTP":   unix.SIGTSTP,
	"TTIN":   unix.SIGTTIN,
	"TTOU":   unix.SIGTTOU,
	"URG":    unix.SIGURG,
	"USR1":   unix.SIGUSR1,
	"USR2":   unix.SIGUSR2,
	"VTALRM": unix.SIGVTALRM,
	"WINCH":  unix.SIGWINCH,
	"XCPU":   unix.SIGXCPU,
	"XFSZ":   unix.SIGXFSZ,
}
