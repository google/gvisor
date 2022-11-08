// Copyright 2022 The gVisor Authors.
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

// Package main implements a tool that can save and replay messages from
// issued from remote.Remote.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/tools/tracereplay"
)

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(&saveCmd{}, "")
	subcommands.Register(&replayCmd{}, "")
	flag.CommandLine.Parse(os.Args[1:])
	os.Exit(int(subcommands.Execute(context.Background())))
}

// saveCmd implements subcommands.Command for the "save" command.
type saveCmd struct {
	endpoint string
	out      string
	prefix   string
}

// Name implements subcommands.Command.
func (*saveCmd) Name() string {
	return "save"
}

// Synopsis implements subcommands.Command.
func (*saveCmd) Synopsis() string {
	return "save trace sessions to files"
}

// Usage implements subcommands.Command.
func (*saveCmd) Usage() string {
	return `save [flags] - save trace sessions to files
`
}

// SetFlags implements subcommands.Command.
func (c *saveCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.endpoint, "endpoint", "", "path to trace server endpoint to connect")
	f.StringVar(&c.out, "out", "./replay", "path to a directory where trace files will be saved")
	f.StringVar(&c.prefix, "prefix", "client-", "name to be prefixed to each trace file")
}

// Execute implements subcommands.Command.
func (c *saveCmd) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unexpected argument: %s\n", f.Args())
		return subcommands.ExitUsageError
	}
	if len(c.endpoint) == 0 {
		fmt.Fprintf(os.Stderr, "--endpoint is required\n")
		return subcommands.ExitUsageError
	}
	_ = os.Remove(c.endpoint)

	server := tracereplay.NewSave(c.endpoint, c.out, c.prefix)
	defer server.Close()

	if err := server.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "starting server: %v\n", err)
		return subcommands.ExitFailure
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)

	done := make(chan struct{})
	go func() {
		<-ch
		fmt.Printf("Ctrl-C pressed, stopping.\n")
		done <- struct{}{}
	}()

	fmt.Printf("Listening on %q. Press ctrl-C to stop...\n", c.endpoint)
	<-done
	return subcommands.ExitSuccess
}

// replayCmd implements subcommands.Command for the "replay" command.
type replayCmd struct {
	endpoint string
	in       string
}

// Name implements subcommands.Command.
func (*replayCmd) Name() string {
	return "replay"
}

// Synopsis implements subcommands.Command.
func (*replayCmd) Synopsis() string {
	return "replay a trace session from a file"
}

// Usage implements subcommands.Command.
func (*replayCmd) Usage() string {
	return `replay [flags] - replay a trace session from a file
`
}

// SetFlags implements subcommands.Command.
func (c *replayCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.endpoint, "endpoint", "", "path to trace server endpoint to connect")
	f.StringVar(&c.in, "in", "", "path to trace file containing messages to be replayed")
}

// Execute implements subcommands.Command.
func (c *replayCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if f.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unexpected argument: %s\n", f.Args())
		return subcommands.ExitUsageError
	}
	if len(c.in) == 0 {
		fmt.Fprintf(os.Stderr, "--in is required\n")
		return subcommands.ExitUsageError
	}

	r := tracereplay.Replay{
		Endpoint: c.endpoint,
		In:       c.in,
	}
	if err := r.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}
