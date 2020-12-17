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
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

// Debug implements subcommands.Command for the "debug" command.
type Debug struct {
	pid          int
	stacks       bool
	signal       int
	profileHeap  string
	profileCPU   string
	profileBlock string
	profileMutex string
	trace        string
	strace       string
	logLevel     string
	logPackets   string
	duration     time.Duration
	ps           bool
}

// Name implements subcommands.Command.
func (*Debug) Name() string {
	return "debug"
}

// Synopsis implements subcommands.Command.
func (*Debug) Synopsis() string {
	return "shows a variety of debug information"
}

// Usage implements subcommands.Command.
func (*Debug) Usage() string {
	return `debug [flags] <container id>`
}

// SetFlags implements subcommands.Command.
func (d *Debug) SetFlags(f *flag.FlagSet) {
	f.IntVar(&d.pid, "pid", 0, "sandbox process ID. Container ID is not necessary if this is set")
	f.BoolVar(&d.stacks, "stacks", false, "if true, dumps all sandbox stacks to the log")
	f.StringVar(&d.profileHeap, "profile-heap", "", "writes heap profile to the given file.")
	f.StringVar(&d.profileCPU, "profile-cpu", "", "writes CPU profile to the given file.")
	f.StringVar(&d.profileBlock, "profile-block", "", "writes block profile to the given file.")
	f.StringVar(&d.profileMutex, "profile-mutex", "", "writes mutex profile to the given file.")
	f.DurationVar(&d.duration, "duration", time.Second, "amount of time to wait for CPU and trace profiles")
	f.StringVar(&d.trace, "trace", "", "writes an execution trace to the given file.")
	f.IntVar(&d.signal, "signal", -1, "sends signal to the sandbox")
	f.StringVar(&d.strace, "strace", "", `A comma separated list of syscalls to trace. "all" enables all traces, "off" disables all`)
	f.StringVar(&d.logLevel, "log-level", "", "The log level to set: warning (0), info (1), or debug (2).")
	f.StringVar(&d.logPackets, "log-packets", "", "A boolean value to enable or disable packet logging: true or false.")
	f.BoolVar(&d.ps, "ps", false, "lists processes")
}

// Execute implements subcommands.Command.Execute.
func (d *Debug) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	var c *container.Container
	conf := args[0].(*config.Config)

	if d.pid == 0 {
		// No pid, container ID must have been provided.
		if f.NArg() != 1 {
			f.Usage()
			return subcommands.ExitUsageError
		}
		id := f.Arg(0)

		var err error
		c, err = container.Load(conf.RootDir, container.FullID{ContainerID: id}, container.LoadOpts{})
		if err != nil {
			return Errorf("loading container %q: %v", f.Arg(0), err)
		}
	} else {
		if f.NArg() != 0 {
			f.Usage()
			return subcommands.ExitUsageError
		}
		// Go over all sandboxes and find the one that matches PID.
		ids, err := container.List(conf.RootDir)
		if err != nil {
			return Errorf("listing containers: %v", err)
		}
		for _, id := range ids {
			candidate, err := container.Load(conf.RootDir, id, container.LoadOpts{Exact: true, SkipCheck: true})
			if err != nil {
				log.Warningf("Skipping container %q: %v", id, err)
				continue
			}
			if candidate.SandboxPid() == d.pid {
				c = candidate
				break
			}
		}
		if c == nil {
			return Errorf("container with PID %d not found", d.pid)
		}
	}

	if c.IsSandboxRunning() {
		return Errorf("container sandbox is not running")
	}
	log.Infof("Found sandbox %q, PID: %d", c.Sandbox.ID, c.Sandbox.Pid)

	if d.signal > 0 {
		log.Infof("Sending signal %d to process: %d", d.signal, c.Sandbox.Pid)
		if err := syscall.Kill(c.Sandbox.Pid, syscall.Signal(d.signal)); err != nil {
			return Errorf("failed to send signal %d to processs %d", d.signal, c.Sandbox.Pid)
		}
	}
	if d.stacks {
		log.Infof("Retrieving sandbox stacks")
		stacks, err := c.Sandbox.Stacks()
		if err != nil {
			return Errorf("retrieving stacks: %v", err)
		}
		log.Infof("     *** Stack dump ***\n%s", stacks)
	}
	if d.profileHeap != "" {
		f, err := os.Create(d.profileHeap)
		if err != nil {
			return Errorf(err.Error())
		}
		defer f.Close()

		if err := c.Sandbox.HeapProfile(f); err != nil {
			return Errorf(err.Error())
		}
		log.Infof("Heap profile written to %q", d.profileHeap)
	}
	if d.profileBlock != "" {
		f, err := os.Create(d.profileBlock)
		if err != nil {
			return Errorf(err.Error())
		}
		defer f.Close()

		if err := c.Sandbox.BlockProfile(f); err != nil {
			return Errorf(err.Error())
		}
		log.Infof("Block profile written to %q", d.profileBlock)
	}
	if d.profileMutex != "" {
		f, err := os.Create(d.profileMutex)
		if err != nil {
			return Errorf(err.Error())
		}
		defer f.Close()

		if err := c.Sandbox.MutexProfile(f); err != nil {
			return Errorf(err.Error())
		}
		log.Infof("Mutex profile written to %q", d.profileMutex)
	}

	delay := false
	if d.profileCPU != "" {
		delay = true
		f, err := os.Create(d.profileCPU)
		if err != nil {
			return Errorf(err.Error())
		}
		defer func() {
			f.Close()
			if err := c.Sandbox.StopCPUProfile(); err != nil {
				Fatalf(err.Error())
			}
			log.Infof("CPU profile written to %q", d.profileCPU)
		}()
		if err := c.Sandbox.StartCPUProfile(f); err != nil {
			return Errorf(err.Error())
		}
		log.Infof("CPU profile started for %v, writing to %q", d.duration, d.profileCPU)
	}
	if d.trace != "" {
		delay = true
		f, err := os.Create(d.trace)
		if err != nil {
			return Errorf(err.Error())
		}
		defer func() {
			f.Close()
			if err := c.Sandbox.StopTrace(); err != nil {
				Fatalf(err.Error())
			}
			log.Infof("Trace written to %q", d.trace)
		}()
		if err := c.Sandbox.StartTrace(f); err != nil {
			return Errorf(err.Error())
		}
		log.Infof("Tracing started for %v, writing to %q", d.duration, d.trace)
	}

	if d.strace != "" || len(d.logLevel) != 0 || len(d.logPackets) != 0 {
		args := control.LoggingArgs{}
		switch strings.ToLower(d.strace) {
		case "":
			// strace not set, nothing to do here.

		case "off":
			log.Infof("Disabling strace")
			args.SetStrace = true

		case "all":
			log.Infof("Enabling all straces")
			args.SetStrace = true
			args.EnableStrace = true

		default:
			log.Infof("Enabling strace for syscalls: %s", d.strace)
			args.SetStrace = true
			args.EnableStrace = true
			args.StraceWhitelist = strings.Split(d.strace, ",")
		}

		if len(d.logLevel) != 0 {
			args.SetLevel = true
			switch strings.ToLower(d.logLevel) {
			case "warning", "0":
				args.Level = log.Warning
			case "info", "1":
				args.Level = log.Info
			case "debug", "2":
				args.Level = log.Debug
			default:
				return Errorf("invalid log level %q", d.logLevel)
			}
			log.Infof("Setting log level %v", args.Level)
		}

		if len(d.logPackets) != 0 {
			args.SetLogPackets = true
			lp, err := strconv.ParseBool(d.logPackets)
			if err != nil {
				return Errorf("invalid value for log_packets %q", d.logPackets)
			}
			args.LogPackets = lp
			if args.LogPackets {
				log.Infof("Enabling packet logging")
			} else {
				log.Infof("Disabling packet logging")
			}
		}

		if err := c.Sandbox.ChangeLogging(args); err != nil {
			return Errorf(err.Error())
		}
		log.Infof("Logging options changed")
	}
	if d.ps {
		pList, err := c.Processes()
		if err != nil {
			Fatalf("getting processes for container: %v", err)
		}
		o, err := control.ProcessListToJSON(pList)
		if err != nil {
			Fatalf("generating JSON: %v", err)
		}
		log.Infof(o)
	}

	if delay {
		time.Sleep(d.duration)
	}

	return subcommands.ExitSuccess
}
