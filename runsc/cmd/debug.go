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
	"os/signal"
	"strconv"
	"strings"
	"sync"
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
	delay        time.Duration
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
	f.DurationVar(&d.delay, "delay", time.Hour, "amount of time to delay for collecting heap and goroutine profiles.")
	f.DurationVar(&d.duration, "duration", time.Hour, "amount of time to wait for CPU and trace profiles.")
	f.StringVar(&d.trace, "trace", "", "writes an execution trace to the given file.")
	f.IntVar(&d.signal, "signal", -1, "sends signal to the sandbox")
	f.StringVar(&d.strace, "strace", "", `A comma separated list of syscalls to trace. "all" enables all traces, "off" disables all.`)
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

	if !c.IsSandboxRunning() {
		return Errorf("container sandbox is not running")
	}
	log.Infof("Found sandbox %q, PID: %d", c.Sandbox.ID, c.Sandbox.Pid)

	// Perform synchronous actions.
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

	// Open profiling files.
	var (
		heapFile  *os.File
		cpuFile   *os.File
		traceFile *os.File
		blockFile *os.File
		mutexFile *os.File
	)
	if d.profileHeap != "" {
		f, err := os.OpenFile(d.profileHeap, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return Errorf("error opening heap profile output: %v", err)
		}
		defer f.Close()
		heapFile = f
	}
	if d.profileCPU != "" {
		f, err := os.OpenFile(d.profileCPU, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return Errorf("error opening cpu profile output: %v", err)
		}
		defer f.Close()
		cpuFile = f
	}
	if d.trace != "" {
		f, err := os.OpenFile(d.trace, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return Errorf("error opening trace profile output: %v", err)
		}
		traceFile = f
	}
	if d.profileBlock != "" {
		f, err := os.OpenFile(d.profileBlock, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return Errorf("error opening blocking profile output: %v", err)
		}
		defer f.Close()
		blockFile = f
	}
	if d.profileMutex != "" {
		f, err := os.OpenFile(d.profileMutex, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return Errorf("error opening mutex profile output: %v", err)
		}
		defer f.Close()
		mutexFile = f
	}

	// Collect profiles.
	var (
		wg       sync.WaitGroup
		heapErr  error
		cpuErr   error
		traceErr error
		blockErr error
		mutexErr error
	)
	if heapFile != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			heapErr = c.Sandbox.HeapProfile(heapFile, d.delay)
		}()
	}
	if cpuFile != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cpuErr = c.Sandbox.CPUProfile(cpuFile, d.duration)
		}()
	}
	if traceFile != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			traceErr = c.Sandbox.Trace(traceFile, d.duration)
		}()
	}
	if blockFile != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			blockErr = c.Sandbox.BlockProfile(blockFile, d.duration)
		}()
	}
	if mutexFile != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mutexErr = c.Sandbox.MutexProfile(mutexFile, d.duration)
		}()
	}

	// Before sleeping, allow us to catch signals and try to exit
	// gracefully before just exiting. If we can't wait for wg, then
	// we will not be able to read the errors below safely.
	readyChan := make(chan struct{})
	go func() {
		defer close(readyChan)
		wg.Wait()
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-readyChan:
		break // Safe to proceed.
	case <-signals:
		log.Infof("caught signal, waiting at most one more second.")
		select {
		case <-signals:
			log.Infof("caught second signal, exiting immediately.")
			os.Exit(1) // Not finished.
		case <-time.After(time.Second):
			log.Infof("timeout, exiting.")
			os.Exit(1) // Not finished.
		case <-readyChan:
			break // Safe to proceed.
		}
	}

	// Collect all errors.
	errorCount := 0
	if heapErr != nil {
		errorCount++
		log.Infof("error collecting heap profile: %v", heapErr)
		os.Remove(heapFile.Name())
	}
	if cpuErr != nil {
		errorCount++
		log.Infof("error collecting cpu profile: %v", cpuErr)
		os.Remove(cpuFile.Name())
	}
	if traceErr != nil {
		errorCount++
		log.Infof("error collecting trace profile: %v", traceErr)
		os.Remove(traceFile.Name())
	}
	if blockErr != nil {
		errorCount++
		log.Infof("error collecting block profile: %v", blockErr)
		os.Remove(blockFile.Name())
	}
	if mutexErr != nil {
		errorCount++
		log.Infof("error collecting mutex profile: %v", mutexErr)
		os.Remove(mutexFile.Name())
	}

	if errorCount > 0 {
		return subcommands.ExitFailure
	}

	return subcommands.ExitSuccess
}
