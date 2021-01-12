// Copyright 2018 The containerd Authors.
// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package cli defines the command line interface for the V1 shim.
package cli

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/containerd/containerd/events"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/sys"
	"github.com/containerd/containerd/sys/reaper"
	"github.com/containerd/ttrpc"
	"github.com/containerd/typeurl"
	"github.com/gogo/protobuf/types"
	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/shim/runsc"
	"gvisor.dev/gvisor/pkg/shim/v1/shim"
)

var (
	debugFlag            bool
	namespaceFlag        string
	socketFlag           string
	addressFlag          string
	workdirFlag          string
	runtimeRootFlag      string
	containerdBinaryFlag string
	shimConfigFlag       string
)

// Containerd defaults to runc, unless another runtime is explicitly specified.
// We keep the same default to make the default behavior consistent.
const defaultRoot = "/run/containerd/runc"

func init() {
	flag.BoolVar(&debugFlag, "debug", false, "enable debug output in logs")
	flag.StringVar(&namespaceFlag, "namespace", "", "namespace that owns the shim")
	flag.StringVar(&socketFlag, "socket", "", "abstract socket path to serve")
	flag.StringVar(&addressFlag, "address", "", "grpc address back to main containerd")
	flag.StringVar(&workdirFlag, "workdir", "", "path used to storge large temporary data")
	flag.StringVar(&runtimeRootFlag, "runtime-root", defaultRoot, "root directory for the runtime")

	// Currently, the `containerd publish` utility is embedded in the
	// daemon binary.  The daemon invokes `containerd-shim
	// -containerd-binary ...` with its own os.Executable() path.
	flag.StringVar(&containerdBinaryFlag, "containerd-binary", "containerd", "path to containerd binary (used for `containerd publish`)")
	flag.StringVar(&shimConfigFlag, "config", "/etc/containerd/runsc.toml", "path to the shim configuration file")
}

// Main is the main entrypoint.
func Main() {
	flag.Parse()

	// This is a hack. Exec current process to run standard containerd-shim
	// if runtime root is not `runsc`. We don't need this for shim v2 api.
	if filepath.Base(runtimeRootFlag) != "runsc" {
		if err := executeRuncShim(); err != nil {
			fmt.Fprintf(os.Stderr, "gvisor-containerd-shim: %s\n", err)
			os.Exit(1)
		}
	}

	// Run regular shim if needed.
	if err := executeShim(); err != nil {
		fmt.Fprintf(os.Stderr, "gvisor-containerd-shim: %s\n", err)
		os.Exit(1)
	}
}

// executeRuncShim execs current process to a containerd-shim process and
// retains all flags and envs.
func executeRuncShim() error {
	c, err := loadConfig(shimConfigFlag)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to load shim config: %w", err)
	}
	shimPath := c.RuncShim
	if shimPath == "" {
		shimPath, err = exec.LookPath("containerd-shim")
		if err != nil {
			return fmt.Errorf("lookup containerd-shim failed: %w", err)
		}
	}

	args := append([]string{shimPath}, os.Args[1:]...)
	if err := syscall.Exec(shimPath, args, os.Environ()); err != nil {
		return fmt.Errorf("exec containerd-shim @ %q failed: %w", shimPath, err)
	}
	return nil
}

func executeShim() error {
	// start handling signals as soon as possible so that things are
	// properly reaped or if runtime exits before we hit the handler.
	signals, err := setupSignals()
	if err != nil {
		return err
	}
	path, err := os.Getwd()
	if err != nil {
		return err
	}
	server, err := ttrpc.NewServer(ttrpc.WithServerHandshaker(ttrpc.UnixSocketRequireSameUser()))
	if err != nil {
		return fmt.Errorf("failed creating server: %w", err)
	}
	c, err := loadConfig(shimConfigFlag)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to load shim config: %w", err)
	}
	sv, err := shim.NewService(
		shim.Config{
			Path:        path,
			Namespace:   namespaceFlag,
			WorkDir:     workdirFlag,
			RuntimeRoot: runtimeRootFlag,
			RunscConfig: c.RunscConfig,
		},
		&remoteEventsPublisher{address: addressFlag},
	)
	if err != nil {
		return err
	}
	registerShimService(server, sv)
	if err := serve(server, socketFlag); err != nil {
		return err
	}
	return handleSignals(signals, server, sv)
}

// serve serves the ttrpc API over a unix socket at the provided path this
// function does not block.
func serve(server *ttrpc.Server, path string) error {
	var (
		l   net.Listener
		err error
	)
	if path == "" {
		l, err = net.FileListener(os.NewFile(3, "socket"))
	} else {
		if len(path) > 106 {
			return fmt.Errorf("%q: unix socket path too long (> 106)", path)
		}
		l, err = net.Listen("unix", "\x00"+path)
	}
	if err != nil {
		return err
	}
	go func() {
		defer l.Close()
		err := server.Serve(context.Background(), l)
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Fatalf("ttrpc server failure: %v", err)
		}
	}()
	return nil
}

// setupSignals creates a new signal handler for all signals and sets the shim
// as a sub-reaper so that the container processes are reparented.
func setupSignals() (chan os.Signal, error) {
	signals := make(chan os.Signal, 32)
	signal.Notify(signals, unix.SIGTERM, unix.SIGINT, unix.SIGCHLD, unix.SIGPIPE)
	// make sure runc is setup to use the monitor for waiting on processes.
	// TODO(random-liu): Move shim/reaper.go to a separate package.
	runsc.Monitor = reaper.Default
	// Set the shim as the subreaper for all orphaned processes created by
	// the container.
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return nil, err
	}
	return signals, nil
}

func handleSignals(signals chan os.Signal, server *ttrpc.Server, sv *shim.Service) error {
	var (
		termOnce sync.Once
		done     = make(chan struct{})
	)

	for {
		select {
		case <-done:
			return nil
		case s := <-signals:
			switch s {
			case unix.SIGCHLD:
				if _, err := sys.Reap(false); err != nil {
					log.Printf("reap error: %v", err)
				}
			case unix.SIGTERM, unix.SIGINT:
				go termOnce.Do(func() {
					ctx := context.TODO()
					if err := server.Shutdown(ctx); err != nil {
						log.Printf("failed to shutdown server: %v", err)
					}
					// Ensure our child is dead if any.
					sv.Kill(ctx, &KillRequest{
						Signal: uint32(syscall.SIGKILL),
						All:    true,
					})
					sv.Delete(context.Background(), &types.Empty{})
					close(done)
				})
			case unix.SIGPIPE:
			}
		}
	}
}

type remoteEventsPublisher struct {
	address string
}

func (l *remoteEventsPublisher) Publish(ctx context.Context, topic string, event events.Event) error {
	ns, _ := namespaces.Namespace(ctx)
	encoded, err := typeurl.MarshalAny(event)
	if err != nil {
		return err
	}
	data, err := encoded.Marshal()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, containerdBinaryFlag, "--address", l.address, "publish", "--topic", topic, "--namespace", ns)
	cmd.Stdin = bytes.NewReader(data)
	c, err := reaper.Default.Start(cmd)
	if err != nil {
		return err
	}
	status, err := reaper.Default.Wait(cmd, c)
	if err != nil {
		return fmt.Errorf("failed to publish event: %w", err)
	}
	if status != 0 {
		return fmt.Errorf("failed to publish event: status %d", status)
	}
	return nil
}
