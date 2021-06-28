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
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

// PortForward implements subcommands.Command for the "portforward" command.
type PortForward struct {
	portNum int
	stream  string
}

// Name implements subcommands.Command.Name.
func (*PortForward) Name() string {
	return "port-forward"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*PortForward) Synopsis() string {
	return "port forward to a secure container"
}

// Usage implements subcommands.Command.Usage.
func (*PortForward) Usage() string {
	return `port-forward CONTAINER_ID [LOCAL_PORT:]REMOTE_PORT - port forward to a secure container.

Open a local port and forward connections to another port inside the specified
container.

EXAMPLES:

The following will forward connections on local port 8080 to port 80 in the
container named 'nginx':

	# runsc port-forward nginx 8080:80
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (p *PortForward) SetFlags(f *flag.FlagSet) {}

// Execute implements subcommands.Command.Execute.
func (p *PortForward) Execute(ctx context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	conf := args[0].(*config.Config)
	// Requires at least the container id and port.
	if f.NArg() != 2 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	id := f.Arg(0)
	portStr := f.Arg(1)

	c, err := container.Load(conf.RootDir, container.FullID{ContainerID: id}, container.LoadOpts{})
	if err != nil {
		Fatalf("loading container: %v", err)
	}

	// Allow forwarding to a local port.
	ports := strings.Split(portStr, ":")
	if len(ports) != 2 {
		Fatalf("invalid port string %q", portStr)
	}

	localPort, err := strconv.Atoi(ports[0])
	if err != nil {
		Fatalf("invalid port string %q: %v", portStr, err)
	}
	portNum, err := strconv.Atoi(ports[1])
	if err != nil {
		Fatalf("invalid port string %q: %v", portStr, err)
	}

	// Start port forwarding with the local port.
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)
	wg.Add(1)
	go func(localPort, portNum int) {
		defer cancel()
		fmt.Printf("Forwarding local port %d to %d...\n", localPort, portNum)
		if err := localForward(ctx, c, localPort, portNum); err != nil {
			log.Warningf("port forwarding: %v", err)
		}
		wg.Done()
	}(localPort, portNum)

	// Exit port forwarding if the container exits.
	go func() {
		// Cancel port forwarding after Wait returns regardless of return
		// value as err may indicate sandbox has terminated already.
		_, _ = c.Wait()
		fmt.Printf("Container %q stopped. Exiting...\n", c.ID)
		cancel()
	}()

	// Wait for ^C from the user.
	go func() {
		sig := waitSignal()
		fmt.Printf("Got %v, Exiting...\n", sig)
		cancel()
	}()

	// Wait on a WaitGroup for port forwarding to clean up before exiting.
	wg.Wait()

	return subcommands.ExitSuccess
}

// localForward starts port forwarding from the given local port.
func localForward(ctx context.Context, c *container.Container, localPort, containerPort int) error {
	l, err := net.Listen("tcp", ":"+strconv.Itoa(localPort))
	if err != nil {
		return err
	}
	defer l.Close()

	go func() {
		for {
			// Exit if the context is done.
			select {
			case <-ctx.Done():
				return
			default:
			}

			localConn, err := l.Accept()
			if err != nil {
				log.Warningf("accepting local connection: %v", err)
				continue
			}

			// Dispatch a new goroutine to handle the new connection.
			go func() {
				defer localConn.Close()
				fmt.Println("Forwarding new connection...")
				err := portCopy(ctx, c, localConn, containerPort)
				if err != nil {
					log.Warningf("port forwarding: %v", err)
				}
				fmt.Println("Finished forwarding connection...")
			}()
		}
	}()

	// Wait until the context is done. When the context is done the listener is
	// closed and connections on the local port are no longer accepted.
	<-ctx.Done()
	return ctx.Err()
}

// portCopy creates a UDS and begins copying data to and from the local
// connection.
func portCopy(ctx context.Context, c *container.Container, localConn net.Conn, port int) error {
	// Create a new path address for the UDS.
	addr, err := tmpUDSAddr()
	if err != nil {
		return err
	}

	// Create the UDS and Listen on it.
	l, err := net.Listen("unix", addr)
	if err != nil {
		return err
	}
	defer l.Close()

	// Open the UDS as a File so it can be donated to the sentry.
	streamFile, err := openStream(addr)
	if err != nil {
		return fmt.Errorf("opening uds stream: %v", err)
	}
	defer streamFile.Close()

	// Request port forwarding from the sentry. This request will return
	// immediately after port forwarding is started and connection state is
	// handled via the UDS from then on.
	if err := c.PortForward(&boot.PortForwardOpts{
		Port:        port,
		FilePayload: urpc.FilePayload{Files: []*os.File{streamFile}},
	}); err != nil {
		return fmt.Errorf("PortForward: %v", err)
	}

	// We have already opened a single connection on the UDS and passed the
	// client end to the sentry. We accept the connection now in order to get
	// the other half of the connection.
	conn, err := l.Accept()
	if err != nil {
		return err
	}

	toErrCh := make(chan error)
	fromErrCh := make(chan error)
	// Copy data from the local port to the UDS.
	go func() {
		defer conn.Close()
		defer localConn.Close()
		log.Debugf("Start copying from %q to %q", localConn.LocalAddr().String(), conn.LocalAddr().String())
		_, err := io.Copy(localConn, conn)
		log.Debugf("Stopped copying from %q to %q", localConn.LocalAddr().String(), conn.LocalAddr().String())
		toErrCh <- err
		close(toErrCh)
	}()

	// Copy data from the UDS to the local port.
	go func() {
		defer conn.Close()
		defer localConn.Close()
		log.Debugf("Start copying from %q to %q", conn.LocalAddr().String(), localConn.LocalAddr().String())
		_, err := io.Copy(conn, localConn)
		log.Debugf("Stopped copying from %q to %q", conn.LocalAddr().String(), localConn.LocalAddr().String())
		fromErrCh <- err
		close(fromErrCh)
	}()

	// Wait for either end of the connection to finish and get the first error.
	var firstErr error
	select {
	case e := <-toErrCh:
		firstErr = e
	case e := <-fromErrCh:
		firstErr = e
	case <-ctx.Done():
		log.Debugf("Port forwarding connection cancelled for %q: %v", localConn.LocalAddr().String(), ctx.Err())
		return ctx.Err()
	}

	// Wait for the 'to' copy side to finish.
	select {
	case e := <-toErrCh:
		if firstErr == nil {
			firstErr = e
		}
	case <-ctx.Done():
		log.Debugf("Port forwarding connection cancelled for %q: %v", localConn.LocalAddr().String(), ctx.Err())
		return ctx.Err()
	}

	// Wait for the 'from' copy side to finish.
	select {
	case e := <-fromErrCh:
		if firstErr == nil {
			firstErr = e
		}
	case <-ctx.Done():
		log.Debugf("Port forwarding connection cancelled for %q: %v", localConn.LocalAddr().String(), ctx.Err())
		return ctx.Err()
	}

	return firstErr
}

// tmpUDS generates a temporary UDS addr.
func tmpUDSAddr() (string, error) {
	tmpFile, err := ioutil.TempFile("", "runsc-port-forward")
	if err != nil {
		return "", err
	}
	path := tmpFile.Name()
	// Remove the tempfile and just use it's name.
	os.Remove(path)

	return path, nil
}

// openStream opens a UDS as a socket and returns the file descriptor in an
// os.File object.
func openStream(name string) (*os.File, error) {
	// The net package will abstract the fd, so we use raw syscalls.
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}

	// We are acting as a client so we will connect to the socket.
	if err = syscall.Connect(fd, &syscall.SockaddrUnix{Name: name}); err != nil {
		return nil, err
	}

	// Return a File so that we can pass it to the Sentry.
	return os.NewFile(uintptr(fd), name), nil
}

// waitSignal waits for SIGINT, SIGQUIT, or SIGTERM from the user.
func waitSignal() os.Signal {
	ch := make(chan os.Signal, 2)
	signal.Notify(
		ch,
		syscall.SIGINT,
		syscall.SIGQUIT,
		syscall.SIGTERM,
	)
	for {
		sig := <-ch
		switch sig {
		case syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM:
			return sig
		}
	}
}
