// Copyright 2019 The gVisor Authors.
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

package main

import (
	"context"
	"io/ioutil"
	"log"
	"os"
	"time"

	"flag"
	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/runsc/testutil"
)

const fileContents = "foobarbaz"

// fdSender will open a file and send the FD over a unix domain socket.
type fdSender struct {
	socketPath string
}

// Name implements subcommands.Command.Name.
func (*fdSender) Name() string {
	return "fd_sender"
}

// Synopsis implements subcommands.Command.Synopsys.
func (*fdSender) Synopsis() string {
	return "creates a file and sends the FD over the socket"
}

// Usage implements subcommands.Command.Usage.
func (*fdSender) Usage() string {
	return "fd_sender <flags>"
}

// SetFlags implements subcommands.Command.SetFlags.
func (fds *fdSender) SetFlags(f *flag.FlagSet) {
	f.StringVar(&fds.socketPath, "socket", "", "path to socket")
}

// Execute implements subcommands.Command.Execute.
func (fds *fdSender) Execute(ctx context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if fds.socketPath == "" {
		log.Fatalf("socket flag must be set")
	}

	dir, err := ioutil.TempDir("", "")
	if err != nil {
		log.Fatalf("TempDir failed: %v", err)
	}

	fileToSend, err := ioutil.TempFile(dir, "")
	if err != nil {
		log.Fatalf("TempFile failed: %v", err)
	}
	defer fileToSend.Close()

	if _, err := fileToSend.WriteString(fileContents); err != nil {
		log.Fatalf("Write(%q) failed: %v", fileContents, err)
	}

	// Receiver may not be started yet, so try connecting in a poll loop.
	var s *unet.Socket
	if err := testutil.Poll(func() error {
		var err error
		s, err = unet.Connect(fds.socketPath, true /* SEQPACKET, so we can send empty message with FD */)
		return err
	}, 10*time.Second); err != nil {
		log.Fatalf("Error connecting to socket %q: %v", fds.socketPath, err)
	}
	defer s.Close()

	w := s.Writer(true)
	w.ControlMessage.PackFDs(int(fileToSend.Fd()))
	if _, err := w.WriteVec([][]byte{[]byte{'a'}}); err != nil {
		log.Fatalf("Error sending FD %q over socket %q: %v", fileToSend.Fd(), fds.socketPath, err)
	}

	log.Print("FD SENDER exiting successfully")
	return subcommands.ExitSuccess
}

// fdReceiver receives an FD from a unix domain socket and does things to it.
type fdReceiver struct {
	socketPath string
}

// Name implements subcommands.Command.Name.
func (*fdReceiver) Name() string {
	return "fd_receiver"
}

// Synopsis implements subcommands.Command.Synopsys.
func (*fdReceiver) Synopsis() string {
	return "reads an FD from a unix socket, and then does things to it"
}

// Usage implements subcommands.Command.Usage.
func (*fdReceiver) Usage() string {
	return "fd_receiver <flags>"
}

// SetFlags implements subcommands.Command.SetFlags.
func (fdr *fdReceiver) SetFlags(f *flag.FlagSet) {
	f.StringVar(&fdr.socketPath, "socket", "", "path to socket")
}

// Execute implements subcommands.Command.Execute.
func (fdr *fdReceiver) Execute(ctx context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if fdr.socketPath == "" {
		log.Fatalf("Flags cannot be empty, given: socket: %q", fdr.socketPath)
	}

	ss, err := unet.BindAndListen(fdr.socketPath, true /* packet */)
	if err != nil {
		log.Fatalf("BindAndListen(%q) failed: %v", fdr.socketPath, err)
	}
	defer ss.Close()

	var s *unet.Socket
	c := make(chan error, 1)
	go func() {
		var err error
		s, err = ss.Accept()
		c <- err
	}()

	select {
	case err := <-c:
		if err != nil {
			log.Fatalf("Accept() failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		log.Fatalf("Timeout waiting for accept")
	}

	r := s.Reader(true)
	r.EnableFDs(1)
	b := [][]byte{{'a'}}
	if n, err := r.ReadVec(b); n != 1 || err != nil {
		log.Fatalf("ReadVec got n=%d err %v (wanted 0, nil)", n, err)
	}

	fds, err := r.ExtractFDs()
	if err != nil {
		log.Fatalf("ExtractFD() got err %v", err)
	}
	if len(fds) != 1 {
		log.Fatalf("ExtractFD() got %d FDs, wanted 1", len(fds))
	}
	fd := fds[0]

	file := os.NewFile(uintptr(fd), "received file")
	defer file.Close()
	if _, err := file.Seek(0, os.SEEK_SET); err != nil {
		log.Fatalf("Seek(0, 0) failed: %v", err)
	}

	got, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatalf("ReadAll failed: %v", err)
	}
	if string(got) != fileContents {
		log.Fatalf("ReadAll got %q want %q", string(got), fileContents)
	}

	log.Print("FD RECEIVER exiting successfully")
	return subcommands.ExitSuccess
}
