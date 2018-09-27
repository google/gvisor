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

// Binary test_app is like a swiss knife for tests that need to run anything
// inside the sandbox. New functionality can be added with new commands.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"flag"
	"github.com/google/subcommands"
)

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(new(uds), "")

	flag.Parse()

	exitCode := subcommands.Execute(context.Background())
	os.Exit(int(exitCode))
}

type uds struct {
	fileName   string
	socketPath string
}

// Name implements subcommands.Command.Name.
func (*uds) Name() string {
	return "uds"
}

// Synopsis implements subcommands.Command.Synopsys.
func (*uds) Synopsis() string {
	return "creates unix domain socket client and server. Client sends a contant flow of sequential numbers. Server prints them to --file"
}

// Usage implements subcommands.Command.Usage.
func (*uds) Usage() string {
	return "uds <flags>"
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *uds) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.fileName, "file", "", "name of output file")
	f.StringVar(&c.socketPath, "socket", "", "path to socket")
}

// Execute implements subcommands.Command.Execute.
func (c *uds) Execute(ctx context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if c.fileName == "" || c.socketPath == "" {
		log.Fatal("Flags cannot be empty, given: fileName: %q, socketPath: %q", c.fileName, c.socketPath)
		return subcommands.ExitFailure
	}
	outputFile, err := os.OpenFile(c.fileName, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		log.Fatal("error opening output file:", err)
	}

	defer os.Remove(c.socketPath)

	listener, err := net.Listen("unix", c.socketPath)
	if err != nil {
		log.Fatal("error listening on socket %q:", c.socketPath, err)
	}

	go server(listener, outputFile)
	for i := 0; ; i++ {
		conn, err := net.Dial("unix", c.socketPath)
		if err != nil {
			log.Fatal("error dialing:", err)
		}
		if _, err := conn.Write([]byte(strconv.Itoa(i))); err != nil {
			log.Fatal("error writing:", err)
		}
		conn.Close()
		time.Sleep(100 * time.Millisecond)
	}
}

func server(listener net.Listener, out *os.File) {
	buf := make([]byte, 16)

	for {
		c, err := listener.Accept()
		if err != nil {
			log.Fatal("error accepting connection:", err)
		}
		nr, err := c.Read(buf)
		if err != nil {
			log.Fatal("error reading from buf:", err)
		}
		data := buf[0:nr]
		fmt.Fprint(out, string(data)+"\n")
	}
}
