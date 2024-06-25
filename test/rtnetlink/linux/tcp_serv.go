// Copyright 2024 The gVisor Authors.
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

// tcp_serv creates a TCP server socket, reads data from stdin, and sends that
// data to the socket. The same thing can be done with the nc tool, but
// tcp_serv can signal when a tcp socket is created.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

func main() {
	port := flag.Int("port", 8888, "port to listen on")
	syncFD := flag.Int("sync-fd", -1, "file descriptor that will be closed after creating a socket")
	flag.Parse()
	address := fmt.Sprintf(":%d", *port)

	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("Error creating listener: %s", err)
		return
	}
	defer listener.Close()
	if *syncFD >= 0 {
		unix.Close(*syncFD)
	}

	conn, err := listener.Accept()
	if err != nil {
		log.Fatalf("Error accepting connection: %s", err)
	}
	defer conn.Close()

	data := make([]byte, 1024)
	for {
		count, err := os.Stdin.Read(data)
		if err == io.EOF {
			break
		}

		_, err = conn.Write(data[:count])
		if err != nil {
			log.Fatalf("Error sending data: %s", err)
		}
	}
}
