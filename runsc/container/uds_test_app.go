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

// Binary uds-test-app opens a socket and reads a series of numbers
// which are then written to an output file.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

var (
	fileName   = flag.String("file", "", "name of output file")
	socketPath = flag.String("socket", "", "path to socket")
)

func server(listener net.Listener, f *os.File) {
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
		fmt.Fprintf(f, string(data)+"\n")
	}
}

func main() {
	flag.Parse()
	if *fileName == "" || *socketPath == "" {
		log.Fatalf("Flags cannot be empty, given: fileName=%s, socketPath=%s", *fileName, *socketPath)
	}
	outputFile, err := os.OpenFile(*fileName, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		log.Fatal("error opening output file:", err)
	}

	socket := *socketPath
	defer os.Remove(socket)

	listener, err := net.Listen("unix", socket)
	if err != nil {
		log.Fatal("error listening on socket:", err)
	}

	go server(listener, outputFile)
	for i := 0; ; i++ {

		conn, err := net.Dial("unix", socket)
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
