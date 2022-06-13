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

package tracereplay

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/log"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

// Replay implements the functionality required for the "replay" command.
type Replay struct {
	Endpoint string
	In       string
}

// Execute connects to the remote endpoint and replays all messages stored in
// the `In` file.
func (r *Replay) Execute() error {
	socket, err := connect(r.Endpoint)
	if err != nil {
		return err
	}
	defer socket.Close()

	f, err := os.Open(r.In)
	if err != nil {
		return err
	}
	defer f.Close()

	hdr := make([]byte, len(signature))
	if err := readFull(f, hdr); err != nil {
		return err
	}
	if string(hdr) != signature {
		return fmt.Errorf("%q is not a replay file", r.In)
	}

	cfgJSON, err := readWithSize(f)
	if err != nil {
		return err
	}
	cfg := Config{}
	if err := json.Unmarshal(cfgJSON, &cfg); err != nil {
		return err
	}
	if err := handshake(socket, cfg.Version); err != nil {
		return err
	}
	fmt.Printf("Handshake completed\n")

	for count := 1; ; count++ {
		bytes, err := readWithSize(f)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		fmt.Printf("\rReplaying message: %d", count)
		if _, err := socket.Write(bytes); err != nil {
			return err
		}
	}
	fmt.Printf("\nDone\n")
	return nil
}

func connect(endpoint string) (*os.File, error) {
	log.Debugf("Connecting to %q", endpoint)
	socket, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		return nil, fmt.Errorf("socket(AF_UNIX, SOCK_SEQPACKET, 0): %w", err)
	}
	f := os.NewFile(uintptr(socket), endpoint)

	addr := unix.SockaddrUnix{Name: endpoint}
	if err := unix.Connect(int(f.Fd()), &addr); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("connect(%q): %w", endpoint, err)
	}
	return f, nil
}

// See common.proto for details about the handshake protocol.
func handshake(socket *os.File, version uint32) error {
	hsOut := pb.Handshake{Version: version}
	out, err := proto.Marshal(&hsOut)
	if err != nil {
		return err
	}
	if _, err := socket.Write(out); err != nil {
		return fmt.Errorf("sending handshake message: %w", err)
	}

	in := make([]byte, 10240)
	read, err := socket.Read(in)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("reading handshake message: %w", err)
	}
	// Protect against the handshake becoming larger than the buffer.
	if read == len(in) {
		return fmt.Errorf("handshake message too big")
	}
	hsIn := pb.Handshake{}
	if err := proto.Unmarshal(in[:read], &hsIn); err != nil {
		return fmt.Errorf("unmarshalling handshake message: %w", err)
	}

	// Just validate that the message can unmarshall and accept any version from
	// the server. Will try to replay and see what happens...
	return nil
}
