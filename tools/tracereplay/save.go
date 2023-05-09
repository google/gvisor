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
	"fmt"
	"os"
	"path/filepath"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote/server"
	"gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote/wire"
)

// Save implements the functionality required for the "save" command.
type Save struct {
	server.CommonServer
	dir         string
	prefix      string
	clientCount atomicbitops.Uint64
}

var _ server.ClientHandler = (*Save)(nil)

// NewSave creates a new Save instance.
func NewSave(endpoint, dir, prefix string) *Save {
	s := &Save{dir: dir, prefix: prefix}
	s.CommonServer.Init(endpoint, s)
	return s
}

// Start starts the server.
func (s *Save) Start() error {
	if err := os.MkdirAll(s.dir, 0755); err != nil {
		return err
	}
	return s.CommonServer.Start()
}

// NewClient creates a new file for the client and writes messages to it.
//
// The file format starts with a string signature to make it easy to check that
// it's a trace file. The signature is followed by a JSON configuration that
// contains information required to process the file. Next, there are a sequence
// of messages. Both JSON and messages are prefixed by an uint64 with their
// size.
//
// Ex: signature <size>Config JSON [<size>message]*
func (s *Save) NewClient() (server.MessageHandler, error) {
	seq := s.clientCount.Add(1)
	filename := filepath.Join(s.dir, fmt.Sprintf("%s%04d", s.prefix, seq))
	fmt.Printf("New client connected, writing to: %q\n", filename)

	out, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	if _, err := out.Write([]byte(signature)); err != nil {
		return nil, err
	}

	handler := &msgHandler{out: out}

	cfg, err := json.Marshal(Config{Version: handler.Version()})
	if err != nil {
		return nil, err
	}
	if err := writeWithSize(out, cfg); err != nil {
		return nil, err
	}

	return handler, nil
}

type msgHandler struct {
	out          *os.File
	messageCount atomicbitops.Uint64
}

var _ server.MessageHandler = (*msgHandler)(nil)

// Version implements server.MessageHandler.
func (m *msgHandler) Version() uint32 {
	return wire.CurrentVersion
}

// Message saves the message to the client file.
func (m *msgHandler) Message(raw []byte, _ wire.Header, _ []byte) error {
	m.messageCount.Add(1)
	return writeWithSize(m.out, raw)
}

// Close closes the client file.
func (m *msgHandler) Close() {
	fmt.Printf("Closing client, wrote %d messages to %q\n", m.messageCount.Load(), m.out.Name())
	_ = m.out.Close()
}
