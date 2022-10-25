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

// Package uds contains helpers for testing external UDS functionality.
package uds

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/unet"
)

func doEcho(s *unet.Socket) error {
	buf := make([]byte, 512)
	n, err := s.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read: %d, %w", n, err)
	}

	n, err = s.Write(buf[:n])
	if err != nil {
		return fmt.Errorf("failed to write: %d, %w", n, err)
	}
	return nil
}

// createEchoSocket creates a socket that echoes back anything received.
//
// Only works for stream, seqpacket sockets.
func createEchoSocket(path string, protocol int) (cleanup func(), err error) {
	fd, err := unix.Socket(unix.AF_UNIX, protocol, 0)
	if err != nil {
		return nil, fmt.Errorf("error creating echo(%d) socket: %v", protocol, err)
	}

	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		return nil, fmt.Errorf("error binding echo(%d) socket: %v", protocol, err)
	}

	if err := unix.Listen(fd, 0); err != nil {
		return nil, fmt.Errorf("error listening echo(%d) socket: %v", protocol, err)
	}

	server, err := unet.NewServerSocket(fd)
	if err != nil {
		return nil, fmt.Errorf("error creating echo(%d) unet socket: %v", protocol, err)
	}

	acceptAndEchoOne := func() error {
		s, err := server.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept: %v", err)
		}
		defer s.Close()

		for {
			if err := doEcho(s); err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
		}
	}

	go func() {
		for {
			if err := acceptAndEchoOne(); err != nil {
				log.Warningf("Failed to handle echo(%d) socket: %v", protocol, err)
				return
			}
		}
	}()

	cleanup = func() {
		if err := server.Close(); err != nil {
			log.Warningf("Failed to close echo(%d) socket: %v", protocol, err)
		}
	}

	return cleanup, nil
}

// connectAndBecomeEcho connects to the given socket and turns into an echo server.
func connectAndBecomeEcho(path string, protocol int) (cleanup func(), err error) {
	usePacket := protocol == unix.SOCK_SEQPACKET
	go func() {
		for {
			sock, err := unet.Connect(path, usePacket)
			log.Infof("Connecting to UDS at %q, got %v", path, err)
			if err != nil {
				// Wait and try again.
				time.Sleep(500 * time.Millisecond)
				continue
			}
			defer sock.Close()
			for {
				log.Infof("Connected to UDS at %q, running echo server", path)
				if err := doEcho(sock); err != nil {
					return
				}
			}
		}
	}()

	return func() {}, nil
}

// createNonListeningSocket creates a socket that is bound but not listening.
//
// Only relevant for stream, seqpacket sockets.
func createNonListeningSocket(path string, protocol int) (cleanup func(), err error) {
	fd, err := unix.Socket(unix.AF_UNIX, protocol, 0)
	if err != nil {
		return nil, fmt.Errorf("error creating nonlistening(%d) socket: %v", protocol, err)
	}

	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		return nil, fmt.Errorf("error binding nonlistening(%d) socket: %v", protocol, err)
	}

	cleanup = func() {
		if err := unix.Close(fd); err != nil {
			log.Warningf("Failed to close nonlistening(%d) socket: %v", protocol, err)
		}
	}

	return cleanup, nil
}

// createNullSocket creates a socket that reads anything received.
//
// Only works for dgram sockets.
func createNullSocket(path string, protocol int) (cleanup func(), err error) {
	fd, err := unix.Socket(unix.AF_UNIX, protocol, 0)
	if err != nil {
		return nil, fmt.Errorf("error creating null(%d) socket: %v", protocol, err)
	}

	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		return nil, fmt.Errorf("error binding null(%d) socket: %v", protocol, err)
	}

	s, err := unet.NewSocket(fd)
	if err != nil {
		return nil, fmt.Errorf("error creating null(%d) unet socket: %v", protocol, err)
	}

	go func() {
		buf := make([]byte, 512)
		for {
			n, err := s.Read(buf)
			if err != nil {
				log.Warningf("failed to read: %d, %v", n, err)
				return
			}
		}
	}()

	cleanup = func() {
		if err := s.Close(); err != nil {
			log.Warningf("Failed to close null(%d) socket: %v", protocol, err)
		}
	}

	return cleanup, nil
}

// createPipeWriter creates a pipe that writes a sequence of bytes starting from
// 0 to 256, wrapping it back to 0.
func createPipeWriter(path string) (func(), error) {
	if err := unix.Mkfifo(path, 0644); err != nil {
		return nil, err
	}

	// Open in another goroutine because open blocks until there is reader. Use a
	// channel to send the file over to the cleanup routine, because closing the
	// file triggers the goroutine to exit.
	writerCh := make(chan *os.File, 1)
	go func() {
		writer, err := os.OpenFile(path, os.O_WRONLY, 0)
		writerCh <- writer
		if err != nil {
			log.Warningf("Failed to open pipe: %v", err)
			return
		}

		for i := 0; ; i++ {
			if _, err := writer.Write([]byte{byte(i)}); err != nil {
				log.Warningf("Failed to write to pipe: %v", err)
				return
			}
		}
	}()

	cleanup := func() {
		// Kick the goroutine in case it's blocked waiting for a reader.
		if kicker, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0); err != nil {
			log.Warningf("Failed to kick pipe writer: %v", err)
			return
		} else {
			_ = kicker.Close()
		}

		writer := <-writerCh
		if writer != nil {
			if err := writer.Close(); err != nil {
				log.Warningf("Failed to close pipe writer: %v", err)
			}
		}
	}
	return cleanup, nil
}

// createPipeReader creates a pipe that reads from the pipe and expects a
// sequence of bytes starting from 0 to 256, wrapping it back to 0.
func createPipeReader(path string) (func(), error) {
	if err := unix.Mkfifo(path, 0644); err != nil {
		return nil, err
	}

	// Open in another goroutine because open blocks until there is writer. Use a
	// channel to send the file over to the cleanup routine, because closing the
	// file triggers the goroutine to exit.
	readerCh := make(chan *os.File, 1)
	go func() {
		reader, err := os.OpenFile(path, os.O_RDONLY, 0)
		readerCh <- reader
		if err != nil {
			log.Warningf("Failed to open pipe: %v", err)
			return
		}

		var buf [1]byte
		prev := byte(0xff)
		for {
			if _, err := reader.Read(buf[:]); err != nil {
				log.Warningf("Failed to read to pipe: %v", err)
				return
			}
			if want, got := prev+1, buf[0]; want != got {
				panic(fmt.Sprintf("Wrong byte read from pipe, want: %v, got: %v", want, got))
			}
			prev = buf[0]
		}
	}()

	cleanup := func() {
		// Kick the goroutine in case it's blocked waiting for a reader.
		if kicker, err := os.OpenFile(path, os.O_WRONLY|unix.O_NONBLOCK, 0); err != nil {
			log.Warningf("Failed to kick pipe reader: %v", err)
			return
		} else {
			_ = kicker.Close()
		}

		reader := <-readerCh
		if reader != nil {
			if err := reader.Close(); err != nil {
				log.Warningf("Failed to close pipe reader: %v", err)
			}
		}
	}
	return cleanup, nil
}

type socketCreator func(path string, proto int) (cleanup func(), err error)
type pipeCreator func(path string) (cleanup func(), err error)

// CreateSocketTree creates a local tree of unix domain sockets and pipes for
// use in testing:
//   - /stream/echo
//   - /stream/nonlistening
//   - /seqpacket/echo
//   - /seqpacket/nonlistening
//   - /dgram/null
//   - /pipe/in
//   - /pipe/out
//
// Additionally, it will attempt to connect to sockets at the following
// locations, and turn into an echo server once connected:
//   - /stream/created-in-sandbox
//   - /seqpacket/created-in-sandbox
func CreateSocketTree(baseDir string) (string, func(), error) {
	dir, err := ioutil.TempDir(baseDir, "sockets")
	if err != nil {
		return "", nil, fmt.Errorf("error creating temp dir: %v", err)
	}
	cu := cleanup.Make(func() {
		_ = os.RemoveAll(dir)
	})
	defer cu.Clean()

	for _, proto := range []struct {
		protocol int
		name     string
		sockets  map[string]socketCreator
	}{
		{
			protocol: unix.SOCK_STREAM,
			name:     "stream",
			sockets: map[string]socketCreator{
				"echo":               createEchoSocket,
				"nonlistening":       createNonListeningSocket,
				"created-in-sandbox": connectAndBecomeEcho,
			},
		},
		{
			protocol: unix.SOCK_SEQPACKET,
			name:     "seqpacket",
			sockets: map[string]socketCreator{
				"echo":               createEchoSocket,
				"nonlistening":       createNonListeningSocket,
				"created-in-sandbox": connectAndBecomeEcho,
			},
		},
		{
			protocol: unix.SOCK_DGRAM,
			name:     "dgram",
			sockets: map[string]socketCreator{
				"null": createNullSocket,
			},
		},
	} {
		protoDir := filepath.Join(dir, proto.name)
		if err := os.Mkdir(protoDir, 0755); err != nil {
			return "", nil, fmt.Errorf("error creating %s dir: %v", proto.name, err)
		}

		for name, fn := range proto.sockets {
			path := filepath.Join(protoDir, name)
			cleanup, err := fn(path, proto.protocol)
			if err != nil {
				return "", nil, fmt.Errorf("error creating %s %s socket: %v", proto.name, name, err)
			}
			cu.Add(cleanup)
		}
	}

	pipeDir := filepath.Join(dir, "pipe")
	if err := os.Mkdir(pipeDir, 0755); err != nil {
		return "", nil, err
	}
	for _, pipe := range []struct {
		name string
		ctor pipeCreator
	}{
		{
			name: "in", ctor: createPipeWriter,
		},
		{
			name: "out", ctor: createPipeReader,
		},
	} {
		cleanup, err := pipe.ctor(filepath.Join(pipeDir, pipe.name))
		if err != nil {
			return "", nil, fmt.Errorf("error creating %q pipe: %w", pipe.name, err)
		}
		cu.Add(cleanup)
	}

	return dir, cu.Release(), nil
}
