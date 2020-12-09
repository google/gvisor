// Copyright 2021 The gVisor Authors.
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

package boot

import (
	"fmt"
	"io"
	"os"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
	hostvfs2 "gvisor.dev/gvisor/pkg/sentry/fsimpl/host"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
	"gvisor.dev/gvisor/runsc/config"
)

// portForward starts forwarding a port in the given container. This opens the
// given UDS address and creates a single connection on it.
func (l *Loader) portForward(opts *PortForwardOpts) error {
	if !kernel.VFS2Enabled {
		return fmt.Errorf("port forwarding is only supported when using VFS v2")
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	cid := opts.ContainerID
	tg, err := l.tryThreadGroupFromIDLocked(execID{cid: cid})
	if err != nil {
		return err
	}
	if tg == nil {
		return fmt.Errorf("container %q not started", cid)
	}

	// Validate that we have a stream FD to write to. If this happens then
	// it means there is a misbehaved urpc client or a bug has occurred.
	if len(opts.Files) < 1 {
		return fmt.Errorf("stream FD is required for port forward")
	}
	streamFile := opts.Files[0]

	// Import the fd for the UDS.
	ctx := l.k.SupervisorContext()
	fd, err := l.importFD(ctx, streamFile)
	if err != nil {
		return fmt.Errorf("importing stream fd: %w", err)
	}

	// Create a connection to localhost.
	var conn portForwardConn
	if l.root.conf.Network == config.NetworkHost {
		log.Debugf("Handling hostinet port forwarding request for %s on port %d", cid, opts.Port)
		conn, err = newHostinetPortForward(ctx, cid, streamFile, fd, opts.Port)
		if err != nil {
			return err
		}
	} else {
		log.Debugf("Handling netstack port forwarding request for %s on port %d", cid, opts.Port)
		stack := l.k.RootNetworkNamespace().Stack().(*netstack.Stack)
		conn, err = newNetstackPortForward(ctx, stack.Stack, cid, streamFile, fd, opts.Port)
		if err != nil {
			return err
		}
	}

	// Add to the list of port forward connections and remove when the
	// connection closes.
	l.portForwardConns = append(l.portForwardConns, conn)
	conn.Cleanup(func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		var newConns []portForwardConn
		for _, c := range l.portForwardConns {
			if c != conn {
				newConns = append(newConns, c)
			}
		}
		l.portForwardConns = newConns
	})

	// Start forwarding on the connection.
	return conn.Start()
}

// fileDescriptionReadWriter implements io.ReadWriter and allows reading and
// writing to a vfs.FileDescription.
type fileDescriptionReadWriter struct {
	// ctx is the context for the socket reader.
	ctx context.Context

	// file is the file to read and write from.
	file *vfs.FileDescription
}

// Read implements io.Reader.Read. It performs a blocking read on the fd.
func (r *fileDescriptionReadWriter) Read(buf []byte) (int, error) {
	var notifyCh chan struct{}
	var waitEntry waiter.Entry
	n, err := r.file.Read(r.ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	for err == syserror.ErrWouldBlock {
		if notifyCh == nil {
			waitEntry, notifyCh = waiter.NewChannelEntry(nil)
			// Register for when the endpoint is readable or disconnected.
			r.file.EventRegister(&waitEntry, waiter.ReadableEvents|waiter.WritableEvents|waiter.EventHUp|waiter.EventErr)
			defer r.file.EventUnregister(&waitEntry)
		}
		<-notifyCh
		n, err = r.file.Read(r.ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	}

	// host fd FileDescriptions use recvmsg which returns zero, when the
	// peer has shutdown. When that happens return EOF
	if n == 0 && err == nil {
		return 0, io.EOF
	}
	return int(n), err
}

// Write implements io.Writer.Write. It performs a blocking write on the fd.
func (r *fileDescriptionReadWriter) Write(buf []byte) (int, error) {
	var notifyCh chan struct{}
	var waitEntry waiter.Entry
	n, err := r.file.Write(r.ctx, usermem.BytesIOSequence(buf), vfs.WriteOptions{})
	for err == syserror.ErrWouldBlock {
		if notifyCh == nil {
			waitEntry, notifyCh = waiter.NewChannelEntry(nil)
			// Register for when the endpoint is writable or disconnected.
			r.file.EventRegister(&waitEntry, waiter.WritableEvents|waiter.EventHUp|waiter.EventErr)
			defer r.file.EventUnregister(&waitEntry)
		}
		<-notifyCh
		n, err = r.file.Write(r.ctx, usermem.BytesIOSequence(buf), vfs.WriteOptions{})
	}
	return int(n), err
}

// portForwardConn is a port forwarding connection. It is used to manage the
// lifecycle of the connection and clean it up if necessary.
type portForwardConn interface {
	// Start starts the connection goroutines and returns.
	Start() error
	// Close closes and cleans up the connection.
	Close() error
	// Cleanup registers a callback for when the connection closes.
	Cleanup(func())
}

// importFD generically imports a host file descriptor without adding it to any
// fd table.
func (l *Loader) importFD(ctx context.Context, f *os.File) (*vfs.FileDescription, error) {
	// FIXME: Should the imported fd be not savable?
	hostFD, err := fd.NewFromFile(f)
	if err != nil {
		return nil, err
	}
	defer hostFD.Close()
	fd, err := hostvfs2.ImportFD(ctx, l.k.HostMount(), hostFD.FD(), false /* isTTY */)
	if err != nil {
		return nil, err
	}
	hostFD.Release()
	return fd, nil
}
