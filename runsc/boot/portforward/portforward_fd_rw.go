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

package portforward

import (
	"io"
	"sync"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// fileDescriptionConn
type fileDescriptionConn struct {
	// file is the file to read and write from.
	file *vfs.FileDescription
	// once makes sure we release the owned FileDescription once.
	once sync.Once
}

// NewFileDescriptionConn initializes a fileDescriptionConn.
func NewFileDescriptionConn(file *vfs.FileDescription) proxyConn {
	return &fileDescriptionConn{file: file}
}

// Name implements proxyConn.Name.
func (r *fileDescriptionConn) Name() string {
	return "fileDescriptionConn"
}

// Read implements proxyConn.Read.
func (r *fileDescriptionConn) Read(ctx context.Context, buf []byte, cancel <-chan struct{}) (int, error) {
	var (
		notifyCh  chan struct{}
		waitEntry waiter.Entry
	)
	n, err := r.file.Read(ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	for linuxerr.Equals(linuxerr.ErrWouldBlock, err) {
		if notifyCh == nil {
			waitEntry, notifyCh = waiter.NewChannelEntry(waiter.ReadableEvents | waiter.WritableEvents | waiter.EventHUp | waiter.EventErr)
			// Register for when the endpoint is readable or disconnected.
			r.file.EventRegister(&waitEntry)
			defer r.file.EventUnregister(&waitEntry)
		}
		select {
		case <-notifyCh:
		case <-cancel:
			return 0, io.EOF
		}
		n, err = r.file.Read(ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	}

	// host fd FileDescriptions use recvmsg which returns zero when the
	// peer has shutdown. When that happens return EOF.
	if n == 0 && err == nil {
		return 0, io.EOF
	}
	return int(n), err
}

// Write implements proxyConn.Write.
func (r *fileDescriptionConn) Write(ctx context.Context, buf []byte, cancel <-chan struct{}) (int, error) {
	var notifyCh chan struct{}
	var waitEntry waiter.Entry
	n, err := r.file.Write(ctx, usermem.BytesIOSequence(buf), vfs.WriteOptions{})
	for linuxerr.Equals(linuxerr.ErrWouldBlock, err) {
		if notifyCh == nil {
			waitEntry, notifyCh = waiter.NewChannelEntry(waiter.WritableEvents | waiter.EventHUp | waiter.EventErr)
			// Register for when the endpoint is writable or disconnected.
			r.file.EventRegister(&waitEntry)
			defer r.file.EventUnregister(&waitEntry)
		}
		select {
		case <-notifyCh:
		case <-cancel:
			return 0, io.EOF
		}
		n, err = r.file.Write(ctx, usermem.BytesIOSequence(buf), vfs.WriteOptions{})
	}
	return int(n), err
}

// Close implements proxyConn.Close.
func (r *fileDescriptionConn) Close(ctx context.Context) {
	r.once.Do(func() {
		r.file.DecRef(ctx)
	})
}
