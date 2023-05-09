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

// Package portforward holds the infrastructure to support the port forward command.
package portforward

import (
	"fmt"
	"sync"

	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
)

// proxyConn is a port forwarding connection. It is used to manage the
// lifecycle of the connection and clean it up if necessary.
type proxyConn interface {
	// Name returns a name for this proxyConn.
	Name() string
	// Write performs a write on this connection.  Write should block on ErrWouldBlock, but it must
	// listen to 'cancel' to interrupt blocked calls.
	Write(ctx context.Context, buf []byte, cancel <-chan struct{}) (int, error)
	// Read performs a read on this connection. Read should block on ErrWouldBlock by the underlying
	// connection, but it must listen to `cancel` to interrupt blocked calls.
	Read(ctx context.Context, buf []byte, cancel <-chan struct{}) (int, error)
	// Close cleans up all resources owned by this proxyConn.
	Close(ctx context.Context)
}

// Proxy controls copying data between two proxyConnections. Proxy takes ownership over the two
// connections and is responsible for cleaning up their resources (i.e. calling their Close method).
// Proxy(s) all run internal to the sandbox on the supervisor context.
type Proxy struct {
	// containerID for this proxy.
	cid string
	// "to" and "from" are the two connections on which this Proxy copies.
	to         proxyConn
	from       proxyConn
	once       sync.Once
	cancelFrom chan struct{}
	cancelTo   chan struct{}
	wg         sync.WaitGroup
	cu         cleanup.Cleanup
}

// ProxyPair wraps the to/from arguments for NewProxy so that the user explicitly labels to/from.
type ProxyPair struct {
	To   proxyConn
	From proxyConn
}

// NewProxy returns a new Proxy.
func NewProxy(pair ProxyPair, cid string) *Proxy {
	return &Proxy{
		to:         pair.To,
		from:       pair.From,
		cid:        cid,
		cancelTo:   make(chan struct{}, 1),
		cancelFrom: make(chan struct{}, 1),
	}
}

// readFrom reads from the application's vfs.FileDescription and writes to the shim.
func (pf *Proxy) readFrom(ctx context.Context) error {
	buf := make([]byte, 16384 /* 16kb buffer size */)
	for ctx.Err() == nil {
		if err := doCopy(ctx, pf.to, pf.from, buf, pf.cancelFrom); err != nil {
			return fmt.Errorf("readFrom failed on container %q: %v", pf.cid, err)
		}
	}
	return ctx.Err()
}

// writeTo writes to the application's vfs.FileDescription and reads from the shim.
func (pf *Proxy) readTo(ctx context.Context) error {
	buf := make([]byte, 16384 /* 16kb buffer size */)
	for ctx.Err() == nil {
		if err := doCopy(ctx, pf.from, pf.to, buf, pf.cancelTo); err != nil {
			return fmt.Errorf("readTo failed on container %q: %v", pf.cid, err)
		}
	}
	return ctx.Err()
}

// doCopy is the shared copy code for each of 'readFrom' and 'readTo'.
func doCopy(ctx context.Context, dst, src proxyConn, buf []byte, cancel chan struct{}) error {
	n, err := src.Read(ctx, buf, cancel)
	if err != nil {
		return fmt.Errorf("failed to read from %q: err %v", src.Name(), err)
	}

	_, err = dst.Write(ctx, buf[0:n], cancel)
	if err != nil {
		return fmt.Errorf("failed to write to %q: err %v", src.Name(), err)
	}
	return nil
}

// Start starts the proxy. On error on either end, the proxy cleans itself up by stopping both
// connections.
func (pf *Proxy) Start(ctx context.Context) {
	pf.cu.Add(func() {
		pf.to.Close(ctx)
		pf.from.Close(ctx)
	})

	pf.wg.Add(1)
	go func() {
		if err := pf.readFrom(ctx); err != nil {
			ctx.Warningf("Shutting down copy from %q to %q on container %s: %v", pf.from.Name(), pf.to.Name(), pf.cid, err)
		}
		pf.wg.Done()
		pf.Close()
	}()
	pf.wg.Add(1)
	go func() {
		if err := pf.readTo(ctx); err != nil {
			ctx.Warningf("Shutting down copy from %q to %q on container %s: %v", pf.to.Name(), pf.from.Name(), pf.cid, err)
		}
		pf.wg.Done()
		pf.Close()
	}()
}

// AddCleanup adds a cleanup to this Proxy's cleanup.
func (pf *Proxy) AddCleanup(cu func()) {
	pf.cu.Add(cu)
}

// Close cleans up the resources in this Proxy and blocks until all resources are cleaned up
// and their goroutines exit.
func (pf *Proxy) Close() {
	pf.once.Do(func() {
		pf.cu.Clean()
		pf.cancelFrom <- struct{}{}
		defer close(pf.cancelFrom)
		pf.cancelTo <- struct{}{}
		defer close(pf.cancelTo)
	})
	pf.wg.Wait()
}
