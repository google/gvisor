// Copyright 2022 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package fdcollector provides a goroutine that reads from a
// vfs.FileDescription (which may block) into a bytes.Buffer.
package fdcollector

import (
	"bytes"
	"io"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Agent represents a goroutine that reads from a vfs.FileDescription
// (which may block) into a bytes.Buffer.
type Agent struct {
	ctx   context.Context
	rfd   *vfs.FileDescription
	desc  string
	stopC chan struct{}
	mu    sync.Mutex
	buf   bytes.Buffer
	wg    sync.WaitGroup
}

// NewAgent creates a new Fdcollector agent.
func NewAgent(ctx context.Context, rfd *vfs.FileDescription, desc string) *Agent {
	c := &Agent{
		ctx:   ctx,
		rfd:   rfd,
		desc:  desc,
		stopC: make(chan struct{}),
	}
	c.wg.Add(1)
	go c.run()
	return c
}

// Run starts the goroutine that reads from the vfs.FileDescription. It blocks
// until the vfs.FileDescription is closed or an error occurs.
func (c *Agent) run() {
	defer c.wg.Done()
	defer c.rfd.DecRef(c.ctx)

	var buf [4096]byte // arbitrary size
	dst := usermem.BytesIOSequence(buf[:])
	e, ch := waiter.NewChannelEntry(waiter.EventIn | waiter.EventErr | waiter.EventHUp)
	if err := c.rfd.EventRegister(&e); err != nil {
		log.Warningf("Error registering for events from %s: %v", c.desc, err)
		return
	}
	defer c.rfd.EventUnregister(&e)
	for {
		n, err := c.rfd.Read(c.ctx, dst, vfs.ReadOptions{})
		if n != 0 {
			c.mu.Lock()
			c.buf.Write(buf[:n])
			c.mu.Unlock()
		}
		if err != nil {
			switch err {
			case linuxerr.ErrWouldBlock:
				select {
				case <-ch:
					continue
				case <-c.stopC:
					return
				}
			case io.EOF:
				log.Debugf("Finished reading output from %s", c.desc)
				return
			default:
				log.Warningf("Error reading output from %s: %v", c.desc, err)
				return
			}
		}
	}
}

// Stop stops the goroutine that reads from the vfs.FileDescription.
func (c *Agent) Stop() {
	close(c.stopC)
	c.wg.Wait()
}

// String returns a string representation of the FdCollector.
func (c *Agent) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Note that the conversion to string is significant since it copies
	// c.buf.Bytes(), which may be modified after c.mu.Unlock(). If you change
	// this function to return []byte for some reason, c.buf.Bytes() needs to
	// be cloned instead.
	return c.buf.String()
}
