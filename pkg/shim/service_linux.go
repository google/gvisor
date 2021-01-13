// Copyright 2018 The containerd Authors.
// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build linux

package shim

import (
	"context"
	"fmt"
	"io"
	"sync"
	"syscall"

	"github.com/containerd/console"
	"github.com/containerd/fifo"
)

type linuxPlatform struct {
	epoller *console.Epoller
}

func (p *linuxPlatform) CopyConsole(ctx context.Context, console console.Console, stdin, stdout, stderr string, wg *sync.WaitGroup) (console.Console, error) {
	if p.epoller == nil {
		return nil, fmt.Errorf("uninitialized epoller")
	}

	epollConsole, err := p.epoller.Add(console)
	if err != nil {
		return nil, err
	}

	if stdin != "" {
		in, err := fifo.OpenFifo(context.Background(), stdin, syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, err
		}
		go func() {
			p := bufPool.Get().(*[]byte)
			defer bufPool.Put(p)
			io.CopyBuffer(epollConsole, in, *p)
		}()
	}

	outw, err := fifo.OpenFifo(ctx, stdout, syscall.O_WRONLY, 0)
	if err != nil {
		return nil, err
	}
	outr, err := fifo.OpenFifo(ctx, stdout, syscall.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	wg.Add(1)
	go func() {
		p := bufPool.Get().(*[]byte)
		defer bufPool.Put(p)
		io.CopyBuffer(outw, epollConsole, *p)
		epollConsole.Close()
		outr.Close()
		outw.Close()
		wg.Done()
	}()
	return epollConsole, nil
}

func (p *linuxPlatform) ShutdownConsole(ctx context.Context, cons console.Console) error {
	if p.epoller == nil {
		return fmt.Errorf("uninitialized epoller")
	}
	epollConsole, ok := cons.(*console.EpollConsole)
	if !ok {
		return fmt.Errorf("expected EpollConsole, got %#v", cons)
	}
	return epollConsole.Shutdown(p.epoller.CloseConsole)
}

func (p *linuxPlatform) Close() error {
	return p.epoller.Close()
}

// initialize a single epoll fd to manage our consoles. `initPlatform` should
// only be called once.
func (s *service) initPlatform() error {
	if s.platform != nil {
		return nil
	}
	epoller, err := console.NewEpoller()
	if err != nil {
		return fmt.Errorf("failed to initialize epoller: %w", err)
	}
	s.platform = &linuxPlatform{
		epoller: epoller,
	}
	go epoller.Wait()
	return nil
}
