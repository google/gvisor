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

package gofer

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Global pipe used by blockUntilNonblockingPipeHasWriter since we can't create
// pipes after sentry initialization due to syscall filters.
var (
	tempPipeMu      sync.Mutex
	tempPipeReadFD  int
	tempPipeWriteFD int
	tempPipeBuf     [1]byte
)

func init() {
	var pipeFDs [2]int
	if err := unix.Pipe(pipeFDs[:]); err != nil {
		panic(fmt.Sprintf("failed to create pipe for gofer.blockUntilNonblockingPipeHasWriter: %v", err))
	}
	tempPipeReadFD = pipeFDs[0]
	tempPipeWriteFD = pipeFDs[1]
}

func blockUntilNonblockingPipeHasWriter(ctx context.Context, fd int32) error {
	for {
		ok, err := nonblockingPipeHasWriter(fd)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		if sleepErr := sleepBetweenNamedPipeOpenChecks(ctx); sleepErr != nil {
			// Another application thread may have opened this pipe for
			// writing, succeeded because we previously opened the pipe for
			// reading, and subsequently interrupted us for checkpointing (e.g.
			// this occurs in mknod tests under cooperative save/restore). In
			// this case, our open has to succeed for the checkpoint to include
			// a readable FD for the pipe, which is in turn necessary to
			// restore the other thread's writable FD for the same pipe
			// (otherwise it will get ENXIO). So we have to check
			// nonblockingPipeHasWriter() once last time.
			ok, err := nonblockingPipeHasWriter(fd)
			if err != nil {
				return err
			}
			if ok {
				return nil
			}
			return sleepErr
		}
	}
}

func nonblockingPipeHasWriter(fd int32) (bool, error) {
	tempPipeMu.Lock()
	defer tempPipeMu.Unlock()
	// Copy 1 byte from fd into the temporary pipe.
	n, err := unix.Tee(int(fd), tempPipeWriteFD, 1, unix.SPLICE_F_NONBLOCK)
	if linuxerr.Equals(linuxerr.EAGAIN, err) {
		// The pipe represented by fd is empty, but has a writer.
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if n == 0 {
		// The pipe represented by fd is empty and has no writer.
		return false, nil
	}
	// The pipe represented by fd is non-empty, so it either has, or has
	// previously had, a writer. Remove the byte copied to the temporary pipe
	// before returning.
	if n, err := unix.Read(tempPipeReadFD, tempPipeBuf[:]); err != nil || n != 1 {
		panic(fmt.Sprintf("failed to drain pipe for gofer.blockUntilNonblockingPipeHasWriter: got (%d, %v), wanted (1, nil)", n, err))
	}
	return true, nil
}

func sleepBetweenNamedPipeOpenChecks(ctx context.Context) error {
	t := time.NewTimer(100 * time.Millisecond)
	defer t.Stop()
	cancel := ctx.SleepStart()
	select {
	case <-t.C:
		ctx.SleepFinish(true)
		return nil
	case <-cancel:
		ctx.SleepFinish(false)
		return syserror.ErrInterrupted
	}
}
