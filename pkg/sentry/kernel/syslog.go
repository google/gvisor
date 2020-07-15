// Copyright 2018 The gVisor Authors.
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

package kernel

import (
	"bytes"
	"fmt"
	"math/rand"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// BufferEntryMax is the maximum number of entries retained by kmsg before new entries overwrite old ones.
	BufferEntryMax = 512

	// BufferMax is the maximum size of an individual entry, in bytes.
	BufferMax = 1024

	// format is the used to format message when syslog it's not initialized.
	format = "<6>[%11.6f] %s\n"
)

// syslog represents a sentry-global kernel log.
//
// Currently, it contains only fun messages for a dmesg easter egg.
//
// +stateify savable
type syslog struct {
	// mu protects the below.
	mu sync.Mutex `state:"nosave"`

	// msg is the syslog message buffer.
	msg [BufferEntryMax]*buffer.View

	// firstSequence is sequence number of the first valid record in buffer.
	firstSequence uint64
	// firstIndex is index of the first valid record in buffer.
	firstIndex uint32

	// nextSequence is the sequence number of next record to store in buffer.
	nextSequence uint64
	// nextIndex is the index to store next record in buffer.
	nextIndex uint32
}

func (s *syslog) DevKmsgRead(ctx context.Context, userSeq uint64, userIndex uint32, dst usermem.IOSequence, statusFlags uint32) (uint64, uint32, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// When an entry gets overwritten in the circular buffer, next read()
	// will return EPIPE and move readIndex to the next available record.
	// See Documentation/ABI/testing/dev-kmsg in the Linux source for reference.
	if userSeq < s.firstSequence {
		return s.firstSequence, s.firstIndex, 0, syserror.EPIPE
	}
	if userSeq == s.nextSequence {
		if statusFlags&^linux.O_NONBLOCK != 0 {
			return userSeq, userIndex, 0, syserror.EAGAIN
		}
		return userSeq, userIndex, 0, syserror.ErrWouldBlock
	}
	if s.msg[userIndex].Size() > dst.NumBytes() {
		return userSeq, userIndex, 0, syserror.EINVAL
	}
	bytesCopied, err := dst.CopyOutFrom(ctx, s.msg[userIndex])
	userSeq++
	userIndex++
	if userIndex == BufferEntryMax {
		userIndex = 0
	}
	return userSeq, userIndex, bytesCopied, err
}

func (s *syslog) DevKmsgWrite(ctx context.Context, src usermem.IOSequence) (int64, error) {
	if src.NumBytes() > BufferMax {
		return 0, syserror.EINVAL
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.msg[s.nextIndex] = new(buffer.View)
	bytesCopied, err := src.CopyInTo(ctx, s.msg[s.nextIndex])
	if s.firstIndex == s.nextIndex && s.nextSequence != 0 {
		s.firstIndex++
		s.firstSequence++
	}
	s.nextSequence++
	s.nextIndex++
	if s.nextIndex == BufferEntryMax {
		s.nextIndex = 0
	}
	return bytesCopied, err
}

// Different from usual behavior, kmsg only support three type of seek:
//	- SEEK_SET seek to the first entry in the buffer.
//	- SEEK_END seek after the last entry in the buffer.
//	- SEEK_DATA perform same action as SEEK_END since gvisor doesn't have syslog yet.
func (s *syslog) DevKmsgSeek(ctx context.Context, whence int32) (uint64, uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch whence {
	case linux.SEEK_SET:
		return s.firstSequence, s.firstIndex, nil
	case linux.SEEK_END, linux.SEEK_DATA:
		return s.nextSequence, s.nextIndex, nil
	default:
		return 0, 0, syserror.EINVAL
	}
}

func (s *syslog) DevKmsgReadiness(userSeq uint64, mask waiter.EventMask) waiter.EventMask {
	var ready waiter.EventMask
	s.mu.Lock()
	defer s.mu.Unlock()
	if userSeq < s.nextSequence {
		ready |= waiter.EventIn
	}
	return ready
}

func (s *syslog) FirstSequence() uint64 {
	return s.firstSequence
}

func (s *syslog) FirstIndex() uint32 {
	return s.firstIndex
}

// Log returns a copy of the syslog.
func (s *syslog) Log() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nextSequence != 0 {
		// Already initialized, just return a copy.
		return s.flatten()
	}

	// Not initialized, create message.
	allMessages := []string{
		"Synthesizing system calls...",
		"Mounting deweydecimalfs...",
		"Moving files to filing cabinet...",
		"Digging up root...",
		"Constructing home...",
		"Segmenting fault lines...",
		"Creating bureaucratic processes...",
		"Searching for needles in stacks...",
		"Preparing for the zombie uprising...",
		"Feeding the init monster...",
		"Creating cloned children...",
		"Daemonizing children...",
		"Waiting for children...",
		"Gathering forks...",
		"Committing treasure map to memory...",
		"Reading process obituaries...",
		"Searching for socket adapter...",
		"Creating process schedule...",
		"Generating random numbers by fair dice roll...",
		"Rewriting operating system in Javascript...",
		"Reticulating splines...",
		"Consulting tar man page...",
		"Forking spaghetti code...",
		"Checking naughty and nice process list...",
		"Checking naughty and nice process list...", // Check it up to twice.
		"Granting licence to kill(2)...",            // British spelling for British movie.
		"Letting the watchdogs out...",
	}

	selectMessage := func() string {
		i := rand.Intn(len(allMessages))
		m := allMessages[i]

		// Delete the selected message.
		allMessages[i] = allMessages[len(allMessages)-1]
		allMessages = allMessages[:len(allMessages)-1]

		return m
	}

	s.storeLogs(0.0, "Starting gVisor...")

	time := 0.1
	for s.nextIndex < 11 {
		time += rand.Float64() / 2
		s.storeLogs(time, selectMessage())
	}

	if VFS2Enabled {
		time += rand.Float64() / 2
		s.msg = append(s.msg, []byte(fmt.Sprintf(format, time, "Setting up VFS2..."))...)
		if FUSEEnabled {
			time += rand.Float64() / 2
			s.msg = append(s.msg, []byte(fmt.Sprintf(format, time, "Setting up FUSE..."))...)
		}
	}

	time += rand.Float64() / 2
	s.storeLogs(time, "Ready!")

	// Return a copy.
	return s.flatten()
}

func (s *syslog) flatten() []byte {
	o := bytes.NewBuffer(make([]byte, 0, (s.nextSequence-s.firstSequence)*BufferMax))
	index := s.firstIndex
	for index != s.nextIndex {
		s.msg[index].ReadToWriter(o, s.msg[index].Size())
		index++
		if index == BufferEntryMax {
			index = 0
		}
	}
	return o.Bytes()
}

func (s *syslog) storeLogs(time float64, log string) {
	s.msg[s.nextIndex] = new(buffer.View)
	s.msg[s.nextIndex].Append([]byte(fmt.Sprintf(format, time, log)))
	s.nextIndex++
	s.nextSequence++
}
