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
	"fmt"
	"math/rand"
	"sync"
)

// syslog represents a sentry-global kernel log.
//
// Currently, it contains only fun messages for a dmesg easter egg.
//
// +stateify savable
type syslog struct {
	// mu protects the below.
	mu sync.Mutex `state:"nosave"`

	// msg is the syslog message buffer. It is lazily initialized.
	msg []byte
}

// Log returns a copy of the syslog.
func (s *syslog) Log() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.msg != nil {
		// Already initialized, just return a copy.
		o := make([]byte, len(s.msg))
		copy(o, s.msg)
		return o
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

	const format = "<6>[%11.6f] %s\n"

	s.msg = append(s.msg, []byte(fmt.Sprintf(format, 0.0, "Starting gVisor..."))...)

	time := 0.1
	for i := 0; i < 10; i++ {
		time += rand.Float64() / 2
		s.msg = append(s.msg, []byte(fmt.Sprintf(format, time, selectMessage()))...)
	}

	time += rand.Float64() / 2
	s.msg = append(s.msg, []byte(fmt.Sprintf(format, time, "Ready!"))...)

	// Return a copy.
	o := make([]byte, len(s.msg))
	copy(o, s.msg)
	return o
}
