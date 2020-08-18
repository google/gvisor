// Copyright 2020 The gVisor Authors.
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

package stack

import "gvisor.dev/gvisor/pkg/tcpip"

const (
	// MinBufferSize is the smallest size of a receive or send buffer.
	MinBufferSize = 4 << 10 // 4 KiB

	// DefaultBufferSize is the default size of the send/recv buffer for a
	// transport endpoint.
	DefaultBufferSize = 212 << 10 // 212 KiB

	// DefaultMaxBufferSize is the default maximum permitted size of a
	// send/receive buffer.
	DefaultMaxBufferSize = 4 << 20 // 4 MiB
)

// SendBufferSizeOption is used by stack.(Stack*).Option/SetOption to
// get/set the default, min and max send buffer sizes.
type SendBufferSizeOption struct {
	Min     int
	Default int
	Max     int
}

// ReceiveBufferSizeOption is used by stack.(Stack*).Option/SetOption to
// get/set the default, min and max receive buffer sizes.
type ReceiveBufferSizeOption struct {
	Min     int
	Default int
	Max     int
}

// SetOption allows setting stack wide options.
func (s *Stack) SetOption(option interface{}) *tcpip.Error {
	switch v := option.(type) {
	case SendBufferSizeOption:
		// Make sure we don't allow lowering the buffer below minimum
		// required for stack to work.
		if v.Min < MinBufferSize {
			return tcpip.ErrInvalidOptionValue
		}

		if v.Default < v.Min || v.Default > v.Max {
			return tcpip.ErrInvalidOptionValue
		}

		s.mu.Lock()
		s.sendBufferSize = v
		s.mu.Unlock()
		return nil

	case ReceiveBufferSizeOption:
		// Make sure we don't allow lowering the buffer below minimum
		// required for stack to work.
		if v.Min < MinBufferSize {
			return tcpip.ErrInvalidOptionValue
		}

		if v.Default < v.Min || v.Default > v.Max {
			return tcpip.ErrInvalidOptionValue
		}

		s.mu.Lock()
		s.receiveBufferSize = v
		s.mu.Unlock()
		return nil

	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

// Option allows retrieving stack wide options.
func (s *Stack) Option(option interface{}) *tcpip.Error {
	switch v := option.(type) {
	case *SendBufferSizeOption:
		s.mu.RLock()
		*v = s.sendBufferSize
		s.mu.RUnlock()
		return nil

	case *ReceiveBufferSizeOption:
		s.mu.RLock()
		*v = s.receiveBufferSize
		s.mu.RUnlock()
		return nil

	default:
		return tcpip.ErrUnknownProtocolOption
	}
}
