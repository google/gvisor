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

//go:build amd64
// +build amd64

package trace

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote/test"
)

func extraMatchers(t *testing.T, msgs []test.Message, matchers map[pb.MessageType]*checkers) {
	// Register functions that verify each available point specific to amd64 architecture.
	matchers[pb.MessageType_MESSAGE_SYSCALL_FORK] = &checkers{checker: checkSyscallFork}
}

func checkSyscallSignalfdFlags(flags int32) error {
	if flags != 0 && flags != (unix.SFD_CLOEXEC|unix.SFD_NONBLOCK) {
		return fmt.Errorf("invalid flag got: %v", flags)
	}
	return nil
}

func checkSyscallFork(msg test.Message) error {
	p := pb.Fork{}
	if err := proto.Unmarshal(msg.Msg, &p); err != nil {
		return err
	}
	if err := checkContextData(p.ContextData); err != nil {
		return err
	}
	return nil
}
