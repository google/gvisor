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

// Package iptables contains a set of iptables tests implemented as TestCases
package iptables

import (
	"context"
	"fmt"
	"net"
	"time"
)

// IPExchangePort is the port the container listens on to receive the IP
// address of the local process.
const IPExchangePort = 2349

// TerminalStatement is the last statement in the test runner.
const TerminalStatement = "Finished!"

// TestTimeout is the timeout used for all tests.
const TestTimeout = 10 * time.Second

// NegativeTimeout is the time tests should wait to establish the negative
// case, i.e. that connections are not made.
const NegativeTimeout = 2 * time.Second

// A TestCase contains one action to run in the container and one to run
// locally. The actions run concurrently and each must succeed for the test
// pass.
type TestCase interface {
	// Name returns the name of the test.
	Name() string

	// ContainerAction runs inside the container. It receives the IP of the
	// local process.
	ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error

	// LocalAction runs locally. It receives the IP of the container.
	LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error

	// ContainerSufficient indicates whether ContainerAction's return value
	// alone indicates whether the test succeeded.
	ContainerSufficient() bool

	// LocalSufficient indicates whether LocalAction's return value alone
	// indicates whether the test succeeded.
	LocalSufficient() bool
}

// baseCase provides defaults for ContainerSufficient and LocalSufficient when
// both actions are required to finish.
type baseCase struct{}

// ContainerSufficient implements TestCase.ContainerSufficient.
func (*baseCase) ContainerSufficient() bool {
	return false
}

// LocalSufficient implements TestCase.LocalSufficient.
func (*baseCase) LocalSufficient() bool {
	return false
}

// localCase provides defaults for ContainerSufficient and LocalSufficient when
// only the local action is required to finish.
type localCase struct{}

// ContainerSufficient implements TestCase.ContainerSufficient.
func (*localCase) ContainerSufficient() bool {
	return false
}

// LocalSufficient implements TestCase.LocalSufficient.
func (*localCase) LocalSufficient() bool {
	return true
}

// containerCase provides defaults for ContainerSufficient and LocalSufficient
// when only the container action is required to finish.
type containerCase struct{}

// ContainerSufficient implements TestCase.ContainerSufficient.
func (*containerCase) ContainerSufficient() bool {
	return true
}

// LocalSufficient implements TestCase.LocalSufficient.
func (*containerCase) LocalSufficient() bool {
	return false
}

// Tests maps test names to TestCase.
//
// New TestCases are added by calling RegisterTestCase in an init function.
var Tests = map[string]TestCase{}

// RegisterTestCase registers tc so it can be run.
func RegisterTestCase(tc TestCase) {
	if _, ok := Tests[tc.Name()]; ok {
		panic(fmt.Sprintf("TestCase %s already registered.", tc.Name()))
	}
	Tests[tc.Name()] = tc
}
