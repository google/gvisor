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

package host

import (
	"fmt"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/fd"
)

// beforeSave is invoked by stateify.
func (c *ConnectedEndpoint) beforeSave() {
	if c.srfd < 0 {
		panic("only host file descriptors provided at sentry startup can be saved")
	}
}

// afterLoad is invoked by stateify.
func (c *ConnectedEndpoint) afterLoad() {
	f, err := syscall.Dup(c.srfd)
	if err != nil {
		panic(fmt.Sprintf("failed to dup restored FD %d: %v", c.srfd, err))
	}
	c.file = fd.New(f)
	if err := c.init(); err != nil {
		panic(fmt.Sprintf("Could not restore host socket FD %d: %v", c.srfd, err))
	}
	c.Init()
}
