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

// Package cmd holds implementations of the runsc commands.
package cmd

import (
	"fmt"

	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

// containerLoader is an embeddable struct for util.SubCommand implementations
// that take the container ID as an argument. It helps load the container and
// caches the result to avoid loading the same container multiple times.
type containerLoader struct {
	cachedContainer *container.Container
}

// loadContainer
func (c *containerLoader) loadContainer(conf *config.Config, f *flag.FlagSet, loadOpts container.LoadOpts) (*container.Container, error) {
	if c.cachedContainer != nil {
		// Container is already loaded.
		return c.cachedContainer, nil
	}
	// Assumes that the first argument is the container ID.
	if f.NArg() < 1 {
		f.Usage()
		return nil, fmt.Errorf("a container-id is required")
	}
	id := f.Arg(0)
	cont, err := container.Load(conf.RootDir, container.FullID{ContainerID: id}, loadOpts)
	if err != nil {
		return nil, err
	}
	c.cachedContainer = cont
	return c.cachedContainer, nil
}
