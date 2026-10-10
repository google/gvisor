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

package control

import (
	"strings"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/control/controlapi"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// Cgroups contains the state for cgroupfs related control commands.
type Cgroups struct {
	Kernel *kernel.Kernel
}

func (c *Cgroups) findCgroup(ctx context.Context, file controlapi.CgroupControlFile) (kernel.Cgroup, error) {
	ctl, err := kernel.ParseCgroupController(file.Controller)
	if err != nil {
		return kernel.Cgroup{}, err
	}
	return c.Kernel.CgroupRegistry().FindCgroup(ctx, ctl, file.Path)
}

func newValue(val string) controlapi.CgroupsResult {
	return controlapi.CgroupsResult{
		Data: strings.TrimSpace(val),
	}
}

func newError(err error) controlapi.CgroupsResult {
	return controlapi.CgroupsResult{
		Data:    err.Error(),
		IsError: true,
	}
}

// cgroup is an interface implemented by both kernel.Cgroup and kernel.Cgroup2.
type cgroup interface {
	ReadControl(ctx context.Context, name string) (string, error)
	WriteControl(ctx context.Context, name string, val string) error
}

func (c *Cgroups) resolveCgroup(ctx context.Context, file controlapi.CgroupControlFile) (cgroup, error) {
	if c.Kernel.Cgroup2FS().EverMounted() {
		if cg, err := c.Kernel.Cgroup2FS().FindCgroup(ctx, file.Path); err == nil {
			return cg, nil
		}
	}
	return c.findCgroup(ctx, file)
}

// ReadControlFiles is an RPC stub for batch-reading cgroupfs control files.
func (c *Cgroups) ReadControlFiles(args *controlapi.CgroupsReadArgs, out *controlapi.CgroupsResults) error {
	ctx := c.Kernel.SupervisorContext()
	for _, arg := range args.Args {
		cg, err := c.resolveCgroup(ctx, arg.File)
		if err != nil {
			out.Results = append(out.Results, newError(err))
			continue
		}

		val, err := cg.ReadControl(ctx, arg.File.Name)
		if err != nil {
			out.Results = append(out.Results, newError(err))
		} else {
			out.Results = append(out.Results, newValue(val))
		}
	}

	return nil
}

// WriteControlFiles is an RPC stub for batch-writing cgroupfs control files.
func (c *Cgroups) WriteControlFiles(args *controlapi.CgroupsWriteArgs, out *controlapi.CgroupsResults) error {
	ctx := c.Kernel.SupervisorContext()

	for _, arg := range args.Args {
		cg, err := c.resolveCgroup(ctx, arg.File)
		if err != nil {
			out.Results = append(out.Results, newError(err))
			continue
		}

		err = cg.WriteControl(ctx, arg.File.Name, arg.Value)
		if err != nil {
			out.Results = append(out.Results, newError(err))
		} else {
			out.Results = append(out.Results, newValue(""))
		}
	}
	return nil
}
