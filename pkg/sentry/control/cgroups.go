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
	"fmt"
	"strings"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// Cgroups contains the state for cgroupfs related control commands.
type Cgroups struct {
	Kernel *kernel.Kernel
}

func (c *Cgroups) findCgroup(ctx context.Context, file CgroupControlFile) (kernel.Cgroup, error) {
	ctl, err := file.controller()
	if err != nil {
		return kernel.Cgroup{}, err
	}
	return c.Kernel.CgroupRegistry().FindCgroup(ctx, ctl, file.Path)
}

// CgroupControlFile identifies a specific control file within a
// specific cgroup, for the hierarchy with a given controller.
type CgroupControlFile struct {
	Controller string `json:"controller"`
	Path       string `json:"path"`
	Name       string `json:"name"`
}

func (f *CgroupControlFile) controller() (kernel.CgroupControllerType, error) {
	return kernel.ParseCgroupController(f.Controller)
}

// CgroupsResult represents the result of a cgroup operation.
type CgroupsResult struct {
	Data    string `json:"value"`
	IsError bool   `json:"is_error"`
}

// AsError interprets the result as an error.
func (r *CgroupsResult) AsError() error {
	if r.IsError {
		return fmt.Errorf(r.Data)
	}
	return nil
}

// Unpack splits CgroupsResult into a (value, error) tuple.
func (r *CgroupsResult) Unpack() (string, error) {
	if r.IsError {
		return "", fmt.Errorf(r.Data)
	}
	return r.Data, nil
}

func newValue(val string) CgroupsResult {
	return CgroupsResult{
		Data: strings.TrimSpace(val),
	}
}

func newError(err error) CgroupsResult {
	return CgroupsResult{
		Data:    err.Error(),
		IsError: true,
	}
}

// CgroupsResults represents the list of results for a batch command.
type CgroupsResults struct {
	Results []CgroupsResult `json:"results"`
}

func (o *CgroupsResults) appendValue(val string) {
	o.Results = append(o.Results, newValue(val))
}

func (o *CgroupsResults) appendError(err error) {
	o.Results = append(o.Results, newError(err))
}

// CgroupsReadArg represents the arguments for a single read command.
type CgroupsReadArg struct {
	File CgroupControlFile `json:"file"`
}

// CgroupsReadArgs represents the list of arguments for a batched read command.
type CgroupsReadArgs struct {
	Args []CgroupsReadArg `json:"args"`
}

// ReadControlFiles is an RPC stub for batch-reading cgroupfs control files.
func (c *Cgroups) ReadControlFiles(args *CgroupsReadArgs, out *CgroupsResults) error {
	ctx := c.Kernel.SupervisorContext()
	for _, arg := range args.Args {
		cg, err := c.findCgroup(ctx, arg.File)
		if err != nil {
			out.appendError(err)
			continue
		}

		val, err := cg.ReadControl(ctx, arg.File.Name)
		if err != nil {
			out.appendError(err)
		} else {
			out.appendValue(val)
		}
	}

	return nil
}

// CgroupsWriteArg represents the arguments for a single write command.
type CgroupsWriteArg struct {
	File  CgroupControlFile `json:"file"`
	Value string            `json:"value"`
}

// CgroupsWriteArgs represents the lust of arguments for a batched write command.
type CgroupsWriteArgs struct {
	Args []CgroupsWriteArg `json:"args"`
}

// WriteControlFiles is an RPC stub for batch-writing cgroupfs control files.
func (c *Cgroups) WriteControlFiles(args *CgroupsWriteArgs, out *CgroupsResults) error {
	ctx := c.Kernel.SupervisorContext()

	for _, arg := range args.Args {
		cg, err := c.findCgroup(ctx, arg.File)
		if err != nil {
			out.appendError(err)
			continue
		}

		err = cg.WriteControl(ctx, arg.File.Name, arg.Value)
		if err != nil {
			out.appendError(err)
		} else {
			out.appendValue("")
		}
	}
	return nil
}
