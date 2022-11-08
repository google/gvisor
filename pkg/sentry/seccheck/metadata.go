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

package seccheck

import (
	"fmt"
	"os"
	"path"

	"gvisor.dev/gvisor/pkg/fd"
)

// PointX represents the checkpoint X.
const (
	PointClone Point = iota
	PointContainerStart
	PointExecve
	PointExitNotifyParent
	PointTaskExit

	// Add new Points above this line.
	pointLengthBeforeSyscalls
)

// FieldCtxtX represents a data field that comes from the Context.
const (
	FieldCtxtContainerID Field = iota
	FieldCtxtCredentials
	FieldCtxtCwd
	FieldCtxtProcessName
	FieldCtxtThreadGroupID
	FieldCtxtThreadGroupStartTime
	FieldCtxtThreadID
	FieldCtxtThreadStartTime
	FieldCtxtTime
)

// Fields for container/start point.
const (
	// FieldContainerStartEnv is an optional field to collect list of environment
	// variables set for the container start process.
	FieldContainerStartEnv Field = iota
)

// Fields for sentry/execve point.
const (
	// FieldSentryExecveBinaryInfo is an optional field to collect information
	// about the binary being executed.
	FieldSentryExecveBinaryInfo Field = iota
)

// Points is a map with all the trace points registered in the system.
var Points = map[string]PointDesc{}

// Sinks is a map with all the sinks registered in the system.
var Sinks = map[string]SinkDesc{}

// defaultContextFields are the fields present in most trace points.
var defaultContextFields = []FieldDesc{
	{
		ID:   FieldCtxtTime,
		Name: "time",
	},
	{
		ID:   FieldCtxtThreadID,
		Name: "thread_id",
	},
	{
		ID:   FieldCtxtThreadStartTime,
		Name: "task_start_time",
	},
	{
		ID:   FieldCtxtThreadGroupID,
		Name: "group_id",
	},
	{
		ID:   FieldCtxtThreadGroupStartTime,
		Name: "thread_group_start_time",
	},
	{
		ID:   FieldCtxtContainerID,
		Name: "container_id",
	},
	{
		ID:   FieldCtxtCredentials,
		Name: "credentials",
	},
	{
		ID:   FieldCtxtCwd,
		Name: "cwd",
	},
	{
		ID:   FieldCtxtProcessName,
		Name: "process_name",
	},
}

// SinkDesc describes a sink that is available to be configured.
type SinkDesc struct {
	// Name is a unique identifier for the sink.
	Name string
	// Setup is called outside the protection of the sandbox. This is done to
	// allow the sink to do whatever is necessary to set it up. If it returns a
	// file, this file is donated to the sandbox and passed to the sink when New
	// is called. config is an opaque json object passed to the sink.
	Setup func(config map[string]any) (*os.File, error)
	// New creates a new sink. config is an opaque json object passed to the sink.
	// endpoing is a file descriptor to the file returned in Setup. It's set to -1
	// if Setup returned nil.
	New func(config map[string]any, endpoint *fd.FD) (Sink, error)
}

// RegisterSink registers a new sink to make it discoverable.
func RegisterSink(sink SinkDesc) {
	if _, ok := Sinks[sink.Name]; ok {
		panic(fmt.Sprintf("Sink %q already registered", sink.Name))
	}
	Sinks[sink.Name] = sink
}

// PointDesc describes a Point that is available to be configured.
// Schema for these points are defined in pkg/sentry/seccheck/points/.
type PointDesc struct {
	// ID is the point unique identifier.
	ID Point
	// Name is the point unique name. Convention is to use the following format:
	// namespace/name
	// Examples: container/start, sentry/clone, etc.
	Name string
	// OptionalFields is a list of fields that are available in the point, but not
	// collected unless specified when the Point is configured.
	// Examples: fd_path, data for read/write Points, etc.
	OptionalFields []FieldDesc
	// ContextFields is a list of fields that can be collected from the context,
	// but are not collected unless specified when the Point is configured.
	// Examples: container_id, PID, etc.
	ContextFields []FieldDesc
}

// FieldDesc describes an optional/context field that is available to be
// configured.
type FieldDesc struct {
	// ID is the numeric identifier of the field.
	ID Field
	// Name is the unique field name.
	Name string
}

func registerPoint(pt PointDesc) {
	if _, ok := Points[pt.Name]; ok {
		panic(fmt.Sprintf("Point %q already registered", pt.Name))
	}
	if err := validateFields(pt.OptionalFields); err != nil {
		panic(err)
	}
	if err := validateFields(pt.ContextFields); err != nil {
		panic(err)
	}
	Points[pt.Name] = pt
}

func validateFields(fields []FieldDesc) error {
	ids := make(map[Field]FieldDesc)
	names := make(map[string]FieldDesc)
	for _, f := range fields {
		if other, ok := names[f.Name]; ok {
			return fmt.Errorf("field %q has repeated name with field %q", f.Name, other.Name)
		}
		if other, ok := ids[f.ID]; ok {
			return fmt.Errorf("field %q has repeated ID (%d) with field %q", f.Name, f.ID, other.Name)
		}
		names[f.Name] = f
		ids[f.ID] = f
	}
	return nil
}

func addRawSyscallPoint(sysno uintptr) {
	addSyscallPointHelper(SyscallRawEnter, sysno, fmt.Sprintf("sysno/%d", sysno), nil)
}

func addSyscallPoint(sysno uintptr, name string, optionalFields []FieldDesc) {
	addSyscallPointHelper(SyscallEnter, sysno, name, optionalFields)
}

func addSyscallPointHelper(typ SyscallType, sysno uintptr, name string, optionalFields []FieldDesc) {
	registerPoint(PointDesc{
		ID:             GetPointForSyscall(typ, sysno),
		Name:           path.Join("syscall", name, "enter"),
		OptionalFields: optionalFields,
		ContextFields:  defaultContextFields,
	})
	registerPoint(PointDesc{
		ID:             GetPointForSyscall(typ+1, sysno),
		Name:           path.Join("syscall", name, "exit"),
		OptionalFields: optionalFields,
		ContextFields:  defaultContextFields,
	})
}

// These are all the Points available in the system.
func init() {
	// Points from the container namespace.
	registerPoint(PointDesc{
		ID:   PointContainerStart,
		Name: "container/start",
		OptionalFields: []FieldDesc{
			{
				ID:   FieldContainerStartEnv,
				Name: "env",
			},
		},
		ContextFields: defaultContextFields,
	})

	// Points from the sentry namespace.
	registerPoint(PointDesc{
		ID:            PointClone,
		Name:          "sentry/clone",
		ContextFields: defaultContextFields,
	})
	registerPoint(PointDesc{
		ID:   PointExecve,
		Name: "sentry/execve",
		OptionalFields: []FieldDesc{
			{
				ID:   FieldSentryExecveBinaryInfo,
				Name: "binary_info",
			},
		},
		ContextFields: defaultContextFields,
	})
	registerPoint(PointDesc{
		ID:            PointExitNotifyParent,
		Name:          "sentry/exit_notify_parent",
		ContextFields: defaultContextFields,
	})
	registerPoint(PointDesc{
		ID:            PointTaskExit,
		Name:          "sentry/task_exit",
		ContextFields: defaultContextFields,
	})
}
