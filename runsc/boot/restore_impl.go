// Copyright 2024 The gVisor Authors.
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

//go:build !false
// +build !false

package boot

import (
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/proc"
	"gvisor.dev/gvisor/pkg/timing"
	"gvisor.dev/gvisor/runsc/config"
)

func preSaveImpl(*Loader, *control.SaveOpts) error {
	return nil
}

// Precondition: The kernel should be running.
func postRestoreImpl(*Loader, *timing.Timeline) error {
	return nil
}

// Precondition: The kernel should be running.
func postResumeImpl(*Loader, *timing.Timeline) error {
	return nil
}

func newProcInternalData(conf *config.Config, _ *specs.Spec) *proc.InternalData {
	return &proc.InternalData{
		GVisorMarkerFile: conf.GVisorMarkerFile,
	}
}

func (l *Loader) kernelInitExtra() {}
