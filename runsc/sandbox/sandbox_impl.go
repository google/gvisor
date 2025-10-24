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

package sandbox

import (
	"os/exec"

	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/donation"
)

func createSandboxProcessExtra(conf *config.Config, args *Args, cmd *exec.Cmd, donations *donation.Agency) error {
	return nil
}

type checkpointOptsExtra struct{}

func setCheckpointOptsImpl(conf *config.Config, imagePath string, opts CheckpointOpts, opt *control.SaveOpts) error {
	return setCheckpointOptsForLocalCheckpointFiles(conf, imagePath, opts, opt)
}

func (s *Sandbox) setRestoreOptsImpl(conf *config.Config, imagePath string, direct bool, opt *boot.RestoreOpts) error {
	return s.setRestoreOptsForLocalCheckpointFiles(conf, imagePath, direct, opt)
}
