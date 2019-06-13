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

package container

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/log"
)

// This file implements hooks as defined in OCI spec:
// https://github.com/opencontainers/runtime-spec/blob/master/config.md#toc22
//
// "hooks":{
// 		"prestart":[{
// 			"path":"/usr/bin/dockerd",
// 			"args":[
// 				"libnetwork-setkey", "arg2",
// 			]
// 		}]
// },

// executeHooksBestEffort executes hooks and logs warning in case they fail.
// Runs all hooks, always.
func executeHooksBestEffort(hooks []specs.Hook, s specs.State) {
	for _, h := range hooks {
		if err := executeHook(h, s); err != nil {
			log.Warningf("Failure to execute hook %+v, err: %v", h, err)
		}
	}
}

// executeHooks executes hooks until the first one fails or they all execute.
func executeHooks(hooks []specs.Hook, s specs.State) error {
	for _, h := range hooks {
		if err := executeHook(h, s); err != nil {
			return err
		}
	}
	return nil
}

func executeHook(h specs.Hook, s specs.State) error {
	log.Debugf("Executing hook %+v, state: %+v", h, s)

	if strings.TrimSpace(h.Path) == "" {
		return fmt.Errorf("empty path for hook")
	}
	if !filepath.IsAbs(h.Path) {
		return fmt.Errorf("path for hook is not absolute: %q", h.Path)
	}

	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Cmd{
		Path:   h.Path,
		Args:   h.Args,
		Env:    h.Env,
		Stdin:  bytes.NewReader(b),
		Stdout: &stdout,
		Stderr: &stderr,
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	c := make(chan error, 1)
	go func() {
		c <- cmd.Wait()
	}()

	var timer <-chan time.Time
	if h.Timeout != nil {
		timer = time.After(time.Duration(*h.Timeout) * time.Second)
	}
	select {
	case err := <-c:
		if err != nil {
			return fmt.Errorf("failure executing hook %q, err: %v\nstdout: %s\nstderr: %s", h.Path, err, stdout.String(), stderr.String())
		}
	case <-timer:
		cmd.Process.Kill()
		cmd.Wait()
		return fmt.Errorf("timeout executing hook %q\nstdout: %s\nstderr: %s", h.Path, stdout.String(), stderr.String())
	}

	log.Debugf("Execute hook %q success!", h.Path)
	return nil
}
