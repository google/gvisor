// Copyright 2018 The containerd Authors.
// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proc

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/shim/runsc"
)

const (
	internalErrorCode = 128
	bufferSize        = 32
)

// ExitCh is the exit events channel for containers and exec processes
// inside the sandbox.
var ExitCh = make(chan Exit, bufferSize)

// TODO(mlaventure): move to runc package?
func getLastRuntimeError(r *runsc.Runsc) (string, error) {
	if r.Log == "" {
		return "", nil
	}

	f, err := os.OpenFile(r.Log, os.O_RDONLY, 0400)
	if err != nil {
		return "", err
	}

	var (
		errMsg string
		log    struct {
			Level string
			Msg   string
			Time  time.Time
		}
	)

	dec := json.NewDecoder(f)
	for err = nil; err == nil; {
		if err = dec.Decode(&log); err != nil && err != io.EOF {
			return "", err
		}
		if log.Level == "error" {
			errMsg = strings.TrimSpace(log.Msg)
		}
	}

	return errMsg, nil
}

func hasNoIO(r *CreateConfig) bool {
	return r.Stdin == "" && r.Stdout == "" && r.Stderr == ""
}
