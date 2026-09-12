// Copyright 2018 The containerd Authors.
// Copyright 2019 The gVisor Authors.
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

// Package cli defines the command line interface for the V2 shim.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"

	containerdshim "github.com/containerd/containerd/v2/pkg/shim"
	// This import registers the runsc plugin with containerd.
	shim "gvisor.dev/gvisor/pkg/shim/v1"
	_ "gvisor.dev/gvisor/pkg/shim/v1/plugin"
)

type bootstrapParams struct {
	Version  int    `json:"version"`
	Address  string `json:"address"`
	Protocol string `json:"protocol"`
}

// Main is the main entrypoint.
func Main() {
	var isStart bool
	for _, arg := range os.Args {
		if arg == "start" {
			isStart = true
			break
		}
	}

	if isStart {
		oldStdout := os.Stdout
		r, w, err := os.Pipe()
		if err == nil {
			os.Stdout = w
			defer func() {
				_ = w.Close()
				os.Stdout = oldStdout
				var buf bytes.Buffer
				_, _ = io.Copy(&buf, r)
				_ = r.Close()
				out := strings.TrimSpace(buf.String())
				if strings.HasPrefix(out, "unix://") || strings.HasPrefix(out, "/") {
					bp := bootstrapParams{
						Version:  2,
						Address:  out,
						Protocol: "ttrpc",
					}
					if data, err := json.Marshal(bp); err == nil {
						_, _ = oldStdout.Write(data)
						return
					}
				}
				_, _ = oldStdout.Write(buf.Bytes())
			}()
		}
	}

	containerdshim.Run(context.Background(), shim.NewShimManager("io.containerd.runsc.v1"))
}
