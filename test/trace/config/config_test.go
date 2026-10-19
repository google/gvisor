// Copyright 2026 The gVisor Authors.
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

package config

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAllPoints(t *testing.T) {
	const metadata = `printf 'POINTS (1)\nName: test, optional fields: [one|two], context fields: [time]\n\nSINKS (0)\n'
`
	for _, test := range []struct {
		name    string
		command string
		wantErr string
		exit    int
	}{
		{name: "metadata", command: metadata},
		{
			name:    "stderr warning",
			command: "printf 'warning: GOCOVERDIR not set, no coverage data emitted\\n' >&2\n" + metadata,
		},
		{
			name:    "malformed stdout",
			command: "printf 'warning on stdout\\n'\n" + metadata,
			wantErr: "missing POINTS header",
		},
		{
			name:    "metadata only on stderr",
			command: "exec 1>&2\n" + metadata,
			wantErr: "returned empty",
		},
		{
			name:    "command failure",
			command: metadata + "printf 'metadata command failed\\n' >&2\nexit 7\n",
			exit:    7,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "runsc")
			if err := os.WriteFile(path, []byte("#!/bin/sh\n"+test.command), 0700); err != nil {
				t.Fatal(err)
			}
			var builder Builder
			err := builder.LoadAllPoints(path)
			if test.exit != 0 {
				exitErr, ok := errors.AsType[*exec.ExitError](err)
				if !ok || exitErr.ExitCode() != test.exit {
					t.Fatalf("LoadAllPoints() = %v, want exit %d", err, test.exit)
				}
			} else if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("LoadAllPoints() = %v, want error containing %q", err, test.wantErr)
				}
			} else {
				if err != nil {
					t.Fatalf("LoadAllPoints(): %v", err)
				}
				if len(builder.points) != 1 || builder.points[0].Name != "test" || strings.Join(builder.points[0].OptionalFields, "|") != "one|two" || strings.Join(builder.points[0].ContextFields, "|") != "time" {
					t.Errorf("LoadAllPoints() points = %+v, want one point with all fields", builder.points)
				}
			}
			if (test.exit != 0 || test.wantErr != "") && len(builder.points) != 0 {
				t.Errorf("failed LoadAllPoints() retained points: %+v", builder.points)
			}
		})
	}
}
