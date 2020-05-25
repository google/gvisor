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

package cmd

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/flag"
)

var specTemplate = `{
	"ociVersion": "1.0.0",
	"process": {
		"terminal": true,
		"user": {
			"uid": 0,
			"gid": 0
		},
		"args": [
			%s
		],
		"env": [
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"TERM=xterm"
		],
		"cwd": "%s",
		"capabilities": {
			"bounding": [
				"CAP_AUDIT_WRITE",
				"CAP_KILL",
				"CAP_NET_BIND_SERVICE"
			],
			"effective": [
				"CAP_AUDIT_WRITE",
				"CAP_KILL",
				"CAP_NET_BIND_SERVICE"
			],
			"inheritable": [
				"CAP_AUDIT_WRITE",
				"CAP_KILL",
				"CAP_NET_BIND_SERVICE"
			],
			"permitted": [
				"CAP_AUDIT_WRITE",
				"CAP_KILL",
				"CAP_NET_BIND_SERVICE"
			],
			"ambient": [
				"CAP_AUDIT_WRITE",
				"CAP_KILL",
				"CAP_NET_BIND_SERVICE"
			]
		},
		"rlimits": [
			{
				"type": "RLIMIT_NOFILE",
				"hard": 1024,
				"soft": 1024
			}
		]
	},
	"root": {
		"path": "rootfs",
		"readonly": true
	},
	"hostname": "runsc",
	"mounts": [
		{
			"destination": "/proc",
			"type": "proc",
			"source": "proc"
		},
		{
			"destination": "/dev",
			"type": "tmpfs",
			"source": "tmpfs",
			"options": []
		},
		{
			"destination": "/sys",
			"type": "sysfs",
			"source": "sysfs",
			"options": [
				"nosuid",
				"noexec",
				"nodev",
				"ro"
			]
		}
	],
	"linux": {
		"namespaces": [
			{
				"type": "pid"
			},
			{
				"type": "network"
			},
			{
				"type": "ipc"
			},
			{
				"type": "uts"
			},
			{
				"type": "mount"
			}
		]
	}
}`

// Spec implements subcommands.Command for the "spec" command.
type Spec struct {
	bundle string
	cwd    string
	cmd    string
}

// Name implements subcommands.Command.Name.
func (*Spec) Name() string {
	return "spec"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Spec) Synopsis() string {
	return "create a new OCI bundle specification file"
}

// Usage implements subcommands.Command.Usage.
func (*Spec) Usage() string {
	return `spec [options] - create a new OCI bundle specification file.

The spec command creates a new specification file (config.json) for a new OCI bundle.

The specification file is a starter file that runs the "sh" command in the container. You
should edit the file to suit your needs. You can find out more about the format of the
specification file by visiting the OCI runtime spec repository:
https://github.com/opencontainers/runtime-spec/

EXAMPLE:
    $ mkdir -p bundle/rootfs
    $ cd bundle
    $ runsc spec -cmd /hello or runsc spec -cmd "<cmd>" -cwd "<cwd>"
    $ docker export $(docker create hello-world) | tar -xf - -C rootfs
    $ sudo runsc run hello

`
}

// SetFlags implements subcommands.Command.SetFlags.
func (s *Spec) SetFlags(f *flag.FlagSet) {
	f.StringVar(&s.bundle, "bundle", ".", "path to the root of the OCI bundle")
	f.StringVar(&s.cwd, "cwd", "/", "working directory that will be set for the executable")
	f.StringVar(&s.cmd, "cmd", "sh", "command to execute at container start")
}

// Execute implements subcommands.Command.Execute.
func (s *Spec) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	confPath := filepath.Join(s.bundle, "config.json")
	if _, err := os.Stat(confPath); !os.IsNotExist(err) {
		Fatalf("file %q already exists", confPath)
	}

	// convert cmd string to comma seperated arg list
	cargs := strings.Split(s.cmd, " ")
	for i, arg := range cargs {
		cargs[i] = strconv.Quote(arg)
	}
	cmdArgs := strings.Join(cargs, ",\n\t\t\t")

	// substitute cmd and cwd variables in the template
	specTemplate = fmt.Sprintf(specTemplate, cmdArgs, s.cwd)

	if err := ioutil.WriteFile(confPath, []byte(specTemplate), 0664); err != nil {
		Fatalf("writing to %q: %v", confPath, err)
	}

	return subcommands.ExitSuccess
}
