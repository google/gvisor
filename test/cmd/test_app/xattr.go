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

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/google/subcommands"
	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/runsc/flag"
)

const xattrSizeMax = 65536

// setXattr sets an extended attribute on a file. The value is passed as a
// base64-encoded string so that arbitrary binary blobs can be specified on
// the command line.
type setXattr struct {
	path  string
	name  string
	value string
}

// Name implements subcommands.Command.Name.
func (*setXattr) Name() string { return "setxattr" }

// Synopsis implements subcommands.Command.Synopsis.
func (*setXattr) Synopsis() string { return "sets an extended attribute (value is base64-encoded)" }

// Usage implements subcommands.Command.Usage.
func (*setXattr) Usage() string {
	return "setxattr --path=<path> --name=<name> --value=<base64>\n"
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *setXattr) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.path, "path", "", "path of the file to set the xattr on")
	f.StringVar(&c.name, "name", "", "name of the xattr")
	f.StringVar(&c.value, "value", "", "base64-encoded value of the xattr")
}

// Execute implements subcommands.Command.Execute.
func (c *setXattr) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if c.path == "" || c.name == "" {
		log.Print("--path and --name must be set")
		return subcommands.ExitUsageError
	}
	value, err := base64.StdEncoding.DecodeString(c.value)
	if err != nil {
		log.Printf("failed to decode --value %q: %v", c.value, err)
		return subcommands.ExitUsageError
	}
	if err := unix.Setxattr(c.path, c.name, value, 0); err != nil {
		log.Printf("setxattr(%q, %q) failed: %v", c.path, c.name, err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

// getXattr prints the base64-encoded value of an extended attribute to stdout.
type getXattr struct {
	path string
	name string
}

// Name implements subcommands.Command.Name.
func (*getXattr) Name() string { return "getxattr" }

// Synopsis implements subcommands.Command.Synopsis.
func (*getXattr) Synopsis() string {
	return "prints the base64-encoded value of an extended attribute to stdout"
}

// Usage implements subcommands.Command.Usage.
func (*getXattr) Usage() string {
	return "getxattr --path=<path> --name=<name>\n"
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *getXattr) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.path, "path", "", "path of the file to get the xattr from")
	f.StringVar(&c.name, "name", "", "name of the xattr")
}

// Execute implements subcommands.Command.Execute.
func (c *getXattr) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if c.path == "" || c.name == "" {
		log.Print("--path and --name must be set")
		return subcommands.ExitUsageError
	}
	buf := make([]byte, xattrSizeMax)
	n, err := unix.Getxattr(c.path, c.name, buf)
	if err != nil {
		log.Printf("getxattr(%q, %q) failed: %v", c.path, c.name, err)
		return subcommands.ExitFailure
	}
	fmt.Println(base64.StdEncoding.EncodeToString(buf[:n]))
	return subcommands.ExitSuccess
}
