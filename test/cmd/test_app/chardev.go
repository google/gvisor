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
	"fmt"
	"log"

	"github.com/google/subcommands"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/flag"
)

// chardevCheck checks the file type, device numbers, and open(2) behavior of
// a character device file.
type chardevCheck struct {
	path     string
	wantRdev string
	wantOpen string
	nullRW   bool
}

// Name implements subcommands.Command.Name.
func (*chardevCheck) Name() string {
	return "chardev-check"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*chardevCheck) Synopsis() string {
	return "checks the file type, device numbers, and open behavior of a character device file"
}

// Usage implements subcommands.Command.Usage.
func (*chardevCheck) Usage() string {
	return "chardev-check --path=<file> --want-rdev=<major:minor> --want-open=ok|enxio|not-enxio [--check-null-rw]"
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *chardevCheck) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.path, "path", "", "device file to check")
	f.StringVar(&c.wantRdev, "want-rdev", "", "expected device numbers as decimal major:minor")
	f.StringVar(&c.wantOpen, "want-open", "", `expected open(2) outcome: "ok" (must succeed), "enxio" (must fail with ENXIO), or "not-enxio" (may succeed or fail, but not with ENXIO)`)
	f.BoolVar(&c.nullRW, "check-null-rw", false, "after a successful open, check that reads return EOF and writes are accepted, like /dev/null")
}

// Execute implements subcommands.Command.Execute.
func (c *chardevCheck) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	var st unix.Stat_t
	if err := unix.Stat(c.path, &st); err != nil {
		log.Fatalf("stat(%q) failed: %v", c.path, err)
	}
	if ft := st.Mode & unix.S_IFMT; ft != unix.S_IFCHR {
		log.Fatalf("%q has file type %#o, want character device (%#o)", c.path, ft, unix.S_IFCHR)
	}
	if rdev := fmt.Sprintf("%d:%d", unix.Major(st.Rdev), unix.Minor(st.Rdev)); rdev != c.wantRdev {
		log.Fatalf("%q has device numbers %s, want %s", c.path, rdev, c.wantRdev)
	}

	openFlags := unix.O_RDONLY
	if c.nullRW {
		openFlags = unix.O_RDWR
	}
	fd, err := unix.Open(c.path, openFlags, 0)
	switch c.wantOpen {
	case "ok":
		if err != nil {
			log.Fatalf("open(%q) failed: %v, want success", c.path, err)
		}
	case "enxio":
		if err != unix.ENXIO {
			log.Fatalf("open(%q) returned error %v, want ENXIO", c.path, err)
		}
	case "not-enxio":
		if err == unix.ENXIO {
			log.Fatalf("open(%q) failed with ENXIO, want the open to reach the host device", c.path)
		}
	default:
		log.Printf("invalid --want-open value %q", c.wantOpen)
		return subcommands.ExitUsageError
	}
	if err != nil {
		// The open failed in the expected way; there is nothing to do with
		// the file.
		return subcommands.ExitSuccess
	}
	defer unix.Close(fd)

	if c.nullRW {
		buf := make([]byte, 8)
		if n, err := unix.Read(fd, buf); err != nil || n != 0 {
			log.Fatalf("read(%q) returned (%d, %v), want EOF (0, nil)", c.path, n, err)
		}
		data := []byte("discarded")
		if n, err := unix.Write(fd, data); err != nil || n != len(data) {
			log.Fatalf("write(%q) returned (%d, %v), want (%d, nil)", c.path, n, err, len(data))
		}
	}
	return subcommands.ExitSuccess
}
