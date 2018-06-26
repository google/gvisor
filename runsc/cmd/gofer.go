// Copyright 2018 Google Inc.
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
	"os"
	"sync"
	"syscall"

	"context"
	"flag"
	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/p9"
	"gvisor.googlesource.com/gvisor/pkg/unet"
	"gvisor.googlesource.com/gvisor/runsc/fsgofer"
	"gvisor.googlesource.com/gvisor/runsc/specutils"
)

// Gofer implements subcommands.Command for the "gofer" command, which starts a
// filesystem gofer.  This command should not be called directly.
type Gofer struct {
	bundleDir string
	ioFDs     intFlags
	applyCaps bool
}

// Name implements subcommands.Command.
func (*Gofer) Name() string {
	return "gofer"
}

// Synopsis implements subcommands.Command.
func (*Gofer) Synopsis() string {
	return "launch a gofer process that serves files over 9P protocol (internal use only)"
}

// Usage implements subcommands.Command.
func (*Gofer) Usage() string {
	return `gofer [flags]`
}

// SetFlags implements subcommands.Command.
func (g *Gofer) SetFlags(f *flag.FlagSet) {
	f.StringVar(&g.bundleDir, "bundle", "", "path to the root of the bundle directory, defaults to the current directory")
	f.Var(&g.ioFDs, "io-fds", "list of FDs to connect 9P servers. They must follow this order: root first, then mounts as defined in the spec")
	f.BoolVar(&g.applyCaps, "apply-caps", true, "if true, apply capabilities to restrict what the Gofer process can do")
}

// Execute implements subcommands.Command.
func (g *Gofer) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if g.bundleDir == "" || len(g.ioFDs) < 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	// fsgofer should run with a umask of 0, because we want to preserve file
	// modes exactly as sent by the sandbox, which will have applied its own umask.
	syscall.Umask(0)

	spec, err := specutils.ReadSpec(g.bundleDir)
	if err != nil {
		Fatalf("error reading spec: %v", err)
	}

	if g.applyCaps {
		// Minimal set of capabilities needed by the Gofer to operate on files.
		caps := []string{
			"CAP_CHOWN",
			"CAP_DAC_OVERRIDE",
			"CAP_DAC_READ_SEARCH",
			"CAP_FOWNER",
			"CAP_FSETID",
		}
		lc := &specs.LinuxCapabilities{
			Bounding:  caps,
			Effective: caps,
			Permitted: caps,
		}

		// Disable caps when calling myself again.
		// Note: minimal argument handling for the default case to keep it simple.
		args := os.Args
		args = append(args, "--apply-caps=false")
		if err := setCapsAndCallSelf(spec, args, lc); err != nil {
			Fatalf("Unable to apply caps: %v", err)
		}
		panic("unreachable")
	}

	specutils.LogSpec(spec)

	// Start with root mount, then add any other addition mount as needed.
	ats := make([]p9.Attacher, 0, len(spec.Mounts)+1)
	p := absPath(g.bundleDir, spec.Root.Path)
	ats = append(ats, fsgofer.NewAttachPoint(p, fsgofer.Config{
		ROMount: spec.Root.Readonly,
		// Docker uses overlay2 by default for the root mount, and overlay2 does a copy-up when
		// each file is opened as writable. Thus, we open files lazily to avoid copy-up.
		LazyOpenForWrite: true,
	}))
	log.Infof("Serving %q mapped to %q on FD %d", "/", p, g.ioFDs[0])

	mountIdx := 1 // first one is the root
	for _, m := range spec.Mounts {
		if specutils.Is9PMount(m) {
			p = absPath(g.bundleDir, m.Source)
			ats = append(ats, fsgofer.NewAttachPoint(p, fsgofer.Config{
				ROMount:          isReadonlyMount(m.Options),
				LazyOpenForWrite: false,
			}))

			if mountIdx >= len(g.ioFDs) {
				Fatalf("No FD found for mount. Did you forget --io-fd? mount: %d, %v", len(g.ioFDs), m)
			}
			log.Infof("Serving %q mapped to %q on FD %d", m.Destination, p, g.ioFDs[mountIdx])
			mountIdx++
		}
	}
	if mountIdx != len(g.ioFDs) {
		Fatalf("Too many FDs passed for mounts. mounts: %d, FDs: %d", mountIdx, len(g.ioFDs))
	}

	runServers(ats, g.ioFDs)
	return subcommands.ExitSuccess
}

func runServers(ats []p9.Attacher, ioFDs []int) {
	// Run the loops and wait for all to exit.
	var wg sync.WaitGroup
	for i, ioFD := range ioFDs {
		wg.Add(1)
		go func(ioFD int, at p9.Attacher) {
			socket, err := unet.NewSocket(ioFD)
			if err != nil {
				Fatalf("err creating server on FD %d: %v", ioFD, err)
			}
			s := p9.NewServer(at)
			if err := s.Handle(socket); err != nil {
				Fatalf("P9 server returned error. Gofer is shutting down. FD: %d, err: %v", ioFD, err)
			}
			wg.Done()
		}(ioFD, ats[i])
	}
	wg.Wait()
	log.Infof("All 9P servers exited.")
}

func isReadonlyMount(opts []string) bool {
	for _, o := range opts {
		if o == "ro" {
			return true
		}
	}
	return false
}
