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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"flag"
	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/fsgofer"
	"gvisor.dev/gvisor/runsc/fsgofer/filter"
	"gvisor.dev/gvisor/runsc/specutils"
)

var caps = []string{
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_DAC_READ_SEARCH",
	"CAP_FOWNER",
	"CAP_FSETID",
	"CAP_SYS_CHROOT",
}

// goferCaps is the minimal set of capabilities needed by the Gofer to operate
// on files.
var goferCaps = &specs.LinuxCapabilities{
	Bounding:  caps,
	Effective: caps,
	Permitted: caps,
}

// Gofer implements subcommands.Command for the "gofer" command, which starts a
// filesystem gofer.  This command should not be called directly.
type Gofer struct {
	bundleDir      string
	ioFDs          intFlags
	applyCaps      bool
	hostUDSAllowed bool
	setUpRoot      bool

	panicOnWrite bool
	specFD       int
	mountsFD     int
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
	f.BoolVar(&g.hostUDSAllowed, "host-uds-allowed", false, "if true, allow the Gofer to mount a host UDS")
	f.BoolVar(&g.panicOnWrite, "panic-on-write", false, "if true, panics on attempts to write to RO mounts. RW mounts are unnaffected")
	f.BoolVar(&g.setUpRoot, "setup-root", true, "if true, set up an empty root for the process")
	f.IntVar(&g.specFD, "spec-fd", -1, "required fd with the container spec")
	f.IntVar(&g.mountsFD, "mounts-fd", -1, "mountsFD is the file descriptor to write list of mounts after they have been resolved (direct paths, no symlinks).")
}

// Execute implements subcommands.Command.
func (g *Gofer) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if g.bundleDir == "" || len(g.ioFDs) < 1 || g.specFD < 0 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	specFile := os.NewFile(uintptr(g.specFD), "spec file")
	defer specFile.Close()
	spec, err := specutils.ReadSpecFromFile(g.bundleDir, specFile)
	if err != nil {
		Fatalf("reading spec: %v", err)
	}

	conf := args[0].(*boot.Config)

	if g.setUpRoot {
		if err := setupRootFS(spec, conf); err != nil {
			Fatalf("Error setting up root FS: %v", err)
		}
	}
	if g.applyCaps {
		// Disable caps when calling myself again.
		// Note: minimal argument handling for the default case to keep it simple.
		args := os.Args
		args = append(args, "--apply-caps=false", "--setup-root=false")
		if err := setCapsAndCallSelf(args, goferCaps); err != nil {
			Fatalf("Unable to apply caps: %v", err)
		}
		panic("unreachable")
	}

	// Find what path is going to be served by this gofer.
	root := spec.Root.Path
	if !conf.TestOnlyAllowRunAsCurrentUserWithoutChroot {
		root = "/root"
	}

	// Resolve mount points paths, then replace mounts from our spec and send the
	// mount list over to the sandbox, so they are both in sync.
	//
	// Note that all mount points have been mounted in the proper location in
	// setupRootFS().
	cleanMounts, err := resolveMounts(spec.Mounts, root)
	if err != nil {
		Fatalf("Failure to resolve mounts: %v", err)
	}
	spec.Mounts = cleanMounts
	go func() {
		if err := g.writeMounts(cleanMounts); err != nil {
			panic(fmt.Sprintf("Failed to write mounts: %v", err))
		}
	}()

	specutils.LogSpec(spec)

	// fsgofer should run with a umask of 0, because we want to preserve file
	// modes exactly as sent by the sandbox, which will have applied its own umask.
	syscall.Umask(0)

	if err := fsgofer.OpenProcSelfFD(); err != nil {
		Fatalf("failed to open /proc/self/fd: %v", err)
	}

	if err := syscall.Chroot(root); err != nil {
		Fatalf("failed to chroot to %q: %v", root, err)
	}
	if err := syscall.Chdir("/"); err != nil {
		Fatalf("changing working dir: %v", err)
	}
	log.Infof("Process chroot'd to %q", root)

	// Start with root mount, then add any other additional mount as needed.
	ats := make([]p9.Attacher, 0, len(spec.Mounts)+1)
	ap, err := fsgofer.NewAttachPoint("/", fsgofer.Config{
		ROMount:      spec.Root.Readonly,
		PanicOnWrite: g.panicOnWrite,
	})
	if err != nil {
		Fatalf("creating attach point: %v", err)
	}
	ats = append(ats, ap)
	log.Infof("Serving %q mapped to %q on FD %d (ro: %t)", "/", root, g.ioFDs[0], spec.Root.Readonly)

	mountIdx := 1 // first one is the root
	for _, m := range spec.Mounts {
		if specutils.Is9PMount(m) {
			cfg := fsgofer.Config{
				ROMount:        isReadonlyMount(m.Options),
				PanicOnWrite:   g.panicOnWrite,
				HostUDSAllowed: g.hostUDSAllowed,
			}
			ap, err := fsgofer.NewAttachPoint(m.Destination, cfg)
			if err != nil {
				Fatalf("creating attach point: %v", err)
			}
			ats = append(ats, ap)

			if mountIdx >= len(g.ioFDs) {
				Fatalf("no FD found for mount. Did you forget --io-fd? mount: %d, %v", len(g.ioFDs), m)
			}
			log.Infof("Serving %q mapped on FD %d (ro: %t)", m.Destination, g.ioFDs[mountIdx], cfg.ROMount)
			mountIdx++
		}
	}
	if mountIdx != len(g.ioFDs) {
		Fatalf("too many FDs passed for mounts. mounts: %d, FDs: %d", mountIdx, len(g.ioFDs))
	}

	if g.hostUDSAllowed {
		filter.InstallUDSFilters()
	}

	if err := filter.Install(); err != nil {
		Fatalf("installing seccomp filters: %v", err)
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
				Fatalf("creating server on FD %d: %v", ioFD, err)
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

func (g *Gofer) writeMounts(mounts []specs.Mount) error {
	bytes, err := json.Marshal(mounts)
	if err != nil {
		return err
	}

	f := os.NewFile(uintptr(g.mountsFD), "mounts file")
	defer f.Close()

	for written := 0; written < len(bytes); {
		w, err := f.Write(bytes[written:])
		if err != nil {
			return err
		}
		written += w
	}
	return nil
}

func isReadonlyMount(opts []string) bool {
	for _, o := range opts {
		if o == "ro" {
			return true
		}
	}
	return false
}

func setupRootFS(spec *specs.Spec, conf *boot.Config) error {
	// Convert all shared mounts into slaves to be sure that nothing will be
	// propagated outside of our namespace.
	if err := syscall.Mount("", "/", "", syscall.MS_SLAVE|syscall.MS_REC, ""); err != nil {
		Fatalf("error converting mounts: %v", err)
	}

	root := spec.Root.Path
	if !conf.TestOnlyAllowRunAsCurrentUserWithoutChroot {
		// FIXME: runsc can't be re-executed without
		// /proc, so we create a tmpfs mount, mount ./proc and ./root
		// there, then move this mount to the root and after
		// setCapsAndCallSelf, runsc will chroot into /root.
		//
		// We need a directory to construct a new root and we know that
		// runsc can't start without /proc, so we can use it for this.
		flags := uintptr(syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC)
		if err := syscall.Mount("runsc-root", "/proc", "tmpfs", flags, ""); err != nil {
			Fatalf("error mounting tmpfs: %v", err)
		}

		// Prepare tree structure for pivot_root(2).
		os.Mkdir("/proc/proc", 0755)
		os.Mkdir("/proc/root", 0755)
		if err := syscall.Mount("runsc-proc", "/proc/proc", "proc", flags|syscall.MS_RDONLY, ""); err != nil {
			Fatalf("error mounting proc: %v", err)
		}
		root = "/proc/root"
	}

	// Mount root path followed by submounts.
	if err := syscall.Mount(spec.Root.Path, root, "bind", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("mounting root on root (%q) err: %v", root, err)
	}

	flags := uint32(syscall.MS_SLAVE | syscall.MS_REC)
	if spec.Linux != nil && spec.Linux.RootfsPropagation != "" {
		flags = specutils.PropOptionsToFlags([]string{spec.Linux.RootfsPropagation})
	}
	if err := syscall.Mount("", root, "", uintptr(flags), ""); err != nil {
		return fmt.Errorf("mounting root (%q) with flags: %#x, err: %v", root, flags, err)
	}

	// Replace the current spec, with the clean spec with symlinks resolved.
	if err := setupMounts(spec.Mounts, root); err != nil {
		Fatalf("error setting up FS: %v", err)
	}

	// Create working directory if needed.
	if spec.Process.Cwd != "" {
		dst, err := resolveSymlinks(root, spec.Process.Cwd)
		if err != nil {
			return fmt.Errorf("resolving symlinks to %q: %v", spec.Process.Cwd, err)
		}
		if err := os.MkdirAll(dst, 0755); err != nil {
			return fmt.Errorf("creating working directory %q: %v", spec.Process.Cwd, err)
		}
	}

	// Check if root needs to be remounted as readonly.
	if spec.Root.Readonly {
		// If root is a mount point but not read-only, we can change mount options
		// to make it read-only for extra safety.
		log.Infof("Remounting root as readonly: %q", root)
		flags := uintptr(syscall.MS_BIND | syscall.MS_REMOUNT | syscall.MS_RDONLY | syscall.MS_REC)
		if err := syscall.Mount(root, root, "bind", flags, ""); err != nil {
			return fmt.Errorf("remounting root as read-only with source: %q, target: %q, flags: %#x, err: %v", root, root, flags, err)
		}
	}

	if !conf.TestOnlyAllowRunAsCurrentUserWithoutChroot {
		if err := pivotRoot("/proc"); err != nil {
			Fatalf("faild to change the root file system: %v", err)
		}
		if err := os.Chdir("/"); err != nil {
			Fatalf("failed to change working directory")
		}
	}
	return nil
}

// setupMounts binds mount all mounts specified in the spec in their correct
// location inside root. It will resolve relative paths and symlinks. It also
// creates directories as needed.
func setupMounts(mounts []specs.Mount, root string) error {
	for _, m := range mounts {
		if m.Type != "bind" || !specutils.IsSupportedDevMount(m) {
			continue
		}

		dst, err := resolveSymlinks(root, m.Destination)
		if err != nil {
			return fmt.Errorf("resolving symlinks to %q: %v", m.Destination, err)
		}

		flags := specutils.OptionsToFlags(m.Options) | syscall.MS_BIND
		log.Infof("Mounting src: %q, dst: %q, flags: %#x", m.Source, dst, flags)
		if err := specutils.Mount(m.Source, dst, m.Type, flags); err != nil {
			return fmt.Errorf("mounting %v: %v", m, err)
		}

		// Set propagation options that cannot be set together with other options.
		flags = specutils.PropOptionsToFlags(m.Options)
		if flags != 0 {
			if err := syscall.Mount("", dst, "", uintptr(flags), ""); err != nil {
				return fmt.Errorf("mount dst: %q, flags: %#x, err: %v", dst, flags, err)
			}
		}
	}
	return nil
}

// resolveMounts resolved relative paths and symlinks to mount points.
//
// Note: mount points must already be in place for resolution to work.
// Otherwise, it may follow symlinks to locations that would be overwritten
// with another mount point and return the wrong location. In short, make sure
// setupMounts() has been called before.
func resolveMounts(mounts []specs.Mount, root string) ([]specs.Mount, error) {
	cleanMounts := make([]specs.Mount, 0, len(mounts))
	for _, m := range mounts {
		if m.Type != "bind" || !specutils.IsSupportedDevMount(m) {
			cleanMounts = append(cleanMounts, m)
			continue
		}
		dst, err := resolveSymlinks(root, m.Destination)
		if err != nil {
			return nil, fmt.Errorf("resolving symlinks to %q: %v", m.Destination, err)
		}
		relDst, err := filepath.Rel(root, dst)
		if err != nil {
			panic(fmt.Sprintf("%q could not be made relative to %q: %v", dst, root, err))
		}
		cpy := m
		cpy.Destination = filepath.Join("/", relDst)
		cleanMounts = append(cleanMounts, cpy)
	}
	return cleanMounts, nil
}

// ResolveSymlinks walks 'rel' having 'root' as the root directory. If there are
// symlinks, they are evaluated relative to 'root' to ensure the end result is
// the same as if the process was running inside the container.
func resolveSymlinks(root, rel string) (string, error) {
	return resolveSymlinksImpl(root, root, rel, 255)
}

func resolveSymlinksImpl(root, base, rel string, followCount uint) (string, error) {
	if followCount == 0 {
		return "", fmt.Errorf("too many symlinks to follow, path: %q", filepath.Join(base, rel))
	}

	rel = filepath.Clean(rel)
	for _, name := range strings.Split(rel, string(filepath.Separator)) {
		if name == "" {
			continue
		}
		// Note that Join() resolves things like ".." and returns a clean path.
		path := filepath.Join(base, name)
		if !strings.HasPrefix(path, root) {
			// One cannot '..' their way out of root.
			path = root
			continue
		}
		fi, err := os.Lstat(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return "", err
			}
			// Not found means there is no symlink to check. Just keep walking dirs.
			base = path
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return "", err
			}
			if filepath.IsAbs(link) {
				base = root
			}
			base, err = resolveSymlinksImpl(root, base, link, followCount-1)
			if err != nil {
				return "", err
			}
			continue
		}
		base = path
	}
	return base, nil
}
