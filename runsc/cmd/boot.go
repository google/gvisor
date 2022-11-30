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
	"os/exec"
	"runtime/debug"
	"strings"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/coretag"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/profile"
	"gvisor.dev/gvisor/runsc/specutils"
)

// Boot implements subcommands.Command for the "boot" command which starts a
// new sandbox. It should not be called directly.
type Boot struct {
	// bundleDir is the directory containing the OCI spec.
	bundleDir string

	// specFD is the file descriptor that the spec will be read from.
	specFD int

	// controllerFD is the file descriptor of a stream socket for the
	// control server that is donated to this process.
	controllerFD int

	// deviceFD is the file descriptor for the platform device file.
	deviceFD int

	// ioFDs is the list of FDs used to connect to FS gofers.
	ioFDs intFlags

	// overlayFilestoreFD is the host FD to the regular file which will back the
	// overlay's upper tmpfs mount for all containers.
	overlayFilestoreFD int

	// stdioFDs are the fds for stdin, stdout, and stderr. They must be
	// provided in that order.
	stdioFDs intFlags

	// applyCaps determines if capabilities defined in the spec should be applied
	// to the process.
	applyCaps bool

	// setUpChroot is set to true if the sandbox is started in an empty root.
	setUpRoot bool

	// cpuNum number of CPUs to create inside the sandbox.
	cpuNum int

	// totalMem sets the initial amount of total memory to report back to the
	// container.
	totalMem uint64

	// userLogFD is the file descriptor to write user logs to.
	userLogFD int

	// startSyncFD is the file descriptor to synchronize runsc and sandbox.
	startSyncFD int

	// mountsFD is the file descriptor to read list of mounts after they have
	// been resolved (direct paths, no symlinks). They are resolved outside the
	// sandbox (e.g. gofer) and sent through this FD.
	mountsFD int

	podInitConfigFD int

	sinkFDs intFlags

	// pidns is set if the sandbox is in its own pid namespace.
	pidns bool

	// attached is set to true to kill the sandbox process when the parent process
	// terminates. This flag is set when the command execve's itself because
	// parent death signal doesn't propagate through execve when uid/gid changes.
	attached bool

	// productName is the value to show in
	// /sys/devices/virtual/dmi/id/product_name.
	productName string

	// FDs for profile data.
	profileFDs profile.FDArgs

	// procMountSyncFD is a file descriptor that has to be closed when the
	// procfs mount isn't needed anymore.
	procMountSyncFD int
}

// Name implements subcommands.Command.Name.
func (*Boot) Name() string {
	return "boot"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Boot) Synopsis() string {
	return "launch a sandbox process"
}

// Usage implements subcommands.Command.Usage.
func (*Boot) Usage() string {
	return `boot [flags] <container id>`
}

// SetFlags implements subcommands.Command.SetFlags.
func (b *Boot) SetFlags(f *flag.FlagSet) {
	f.StringVar(&b.bundleDir, "bundle", "", "required path to the root of the bundle directory")
	f.BoolVar(&b.applyCaps, "apply-caps", false, "if true, apply capabilities defined in the spec to the process")
	f.BoolVar(&b.setUpRoot, "setup-root", false, "if true, set up an empty root for the process")
	f.BoolVar(&b.pidns, "pidns", false, "if true, the sandbox is in its own PID namespace")
	f.IntVar(&b.cpuNum, "cpu-num", 0, "number of CPUs to create inside the sandbox")
	f.IntVar(&b.procMountSyncFD, "proc-mount-sync-fd", -1, "file descriptor that has to be closed when /proc isn't needed")
	f.Uint64Var(&b.totalMem, "total-memory", 0, "sets the initial amount of total memory to report back to the container")
	f.BoolVar(&b.attached, "attached", false, "if attached is true, kills the sandbox process when the parent process terminates")
	f.StringVar(&b.productName, "product-name", "", "value to show in /sys/devices/virtual/dmi/id/product_name")

	// Open FDs that are donated to the sandbox.
	f.IntVar(&b.specFD, "spec-fd", -1, "required fd with the container spec")
	f.IntVar(&b.controllerFD, "controller-fd", -1, "required FD of a stream socket for the control server that must be donated to this process")
	f.IntVar(&b.deviceFD, "device-fd", -1, "FD for the platform device file")
	f.Var(&b.ioFDs, "io-fds", "list of FDs to connect gofer clients. They must follow this order: root first, then mounts as defined in the spec")
	f.Var(&b.stdioFDs, "stdio-fds", "list of FDs containing sandbox stdin, stdout, and stderr in that order")
	f.IntVar(&b.overlayFilestoreFD, "overlay-filestore-fd", -1, "FD to a regular file which will be used to back the overlay's tmpfs upper mount.")
	f.IntVar(&b.userLogFD, "user-log-fd", 0, "file descriptor to write user logs to. 0 means no logging.")
	f.IntVar(&b.startSyncFD, "start-sync-fd", -1, "required FD to used to synchronize sandbox startup")
	f.IntVar(&b.mountsFD, "mounts-fd", -1, "mountsFD is the file descriptor to read list of mounts after they have been resolved (direct paths, no symlinks).")
	f.IntVar(&b.podInitConfigFD, "pod-init-config-fd", -1, "file descriptor to the pod init configuration file.")
	f.Var(&b.sinkFDs, "sink-fds", "ordered list of file descriptors to be used by the sinks defined in --pod-init-config.")

	// Profiling flags.
	b.profileFDs.SetFromFlags(f)
}

// Execute implements subcommands.Command.Execute.  It starts a sandbox in a
// waiting state.
func (b *Boot) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if b.specFD == -1 || b.controllerFD == -1 || b.startSyncFD == -1 || f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	conf := args[0].(*config.Config)

	// Set traceback level
	debug.SetTraceback(conf.Traceback)

	if len(b.productName) == 0 {
		// Do this before chroot takes effect, otherwise we can't read /sys.
		if product, err := ioutil.ReadFile("/sys/devices/virtual/dmi/id/product_name"); err != nil {
			log.Warningf("Not setting product_name: %v", err)
		} else {
			b.productName = strings.TrimSpace(string(product))
			log.Infof("Setting product_name: %q", b.productName)
		}
	}

	if b.attached {
		// Ensure this process is killed after parent process terminates when
		// attached mode is enabled. In the unfortunate event that the parent
		// terminates before this point, this process leaks.
		if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0); err != nil {
			util.Fatalf("error setting parent death signal: %v", err)
		}
	}

	if b.setUpRoot {
		if err := setUpChroot(b.pidns); err != nil {
			util.Fatalf("error setting up chroot: %v", err)
		}

		if !b.applyCaps && !conf.Rootless {
			// /proc is umounted from a forked process, because the
			// current one is going to re-execute itself without
			// capabilities.
			cmd, w := b.execProcUmounter()
			defer w.Close()
			defer cmd.Wait()
			if b.procMountSyncFD != -1 {
				panic("procMountSyncFD is set")
			}
			b.procMountSyncFD = int(w.Fd())

			// Remove --apply-caps arg to call myself. It has already been done.
			args := b.prepareArgs("setup-root")

			// Clear FD_CLOEXEC.
			if _, _, errno := unix.RawSyscall(unix.SYS_FCNTL, w.Fd(), unix.F_SETFD, 0); errno != 0 {
				util.Fatalf("error clearing CLOEXEC: %v", errno)
			}
			// Note that we've already read the spec from the spec FD, and
			// we will read it again after the exec call. This works
			// because the ReadSpecFromFile function seeks to the beginning
			// of the file before reading.
			util.Fatalf("callSelfAsNobody(%v): %v", args, callSelfAsNobody(args))
			panic("unreachable")
		}
	}

	// Get the spec from the specFD.
	specFile := os.NewFile(uintptr(b.specFD), "spec file")
	defer specFile.Close()
	spec, err := specutils.ReadSpecFromFile(b.bundleDir, specFile, conf)
	if err != nil {
		util.Fatalf("reading spec: %v", err)
	}
	specutils.LogSpec(spec)

	if b.applyCaps {
		caps := spec.Process.Capabilities
		if caps == nil {
			caps = &specs.LinuxCapabilities{}
		}

		gPlatform, err := platform.Lookup(conf.Platform)
		if err != nil {
			util.Fatalf("loading platform: %v", err)
		}
		if gPlatform.Requirements().RequiresCapSysPtrace {
			// Ptrace platform requires extra capabilities.
			const c = "CAP_SYS_PTRACE"
			caps.Bounding = append(caps.Bounding, c)
			caps.Effective = append(caps.Effective, c)
			caps.Permitted = append(caps.Permitted, c)
		}

		// Remove --apply-caps and --setup-root arg to call myself. Both have
		// already been done.
		args := b.prepareArgs("setup-root", "apply-caps")

		// Note that we've already read the spec from the spec FD, and
		// we will read it again after the exec call. This works
		// because the ReadSpecFromFile function seeks to the beginning
		// of the file before reading.
		util.Fatalf("setCapsAndCallSelf(%v, %v): %v", args, caps, setCapsAndCallSelf(args, caps))
		panic("unreachable")
	}

	// At this point we won't re-execute, so it's safe to limit via rlimits. Any
	// limit >= 0 works. If the limit is lower than the current number of open
	// files, then Setrlimit will succeed, and the next open will fail.
	if conf.FDLimit > -1 {
		rlimit := unix.Rlimit{
			Cur: uint64(conf.FDLimit),
			Max: uint64(conf.FDLimit),
		}
		switch err := unix.Setrlimit(unix.RLIMIT_NOFILE, &rlimit); err {
		case nil:
		case unix.EPERM:
			log.Warningf("FD limit %d is higher than the current hard limit or system-wide maximum", conf.FDLimit)
		default:
			util.Fatalf("Failed to set RLIMIT_NOFILE: %v", err)
		}
	}

	// Read resolved mount list and replace the original one from the spec.
	mountsFile := os.NewFile(uintptr(b.mountsFD), "mounts file")
	cleanMounts, err := specutils.ReadMounts(mountsFile)
	if err != nil {
		mountsFile.Close()
		util.Fatalf("Error reading mounts file: %v", err)
	}
	mountsFile.Close()
	spec.Mounts = cleanMounts

	if conf.EnableCoreTags {
		if err := coretag.Enable(); err != nil {
			util.Fatalf("Failed to core tag sentry: %v", err)
		}

		// Verify that all sentry threads are properly core tagged, and log
		// current core tag.
		coreTags, err := coretag.GetAllCoreTags(os.Getpid())
		if err != nil {
			util.Fatalf("Failed read current core tags: %v", err)
		}
		if len(coreTags) != 1 {
			util.Fatalf("Not all child threads were core tagged the same. Tags=%v", coreTags)
		}
		log.Infof("Core tag enabled (core tag=%d)", coreTags[0])
	}

	// Create the loader.
	bootArgs := boot.Args{
		ID:                 f.Arg(0),
		Spec:               spec,
		Conf:               conf,
		ControllerFD:       b.controllerFD,
		Device:             os.NewFile(uintptr(b.deviceFD), "platform device"),
		GoferFDs:           b.ioFDs.GetArray(),
		StdioFDs:           b.stdioFDs.GetArray(),
		OverlayFilestoreFD: b.overlayFilestoreFD,
		NumCPU:             b.cpuNum,
		TotalMem:           b.totalMem,
		UserLogFD:          b.userLogFD,
		ProductName:        b.productName,
		PodInitConfigFD:    b.podInitConfigFD,
		SinkFDs:            b.sinkFDs.GetArray(),
		ProfileOpts:        b.profileFDs.ToOpts(),
	}
	l, err := boot.New(bootArgs)
	if err != nil {
		util.Fatalf("creating loader: %v", err)
	}

	// Fatalf exits the process and doesn't run defers.
	// 'l' must be destroyed explicitly after this point!

	if b.procMountSyncFD != -1 {
		l.PreSeccompCallback = func() {
			syncFile := os.NewFile(uintptr(b.procMountSyncFD), "sync file")
			buf := make([]byte, 1)
			if w, err := syncFile.Write(buf); err != nil || w != 1 {
				util.Fatalf("unable to write into the proc umounter descriptor: %v", err)
			}
			syncFile.Close()

			var waitStatus unix.WaitStatus
			if _, err := unix.Wait4(0, &waitStatus, 0, nil); err != nil {
				util.Fatalf("error waiting for the proc umounter process: %v", err)
			}
			if !waitStatus.Exited() || waitStatus.ExitStatus() != 0 {
				util.Fatalf("the proc umounter process failed: %v", waitStatus)
			}
			if err := unix.Access("/proc/self", unix.F_OK); err != unix.ENOENT {
				util.Fatalf("/proc is still accessible")
			}
		}
	}

	// Notify the parent process the sandbox has booted (and that the controller
	// is up).
	startSyncFile := os.NewFile(uintptr(b.startSyncFD), "start-sync file")
	buf := make([]byte, 1)
	if w, err := startSyncFile.Write(buf); err != nil || w != 1 {
		l.Destroy()
		util.Fatalf("unable to write into the start-sync descriptor: %v", err)
	}
	// Closes startSyncFile because 'l.Run()' only returns when the sandbox exits.
	startSyncFile.Close()

	// Wait for the start signal from runsc.
	l.WaitForStartSignal()

	// Run the application and wait for it to finish.
	if err := l.Run(); err != nil {
		l.Destroy()
		util.Fatalf("running sandbox: %v", err)
	}

	ws := l.WaitExit()
	log.Infof("application exiting with %+v", ws)
	waitStatus := args[1].(*unix.WaitStatus)
	*waitStatus = unix.WaitStatus(ws)
	l.Destroy()
	return subcommands.ExitSuccess
}

func (b *Boot) prepareArgs(exclude ...string) []string {
	var args []string
	for _, arg := range os.Args {
		for _, excl := range exclude {
			if strings.Contains(arg, excl) {
				goto skip
			}
		}
		args = append(args, arg)
		// Strategically add parameters after the command and before the container
		// ID at the end.
		if arg == "boot" {
			if b.attached {
				// This is needed to ensure the new process is killed when the parent
				// process terminates.
				args = append(args, "--attached")
			}
			if b.procMountSyncFD != -1 {
				args = append(args, fmt.Sprintf("--proc-mount-sync-fd=%d", b.procMountSyncFD))
			}
			if len(b.productName) > 0 {
				args = append(args, "--product-name", b.productName)
			}
		}
	skip:
	}
	return args
}

// execProcUmounter execute a child process that umounts /proc when the sks[1]
// socket is closed.
func (b *Boot) execProcUmounter() (*exec.Cmd, *os.File) {
	r, w, err := os.Pipe()
	if err != nil {
		util.Fatalf("error creating a pipe: %v", err)
	}
	defer r.Close()

	cmd := exec.Command(specutils.ExePath)
	cmd.Args = append(cmd.Args, "umount", "--sync-fd=3", "/proc")
	cmd.ExtraFiles = append(cmd.ExtraFiles, r)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		util.Fatalf("error executing umounter: %v", err)
	}
	return cmd, w
}
