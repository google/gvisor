// Copyright 2026 The gVisor Authors.
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

// Package sandbox provides a simple Go API for creating gVisor sandbox
// and executing commands in the sandbox.
package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// Options holds the configuration for a Sandbox.
type Options struct {
	runtimeDir string
	// stateDir is the runsc --root directory. It is set internally by New,
	// which keeps the state inside the runtime directory; Run leaves it empty
	// and lets runsc's own flags decide.
	stateDir         string
	id               string
	enableNetworking bool
	mounts           []Mount
	snapshot         *Snapshot
	env              []string
	err              error
	workingDir       string
	hostname         string

	// Process and filesystem layout.
	args         []string
	rootPath     string
	rootReadonly bool
	user         *specs.User
	capabilities *specs.LinuxCapabilities
	terminal     bool

	// Namespaces and ID mappings.
	namespaces            []specs.LinuxNamespace
	skipDefaultNamespaces bool
	uidMappings           []specs.LinuxIDMapping
	gidMappings           []specs.LinuxIDMapping

	// Default-layout opt-outs.
	skipDefaultMounts    bool
	skipHostBinaryMounts bool
	skipBaseEnv          bool

	// runsc invocation.
	runscPath  string
	runscFlags []string

	// Standard streams, used by Run.
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

// Option configures the Options struct.
type Option func(*Options)

// MountType represents the type of a mount point inside the sandbox.
type MountType int

const (
	// MountTypeBind represents a host bind mount.
	MountTypeBind MountType = iota
	// MountTypeTmpfs represents an in-memory tmpfs mount.
	MountTypeTmpfs
	// MountTypeProc represents a procfs mount.
	MountTypeProc
	// MountTypeSysfs represents a sysfs mount.
	MountTypeSysfs
	// MountTypeDevtmpfs represents a devtmpfs mount.
	MountTypeDevtmpfs
	// MountTypeDevpts represents a devpts mount.
	MountTypeDevpts
	// MountTypeCgroup represents a cgroupfs mount.
	MountTypeCgroup
)

// Mount holds settings for a custom host bind directory or in-memory mount.
type Mount struct {
	Source      string
	Destination string
	Type        MountType
	ReadOnly    bool

	// Options are the OCI mount options. When nil, bind mounts default to
	// "rbind" plus "ro" or "rw" according to ReadOnly, and other mount types
	// default to no options. A non-nil value is used verbatim, so an empty
	// (but non-nil) slice means "no options".
	Options []string
}

// WithRuntimeDir sets a custom runtime directory where bundle and state files are written.
func WithRuntimeDir(runtimeDir string) Option {
	return func(o *Options) {
		o.runtimeDir = runtimeDir
	}
}

// WithID sets a specific sandbox ID. If not set, a unique ID will be generated automatically.
func WithID(id string) Option {
	return func(o *Options) {
		o.id = id
	}
}

// WithNetworking configures whether networking is enabled inside the sandbox.
func WithNetworking(enabled bool) Option {
	return func(o *Options) {
		o.enableNetworking = enabled
	}
}

// WithBindMount adds a custom bind mount from host's source path to the sandbox's destination path.
func WithBindMount(source, destination string, readOnly bool) Option {
	return func(o *Options) {
		o.mounts = append(o.mounts, Mount{
			Source:      filepath.Clean(source),
			Destination: filepath.Clean(destination),
			Type:        MountTypeBind,
			ReadOnly:    readOnly,
		})
	}
}

// WithTmpfsMount adds an in-memory tmpfs filesystem at the destination path inside the sandbox.
func WithTmpfsMount(destination string) Option {
	return func(o *Options) {
		o.mounts = append(o.mounts, Mount{
			Source:      "tmpfs",
			Destination: filepath.Clean(destination),
			Type:        MountTypeTmpfs,
		})
	}
}

// WithProcMount adds a procfs mount at the destination path inside the sandbox.
func WithProcMount(destination string) Option {
	return func(o *Options) {
		o.mounts = append(o.mounts, Mount{
			Source:      "proc",
			Destination: filepath.Clean(destination),
			Type:        MountTypeProc,
		})
	}
}

// WithMount adds mounts with full control over their type and OCI options.
// Mounts are applied in the order given, after the sandbox's default mounts.
func WithMount(mounts ...Mount) Option {
	return func(o *Options) {
		o.mounts = append(o.mounts, mounts...)
	}
}

// WithHostname sets the hostname for the sandbox.
func WithHostname(hostname string) Option {
	return func(o *Options) {
		o.hostname = hostname
	}
}

// WithSnapshot configures the sandbox to restore state from the given snapshot.
// The sandbox automatically reads the snapshot metadata to determine if it is a
// full Checkpoint/Restore, Filesystem snapshot, or Rootfs Tar snapshot.
func WithSnapshot(snapshot *Snapshot) Option {
	return func(o *Options) {
		o.snapshot = snapshot
	}
}

// WithEnv sets one or more environment variables in the sandbox process.
// Each env string must be in the "KEY=VALUE" format.
func WithEnv(envs ...string) Option {
	return func(o *Options) {
		for _, env := range envs {
			if !strings.Contains(env, "=") {
				o.err = fmt.Errorf("invalid environment variable format, expected KEY=VALUE: %q", env)
				return
			}
		}
		o.env = append(o.env, envs...)
	}
}

// WithWorkingDir sets the current working directory for the sandbox process.
// If the path is relative, it will be resolved as an absolute path from the root directory "/".
// This is not a bind mount; it is simply setting the cwd inside the sandbox process.
// Defaults to "/".
func WithWorkingDir(cwd string) Option {
	return func(o *Options) {
		if cwd == "" {
			o.err = fmt.Errorf("working directory cannot be empty")
			return
		}
		// ensure absolute path inside sandbox
		if !filepath.IsAbs(cwd) {
			cwd = filepath.Join("/", cwd)
		}
		cwd = filepath.Clean(cwd)
		o.workingDir = cwd
	}
}

// WithArgs sets the argv of the sandbox's init process. Run requires it. New
// ignores it, because the init process of a persistent sandbox is a
// placeholder that keeps the sandbox alive between Exec calls.
func WithArgs(args ...string) Option {
	return func(o *Options) {
		o.args = args
	}
}

// WithStdio connects the standard streams of the sandbox's init process.
// It only applies to Run, and defaults to the current process's streams.
func WithStdio(stdin io.Reader, stdout, stderr io.Writer) Option {
	return func(o *Options) {
		o.stdin, o.stdout, o.stderr = stdin, stdout, stderr
	}
}

// WithRootfs uses an existing host directory as the sandbox's root filesystem.
// By default the sandbox is given an empty root directory inside its bundle.
func WithRootfs(path string, readOnly bool) Option {
	return func(o *Options) {
		if path == "" {
			o.err = fmt.Errorf("rootfs path cannot be empty")
			return
		}
		o.rootPath = filepath.Clean(path)
		o.rootReadonly = readOnly
	}
}

// WithUser sets the UID and GID of the sandbox's init process. Defaults to 0:0.
func WithUser(uid, gid uint32) Option {
	return func(o *Options) {
		o.user = &specs.User{UID: uid, GID: gid}
	}
}

// WithCapabilities sets the capability set of the sandbox's init process.
func WithCapabilities(caps *specs.LinuxCapabilities) Option {
	return func(o *Options) {
		o.capabilities = caps
	}
}

// WithTerminal marks the init process as attached to a pseudoterminal.
func WithTerminal(terminal bool) Option {
	return func(o *Options) {
		o.terminal = terminal
	}
}

// WithNamespaces replaces the sandbox's default namespace set with the given
// namespaces. Passing no namespaces leaves the sandbox with none, which is
// meaningful because the Sentry isolates PID, IPC and UTS regardless.
func WithNamespaces(namespaces ...specs.LinuxNamespace) Option {
	return func(o *Options) {
		o.skipDefaultNamespaces = true
		o.namespaces = namespaces
	}
}

// WithIDMappings replaces the sandbox's default UID and GID mappings. It is
// only meaningful alongside a user namespace.
func WithIDMappings(uidMappings, gidMappings []specs.LinuxIDMapping) Option {
	return func(o *Options) {
		o.uidMappings, o.gidMappings = uidMappings, gidMappings
	}
}

// WithoutDefaultMounts omits the automatic /proc and /dev mounts, leaving the
// caller responsible for whatever the sandboxed application needs.
func WithoutDefaultMounts() Option {
	return func(o *Options) {
		o.skipDefaultMounts = true
	}
}

// WithoutHostBinaryMounts omits the read-only binds of the host's binary and
// library directories that are otherwise mapped into the sandbox.
func WithoutHostBinaryMounts() Option {
	return func(o *Options) {
		o.skipHostBinaryMounts = true
	}
}

// WithoutBaseEnv omits the default PATH entry that is otherwise prepended to
// the environment set by WithEnv.
func WithoutBaseEnv() Option {
	return func(o *Options) {
		o.skipBaseEnv = true
	}
}

// WithRunscPath sets the runsc binary to invoke. By default it is taken from
// the RUNSC_PATH environment variable, falling back to a PATH lookup.
func WithRunscPath(path string) Option {
	return func(o *Options) {
		o.runscPath = path
	}
}

// WithRunscFlags passes global flags to runsc, after the flags the sandbox
// infers for itself. Later flags win, so these take precedence.
func WithRunscFlags(flags ...string) Option {
	return func(o *Options) {
		o.runscFlags = append(o.runscFlags, flags...)
	}
}

// Sandbox represents a running gVisor sandbox where applications
// run inside.
type Sandbox struct {
	id        string
	bundleDir string
	runscPath string
	rootState string
}

// newID returns a unique ID for the sandbox.
func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// rand.Read never returns an error, and always fills b entirely.
		panic(fmt.Sprintf("failed to generate random bytes for sandbox ID: %v", err))
	}
	return fmt.Sprintf("%x", b)
}

// resolveRunscPath returns the runsc binary to invoke: the one set by
// WithRunscPath, else the RUNSC_PATH environment variable, else a system PATH
// lookup.
func (o *Options) resolveRunscPath() (string, error) {
	if o.runscPath != "" {
		return o.runscPath, nil
	}
	if path := os.Getenv("RUNSC_PATH"); path != "" {
		return path, nil
	}
	path, err := exec.LookPath("runsc")
	if err != nil {
		return "", fmt.Errorf("runsc binary is not found: %w", err)
	}
	return path, nil
}

// newOptions applies opts on top of the defaults shared by New and Run.
func newOptions(opts ...Option) (*Options, error) {
	options := &Options{
		enableNetworking: true,
		workingDir:       "/",
		stdin:            os.Stdin,
		stdout:           os.Stdout,
		stderr:           os.Stderr,
	}
	for _, o := range opts {
		o(options)
	}
	if options.err != nil {
		return nil, options.err
	}
	if options.id == "" {
		options.id = newID()
	}
	return options, nil
}

// bundleConfig converts the resolved options into a BundleConfig.
func (o *Options) bundleConfig(annotations map[string]string) BundleConfig {
	return BundleConfig{
		ID:               o.id,
		RuntimeDir:       o.runtimeDir,
		EnableNetworking: o.enableNetworking,
		Mounts:           o.mounts,
		Env:              o.env,
		Annotations:      annotations,
		WorkingDir:       o.workingDir,
		Hostname:         o.hostname,

		Args:         o.args,
		RootPath:     o.rootPath,
		RootReadonly: o.rootReadonly,
		User:         o.user,
		Capabilities: o.capabilities,
		Terminal:     o.terminal,

		Namespaces:            o.namespaces,
		SkipDefaultNamespaces: o.skipDefaultNamespaces,
		UIDMappings:           o.uidMappings,
		GIDMappings:           o.gidMappings,

		SkipDefaultMounts:    o.skipDefaultMounts,
		SkipHostBinaryMounts: o.skipHostBinaryMounts,
		SkipBaseEnv:          o.skipBaseEnv,
	}
}

// Config resolves opts into the OCI bundle configuration they describe,
// without creating a sandbox. It is useful for inspecting or logging what a
// given set of options produces.
func Config(opts ...Option) (BundleConfig, error) {
	options, err := newOptions(opts...)
	if err != nil {
		return BundleConfig{}, err
	}
	return options.bundleConfig(nil), nil
}

// runscGlobalArgs returns the global runsc flags for this sandbox. The flags
// the sandbox infers come first, so that anything the caller passed to
// WithRunscFlags overrides them.
func (o *Options) runscGlobalArgs() []string {
	var args []string
	if o.stateDir != "" {
		args = append(args, "--root", o.stateDir)
	}
	if os.Geteuid() != 0 {
		args = append(args, "--ignore-cgroups")
	}
	if !o.enableNetworking {
		args = append(args, "--network=none")
	}
	return append(args, o.runscFlags...)
}

// readStderrFile returns what a subprocess wrote to f, the file its stderr was
// redirected to. It returns "" if stderr was not captured or cannot be read.
func readStderrFile(f *os.File) string {
	if f == nil {
		return ""
	}
	out, err := os.ReadFile(f.Name())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// numSignals is the highest signal number Run relays, matching the constant
// of the same name in pkg/sighandling.
const numSignals = 32

// relayedSignals returns the signals Run forwards into the sandbox. It mirrors
// pkg/sighandling: real-time signals are left to the Go runtime, and the
// signals below are skipped because they are induced by the behavior of the
// relaying process rather than aimed at the sandboxed command. Relaying
// SIGCHLD in particular is self-sustaining, since every forwarded signal
// spawns a runsc process whose exit raises another SIGCHLD.
func relayedSignals() []os.Signal {
	sigs := make([]os.Signal, 0, numSignals)
	for sig := 1; sig <= numSignals; sig++ {
		switch syscall.Signal(sig) {
		case syscall.SIGURG, syscall.SIGPIPE, syscall.SIGCHLD:
			continue
		}
		sigs = append(sigs, syscall.Signal(sig))
	}
	return sigs
}

// New spawns a new sandbox as a subprocess, the sandbox
// will be started and running in detached mode.
func New(ctx context.Context, opts ...Option) (*Sandbox, error) {
	options, err := newOptions(opts...)
	if err != nil {
		return nil, err
	}

	if options.runtimeDir == "" {
		dir, err := os.MkdirTemp("", "gvisor-sandbox-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create runtime directory: %v", err)
		}
		options.runtimeDir = dir
	}

	if os.Geteuid() != 0 && options.enableNetworking {
		return nil, fmt.Errorf("enabling networking requires running as root")
	}

	runDir := options.runtimeDir
	stateDir := filepath.Join(runDir, "state")
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create sandbox state directory: %v", err)
	}
	// Verify that the state directory actually has 0700 permissions.
	fi, err := os.Stat(stateDir)
	if err != nil {
		return nil, fmt.Errorf("failed to stat sandbox state directory: %v", err)
	}
	if fi.Mode().Perm() != 0700 {
		return nil, fmt.Errorf("sandbox state directory has incorrect permissions: got %v, want %v", fi.Mode().Perm(), os.FileMode(0700))
	}

	var annotations map[string]string
	var globalFlags []string
	var runFlags []string
	var isCheckpointRestore bool
	var checkpointRestoreDir string

	if options.snapshot != nil {
		store := options.snapshot.Storage
		snapshotID := options.snapshot.ID
		if store == nil {
			return nil, fmt.Errorf("no snapshot storage configured for restore")
		}

		// Fetch metadata.json from store.
		metaReader, err := store.GetReader(ctx, snapshotID, MetadataAsset)
		if err != nil {
			return nil, fmt.Errorf("failed to read snapshot metadata: %w", err)
		}
		defer metaReader.Close()

		var meta SnapshotMetadata
		if err := json.NewDecoder(metaReader).Decode(&meta); err != nil {
			return nil, fmt.Errorf("failed to parse snapshot metadata: %w", err)
		}

		// Perform restore based on type.
		switch meta.Type {
		case RootfsTarSnapshot:
			tarPath, err := readRootfsTar(ctx, snapshotID, store)
			if err != nil {
				return nil, err
			}
			defer os.Remove(tarPath)

			annotations = map[string]string{
				"dev.gvisor.tar.rootfs.upper": tarPath,
			}
			globalFlags = append(globalFlags, "--allow-rootfs-tar-annotation")

		case FilesystemSnapshot:
			fsRestoreDir := filepath.Join(stateDir, "fs-restore")
			if err := os.MkdirAll(fsRestoreDir, 0700); err != nil {
				return nil, err
			}
			// TODO: List assets in store and download all filesystem image assets to fsRestoreDir.
			runFlags = append(runFlags, fmt.Sprintf("--fs-restore-image-path=%s", fsRestoreDir))

		case CheckpointRestore:
			checkpointRestoreDir = filepath.Join(stateDir, "checkpoint-restore")
			if err := os.MkdirAll(checkpointRestoreDir, 0700); err != nil {
				return nil, err
			}
			// TODO: List assets in store and download all checkpoint image assets to checkpointRestoreDir.
			isCheckpointRestore = true
		}
	}
	// The init process of a persistent sandbox is a placeholder that keeps the
	// sandbox alive between Exec calls, so any WithArgs is not applicable here.
	options.args = nil
	options.stateDir = stateDir
	bundleDir, err := NewBundle(options.bundleConfig(annotations))
	if err != nil {
		return nil, fmt.Errorf("failed to create OCI bundle: %v", err)
	}

	runscBin, err := options.resolveRunscPath()
	if err != nil {
		return nil, err
	}
	sb := &Sandbox{
		id:        options.id,
		bundleDir: bundleDir,
		runscPath: runscBin,
		rootState: stateDir,
	}

	// Launch the sandbox in detached mode via os/exec.
	args := append(options.runscGlobalArgs(), globalFlags...)

	if isCheckpointRestore {
		args = append(args, "restore", "--image-path", checkpointRestoreDir, "--detach", sb.id)
	} else {
		args = append(args, "run")
		args = append(args, runFlags...)
		args = append(args, "--bundle", sb.bundleDir, "--detach", sb.id)
	}
	cmd := exec.CommandContext(ctx, sb.runscPath, args...)
	// Collect runsc's stderr, so that a failure reports why rather than just an
	// exit status. It has to be a file rather than an in-memory writer: the
	// latter makes os/exec build a pipe and wait for it to reach EOF, and the
	// detached sandbox inherits that pipe and holds it open for its lifetime.
	var errFile *os.File
	if f, err := os.CreateTemp("", "runsc-stderr-*"); err == nil {
		errFile = f
		defer os.Remove(f.Name())
		defer f.Close()
		cmd.Stderr = f
	}
	if err := cmd.Run(); err != nil {
		if msg := readStderrFile(errFile); msg != "" {
			return nil, fmt.Errorf("failed to create sandbox via subprocess: %v: %s", err, msg)
		}
		return nil, fmt.Errorf("failed to create sandbox via subprocess: %v", err)
	}

	return sb, nil
}

// Run creates a sandbox whose init process is the command given by WithArgs,
// runs it in the foreground, and returns its exit code once it exits.
//
// Unlike New, Run does not outlive the command: the sandbox is torn down when
// the command exits, and there is nothing left to Exec into. The command's
// standard streams are those set by WithStdio, defaulting to the calling
// process's, so its output streams rather than being buffered.
//
// Signals received by the calling process are relayed into the sandbox and
// delivered to the command, so that it can handle or die from them as it would
// outside a sandbox. runsc stays alive to reap the command and tear the sandbox
// down. Note that a signal that kills runsc outright, such as SIGKILL, leaves
// the sandbox behind.
func Run(ctx context.Context, opts ...Option) (int, error) {
	options, err := newOptions(opts...)
	if err != nil {
		return -1, err
	}
	if len(options.args) == 0 {
		return -1, fmt.Errorf("no command to run: Run requires WithArgs")
	}

	if options.runtimeDir == "" {
		dir, err := os.MkdirTemp("", "gvisor-sandbox-*")
		if err != nil {
			return -1, fmt.Errorf("failed to create runtime directory: %v", err)
		}
		options.runtimeDir = dir
		defer os.RemoveAll(dir)
	}

	runscBin, err := options.resolveRunscPath()
	if err != nil {
		return -1, err
	}

	bundleDir, err := NewBundle(options.bundleConfig(nil))
	if err != nil {
		return -1, fmt.Errorf("failed to create OCI bundle: %v", err)
	}

	// runsc run without --detach creates the container, runs it attached to
	// the streams below, and destroys it once it exits.
	args := append(options.runscGlobalArgs(), "run", "--bundle", bundleDir, options.id)
	cmd := exec.CommandContext(ctx, runscBin, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = options.stdin, options.stdout, options.stderr

	if err := cmd.Start(); err != nil {
		return -1, fmt.Errorf("failed to start sandbox: %v", err)
	}

	// Relay signals into the sandbox rather than to the runsc process. Signaling
	// runsc directly would kill it before it could reap the command and clean
	// up, and the command itself would never see the signal.
	relayed := relayedSignals()
	sigCh := make(chan os.Signal, len(relayed))
	signal.Notify(sigCh, relayed...)
	defer signal.Stop(sigCh)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case sig := <-sigCh:
				unixSig, ok := sig.(syscall.Signal)
				if !ok {
					continue
				}
				// The container may not exist yet, in which case the signal is
				// dropped, just as it is before an attached runsc starts
				// forwarding.
				killArgs := append(options.runscGlobalArgs(), "kill", options.id, strconv.Itoa(int(unixSig)))
				_ = exec.CommandContext(ctx, runscBin, killArgs...).Run()
			case <-done:
				return
			}
		}
	}()

	if err := cmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// runsc exits with the container's own status, including
			// 128+signal when the container was signaled. If runsc itself was
			// signaled, ExitCode reports -1, so derive the status the shell
			// would have reported.
			if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				return 128 + int(ws.Signal()), nil
			}
			return exitErr.ExitCode(), nil
		}
		return -1, fmt.Errorf("failed to run sandbox: %v", err)
	}
	return 0, nil
}

// Exec runs the given command inside the running sandbox and returns the output.
func (s *Sandbox) Exec(ctx context.Context, cmd string, opts ...string) (stdout string, stderr string, err error) {
	args := append([]string{"--root", s.rootState, "exec", s.id, cmd}, opts...)

	commandContext := exec.CommandContext(ctx, s.runscPath, args...)

	var stdoutBuf, stderrBuf bytes.Buffer

	commandContext.Stdout = io.MultiWriter(&stdoutBuf)
	commandContext.Stderr = io.MultiWriter(&stderrBuf)

	err = commandContext.Run()
	if err != nil {
		return "", stderrBuf.String(), fmt.Errorf("exec failed: %v", err)
	}

	return stdoutBuf.String(), stderrBuf.String(), err
}

// Close kills the sandbox processes and cleans up the state directory.
func (s *Sandbox) Close(ctx context.Context) error {
	killArgs := []string{"--root", s.rootState, "kill", s.id, "SIGKILL"}
	_ = exec.CommandContext(ctx, s.runscPath, killArgs...).Run()

	deleteArgs := []string{"--root", s.rootState, "delete", "--force", s.id}
	if err := exec.CommandContext(ctx, s.runscPath, deleteArgs...).Run(); err != nil {
		return fmt.Errorf("failed to clean up sandbox state: %v", err)
	}

	if err := os.RemoveAll(s.bundleDir); err != nil {
		return fmt.Errorf("failed to clean up sandbox bundle directory: %v", err)
	}

	if err := os.RemoveAll(s.rootState); err != nil {
		return fmt.Errorf("failed to clean up sandbox state directory: %v", err)
	}

	return nil
}

// Bundle returns the path to the OCI bundle directory for this sandbox.
func (s *Sandbox) Bundle() string {
	return s.bundleDir
}

// SnapshotOptions holds configuration for taking a snapshot.
type SnapshotOptions struct {
	LeaveRunning bool
}

// SnapshotOption configures SnapshotOptions.
type SnapshotOption func(*SnapshotOptions)

// WithLeaveRunning keeps the sandbox running after taking the snapshot.
func WithLeaveRunning(leaveRunning bool) SnapshotOption {
	return func(o *SnapshotOptions) {
		o.LeaveRunning = leaveRunning
	}
}

func newSnapshotID() SnapshotID {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate random bytes for snapshot ID: %v", err))
	}
	return SnapshotID(fmt.Sprintf("snap-%x", b))
}

// Snapshot serializes and saves the sandbox state to storage, returning the generated snapshot.
// Depending on the snapshotType, it will perform a full Checkpoint, a Filesystem Snapshot, or a Rootfs Tar Snapshot.
// It also automatically generates and writes "metadata.json" into the storage.
func (s *Sandbox) Snapshot(ctx context.Context, snapshotType SnapshotType, storage SnapshotStorage, opts ...SnapshotOption) (*Snapshot, error) {
	options := SnapshotOptions{
		LeaveRunning: false, // Default is false.
	}
	for _, o := range opts {
		o(&options)
	}

	snapshotID := newSnapshotID()

	switch snapshotType {
	case RootfsTarSnapshot:
		if err := s.snapshotRootfsTar(ctx, snapshotID, storage); err != nil {
			return nil, err
		}

	case FilesystemSnapshot:
		// TODO: Run `runsc fscheckpoint --image-path=<localTempDir> [--leave-running] <sandboxID>`.
		// TODO: Walk `<localTempDir>` and upload each file to storage.

	case CheckpointRestore:
		// TODO: Run `runsc checkpoint --image-path=<localTempDir> [--leave-running] <sandboxID>`.
		// TODO: Walk `<localTempDir>` and upload each file to storage.
	}

	meta := SnapshotMetadata{
		Type:      snapshotType,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	metaWriter, err := storage.PutWriter(ctx, snapshotID, MetadataAsset)
	if err != nil {
		return nil, fmt.Errorf("failed to create metadata.json in storage: %w", err)
	}
	defer metaWriter.Close()

	if err := json.NewEncoder(metaWriter).Encode(&meta); err != nil {
		return nil, fmt.Errorf("failed to write metadata.json to storage: %w", err)
	}

	return &Snapshot{
		ID:      snapshotID,
		Storage: storage,
	}, nil
}

func (s *Sandbox) snapshotRootfsTar(ctx context.Context, snapshotID SnapshotID, storage SnapshotStorage) error {
	tarFile, err := os.CreateTemp(os.TempDir(), "rootfs-*.tar")
	if err != nil {
		return fmt.Errorf("failed to create temp tar file: %w", err)
	}
	tarPath := tarFile.Name()
	tarFile.Close()
	defer os.Remove(tarPath)

	cmd := exec.CommandContext(ctx, s.runscPath, "--root", s.rootState, "tar", "rootfs-upper", "--file", tarPath, s.id)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("runsc tar failed: %v (stderr: %q)", err, stderr.String())
	}

	localFile, err := os.Open(tarPath)
	if err != nil {
		return fmt.Errorf("failed to open temp tar file: %w", err)
	}
	defer localFile.Close()

	storageWriter, err := storage.PutWriter(ctx, snapshotID, RootfsAsset)
	if err != nil {
		return fmt.Errorf("failed to create storage writer: %w", err)
	}
	defer storageWriter.Close()

	if _, err := io.Copy(storageWriter, localFile); err != nil {
		return fmt.Errorf("failed to upload rootfs tar: %w", err)
	}
	return nil
}

func readRootfsTar(ctx context.Context, snapshotID SnapshotID, store SnapshotStorage) (string, error) {
	tarFile, err := os.CreateTemp(os.TempDir(), "rootfs-*.tar")
	if err != nil {
		return "", fmt.Errorf("failed to create temp tar file: %w", err)
	}
	tarPath := tarFile.Name()
	defer tarFile.Close()

	cleanup := true
	defer func() {
		if cleanup {
			os.Remove(tarPath)
		}
	}()

	storageReader, err := store.GetReader(ctx, snapshotID, RootfsAsset)
	if err != nil {
		return "", fmt.Errorf("failed to get rootfs reader from storage: %w", err)
	}
	defer storageReader.Close()

	if _, err := io.Copy(tarFile, storageReader); err != nil {
		return "", fmt.Errorf("failed to download rootfs asset: %w", err)
	}

	cleanup = false
	return tarPath, nil
}
