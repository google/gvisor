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
	// stateDir is where the sandbox keeps its own state. When empty, New keeps
	// it inside the runtime directory.
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
	rootPath     string
	rootReadonly bool
	user         *specs.User
	capabilities *specs.LinuxCapabilities

	// Namespaces and ID mappings.
	namespaces            []specs.LinuxNamespace
	skipDefaultNamespaces bool
	uidMappings           []specs.LinuxIDMapping
	gidMappings           []specs.LinuxIDMapping

	// Default-layout opt-outs.
	skipDefaultMounts    bool
	skipHostBinaryMounts bool
	skipBaseEnv          bool

	// Runtime behavior. These describe how the sandbox itself is run, rather
	// than what runs inside it.
	platform string
	debug    bool
	debugLog string
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

// WithStateDir sets the directory where the sandbox keeps its own state, as
// opposed to the runtime directory that holds its bundle. It defaults to a
// "state" directory inside the runtime directory, which Close removes along
// with the rest of the sandbox. A directory named here belongs to the caller,
// so Close leaves it in place.
func WithStateDir(dir string) Option {
	return func(o *Options) {
		o.stateDir = dir
	}
}

// WithPlatform selects the platform the Sentry uses to intercept the
// application's system calls, for example "systrap", "ptrace" or "kvm". When
// unset, the runtime picks its own default.
func WithPlatform(platform string) Option {
	return func(o *Options) {
		o.platform = platform
	}
}

// WithDebug turns on the sandbox's debug logging. logPath is where the logs
// are written, in the format the runtime expects; when empty they go to the
// sandbox's standard error.
func WithDebug(logPath string) Option {
	return func(o *Options) {
		o.debug = true
		o.debugLog = logPath
	}
}

// Sandbox represents a running gVisor sandbox where applications
// run inside.
type Sandbox struct {
	id        string
	bundleDir string
	runscPath string
	rootState string

	// ownStateDir records that rootState was created by New rather than named
	// by WithStateDir, and so is Close's to remove.
	ownStateDir bool
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

// RunscPathEnvVar names the runsc binary the sandbox invokes. When it is
// unset, the binary is looked up on the system PATH.
const RunscPathEnvVar = "RUNSC_PATH"

// resolveRunscPath returns the runsc binary to invoke: the one named by
// RunscPathEnvVar, else a system PATH lookup.
func resolveRunscPath() (string, error) {
	if path := os.Getenv(RunscPathEnvVar); path != "" {
		return path, nil
	}
	path, err := exec.LookPath("runsc")
	if err != nil {
		return "", fmt.Errorf("runsc binary is not found: %w", err)
	}
	return path, nil
}

// newOptions applies opts on top of the sandbox defaults.
func newOptions(opts ...Option) (*Options, error) {
	options := &Options{
		enableNetworking: true,
		workingDir:       "/",
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

// toBundleConfig converts the resolved options into a bundleConfig.
func (o *Options) toBundleConfig(annotations map[string]string) bundleConfig {
	return bundleConfig{
		ID:               o.id,
		RuntimeDir:       o.runtimeDir,
		EnableNetworking: o.enableNetworking,
		Mounts:           o.mounts,
		Env:              o.env,
		Annotations:      annotations,
		WorkingDir:       o.workingDir,
		Hostname:         o.hostname,

		RootPath:     o.rootPath,
		RootReadonly: o.rootReadonly,
		User:         o.user,
		Capabilities: o.capabilities,

		Namespaces:            o.namespaces,
		SkipDefaultNamespaces: o.skipDefaultNamespaces,
		UIDMappings:           o.uidMappings,
		GIDMappings:           o.gidMappings,

		SkipDefaultMounts:    o.skipDefaultMounts,
		SkipHostBinaryMounts: o.skipHostBinaryMounts,
		SkipBaseEnv:          o.skipBaseEnv,
	}
}

// Spec resolves opts into the OCI runtime specification they describe, without
// creating a sandbox. It is useful for inspecting or testing what a given set
// of options produces; the result cannot be fed back into this package, which
// runs sandboxes only through New.
func Spec(opts ...Option) (*specs.Spec, error) {
	options, err := newOptions(opts...)
	if err != nil {
		return nil, err
	}
	return newSpec(options.toBundleConfig(nil))
}

// runscGlobalArgs translates the options that describe how the sandbox is run
// into global runsc flags. This is the only place runsc flags are derived from
// options, so callers never pass runsc flags themselves.
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
	if o.platform != "" {
		args = append(args, "--platform="+o.platform)
	}
	if o.debug {
		args = append(args, "--debug")
		if o.debugLog != "" {
			args = append(args, "--debug-log="+o.debugLog)
		}
	}
	return args
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

// numSignals is the highest signal number Exec relays, matching the constant
// of the same name in pkg/sighandling.
const numSignals = 32

// relaySignals forwards the signals this process receives to the command
// running in the sandbox, and returns a function that stops the relay.
//
// Signals go to the sandbox-internal PID runsc records in pidFile, via "runsc
// kill", rather than to the runsc process itself: runsc only forwards signals
// into the sandbox when it allocated a terminal.
//
// As in pkg/sighandling, real-time signals are left to the Go runtime. SIGURG,
// SIGPIPE and SIGCHLD describe the relaying process, not the sandboxed
// command; skipping SIGCHLD also stops the relay feeding itself, since every
// kill it runs is a child whose exit raises one.
func (s *Sandbox) relaySignals(ctx context.Context, pidFile string) func() {
	sigs := make([]os.Signal, 0, numSignals)
	for sig := 1; sig <= numSignals; sig++ {
		switch syscall.Signal(sig) {
		case syscall.SIGURG, syscall.SIGPIPE, syscall.SIGCHLD:
			continue
		}
		sigs = append(sigs, syscall.Signal(sig))
	}

	ch := make(chan os.Signal, len(sigs))
	signal.Notify(ch, sigs...)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-ch:
				unixSig, ok := sig.(syscall.Signal)
				if !ok {
					continue
				}
				pid, err := readPidFile(pidFile)
				if err != nil {
					// The command is not running yet; drop the signal.
					continue
				}
				killArgs := []string{"--root", s.rootState, "kill", "--pid", strconv.Itoa(pid), s.id, strconv.Itoa(int(unixSig))}
				_ = exec.CommandContext(ctx, s.runscPath, killArgs...).Run()
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}

// readPidFile returns the PID runsc wrote to path.
func readPidFile(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

// New spawns a new sandbox as a subprocess, the sandbox will be started and
// running in detached mode. Its init process is a placeholder that keeps the
// sandbox alive; commands run in it with Exec, and Close tears it down.
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

	// A sandbox always has a state directory: the one WithStateDir named, else
	// one inside the runtime directory.
	stateDir := options.stateDir
	ownStateDir := stateDir == ""
	if ownStateDir {
		stateDir = filepath.Join(options.runtimeDir, "state")
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create sandbox state directory: %v", err)
	}
	if ownStateDir {
		// Only check a directory this sandbox created; one the caller named is
		// the caller's to protect.
		fi, err := os.Stat(stateDir)
		if err != nil {
			return nil, fmt.Errorf("failed to stat sandbox state directory: %v", err)
		}
		if fi.Mode().Perm() != 0700 {
			return nil, fmt.Errorf("sandbox state directory has incorrect permissions: got %v, want %v", fi.Mode().Perm(), os.FileMode(0700))
		}
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
	options.stateDir = stateDir
	bundleDir, err := newBundle(options.toBundleConfig(annotations))
	if err != nil {
		return nil, fmt.Errorf("failed to create OCI bundle: %v", err)
	}

	runscBin, err := resolveRunscPath()
	if err != nil {
		return nil, err
	}
	sb := &Sandbox{
		id:          options.id,
		bundleDir:   bundleDir,
		runscPath:   runscBin,
		rootState:   stateDir,
		ownStateDir: ownStateDir,
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
	// Collect runsc's stderr so a failure reports why, not just an exit status.
	// This must be a file, not an in-memory writer: os/exec would then build a
	// pipe and wait for EOF, which the detached sandbox holds open for its
	// whole lifetime.
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

// ExecOption configures a single command run by Exec.
type ExecOption func(*execOptions)

// execOptions holds the configuration for one Exec call.
type execOptions struct {
	args   []string
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

// WithExecArgs sets the argv of the command to run. Exec requires it.
func WithExecArgs(args ...string) ExecOption {
	return func(o *execOptions) {
		o.args = args
	}
}

// WithExecStdio streams the command's standard streams to the given ones
// instead of buffering them. A nil stream is left to Exec, which reads nothing
// on stdin and collects the output into the ExecResult.
func WithExecStdio(stdin io.Reader, stdout, stderr io.Writer) ExecOption {
	return func(o *execOptions) {
		o.stdin, o.stdout, o.stderr = stdin, stdout, stderr
	}
}

// ExecResult is the outcome of a command run by Exec.
type ExecResult struct {
	// ExitCode is the status the command exited with, or 128 plus the signal
	// number if a signal killed it, the same way a shell reports it.
	ExitCode int

	// Stdout and Stderr hold what the command wrote to those streams. A stream
	// that WithExecStdio redirected is not collected here.
	Stdout string
	Stderr string
}

// Exec runs a command inside the sandbox and waits for it to exit. A non-zero
// exit is not an error: it is reported in the ExecResult, and an error means
// the command could not be run at all.
//
// The command inherits the working directory, environment, user and
// capabilities the sandbox was created with. Signals this process receives are
// relayed to it; see relaySignals.
func (s *Sandbox) Exec(ctx context.Context, opts ...ExecOption) (*ExecResult, error) {
	options := &execOptions{}
	for _, o := range opts {
		o(options)
	}
	if len(options.args) == 0 {
		return nil, fmt.Errorf("no command to run: Exec requires WithExecArgs")
	}

	// The relay needs the command's PID inside the sandbox to signal it, and
	// runsc reports it here once the command is running.
	pidFile := filepath.Join(s.bundleDir, "exec-"+newID()+".pid")
	defer os.Remove(pidFile)

	args := append([]string{"--root", s.rootState, "exec", "--internal-pid-file", pidFile, s.id}, options.args...)
	cmd := exec.CommandContext(ctx, s.runscPath, args...)
	cmd.Stdin = options.stdin
	var stdout, stderr bytes.Buffer
	if cmd.Stdout = options.stdout; cmd.Stdout == nil {
		cmd.Stdout = &stdout
	}
	if cmd.Stderr = options.stderr; cmd.Stderr == nil {
		cmd.Stderr = &stderr
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start command in sandbox: %v", err)
	}
	stopRelay := s.relaySignals(ctx, pidFile)
	defer stopRelay()

	res := &ExecResult{}
	err := cmd.Wait()
	res.Stdout, res.Stderr = stdout.String(), stderr.String()
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return nil, fmt.Errorf("failed to run command in sandbox: %v", err)
		}
		// runsc exits with the command's own status, already 128+signal if a
		// signal killed it. But if runsc itself was signaled, ExitCode is -1,
		// so derive the status from the signal instead.
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			res.ExitCode = 128 + int(ws.Signal())
		} else {
			res.ExitCode = exitErr.ExitCode()
		}
	}
	return res, nil
}

// Close kills the sandbox processes and cleans up after it.
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

	// runsc delete already removed the container's own state. Only remove a
	// state directory this sandbox created; one the caller named may hold
	// other sandboxes.
	if s.ownStateDir {
		unmountNullNetNS(s.rootState)
		if err := os.RemoveAll(s.rootState); err != nil {
			return fmt.Errorf("failed to clean up sandbox state directory: %v", err)
		}
	}

	return nil
}

// nullNetNSFilename is the name, relative to the state directory, of the empty
// network namespace runsc bind mounts there to share between gofers. It
// mirrors specutils.NullNetNSFilename.
const nullNetNSFilename = "null-netns"

// unmountNullNetNS undoes the bind mounts runsc left in the state directory,
// which would otherwise keep it busy and undeletable. Creation is not
// serialized across invocations, so mounts can stack on the same path; unmount
// until none are left.
func unmountNullNetNS(stateDir string) {
	path := filepath.Join(stateDir, nullNetNSFilename)
	for syscall.Unmount(path, syscall.MNT_DETACH) == nil {
	}
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
