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
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sighandling"
	"gvisor.dev/gvisor/runsc/specutils"
)

// NetworkMode defines the network isolation mode for the sandbox.
type NetworkMode string

const (
	// NetworkModeNone disables networking completely inside the sandbox.
	NetworkModeNone NetworkMode = "none"

	// NetworkModeHost shares the host network namespace with the sandbox.
	// This mode is supported for rootless execution.
	NetworkModeHost NetworkMode = "host"

	// NetworkModeSandbox enables a dedicated network namespace using gVisor netstack.
	// This mode requires host root privileges (UID 0).
	NetworkModeSandbox NetworkMode = "sandbox"
)

// Options holds the configuration for a Sandbox.
type Options struct {
	runtimeDir string
	// stateDir is where the sandbox keeps its state. Defaults to a directory
	// inside the runtime directory.
	stateDir   string
	id         string
	network    NetworkMode
	mounts     []Mount
	snapshot   *Snapshot
	env        []string
	err        error
	workingDir string
	hostname   string

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
	skipLinuxSystemMounts bool
	skipHostBinaryMounts  bool
	skipBaseEnv           bool

	// Runtime behavior.
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

	// ReadOnly adds "ro".
	ReadOnly bool

	// Recursive adds "rbind", carrying over the source's submounts.
	Recursive bool

	// Private adds "rprivate".
	Private bool

	// NoSuid adds "nosuid".
	NoSuid bool

	// NoDev adds "nodev".
	NoDev bool
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

// WithNetwork sets the network mode for the sandbox.
// Supported modes: NetworkModeNone ("none"), NetworkModeHost ("host"), NetworkModeSandbox ("sandbox").
func WithNetwork(mode NetworkMode) Option {
	return func(o *Options) {
		switch mode {
		case NetworkModeNone, NetworkModeHost, NetworkModeSandbox:
			o.network = mode
		default:
			o.err = fmt.Errorf("invalid network mode %q: must be one of none, host, sandbox", mode)
		}
	}
}

// WithMount adds custom filesystem mounts to the sandbox. Mounts are applied
// in the order provided, after any default mounts.
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
// namespaces. Passing no namespaces leaves the sandbox with none.
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

// WithoutLinuxSystemMounts omits the automatic /proc and /dev mounts.
func WithoutLinuxSystemMounts() Option {
	return func(o *Options) {
		o.skipLinuxSystemMounts = true
	}
}

// WithoutHostBinaryMounts omits the read-only binds of the host's binary and
// library directories.
func WithoutHostBinaryMounts() Option {
	return func(o *Options) {
		o.skipHostBinaryMounts = true
	}
}

// WithoutBaseEnv omits the default PATH entry.
func WithoutBaseEnv() Option {
	return func(o *Options) {
		o.skipBaseEnv = true
	}
}

// WithStateDir sets the directory where the sandbox keeps its state. Close
// removes the default directory, but leaves this one in place.
func WithStateDir(dir string) Option {
	return func(o *Options) {
		o.stateDir = dir
	}
}

// WithDebug turns on the sandbox's debug logging. The logs are written to
// logPath, or to standard error when it is empty.
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

	// ownStateDir means Close should remove rootState.
	ownStateDir bool

	// ownRuntimeDir means Close should remove runtimeDir.
	runtimeDir    string
	ownRuntimeDir bool

	// execMu keeps a signal-relaying Exec from overlapping other Exec calls.
	execMu sync.RWMutex
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
		network:    NetworkModeNone,
		workingDir: "/",
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
		ID:          o.id,
		RuntimeDir:  o.runtimeDir,
		Network:     o.network,
		Mounts:      o.mounts,
		Env:         o.env,
		Annotations: annotations,
		WorkingDir:  o.workingDir,
		Hostname:    o.hostname,

		RootPath:     o.rootPath,
		RootReadonly: o.rootReadonly,
		User:         o.user,
		Capabilities: o.capabilities,

		Namespaces:            o.namespaces,
		SkipDefaultNamespaces: o.skipDefaultNamespaces,
		UIDMappings:           o.uidMappings,
		GIDMappings:           o.gidMappings,

		SkipLinuxSystemMounts: o.skipLinuxSystemMounts,
		SkipHostBinaryMounts:  o.skipHostBinaryMounts,
		SkipBaseEnv:           o.skipBaseEnv,
	}
}

// runscGlobalArgs returns the global runsc flags the options ask for.
func (o *Options) runscGlobalArgs() []string {
	var args []string
	if o.stateDir != "" {
		args = append(args, "--root", o.stateDir)
	}
	if os.Geteuid() != 0 {
		args = append(args, "--ignore-cgroups")
	}
	switch o.network {
	case NetworkModeHost:
		args = append(args, "--network=host")
	case NetworkModeNone, "":
		args = append(args, "--network=none")
	case NetworkModeSandbox:
		args = append(args, "--network=sandbox")
	}
	if o.debug {
		args = append(args, "--debug")
		if o.debugLog != "" {
			args = append(args, "--debug-log="+o.debugLog)
		}
	}
	return args
}

// readFileTrimmed returns the contents of f with surrounding whitespace
// removed, or "" if f is nil or cannot be read.
func readFileTrimmed(f *os.File) string {
	if f == nil {
		return ""
	}
	out, err := os.ReadFile(f.Name())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// relaySignals forwards this process's signals to the command whose PID runsc
// writes to pidFile, and returns a function that stops the relay.
func (s *Sandbox) relaySignals(ctx context.Context, pidFile string) func() {
	return sighandling.StartSignalForwarding(func(sig linux.Signal) {
		pid, err := readPidFile(pidFile)
		if err != nil {
			// The command is not running yet; drop the signal.
			return
		}
		killArgs := []string{"--root", s.rootState, "kill", "--pid", strconv.Itoa(pid), s.id, strconv.Itoa(int(sig))}
		if err := exec.CommandContext(ctx, s.runscPath, killArgs...).Run(); err != nil {
			log.Warningf("failed to forward signal %d to sandbox %s: %v", sig, s.id, err)
		}
	})
}

// readPidFile returns the PID runsc wrote to path.
func readPidFile(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

// New creates a new sandbox.
func New(ctx context.Context, opts ...Option) (*Sandbox, error) {
	options, err := newOptions(opts...)
	if err != nil {
		return nil, err
	}

	ownRuntimeDir := options.runtimeDir == ""
	if ownRuntimeDir {
		dir, err := os.MkdirTemp("", "gvisor-sandbox-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create runtime directory: %v", err)
		}
		options.runtimeDir = dir
	}

	var stateDir, bundleDir string
	var ownStateDir, created bool
	defer func() {
		if created {
			return
		}
		if bundleDir != "" {
			os.RemoveAll(bundleDir)
		}
		if ownStateDir {
			specutils.UnmountNullNetNS(stateDir)
			os.RemoveAll(stateDir)
		}
		if ownRuntimeDir {
			os.RemoveAll(options.runtimeDir)
		}
	}()

	if os.Geteuid() != 0 && options.network == NetworkModeSandbox {
		return nil, fmt.Errorf("sandbox networking requires running as root")
	}

	stateDir = options.stateDir
	ownStateDir = stateDir == ""
	if ownStateDir {
		stateDir = filepath.Join(options.runtimeDir, "state")
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create sandbox state directory: %v", err)
	}
	if ownStateDir {
		// Only check a directory this sandbox created.
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
	bundleDir, err = newBundle(options.toBundleConfig(annotations))
	if err != nil {
		return nil, fmt.Errorf("failed to create OCI bundle: %v", err)
	}

	runscBin, err := resolveRunscPath()
	if err != nil {
		return nil, err
	}
	sb := &Sandbox{
		id:            options.id,
		bundleDir:     bundleDir,
		runscPath:     runscBin,
		rootState:     stateDir,
		ownStateDir:   ownStateDir,
		runtimeDir:    options.runtimeDir,
		ownRuntimeDir: ownRuntimeDir,
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
	// Capture runsc standard error output for diagnostic errors on launch failure.
	var errFile *os.File
	if f, err := os.CreateTemp("", "runsc-stderr-*"); err == nil {
		errFile = f
		defer os.Remove(f.Name())
		defer f.Close()
		cmd.Stderr = f
	}
	if err := cmd.Run(); err != nil {
		if msg := readFileTrimmed(errFile); msg != "" {
			return nil, fmt.Errorf("failed to create sandbox via subprocess: %v: %s", err, msg)
		}
		return nil, fmt.Errorf("failed to create sandbox via subprocess: %v", err)
	}

	created = true
	return sb, nil
}

// ExecOption configures a single command run by Exec.
type ExecOption func(*execOptions)

// execOptions holds the configuration for one Exec call.
type execOptions struct {
	args         []string
	stdin        io.Reader
	stdout       io.Writer
	stderr       io.Writer
	relaySignals bool
}

// WithExecStdio streams the command's standard streams to the given ones. A
// nil stdin reads nothing; a nil stdout or stderr is collected into the
// ExecResult.
func WithExecStdio(stdin io.Reader, stdout, stderr io.Writer) ExecOption {
	return func(o *execOptions) {
		o.stdin, o.stdout, o.stderr = stdin, stdout, stderr
	}
}

// WithExecSignalRelay relays the signals this process receives to the command.
func WithExecSignalRelay() ExecOption {
	return func(o *execOptions) {
		o.relaySignals = true
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
// exit is reported in the ExecResult; an error means the command did not run.
//
// The command inherits the working directory, environment, user and
// capabilities the sandbox was created with. Calls may run concurrently, unless
// WithExecSignalRelay asks for the signal relay.
func (s *Sandbox) Exec(ctx context.Context, argv []string, opts ...ExecOption) (*ExecResult, error) {
	options := &execOptions{args: argv}
	for _, o := range opts {
		o(options)
	}

	if options.relaySignals {
		s.execMu.Lock()
		defer s.execMu.Unlock()
	} else {
		s.execMu.RLock()
		defer s.execMu.RUnlock()
	}

	args := []string{"--root", s.rootState, "exec"}
	var pidFile string
	if options.relaySignals {
		pidFile = filepath.Join(s.bundleDir, "exec-"+newID()+".pid")
		defer os.Remove(pidFile)
		args = append(args, "--internal-pid-file", pidFile)
	}
	args = append(append(args, s.id), options.args...)
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
	if options.relaySignals {
		stopRelay := s.relaySignals(ctx, pidFile)
		defer stopRelay()
	}

	res := &ExecResult{}
	err := cmd.Wait()
	res.Stdout, res.Stderr = stdout.String(), stderr.String()
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return nil, fmt.Errorf("failed to run command in sandbox: %v", err)
		}
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

	var errs []error
	deleteArgs := []string{"--root", s.rootState, "delete", "--force", s.id}
	if err := exec.CommandContext(ctx, s.runscPath, deleteArgs...).Run(); err != nil {
		errs = append(errs, fmt.Errorf("failed to clean up sandbox state: %v", err))
	}

	if err := os.RemoveAll(s.bundleDir); err != nil {
		errs = append(errs, fmt.Errorf("failed to clean up sandbox bundle directory: %v", err))
	}

	if s.ownStateDir {
		specutils.UnmountNullNetNS(s.rootState)
		if err := os.RemoveAll(s.rootState); err != nil {
			errs = append(errs, fmt.Errorf("failed to clean up sandbox state directory: %v", err))
		}
	}

	if s.ownRuntimeDir {
		if err := os.RemoveAll(s.runtimeDir); err != nil {
			errs = append(errs, fmt.Errorf("failed to clean up sandbox runtime directory: %v", err))
		}
	}

	return errors.Join(errs...)
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
