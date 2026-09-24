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

package sandboxposture

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/sys/unix"
)

// Reference describes the posture of process the sandbox was launched from.
type Reference struct {
	// Umask is the reference process's umask, e.g. "0022".
	Umask string

	// PermittedCaps is the reference process's permitted capability set.
	PermittedCaps []string

	// Limits is the reference process's resource limits.
	Limits map[string]string

	// StdioFDs holds the FD classes of the reference process's own
	// stdin/stdout/stderr.
	StdioFDs []string
}

// SelfReference builds a `Reference` from the calling process.
func SelfReference() (Reference, error) {
	return ReferenceOf(os.Getpid(), "")
}

// ReferenceOf builds a `Reference` from the given process.
// `procRoot` defaults to "/proc".
func ReferenceOf(pid int, procRoot string) (Reference, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	p := &proc{root: procRoot, pid: pid}
	status, err := p.status()
	if err != nil {
		return Reference{}, fmt.Errorf("reading status of %d: %w", pid, err)
	}
	umask, ok := status["Umask"]
	if !ok {
		return Reference{}, fmt.Errorf("status of %d has no umask line", pid)
	}
	perm, err := capSet(status, "CapPrm")
	if err != nil {
		return Reference{}, err
	}
	limitsRaw, err := p.read("limits")
	if err != nil {
		return Reference{}, fmt.Errorf("reading limits of %d: %w", pid, err)
	}
	limits, err := parseLimits(limitsRaw)
	if err != nil {
		return Reference{}, fmt.Errorf("limits of %d: %w", pid, err)
	}
	return Reference{
		Umask:         umask,
		PermittedCaps: perm,
		Limits:        limits,
		StdioFDs:      stdioClasses(p),
	}, nil
}

// stdioClasses classifies a process's stdin/stdout/stderr.
func stdioClasses(p *proc) []string {
	var classes []string
	for fd := range 3 {
		path := p.path("fd", strconv.Itoa(fd))
		link, err := os.Readlink(path)
		if err != nil {
			continue
		}
		var st unix.Stat_t
		mode := uint32(0)
		if err := unix.Stat(path, &st); err == nil {
			mode = st.Mode
		}
		classes = append(classes, classifyFD(link, mode))
	}
	return dedupe(classes)
}

// KVMFDClasses returns the FD classes a sandbox on the KVM platform holds
// beyond the ones other platforms have.
func KVMFDClasses() []string {
	const (
		kvmCheckExtension = 0xae03 // _IO(KVMIO, 0x03)
		kvmCapMaxVCPUs    = 0x42
	)
	kvmMaxVCPUs := 1024
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err == nil {
		defer f.Close()
		n, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), kvmCheckExtension, kvmCapMaxVCPUs)
		if errno == 0 && kvmMaxVCPUs < int(n) {
			kvmMaxVCPUs = int(n)
		}
	}
	classes := []string{
		FDCharDev + ":/dev/kvm",
		FDAnonPrefix + "kvm-vm",
		FDAnonPrefix + "kvm-vcpu",
	}
	for i := 0; i < kvmMaxVCPUs; i++ {
		classes = append(classes, fmt.Sprintf("%skvm-vcpu:%d", FDAnonPrefix, i))
	}
	return classes
}

// directfsCaps is the capability set on DirectFS sandboxes.
// See `directfsSandboxCaps` in `runsc/cmd/boot.go`.
var directfsCaps = []string{
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_DAC_READ_SEARCH",
	"CAP_FOWNER",
	"CAP_FSETID",
}

// hostNetworkCaps is the capability set on hostinet sandboxes.
// See `hostnetSandboxLinuxCaps` in `runsc/cmd/boot.go`.
var hostNetworkCaps = []string{
	"CAP_NET_ADMIN",
	"CAP_NET_BIND_SERVICE",
}

// capNetRaw is the third member of `hostnetSandboxLinuxCaps`, but is only
// used when both hostinet and raw sockets are enabled.
const capNetRaw = "CAP_NET_RAW"

// capSysPtrace is granted when the platform needs to ptrace its stub
// processes.
const capSysPtrace = "CAP_SYS_PTRACE"

// baseFDClasses are the FD kinds every sandbox may hold, regardless of
// config.
var baseFDClasses = []string{
	FDNullDev,
	FDRegular, // debug and log files donated by the parent
	FDPipe,
	FDSocket,
	FDAnonPrefix + "eventfd",
	FDAnonPrefix + "eventpoll",
	FDMemfdPrefix + "runsc-memory",
	FDMemfdPrefix + "memory-usage",
}

// ExpectedOpts describes the runsc configuration a sandbox was started with,
// or at least the subset of it that determines its expected security posture.
type ExpectedOpts struct {
	// Ref describes the process the sandbox was launched from.
	Ref Reference

	// Sandbox config options follow.

	DirectFS             bool
	NetworkMode          string
	EnableRaw            bool
	RequiresCapSysPtrace bool
	SpecHasUserNamespace bool
	NetNamespaceTarget   string
	CgoEnabled           bool
	GoDebug              string

	// ChildOfRef is whether the sandbox is expected to be a direct child
	// of the reference process. False under shim.
	ChildOfRef bool

	// Umask defaults to Ref.Umask, then to "0022".
	Umask string

	// NOFILE defaults to LimitSameAsRef.
	NOFILE string
	// MEMLOCK defaults to LimitUnlimited.
	MEMLOCK string

	// ExtraRootEntries, ExtraFDClasses and ExtraMounts widen the corresponding
	// expectations.
	ExtraRootEntries []string
	ExtraFDClasses   []string
	ExtraMounts      []string
}

// HostNetwork returns true if the sandbox is using hostinet.
func (e *ExpectedOpts) HostNetwork() bool {
	return e.NetworkMode == "host"
}

// Expected returns the posture a sandbox started with the given configuration
// must have.
func Expected(opts ExpectedOpts) *Posture {
	applyCaps := opts.DirectFS || opts.HostNetwork()
	newUserNS := !applyCaps || opts.SpecHasUserNamespace || (opts.DirectFS && !opts.HostNetwork())
	return &Posture{
		Creds:      expectedCreds(applyCaps),
		Caps:       expectedCaps(opts, applyCaps),
		Seccomp:    Seccomp{Mode: 2, NoNewPrivs: 1},
		Namespaces: expectedNamespaces(opts, newUserNS),
		FS:         expectedFilesystem(opts),
		FDs:        expectedFDs(opts),
		Attrs:      expectedAttrs(opts, applyCaps, newUserNS),
		Threads:    Threads{Uniform: true},
	}
}

func expectedCreds(applyCaps bool) Credentials {
	if applyCaps {
		// The sandbox stays as whoever ran runsc. Under a user namespace of
		// its own that identity is remapped to itself, so it is still the same
		// user.
		return Credentials{UID: IDSameAsRef, GID: IDSameAsRef}
	}
	return Credentials{UID: IDNobody, GID: IDNobody}
}

func expectedCaps(opts ExpectedOpts, applyCaps bool) Capabilities {
	if !applyCaps {
		return Capabilities{}
	}
	var caps []string
	if opts.RequiresCapSysPtrace {
		caps = append(caps, capSysPtrace)
	}
	if opts.DirectFS {
		caps = append(caps, directfsCaps...)
	}
	if opts.HostNetwork() {
		held := make(map[string]bool, len(opts.Ref.PermittedCaps))
		for _, c := range opts.Ref.PermittedCaps {
			held[c] = true
		}
		for _, c := range hostNetworkCaps {
			if held[c] {
				caps = append(caps, c)
			}
		}
		if opts.EnableRaw && held[capNetRaw] {
			caps = append(caps, capNetRaw)
		}
	}
	caps = dedupe(caps)
	return Capabilities{
		Bounding:  caps,
		Effective: caps,
		Permitted: caps,
	}
}

func expectedNamespaces(opts ExpectedOpts, newUserNS bool) Namespaces {
	ns := Namespaces{
		// Unconditionally requested.
		Mnt:    NSNew,
		PID:    NSNew,
		IPC:    NSNew,
		UTS:    NSNew,
		Cgroup: NSInherited, // We set IgnoreCgroups, so this doesn't change.
		Time:   NSInherited,
		User:   NSInherited,
	}
	if newUserNS {
		ns.User = NSNew
	}
	switch {
	case opts.NetNamespaceTarget != "":
		ns.Net = NSJoined(opts.NetNamespaceTarget)
	case opts.HostNetwork():
		ns.Net = NSInherited
	default:
		ns.Net = NSNew
	}
	return ns
}

func expectedFilesystem(opts ExpectedOpts) Filesystem {
	entries := []string{"etc/", "etc/localtime", "proc/"}
	entries = append(entries, opts.ExtraRootEntries...)

	mounts := []string{"/ tmpfs ro"}
	mounts = append(mounts, opts.ExtraMounts...)

	sort.Strings(entries)
	sort.Strings(mounts)
	return Filesystem{
		Root:     RootOwn,
		Entries:  entries,
		Cwd:      "/",
		ReadOnly: true,
		Mounts:   mounts,
	}
}

func expectedFDs(opts ExpectedOpts) FDTable {
	classes := append([]string(nil), baseFDClasses...)
	classes = append(classes, opts.Ref.StdioFDs...)
	if opts.RequiresCapSysPtrace {
		classes = append(classes,
			FDAnonPrefix+"seccomp-notify",
			FDMemfdPrefix+"systrap-memory",
		)
	}
	hasDirs := false
	if opts.DirectFS {
		// A directfs sandbox holds directory descriptors to open files
		// without gofer roundtrip.
		classes = append(classes, FDDirectory, FDSymlink)
		hasDirs = true
	}
	classes = append(classes, opts.ExtraFDClasses...)
	return FDTable{
		Classes:        dedupe(classes),
		HasDirectories: hasDirs,
	}
}

func expectedAttrs(opts ExpectedOpts, applyCaps, newUserNS bool) Attrs {
	umask := opts.Umask
	if umask == "" {
		umask = opts.Ref.Umask
	}
	if umask == "" {
		umask = "0022"
	}
	if opts.DirectFS {
		umask = "0000"
	}

	var env []string
	if opts.NetworkMode == "plugin" {
		env = append(env, "GLIBC_TUNABLES=glibc.pthread.rseq=0")
	}
	if opts.GoDebug != "" {
		env = append(env, "GODEBUG="+opts.GoDebug)
	}
	sort.Strings(env)

	nofile := opts.NOFILE
	if nofile == "" {
		nofile = LimitSameAsRef
	}
	memlock := opts.MEMLOCK
	if memlock == "" {
		memlock = LimitUnlimited
	}

	uidMap, gidMap := MapSameAsRef, MapSameAsRef
	if newUserNS {
		if applyCaps {
			uidMap, gidMap = MapIdentityOfRef, MapIdentityOfRef
		} else {
			uidMap, gidMap = MapNobodyToNobody, MapNobodyToNobody
		}
	}

	return Attrs{
		Umask:              umask,
		SessionLeader:      true,
		ProcessGroupLeader: true,
		ChildOfRef:         opts.ChildOfRef,
		Environ:            env,
		Argv0:              "runsc-sandbox",
		Limits:             map[string]string{"NOFILE": nofile, "MEMLOCK": memlock},
		UIDMap:             uidMap,
		GIDMap:             gidMap,
		ProcFileOwner:      OwnerSameAsProcess,
	}
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// ExecutableByOthers reports whether a process holding none of the file's
// owning IDs, and no capability, could execute it.
// Needed to know if `runsc` is re-exec-able as `nobody`.
func ExecutableByOthers(path string) (bool, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}
	if abs, err = filepath.EvalSymlinks(abs); err != nil {
		return false, err
	}
	for p := abs; ; p = filepath.Dir(p) {
		fi, err := os.Stat(p)
		if err != nil {
			return false, err
		}
		if fi.Mode().Perm()&0o001 == 0 {
			return false, nil
		}
		if p == "/" {
			return true, nil
		}
	}
}

// UserNamespaceMapsID reports whether the calling process's user namespace
// maps the given ID, i.e. whether a child user namespace could be created that
// maps it.
func UserNamespaceMapsID(id int) (bool, error) {
	b, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return false, fmt.Errorf("reading /proc/self/uid_map: %w", err)
	}
	entries, err := parseIDMap(string(b))
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if id >= e.inside && id < e.inside+e.count {
			return true, nil
		}
	}
	return false, nil
}

// Common cmp options.
var (
	infoFields, subsetFields = taggedFields(reflect.TypeFor[Posture](), "", nil)
	cmpAlwaysOnOpts          = cmp.Options{
		cmpopts.EquateEmpty(),
		cmpopts.IgnoreFields(Posture{}, infoFields...),
	}
)

const (
	// postureTag is the struct tag that controls how a Posture field is compared.
	postureTag = "posture"

	// Values for postureTag:

	// tagInfo is a field that is printed but not compared.
	tagInfo = "info"

	// tagSubset is a string slice that must be a subset of `want`.
	tagSubset = "subset"
)

// Diff compares a collected `Posture` against an expected one.
// `posture` field tags determine comparison semantics.
// Returns the empty string when they match.
func Diff(want, got *Posture, opts ...cmp.Option) string {
	if want == nil || got == nil {
		return fmt.Sprintf("nil posture: want %v, got %v", want != nil, got != nil)
	}
	d := cmp.Diff(relaxSubsets(want, got), got, cmpAlwaysOnOpts, cmp.Options(opts))
	if d == "" {
		return ""
	}
	// Context for the diff above it, on one very long line. There is nothing
	// to paste it into: expectations are computed by `Expected`, not written
	// out as literals.
	return fmt.Sprintf("sandbox posture differs from expectation (-want +got):\n%s\n\nCollected posture:\n%#v\n",
		strings.TrimRight(d, "\n"), got)
}

// taggedFields walks a posture type and returns the dot-delimited names of the
// fields tagged `posture:"info"` and the index chains of those tagged
// `posture:"subset"`.
func taggedFields(t reflect.Type, prefix string, index []int) (info []string, subset [][]int) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := prefix + f.Name
		idx := append(append([]int(nil), index...), i)
		switch f.Tag.Get(postureTag) {
		case tagInfo:
			info = append(info, name)
		case tagSubset:
			if f.Type.Kind() != reflect.Slice || f.Type.Elem().Kind() != reflect.String {
				panic(fmt.Sprintf("%s is tagged %q but is not a slice of strings", name, tagSubset))
			}
			subset = append(subset, idx)
		default:
			if f.Type.Kind() == reflect.Struct {
				ni, ns := taggedFields(f.Type, name+".", idx)
				info = append(info, ni...)
				subset = append(subset, ns...)
			}
		}
	}
	return info, subset
}

// relaxSubsets returns a copy of want holding, in each of its subset fields,
// only the elements got holds too.
func relaxSubsets(want, got *Posture) *Posture {
	intersect := func(got, want reflect.Value) reflect.Value {
		inGot := make(map[string]bool, got.Len())
		for i := 0; i < got.Len(); i++ {
			inGot[got.Index(i).String()] = true
		}
		out := reflect.MakeSlice(want.Type(), 0, want.Len())
		for i := 0; i < want.Len(); i++ {
			if inGot[want.Index(i).String()] {
				out = reflect.Append(out, want.Index(i))
			}
		}
		return out
	}
	relaxed := *want
	w := reflect.ValueOf(&relaxed).Elem()
	g := reflect.ValueOf(got).Elem()
	for _, idx := range subsetFields {
		wf := w.FieldByIndex(idx)
		wf.Set(intersect(g.FieldByIndex(idx), wf))
	}
	return &relaxed
}
