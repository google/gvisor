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

// Package sandboxposture collects the externally-observable Linux security
// posture of a running `runsc boot` (Sentry) process, and compares it against
// expectations depending on the runsc configuration.
package sandboxposture

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/moby/sys/capability"
	"golang.org/x/sys/unix"
)

// Normalized namespace classifications, used by every field of `Namespaces`.
const (
	// NSInherited means the namespace is the same as the reference process's.
	NSInherited = "inherited"

	// NSNew means the namespace is *not* the reference process's namespace.
	NSNew = "new"

	// NSJoinedPrefix prefixes a namespace that matches the specific namespace
	// named after the prefix. See `NSJoined`.
	NSJoinedPrefix = "joined:"
)

// NSJoined returns the namespace value meaning "this namespace is the one
// registered under `name` in `Opts.NamespaceTargets`".
func NSJoined(name string) string { return NSJoinedPrefix + name }

// Normalized values for `Credentials.Groups`.
const (
	// GroupsNone means the process has an empty supplementary group list.
	GroupsNone = "none"

	// GroupsSameAsRef means the process's supplementary group list is the same
	// as the reference process's.
	GroupsSameAsRef = "same-as-ref"
)

// Normalized values for `Credentials.UID` and `Credentials.GID`.
const (
	// IDSameAsRef means the ID is the reference process's ID.
	IDSameAsRef = "same-as-ref"

	// IDNobody is the conventional "nobody" unprivileged ID.
	IDNobody = "nobody(65534)"

	// IDRoot is uid/gid 0. Note that inside a user namespace, this means
	// "root of that user namespace", not necessarily root-userns root.
	IDRoot = "root(0)"
)

// Normalized values for `Filesystem.Root` (as in filesystem).
const (
	// RootSameAsRef means the process shares the reference process's root
	// directory.
	RootSameAsRef = "same-as-ref"

	// RootOwn means the process's root directory is *not* the reference
	// process's root directory: it has been chrooted or pivot_root'ed away.
	RootOwn = "own"
)

// Normalized values for `Attrs.UIDMap` and `Attrs.GIDMap`.
const (
	// MapSameAsRef means the process is in the reference process's user
	// namespace.
	MapSameAsRef = "same-as-ref"

	// MapIdentityOfRef means the process is in a new user namespace whose map
	// covers exactly the same IDs as the reference process's map, mapped to
	// themselves.
	MapIdentityOfRef = "identity-of-ref"

	// MapNobodyToNobody means the map is the single entry "65534 65534 1".
	MapNobodyToNobody = "nobody->nobody"

	// MapNobodyToRef means the map is the single entry "65534 <refuid> 1".
	MapNobodyToRef = "nobody->ref"

	// MapEmpty means the map file is empty.
	// A process in this state has no valid IDs.
	MapEmpty = "empty"
)

// Normalized values for `Attrs.ProcFileOwner`.
const (
	// OwnerSameAsProcess means the files under `/proc/<pid>` are owned by the
	// process's own effective IDs, which is what the kernel does for a
	// "dumpable" process.
	OwnerSameAsProcess = "same-as-process"

	// OwnerRoot means the files under `/proc/<pid>` are owned by 0:0 while
	// the process itself runs as something else. The kernel does this when a
	// process is not "dumpable", so this doubles as the observable proxy for
	// dumpability (see `Attrs.ProcFileOwner`).
	OwnerRoot = "root"
)

// Normalized values for `Attrs.Limits`.
const (
	// LimitSameAsRef means the limit is identical to the reference process's.
	LimitSameAsRef = "same-as-ref"

	// LimitUnlimited means both soft and hard limit are `RLIM_INFINITY`.
	LimitUnlimited = "unlimited/unlimited"
)

// FD classes reported in `FDTable.Classes`.
const (
	FDDirectory = "dir"
	FDSocket    = "socket"
	FDPipe      = "pipe"
	FDNullDev   = "null-dev"
	FDRegular   = "regular"
	FDDeleted   = "regular-deleted"
	FDCharDev   = "chardev"
	FDBlockDev  = "blockdev"
	FDFifo      = "fifo"
	FDSymlink   = "symlink"
	FDUnknown   = "unknown"

	// FDAnonPrefix prefixes anonymous inode FDs, e.g. "anon:eventfd".
	FDAnonPrefix = "anon:"

	// FDMemfdPrefix prefixes memfd FDs, e.g. "memfd:systrap-memory".
	FDMemfdPrefix = "memfd:"
)

// Posture is a normalized, comparable view of a process's
// externally-observable Linux security posture.
type Posture struct {
	// Creds is the process's user and group identity.
	Creds Credentials

	// Caps is the process's capability sets.
	Caps Capabilities

	// Seccomp is the process's seccomp status.
	Seccomp Seccomp

	// Namespaces classifies each namespace the process is in.
	Namespaces Namespaces

	// FS is the process's view of the filesystem.
	FS Filesystem

	// FDs describes what the process holds open.
	FDs FDTable

	// Attrs holds the process attributes.
	Attrs Attrs

	// Threads reports whether every thread in the process all share the
	// same process-level credentials, capabilities and seccomp state.
	Threads Threads

	// Children counts the process's direct children by command name.
	// Useful for debugging, not used for comparison.
	Children map[string]int `posture:"info"`
}

// Credentials is a process's user and group identity.
type Credentials struct {
	// UID is the real/effective/saved/filesystem UID, normalized.
	UID string

	// GID is the group equivalent of `UID`.
	GID string

	// ExtraGroups is the sorted set of supplementary groups the process holds
	// that the reference process did not (excluding the overflow GID).
	ExtraGroups []string

	// Groups is the raw supplementary group list. Informational only.
	Groups string `posture:"info"`
}

// overflowID is the kernel's overflowuid/overflowgid.
// It is also the conventional "nobody" ID.
const overflowID = 65534

// Capabilities is a process's capability sets, each as a sorted list, with
// a "CAP_" prefix.
type Capabilities struct {
	Inheritable []string
	Permitted   []string
	Effective   []string
	Bounding    []string
	Ambient     []string
}

// Seccomp is a process's seccomp state.
//
// Does not test for filter contents, as this requires custom kernel settings.
// Other gVisor tests cover seccomp filter contents.
type Seccomp struct {
	// Mode is the value of the Seccomp field in procfs status:
	// 0 = disabled, 1 = strict, 2 = filtered.
	Mode int

	// NumFilters is the value of the Seccomp_filters field in procfs status,
	// i.e. how many filter programs are attached. Informational only.
	NumFilters int `posture:"info"`

	// NoNewPrivs is the `no_new_privs` bit, which must be set before a
	// non-privileged process may install a filter, and which prevents
	// subsequent execve's from regaining privileges.
	NoNewPrivs int
}

// Namespaces classifies each of a process's namespaces relative to the
// reference process and to any named targets.
type Namespaces struct {
	Mnt    string
	PID    string
	IPC    string
	UTS    string
	Net    string
	User   string
	Cgroup string
	Time   string
}

// Filesystem is a process's view of the filesystem.
type Filesystem struct {
	// Root is `RootOwn` or `RootSameAsRef`.
	Root string

	// Entries is a recursive listing of the process's root directory, sorted,
	// with paths relative to that root and directories suffixed with "/".
	// Does not cross mountpoints.
	//
	// Compared as a subset: the sandbox may see fewer files than expected,
	// but never more.
	Entries []string `posture:"subset"`

	// Cwd is the working directory as seen from inside the process's own root.
	Cwd string

	// ReadOnly reports whether the filesystem mounted at the process's root is
	// read-only.
	ReadOnly bool

	// Mounts is the process's mount table, one entry per line, normalized to
	// "<mountpoint> <fstype> <flags>" with flags restricted to the
	// security-relevant ones + deduped + sorted.
	Mounts []string

	// RootLink is the raw target of `/proc/<pid>/root`, for debugging.
	RootLink string `posture:"info"`
}

// FDTable describes a process's open file descriptors.
type FDTable struct {
	// Classes is the sorted set of distinct FD classes the process holds.
	// It is a set, not a count, because the number of memfds or eventfds a
	// sandbox holds is an implementation detail while the *kind* of thing it
	// holds is its security posture.
	//
	// Compared as a subset, as the the sandbox holding fewer kinds of FDs
	// than expected is not a regression.
	Classes []string `posture:"subset"`

	// HasDirectories reports whether the process holds any directory FD.
	//
	// This is critical because a directory FD grants the ability to reach
	// anything under it, and survives `chroot` and `pivot_root`.
	HasDirectories bool

	// Counts is the number of FDs in each class. Informational.
	Counts map[string]int `posture:"info"`

	// Links is the sorted set of readlink targets with inode numbers stripped,
	// so that a failure report says what the unexpected FD actually was.
	Links []string `posture:"info"`
}

// Attrs holds per-process attributes that do not group naturally elsewhere.
type Attrs struct {
	// Umask is the process's file mode creation mask, e.g. "0022".
	Umask string

	// SessionLeader reports whether the process is its own session leader.
	SessionLeader bool

	// ProcessGroupLeader reports whether the process is its own group leader.
	ProcessGroupLeader bool

	// ChildOfRef reports whether the process's parent is the reference
	// process. False under shim.
	ChildOfRef bool

	// Environ is the environment, sorted, with variables like
	// `RUNSC_START_TIME_NANOS` and `GVISOR_ENFORCE_RELEASE` removed.
	Environ []string

	// Argv0 is argv[0], which `runsc` should set to "runsc-sandbox".
	Argv0 string

	// Limits maps resource names to normalized "<soft>/<hard>" strings, or to
	// `LimitSameAsRef`.
	Limits map[string]string

	// UIDMap and GIDMap classify the process's user namespace ID mappings.
	UIDMap string
	GIDMap string

	// ProcFileOwner is the ownership of the files under `/proc/<pid>`, which
	// the kernel gives to root when a process is not dumpable.
	// We use this as a proxy for whether `/proc/<pid>/mem` is reachable by
	// the process's own user.
	ProcFileOwner string

	// Argv is the full command line. Informational only.
	Argv []string `posture:"info"`
}

// Threads reports whether the process's threads share its posture.
type Threads struct {
	// Uniform reports whether every thread's credentials, capabilities and
	// seccomp state match process-wide values.
	Uniform bool

	// Divergences describes each mismatch found.
	// Empty when `Uniform` is true.
	Divergences []string
}

// PlatformCapSysPtrace contains which platforms need CAP_SYS_PTRACE.
// Platforms absent here are expected to not need it.
var PlatformCapSysPtrace = map[string]bool{
	"systrap": true,
	"ptrace":  true,
}

// PlatformGoDebug contains the expected GODEBUG for each platform, if any.
var PlatformGoDebug = map[string]string{
	"kvm":    "asyncpreemptoff=1",
	"slimvm": "asyncpreemptoff=1",
}

// Opts is the set of options to `Collect`.
type Opts struct {
	// PID is the process to collect.
	PID int

	// RefPID is the reference process that posture is expressed relative to.
	RefPID int

	// NamespaceTargets maps a name to a path naming a namespace, such as
	// {"container-netns": "/var/run/docker/netns/abc123"}.
	NamespaceTargets map[string]string

	// ProcRoot is the procfs mount to read through. Defaults to "/proc".
	ProcRoot string
}

// Collect gathers the posture of `opts.PID`.
func Collect(opts Opts) (*Posture, error) {
	if opts.PID <= 0 {
		return nil, fmt.Errorf("invalid PID %d", opts.PID)
	}
	if opts.RefPID <= 0 {
		return nil, fmt.Errorf("invalid reference PID %d", opts.RefPID)
	}
	procRoot := opts.ProcRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	p := &proc{root: procRoot, pid: opts.PID}
	ref := &proc{root: procRoot, pid: opts.RefPID}

	status, err := p.status()
	if err != nil {
		return nil, fmt.Errorf("reading status: %w", err)
	}
	refStatus, err := ref.status()
	if err != nil {
		return nil, fmt.Errorf("reading reference status: %w", err)
	}

	var posture Posture
	if posture.Creds, err = collectCreds(status, refStatus); err != nil {
		return nil, fmt.Errorf("collecting credentials: %w", err)
	}
	if posture.Caps, err = collectCaps(status); err != nil {
		return nil, fmt.Errorf("collecting capabilities: %w", err)
	}
	if posture.Seccomp, err = collectSeccomp(status); err != nil {
		return nil, fmt.Errorf("collecting seccomp state: %w", err)
	}
	if posture.Namespaces, err = collectNamespaces(p, ref, opts.NamespaceTargets); err != nil {
		return nil, fmt.Errorf("collecting namespaces: %w", err)
	}
	if posture.FS, err = collectFilesystem(p, ref); err != nil {
		return nil, fmt.Errorf("collecting filesystem view: %w", err)
	}
	if posture.FDs, err = collectFDs(p); err != nil {
		return nil, fmt.Errorf("collecting FD table: %w", err)
	}
	if posture.Attrs, err = collectAttrs(p, ref, status, refStatus, posture.Namespaces.User); err != nil {
		return nil, fmt.Errorf("collecting process attributes: %w", err)
	}
	if posture.Threads, err = collectThreads(p, status); err != nil {
		return nil, fmt.Errorf("collecting per-thread posture: %w", err)
	}
	if posture.Children, err = collectChildren(p); err != nil {
		return nil, fmt.Errorf("collecting children: %w", err)
	}
	return &posture, nil
}

// proc reads files out of one process's procfs directory.
type proc struct {
	root string
	pid  int
}

func (p *proc) path(elems ...string) string {
	return filepath.Join(append([]string{p.root, strconv.Itoa(p.pid)}, elems...)...)
}

func (p *proc) read(elems ...string) (string, error) {
	b, err := os.ReadFile(p.path(elems...))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// readNUL reads a `\x00`-separated procfs file (cmdline, environ).
func (p *proc) readNUL(elems ...string) ([]string, error) {
	s, err := p.read(elems...)
	if err != nil {
		return nil, err
	}
	s = strings.TrimRight(s, "\x00")
	if s == "" {
		return nil, nil
	}
	return strings.Split(s, "\x00"), nil
}

// status parses the process's status file into a map.
func (p *proc) status() (map[string]string, error) {
	return parseStatus(p.path("status"))
}

// taskStatus parses the status file of one of p's threads.
func (p *proc) taskStatus(tid string) (map[string]string, error) {
	return parseStatus(p.path("task", tid, "status"))
}

func parseStatus(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := make(map[string]string)
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		m[k] = strings.TrimSpace(v)
	}
	return m, nil
}

// idQuad parses a status line of four IDs (e.g. "Uid:\t0\t0\t0\t0").
func idQuad(status map[string]string, key string) ([4]int, error) {
	var out [4]int
	fields := strings.Fields(status[key])
	if len(fields) != 4 {
		return out, fmt.Errorf("malformed %s line %q", key, status[key])
	}
	for i, f := range fields {
		v, err := strconv.Atoi(f)
		if err != nil {
			return out, fmt.Errorf("malformed %s line %q: %w", key, status[key], err)
		}
		out[i] = v
	}
	return out, nil
}

// normalizeID pretty-prints an ID quad against `refQuad`.
func normalizeID(quad [4]int, refQuad [4]int) string {
	uniform := quad[0] == quad[1] && quad[1] == quad[2] && quad[2] == quad[3]
	name := func(id int) string {
		switch id {
		case refQuad[0]:
			return IDSameAsRef
		case overflowID:
			return IDNobody
		case 0:
			return IDRoot
		default:
			return strconv.Itoa(id)
		}
	}
	if uniform {
		return name(quad[0])
	}
	parts := make([]string, 0, 4)
	for _, id := range quad {
		parts = append(parts, name(id))
	}
	return "real=" + parts[0] + " effective=" + parts[1] + " saved=" + parts[2] + " fs=" + parts[3]
}

func collectCreds(status, refStatus map[string]string) (Credentials, error) {
	var c Credentials
	uid, err := idQuad(status, "Uid")
	if err != nil {
		return c, err
	}
	refUID, err := idQuad(refStatus, "Uid")
	if err != nil {
		return c, fmt.Errorf("reference: %w", err)
	}
	gid, err := idQuad(status, "Gid")
	if err != nil {
		return c, err
	}
	refGID, err := idQuad(refStatus, "Gid")
	if err != nil {
		return c, fmt.Errorf("reference: %w", err)
	}
	c.UID = normalizeID(uid, refUID)
	c.GID = normalizeID(gid, refGID)

	groups := strings.Fields(status["Groups"])
	refGroups := strings.Fields(refStatus["Groups"])
	inRef := make(map[string]bool, len(refGroups))
	for _, g := range refGroups {
		inRef[g] = true
	}
	extra := make(map[string]bool)
	for _, g := range groups {
		if inRef[g] || g == strconv.Itoa(overflowID) {
			continue
		}
		extra[g] = true
	}
	for g := range extra {
		c.ExtraGroups = append(c.ExtraGroups, g)
	}
	sort.Strings(c.ExtraGroups)

	sorted := append([]string(nil), groups...)
	sort.Strings(sorted)
	switch {
	case len(sorted) == 0:
		c.Groups = GroupsNone
	case len(extra) == 0:
		c.Groups = GroupsSameAsRef
	default:
		c.Groups = "gids:" + strings.Join(sorted, ",")
	}
	return c, nil
}

// capNames maps a capability bit to its symbolic kernel name.
var capNames = func() map[int]string {
	m := make(map[int]string)
	for _, c := range capability.ListKnown() {
		m[int(c)] = "CAP_" + strings.ToUpper(c.String())
	}
	return m
}()

// capName returns the symbolic name of the capability at bit position i.
// Unknown bits are rendered numerically rather than dropped: a capability this
// binary has never heard of appearing in a sandbox's permitted set is exactly
// the kind of thing that must show up in a diff.
func capName(i int) string {
	if n, ok := capNames[i]; ok {
		return n
	}
	return fmt.Sprintf("CAP_UNKNOWN_%d", i)
}

func capsFromMask(mask uint64) []string {
	var out []string
	for i := 0; i < 64; i++ {
		if mask&(uint64(1)<<uint(i)) != 0 {
			out = append(out, capName(i))
		}
	}
	sort.Strings(out)
	return out
}

func capSet(status map[string]string, key string) ([]string, error) {
	v, ok := status[key]
	if !ok {
		return nil, fmt.Errorf("status has no %s line", key)
	}
	mask, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
	if err != nil {
		return nil, fmt.Errorf("malformed %s line %q: %w", key, v, err)
	}
	return capsFromMask(mask), nil
}

func collectCaps(status map[string]string) (Capabilities, error) {
	var c Capabilities
	var err error
	if c.Inheritable, err = capSet(status, "CapInh"); err != nil {
		return c, err
	}
	if c.Permitted, err = capSet(status, "CapPrm"); err != nil {
		return c, err
	}
	if c.Effective, err = capSet(status, "CapEff"); err != nil {
		return c, err
	}
	if c.Bounding, err = capSet(status, "CapBnd"); err != nil {
		return c, err
	}
	// CapAmb was added in Linux 4.something.
	// Treat absence as an empty set, since this does imply
	// "no ambient caps".
	if _, ok := status["CapAmb"]; ok {
		if c.Ambient, err = capSet(status, "CapAmb"); err != nil {
			return c, err
		}
	}
	return c, nil
}

func collectSeccomp(status map[string]string) (Seccomp, error) {
	var s Seccomp
	var err error
	if s.Mode, err = statusInt(status, "Seccomp", true); err != nil {
		return s, err
	}
	// Seccomp_filters was added in Linux 5.9; older kernels do not report it.
	if s.NumFilters, err = statusInt(status, "Seccomp_filters", false); err != nil {
		return s, err
	}
	if s.NoNewPrivs, err = statusInt(status, "NoNewPrivs", true); err != nil {
		return s, err
	}
	return s, nil
}

// statusInt reads an integer status field.
// If `required` is false, missing means zero rather than an error.
func statusInt(status map[string]string, key string, required bool) (int, error) {
	v, ok := status[key]
	if !ok {
		if required {
			return 0, fmt.Errorf("status has no %s line", key)
		}
		return 0, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, fmt.Errorf("malformed %s line %q: %w", key, v, err)
	}
	return n, nil
}

// nsKinds are the namespace types collected, in the order they appear in
// `Namespaces`.
var nsKinds = []string{"mnt", "pid", "ipc", "uts", "net", "user", "cgroup", "time"}

// UnsupportedFeatures returns the posture-relevant things this kernel cannot
// report. Callers should skip the whole test when this function returns
// anything.
func UnsupportedFeatures() []string {
	var missing []string
	for _, kind := range nsKinds {
		if _, err := nsIdentity(filepath.Join("/proc/self/ns", kind)); os.IsNotExist(err) {
			missing = append(missing, kind+" namespace")
		}
	}
	return missing
}

func collectNamespaces(p, ref *proc, targets map[string]string) (Namespaces, error) {
	resolved := make(map[string]string, len(targets))
	for name, path := range targets {
		id, err := nsIdentity(path)
		if err != nil {
			return Namespaces{}, fmt.Errorf("resolving namespace target %q at %q: %w", name, path, err)
		}
		resolved[name] = id
	}

	classify := func(kind string) (string, error) {
		id, err := nsIdentity(p.path("ns", kind))
		if err != nil {
			return "", err
		}
		refID, refErr := nsIdentity(ref.path("ns", kind))
		if refErr == nil && id == refID {
			return NSInherited, nil
		}
		// Sort names so that a namespace matching two targets classifies
		// deterministically.
		names := make([]string, 0, len(resolved))
		for name := range resolved {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if resolved[name] == id {
				return NSJoined(name), nil
			}
		}
		return NSNew, nil
	}

	var ns Namespaces
	dst := map[string]*string{
		"mnt": &ns.Mnt, "pid": &ns.PID, "ipc": &ns.IPC, "uts": &ns.UTS,
		"net": &ns.Net, "user": &ns.User, "cgroup": &ns.Cgroup, "time": &ns.Time,
	}
	for _, kind := range nsKinds {
		v, err := classify(kind)
		if err != nil {
			return ns, fmt.Errorf("classifying %s namespace: %w", kind, err)
		}
		*dst[kind] = v
	}
	return ns, nil
}

// nsIdentity returns the dev/inode numbers for the namespace named by path.
// Used to match different paths referring to the same namespace.
func nsIdentity(path string) (string, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return "", &os.PathError{Op: "stat", Path: path, Err: err}
	}
	return fmt.Sprintf("%d:%d", st.Dev, st.Ino), nil
}

// procfsSubmountRE matches the two names `runsc` gives the procfs instance it
// mounts inside the sandbox chroot.
var procfsSubmountRE = regexp.MustCompile(`/(sandbox-proc|host-proc)(/|$)`)

const procfsSubmountToken = "/<procfs>"

// normalizeMountpoint rewrites the procfs submount name to a stable string.
func normalizeMountpoint(path string) string {
	return procfsSubmountRE.ReplaceAllString(path, procfsSubmountToken+"$2")
}

// mountFlags are the mount options that carry security implications.
var mountFlags = []string{"ro", "nosuid", "nodev", "noexec"}

// unescapeMount undoes the octal escaping procfs applies to path fields in
// mountinfo.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 4
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// mountEntry is a parsed `/proc/<pid>/mountinfo` line.
type mountEntry struct {
	mountpoint string
	fstype     string
	flags      string
}

func (m mountEntry) String() string {
	return fmt.Sprintf("%s %s %s", m.mountpoint, m.fstype, m.flags)
}

func parseMountinfo(s string) ([]mountEntry, error) {
	var out []mountEntry
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		// Fields up to the optional-field separator "-": mountID parentID
		// major:minor rootWithinFS mountpoint options [optional...]
		if len(fields) < 7 {
			return nil, fmt.Errorf("malformed mountinfo line %q", line)
		}
		sep := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+2 >= len(fields) {
			return nil, fmt.Errorf("malformed mountinfo line %q: no separator", line)
		}
		var flags []string
		opts := strings.Split(fields[5], ",")
		for _, want := range mountFlags {
			for _, got := range opts {
				if got == want {
					flags = append(flags, want)
					break
				}
			}
		}
		out = append(out, mountEntry{
			mountpoint: normalizeMountpoint(unescapeMount(fields[4])),
			fstype:     fields[sep+1],
			flags:      strings.Join(flags, ","),
		})
	}
	return out, nil
}

func collectFilesystem(p, ref *proc) (Filesystem, error) {
	var fs Filesystem

	rootPath := p.path("root")
	if link, err := os.Readlink(rootPath); err == nil {
		fs.RootLink = link
	} else {
		fs.RootLink = "unreadable: " + err.Error()
	}

	rootID, err := nsIdentity(rootPath)
	if err != nil {
		return fs, fmt.Errorf("stat %s: %w", rootPath, err)
	}
	refRootID, err := nsIdentity(ref.path("root"))
	if err != nil {
		return fs, fmt.Errorf("stat reference root: %w", err)
	}
	if rootID == refRootID {
		fs.Root = RootSameAsRef
	} else {
		fs.Root = RootOwn
	}

	if fs.Entries, err = walkRoot(rootPath); err != nil {
		return fs, fmt.Errorf("listing root: %w", err)
	}

	// The cwd link is resolved against the target's root, so compare its text
	// with the root link's text to express cwd relative to that root.
	cwd, err := os.Readlink(p.path("cwd"))
	if err != nil {
		return fs, fmt.Errorf("reading cwd: %w", err)
	}
	fs.Cwd = func() string {
		if fs.RootLink == "" || fs.RootLink == "/" || strings.HasPrefix(fs.RootLink, "unreadable") {
			return cwd
		}
		if cwd == fs.RootLink {
			return "/"
		}
		if rest, ok := strings.CutPrefix(cwd, fs.RootLink+"/"); ok {
			return "/" + rest
		}
		return cwd
	}()

	var statfs unix.Statfs_t
	if err := unix.Statfs(rootPath, &statfs); err != nil {
		return fs, fmt.Errorf("statfs %s: %w", rootPath, err)
	}
	fs.ReadOnly = statfs.Flags&unix.ST_RDONLY != 0

	mountinfo, err := p.read("mountinfo")
	if err != nil {
		return fs, fmt.Errorf("reading mountinfo: %w", err)
	}
	entries, err := parseMountinfo(mountinfo)
	if err != nil {
		return fs, err
	}
	for _, e := range entries {
		// Drop mounts nested underneath the minimal procfs submount.
		if strings.Contains(e.mountpoint, procfsSubmountToken+"/") {
			continue
		}
		fs.Mounts = append(fs.Mounts, e.String())
	}
	sort.Strings(fs.Mounts)
	return fs, nil
}

// walkRoot lists the contents of `root` without crossing mountpoints.
func walkRoot(root string) ([]string, error) {
	const maxRootEntries = 256
	var rootStat unix.Stat_t
	if err := unix.Stat(root, &rootStat); err != nil {
		return nil, &os.PathError{Op: "stat", Path: root, Err: err}
	}

	var out []string
	var walk func(dir, prefix string) error
	walk = func(dir, prefix string) error {
		ents, err := os.ReadDir(dir)
		if err != nil {
			// runsc chmods the chroot's procfs root to 0111 on purpose.
			if os.IsPermission(err) {
				out = append(out, prefix+" [unreadable]")
				return nil
			}
			return err
		}
		for _, ent := range ents {
			if len(out) >= maxRootEntries {
				return nil
			}
			name := prefix + ent.Name()
			full := filepath.Join(dir, ent.Name())
			if !ent.IsDir() {
				out = append(out, name)
				continue
			}
			out = append(out, name+"/")
			var st unix.Stat_t
			if err := unix.Lstat(full, &st); err != nil {
				continue
			}
			if st.Dev != rootStat.Dev {
				continue // Do not descend into a separate mount.
			}
			if err := walk(full, name+"/"); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root, ""); err != nil {
		return nil, err
	}
	if len(out) >= maxRootEntries {
		out = append(out[:maxRootEntries], fmt.Sprintf("[truncated at %d entries]", maxRootEntries))
	}
	sort.Strings(out)
	return out, nil
}

// inodeRE matches the inode number inside a readlink target such as
// "socket:[12345]" or "pipe:[678]".
var inodeRE = regexp.MustCompile(`\[\d+\]`)

// deletedSuffix is what the kernel appends to a readlink target whose file has
// been unlinked.
const deletedSuffix = " (deleted)"

func collectFDs(p *proc) (FDTable, error) {
	var t FDTable
	fdDir := p.path("fd")
	ents, err := os.ReadDir(fdDir)
	if err != nil {
		return t, fmt.Errorf("reading %s: %w", fdDir, err)
	}

	classes := make(map[string]int)
	links := make(map[string]bool)
	for _, ent := range ents {
		full := filepath.Join(fdDir, ent.Name())
		link, err := os.Readlink(full)
		if err != nil {
			if os.IsNotExist(err) {
				continue // The FD was closed while we were looking at it.
			}
			return t, fmt.Errorf("readlink %s: %w", full, err)
		}
		var st unix.Stat_t
		mode := uint32(0)
		if err := unix.Stat(full, &st); err == nil {
			mode = st.Mode
		}
		class := classifyFD(link, mode)
		classes[class]++
		links[inodeRE.ReplaceAllString(link, "[N]")] = true
		if class == FDDirectory {
			t.HasDirectories = true
		}
	}
	t.Counts = classes
	for c := range classes {
		t.Classes = append(t.Classes, c)
	}
	sort.Strings(t.Classes)
	for l := range links {
		t.Links = append(t.Links, l)
	}
	sort.Strings(t.Links)
	return t, nil
}

// classifyFD reduces one FD to a normalized class.
// `link` is the readlink text. `mode` is the `st_mode` from `stat`'ing
// through the link, or `0` if that failed.
func classifyFD(link string, mode uint32) string {
	switch {
	case strings.HasPrefix(link, "socket:"):
		return FDSocket
	case strings.HasPrefix(link, "pipe:"):
		return FDPipe
	case strings.HasPrefix(link, "anon_inode:"):
		name := strings.TrimPrefix(link, "anon_inode:")
		name = strings.TrimSuffix(strings.TrimPrefix(name, "["), "]")
		return FDAnonPrefix + strings.ReplaceAll(name, " ", "-")
	case strings.HasPrefix(link, "/memfd:"):
		name := strings.TrimSuffix(strings.TrimPrefix(link, "/memfd:"), deletedSuffix)
		return FDMemfdPrefix + strings.TrimSpace(name)
	case link == "/dev/null":
		return FDNullDev
	}
	switch mode & unix.S_IFMT {
	case unix.S_IFDIR:
		return FDDirectory
	case unix.S_IFCHR:
		return FDCharDev + ":" + strings.TrimSuffix(link, deletedSuffix)
	case unix.S_IFBLK:
		return FDBlockDev
	case unix.S_IFIFO:
		return FDFifo
	case unix.S_IFSOCK:
		return FDSocket
	case unix.S_IFLNK:
		return FDSymlink
	case unix.S_IFREG:
		if strings.HasSuffix(link, deletedSuffix) {
			return FDDeleted
		}
		return FDRegular
	}
	return FDUnknown
}

// limitKeys maps the procfs `limits` file's human-readable names to the short
// names used in `Attrs.Limits`.
var limitKeys = map[string]string{
	"Max open files":    "NOFILE",
	"Max locked memory": "MEMLOCK",
}

// relativeLimits are the limits reported as `LimitSameAsRef` when they match
// the reference process's, rather than by value.
var relativeLimits = map[string]bool{
	"NOFILE": true,
}

func parseLimits(s string) (map[string]string, error) {
	out := make(map[string]string)
	lines := strings.Split(s, "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty limits file")
	}
	for _, line := range lines[1:] { // Skip header
		for human, short := range limitKeys {
			rest, ok := strings.CutPrefix(line, human)
			if !ok {
				continue
			}
			fields := strings.Fields(rest)
			if len(fields) < 2 {
				return nil, fmt.Errorf("malformed limits line %q", line)
			}
			out[short] = fields[0] + "/" + fields[1]
		}
	}
	for _, short := range limitKeys {
		if _, ok := out[short]; !ok {
			return nil, fmt.Errorf("limits file has no %s entry", short)
		}
	}
	return out, nil
}

// ignoredEnvRegExp matches the start-time env variable `runsc` uses.
var ignoredEnvRegExp = regexp.MustCompile(`^(RUNSC_START_TIME_NANOS=\d+|GVISOR_ENFORCE_RELEASE=.*)$`)

func collectAttrs(p, ref *proc, status, refStatus map[string]string, userNS string) (Attrs, error) {
	var a Attrs

	umask, ok := status["Umask"]
	if !ok {
		return a, fmt.Errorf("status has no Umask line")
	}
	a.Umask = umask

	stat, err := p.read("stat")
	if err != nil {
		return a, fmt.Errorf("reading stat: %w", err)
	}
	st, err := parseStat(stat)
	if err != nil {
		return a, err
	}
	a.SessionLeader = st.session == p.pid
	a.ProcessGroupLeader = st.pgrp == p.pid
	a.ChildOfRef = st.ppid == ref.pid

	env, err := p.readNUL("environ")
	if err != nil {
		return a, fmt.Errorf("reading environ: %w", err)
	}
	for _, e := range env {
		if ignoredEnvRegExp.MatchString(e) {
			continue
		}
		a.Environ = append(a.Environ, e)
	}
	sort.Strings(a.Environ)

	if a.Argv, err = p.readNUL("cmdline"); err != nil {
		return a, fmt.Errorf("reading cmdline: %w", err)
	}
	if len(a.Argv) == 0 {
		return a, fmt.Errorf("empty cmdline: process %d is a zombie or exited", p.pid)
	}
	a.Argv0 = a.Argv[0]
	limitsRaw, err := p.read("limits")
	if err != nil {
		return a, fmt.Errorf("reading limits: %w", err)
	}
	limits, err := parseLimits(limitsRaw)
	if err != nil {
		return a, err
	}
	refLimitsRaw, err := ref.read("limits")
	if err != nil {
		return a, fmt.Errorf("reading reference limits: %w", err)
	}
	refLimits, err := parseLimits(refLimitsRaw)
	if err != nil {
		return a, fmt.Errorf("reference: %w", err)
	}
	a.Limits = make(map[string]string, len(limits))
	for k, v := range limits {
		switch {
		case relativeLimits[k] && v == refLimits[k]:
			a.Limits[k] = LimitSameAsRef
		default:
			a.Limits[k] = v
		}
	}
	refUID, err := idQuad(refStatus, "Uid")
	if err != nil {
		return a, fmt.Errorf("reference: %w", err)
	}
	refGID, err := idQuad(refStatus, "Gid")
	if err != nil {
		return a, fmt.Errorf("reference: %w", err)
	}
	if a.UIDMap, err = collectIDMap(p, ref, "uid_map", userNS, refUID[0]); err != nil {
		return a, err
	}
	if a.GIDMap, err = collectIDMap(p, ref, "gid_map", userNS, refGID[0]); err != nil {
		return a, err
	}

	if a.ProcFileOwner, err = collectProcFileOwner(p, status); err != nil {
		return a, err
	}
	return a, nil
}

// statFields holds the fields of a procfs stat file that this package uses.
type statFields struct {
	ppid    int
	pgrp    int
	session int
}

// parseStat parses a procfs stat file.
func parseStat(s string) (statFields, error) {
	var out statFields
	idx := strings.LastIndex(s, ")")
	if idx < 0 {
		return out, fmt.Errorf("malformed stat file %q", s)
	}
	// Fields after the comm: state ppid pgrp session ...
	fields := strings.Fields(s[idx+1:])
	if len(fields) < 4 {
		return out, fmt.Errorf("malformed stat file %q: only %d fields after comm", s, len(fields))
	}
	var err error
	if out.ppid, err = strconv.Atoi(fields[1]); err != nil {
		return out, fmt.Errorf("malformed ppid in stat file %q: %w", s, err)
	}
	if out.pgrp, err = strconv.Atoi(fields[2]); err != nil {
		return out, fmt.Errorf("malformed pgrp in stat file %q: %w", s, err)
	}
	if out.session, err = strconv.Atoi(fields[3]); err != nil {
		return out, fmt.Errorf("malformed session in stat file %q: %w", s, err)
	}
	return out, nil
}

// idMapEntry is one line of a `uid_map` or `gid_map` file.
type idMapEntry struct {
	inside  int
	outside int
	count   int
}

func parseIDMap(s string) ([]idMapEntry, error) {
	var out []idMapEntry
	for _, line := range strings.Split(s, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 3 {
			return nil, fmt.Errorf("malformed ID map line %q", line)
		}
		var e idMapEntry
		var err error
		if e.inside, err = strconv.Atoi(fields[0]); err != nil {
			return nil, fmt.Errorf("malformed ID map line %q: %w", line, err)
		}
		if e.outside, err = strconv.Atoi(fields[1]); err != nil {
			return nil, fmt.Errorf("malformed ID map line %q: %w", line, err)
		}
		if e.count, err = strconv.Atoi(fields[2]); err != nil {
			return nil, fmt.Errorf("malformed ID map line %q: %w", line, err)
		}
		out = append(out, e)
	}
	return out, nil
}

// collectIDMap classifies a process's `uid_map` or `gid_map`.
func collectIDMap(p, ref *proc, file, userNS string, refID int) (string, error) {
	raw, err := p.read(file)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", file, err)
	}
	entries, err := parseIDMap(raw)
	if err != nil {
		return "", fmt.Errorf("parsing %s: %w", file, err)
	}
	if len(entries) == 0 {
		return MapEmpty, nil
	}
	if userNS == NSInherited {
		return MapSameAsRef, nil
	}

	refRaw, err := ref.read(file)
	if err != nil {
		return "", fmt.Errorf("reading reference %s: %w", file, err)
	}
	refEntries, err := parseIDMap(refRaw)
	if err != nil {
		return "", fmt.Errorf("parsing reference %s: %w", file, err)
	}

	if isIdentityOf(entries, refEntries) {
		return MapIdentityOfRef, nil
	}
	if len(entries) == 1 && entries[0].inside == overflowID && entries[0].count == 1 {
		switch entries[0].outside {
		case overflowID:
			return MapNobodyToNobody, nil
		case refID:
			return MapNobodyToRef, nil
		}
	}
	parts := make([]string, 0, len(entries))
	for _, e := range entries {
		parts = append(parts, fmt.Sprintf("%d %d %d", e.inside, e.outside, e.count))
	}
	return "raw:" + strings.Join(parts, ";"), nil
}

// isIdentityOf reports whether entries maps every ID to itself, over exactly
// the ranges that `ref` makes available.
func isIdentityOf(entries, ref []idMapEntry) bool {
	if len(entries) != len(ref) || len(entries) == 0 {
		return false
	}
	for _, e := range entries {
		if e.inside != e.outside {
			return false
		}
	}
	key := func(es []idMapEntry) []string {
		out := make([]string, 0, len(es))
		for _, e := range es {
			out = append(out, fmt.Sprintf("%d+%d", e.inside, e.count))
		}
		sort.Strings(out)
		return out
	}
	a, b := key(entries), key(ref)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func collectProcFileOwner(p *proc, status map[string]string) (string, error) {
	// We use a file under `/proc/<pid>` here, not `/proc/<pid>` itself.
	// The kernel exempts the `/proc/<pid>` directory from the rule that makes
	// non-dumpable tasks procfs files owned as root.
	path := p.path("status")
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return "", fmt.Errorf("stat %s: %w", path, err)
	}
	uid, err := idQuad(status, "Uid")
	if err != nil {
		return "", err
	}
	gid, err := idQuad(status, "Gid")
	if err != nil {
		return "", err
	}
	switch {
	case int(st.Uid) == uid[1] && int(st.Gid) == gid[1]:
		return OwnerSameAsProcess, nil
	case st.Uid == 0 && st.Gid == 0:
		return OwnerRoot, nil
	default:
		return fmt.Sprintf("uid=%d gid=%d", st.Uid, st.Gid), nil
	}
}

// threadFields are the status fields that must match on *every* thread.
var threadFields = []string{
	"Uid", "Gid",
	"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb",
	"NoNewPrivs", "Seccomp", "Seccomp_filters",
}

func collectThreads(p *proc, status map[string]string) (Threads, error) {
	var t Threads
	taskDir := p.path("task")
	ents, err := os.ReadDir(taskDir)
	if err != nil {
		return t, fmt.Errorf("reading %s: %w", taskDir, err)
	}
	seen := make(map[string]bool)
	var count int
	for _, ent := range ents {
		ts, err := p.taskStatus(ent.Name())
		if err != nil {
			if os.IsNotExist(err) {
				continue // Thread exited while we were looking at it.
			}
			return t, fmt.Errorf("reading thread %s status: %w", ent.Name(), err)
		}
		count++
		comm := ts["Name"]
		for _, f := range threadFields {
			want, haveWant := status[f]
			got, haveGot := ts[f]
			if haveWant != haveGot || want != got {
				seen[fmt.Sprintf("thread %q: %s = %q, process has %q", comm, f, got, want)] = true
			}
		}
	}
	if count == 0 {
		return t, fmt.Errorf("no threads found in %s", taskDir)
	}
	for d := range seen {
		t.Divergences = append(t.Divergences, d)
	}
	sort.Strings(t.Divergences)
	t.Uniform = len(t.Divergences) == 0
	return t, nil
}

func collectChildren(p *proc) (map[string]int, error) {
	out := make(map[string]int)
	taskDir := p.path("task")
	ents, err := os.ReadDir(taskDir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", taskDir, err)
	}
	for _, ent := range ents {
		raw, err := os.ReadFile(filepath.Join(taskDir, ent.Name(), "children"))
		if err != nil {
			continue // This field is best-effort anyway
		}
		for f := range strings.FieldsSeq(string(raw)) {
			comm, err := os.ReadFile(filepath.Join(p.root, f, "comm"))
			if err != nil {
				continue
			}
			out[strings.TrimSpace(string(comm))]++
		}
	}
	return out, nil
}
