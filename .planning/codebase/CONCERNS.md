# Codebase Concerns

**Analysis Date:** 2026-03-08

## Tech Debt

**syserr/linuxerr dual error system (b/34162363):**
- Issue: The `pkg/syserr` package contains legacy error translation infrastructure with 6 separate TODO markers referencing b/34162363 asking to "remove or replace most of these errors." The codebase maintains two parallel error representations: `syserr.Error` (used in socket/network code) and `linuxerr` (used everywhere else), requiring constant translation.
- Files: `pkg/syserr/syserr.go`, `pkg/syserr/host_linux.go`, `pkg/syserr/host_darwin.go`
- Impact: Dual error system creates confusion about which error type to use and unnecessary translation overhead. Every socket operation pays a cost to map between the two systems.
- Fix approach: Unify on `linuxerr` and replace `syserr.Error` usage throughout the network stack, removing the backwards translation table in `syserr.go`.

**Stub /proc filesystem implementations (b/37226836):**
- Issue: Multiple /proc files return hardcoded zero values instead of real data: `/proc/stat` (CPU stats, context switches, process counts), `/proc/loadavg` (all zeros), `/proc/meminfo` (partially stubbed). These are long-standing TODOs.
- Files: `pkg/sentry/fsimpl/proc/tasks_files.go` (lines 189-304), `pkg/sentry/fsimpl/proc/task_fds.go` (line 346)
- Impact: Applications that rely on `/proc/stat` or `/proc/loadavg` for monitoring, load balancing, or autoscaling get useless data. This affects container monitoring tools (Prometheus node_exporter, cAdvisor) and applications with self-tuning behavior.
- Fix approach: Wire up actual kernel counters for context switches, process forks, and running task counts through `pkg/sentry/kernel`.

**FUSE filesystem incomplete implementation (~30 TODOs):**
- Issue: The FUSE implementation lacks async read/write support (gvisor.dev/issue/3247), file locking (gvisor.dev/issue/3245), writeback cache (gvisor.dev/issue/3237), mmap support (gvisor.dev/issue/3234), and per-field cache validity (gvisor.dev/issue/3679). Additionally, fuseFD fields are accessed without synchronization (gvisor.dev/issue/4813).
- Files: `pkg/sentry/fsimpl/fuse/read_write.go` (10 TODOs), `pkg/sentry/fsimpl/fuse/inode.go` (4 TODOs), `pkg/sentry/fsimpl/fuse/connection_control.go` (4 TODOs), `pkg/sentry/fsimpl/fuse/connection.go` (3 TODOs), `pkg/sentry/fsimpl/fuse/regular_file.go` (4 TODOs)
- Impact: FUSE-based filesystems (sshfs, rclone, CVMFS, etc.) have degraded performance and missing functionality inside gVisor. The synchronization issue in `connection.go:224` is a potential data race.
- Fix approach: Prioritize async I/O and writeback cache for performance; fix the synchronization issue in `newFUSEConnection` as a correctness bug.

**Unimplemented syscalls and partially supported operations:**
- Issue: Over 20 syscalls return ENOSYS including `vmsplice` (gvisor.dev/issue/138), `userfaultfd` (gvisor.dev/issue/266), `sched_setattr`/`sched_getattr` (gvisor.dev/issue/264), and all `mq_*` message queue operations (gvisor.dev/issue/136). Many supported syscalls have stub implementations (getpriority, setpriority, sched_* family, mlock*).
- Files: `pkg/sentry/syscalls/linux/linux64.go` (20+ TODO annotations)
- Impact: Applications using these syscalls fail or behave incorrectly. This limits compatibility with workloads that use memory-mapped I/O, POSIX message queues, or splice-family operations.
- Fix approach: Prioritize based on workload compatibility needs. `vmsplice` and `userfaultfd` are most commonly encountered.

**RWF_NOWAIT support missing across all filesystems (gvisor.dev/issue/2601):**
- Issue: `RWF_NOWAIT` flag for `preadv2`/`pwritev2` is not supported in any filesystem implementation. 29 occurrences across 10 files all reference the same issue.
- Files: `pkg/sentry/fsimpl/gofer/regular_file.go`, `pkg/sentry/fsimpl/gofer/special_file.go`, `pkg/sentry/fsimpl/tmpfs/regular_file.go`, `pkg/sentry/fsimpl/host/host.go`, `pkg/sentry/socket/netstack/netstack.go`, `pkg/sentry/socket/unix/unix.go`, `pkg/sentry/socket/netlink/socket.go`, `pkg/sentry/socket/hostinet/socket.go`, `pkg/sentry/fsimpl/erofs/regular_file.go`, `pkg/sentry/fsimpl/fuse/regular_file.go`
- Impact: Applications using io_uring or async I/O patterns that rely on `RWF_NOWAIT` cannot avoid blocking.
- Fix approach: Implement per-filesystem: return `EAGAIN` when I/O would block and the flag is set.

**Gofer hard link support missing (gvisor.dev/issue/6739):**
- Issue: Hard linked dentries do not share the same inode. Each hard link creates a separate dentry with its own metadata, leading to inconsistencies when one link modifies the file.
- Files: `pkg/sentry/fsimpl/gofer/lisafs_inode.go:451`, `pkg/sentry/fsimpl/gofer/directfs_inode.go:586`, `pkg/sentry/fsimpl/gofer/filesystem.go:830`
- Impact: Applications relying on hard link semantics (e.g., build systems, package managers) may see stale metadata or inconsistent file content.
- Fix approach: Implement shared inode tracking in the gofer client, mapping multiple dentries to a single inode object when hard links are detected.

**Per-dirent stat in readdir (gvisor.dev/issue/6665):**
- Issue: Directory listing performs a stat call for every directory entry, causing O(n) round trips to the gofer for large directories.
- Files: `runsc/fsgofer/lisafs.go:1143`, `pkg/sentry/fsimpl/gofer/directfs_inode.go:629`
- Impact: Listing directories with many files is significantly slower than native Linux, especially over high-latency gofer connections.
- Fix approach: Batch stat operations or cache directory entry metadata during readdir.

## Known Bugs

**XDP memory corruption (b/240191988):**
- Symptoms: Intermittent memory corruption in XDP UMEM shared memory area, occurring even before TX support was added. 20 TODO/bug references across 5 files.
- Files: `pkg/xdp/umem.go:27`, `pkg/xdp/xdp.go`, `runsc/sandbox/xdp.go`, `pkg/tcpip/link/xdp/endpoint.go`
- Trigger: Occurs occasionally during XDP packet processing. Exact reproduction conditions unknown.
- Workaround: XDP is behind the `EXPERIMENTAL-xdp` flag and not enabled by default. Additional issues include lack of IPv6 support, no device sharing (XDP_SHARED_UMEM), and unsynchronized pinned BPF map updates.

**FUSE connection field access without synchronization (gvisor.dev/issue/4813):**
- Symptoms: Potential data races when fuseFD fields are accessed concurrently, or when fuseFD is reused for mounting another filesystem without checking prior use.
- Files: `pkg/sentry/fsimpl/fuse/connection.go:224-226`
- Trigger: Concurrent FUSE operations or mounting multiple FUSE filesystems using the same device FD.
- Workaround: None documented.

**Host file O_APPEND race condition (gvisor.dev/issue/2983):**
- Symptoms: Memory corruption when multiple processes write to a host-backed file with O_APPEND. The sentry performs a non-atomic fstat + write sequence.
- Files: `pkg/sentry/fsimpl/host/host.go:902-917`
- Trigger: Multiple writers (sentry + external process) to an O_APPEND host file.
- Workaround: Documented as "unavoidable race condition" since the sentry cannot enforce synchronization on the host.

**Gofer dentry cache race condition:**
- Symptoms: The dentry cache may contain dentries with non-zero reference counts due to race conditions, leading to potential use-after-free or incorrect eviction.
- Files: `pkg/sentry/fsimpl/gofer/gofer.go:154-155`
- Trigger: Concurrent dentry lookups and eviction under high filesystem load.
- Workaround: The existing code tolerates this; dentries with non-zero refs are re-validated before use.

**Transport demuxer save/restore broken (gvisor.dev/issue/873):**
- Symptoms: Transport demuxer state is saved but only partially restored, as endpoint maps are not properly reconstructed.
- Files: `pkg/tcpip/stack/transport_demuxer.go:342`
- Trigger: Save/restore (checkpoint) of a container with active network connections.
- Workaround: None; connections may be lost across checkpoint/restore.

## Security Considerations

**Extensive unsafe pointer usage:**
- Risk: 3,699 `unsafe.Pointer`/`unsafe.Slice`/`unsafe.Add` usages across 139 files. Heavy use in KVM bluepill (`pkg/sentry/platform/kvm/bluepill_unsafe.go`), systrap subprocess management (`pkg/sentry/platform/systrap/stub_unsafe.go`), and memory management (`pkg/sentry/vfs/mount_unsafe.go` with 23 usages). Memory safety violations in any of these could compromise sandbox isolation.
- Files: `pkg/sentry/platform/kvm/bluepill_unsafe.go`, `pkg/sentry/platform/kvm/machine_amd64_unsafe.go`, `pkg/sentry/platform/systrap/stub_unsafe.go`, `pkg/sentry/vfs/mount_unsafe.go`, `pkg/sentry/socket/plugin/cgo/socket_unsafe.go` (40 usages)
- Current mitigation: `go:nosplit` annotations (1,799 across 216 files) prevent stack growth in critical paths. The `checklocks` static analyzer validates lock ordering. Code generation (`*_autogen_unsafe.go`) handles marshaling to reduce hand-written unsafe code.
- Recommendations: Increase fuzzing coverage on marshal/unmarshal paths. Consider migrating auto-generated unsafe marshaling code to use `encoding/binary` where performance is not critical.

**nftables package is not thread-safe:**
- Risk: The entire `pkg/tcpip/nftables` package explicitly documents it is "not yet thread-safe" (nftables_types.go:22, :57). It is currently gated behind a runtime flag (`enableNFTables`), but if enabled, concurrent packet evaluation could corrupt rule state.
- Files: `pkg/tcpip/nftables/nftables_types.go:22`, `pkg/tcpip/nftables/nftables_types.go:57`
- Current mitigation: Package is disabled by default; requires explicit `EnableNFTables()` call.
- Recommendations: Must be made thread-safe before production use. The TODO at line 57 explicitly states "Must be done before the package is used in production."

**seccomp filter bypass risks in CGO paths:**
- Risk: Three seccomp rules in the gofer and boot filters for CGO are marked with TODO for removal (`TODO(eperot): remove this syscall seccomp rule`). These are temporary relaxations of the seccomp sandbox to accommodate CGO runtime behavior.
- Files: `runsc/fsgofer/filter/config_cgo.go:43-47`, `runsc/boot/filter/config/config_cgo.go:51-55`
- Current mitigation: Only applies when CGO is enabled. The filter debug tip in `runsc/boot/filter/filter.go:28` and `pkg/seccomp/seccomp.go:57` provide guidance for auditing filter violations.
- Recommendations: Profile CGO syscall usage and tighten the seccomp filters to exact needed syscalls.

**Ambient capability support missing (gvisor.dev/issue/3166):**
- Risk: Ambient capabilities from the OCI spec are silently ignored. Applications that expect ambient capabilities will run with fewer privileges than intended, which could cause silent failures.
- Files: `runsc/specutils/specutils.go:356`, `runsc/cmd/spec.go:65`
- Current mitigation: None; capabilities are simply skipped.
- Recommendations: Implement ambient capability support or clearly document the limitation and error when ambient capabilities are specified.

**Silent socket option failures:**
- Risk: Several socket options are silently accepted but not implemented (SO_RCVLOWAT partial, MCAST_JOIN_GROUP not implemented). Applications may believe multicast or other socket features are working when they are not.
- Files: `pkg/sentry/socket/netstack/netstack.go:2621-2624` (SO_MARK, SO_INCOMING_CPU), `pkg/sentry/socket/netstack/netstack.go:2771` (MCAST_JOIN_GROUP), `pkg/sentry/socket/netstack/netstack.go:2929-2932` (IP_MULTICAST_ALL, IPV6_FREEBIND, IPV6_RECVORIGDSTADDR)
- Current mitigation: FIXME comments acknowledge this should be addressed "once we're confident we can handle them."
- Recommendations: Either implement the options or return ENOPROTOOPT to signal lack of support.

## Performance Bottlenecks

**TCP endpoint complexity (3,368 lines):**
- Problem: The TCP endpoint implementation is the largest non-generated file in the TCP stack, with complex state management, 10 TODO/FIXME markers, and partial checklocks coverage (TODO at line 341: "Checklocks should be used more extensively here").
- Files: `pkg/tcpip/transport/tcp/endpoint.go` (3,368 lines), `pkg/tcpip/transport/tcp/snd.go` (1,905 lines), `pkg/tcpip/transport/tcp/connect.go` (1,533 lines)
- Cause: Monolithic design; single file handles connection setup, data transfer, teardown, socket options, timers, and state management. ECN not supported (gvisor.dev/issue/995).
- Improvement path: Split endpoint.go by concern (options handling, state machine, data path). Extend checklocks annotations for better static verification.

**Netstack socket layer (3,845 lines):**
- Problem: `pkg/sentry/socket/netstack/netstack.go` is the largest non-generated file in the sentry. It handles all socket syscall translation between the sentry and netstack, with 23 TODO/FIXME annotations.
- Files: `pkg/sentry/socket/netstack/netstack.go`
- Cause: All socket option handling, ioctl dispatch, and data transfer for every socket type is in a single file.
- Improvement path: Split by socket operation type (get/setsockopt, read/write, ioctl) into separate files.

**Conntrack fixed-size hash table:**
- Problem: Connection tracking uses a hardcoded 16K bucket table (`numBuckets = 1 << 14`). With many concurrent connections, bucket chains grow linearly, degrading NAT and firewall lookup performance.
- Files: `pkg/tcpip/stack/conntrack.go:41`
- Cause: No dynamic resizing; table size chosen at compile time.
- Improvement path: Implement dynamic resizing or make the bucket count configurable based on expected connection volume.

**erofs dentry tree unbounded memory growth:**
- Problem: The erofs filesystem implementation has no dentry LRU cache, causing unbounded memory growth as the dentry tree grows with every accessed file/directory. This is explicitly documented as a TODO.
- Files: `pkg/sentry/fsimpl/erofs/erofs.go:368-369`
- Cause: Missing eviction policy; all dentries are retained indefinitely.
- Improvement path: Implement a dentry LRU cache similar to `pkg/sentry/fsimpl/gofer/gofer.go` (`dentryCache` struct).

**Neighbor cache static entries unbounded:**
- Problem: Static entries in the neighbor cache have no eviction and grow without bound, as documented in the code.
- Files: `pkg/tcpip/stack/neighbor_cache.go:63`
- Cause: No limit or eviction policy for static neighbor entries.
- Improvement path: Add a maximum static entry count or LRU eviction for static entries.

## Fragile Areas

**KVM platform bluepill mechanism:**
- Files: `pkg/sentry/platform/kvm/bluepill_unsafe.go`, `pkg/sentry/platform/kvm/bluepill_amd64_unsafe.go`, `pkg/sentry/platform/kvm/machine_unsafe.go`, `pkg/sentry/platform/kvm/machine_amd64_unsafe.go`
- Why fragile: The bluepill mechanism uses signal handlers (SIGSEGV, SIGBUS) to trap back into the kernel from guest mode. It relies on precise hardware behavior, Go runtime internals, and atomic state transitions. A `throw("failed to swallow the bluepill")` at `bluepill_amd64_unsafe.go:191` indicates a fatal state if the trap mechanism fails. TLS is not supported on ARM64 (`machine_arm64_unsafe.go:267`).
- Safe modification: Changes require deep understanding of x86/ARM64 ring transitions and Go runtime signal handling. Test on both architectures. The `go:nosplit` annotations are critical and must not be removed.
- Test coverage: Platform tests exist but hardware-specific edge cases (NMI, MCE) are difficult to test.

**Systrap subprocess management:**
- Files: `pkg/sentry/platform/systrap/subprocess.go` (35 `go:nosplit`), `pkg/sentry/platform/systrap/stub_unsafe.go` (14 `go:nosplit`), `pkg/sentry/platform/systrap/subprocess_unsafe.go`, `pkg/sentry/platform/systrap/syscall_thread_unsafe.go`
- Why fragile: The systrap platform creates stub processes and uses shared memory for communication. The code has extensive `go:nosplit` constraints to prevent stack growth during critical sections and uses raw syscalls for process control.
- Safe modification: Any changes to the shared memory protocol (`sysmsg`) must be coordinated between Go code and assembly stubs. Verify on both amd64 and arm64.
- Test coverage: Integration tests cover basic functionality but edge cases around process death, signal delivery, and memory pressure are hard to test.

**Gofer filesystem lock ordering:**
- Files: `pkg/sentry/fsimpl/gofer/gofer.go:18-41` (explicit lock ordering documentation)
- Why fragile: The gofer filesystem has an 11-level deep lock ordering hierarchy (from `regularFileFD.mu` down to `dentry.dataMu`). The comment at `gofer.go:1849` describes a potential deadlock between two filesystems that could wait on each other's rename mutexes. Directory operations require careful lock acquisition across parent-child relationships.
- Safe modification: Always follow the documented lock ordering in `gofer.go:18-41`. Never lock child dentries before parent dentries without holding `filesystem.renameMu`. Use `dentry.cachingMu` only within the documented position.
- Test coverage: Functional tests exist but concurrent rename/unlink/readdir stress tests are limited.

**Save/restore (checkpoint) system:**
- Files: `pkg/sentry/pgalloc/save_restore.go` (10 panics), `runsc/boot/restore.go`, `pkg/sentry/kernel/kernel_restore.go`
- Why fragile: 271 `state:"nosave"` annotations across sentry code mark fields that are not persisted during checkpoint. Each is a potential source of state loss or corruption on restore. Save/restore does not work with hostinet (`runsc/boot/restore.go:417`), TPU devices (`pkg/sentry/devices/tpuproxy/vfio/save_restore.go:21`), or the transport demuxer (`pkg/tcpip/stack/transport_demuxer.go:342`). The netstack stack has fields marked as TODO for S/R support (`pkg/tcpip/stack/stack.go:120,140`).
- Safe modification: When adding new stateful fields, always consider whether they need `+stateify savable` annotation. Fields marked `nosave` must be re-initialized in `afterLoad()` methods.
- Test coverage: Checkpoint/restore is explicitly marked as "experimental" (`runsc/cmd/checkpoint.go:57`, `runsc/cmd/restore.go:65`).

**Overlay filesystem:**
- Files: `pkg/sentry/fsimpl/overlay/filesystem.go` (1,865 lines), `pkg/sentry/fsimpl/overlay/overlay.go`
- Why fragile: Only tmpfs supports whiteouts (`overlay.go:224`, TODO b/286942303). Lock ordering between overlayfs dentries must be carefully maintained (`overlay.go:122`). Copy-up semantics add complexity.
- Safe modification: Test with various lower/upper filesystem combinations. Ensure whiteout behavior matches Linux.
- Test coverage: Whiteout handling for non-tmpfs upper filesystems is not supported.

## Scaling Limits

**Connection tracking table:**
- Current capacity: 16,384 buckets (hardcoded)
- Limit: Performance degrades when bucket chains grow long under high connection counts
- Scaling path: Make `numBuckets` configurable or implement dynamic resizing in `pkg/tcpip/stack/conntrack.go`

**Gofer dentry cache:**
- Current capacity: Configurable via `SetDentryCacheSize()`, defaults to system-dependent value
- Limit: All dentries with zero references are cached; cache eviction is LRU but cache size is global across all gofer mounts
- Scaling path: Per-filesystem cache limits or adaptive caching based on memory pressure

**FUSE max active requests:**
- Current capacity: Configurable via `maxActiveRequests` in filesystem options
- Limit: When the full queue channel is full, FUSE requests block
- Scaling path: Implement async I/O support (gvisor.dev/issue/3247) to reduce queue pressure

## Dependencies at Risk

**Go 1.24.1 runtime internals dependency:**
- Risk: The codebase uses `go:linkname` to access Go runtime internals (`pkg/gohacks/linkname_go113_unsafe.go`, `pkg/sync/runtime_unsafe.go`). These are not stable APIs and break across Go versions.
- Impact: Go version upgrades require verifying all linkname targets still exist and have compatible signatures. Files `pkg/gohacks/string_go113_unsafe.go` and `pkg/gohacks/slice_go113_unsafe.go` are conditionally compiled with a TODO to remove once Go 1.19 is no longer supported (already past).
- Migration plan: Replace linkname usage with stable APIs when available. Remove the Go 1.13/1.19 compatibility files.

**containerd v1 shim:**
- Risk: `pkg/shim/v1/` contains the containerd v1 shim implementation with deprecated protobuf patterns (`XXX_` fields in `runtimeoptions_cri.go`) and multiple TODOs for missing functionality (cgroup/OOM notifications on restore, `shouldKillAll` logic, subpath support).
- Impact: containerd v1 is legacy; the v1 shim may not receive ongoing maintenance.
- Migration plan: Focus development on the v2 shim at `shim/` (top-level).

**Nvidia driver ABI versioning:**
- Risk: The nvproxy device passthrough requires maintaining exact ABI compatibility with specific Nvidia driver versions. Each version has unique ioctl handlers, control commands, and struct layouts.
- Impact: Every new Nvidia driver release requires adding a new ABI definition. The system tracks driver checksums for verification.
- Migration plan: Continue the current version-per-ABI pattern. Consider automated ABI extraction tooling.

## Missing Critical Features

**Scheduler implementation:**
- Problem: gVisor does not implement a real scheduler. `sched_setattr`, `sched_getattr` return ENOSYS (gvisor.dev/issue/264). Priority syscalls (`getpriority`, `setpriority`) are stubs. `sched_setaffinity`/`sched_getaffinity` are stubs.
- Blocks: Real-time applications, workloads with CPU affinity requirements, priority-based scheduling.

**IPv6 in XDP:**
- Problem: XDP implementation does not support IPv6 (TODO b/240191988).
- Blocks: IPv6-only or dual-stack environments using XDP acceleration.

**Mount propagation MS_UNBINDABLE:**
- Problem: `MS_UNBINDABLE` mount propagation type is not supported (TODO b/305893463).
- Blocks: Complex container mount namespace configurations that rely on unbindable mounts.
- Files: `pkg/sentry/vfs/mount.go:1590`

**nftables jump/goto verdicts:**
- Problem: Jump and goto verdicts in nftables rules are not implemented (TODO b/434244017).
- Blocks: Complex firewall rulesets that use chain jumping for modular rule organization.
- Files: `pkg/tcpip/nftables/nft_immediate.go:80`

## Test Coverage Gaps

**nftables package:**
- What's not tested: Thread safety (package is explicitly not thread-safe), jump/goto verdicts, transaction atomicity, chain deletion with dependent rules
- Files: `pkg/tcpip/nftables/`
- Risk: Enabling nftables in production without thread safety could cause data races in the packet processing path
- Priority: High (blocking production readiness)

**FUSE filesystem concurrent operations:**
- What's not tested: Concurrent mount/unmount with the same device FD (gvisor.dev/issue/4813), async I/O paths (not implemented), file locking
- Files: `pkg/sentry/fsimpl/fuse/`
- Risk: Data races in connection setup; missing I/O functionality causes application failures
- Priority: Medium

**Platform-specific edge cases:**
- What's not tested: ARM64 TLS support (not implemented, gvisor.dev/issue/1238), 5-level page table support (gvisor.dev/issue/7349), AMX instruction set support (gvisor.dev/issues/9896)
- Files: `pkg/sentry/platform/kvm/machine_arm64_unsafe.go:267`, `pkg/ring0/lib_amd64.go:103`, `pkg/cpuid/cpuid_amd64.go:430`
- Risk: Crashes or incorrect behavior on hardware with these features
- Priority: Medium (ARM64 TLS), Low (5-level paging, AMX)

**Checkpoint/restore with network state:**
- What's not tested: Restoring active TCP connections (transport demuxer state not properly restored), save/restore with hostinet (explicitly unsupported)
- Files: `pkg/tcpip/stack/transport_demuxer.go:342`, `runsc/boot/restore.go:417`, `pkg/tcpip/stack/stack.go:120,140`
- Risk: Network connections silently lost or corrupted after restore
- Priority: High (checkpoint/restore is an advertised feature)

**Socket option compatibility:**
- What's not tested: Silently accepted but unimplemented socket options (SO_MARK, MCAST_JOIN_GROUP, IP_MULTICAST_ALL)
- Files: `pkg/sentry/socket/netstack/netstack.go:2621-2632`, `pkg/sentry/socket/netstack/netstack.go:2771`, `pkg/sentry/socket/netstack/netstack.go:2929-2935`
- Risk: Applications assume features are working when they are silently ignored
- Priority: Medium

---

*Concerns audit: 2026-03-08*
