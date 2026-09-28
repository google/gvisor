# Testing the Landlock ABI v1 implementation

This document records how the Landlock ABI v1 implementation was tested, with
the exact commands, so that the runs can be repeated, and what the results were
at the head of the change series, so that a future run can be compared against
a known state.

Two suites were used:

1.  gVisor's own conformance suite, `test/syscalls/linux/landlock_v1*.cc`,
    which runs natively on Linux (the correctness oracle) and under runsc in
    the platform and filesystem variants the syscall test harness generates.
2.  The kernel's own Landlock selftests, `tools/testing/selftests/landlock`,
    built from the kernel sources and run unmodified (with one documented
    harness adaptation) both natively and under runsc. Two vintages were used:
    Linux v5.18, the last release where ABI 1 was current, and Linux v6.1,
    where ABI 2 was current. Later vintages pin the reported ABI version and
    exercise access rights that do not exist in ABI 1, so they would say less.

---

## 1. Environment

| | |
|---|---|
| Machine | GCE `n2-standard-16`, Ubuntu 24.04, 200 GB pd-ssd |
| Host kernel | `7.0.0-1011-gcp`, native Landlock ABI 8 |
| gVisor | the change series rebased onto upstream master `e2463e8b8`, `runsc --platform=systrap` |
| Bazel | 8.3.1 via bazelisk |

The host kernel is recent enough that a native run of any test below is a run
against Linux, which is what makes the native columns an oracle.

Packages beyond the stock image that the build needs:

```
apt-get install -y git build-essential curl python3 clang libcap-dev \
    libbpf-dev libc6-dev-i386 \
    gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross
```

Two of these are easy to get wrong. `libbpf-dev` and `libc6-dev-i386` are
needed by the eBPF genrules that runsc links (`bpf/bpf_helpers.h` and
`gnu/stubs-32.h` respectively); without them every syscall test target fails
to build. Do not use `gcc-multilib` to get the 32-bit headers: on Ubuntu it
removes the aarch64 cross toolchain that other genrules need.

---

## 2. gVisor's conformance suite

### Running it

The two test binaries, `landlock_v1_test` (58 gVisor-originated tests) and
`landlock_v1_selftests_test` (100 tests ported from the kernel selftests), are
wrapped by `syscall_test` rules that produce one target per variant. The set
run here excludes the KVM and ptrace platforms, which the VM cannot host:

```
cd gvisor
bazel query 'tests(//test/syscalls:all)' | grep -E 'landlock_v1' | grep -vE 'kvm|ptrace|slimvm' > targets.txt
bazel test --test_output=errors --keep_going --local_test_jobs=4 \
    $(cat targets.txt) \
    //pkg/sentry/vfs:vfs_test \
    //pkg/sentry/fsimpl/overlay:overlay_test \
    //pkg/sentry/fsimpl/gofer:gofer_test
```

That is 20 syscall test targets: for each binary, `native`, and
`runsc_systrap_{directfs,overlay,shared}` each in plain, `_save`, and
`_save_resume` form. The three Go tests are the unit tests added by the change.

### Results

All 23 targets pass. Per binary and variant:

| Binary | Variant | Passed | Skipped |
|---|---|---|---|
| landlock_v1_test | native | 51 | 7 |
| landlock_v1_test | runsc directfs / overlay / shared (plain, save, save_resume) | 58 | 0 |
| landlock_v1_selftests_test | native | 100 | 0 |
| landlock_v1_selftests_test | runsc directfs / overlay / shared (plain, save, save_resume) | 100 | 0 |
| vfs_test, overlay_test, gofer_test | | pass | |

The seven native skips are all environmental and each test names its reason:
`HostFdsAreInternal` is gVisor-only by construction; the other six
(`DomainSurvivesSetuid`, `LinkOfUnsafeSourceReportsEpermNotEacces`,
`UnlinkInStickyDirReportsEaccesNotEperm`,
`MknodDeviceWithoutCapabilityIsEaccesUnderLandlock`, and the two
read-only-procfs errno tests) need a control case that the Bazel sandbox does
not provide, such as a setuid transition or a mountable procfs.

One infrastructure flake was seen once in `landlock_v1_test_runsc_systrap_shared_save`:
the restored sandbox failed to load its checkpoint (`failed to load kernel:
header error: EOF`) before any test ran. Three immediate reruns passed.

---

## 3. The kernel's Landlock selftests

### Fetching and building

The selftests are three C programs plus a `true` helper, built against the
shared kselftest harness. They are fetched straight from the kernel tree at
the two tags:

```
for v in v6.1 v5.18; do
  d=kself/$v; mkdir -p $d/landlock
  for f in base_test.c fs_test.c ptrace_test.c common.h config Makefile true.c; do
    curl -sSfL "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/tools/testing/selftests/landlock/$f?h=$v" -o $d/landlock/$f
  done
  for f in kselftest_harness.h kselftest.h; do
    curl -sSfL "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/tools/testing/selftests/$f?h=$v" -o $d/$f
  done
done
```

They are built statically so that the same binary runs natively and inside
the sandbox with no dependency on the sandbox's root filesystem:

```
cd kself/$v/landlock
for t in base_test fs_test ptrace_test; do
  gcc -Wall -O2 -static -pthread -o $t $t.c -lcap
done
gcc -static -o true true.c
```

### Environment the selftests assume

Three things must be true or every test fails for reasons unrelated to
Landlock:

1.  **The test tree must be owned by root.** The fixtures drop every
    capability except a handful, then `mkdir tmp` in the current directory;
    a tree owned by another user is `EACCES` even for uid 0 once
    `CAP_DAC_OVERRIDE` is gone. `chown -R root:root kself`.
2.  **Yama must be off.** `ptrace_test.c` says so in a comment; Ubuntu ships
    `kernel.yama.ptrace_scope=1`. Natively:
    `sysctl -w kernel.yama.ptrace_scope=0`. Inside the sandbox the test is
    run as `sh -c 'echo 0 > /proc/sys/kernel/yama/ptrace_scope; exec ./ptrace_test'`.
3.  **A leaked `tmp` mount breaks every later test.** If a run is interrupted
    with the fixture's tmpfs still mounted at `<dir>/tmp`, unmount it with
    `umount -l` before the next run.

### One harness adaptation for gVisor

The `layout2_overlay` fixture mounts an overlay with `lowerdir`, `upperdir`
and `workdir` given relative to the current directory. Linux accepts that;
gVisor's overlay mount requires absolute paths and fails the mount with
`EINVAL` ("workdir must be absolute"). This is a pre-existing limitation of
gVisor's overlay mount option parsing, unrelated to Landlock. To get the two
overlay tests to run, `fs_test.c` was patched to prefix only the mount option
string with the absolute path of the test directory:

```
d=$PWD   # the directory holding fs_test
sed -i "0,/#define TMP_DIR/s||#define ABS_CWD \"$d/\"\n#define TMP_DIR|" fs_test.c
sed -i -e 's|"lowerdir=" LOWER_DATA|"lowerdir=" ABS_CWD LOWER_DATA|' \
       -e 's|upperdir=" UPPER_DATA|upperdir=" ABS_CWD UPPER_DATA|' \
       -e 's|workdir=" UPPER_WORK|workdir=" ABS_CWD UPPER_WORK|' fs_test.c
```

`TMP_DIR` itself must stay relative: the fixture's directory-creation helper
walks the path component by component and cannot create an absolute one from
a process that has dropped its capabilities. Every path the tests open or
rename is unchanged by this patch; only the string handed to `mount(2)` is.

### Running

Natively, as root, from the directory holding the binaries:

```
cd kself/$v/landlock && ./base_test; ./ptrace_test; ./fs_test
```

Under runsc, using `runsc do`, which starts a sandbox with the host root
mounted read-only under a memory overlay and runs one command in it. The
sandbox has `CAP_SYS_ADMIN`, so the fixtures can unshare a mount namespace
and mount their tmpfs and overlays inside it. runsc must come from the release
layout, `bazel build //:release`, because it ships the sentry as a sidecar
binary (`gvisor-bin/gvisor_sentry`) that it expects next to itself and refuses
to start without under the default sidecar policy; the bare `//runsc` target
lacks it:

```
(cd gvisor && bazel build //:release)
RUNSC=gvisor/bazel-bin/release/runsc
cd kself/$v/landlock
$RUNSC --network=none --platform=systrap do --quiet --cwd=$PWD ./base_test
$RUNSC --network=none --platform=systrap do --quiet --cwd=$PWD \
    /bin/sh -c 'echo 0 > /proc/sys/kernel/yama/ptrace_scope; exec ./ptrace_test'
$RUNSC --network=none --platform=systrap do --quiet --cwd=$PWD ./fs_test
```

The harness prints TAP; `# Totals:` at the end has the counts. Because the
forked test bodies write diagnostics unsynchronized with the parent's TAP
lines, the output interleaves; the per-test diagnostics are most reliably
recovered with `grep -o 'fs_test.c:[0-9]*:[A-Za-z0-9_]*:[^#]*'`.

### Results

| Suite | Tests | Native Linux 7.0 | gVisor |
|---|---|---|---|
| v5.18 base_test | 8 | 6 | 7 |
| v5.18 ptrace_test | 8 | 8 | 8 |
| v5.18 fs_test | 46 | 44 | 44 |
| v6.1 base_test | 7 | 5 | 5 |
| v6.1 ptrace_test | 8 | 8 | 8 |
| v6.1 fs_test | 63 | 62 | 47 |

Every failure, on either side, is accounted for below. For v5.18, gVisor and
native Linux fail exactly the same two tests. None of the gVisor failures is a
Landlock behavior that differs from what a Linux kernel implementing exactly
ABI 1 would do; where a test's expectation has moved with the ABI, the native
column fails it too.

**Failures that reflect ABI drift, on both sides.**

*   `base_test abi_version` (both vintages) pins the version to the one the
    test was written for. Native reports 8, gVisor 1.
*   `base_test inval_create_ruleset_flags` (v5.18) and
    `create_ruleset_checks_ordering` (v6.1) assert that flag value 2 is
    invalid. Since Linux 6.15 it is `LANDLOCK_CREATE_RULESET_ERRATA`; native
    returns its errata mask (7) and gVisor returns its own (4, erratum 3).
*   `layout1.max_layers` (v5.18) stacks 64 layers. The limit became 16 in
    Linux 5.19; native and gVisor both refuse the 17th with `E2BIG`.
*   `layout1.unknown_access_rights` (v6.1) asserts that bit 14 is invalid.
    Native accepts it (`TRUNCATE`, ABI 3); gVisor rejects it, correctly for
    ABI 1, so this one passes under gVisor and fails natively.
*   `layout1.rename_file` (v5.18, line 1654) expects `EXDEV` for a
    cross-directory rename out of a directory that lacks `REMOVE_FILE`.
    Linux 5.19 changed this to prioritize `EACCES`, which is what native and
    gVisor both return.

**Failures under gVisor only, all expected for an ABI 1 implementation.**

*   All sixteen remaining v6.1 failures create a ruleset that handles
    `LANDLOCK_ACCESS_FS_REFER` (ABI 2) and stop at `landlock_create_ruleset`
    returning `EINVAL`: `file_and_dir_access_rights`, `reparent_refer`,
    `reparent_link`, `reparent_rename`, `reparent_remove`,
    `reparent_dom_superset`, `reparent_cross_mount`,
    `reparent_exdev_layers_{rename1,rename2,exchange1,exchange2,exchange3}`,
    and `refer_denied_by_default{1,3}`. `refer_denied_by_default{2,4}` fail
    the same way at their second layer. There is no other gVisor-only failure.

**What the runs found and fixed.** Earlier runs of these same suites against
earlier heads of the series caught three divergences, since fixed in place:
`layout1.inval` (an `O_PATH` descriptor as the ruleset fd must be `EBADF`),
`layout2_overlay.same_content_different_file` (a rule on a merged directory
must not reach the layer directory it is built from, nor the reverse; gVisor's
overlay identities aliased the two), and the `rename_file`/`rename_dir`
`EXDEV` assertions (a filesystem's `EINVAL` for an unimplemented rename flag
preceded the hook). Fixing the second exposed a fourth: the overlay performed
its upper-layer rename under the caller's credentials rather than the mount's,
so the caller's domain was checked again against upper-layer inodes. All four
now pass; the counts above are from the fixed series after its rebase onto a
master that implements `RENAME_EXCHANGE` in tmpfs, gofer and overlay, which is
what lets `rename_file` and `rename_dir` run to completion.

---

## 4. Not covered here

*   The KVM and ptrace runsc platforms (the VM cannot host them). The suites
    exercise nothing platform-specific.
*   Kernel selftests newer than v6.1. Their `fs_test.c` requires ABI 3 and
    later rights from the first fixture on, so under ABI 1 almost every test
    stops at ruleset creation.
*   `RENAME_WHITEOUT`, which no gVisor filesystem implements, and
    `RENAME_EXCHANGE` on kernfs, which does not implement it either. Both are
    independent of Landlock; the Landlock check runs before either rejection.

---

## 5. Re-run for the overlay identity rework

The overlay's `PinInodeIdentity` was reworked to hold a reference on the
overlay dentry instead of recording copy-up origins, and its identities to
re-scope the layer file's identity through `MakeLayeredInodeIdentity` instead
of translating it through a per-overlay table. The full matrix above was re-run
on 2026-09-21 on a fresh GCE `n2-standard-16` (Ubuntu 24.04, host kernel
`7.0.0-1011-gcp`, `runsc --platform=systrap`) at the head of the reworked
series. The results are identical to those recorded above: all 23 Bazel targets
pass with the same per-variant pass and skip counts, and every kernel selftest
total, native and under runsc, for both v5.18 and v6.1, is unchanged, with the
same failing tests.

---

## 6. Re-run for Landlock objects

Rules were rekeyed from inode identities to refcounted `LandlockObject`s. On
2026-09-23 the change and the commit before it were run side by side on two GCE
`n2-standard-16` VMs, set up as in section 5. The Bazel run was wider than the
23 targets above. It covered every `landlock_v1`–`landlock_v6` variant
including `_save_resume`, and the `access`, `chdir`, `chroot`, `creat`, `dev`,
`fchdir`, `inotify`, `link`, `mkdir`, `mount`, `open_create`, `pivot_root`,
`rename`, `stat`, `statfs`, `symlink`, `truncate`, `unlink` and `xattr` suites,
each in its native and `runsc_systrap_{directfs,overlay,shared}` variants plus
the `_save` variants where they exist. It also covered the `vfs`, `overlay`,
`gofer`, `tmpfs`, `kernfs`, `fuse`, `kernel` and `syscalls/linux` unit tests.
That is 207 targets, run with `--nocache_test_results`.

Both commits gave the same results. For each target the test, failure and skip
counts match, and so does every kernel selftest total and failing test (v5.18
and v6.1, native and under runsc). All Landlock targets and all Landlock unit
tests pass. Fourteen targets fail on both commits, and none of the failures
involve Landlock:

*   `syscalls/linux:linux_test`: `TestSeccheckMax` has no seccheck point for
    syscall 446, `landlock_restrict_self`.
*   `link_test` (`native`, `directfs`, `shared` and their `_save` variants):
    `LinkTest.PermissionDenied` fails when run as root on this host.
*   The native `landlock_v6`, `mount`, `rename` and `xattr` tests, and
    `xattr_test_runsc_systrap_overlay{,_save}`. These are host-kernel
    differences.

---

## 7. Re-run for merged domains and bounded objects

The domain now keeps one merged rule map, the overlay and FUSE slot tables are
read without locks, and an operation that skips the Landlock check fails
closed. On 2026-09-28 the matrix of section 3 was re-run at the head of the
series on the VM from section 5, with the `fuse` and `kernel` unit tests added:
25 targets.

All 25 targets pass. `landlock_v1_selftests_test` passes 100 of 100 in every
variant. `landlock_v1_test` runs 58 tests; 7 skip natively, as in section 3.
Every kernel selftest total and failing test (v5.18 and v6.1, native and under
runsc) matches sections 5 and 6.

That run found that `UnlinkInStickyDirReportsEaccesNotEperm` and
`LinkOfUnsafeSourceReportsEpermNotEacces` skipped in every runsc variant: as
uid 65534 their control could not search `TEST_TMPDIR`'s ancestors, so it got
EACCES instead of the EPERM it arranges. Both now create their files under
`/tmp`, as `DomainSurvivesSetuid` does, and pass under runsc; the table above
reflects that.
