// Copyright 2019 The gVisor Authors.
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

package nogo

import (
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/asmdecl"
	"golang.org/x/tools/go/analysis/passes/assign"
	"golang.org/x/tools/go/analysis/passes/atomic"
	"golang.org/x/tools/go/analysis/passes/bools"
	"golang.org/x/tools/go/analysis/passes/buildtag"
	"golang.org/x/tools/go/analysis/passes/cgocall"
	"golang.org/x/tools/go/analysis/passes/composite"
	"golang.org/x/tools/go/analysis/passes/copylock"
	"golang.org/x/tools/go/analysis/passes/errorsas"
	"golang.org/x/tools/go/analysis/passes/httpresponse"
	"golang.org/x/tools/go/analysis/passes/loopclosure"
	"golang.org/x/tools/go/analysis/passes/lostcancel"
	"golang.org/x/tools/go/analysis/passes/nilfunc"
	"golang.org/x/tools/go/analysis/passes/nilness"
	"golang.org/x/tools/go/analysis/passes/printf"
	"golang.org/x/tools/go/analysis/passes/shadow"
	"golang.org/x/tools/go/analysis/passes/shift"
	"golang.org/x/tools/go/analysis/passes/stdmethods"
	"golang.org/x/tools/go/analysis/passes/stringintconv"
	"golang.org/x/tools/go/analysis/passes/structtag"
	"golang.org/x/tools/go/analysis/passes/tests"
	"golang.org/x/tools/go/analysis/passes/unmarshal"
	"golang.org/x/tools/go/analysis/passes/unreachable"
	"golang.org/x/tools/go/analysis/passes/unsafeptr"
	"golang.org/x/tools/go/analysis/passes/unusedresult"
	"honnef.co/go/tools/staticcheck"
	"honnef.co/go/tools/stylecheck"

	"gvisor.dev/gvisor/tools/checkescape"
	"gvisor.dev/gvisor/tools/checkunsafe"
)

var analyzerConfig = map[*analysis.Analyzer]matcher{
	// Standard analyzers.
	asmdecl.Analyzer: alwaysMatches(),
	assign.Analyzer: externalExcluded(
		".*gazelle/walk/walk.go", // False positive.
	),
	atomic.Analyzer:   alwaysMatches(),
	bools.Analyzer:    alwaysMatches(),
	buildtag.Analyzer: alwaysMatches(),
	cgocall.Analyzer:  alwaysMatches(),
	composite.Analyzer: and(
		disableMatches(), // Disabled for now.
		resultExcluded{
			"Object_",
			"Range{",
		},
	),
	copylock.Analyzer:     internalMatches(), // Common external issues (e.g. protos).
	errorsas.Analyzer:     alwaysMatches(),
	httpresponse.Analyzer: alwaysMatches(),
	loopclosure.Analyzer:  alwaysMatches(),
	lostcancel.Analyzer:   internalMatches(), // Common external issues.
	nilfunc.Analyzer:      alwaysMatches(),
	nilness.Analyzer: and(
		internalMatches(), // Common "tautological checks".
		internalExcluded(
			"pkg/sentry/platform/kvm/kvm_test.go", // Intentional.
			"tools/bigquery/bigquery.go",          // False positive.
		),
	),
	printf.Analyzer:     alwaysMatches(),
	shift.Analyzer:      alwaysMatches(),
	stdmethods.Analyzer: internalMatches(), // Common external issues (e.g. methods named "Write").
	stringintconv.Analyzer: and(
		internalExcluded(),
		externalExcluded(
			".*protobuf/.*.go",              // Bad conversions.
			".*flate/huffman_bit_writer.go", // Bad conversion.

			// Runtime internal violations.
			".*reflect/value.go",
			".*encoding/xml/xml.go",
			".*runtime/pprof/internal/profile/proto.go",
			".*fmt/scan.go",
			".*go/types/conversions.go",
			".*golang.org/x/net/dns/dnsmessage/message.go",
		),
	),
	shadow.Analyzer:      disableMatches(),  // Disabled for now.
	structtag.Analyzer:   internalMatches(), // External not subject to rules.
	tests.Analyzer:       alwaysMatches(),
	unmarshal.Analyzer:   alwaysMatches(),
	unreachable.Analyzer: internalMatches(),
	unsafeptr.Analyzer: and(
		internalMatches(),
		internalExcluded(
			".*_test.go",                                               // Exclude tests.
			"pkg/flipcall/.*_unsafe.go",                                // Special case.
			"pkg/gohacks/gohacks_unsafe.go",                            // Special case.
			"pkg/sentry/fs/fsutil/host_file_mapper_unsafe.go",          // Special case.
			"pkg/sentry/platform/kvm/bluepill_unsafe.go",               // Special case.
			"pkg/sentry/platform/kvm/machine_unsafe.go",                // Special case.
			"pkg/sentry/platform/ring0/pagetables/allocator_unsafe.go", // Special case.
			"pkg/sentry/platform/safecopy/safecopy_unsafe.go",          // Special case.
			"pkg/sentry/vfs/mount_unsafe.go",                           // Special case.
			"pkg/sentry/platform/systrap/stub_unsafe.go",               // Special case.
			"pkg/sentry/platform/systrap/switchto_google_unsafe.go",    // Special case.
			"pkg/sentry/platform/systrap/sysmsg_thread_unsafe.go",      // Special case.
		),
	),
	unusedresult.Analyzer: alwaysMatches(),

	// Internal analyzers: external packages not subject.
	checkescape.Analyzer: internalMatches(),
	checkunsafe.Analyzer: internalMatches(),
}

func init() {
	staticMatcher := and(
		// Only match internal, non-generated files.
		internalMatches(),
		generatedExcluded(),

		// We use ALL_CAPS for system definitions,
		// which are common enough in the code base
		// that we shouldn't annotate exceptions.
		//
		// Same story for underscores.
		resultExcluded([]string{
			"should not use ALL_CAPS in Go names",
			"should not use underscores in Go names",
		}),

		// Exclude existing matches.
		internalExcluded(
			"pkg/abi/linux/fuse.go:22",
			"pkg/abi/linux/fuse.go:25",
			"pkg/abi/linux/socket.go:113",
			"pkg/abi/linux/tty.go:73",
			"pkg/bpf/decoder.go:112",
			"pkg/cpuid/cpuid_x86.go:675",
			"pkg/eventchannel/event.go:193",
			"pkg/eventchannel/event.go:27",
			"pkg/eventchannel/event_test.go:22",
			"pkg/eventchannel/rate.go:19",
			"pkg/gohacks/gohacks_unsafe.go:33",
			"pkg/log/json.go:30",
			"pkg/log/log.go:359",
			"pkg/merkletree/merkletree.go:230",
			"pkg/merkletree/merkletree.go:243",
			"pkg/merkletree/merkletree.go:249",
			"pkg/merkletree/merkletree.go:266",
			"pkg/merkletree/merkletree.go:355",
			"pkg/merkletree/merkletree.go:369",
			"pkg/metric/metric_test.go:20",
			"pkg/p9/p9test/client_test.go:687",
			"pkg/p9/transport_test.go:196",
			"pkg/pool/pool.go:15",
			"pkg/refs/refcounter.go:510",
			"pkg/refs/refcounter_test.go:169",
			"pkg/safemem/block_unsafe.go:89",
			"pkg/seccomp/seccomp.go:82",
			"pkg/segment/test/set_functions.go:15",
			"pkg/sentry/arch/signal.go:166",
			"pkg/sentry/arch/signal.go:171",
			"pkg/sentry/control/pprof.go:196",
			"pkg/sentry/devices/memdev/full.go:58",
			"pkg/sentry/devices/memdev/null.go:59",
			"pkg/sentry/devices/memdev/random.go:68",
			"pkg/sentry/devices/memdev/zero.go:86",
			"pkg/sentry/fdimport/fdimport.go:15",
			"pkg/sentry/fs/attr.go:257",
			"pkg/sentry/fsbridge/fs.go:116",
			"pkg/sentry/fsbridge/vfs.go:124",
			"pkg/sentry/fsbridge/vfs.go:70",
			"pkg/sentry/fs/copy_up.go:365",
			"pkg/sentry/fs/copy_up_test.go:65",
			"pkg/sentry/fs/dev/net_tun.go:161",
			"pkg/sentry/fs/dev/net_tun.go:63",
			"pkg/sentry/fs/dev/null.go:97",
			"pkg/sentry/fs/dirent_cache.go:64",
			"pkg/sentry/fs/file_overlay.go:327",
			"pkg/sentry/fs/file_overlay.go:524",
			"pkg/sentry/fs/filetest/filetest.go:55",
			"pkg/sentry/fs/filetest/filetest.go:60",
			"pkg/sentry/fs/fs.go:77",
			"pkg/sentry/fs/fsutil/file.go:290",
			"pkg/sentry/fs/fsutil/file.go:346",
			"pkg/sentry/fs/fsutil/host_file_mapper.go:105",
			"pkg/sentry/fs/fsutil/inode_cached.go:676",
			"pkg/sentry/fs/fsutil/inode_cached.go:772",
			"pkg/sentry/fs/gofer/attr.go:120",
			"pkg/sentry/fs/gofer/fifo.go:33",
			"pkg/sentry/fs/gofer/inode.go:410",
			"pkg/sentry/fsimpl/devpts/devpts.go:110",
			"pkg/sentry/fsimpl/devpts/devpts.go:246",
			"pkg/sentry/fsimpl/devpts/devpts.go:50",
			"pkg/sentry/fsimpl/devpts/master.go:110",
			"pkg/sentry/fsimpl/devpts/master.go:55",
			"pkg/sentry/fsimpl/devpts/replica.go:113",
			"pkg/sentry/fsimpl/devpts/replica.go:57",
			"pkg/sentry/fsimpl/devtmpfs/devtmpfs.go:54",
			"pkg/sentry/fsimpl/ext/disklayout/superblock_64.go:97",
			"pkg/sentry/fsimpl/ext/disklayout/superblock_old.go:92",
			"pkg/sentry/fsimpl/ext/disklayout/block_group_32.go:44",
			"pkg/sentry/fsimpl/ext/disklayout/inode_new.go:91",
			"pkg/sentry/fsimpl/ext/disklayout/inode_old.go:93",
			"pkg/sentry/fsimpl/ext/disklayout/superblock_32.go:66",
			"pkg/sentry/fsimpl/ext/disklayout/block_group_64.go:53",
			"pkg/sentry/fsimpl/eventfd/eventfd.go:268",
			"pkg/sentry/fsimpl/ext/directory.go:163",
			"pkg/sentry/fsimpl/ext/directory.go:164",
			"pkg/sentry/fsimpl/ext/extent_file.go:142",
			"pkg/sentry/fsimpl/ext/extent_file.go:143",
			"pkg/sentry/fsimpl/ext/ext.go:105",
			"pkg/sentry/fsimpl/ext/filesystem.go:287",
			"pkg/sentry/fsimpl/ext/regular_file.go:153",
			"pkg/sentry/fsimpl/ext/symlink.go:113",
			"pkg/sentry/fsimpl/fuse/connection_control.go:194",
			"pkg/sentry/fsimpl/fuse/dev.go:387",
			"pkg/sentry/fsimpl/fuse/dev_test.go:318",
			"pkg/sentry/fsimpl/fuse/fusefs.go:102",
			"pkg/sentry/fsimpl/fuse/read_write.go:129",
			"pkg/sentry/fsimpl/fuse/request_response.go:71",
			"pkg/sentry/fsimpl/gofer/directory.go:135",
			"pkg/sentry/fsimpl/gofer/filesystem.go:679",
			"pkg/sentry/fsimpl/gofer/gofer.go:1694",
			"pkg/sentry/fsimpl/gofer/gofer.go:276",
			"pkg/sentry/fsimpl/gofer/regular_file.go:81",
			"pkg/sentry/fsimpl/gofer/special_file.go:141",
			"pkg/sentry/fsimpl/host/host.go:184",
			"pkg/sentry/fsimpl/kernfs/dynamic_bytes_file.go:50",
			"pkg/sentry/fsimpl/kernfs/dynamic_bytes_file.go:90",
			"pkg/sentry/fsimpl/kernfs/fd_impl_util.go:273",
			"pkg/sentry/fsimpl/kernfs/filesystem.go:247",
			"pkg/sentry/fsimpl/kernfs/inode_impl_util.go:320",
			"pkg/sentry/fsimpl/kernfs/inode_impl_util.go:497",
			"pkg/sentry/fsimpl/kernfs/synthetic_directory.go:52",
			"pkg/sentry/fsimpl/overlay/directory.go:119",
			"pkg/sentry/fsimpl/overlay/filesystem.go:527",
			"pkg/sentry/fsimpl/overlay/non_directory.go:152",
			"pkg/sentry/fsimpl/overlay/overlay.go:115",
			"pkg/sentry/fsimpl/overlay/overlay.go:719",
			"pkg/sentry/fsimpl/pipefs/pipefs.go:74",
			"pkg/sentry/fsimpl/proc/filesystem.go:52",
			"pkg/sentry/fsimpl/proc/filesystem.go:81",
			"pkg/sentry/fsimpl/proc/subtasks.go:126",
			"pkg/sentry/fsimpl/proc/subtasks.go:189",
			"pkg/sentry/fsimpl/proc/task_fds.go:168",
			"pkg/sentry/fsimpl/proc/task_fds.go:228",
			"pkg/sentry/fsimpl/proc/task_fds.go:301",
			"pkg/sentry/fsimpl/proc/task_fds.go:318",
			"pkg/sentry/fsimpl/proc/task_fds.go:67",
			"pkg/sentry/fsimpl/proc/task_files.go:112",
			"pkg/sentry/fsimpl/proc/task_files.go:158",
			"pkg/sentry/fsimpl/proc/task_files.go:259",
			"pkg/sentry/fsimpl/proc/task_files.go:285",
			"pkg/sentry/fsimpl/proc/task_files.go:305",
			"pkg/sentry/fsimpl/proc/task_files.go:384",
			"pkg/sentry/fsimpl/proc/task_files.go:403",
			"pkg/sentry/fsimpl/proc/task_files.go:428",
			"pkg/sentry/fsimpl/proc/task_files.go:691",
			"pkg/sentry/fsimpl/proc/task_files.go:770",
			"pkg/sentry/fsimpl/proc/task_files.go:797",
			"pkg/sentry/fsimpl/proc/task_files.go:828",
			"pkg/sentry/fsimpl/proc/task_files.go:879",
			"pkg/sentry/fsimpl/proc/task_files.go:910",
			"pkg/sentry/fsimpl/proc/task_files.go:961",
			"pkg/sentry/fsimpl/proc/task.go:127",
			"pkg/sentry/fsimpl/proc/task.go:193",
			"pkg/sentry/fsimpl/proc/task_net.go:134",
			"pkg/sentry/fsimpl/proc/task_net.go:475",
			"pkg/sentry/fsimpl/proc/task_net.go:491",
			"pkg/sentry/fsimpl/proc/task_net.go:508",
			"pkg/sentry/fsimpl/proc/task_net.go:665",
			"pkg/sentry/fsimpl/proc/task_net.go:715",
			"pkg/sentry/fsimpl/proc/task_net.go:779",
			"pkg/sentry/fsimpl/proc/tasks_files.go:113",
			"pkg/sentry/fsimpl/proc/tasks_files.go:388",
			"pkg/sentry/fsimpl/proc/tasks.go:232",
			"pkg/sentry/fsimpl/proc/tasks_sys.go:145",
			"pkg/sentry/fsimpl/proc/tasks_sys.go:181",
			"pkg/sentry/fsimpl/proc/tasks_sys.go:239",
			"pkg/sentry/fsimpl/proc/tasks_sys.go:291",
			"pkg/sentry/fsimpl/proc/tasks_sys.go:375",
			"pkg/sentry/fsimpl/signalfd/signalfd.go:124",
			"pkg/sentry/fsimpl/signalfd/signalfd.go:15",
			"pkg/sentry/fsimpl/signalfd/signalfd.go:126",
			"pkg/sentry/fsimpl/sockfs/sockfs.go:36",
			"pkg/sentry/fsimpl/sockfs/sockfs.go:79",
			"pkg/sentry/fsimpl/sys/kcov.go:49",
			"pkg/sentry/fsimpl/sys/kcov.go:99",
			"pkg/sentry/fsimpl/sys/sys.go:118",
			"pkg/sentry/fsimpl/sys/sys.go:56",
			"pkg/sentry/fsimpl/testutil/testutil.go:257",
			"pkg/sentry/fsimpl/testutil/testutil.go:260",
			"pkg/sentry/fsimpl/timerfd/timerfd.go:87",
			"pkg/sentry/fsimpl/tmpfs/directory.go:112",
			"pkg/sentry/fsimpl/tmpfs/filesystem.go:195",
			"pkg/sentry/fsimpl/tmpfs/regular_file.go:226",
			"pkg/sentry/fsimpl/tmpfs/regular_file.go:346",
			"pkg/sentry/fsimpl/tmpfs/tmpfs.go:103",
			"pkg/sentry/fsimpl/tmpfs/tmpfs.go:733",
			"pkg/sentry/fsimpl/verity/filesystem.go:490",
			"pkg/sentry/fsimpl/verity/verity.go:156",
			"pkg/sentry/fsimpl/verity/verity.go:629",
			"pkg/sentry/fsimpl/verity/verity.go:672",
			"pkg/sentry/fs/mount.go:162",
			"pkg/sentry/fs/mount.go:256",
			"pkg/sentry/fs/mount_overlay.go:144",
			"pkg/sentry/fs/mounts.go:432",
			"pkg/sentry/fs/proc/exec_args.go:104",
			"pkg/sentry/fs/proc/exec_args.go:73",
			"pkg/sentry/fs/proc/fds.go:269",
			"pkg/sentry/fs/proc/loadavg.go:33",
			"pkg/sentry/fs/proc/meminfo.go:39",
			"pkg/sentry/fs/proc/mounts.go:193",
			"pkg/sentry/fs/proc/mounts.go:84",
			"pkg/sentry/fs/proc/net.go:125",
			"pkg/sentry/fs/proc/proc.go:146",
			"pkg/sentry/fs/proc/proc.go:204",
			"pkg/sentry/fs/proc/seqfile/seqfile.go:210",
			"pkg/sentry/fs/proc/sys.go:146",
			"pkg/sentry/fs/proc/sys.go:43",
			"pkg/sentry/fs/proc/sys_net.go:113",
			"pkg/sentry/fs/proc/sys_net.go:205",
			"pkg/sentry/fs/proc/sys_net.go:233",
			"pkg/sentry/fs/proc/sys_net.go:307",
			"pkg/sentry/fs/proc/sys_net.go:335",
			"pkg/sentry/fs/proc/sys_net.go:446",
			"pkg/sentry/fs/proc/sys_net.go:456",
			"pkg/sentry/fs/proc/sys_net.go:89",
			"pkg/sentry/fs/proc/task.go:170",
			"pkg/sentry/fs/proc/task.go:322",
			"pkg/sentry/fs/proc/task.go:427",
			"pkg/sentry/fs/proc/task.go:467",
			"pkg/sentry/fs/proc/task.go:500",
			"pkg/sentry/fs/proc/task.go:784",
			"pkg/sentry/fs/proc/task.go:839",
			"pkg/sentry/fs/proc/task.go:920",
			"pkg/sentry/fs/proc/uid_gid_map.go:108",
			"pkg/sentry/fs/proc/uid_gid_map.go:79",
			"pkg/sentry/fs/proc/uptime.go:75",
			"pkg/sentry/fs/ramfs/dir.go:447",
			"pkg/sentry/fs/tmpfs/inode_file.go:436",
			"pkg/sentry/fs/tmpfs/inode_file.go:537",
			"pkg/sentry/fs/tty/dir.go:313",
			"pkg/sentry/fs/tty/master.go:131",
			"pkg/sentry/fs/tty/master.go:91",
			"pkg/sentry/fs/tty/replica.go:116",
			"pkg/sentry/fs/tty/replica.go:88",
			"pkg/sentry/kernel/auth/id_map.go:269",
			"pkg/sentry/kernel/fasync/fasync.go:67",
			"pkg/sentry/kernel/kcov.go:209",
			"pkg/sentry/kernel/kcov.go:223",
			"pkg/sentry/kernel/kernel.go:343",
			"pkg/sentry/kernel/kernel.go:368",
			"pkg/sentry/kernel/pipe/node_test.go:112",
			"pkg/sentry/kernel/pipe/node_test.go:119",
			"pkg/sentry/kernel/pipe/node_test.go:130",
			"pkg/sentry/kernel/pipe/node_test.go:137",
			"pkg/sentry/kernel/pipe/node_test.go:149",
			"pkg/sentry/kernel/pipe/node_test.go:150",
			"pkg/sentry/kernel/pipe/node_test.go:158",
			"pkg/sentry/kernel/pipe/node_test.go:174",
			"pkg/sentry/kernel/pipe/node_test.go:180",
			"pkg/sentry/kernel/pipe/node_test.go:193",
			"pkg/sentry/kernel/pipe/node_test.go:202",
			"pkg/sentry/kernel/pipe/node_test.go:205",
			"pkg/sentry/kernel/pipe/node_test.go:216",
			"pkg/sentry/kernel/pipe/node_test.go:219",
			"pkg/sentry/kernel/pipe/node_test.go:271",
			"pkg/sentry/kernel/pipe/node_test.go:290",
			"pkg/sentry/kernel/pipe/pipe_test.go:93",
			"pkg/sentry/kernel/pipe/reader_writer.go:65",
			"pkg/sentry/kernel/posixtimer.go:157",
			"pkg/sentry/kernel/ptrace.go:218",
			"pkg/sentry/kernel/semaphore/semaphore.go:323",
			"pkg/sentry/kernel/sessions.go:123",
			"pkg/sentry/kernel/sessions.go:508",
			"pkg/sentry/kernel/signal_handlers.go:57",
			"pkg/sentry/kernel/task_context.go:72",
			"pkg/sentry/kernel/task_exit.go:67",
			"pkg/sentry/kernel/task_sched.go:255",
			"pkg/sentry/kernel/task_sched.go:280",
			"pkg/sentry/kernel/task_sched.go:323",
			"pkg/sentry/kernel/task_stop.go:192",
			"pkg/sentry/kernel/thread_group.go:530",
			"pkg/sentry/kernel/timekeeper.go:316",
			"pkg/sentry/kernel/vdso.go:106",
			"pkg/sentry/kernel/vdso.go:118",
			"pkg/sentry/memmap/memmap.go:103",
			"pkg/sentry/memmap/memmap.go:163",
			"pkg/sentry/mm/address_space.go:42",
			"pkg/sentry/mm/address_space.go:42",
			"pkg/sentry/mm/aio_context.go:208",
			"pkg/sentry/mm/aio_context.go:288",
			"pkg/sentry/mm/pma.go:683",
			"pkg/sentry/mm/special_mappable.go:80",
			"pkg/sentry/platform/systrap/subprocess.go:370",
			"pkg/sentry/platform/systrap/usertrap/usertrap_amd64.go:124",
			"pkg/sentry/socket/control/control.go:260",
			"pkg/sentry/socket/control/control.go:94",
			"pkg/sentry/socket/control/control_vfs2.go:37",
			"pkg/sentry/socket/hostinet/stack.go:433",
			"pkg/sentry/socket/hostinet/stack.go:438",
			"pkg/sentry/socket/hostinet/stack.go:444",
			"pkg/sentry/socket/hostinet/stack.go:460",
			"pkg/sentry/socket/netfilter/tcp_matcher.go:74",
			"pkg/sentry/socket/netfilter/udp_matcher.go:71",
			"pkg/sentry/socket/netlink/route/protocol.go:38",
			"pkg/sentry/socket/socket.go:332",
			"pkg/sentry/socket/unix/transport/connectioned.go:394",
			"pkg/sentry/socket/unix/transport/connectionless.go:152",
			"pkg/sentry/socket/unix/transport/unix.go:436",
			"pkg/sentry/socket/unix/transport/unix.go:490",
			"pkg/sentry/socket/unix/transport/unix.go:685",
			"pkg/sentry/socket/unix/transport/unix.go:795",
			"pkg/sentry/syscalls/linux/sys_sem.go:62",
			"pkg/sentry/syscalls/linux/sys_time.go:189",
			"pkg/sentry/usage/cpu.go:42",
			"pkg/sentry/vfs/anonfs.go:302",
			"pkg/sentry/vfs/anonfs.go:99",
			"pkg/sentry/vfs/dentry.go:214",
			"pkg/sentry/vfs/epoll.go:168",
			"pkg/sentry/vfs/epoll.go:314",
			"pkg/sentry/vfs/file_description.go:549",
			"pkg/sentry/vfs/file_description_impl_util.go:304",
			"pkg/sentry/vfs/file_description_impl_util.go:412",
			"pkg/sentry/vfs/filesystem.go:76",
			"pkg/sentry/vfs/lock.go:15",
			"pkg/sentry/vfs/lock.go:47",
			"pkg/sentry/vfs/memxattr/xattr.go:37",
			"pkg/sentry/vfs/mount.go:510",
			"pkg/sentry/vfs/mount.go:667",
			"pkg/sentry/vfs/mount_test.go:106",
			"pkg/sentry/vfs/mount_test.go:160",
			"pkg/sentry/vfs/mount_test.go:215",
			"pkg/sentry/vfs/mount_unsafe.go:153",
			"pkg/sentry/vfs/resolving_path.go:228",
			"pkg/sentry/vfs/vfs.go:897",
			"pkg/shim/runsc/runsc.go:16",
			"pkg/shim/runsc/utils.go:16",
			"pkg/shim/v1/proc/deleted_state.go:16",
			"pkg/shim/v1/proc/exec.go:16",
			"pkg/shim/v1/proc/exec_state.go:16",
			"pkg/shim/v1/proc/init.go:16",
			"pkg/shim/v1/proc/init_state.go:16",
			"pkg/shim/v1/proc/io.go:16",
			"pkg/shim/v1/proc/process.go:16",
			"pkg/shim/v1/proc/types.go:16",
			"pkg/shim/v1/proc/utils.go:16",
			"pkg/shim/v1/shim/api.go:16",
			"pkg/shim/v1/shim/platform.go:16",
			"pkg/shim/v1/shim/service.go:16",
			"pkg/shim/v1/utils/annotations.go:15",
			"pkg/shim/v1/utils/utils.go:15",
			"pkg/shim/v1/utils/volumes.go:15",
			"pkg/shim/v2/api.go:16",
			"pkg/shim/v2/epoll.go:18",
			"pkg/shim/v2/options/options.go:15",
			"pkg/shim/v2/options/options.go:24",
			"pkg/shim/v2/options/options.go:26",
			"pkg/shim/v2/runtimeoptions/runtimeoptions.go:16",
			"pkg/shim/v2/runtimeoptions/runtimeoptions_cri.go", // Generated: exempt all.
			"pkg/shim/v2/runtimeoptions/runtimeoptions_test.go:22",
			"pkg/shim/v2/service.go:15",
			"pkg/shim/v2/service_linux.go:18",
			"pkg/state/tests/integer_test.go:23",
			"pkg/state/tests/integer_test.go:28",
			"pkg/sync/rwmutex_test.go:105",
			"pkg/syserr/host_linux.go:35",
			"pkg/unet/unet_test.go:634",
			"pkg/unet/unet_test.go:662",
			"pkg/unet/unet_test.go:703",
			"pkg/unet/unet_test.go:98",
			"pkg/usermem/addr.go:34",
			"pkg/usermem/usermem.go:171",
			"pkg/usermem/usermem.go:170",
			"runsc/boot/compat.go:22",
			"runsc/boot/compat.go:56",
			"runsc/boot/loader.go:1115",
			"runsc/boot/loader.go:1120",
			"runsc/cmd/checkpoint.go:151",
			"runsc/config/flags.go:32",
			"runsc/container/container.go:641",
			"runsc/container/container.go:988",
			"runsc/specutils/specutils.go:172",
			"runsc/specutils/specutils.go:428",
			"runsc/specutils/specutils.go:436",
			"runsc/specutils/specutils.go:442",
			"runsc/specutils/specutils.go:447",
			"runsc/specutils/specutils.go:454",
			"test/cmd/test_app/fds.go:171",
			"test/iptables/filter_output.go:251",
			"test/packetimpact/testbench/connections.go:77",
			"tools/bigquery/bigquery.go:106",
			"tools/checkescape/test1/test1.go:108",
			"tools/checkescape/test1/test1.go:122",
			"tools/checkescape/test1/test1.go:137",
			"tools/checkescape/test1/test1.go:151",
			"tools/checkescape/test1/test1.go:170",
			"tools/checkescape/test1/test1.go:39",
			"tools/checkescape/test1/test1.go:45",
			"tools/checkescape/test1/test1.go:50",
			"tools/checkescape/test1/test1.go:64",
			"tools/checkescape/test1/test1.go:80",
			"tools/checkescape/test1/test1.go:94",
			"tools/go_generics/imports.go:51",
			"tools/go_generics/imports.go:75",
			"tools/go_marshal/gomarshal/generator.go:177",
			"tools/go_marshal/gomarshal/generator.go:81",
			"tools/go_marshal/gomarshal/generator.go:85",
			"tools/go_marshal/test/escape/escape.go:15",
			"tools/go_marshal/test/test.go:164",
		),
	)

	// Add all staticcheck analyzers; internal only.
	for _, a := range staticcheck.Analyzers {
		analyzerConfig[a] = staticMatcher
	}
	// Add all stylecheck analyzers; internal only.
	for _, a := range stylecheck.Analyzers {
		analyzerConfig[a] = staticMatcher
	}
}

var escapesConfig = map[*analysis.Analyzer]matcher{
	// Informational only: include all packages.
	checkescape.EscapeAnalyzer: alwaysMatches(),
}
