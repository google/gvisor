load("//tools:defs.bzl", "more_shards", "most_shards")
load("//test/runner:defs.bzl", "syscall_test")

package(licenses = ["notice"])

# Please keep syscall tests ordered alphabetically by name.

syscall_test(
    test = "//test/syscalls/linux:32bit_test",
)

syscall_test(
    test = "//test/syscalls/linux:accept_bind_stream_test",
)

syscall_test(
    size = "large",
    shard_count = most_shards,
    test = "//test/syscalls/linux:accept_bind_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:access_test",
)

syscall_test(
    test = "//test/syscalls/linux:affinity_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:aio_test",
)

syscall_test(
    size = "medium",
    shard_count = more_shards,
    test = "//test/syscalls/linux:alarm_test",
)

syscall_test(
    test = "//test/syscalls/linux:arch_prctl_test",
)

syscall_test(
    test = "//test/syscalls/linux:bad_test",
)

syscall_test(
    size = "large",
    add_overlay = True,
    test = "//test/syscalls/linux:bind_test",
)

syscall_test(
    test = "//test/syscalls/linux:brk_test",
)

syscall_test(
    test = "//test/syscalls/linux:cgroup_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:chdir_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:chmod_test",
)

syscall_test(
    size = "medium",
    add_overlay = True,
    test = "//test/syscalls/linux:chown_test",
    use_tmpfs = True,  # chown tests require gofer to be running as root.
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:chroot_test",
)

syscall_test(
    test = "//test/syscalls/linux:clock_getres_test",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:clock_gettime_test",
)

syscall_test(
    test = "//test/syscalls/linux:clock_nanosleep_test",
)

syscall_test(
    test = "//test/syscalls/linux:concurrency_test",
)

syscall_test(
    add_uds_tree = True,
    test = "//test/syscalls/linux:connect_external_test",
    use_tmpfs = True,
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:creat_test",
)

syscall_test(
    fuse = "True",
    test = "//test/syscalls/linux:dev_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:dup_test",
)

syscall_test(
    test = "//test/syscalls/linux:epoll_test",
)

syscall_test(
    test = "//test/syscalls/linux:eventfd_test",
)

syscall_test(
    test = "//test/syscalls/linux:exceptions_test",
)

syscall_test(
    size = "medium",
    add_overlay = True,
    test = "//test/syscalls/linux:exec_test",
)

syscall_test(
    size = "medium",
    add_overlay = True,
    test = "//test/syscalls/linux:exec_binary_test",
)

syscall_test(
    test = "//test/syscalls/linux:exit_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:fadvise64_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:fallocate_test",
)

syscall_test(
    test = "//test/syscalls/linux:fault_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:fchdir_test",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:fcntl_test",
)

syscall_test(
    size = "medium",
    add_overlay = True,
    test = "//test/syscalls/linux:flock_test",
)

syscall_test(
    test = "//test/syscalls/linux:fork_test",
)

syscall_test(
    test = "//test/syscalls/linux:fpsig_fork_test",
)

syscall_test(
    test = "//test/syscalls/linux:fpsig_nested_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:fsync_test",
)

syscall_test(
    size = "medium",
    shard_count = more_shards,
    test = "//test/syscalls/linux:futex_test",
)

syscall_test(
    test = "//test/syscalls/linux:getcpu_host_test",
)

syscall_test(
    test = "//test/syscalls/linux:getcpu_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:getdents_test",
)

syscall_test(
    test = "//test/syscalls/linux:verity_getdents_test",
)

syscall_test(
    test = "//test/syscalls/linux:getrandom_test",
)

syscall_test(
    test = "//test/syscalls/linux:getrusage_test",
)

syscall_test(
    size = "medium",
    add_overlay = True,
    test = "//test/syscalls/linux:inotify_test",
)

syscall_test(
    size = "medium",
    add_overlay = True,
    test = "//test/syscalls/linux:ioctl_test",
)

syscall_test(
    test = "//test/syscalls/linux:verity_ioctl_test",
)

syscall_test(
    test = "//test/syscalls/linux:iptables_test",
)

syscall_test(
    test = "//test/syscalls/linux:ip6tables_test",
)

syscall_test(
    size = "large",
    shard_count = more_shards,
    test = "//test/syscalls/linux:itimer_test",
)

syscall_test(
    test = "//test/syscalls/linux:kcov_test",
)

syscall_test(
    test = "//test/syscalls/linux:kill_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:link_test",
    use_tmpfs = True,  # gofer needs CAP_DAC_READ_SEARCH to use AT_EMPTY_PATH with linkat(2)
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:lseek_test",
)

syscall_test(
    test = "//test/syscalls/linux:madvise_test",
)

syscall_test(
    test = "//test/syscalls/linux:membarrier_test",
)

syscall_test(
    test = "//test/syscalls/linux:memory_accounting_test",
)

syscall_test(
    test = "//test/syscalls/linux:mempolicy_test",
)

syscall_test(
    test = "//test/syscalls/linux:mincore_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:mkdir_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:mknod_test",
)

syscall_test(
    test = "//test/syscalls/linux:mlock_test",
)

syscall_test(
    size = "medium",
    shard_count = more_shards,
    test = "//test/syscalls/linux:mmap_test",
)

syscall_test(
    test = "//test/syscalls/linux:verity_mmap_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:mount_test",
)

syscall_test(
    test = "//test/syscalls/linux:mq_test",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:mremap_test",
)

syscall_test(
    test = "//test/syscalls/linux:msgqueue_test",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:msync_test",
)

syscall_test(
    test = "//test/syscalls/linux:munmap_test",
)

syscall_test(
    test = "//test/syscalls/linux:network_namespace_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:open_create_test",
)

syscall_test(
    add_overlay = True,
    shard_count = more_shards,
    test = "//test/syscalls/linux:open_test",
)

syscall_test(
    test = "//test/syscalls/linux:packet_socket_dgram_test",
)

syscall_test(
    test = "//test/syscalls/linux:packet_socket_raw_test",
)

syscall_test(
    test = "//test/syscalls/linux:packet_socket_test",
)

syscall_test(
    test = "//test/syscalls/linux:partial_bad_buffer_test",
)

syscall_test(
    test = "//test/syscalls/linux:pause_test",
)

syscall_test(
    size = "medium",
    # Takes too long under gotsan to run.
    tags = ["nogotsan"],
    test = "//test/syscalls/linux:ping_socket_test",
)

syscall_test(
    size = "large",
    add_overlay = True,
    shard_count = more_shards,
    test = "//test/syscalls/linux:pipe_test",
)

syscall_test(
    test = "//test/syscalls/linux:poll_test",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:ppoll_test",
)

syscall_test(
    test = "//test/syscalls/linux:prctl_setuid_test",
)

syscall_test(
    test = "//test/syscalls/linux:prctl_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:pread64_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:preadv_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:preadv2_test",
)

syscall_test(
    test = "//test/syscalls/linux:priority_test",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:proc_test",
)

syscall_test(
    tags = ["container"],
    test = "//test/syscalls/linux:proc_isolated_test",
)

syscall_test(
    test = "//test/syscalls/linux:proc_net_test",
)

syscall_test(
    test = "//test/syscalls/linux:proc_pid_oomscore_test",
)

syscall_test(
    test = "//test/syscalls/linux:proc_pid_smaps_test",
)

syscall_test(
    test = "//test/syscalls/linux:proc_pid_uid_gid_map_test",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:pselect_test",
)

syscall_test(
    test = "//test/syscalls/linux:ptrace_test",
)

syscall_test(
    size = "medium",
    shard_count = more_shards,
    test = "//test/syscalls/linux:pty_test",
)

syscall_test(
    test = "//test/syscalls/linux:pty_root_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:pwritev2_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:pwrite64_test",
)

syscall_test(
    test = "//test/syscalls/linux:raw_socket_hdrincl_test",
)

syscall_test(
    test = "//test/syscalls/linux:raw_socket_icmp_test",
)

syscall_test(
    shard_count = more_shards,
    test = "//test/syscalls/linux:raw_socket_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:read_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:readahead_test",
)

syscall_test(
    size = "medium",
    shard_count = more_shards,
    test = "//test/syscalls/linux:readv_socket_test",
)

syscall_test(
    size = "medium",
    add_overlay = True,
    test = "//test/syscalls/linux:readv_test",
)

syscall_test(
    size = "medium",
    add_overlay = True,
    test = "//test/syscalls/linux:rename_test",
)

syscall_test(
    test = "//test/syscalls/linux:rlimits_test",
)

syscall_test(
    test = "//test/syscalls/linux:rseq_test",
)

syscall_test(
    test = "//test/syscalls/linux:rtsignal_test",
)

syscall_test(
    test = "//test/syscalls/linux:signalfd_test",
)

syscall_test(
    test = "//test/syscalls/linux:sched_test",
)

syscall_test(
    test = "//test/syscalls/linux:sched_yield_test",
)

syscall_test(
    test = "//test/syscalls/linux:seccomp_test",
)

syscall_test(
    test = "//test/syscalls/linux:select_test",
)

syscall_test(
    shard_count = more_shards,
    test = "//test/syscalls/linux:semaphore_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:sendfile_socket_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:sendfile_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:setgid_test",
    # setgid tests require the gofer's user namespace to have multiple groups,
    # but bazel only provides one.
    use_tmpfs = True,
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:splice_test",
)

syscall_test(
    test = "//test/syscalls/linux:sigaction_test",
)

# TODO(b/119826902): Enable once the test passes in runsc.
# syscall_test(vfs2="True",test = "//test/syscalls/linux:sigaltstack_test")

syscall_test(
    test = "//test/syscalls/linux:sigreturn_test",
)

syscall_test(
    test = "//test/syscalls/linux:sigprocmask_test",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:sigstop_test",
)

syscall_test(
    test = "//test/syscalls/linux:sigtimedwait_test",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:shm_test",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:socket_abstract_non_blocking_test",
)

syscall_test(
    size = "large",
    shard_count = most_shards,
    test = "//test/syscalls/linux:socket_abstract_test",
)

syscall_test(
    test = "//test/syscalls/linux:socket_capability_test",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:socket_domain_non_blocking_test",
)

syscall_test(
    size = "large",
    shard_count = most_shards,
    test = "//test/syscalls/linux:socket_domain_test",
)

syscall_test(
    size = "medium",
    add_overlay = True,
    test = "//test/syscalls/linux:socket_filesystem_non_blocking_test",
)

syscall_test(
    size = "large",
    add_overlay = True,
    shard_count = most_shards,
    test = "//test/syscalls/linux:socket_filesystem_test",
)

syscall_test(
    size = "large",
    shard_count = most_shards,
    test = "//test/syscalls/linux:socket_inet_loopback_test",
)

syscall_test(
    size = "large",
    shard_count = most_shards,
    tags = ["container"],
    test = "//test/syscalls/linux:socket_inet_loopback_isolated_test",
)

syscall_test(
    size = "large",
    shard_count = most_shards,
    # Takes too long for TSAN. Creates a lot of TCP sockets.
    tags = ["nogotsan"],
    test = "//test/syscalls/linux:socket_inet_loopback_nogotsan_test",
)

syscall_test(
    test = "//test/syscalls/linux:socket_ipv4_udp_unbound_external_networking_test",
)

syscall_test(
    size = "large",
    shard_count = most_shards,
    test = "//test/syscalls/linux:socket_ip_tcp_generic_loopback_test",
)

syscall_test(
    size = "medium",
    add_hostinet = True,
    test = "//test/syscalls/linux:socket_ip_tcp_loopback_non_blocking_test",
)

syscall_test(
    size = "large",
    shard_count = most_shards,
    test = "//test/syscalls/linux:socket_ip_tcp_loopback_test",
)

syscall_test(
    size = "medium",
    add_hostinet = True,
    shard_count = most_shards,
    test = "//test/syscalls/linux:socket_ip_tcp_udp_generic_loopback_test",
)

syscall_test(
    size = "medium",
    add_hostinet = True,
    test = "//test/syscalls/linux:socket_ip_udp_loopback_non_blocking_test",
)

syscall_test(
    size = "large",
    shard_count = most_shards,
    test = "//test/syscalls/linux:socket_ip_udp_loopback_test",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:socket_ipv4_datagram_based_socket_unbound_loopback_test",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:socket_ipv4_udp_unbound_loopback_test",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:socket_ipv6_udp_unbound_loopback_test",
)

syscall_test(
    size = "medium",
    add_hostinet = True,
    shard_count = more_shards,
    # Takes too long under gotsan to run.
    tags = ["nogotsan"],
    test = "//test/syscalls/linux:socket_ipv4_udp_unbound_loopback_nogotsan_test",
)

syscall_test(
    test = "//test/syscalls/linux:socket_ipv4_udp_unbound_loopback_netlink_test",
)

syscall_test(
    test = "//test/syscalls/linux:socket_ipv6_udp_unbound_loopback_netlink_test",
)

syscall_test(
    shard_count = more_shards,
    test = "//test/syscalls/linux:socket_ip_unbound_test",
)

syscall_test(
    test = "//test/syscalls/linux:socket_ip_unbound_netlink_test",
)

syscall_test(
    add_hostinet = True,
    test = "//test/syscalls/linux:socket_netdevice_test",
)

syscall_test(
    test = "//test/syscalls/linux:socket_netlink_test",
)

syscall_test(
    test = "//test/syscalls/linux:socket_netlink_route_test",
)

syscall_test(
    test = "//test/syscalls/linux:socket_netlink_uevent_test",
)

syscall_test(
    test = "//test/syscalls/linux:socket_blocking_local_test",
)

syscall_test(
    test = "//test/syscalls/linux:socket_blocking_ip_test",
)

syscall_test(
    add_hostinet = True,
    test = "//test/syscalls/linux:socket_non_stream_blocking_local_test",
)

syscall_test(
    test = "//test/syscalls/linux:socket_non_stream_blocking_udp_test",
)

syscall_test(
    size = "large",
    test = "//test/syscalls/linux:socket_stream_blocking_local_test",
)

syscall_test(
    size = "large",
    test = "//test/syscalls/linux:socket_stream_blocking_tcp_test",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:socket_stream_local_test",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:socket_stream_nonblock_local_test",
)

syscall_test(
    size = "large",
    shard_count = most_shards,
    test = "//test/syscalls/linux:socket_stress_test",
)

syscall_test(
    test = "//test/syscalls/linux:socket_test",
)

syscall_test(
    flaky = 1,  # NOTE(b/116636318): Large sendmsg may stall a long time.
    shard_count = more_shards,
    test = "//test/syscalls/linux:socket_unix_dgram_local_test",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:socket_unix_dgram_non_blocking_test",
)

syscall_test(
    size = "large",
    add_overlay = True,
    shard_count = most_shards,
    test = "//test/syscalls/linux:socket_unix_pair_test",
)

syscall_test(
    flaky = 1,  # NOTE(b/116636318): Large sendmsg may stall a long time.
    shard_count = more_shards,
    test = "//test/syscalls/linux:socket_unix_seqpacket_local_test",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:socket_unix_stream_test",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:socket_unix_unbound_abstract_test",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:socket_unix_unbound_dgram_test",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:socket_unix_unbound_filesystem_test",
)

syscall_test(
    size = "medium",
    shard_count = more_shards,
    test = "//test/syscalls/linux:socket_unix_unbound_seqpacket_test",
)

syscall_test(
    size = "large",
    shard_count = most_shards,
    test = "//test/syscalls/linux:socket_unix_unbound_stream_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:statfs_test",
    use_tmpfs = True,  # Test specifically relies on TEST_TMPDIR to be tmpfs.
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:stat_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:stat_times_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:sticky_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:symlink_test",
)

syscall_test(
    test = "//test/syscalls/linux:verity_symlink_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:sync_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:sync_file_range_test",
)

syscall_test(
    test = "//test/syscalls/linux:sysinfo_test",
)

syscall_test(
    test = "//test/syscalls/linux:syslog_test",
)

syscall_test(
    test = "//test/syscalls/linux:sysret_test",
)

syscall_test(
    size = "medium",
    shard_count = more_shards,
    test = "//test/syscalls/linux:tcp_socket_test",
)

syscall_test(
    test = "//test/syscalls/linux:tgkill_test",
)

syscall_test(
    shard_count = more_shards,
    test = "//test/syscalls/linux:timerfd_test",
)

syscall_test(
    test = "//test/syscalls/linux:timers_test",
)

syscall_test(
    test = "//test/syscalls/linux:time_test",
)

syscall_test(
    test = "//test/syscalls/linux:tkill_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:truncate_test",
)

syscall_test(
    test = "//test/syscalls/linux:tuntap_test",
)

syscall_test(
    add_hostinet = True,
    test = "//test/syscalls/linux:tuntap_hostinet_test",
)

syscall_test(
    add_hostinet = True,
    test = "//test/syscalls/linux:udp_bind_test",
)

syscall_test(
    size = "medium",
    add_hostinet = True,
    shard_count = more_shards,
    test = "//test/syscalls/linux:udp_socket_test",
)

syscall_test(
    test = "//test/syscalls/linux:uidgid_test",
)

syscall_test(
    test = "//test/syscalls/linux:uname_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:unlink_test",
)

syscall_test(
    test = "//test/syscalls/linux:unshare_test",
)

syscall_test(
    test = "//test/syscalls/linux:utimes_test",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:vdso_clock_gettime_test",
)

syscall_test(
    test = "//test/syscalls/linux:vdso_test",
)

syscall_test(
    test = "//test/syscalls/linux:vsyscall_test",
)

syscall_test(
    test = "//test/syscalls/linux:vfork_test",
)

syscall_test(
    size = "medium",
    shard_count = more_shards,
    test = "//test/syscalls/linux:wait_test",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:write_test",
)

syscall_test(
    test = "//test/syscalls/linux:proc_net_unix_test",
)

syscall_test(
    add_hostinet = True,
    test = "//test/syscalls/linux:proc_net_tcp_test",
)

syscall_test(
    test = "//test/syscalls/linux:proc_net_udp_test",
)

syscall_test(
    test = "//test/syscalls/linux:processes_test",
)

syscall_test(
    test = "//test/syscalls/linux:verity_mount_test",
)
