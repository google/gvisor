load("//test/runner:defs.bzl", "syscall_test")

package(licenses = ["notice"])

syscall_test(
    test = "//test/syscalls/linux:32bit_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:accept_bind_stream_test",
    vfs2 = "True",
)

syscall_test(
    size = "large",
    shard_count = 50,
    test = "//test/syscalls/linux:accept_bind_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:access_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:affinity_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:aio_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    shard_count = 5,
    test = "//test/syscalls/linux:alarm_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:arch_prctl_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:bad_test",
    vfs2 = "True",
)

syscall_test(
    size = "large",
    add_overlay = True,
    test = "//test/syscalls/linux:bind_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:brk_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:socket_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:socket_capability_test",
    vfs2 = "True",
)

syscall_test(
    size = "large",
    shard_count = 50,
    # Takes too long for TSAN. Since this is kind of a stress test that doesn't
    # involve much concurrency, TSAN's usefulness here is limited anyway.
    tags = ["nogotsan"],
    test = "//test/syscalls/linux:socket_stress_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:chdir_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:chmod_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    add_overlay = True,
    test = "//test/syscalls/linux:chown_test",
    use_tmpfs = True,  # chwon tests require gofer to be running as root.
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:chroot_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:clock_getres_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:clock_gettime_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:clock_nanosleep_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:concurrency_test",
    vfs2 = "True",
)

syscall_test(
    add_uds_tree = True,
    test = "//test/syscalls/linux:connect_external_test",
    use_tmpfs = True,
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:creat_test",
    vfs2 = "True",
)

syscall_test(
    fuse = "True",
    test = "//test/syscalls/linux:dev_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:dup_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:epoll_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:eventfd_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:exceptions_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    add_overlay = True,
    test = "//test/syscalls/linux:exec_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    add_overlay = True,
    test = "//test/syscalls/linux:exec_binary_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:exit_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:fadvise64_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:fallocate_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:fault_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:fchdir_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:fcntl_test",
)

syscall_test(
    size = "medium",
    add_overlay = True,
    test = "//test/syscalls/linux:flock_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:fork_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:fpsig_fork_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:fpsig_nested_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:fsync_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    shard_count = 5,
    test = "//test/syscalls/linux:futex_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:getcpu_host_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:getcpu_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:getdents_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:getrandom_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:getrusage_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    add_overlay = False,  # TODO(gvisor.dev/issue/317): enable when fixed.
    test = "//test/syscalls/linux:inotify_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    add_overlay = True,
    test = "//test/syscalls/linux:ioctl_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:iptables_test",
    vfs2 = "True",
)

syscall_test(
    size = "large",
    shard_count = 5,
    test = "//test/syscalls/linux:itimer_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:kill_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:link_test",
    use_tmpfs = True,  # gofer needs CAP_DAC_READ_SEARCH to use AT_EMPTY_PATH with linkat(2)
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:lseek_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:madvise_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:memory_accounting_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:mempolicy_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:mincore_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:mkdir_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:mknod_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    shard_count = 5,
    test = "//test/syscalls/linux:mmap_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:mount_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:mremap_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:msync_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:munmap_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:network_namespace_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:open_create_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:open_test",
)

syscall_test(
    test = "//test/syscalls/linux:packet_socket_raw_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:packet_socket_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:partial_bad_buffer_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:pause_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    # Takes too long under gotsan to run.
    tags = ["nogotsan"],
    test = "//test/syscalls/linux:ping_socket_test",
    vfs2 = "True",
)

syscall_test(
    size = "large",
    add_overlay = True,
    shard_count = 5,
    test = "//test/syscalls/linux:pipe_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:poll_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:ppoll_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:prctl_setuid_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:prctl_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:pread64_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:preadv_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:preadv2_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:priority_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:proc_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:proc_net_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:proc_pid_oomscore_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:proc_pid_smaps_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:proc_pid_uid_gid_map_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:pselect_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:ptrace_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    shard_count = 5,
    test = "//test/syscalls/linux:pty_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:pty_root_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:pwritev2_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:pwrite64_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:raw_socket_hdrincl_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:raw_socket_icmp_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:raw_socket_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:read_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:readahead_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    shard_count = 5,
    test = "//test/syscalls/linux:readv_socket_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    add_overlay = True,
    test = "//test/syscalls/linux:readv_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    add_overlay = True,
    test = "//test/syscalls/linux:rename_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:rlimits_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:rseq_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:rtsignal_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:signalfd_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:sched_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:sched_yield_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:seccomp_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:select_test",
    vfs2 = "True",
)

syscall_test(
    shard_count = 20,
    test = "//test/syscalls/linux:semaphore_test",
    vfs2 = "True",
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
    test = "//test/syscalls/linux:splice_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:sigaction_test",
    vfs2 = "True",
)

# TODO(b/119826902): Enable once the test passes in runsc.
# syscall_test(vfs2="True",test = "//test/syscalls/linux:sigaltstack_test")

syscall_test(
    test = "//test/syscalls/linux:sigiret_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:sigprocmask_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:sigstop_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:sigtimedwait_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:shm_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:socket_abstract_non_blocking_test",
    vfs2 = "True",
)

syscall_test(
    size = "large",
    shard_count = 50,
    test = "//test/syscalls/linux:socket_abstract_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:socket_domain_non_blocking_test",
    vfs2 = "True",
)

syscall_test(
    size = "large",
    shard_count = 50,
    test = "//test/syscalls/linux:socket_domain_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    add_overlay = True,
    test = "//test/syscalls/linux:socket_filesystem_non_blocking_test",
    vfs2 = "True",
)

syscall_test(
    size = "large",
    add_overlay = True,
    shard_count = 50,
    test = "//test/syscalls/linux:socket_filesystem_test",
    vfs2 = "True",
)

syscall_test(
    size = "large",
    shard_count = 50,
    test = "//test/syscalls/linux:socket_inet_loopback_test",
    vfs2 = "True",
)

syscall_test(
    size = "large",
    shard_count = 50,
    # Takes too long for TSAN. Creates a lot of TCP sockets.
    tags = ["nogotsan"],
    test = "//test/syscalls/linux:socket_inet_loopback_nogotsan_test",
    vfs2 = "True",
)

syscall_test(
    size = "large",
    shard_count = 50,
    test = "//test/syscalls/linux:socket_ip_tcp_generic_loopback_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:socket_ip_tcp_loopback_non_blocking_test",
    vfs2 = "True",
)

syscall_test(
    size = "large",
    shard_count = 50,
    test = "//test/syscalls/linux:socket_ip_tcp_loopback_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    shard_count = 50,
    test = "//test/syscalls/linux:socket_ip_tcp_udp_generic_loopback_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:socket_ip_udp_loopback_non_blocking_test",
    vfs2 = "True",
)

syscall_test(
    size = "large",
    shard_count = 50,
    test = "//test/syscalls/linux:socket_ip_udp_loopback_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:socket_ipv4_udp_unbound_loopback_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:socket_ip_unbound_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:socket_netdevice_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:socket_netlink_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:socket_netlink_route_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:socket_netlink_uevent_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:socket_blocking_local_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:socket_blocking_ip_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:socket_non_stream_blocking_local_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:socket_non_stream_blocking_udp_test",
    vfs2 = "True",
)

syscall_test(
    size = "large",
    test = "//test/syscalls/linux:socket_stream_blocking_local_test",
    vfs2 = "True",
)

syscall_test(
    size = "large",
    test = "//test/syscalls/linux:socket_stream_blocking_tcp_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:socket_stream_local_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:socket_stream_nonblock_local_test",
    vfs2 = "True",
)

syscall_test(
    # NOTE(b/116636318): Large sendmsg may stall a long time.
    size = "enormous",
    shard_count = 5,
    test = "//test/syscalls/linux:socket_unix_dgram_local_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:socket_unix_dgram_non_blocking_test",
    vfs2 = "True",
)

syscall_test(
    size = "large",
    add_overlay = True,
    shard_count = 50,
    test = "//test/syscalls/linux:socket_unix_pair_test",
    vfs2 = "True",
)

syscall_test(
    # NOTE(b/116636318): Large sendmsg may stall a long time.
    size = "enormous",
    shard_count = 5,
    test = "//test/syscalls/linux:socket_unix_seqpacket_local_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:socket_unix_stream_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:socket_unix_unbound_abstract_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:socket_unix_unbound_dgram_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:socket_unix_unbound_filesystem_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    shard_count = 10,
    test = "//test/syscalls/linux:socket_unix_unbound_seqpacket_test",
    vfs2 = "True",
)

syscall_test(
    size = "large",
    shard_count = 50,
    test = "//test/syscalls/linux:socket_unix_unbound_stream_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:statfs_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:stat_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:stat_times_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:sticky_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:symlink_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:sync_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:sync_file_range_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:sysinfo_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:syslog_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:sysret_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    shard_count = 10,
    test = "//test/syscalls/linux:tcp_socket_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:tgkill_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:timerfd_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:timers_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:time_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:tkill_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:truncate_test",
)

syscall_test(
    test = "//test/syscalls/linux:tuntap_test",
    vfs2 = "True",
)

syscall_test(
    add_hostinet = True,
    test = "//test/syscalls/linux:tuntap_hostinet_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:udp_bind_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    add_hostinet = True,
    shard_count = 10,
    test = "//test/syscalls/linux:udp_socket_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:uidgid_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:uname_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:unlink_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:unshare_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:utimes_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    test = "//test/syscalls/linux:vdso_clock_gettime_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:vdso_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:vsyscall_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:vfork_test",
    vfs2 = "True",
)

syscall_test(
    size = "medium",
    shard_count = 5,
    test = "//test/syscalls/linux:wait_test",
    vfs2 = "True",
)

syscall_test(
    add_overlay = True,
    test = "//test/syscalls/linux:write_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:proc_net_unix_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:proc_net_tcp_test",
    vfs2 = "True",
)

syscall_test(
    test = "//test/syscalls/linux:proc_net_udp_test",
    vfs2 = "True",
)
