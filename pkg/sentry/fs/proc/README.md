This document tracks what is implemented in procfs. Refer to
Documentation/filesystems/proc.txt in the Linux project for information about
procfs generally.

**NOTE**: This document is not guaranteed to be up to date. If you find an
inconsistency, please file a bug.

[TOC]

## Kernel data

The following files are implemented:

| File /proc/                 | Content                                               |
| :------------------------   | :---------------------------------------------------- |
| [cpuinfo](#cpuinfo)         | Info about the CPU                                    |
| [filesystems](#filesystems) | Supported filesystems                                 |
| [loadavg](#loadavg)         | Load average of last 1, 5 & 15 minutes                |
| [meminfo](#meminfo)         | Overall memory info                                   |
| [stat](#stat)               | Overall kernel statistics                             |
| [sys](#sys)                 | Change parameters within the kernel                   |
| [uptime](#uptime)           | Wall clock since boot, combined idle time of all cpus |
| [version](#version)         | Kernel version                                        |

### cpuinfo

```bash
$ cat /proc/cpuinfo
processor   : 0
vendor_id   : GenuineIntel
cpu family  : 6
model       : 45
model name  : unknown
stepping    : unknown
cpu MHz     : 1234.588
fpu     : yes
fpu_exception   : yes
cpuid level : 13
wp      : yes
flags       : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 cx16 xtpr pdcm pcid dca sse4_1 sse4_2 x2apic popcnt tsc_deadline_timer aes xsave avx xsaveopt
bogomips    : 1234.59
clflush size    : 64
cache_alignment : 64
address sizes   : 46 bits physical, 48 bits virtual
power management:

...
```

Notable divergences:

Field name       | Notes
:--------------- | :---------------------------------------
model name       | Always unknown
stepping         | Always unknown
fpu              | Always yes
fpu_exception    | Always yes
wp               | Always yes
bogomips         | Bogus value (matches cpu MHz)
clflush size     | Always 64
cache_alignment  | Always 64
address sizes    | Always 46 bits physical, 48 bits virtual
power management | Always blank

Otherwise fields are derived from the sentry configuration.

### filesystems

```bash
$ cat /proc/filesystems
nodev   9p
nodev   devpts
nodev   devtmpfs
nodev   proc
nodev   sysfs
nodev   tmpfs
```

### loadavg

```bash
$ cat /proc/loadavg
0.00 0.00 0.00 0/0 0
```

Column                                | Notes
:------------------------------------ | :----------
CPU.IO utilization in last 1 minute   | Always zero
CPU.IO utilization in last 5 minutes  | Always zero
CPU.IO utilization in last 10 minutes | Always zero
Num currently running processes       | Always zero
Total num processes                   | Always zero

TODO: Populate the columns with accurate statistics.

### meminfo

```bash
$ cat /proc/meminfo
MemTotal:        2097152 kB
MemFree:         2083540 kB
MemAvailable:    2083540 kB
Buffers:               0 kB
Cached:             4428 kB
SwapCache:             0 kB
Active:            10812 kB
Inactive:           2216 kB
Active(anon):       8600 kB
Inactive(anon):        0 kB
Active(file):       2212 kB
Inactive(file):     2216 kB
Unevictable:           0 kB
Mlocked:               0 kB
SwapTotal:             0 kB
SwapFree:              0 kB
Dirty:                 0 kB
Writeback:             0 kB
AnonPages:          8600 kB
Mapped:             4428 kB
Shmem:                 0 kB

```

Notable divergences:

Field name        | Notes
:---------------- | :-----------------------------------------------------
Buffers           | Always zero, no block devices
SwapCache         | Always zero, no swap
Inactive(anon)    | Always zero, see SwapCache
Unevictable       | Always zero TODO
Mlocked           | Always zero TODO
SwapTotal         | Always zero, no swap
SwapFree          | Always zero, no swap
Dirty             | Always zero TODO
Writeback         | Always zero TODO
MemAvailable      | Uses the same value as MemFree since there is no swap.
Slab              | Missing
SReclaimable      | Missing
SUnreclaim        | Missing
KernelStack       | Missing
PageTables        | Missing
NFS_Unstable      | Missing
Bounce            | Missing
WritebackTmp      | Missing
CommitLimit       | Missing
Committed_AS      | Missing
VmallocTotal      | Missing
VmallocUsed       | Missing
VmallocChunk      | Missing
HardwareCorrupted | Missing
AnonHugePages     | Missing
ShmemHugePages    | Missing
ShmemPmdMapped    | Missing
HugePages_Total   | Missing
HugePages_Free    | Missing
HugePages_Rsvd    | Missing
HugePages_Surp    | Missing
Hugepagesize      | Missing
DirectMap4k       | Missing
DirectMap2M       | Missing
DirectMap1G       | Missing

### stat

```bash
$ cat /proc/stat
cpu  0 0 0 0 0 0 0 0 0 0
cpu0 0 0 0 0 0 0 0 0 0 0
cpu1 0 0 0 0 0 0 0 0 0 0
cpu2 0 0 0 0 0 0 0 0 0 0
cpu3 0 0 0 0 0 0 0 0 0 0
cpu4 0 0 0 0 0 0 0 0 0 0
cpu5 0 0 0 0 0 0 0 0 0 0
cpu6 0 0 0 0 0 0 0 0 0 0
cpu7 0 0 0 0 0 0 0 0 0 0
intr 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
ctxt 0
btime 1504040968
processes 0
procs_running 0
procs_blokkcked 0
softirq 0 0 0 0 0 0 0 0 0 0 0
```

All fields except for `btime` are always zero.

TODO: Populate with accurate fields.

### sys

```bash
$ ls /proc/sys
kernel vm
```

Directory | Notes
:-------- | :----------------------------
abi       | Missing
debug     | Missing
dev       | Missing
fs        | Missing
kernel    | Contains hostname (only)
net       | Missing
user      | Missing
vm        | Contains mmap_min_addr (only)

### uptime

```bash
$ cat /proc/uptime
3204.62 0.00
```

Column                           | Notes
:------------------------------- | :----------------------------
Total num seconds system running | Time since procfs was mounted
Number of seconds idle           | Always zero

### version

```bash
$ cat /proc/version
Linux version 3.11.10 #1 SMP Fri Nov 29 10:47:50 PST 2013
```

## Process-specific data

The following files are implemented:

File /proc/PID          | Content
:---------------------- | :---------------------------------------------------
[auxv](#auxv)           | Copy of auxiliary vector for the process
[cmdline](#cmdline)     | Command line arguments
[comm](#comm)           | Command name associated with the process
[environ](#environ)     | Process environment
[exe](#exe)             | Symlink to the process's executable
[fd](#fd)               | Directory containing links to open file descriptors
[fdinfo](#fdinfo)       | Information associated with open file descriptors
[gid_map](#gid_map)     | Mappings for group IDs inside the user namespace
[io](#io)               | IO statistics
[maps](#maps)           | Memory mappings (anon, executables, library files)
[mounts](#mounts)       | Mounted filesystems
[mountinfo](#mountinfo) | Information about mounts
[ns](#ns)               | Directory containing info about supported namespaces
[stat](#stat)           | Process statistics
[statm](#statm)         | Process memory statistics
[status](#status)       | Process status in human readable format
[task](#task)           | Directory containing info about running threads
[uid_map](#uid_map)     | Mappings for user IDs inside the user namespace

### auxv

TODO

### cmdline

TODO

### comm

TODO

### environment

TODO

### exe

TODO

### fd

TODO

### fdinfo

TODO

### gid_map

TODO

### io

Only has data for rchar, wchar, syscr, and syscw.

TODO: add more detail.

### maps

TODO

### mounts

TODO

### mountinfo

TODO

### ns

TODO

### stat

Only has data for pid, comm, state, ppid, utime, stime, cutime, cstime,
num_threads, and exit_signal.

TODO: add more detail.

### statm

Only has data for vss and rss.

TODO: add more detail.

### status

Contains data for Name, State, Tgid, Pid, Ppid, TracerPid, FDSize, VmSize,
VmRSS, Threads, CapInh, CapPrm, CapEff, CapBnd, Seccomp.

TODO: add more detail.

### task

TODO

### uid_map

TODO
