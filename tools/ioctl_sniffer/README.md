# Ioctl Sniffer

This tool provides a way to profile GPU workloads, sniff out all the Nvidia
`ioctl(2)` calls that are involved, and ultimately filter out the calls that are
currently unsupported by nvproxy.

This is accomplished by providing a `libioctl_hook.so` shared library, which can
be `LD_PRELOAD`ed and intercepts all `ioctl(2)` calls made. Any calls made to
known Nvidia device files are then captured and parsed by the `sniffer` Go
package. The sniffer compares against nvproxy's list of supported `ioctl(2)`
numbers for the current driver version, and checks if the given call is
contained in the list. For `NV_ESC_RM_CONTROL` and `NV_ESC_RM_ALLOC` calls, it
also extracts the control command and allocation class respectively, and checks
if nvproxy supports them.

## Usage

To start, we need to build the shared library and Go binary:

```
make copy TARGETS=//tools/ioctl_sniffer:run_sniffer DESTINATION=bin/
make copy TARGETS=//tools/ioctl_sniffer:ioctl_hook DESTINATION=bin/
```

Once we have the binary, we can hook into any GPU workload by passing the
corresponding command to run it to `run_sniffer`, like so:

```
./run_sniffer nvidia-smi
```

This should run the workload as normal and provide an output of all the
unsupported `ioctl(2)` calls it detected at the end:

```
============== Unsupported ioctls ==============
Frontend:
UVM:
Control:
    Control ioctl: request=0xc020462a [nr=0x2a (42), cmd=0x20810110 (545325328)] => ret=0
    Control ioctl: request=0xc020462a [nr=0x2a (42), cmd=0x2080014b (545259851)] => ret=0
    ...
Alloc:
    Alloc ioctl: request=0xc030462b [nr=0x2b (43), hClass=0xc639 (50745)] => ret=0
    Alloc ioctl: request=0xc030462b [nr=0x2b (43), hClass=0xc640 (50752)] => ret=0
    ...
Unknown:
```

Note that by default, `run_sniffer` assumes the shared library is located in the
same directory. You can specify the path to the library with the optional
`-ld_preload` flag.
