// Copyright 2018 The gVisor Authors.
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

package linux

// ioctl(2) requests provided by asm-generic/ioctls.h
//
// These are ordered by request number (low byte).
const (
	TCGETS      = 0x00005401
	TCSETS      = 0x00005402
	TCSETSW     = 0x00005403
	TCSETSF     = 0x00005404
	TCSBRK      = 0x00005409
	TIOCEXCL    = 0x0000540c
	TIOCNXCL    = 0x0000540d
	TIOCSCTTY   = 0x0000540e
	TIOCGPGRP   = 0x0000540f
	TIOCSPGRP   = 0x00005410
	TIOCOUTQ    = 0x00005411
	TIOCSTI     = 0x00005412
	TIOCGWINSZ  = 0x00005413
	TIOCSWINSZ  = 0x00005414
	TIOCMGET    = 0x00005415
	TIOCMBIS    = 0x00005416
	TIOCMBIC    = 0x00005417
	TIOCMSET    = 0x00005418
	TIOCINQ     = 0x0000541b
	FIONREAD    = TIOCINQ
	FIONBIO     = 0x00005421
	TIOCSETD    = 0x00005423
	TIOCNOTTY   = 0x00005422
	TIOCGETD    = 0x00005424
	TCSBRKP     = 0x00005425
	TIOCSBRK    = 0x00005427
	TIOCCBRK    = 0x00005428
	TIOCGSID    = 0x00005429
	TIOCGPTN    = 0x80045430
	TIOCSPTLCK  = 0x40045431
	TIOCGDEV    = 0x80045432
	TIOCVHANGUP = 0x00005437
	TCFLSH      = 0x0000540b
	TIOCCONS    = 0x0000541d
	TIOCSSERIAL = 0x0000541f
	TIOCGEXCL   = 0x80045440
	TIOCGPTPEER = 0x80045441
	TIOCGICOUNT = 0x0000545d
	FIONCLEX    = 0x00005450
	FIOCLEX     = 0x00005451
	FIOASYNC    = 0x00005452
	FIOSETOWN   = 0x00008901
	SIOCSPGRP   = 0x00008902
	FIOGETOWN   = 0x00008903
	SIOCGPGRP   = 0x00008904
)

// ioctl(2) requests provided by uapi/linux/sockios.h
const (
	SIOCGIFNAME    = 0x8910
	SIOCGIFCONF    = 0x8912
	SIOCGIFFLAGS   = 0x8913
	SIOCGIFADDR    = 0x8915
	SIOCGIFDSTADDR = 0x8917
	SIOCGIFBRDADDR = 0x8919
	SIOCGIFNETMASK = 0x891b
	SIOCGIFMETRIC  = 0x891d
	SIOCGIFMTU     = 0x8921
	SIOCGIFMEM     = 0x891f
	SIOCGIFHWADDR  = 0x8927
	SIOCGIFINDEX   = 0x8933
	SIOCGIFPFLAGS  = 0x8935
	SIOCGIFTXQLEN  = 0x8942
	SIOCETHTOOL    = 0x8946
	SIOCGMIIPHY    = 0x8947
	SIOCGMIIREG    = 0x8948
	SIOCGIFMAP     = 0x8970
)

// ioctl(2) requests provided by uapi/asm-generic/sockios.h
const (
	SIOCGSTAMP = 0x8906
)

// ioctl(2) directions. Used to calculate requests number.
// Constants from asm-generic/ioctl.h.
const (
	IOC_NONE  = 0
	IOC_WRITE = 1
	IOC_READ  = 2
)

// Constants from asm-generic/ioctl.h.
const (
	IOC_NRBITS   = 8
	IOC_TYPEBITS = 8
	IOC_SIZEBITS = 14
	IOC_DIRBITS  = 2

	IOC_NRSHIFT   = 0
	IOC_TYPESHIFT = IOC_NRSHIFT + IOC_NRBITS
	IOC_SIZESHIFT = IOC_TYPESHIFT + IOC_TYPEBITS
	IOC_DIRSHIFT  = IOC_SIZESHIFT + IOC_SIZEBITS
)

// IOC outputs the result of _IOC macro in include/uapi/asm-generic/ioctl.h.
func IOC(dir, typ, nr, size uint32) uint32 {
	return uint32(dir)<<IOC_DIRSHIFT | typ<<IOC_TYPESHIFT | nr<<IOC_NRSHIFT | size<<IOC_SIZESHIFT
}

// IO outputs the result of _IO macro in include/uapi/asm-generic/ioctl.h.
func IO(typ, nr uint32) uint32 {
	return IOC(IOC_NONE, typ, nr, 0)
}

// IOR outputs the result of _IOR macro in include/uapi/asm-generic/ioctl.h.
func IOR(typ, nr, size uint32) uint32 {
	return IOC(IOC_READ, typ, nr, size)
}

// IOW outputs the result of _IOW macro in include/uapi/asm-generic/ioctl.h.
func IOW(typ, nr, size uint32) uint32 {
	return IOC(IOC_WRITE, typ, nr, size)
}

// IOWR outputs the result of _IOWR macro in include/uapi/asm-generic/ioctl.h.
func IOWR(typ, nr, size uint32) uint32 {
	return IOC(IOC_READ|IOC_WRITE, typ, nr, size)
}

// IOC_NR outputs the result of IOC_NR macro in
// include/uapi/asm-generic/ioctl.h.
func IOC_NR(nr uint32) uint32 {
	return (nr >> IOC_NRSHIFT) & ((1 << IOC_NRBITS) - 1)
}

// IOC_SIZE outputs the result of IOC_SIZE macro in
// include/uapi/asm-generic/ioctl.h.
func IOC_SIZE(nr uint32) uint32 {
	return (nr >> IOC_SIZESHIFT) & ((1 << IOC_SIZEBITS) - 1)
}

// Kcov ioctls from include/uapi/linux/kcov.h.
var (
	KCOV_INIT_TRACE = IOR('c', 1, 8)
	KCOV_ENABLE     = IO('c', 100)
	KCOV_DISABLE    = IO('c', 101)
)

// Kcov trace types from include/uapi/linux/kcov.h.
const (
	KCOV_TRACE_PC  = 0
	KCOV_TRACE_CMP = 1
)

// Kcov state constants from include/uapi/linux/kcov.h.
const (
	KCOV_MODE_DISABLED  = 0
	KCOV_MODE_INIT      = 1
	KCOV_MODE_TRACE_PC  = 2
	KCOV_MODE_TRACE_CMP = 3
)
