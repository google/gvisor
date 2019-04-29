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

// Errno represents a Linux errno value.
type Errno struct {
	number int
	name   string
}

// Number returns the errno number.
func (e *Errno) Number() int {
	return e.number
}

// String implements fmt.Stringer.String.
func (e *Errno) String() string {
	return e.name
}

// Errno values from include/uapi/asm-generic/errno-base.h.
var (
	EPERM   = &Errno{1, "operation not permitted"}
	ENOENT  = &Errno{2, "no such file or directory"}
	ESRCH   = &Errno{3, "no such process"}
	EINTR   = &Errno{4, "interrupted system call"}
	EIO     = &Errno{5, "I/O error"}
	ENXIO   = &Errno{6, "no such device or address"}
	E2BIG   = &Errno{7, "argument list too long"}
	ENOEXEC = &Errno{8, "exec format error"}
	EBADF   = &Errno{9, "bad file number"}
	ECHILD  = &Errno{10, "no child processes"}
	EAGAIN  = &Errno{11, "try again"}
	ENOMEM  = &Errno{12, "out of memory"}
	EACCES  = &Errno{13, "permission denied"}
	EFAULT  = &Errno{14, "bad address"}
	ENOTBLK = &Errno{15, "block device required"}
	EBUSY   = &Errno{16, "device or resource busy"}
	EEXIST  = &Errno{17, "file exists"}
	EXDEV   = &Errno{18, "cross-device link"}
	ENODEV  = &Errno{19, "no such device"}
	ENOTDIR = &Errno{20, "not a directory"}
	EISDIR  = &Errno{21, "is a directory"}
	EINVAL  = &Errno{22, "invalid argument"}
	ENFILE  = &Errno{23, "file table overflow"}
	EMFILE  = &Errno{24, "too many open files"}
	ENOTTY  = &Errno{25, "not a typewriter"}
	ETXTBSY = &Errno{26, "text file busy"}
	EFBIG   = &Errno{27, "file too large"}
	ENOSPC  = &Errno{28, "no space left on device"}
	ESPIPE  = &Errno{29, "illegal seek"}
	EROFS   = &Errno{30, "read-only file system"}
	EMLINK  = &Errno{31, "too many links"}
	EPIPE   = &Errno{32, "broken pipe"}
	EDOM    = &Errno{33, "math argument out of domain of func"}
	ERANGE  = &Errno{34, "math result not representable"}
)

// Errno values from include/uapi/asm-generic/errno.h.
var (
	EDEADLK         = &Errno{35, "resource deadlock would occur"}
	ENAMETOOLONG    = &Errno{36, "file name too long"}
	ENOLCK          = &Errno{37, "no record locks available"}
	ENOSYS          = &Errno{38, "invalid system call number"}
	ENOTEMPTY       = &Errno{39, "directory not empty"}
	ELOOP           = &Errno{40, "too many symbolic links encountered"}
	EWOULDBLOCK     = &Errno{EAGAIN.number, "operation would block"}
	ENOMSG          = &Errno{42, "no message of desired type"}
	EIDRM           = &Errno{43, "identifier removed"}
	ECHRNG          = &Errno{44, "channel number out of range"}
	EL2NSYNC        = &Errno{45, "level 2 not synchronized"}
	EL3HLT          = &Errno{46, "level 3 halted"}
	EL3RST          = &Errno{47, "level 3 reset"}
	ELNRNG          = &Errno{48, "link number out of range"}
	EUNATCH         = &Errno{49, "protocol driver not attached"}
	ENOCSI          = &Errno{50, "no CSI structure available"}
	EL2HLT          = &Errno{51, "level 2 halted"}
	EBADE           = &Errno{52, "invalid exchange"}
	EBADR           = &Errno{53, "invalid request descriptor"}
	EXFULL          = &Errno{54, "exchange full"}
	ENOANO          = &Errno{55, "no anode"}
	EBADRQC         = &Errno{56, "invalid request code"}
	EBADSLT         = &Errno{57, "invalid slot"}
	EDEADLOCK       = EDEADLK
	EBFONT          = &Errno{59, "bad font file format"}
	ENOSTR          = &Errno{60, "device not a stream"}
	ENODATA         = &Errno{61, "no data available"}
	ETIME           = &Errno{62, "timer expired"}
	ENOSR           = &Errno{63, "out of streams resources"}
	ENONET          = &Errno{64, "machine is not on the network"}
	ENOPKG          = &Errno{65, "package not installed"}
	EREMOTE         = &Errno{66, "object is remote"}
	ENOLINK         = &Errno{67, "link has been severed"}
	EADV            = &Errno{68, "advertise error"}
	ESRMNT          = &Errno{69, "srmount error"}
	ECOMM           = &Errno{70, "communication error on send"}
	EPROTO          = &Errno{71, "protocol error"}
	EMULTIHOP       = &Errno{72, "multihop attempted"}
	EDOTDOT         = &Errno{73, "RFS specific error"}
	EBADMSG         = &Errno{74, "not a data message"}
	EOVERFLOW       = &Errno{75, "value too large for defined data type"}
	ENOTUNIQ        = &Errno{76, "name not unique on network"}
	EBADFD          = &Errno{77, "file descriptor in bad state"}
	EREMCHG         = &Errno{78, "remote address changed"}
	ELIBACC         = &Errno{79, "can not access a needed shared library"}
	ELIBBAD         = &Errno{80, "accessing a corrupted shared library"}
	ELIBSCN         = &Errno{81, ".lib section in a.out corrupted"}
	ELIBMAX         = &Errno{82, "attempting to link in too many shared libraries"}
	ELIBEXEC        = &Errno{83, "cannot exec a shared library directly"}
	EILSEQ          = &Errno{84, "illegal byte sequence"}
	ERESTART        = &Errno{85, "interrupted system call should be restarted"}
	ESTRPIPE        = &Errno{86, "streams pipe error"}
	EUSERS          = &Errno{87, "too many users"}
	ENOTSOCK        = &Errno{88, "socket operation on non-socket"}
	EDESTADDRREQ    = &Errno{89, "destination address required"}
	EMSGSIZE        = &Errno{90, "message too long"}
	EPROTOTYPE      = &Errno{91, "protocol wrong type for socket"}
	ENOPROTOOPT     = &Errno{92, "protocol not available"}
	EPROTONOSUPPORT = &Errno{93, "protocol not supported"}
	ESOCKTNOSUPPORT = &Errno{94, "socket type not supported"}
	EOPNOTSUPP      = &Errno{95, "operation not supported on transport endpoint"}
	EPFNOSUPPORT    = &Errno{96, "protocol family not supported"}
	EAFNOSUPPORT    = &Errno{97, "address family not supported by protocol"}
	EADDRINUSE      = &Errno{98, "address already in use"}
	EADDRNOTAVAIL   = &Errno{99, "cannot assign requested address"}
	ENETDOWN        = &Errno{100, "network is down"}
	ENETUNREACH     = &Errno{101, "network is unreachable"}
	ENETRESET       = &Errno{102, "network dropped connection because of reset"}
	ECONNABORTED    = &Errno{103, "software caused connection abort"}
	ECONNRESET      = &Errno{104, "connection reset by peer"}
	ENOBUFS         = &Errno{105, "no buffer space available"}
	EISCONN         = &Errno{106, "transport endpoint is already connected"}
	ENOTCONN        = &Errno{107, "transport endpoint is not connected"}
	ESHUTDOWN       = &Errno{108, "cannot send after transport endpoint shutdown"}
	ETOOMANYREFS    = &Errno{109, "too many references: cannot splice"}
	ETIMEDOUT       = &Errno{110, "connection timed out"}
	ECONNREFUSED    = &Errno{111, "connection refused"}
	EHOSTDOWN       = &Errno{112, "host is down"}
	EHOSTUNREACH    = &Errno{113, "no route to host"}
	EALREADY        = &Errno{114, "operation already in progress"}
	EINPROGRESS     = &Errno{115, "operation now in progress"}
	ESTALE          = &Errno{116, "stale file handle"}
	EUCLEAN         = &Errno{117, "structure needs cleaning"}
	ENOTNAM         = &Errno{118, "not a XENIX named type file"}
	ENAVAIL         = &Errno{119, "no XENIX semaphores available"}
	EISNAM          = &Errno{120, "is a named type file"}
	EREMOTEIO       = &Errno{121, "remote I/O error"}
	EDQUOT          = &Errno{122, "quota exceeded"}
	ENOMEDIUM       = &Errno{123, "no medium found"}
	EMEDIUMTYPE     = &Errno{124, "wrong medium type"}
	ECANCELED       = &Errno{125, "operation Canceled"}
	ENOKEY          = &Errno{126, "required key not available"}
	EKEYEXPIRED     = &Errno{127, "key has expired"}
	EKEYREVOKED     = &Errno{128, "key has been revoked"}
	EKEYREJECTED    = &Errno{129, "key was rejected by service"}
	EOWNERDEAD      = &Errno{130, "owner died"}
	ENOTRECOVERABLE = &Errno{131, "state not recoverable"}
	ERFKILL         = &Errno{132, "operation not possible due to RF-kill"}
	EHWPOISON       = &Errno{133, "memory page has hardware error"}
)
