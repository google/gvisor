// Copyright 2021 The gVisor Authors.
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

// Package linuxerr contains syscall error codes exported as an error interface
// pointers. This allows for fast comparison and return operations comperable
// to unix.Errno constants.
package linuxerr

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
)

// Error represents a syscall errno with a descriptive message.
type Error struct {
	errno   linux.Errno
	message string
}

func new(err linux.Errno, message string) *Error {
	return &Error{
		errno:   err,
		message: message,
	}
}

// Error implements error.Error.
func (e *Error) Error() string { return e.message }

// Errno returns the underlying linux.Errno value.
func (e *Error) Errno() linux.Errno { return e.errno }

// The following varables have the same meaning as their errno equivalent.

// Errno values from include/uapi/asm-generic/errno-base.h.
var (
	EPERM   = new(linux.EPERM, "operation not permitted")
	ENOENT  = new(linux.ENOENT, "no such file or directory")
	ESRCH   = new(linux.ESRCH, "no such process")
	EINTR   = new(linux.EINTR, "interrupted system call")
	EIO     = new(linux.EIO, "I/O error")
	ENXIO   = new(linux.ENXIO, "no such device or address")
	E2BIG   = new(linux.E2BIG, "argument list too long")
	ENOEXEC = new(linux.ENOEXEC, "exec format error")
	EBADF   = new(linux.EBADF, "bad file number")
	ECHILD  = new(linux.ECHILD, "no child processes")
	EAGAIN  = new(linux.EAGAIN, "try again")
	ENOMEM  = new(linux.ENOMEM, "out of memory")
	EACCES  = new(linux.EACCES, "permission denied")
	EFAULT  = new(linux.EFAULT, "bad address")
	ENOTBLK = new(linux.ENOTBLK, "block device required")
	EBUSY   = new(linux.EBUSY, "device or resource busy")
	EEXIST  = new(linux.EEXIST, "file exists")
	EXDEV   = new(linux.EXDEV, "cross-device link")
	ENODEV  = new(linux.ENODEV, "no such device")
	ENOTDIR = new(linux.ENOTDIR, "not a directory")
	EISDIR  = new(linux.EISDIR, "is a directory")
	EINVAL  = new(linux.EINVAL, "invalid argument")
	ENFILE  = new(linux.ENFILE, "file table overflow")
	EMFILE  = new(linux.EMFILE, "too many open files")
	ENOTTY  = new(linux.ENOTTY, "not a typewriter")
	ETXTBSY = new(linux.ETXTBSY, "text file busy")
	EFBIG   = new(linux.EFBIG, "file too large")
	ENOSPC  = new(linux.ENOSPC, "no space left on device")
	ESPIPE  = new(linux.ESPIPE, "illegal seek")
	EROFS   = new(linux.EROFS, "read-only file system")
	EMLINK  = new(linux.EMLINK, "too many links")
	EPIPE   = new(linux.EPIPE, "broken pipe")
	EDOM    = new(linux.EDOM, "math argument out of domain of func")
	ERANGE  = new(linux.ERANGE, "math result not representable")
)

// Errno values from include/uapi/asm-generic/errno.h.
var (
	EDEADLK         = new(linux.EDEADLK, "resource deadlock would occur")
	ENAMETOOLONG    = new(linux.ENAMETOOLONG, "file name too long")
	ENOLCK          = new(linux.ENOLCK, "no record locks available")
	ENOSYS          = new(linux.ENOSYS, "invalid system call number")
	ENOTEMPTY       = new(linux.ENOTEMPTY, "directory not empty")
	ELOOP           = new(linux.ELOOP, "too many symbolic links encountered")
	EWOULDBLOCK     = new(linux.EWOULDBLOCK, "operation would block")
	ENOMSG          = new(linux.ENOMSG, "no message of desired type")
	EIDRM           = new(linux.EIDRM, "identifier removed")
	ECHRNG          = new(linux.ECHRNG, "channel number out of range")
	EL2NSYNC        = new(linux.EL2NSYNC, "level 2 not synchronized")
	EL3HLT          = new(linux.EL3HLT, "level 3 halted")
	EL3RST          = new(linux.EL3RST, "level 3 reset")
	ELNRNG          = new(linux.ELNRNG, "link number out of range")
	EUNATCH         = new(linux.EUNATCH, "protocol driver not attached")
	ENOCSI          = new(linux.ENOCSI, "no CSI structure available")
	EL2HLT          = new(linux.EL2HLT, "level 2 halted")
	EBADE           = new(linux.EBADE, "invalid exchange")
	EBADR           = new(linux.EBADR, "invalid request descriptor")
	EXFULL          = new(linux.EXFULL, "exchange full")
	ENOANO          = new(linux.ENOANO, "no anode")
	EBADRQC         = new(linux.EBADRQC, "invalid request code")
	EBADSLT         = new(linux.EBADSLT, "invalid slot")
	EDEADLOCK       = new(linux.EDEADLOCK, EDEADLK.message)
	EBFONT          = new(linux.EBFONT, "bad font file format")
	ENOSTR          = new(linux.ENOSTR, "device not a stream")
	ENODATA         = new(linux.ENODATA, "no data available")
	ETIME           = new(linux.ETIME, "timer expired")
	ENOSR           = new(linux.ENOSR, "out of streams resources")
	ENONET          = new(linux.ENOENT, "machine is not on the network")
	ENOPKG          = new(linux.ENOPKG, "package not installed")
	EREMOTE         = new(linux.EREMOTE, "object is remote")
	ENOLINK         = new(linux.ENOLINK, "link has been severed")
	EADV            = new(linux.EADV, "advertise error")
	ESRMNT          = new(linux.ESRMNT, "srmount error")
	ECOMM           = new(linux.ECOMM, "communication error on send")
	EPROTO          = new(linux.EPROTO, "protocol error")
	EMULTIHOP       = new(linux.EMULTIHOP, "multihop attempted")
	EDOTDOT         = new(linux.EDOTDOT, "RFS specific error")
	EBADMSG         = new(linux.EBADMSG, "not a data message")
	EOVERFLOW       = new(linux.EOVERFLOW, "value too large for defined data type")
	ENOTUNIQ        = new(linux.ENOTUNIQ, "name not unique on network")
	EBADFD          = new(linux.EBADFD, "file descriptor in bad state")
	EREMCHG         = new(linux.EREMCHG, "remote address changed")
	ELIBACC         = new(linux.ELIBACC, "can not access a needed shared library")
	ELIBBAD         = new(linux.ELIBBAD, "accessing a corrupted shared library")
	ELIBSCN         = new(linux.ELIBSCN, ".lib section in a.out corrupted")
	ELIBMAX         = new(linux.ELIBMAX, "attempting to link in too many shared libraries")
	ELIBEXEC        = new(linux.ELIBEXEC, "cannot exec a shared library directly")
	EILSEQ          = new(linux.EILSEQ, "illegal byte sequence")
	ERESTART        = new(linux.ERESTART, "interrupted system call should be restarted")
	ESTRPIPE        = new(linux.ESTRPIPE, "streams pipe error")
	EUSERS          = new(linux.EUSERS, "too many users")
	ENOTSOCK        = new(linux.ENOTSOCK, "socket operation on non-socket")
	EDESTADDRREQ    = new(linux.EDESTADDRREQ, "destination address required")
	EMSGSIZE        = new(linux.EMSGSIZE, "message too long")
	EPROTOTYPE      = new(linux.EPROTOTYPE, "protocol wrong type for socket")
	ENOPROTOOPT     = new(linux.ENOPROTOOPT, "protocol not available")
	EPROTONOSUPPORT = new(linux.EPROTONOSUPPORT, "protocol not supported")
	ESOCKTNOSUPPORT = new(linux.ESOCKTNOSUPPORT, "socket type not supported")
	EOPNOTSUPP      = new(linux.EOPNOTSUPP, "operation not supported on transport endpoint")
	EPFNOSUPPORT    = new(linux.EPFNOSUPPORT, "protocol family not supported")
	EAFNOSUPPORT    = new(linux.EAFNOSUPPORT, "address family not supported by protocol")
	EADDRINUSE      = new(linux.EADDRINUSE, "address already in use")
	EADDRNOTAVAIL   = new(linux.EADDRNOTAVAIL, "cannot assign requested address")
	ENETDOWN        = new(linux.ENETDOWN, "network is down")
	ENETUNREACH     = new(linux.ENETUNREACH, "network is unreachable")
	ENETRESET       = new(linux.ENETRESET, "network dropped connection because of reset")
	ECONNABORTED    = new(linux.ECONNABORTED, "software caused connection abort")
	ECONNRESET      = new(linux.ECONNRESET, "connection reset by peer")
	ENOBUFS         = new(linux.ENOBUFS, "no buffer space available")
	EISCONN         = new(linux.EISCONN, "transport endpoint is already connected")
	ENOTCONN        = new(linux.ENOTCONN, "transport endpoint is not connected")
	ESHUTDOWN       = new(linux.ESHUTDOWN, "cannot send after transport endpoint shutdown")
	ETOOMANYREFS    = new(linux.ETOOMANYREFS, "too many references: cannot splice")
	ETIMEDOUT       = new(linux.ETIMEDOUT, "connection timed out")
	ECONNREFUSED    = new(linux.ECONNREFUSED, "connection refused")
	EHOSTDOWN       = new(linux.EHOSTDOWN, "host is down")
	EHOSTUNREACH    = new(linux.EHOSTUNREACH, "no route to host")
	EALREADY        = new(linux.EALREADY, "operation already in progress")
	EINPROGRESS     = new(linux.EINPROGRESS, "operation now in progress")
	ESTALE          = new(linux.ESTALE, "stale file handle")
	EUCLEAN         = new(linux.EUCLEAN, "structure needs cleaning")
	ENOTNAM         = new(linux.ENOTNAM, "not a XENIX named type file")
	ENAVAIL         = new(linux.ENAVAIL, "no XENIX semaphores available")
	EISNAM          = new(linux.EISNAM, "is a named type file")
	EREMOTEIO       = new(linux.EREMOTEIO, "remote I/O error")
	EDQUOT          = new(linux.EDQUOT, "quota exceeded")
	ENOMEDIUM       = new(linux.ENOMEDIUM, "no medium found")
	EMEDIUMTYPE     = new(linux.EMEDIUMTYPE, "wrong medium type")
	ECANCELED       = new(linux.ECANCELED, "operation Canceled")
	ENOKEY          = new(linux.ENOKEY, "required key not available")
	EKEYEXPIRED     = new(linux.EKEYEXPIRED, "key has expired")
	EKEYREVOKED     = new(linux.EKEYREVOKED, "key has been revoked")
	EKEYREJECTED    = new(linux.EKEYREJECTED, "key was rejected by service")
	EOWNERDEAD      = new(linux.EOWNERDEAD, "owner died")
	ENOTRECOVERABLE = new(linux.ENOTRECOVERABLE, "state not recoverable")
	ERFKILL         = new(linux.ERFKILL, "operation not possible due to RF-kill")
	EHWPOISON       = new(linux.EHWPOISON, "memory page has hardware error")
)
