// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"),;
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
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux/errno"
	"gvisor.dev/gvisor/pkg/errors"
)

const maxErrno uint32 = errno.EHWPOISON + 1

// The following errors are semantically identical to Errno of type unix.Errno
// or sycall.Errno. However, since the type are distinct ( these are
// *errors.Error), they are not directly comperable. However, the Errno method
// returns an Errno number such that the error can be compared to unix/syscall.Errno
// (e.g. unix.Errno(EPERM.Errno()) == unix.EPERM is true). Converting unix/syscall.Errno
// to the errors should be done via the lookup methods provided.
var (
	noError *errors.Error = nil
	EPERM                 = errors.New(errno.EPERM, "operation not permitted")
	ENOENT                = errors.New(errno.ENOENT, "no such file or directory")
	ESRCH                 = errors.New(errno.ESRCH, "no such process")
	EINTR                 = errors.New(errno.EINTR, "interrupted system call")
	EIO                   = errors.New(errno.EIO, "I/O error")
	ENXIO                 = errors.New(errno.ENXIO, "no such device or address")
	E2BIG                 = errors.New(errno.E2BIG, "argument list too long")
	ENOEXEC               = errors.New(errno.ENOEXEC, "exec format error")
	EBADF                 = errors.New(errno.EBADF, "bad file number")
	ECHILD                = errors.New(errno.ECHILD, "no child processes")
	EAGAIN                = errors.New(errno.EAGAIN, "try again")
	ENOMEM                = errors.New(errno.ENOMEM, "out of memory")
	EACCES                = errors.New(errno.EACCES, "permission denied")
	EFAULT                = errors.New(errno.EFAULT, "bad address")
	ENOTBLK               = errors.New(errno.ENOTBLK, "block device required")
	EBUSY                 = errors.New(errno.EBUSY, "device or resource busy")
	EEXIST                = errors.New(errno.EEXIST, "file exists")
	EXDEV                 = errors.New(errno.EXDEV, "cross-device link")
	ENODEV                = errors.New(errno.ENODEV, "no such device")
	ENOTDIR               = errors.New(errno.ENOTDIR, "not a directory")
	EISDIR                = errors.New(errno.EISDIR, "is a directory")
	EINVAL                = errors.New(errno.EINVAL, "invalid argument")
	ENFILE                = errors.New(errno.ENFILE, "file table overflow")
	EMFILE                = errors.New(errno.EMFILE, "too many open files")
	ENOTTY                = errors.New(errno.ENOTTY, "not a typewriter")
	ETXTBSY               = errors.New(errno.ETXTBSY, "text file busy")
	EFBIG                 = errors.New(errno.EFBIG, "file too large")
	ENOSPC                = errors.New(errno.ENOSPC, "no space left on device")
	ESPIPE                = errors.New(errno.ESPIPE, "illegal seek")
	EROFS                 = errors.New(errno.EROFS, "read-only file system")
	EMLINK                = errors.New(errno.EMLINK, "too many links")
	EPIPE                 = errors.New(errno.EPIPE, "broken pipe")
	EDOM                  = errors.New(errno.EDOM, "math argument out of domain of func")
	ERANGE                = errors.New(errno.ERANGE, "math result not representable")

	// Errno values from include/uapi/asm-generic/errno.h.
	EDEADLK         = errors.New(errno.EDEADLK, "resource deadlock would occur")
	ENAMETOOLONG    = errors.New(errno.ENAMETOOLONG, "file name too long")
	ENOLCK          = errors.New(errno.ENOLCK, "no record locks available")
	ENOSYS          = errors.New(errno.ENOSYS, "invalid system call number")
	ENOTEMPTY       = errors.New(errno.ENOTEMPTY, "directory not empty")
	ELOOP           = errors.New(errno.ELOOP, "too many symbolic links encountered")
	ENOMSG          = errors.New(errno.ENOMSG, "no message of desired type")
	EIDRM           = errors.New(errno.EIDRM, "identifier removed")
	ECHRNG          = errors.New(errno.ECHRNG, "channel number out of range")
	EL2NSYNC        = errors.New(errno.EL2NSYNC, "level 2 not synchronized")
	EL3HLT          = errors.New(errno.EL3HLT, "level 3 halted")
	EL3RST          = errors.New(errno.EL3RST, "level 3 reset")
	ELNRNG          = errors.New(errno.ELNRNG, "link number out of range")
	EUNATCH         = errors.New(errno.EUNATCH, "protocol driver not attached")
	ENOCSI          = errors.New(errno.ENOCSI, "no CSI structure available")
	EL2HLT          = errors.New(errno.EL2HLT, "level 2 halted")
	EBADE           = errors.New(errno.EBADE, "invalid exchange")
	EBADR           = errors.New(errno.EBADR, "invalid request descriptor")
	EXFULL          = errors.New(errno.EXFULL, "exchange full")
	ENOANO          = errors.New(errno.ENOANO, "no anode")
	EBADRQC         = errors.New(errno.EBADRQC, "invalid request code")
	EBADSLT         = errors.New(errno.EBADSLT, "invalid slot")
	EBFONT          = errors.New(errno.EBFONT, "bad font file format")
	ENOSTR          = errors.New(errno.ENOSTR, "device not a stream")
	ENODATA         = errors.New(errno.ENODATA, "no data available")
	ETIME           = errors.New(errno.ETIME, "timer expired")
	ENOSR           = errors.New(errno.ENOSR, "out of streams resources")
	ENOPKG          = errors.New(errno.ENOPKG, "package not installed")
	EREMOTE         = errors.New(errno.EREMOTE, "object is remote")
	ENOLINK         = errors.New(errno.ENOLINK, "link has been severed")
	EADV            = errors.New(errno.EADV, "advertise error")
	ESRMNT          = errors.New(errno.ESRMNT, "srmount error")
	ECOMM           = errors.New(errno.ECOMM, "communication error on send")
	EPROTO          = errors.New(errno.EPROTO, "protocol error")
	EMULTIHOP       = errors.New(errno.EMULTIHOP, "multihop attempted")
	EDOTDOT         = errors.New(errno.EDOTDOT, "RFS specific error")
	EBADMSG         = errors.New(errno.EBADMSG, "not a data message")
	EOVERFLOW       = errors.New(errno.EOVERFLOW, "value too large for defined data type")
	ENOTUNIQ        = errors.New(errno.ENOTUNIQ, "name not unique on network")
	EBADFD          = errors.New(errno.EBADFD, "file descriptor in bad state")
	EREMCHG         = errors.New(errno.EREMCHG, "remote address changed")
	ELIBACC         = errors.New(errno.ELIBACC, "can not access a needed shared library")
	ELIBBAD         = errors.New(errno.ELIBBAD, "accessing a corrupted shared library")
	ELIBSCN         = errors.New(errno.ELIBSCN, ".lib section in a.out corrupted")
	ELIBMAX         = errors.New(errno.ELIBMAX, "attempting to link in too many shared libraries")
	ELIBEXEC        = errors.New(errno.ELIBEXEC, "cannot exec a shared library directly")
	EILSEQ          = errors.New(errno.EILSEQ, "illegal byte sequence")
	ERESTART        = errors.New(errno.ERESTART, "interrupted system call should be restarted")
	ESTRPIPE        = errors.New(errno.ESTRPIPE, "streams pipe error")
	EUSERS          = errors.New(errno.EUSERS, "too many users")
	ENOTSOCK        = errors.New(errno.ENOTSOCK, "socket operation on non-socket")
	EDESTADDRREQ    = errors.New(errno.EDESTADDRREQ, "destination address required")
	EMSGSIZE        = errors.New(errno.EMSGSIZE, "message too long")
	EPROTOTYPE      = errors.New(errno.EPROTOTYPE, "protocol wrong type for socket")
	ENOPROTOOPT     = errors.New(errno.ENOPROTOOPT, "protocol not available")
	EPROTONOSUPPORT = errors.New(errno.EPROTONOSUPPORT, "protocol not supported")
	ESOCKTNOSUPPORT = errors.New(errno.ESOCKTNOSUPPORT, "socket type not supported")
	EOPNOTSUPP      = errors.New(errno.EOPNOTSUPP, "operation not supported on transport endpoint")
	EPFNOSUPPORT    = errors.New(errno.EPFNOSUPPORT, "protocol family not supported")
	EAFNOSUPPORT    = errors.New(errno.EAFNOSUPPORT, "address family not supported by protocol")
	EADDRINUSE      = errors.New(errno.EADDRINUSE, "address already in use")
	EADDRNOTAVAIL   = errors.New(errno.EADDRNOTAVAIL, "cannot assign requested address")
	ENETDOWN        = errors.New(errno.ENETDOWN, "network is down")
	ENETUNREACH     = errors.New(errno.ENETUNREACH, "network is unreachable")
	ENETRESET       = errors.New(errno.ENETRESET, "network dropped connection because of reset")
	ECONNABORTED    = errors.New(errno.ECONNABORTED, "software caused connection abort")
	ECONNRESET      = errors.New(errno.ECONNRESET, "connection reset by peer")
	ENOBUFS         = errors.New(errno.ENOBUFS, "no buffer space available")
	EISCONN         = errors.New(errno.EISCONN, "transport endpoint is already connected")
	ENOTCONN        = errors.New(errno.ENOTCONN, "transport endpoint is not connected")
	ESHUTDOWN       = errors.New(errno.ESHUTDOWN, "cannot send after transport endpoint shutdown")
	ETOOMANYREFS    = errors.New(errno.ETOOMANYREFS, "too many references: cannot splice")
	ETIMEDOUT       = errors.New(errno.ETIMEDOUT, "connection timed out")
	ECONNREFUSED    = errors.New(errno.ECONNREFUSED, "connection refused")
	EHOSTDOWN       = errors.New(errno.EHOSTDOWN, "host is down")
	EHOSTUNREACH    = errors.New(errno.EHOSTUNREACH, "no route to host")
	EALREADY        = errors.New(errno.EALREADY, "operation already in progress")
	EINPROGRESS     = errors.New(errno.EINPROGRESS, "operation now in progress")
	ESTALE          = errors.New(errno.ESTALE, "stale file handle")
	EUCLEAN         = errors.New(errno.EUCLEAN, "structure needs cleaning")
	ENOTNAM         = errors.New(errno.ENOTNAM, "not a XENIX named type file")
	ENAVAIL         = errors.New(errno.ENAVAIL, "no XENIX semaphores available")
	EISNAM          = errors.New(errno.EISNAM, "is a named type file")
	EREMOTEIO       = errors.New(errno.EREMOTEIO, "remote I/O error")
	EDQUOT          = errors.New(errno.EDQUOT, "quota exceeded")
	ENOMEDIUM       = errors.New(errno.ENOMEDIUM, "no medium found")
	EMEDIUMTYPE     = errors.New(errno.EMEDIUMTYPE, "wrong medium type")
	ECANCELED       = errors.New(errno.ECANCELED, "operation Canceled")
	ENOKEY          = errors.New(errno.ENOKEY, "required key not available")
	EKEYEXPIRED     = errors.New(errno.EKEYEXPIRED, "key has expired")
	EKEYREVOKED     = errors.New(errno.EKEYREVOKED, "key has been revoked")
	EKEYREJECTED    = errors.New(errno.EKEYREJECTED, "key was rejected by service")
	EOWNERDEAD      = errors.New(errno.EOWNERDEAD, "owner died")
	ENOTRECOVERABLE = errors.New(errno.ENOTRECOVERABLE, "state not recoverable")
	ERFKILL         = errors.New(errno.ERFKILL, "operation not possible due to RF-kill")
	EHWPOISON       = errors.New(errno.EHWPOISON, "memory page has hardware error")

	// Errors equivalent to other errors.
	EWOULDBLOCK = EAGAIN
	EDEADLOCK   = EDEADLK
	ENONET      = ENOENT
	ENOATTR     = ENODATA
	ENOTSUP     = EOPNOTSUPP
)

// A nil *errors.Error denotes no error and is placed at the 0 index of
// errorSlice. Thus, any other empty index should not be nil or a valid error.
// This marks that index as an invalid error so any comparison to nil or a
// valid linuxerr fails.
var errNotValidError = errors.New(errno.Errno(maxErrno), "not a valid error")

// The following errorSlice holds errors by errno for fast translation between
// errnos (especially uint32(sycall.Errno)) and *errors.Error.
var errorSlice = []*errors.Error{
	// Errno values from include/uapi/asm-generic/errno-base.h.
	errno.NOERRNO: noError,
	errno.EPERM:   EPERM,
	errno.ENOENT:  ENOENT,
	errno.ESRCH:   ESRCH,
	errno.EINTR:   EINTR,
	errno.EIO:     EIO,
	errno.ENXIO:   ENXIO,
	errno.E2BIG:   E2BIG,
	errno.ENOEXEC: ENOEXEC,
	errno.EBADF:   EBADF,
	errno.ECHILD:  ECHILD,
	errno.EAGAIN:  EAGAIN,
	errno.ENOMEM:  ENOMEM,
	errno.EACCES:  EACCES,
	errno.EFAULT:  EFAULT,
	errno.ENOTBLK: ENOTBLK,
	errno.EBUSY:   EBUSY,
	errno.EEXIST:  EEXIST,
	errno.EXDEV:   EXDEV,
	errno.ENODEV:  ENODEV,
	errno.ENOTDIR: ENOTDIR,
	errno.EISDIR:  EISDIR,
	errno.EINVAL:  EINVAL,
	errno.ENFILE:  ENFILE,
	errno.EMFILE:  EMFILE,
	errno.ENOTTY:  ENOTTY,
	errno.ETXTBSY: ETXTBSY,
	errno.EFBIG:   EFBIG,
	errno.ENOSPC:  ENOSPC,
	errno.ESPIPE:  ESPIPE,
	errno.EROFS:   EROFS,
	errno.EMLINK:  EMLINK,
	errno.EPIPE:   EPIPE,
	errno.EDOM:    EDOM,
	errno.ERANGE:  ERANGE,

	// Errno values from include/uapi/asm-generic/errno.h.
	errno.EDEADLK:         EDEADLK,
	errno.ENAMETOOLONG:    ENAMETOOLONG,
	errno.ENOLCK:          ENOLCK,
	errno.ENOSYS:          ENOSYS,
	errno.ENOTEMPTY:       ENOTEMPTY,
	errno.ELOOP:           ELOOP,
	errno.ELOOP + 1:       errNotValidError, // No valid errno between ELOOP and ENOMSG.
	errno.ENOMSG:          ENOMSG,
	errno.EIDRM:           EIDRM,
	errno.ECHRNG:          ECHRNG,
	errno.EL2NSYNC:        EL2NSYNC,
	errno.EL3HLT:          EL3HLT,
	errno.EL3RST:          EL3RST,
	errno.ELNRNG:          ELNRNG,
	errno.EUNATCH:         EUNATCH,
	errno.ENOCSI:          ENOCSI,
	errno.EL2HLT:          EL2HLT,
	errno.EBADE:           EBADE,
	errno.EBADR:           EBADR,
	errno.EXFULL:          EXFULL,
	errno.ENOANO:          ENOANO,
	errno.EBADRQC:         EBADRQC,
	errno.EBADSLT:         EBADSLT,
	errno.EBADSLT + 1:     errNotValidError, // No valid errno between EBADSLT and ENOPKG.
	errno.EBFONT:          EBFONT,
	errno.ENOSTR:          ENOSTR,
	errno.ENODATA:         ENODATA,
	errno.ETIME:           ETIME,
	errno.ENOSR:           ENOSR,
	errno.ENOSR + 1:       errNotValidError, // No valid errno betweeen ENOSR and ENOPKG.
	errno.ENOPKG:          ENOPKG,
	errno.EREMOTE:         EREMOTE,
	errno.ENOLINK:         ENOLINK,
	errno.EADV:            EADV,
	errno.ESRMNT:          ESRMNT,
	errno.ECOMM:           ECOMM,
	errno.EPROTO:          EPROTO,
	errno.EMULTIHOP:       EMULTIHOP,
	errno.EDOTDOT:         EDOTDOT,
	errno.EBADMSG:         EBADMSG,
	errno.EOVERFLOW:       EOVERFLOW,
	errno.ENOTUNIQ:        ENOTUNIQ,
	errno.EBADFD:          EBADFD,
	errno.EREMCHG:         EREMCHG,
	errno.ELIBACC:         ELIBACC,
	errno.ELIBBAD:         ELIBBAD,
	errno.ELIBSCN:         ELIBSCN,
	errno.ELIBMAX:         ELIBMAX,
	errno.ELIBEXEC:        ELIBEXEC,
	errno.EILSEQ:          EILSEQ,
	errno.ERESTART:        ERESTART,
	errno.ESTRPIPE:        ESTRPIPE,
	errno.EUSERS:          EUSERS,
	errno.ENOTSOCK:        ENOTSOCK,
	errno.EDESTADDRREQ:    EDESTADDRREQ,
	errno.EMSGSIZE:        EMSGSIZE,
	errno.EPROTOTYPE:      EPROTOTYPE,
	errno.ENOPROTOOPT:     ENOPROTOOPT,
	errno.EPROTONOSUPPORT: EPROTONOSUPPORT,
	errno.ESOCKTNOSUPPORT: ESOCKTNOSUPPORT,
	errno.EOPNOTSUPP:      EOPNOTSUPP,
	errno.EPFNOSUPPORT:    EPFNOSUPPORT,
	errno.EAFNOSUPPORT:    EAFNOSUPPORT,
	errno.EADDRINUSE:      EADDRINUSE,
	errno.EADDRNOTAVAIL:   EADDRNOTAVAIL,
	errno.ENETDOWN:        ENETDOWN,
	errno.ENETUNREACH:     ENETUNREACH,
	errno.ENETRESET:       ENETRESET,
	errno.ECONNABORTED:    ECONNABORTED,
	errno.ECONNRESET:      ECONNRESET,
	errno.ENOBUFS:         ENOBUFS,
	errno.EISCONN:         EISCONN,
	errno.ENOTCONN:        ENOTCONN,
	errno.ESHUTDOWN:       ESHUTDOWN,
	errno.ETOOMANYREFS:    ETOOMANYREFS,
	errno.ETIMEDOUT:       ETIMEDOUT,
	errno.ECONNREFUSED:    ECONNREFUSED,
	errno.EHOSTDOWN:       EHOSTDOWN,
	errno.EHOSTUNREACH:    EHOSTUNREACH,
	errno.EALREADY:        EALREADY,
	errno.EINPROGRESS:     EINPROGRESS,
	errno.ESTALE:          ESTALE,
	errno.EUCLEAN:         EUCLEAN,
	errno.ENOTNAM:         ENOTNAM,
	errno.ENAVAIL:         ENAVAIL,
	errno.EISNAM:          EISNAM,
	errno.EREMOTEIO:       EREMOTEIO,
	errno.EDQUOT:          EDQUOT,
	errno.ENOMEDIUM:       ENOMEDIUM,
	errno.EMEDIUMTYPE:     EMEDIUMTYPE,
	errno.ECANCELED:       ECANCELED,
	errno.ENOKEY:          ENOKEY,
	errno.EKEYEXPIRED:     EKEYEXPIRED,
	errno.EKEYREVOKED:     EKEYREVOKED,
	errno.EKEYREJECTED:    EKEYREJECTED,
	errno.EOWNERDEAD:      EOWNERDEAD,
	errno.ENOTRECOVERABLE: ENOTRECOVERABLE,
	errno.ERFKILL:         ERFKILL,
	errno.EHWPOISON:       EHWPOISON,
}

// ErrorFromUnix returns a linuxerr from a unix.Errno.
func ErrorFromUnix(err unix.Errno) error {
	if err == unix.Errno(0) {
		return nil
	}
	e := errorSlice[errno.Errno(err)]
	// Done this way because a single comparison in benchmarks is 2-3 faster
	// than something like ( if err == nil && err > 0 ).
	if e == errNotValidError {
		panic(fmt.Sprintf("invalid error requested with errno: %v", e))
	}
	return e
}

// ToError converts a linuxerr to an error type.
func ToError(err *errors.Error) error {
	if err == noError {
		return nil
	}
	return err
}

// ToUnix converts a linuxerr to a unix.Errno.
func ToUnix(e *errors.Error) unix.Errno {
	var unixErr unix.Errno
	if e != noError {
		unixErr = unix.Errno(e.Errno())
	}
	return unixErr
}

// Equals compars a linuxerr to a given error.
func Equals(e *errors.Error, err error) bool {
	var unixErr unix.Errno
	if e != noError {
		unixErr = unix.Errno(e.Errno())
	}
	if err == nil {
		err = noError
	}
	return e == err || unixErr == err
}
