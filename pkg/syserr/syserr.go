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

// Package syserr contains sandbox-internal errors. These errors are distinct
// from both the errors returned by host system calls and the errors returned
// to sandboxed applications.
package syserr

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux/errno"
	"gvisor.dev/gvisor/pkg/errors"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/safecopy"
)

// Error represents an internal error.
type Error struct {
	// message is the human readable form of this Error.
	message string

	// noTranslation indicates that this Error cannot be translated to a
	// errno.Errno.
	noTranslation bool

	// errno is the errno.Errno this Error should be translated to.
	errno errno.Errno
}

// New creates a new Error and adds a translation for it.
//
// New must only be called at init.
func New(message string, linuxTranslation errno.Errno) *Error {
	err := &Error{message: message, errno: linuxTranslation}

	// TODO(b/34162363): Remove this.
	if int(err.errno) >= len(linuxBackwardsTranslations) {
		panic(fmt.Sprint("invalid errno: ", err.errno))
	}

	e := error(unix.Errno(err.errno))
	// linuxerr.ErrWouldBlock gets translated to linuxerr.EWOULDBLOCK and
	// enables proper blocking semantics. This should temporary address the
	// class of blocking bugs that keep popping up with the current state of
	// the error space.
	if err.errno == linuxerr.EWOULDBLOCK.Errno() {
		e = linuxerr.ErrWouldBlock
	}
	linuxBackwardsTranslations[err.errno] = linuxBackwardsTranslation{err: e, ok: true}

	return err
}

// NewDynamic creates a new error with a dynamic error message and an errno
// translation.
//
// NewDynamic should only be used sparingly and not be used for static error
// messages. Errors with static error messages should be declared with New as
// global variables.
func NewDynamic(message string, linuxTranslation errno.Errno) *Error {
	return &Error{message: message, errno: linuxTranslation}
}

func newWithHost(message string, linuxTranslation errno.Errno, hostErrno unix.Errno) *Error {
	e := New(message, linuxTranslation)
	addHostTranslation(hostErrno, e)
	return e
}

// String implements fmt.Stringer.String.
func (e *Error) String() string {
	if e == nil {
		return "<nil>"
	}
	return e.message
}

type linuxBackwardsTranslation struct {
	err error
	ok  bool
}

// TODO(b/34162363): Remove this.
var linuxBackwardsTranslations [maxErrno]linuxBackwardsTranslation

// ToError translates an Error to a corresponding error value.
//
// TODO(b/34162363): Remove this.
func (e *Error) ToError() error {
	if e == nil {
		return nil
	}
	if e.noTranslation {
		panic(fmt.Sprintf("error %q does not support translation", e.message))
	}
	err := int(e.errno)
	if err == errno.NOERRNO {
		return nil
	}
	if err >= len(linuxBackwardsTranslations) || !linuxBackwardsTranslations[err].ok {
		panic(fmt.Sprintf("unknown error %q (%d)", e.message, err))
	}
	return linuxBackwardsTranslations[err].err
}

// ToLinux converts the Error to a Linux ABI error that can be returned to the
// application.
func (e *Error) ToLinux() errno.Errno {
	if e.noTranslation {
		panic(fmt.Sprintf("No Linux ABI translation available for %q", e.message))
	}
	return e.errno
}

// TODO(b/34162363): Remove or replace most of these errors.
//
// Some of the errors should be replaced with package specific errors and
// others should be removed entirely.
//
// Note that some errors are declared in platform-specific files.
var (
	ErrNotPermitted               = newWithHost("operation not permitted", errno.EPERM, unix.EPERM)
	ErrNoFileOrDir                = newWithHost("no such file or directory", errno.ENOENT, unix.ENOENT)
	ErrNoProcess                  = newWithHost("no such process", errno.ESRCH, unix.ESRCH)
	ErrInterrupted                = newWithHost("interrupted system call", errno.EINTR, unix.EINTR)
	ErrIO                         = newWithHost("I/O error", errno.EIO, unix.EIO)
	ErrDeviceOrAddress            = newWithHost("no such device or address", errno.ENXIO, unix.ENXIO)
	ErrTooManyArgs                = newWithHost("argument list too long", errno.E2BIG, unix.E2BIG)
	ErrEcec                       = newWithHost("exec format error", errno.ENOEXEC, unix.ENOEXEC)
	ErrBadFD                      = newWithHost("bad file number", errno.EBADF, unix.EBADF)
	ErrNoChild                    = newWithHost("no child processes", errno.ECHILD, unix.ECHILD)
	ErrTryAgain                   = newWithHost("try again", errno.EAGAIN, unix.EAGAIN)
	ErrNoMemory                   = newWithHost("out of memory", errno.ENOMEM, unix.ENOMEM)
	ErrPermissionDenied           = newWithHost("permission denied", errno.EACCES, unix.EACCES)
	ErrBadAddress                 = newWithHost("bad address", errno.EFAULT, unix.EFAULT)
	ErrNotBlockDevice             = newWithHost("block device required", errno.ENOTBLK, unix.ENOTBLK)
	ErrBusy                       = newWithHost("device or resource busy", errno.EBUSY, unix.EBUSY)
	ErrExists                     = newWithHost("file exists", errno.EEXIST, unix.EEXIST)
	ErrCrossDeviceLink            = newWithHost("cross-device link", errno.EXDEV, unix.EXDEV)
	ErrNoDevice                   = newWithHost("no such device", errno.ENODEV, unix.ENODEV)
	ErrNotDir                     = newWithHost("not a directory", errno.ENOTDIR, unix.ENOTDIR)
	ErrIsDir                      = newWithHost("is a directory", errno.EISDIR, unix.EISDIR)
	ErrInvalidArgument            = newWithHost("invalid argument", errno.EINVAL, unix.EINVAL)
	ErrFileTableOverflow          = newWithHost("file table overflow", errno.ENFILE, unix.ENFILE)
	ErrTooManyOpenFiles           = newWithHost("too many open files", errno.EMFILE, unix.EMFILE)
	ErrNotTTY                     = newWithHost("not a typewriter", errno.ENOTTY, unix.ENOTTY)
	ErrTestFileBusy               = newWithHost("text file busy", errno.ETXTBSY, unix.ETXTBSY)
	ErrFileTooBig                 = newWithHost("file too large", errno.EFBIG, unix.EFBIG)
	ErrNoSpace                    = newWithHost("no space left on device", errno.ENOSPC, unix.ENOSPC)
	ErrIllegalSeek                = newWithHost("illegal seek", errno.ESPIPE, unix.ESPIPE)
	ErrReadOnlyFS                 = newWithHost("read-only file system", errno.EROFS, unix.EROFS)
	ErrTooManyLinks               = newWithHost("too many links", errno.EMLINK, unix.EMLINK)
	ErrBrokenPipe                 = newWithHost("broken pipe", errno.EPIPE, unix.EPIPE)
	ErrDomain                     = newWithHost("math argument out of domain of func", errno.EDOM, unix.EDOM)
	ErrRange                      = newWithHost("math result not representable", errno.ERANGE, unix.ERANGE)
	ErrNameTooLong                = newWithHost("file name too long", errno.ENAMETOOLONG, unix.ENAMETOOLONG)
	ErrNoLocksAvailable           = newWithHost("no record locks available", errno.ENOLCK, unix.ENOLCK)
	ErrInvalidSyscall             = newWithHost("invalid system call number", errno.ENOSYS, unix.ENOSYS)
	ErrDirNotEmpty                = newWithHost("directory not empty", errno.ENOTEMPTY, unix.ENOTEMPTY)
	ErrLinkLoop                   = newWithHost("too many symbolic links encountered", errno.ELOOP, unix.ELOOP)
	ErrNoMessage                  = newWithHost("no message of desired type", errno.ENOMSG, unix.ENOMSG)
	ErrIdentifierRemoved          = newWithHost("identifier removed", errno.EIDRM, unix.EIDRM)
	ErrNotStream                  = newWithHost("device not a stream", errno.ENOSTR, unix.ENOSTR)
	ErrNoDataAvailable            = newWithHost("no data available", errno.ENODATA, unix.ENODATA)
	ErrTimerExpired               = newWithHost("timer expired", errno.ETIME, unix.ETIME)
	ErrStreamsResourceDepleted    = newWithHost("out of streams resources", errno.ENOSR, unix.ENOSR)
	ErrIsRemote                   = newWithHost("object is remote", errno.EREMOTE, unix.EREMOTE)
	ErrNoLink                     = newWithHost("link has been severed", errno.ENOLINK, unix.ENOLINK)
	ErrProtocol                   = newWithHost("protocol error", errno.EPROTO, unix.EPROTO)
	ErrMultihopAttempted          = newWithHost("multihop attempted", errno.EMULTIHOP, unix.EMULTIHOP)
	ErrInvalidDataMessage         = newWithHost("not a data message", errno.EBADMSG, unix.EBADMSG)
	ErrOverflow                   = newWithHost("value too large for defined data type", errno.EOVERFLOW, unix.EOVERFLOW)
	ErrIllegalByteSequence        = newWithHost("illegal byte sequence", errno.EILSEQ, unix.EILSEQ)
	ErrTooManyUsers               = newWithHost("too many users", errno.EUSERS, unix.EUSERS)
	ErrNotASocket                 = newWithHost("socket operation on non-socket", errno.ENOTSOCK, unix.ENOTSOCK)
	ErrDestinationAddressRequired = newWithHost("destination address required", errno.EDESTADDRREQ, unix.EDESTADDRREQ)
	ErrMessageTooLong             = newWithHost("message too long", errno.EMSGSIZE, unix.EMSGSIZE)
	ErrWrongProtocolForSocket     = newWithHost("protocol wrong type for socket", errno.EPROTOTYPE, unix.EPROTOTYPE)
	ErrProtocolNotAvailable       = newWithHost("protocol not available", errno.ENOPROTOOPT, unix.ENOPROTOOPT)
	ErrProtocolNotSupported       = newWithHost("protocol not supported", errno.EPROTONOSUPPORT, unix.EPROTONOSUPPORT)
	ErrSocketNotSupported         = newWithHost("socket type not supported", errno.ESOCKTNOSUPPORT, unix.ESOCKTNOSUPPORT)
	ErrEndpointOperation          = newWithHost("operation not supported on transport endpoint", errno.EOPNOTSUPP, unix.EOPNOTSUPP)
	ErrProtocolFamilyNotSupported = newWithHost("protocol family not supported", errno.EPFNOSUPPORT, unix.EPFNOSUPPORT)
	ErrAddressFamilyNotSupported  = newWithHost("address family not supported by protocol", errno.EAFNOSUPPORT, unix.EAFNOSUPPORT)
	ErrAddressInUse               = newWithHost("address already in use", errno.EADDRINUSE, unix.EADDRINUSE)
	ErrAddressNotAvailable        = newWithHost("cannot assign requested address", errno.EADDRNOTAVAIL, unix.EADDRNOTAVAIL)
	ErrNetworkDown                = newWithHost("network is down", errno.ENETDOWN, unix.ENETDOWN)
	ErrNetworkUnreachable         = newWithHost("network is unreachable", errno.ENETUNREACH, unix.ENETUNREACH)
	ErrNetworkReset               = newWithHost("network dropped connection because of reset", errno.ENETRESET, unix.ENETRESET)
	ErrConnectionAborted          = newWithHost("software caused connection abort", errno.ECONNABORTED, unix.ECONNABORTED)
	ErrConnectionReset            = newWithHost("connection reset by peer", errno.ECONNRESET, unix.ECONNRESET)
	ErrNoBufferSpace              = newWithHost("no buffer space available", errno.ENOBUFS, unix.ENOBUFS)
	ErrAlreadyConnected           = newWithHost("transport endpoint is already connected", errno.EISCONN, unix.EISCONN)
	ErrNotConnected               = newWithHost("transport endpoint is not connected", errno.ENOTCONN, unix.ENOTCONN)
	ErrShutdown                   = newWithHost("cannot send after transport endpoint shutdown", errno.ESHUTDOWN, unix.ESHUTDOWN)
	ErrTooManyRefs                = newWithHost("too many references: cannot splice", errno.ETOOMANYREFS, unix.ETOOMANYREFS)
	ErrTimedOut                   = newWithHost("connection timed out", errno.ETIMEDOUT, unix.ETIMEDOUT)
	ErrConnectionRefused          = newWithHost("connection refused", errno.ECONNREFUSED, unix.ECONNREFUSED)
	ErrHostDown                   = newWithHost("host is down", errno.EHOSTDOWN, unix.EHOSTDOWN)
	ErrHostUnreachable            = newWithHost("no route to host", errno.EHOSTUNREACH, unix.EHOSTUNREACH)
	ErrAlreadyInProgress          = newWithHost("operation already in progress", errno.EALREADY, unix.EALREADY)
	ErrInProgress                 = newWithHost("operation now in progress", errno.EINPROGRESS, unix.EINPROGRESS)
	ErrStaleFileHandle            = newWithHost("stale file handle", errno.ESTALE, unix.ESTALE)
	ErrQuotaExceeded              = newWithHost("quota exceeded", errno.EDQUOT, unix.EDQUOT)
	ErrCanceled                   = newWithHost("operation canceled", errno.ECANCELED, unix.ECANCELED)
	ErrOwnerDied                  = newWithHost("owner died", errno.EOWNERDEAD, unix.EOWNERDEAD)
	ErrNotRecoverable             = newWithHost("state not recoverable", errno.ENOTRECOVERABLE, unix.ENOTRECOVERABLE)

	// ErrWouldBlock translates to EWOULDBLOCK which is the same as EAGAIN
	// on Linux.
	ErrWouldBlock = New("operation would block", errno.EWOULDBLOCK)
)

// FromError converts a generic error to an *Error.
//
// TODO(b/34162363): Remove this function.
func FromError(err error) *Error {
	if err == nil {
		return nil
	}

	switch e := err.(type) {
	case unix.Errno:
		return FromHost(e)
	case *errors.Error:
		return FromHost(unix.Errno(e.Errno()))
	case safecopy.SegvError, safecopy.BusError, safecopy.AlignmentError:
		return FromHost(unix.EFAULT)
	}

	msg := fmt.Sprintf("err: %s type: %T", err.Error(), err)
	panic(msg)
}
