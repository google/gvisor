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
	"gvisor.dev/gvisor/pkg/syserror"
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
	// syserror.ErrWouldBlock gets translated to syserror.EWOULDBLOCK and
	// enables proper blocking semantics. This should temporary address the
	// class of blocking bugs that keep popping up with the current state of
	// the error space.
	if err.errno == linuxerr.EWOULDBLOCK.Errno() {
		e = syserror.ErrWouldBlock
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

// NewWithoutTranslation creates a new Error. If translation is attempted on
// the error, translation will fail.
//
// NewWithoutTranslation may be called at any time, but static errors should
// be declared as global variables and dynamic errors should be used sparingly.
func NewWithoutTranslation(message string) *Error {
	return &Error{message: message, noTranslation: true}
}

func newWithHost(message string, linuxTranslation errno.Errno, hostErrno unix.Errno) *Error {
	e := New(message, linuxTranslation)
	addLinuxHostTranslation(hostErrno, e)
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
	ErrDeadlock                   = newWithHost("resource deadlock would occur", errno.EDEADLOCK, unix.EDEADLOCK)
	ErrNameTooLong                = newWithHost("file name too long", errno.ENAMETOOLONG, unix.ENAMETOOLONG)
	ErrNoLocksAvailable           = newWithHost("no record locks available", errno.ENOLCK, unix.ENOLCK)
	ErrInvalidSyscall             = newWithHost("invalid system call number", errno.ENOSYS, unix.ENOSYS)
	ErrDirNotEmpty                = newWithHost("directory not empty", errno.ENOTEMPTY, unix.ENOTEMPTY)
	ErrLinkLoop                   = newWithHost("too many symbolic links encountered", errno.ELOOP, unix.ELOOP)
	ErrNoMessage                  = newWithHost("no message of desired type", errno.ENOMSG, unix.ENOMSG)
	ErrIdentifierRemoved          = newWithHost("identifier removed", errno.EIDRM, unix.EIDRM)
	ErrChannelOutOfRange          = newWithHost("channel number out of range", errno.ECHRNG, unix.ECHRNG)
	ErrLevelTwoNotSynced          = newWithHost("level 2 not synchronized", errno.EL2NSYNC, unix.EL2NSYNC)
	ErrLevelThreeHalted           = newWithHost("level 3 halted", errno.EL3HLT, unix.EL3HLT)
	ErrLevelThreeReset            = newWithHost("level 3 reset", errno.EL3RST, unix.EL3RST)
	ErrLinkNumberOutOfRange       = newWithHost("link number out of range", errno.ELNRNG, unix.ELNRNG)
	ErrProtocolDriverNotAttached  = newWithHost("protocol driver not attached", errno.EUNATCH, unix.EUNATCH)
	ErrNoCSIAvailable             = newWithHost("no CSI structure available", errno.ENOCSI, unix.ENOCSI)
	ErrLevelTwoHalted             = newWithHost("level 2 halted", errno.EL2HLT, unix.EL2HLT)
	ErrInvalidExchange            = newWithHost("invalid exchange", errno.EBADE, unix.EBADE)
	ErrInvalidRequestDescriptor   = newWithHost("invalid request descriptor", errno.EBADR, unix.EBADR)
	ErrExchangeFull               = newWithHost("exchange full", errno.EXFULL, unix.EXFULL)
	ErrNoAnode                    = newWithHost("no anode", errno.ENOANO, unix.ENOANO)
	ErrInvalidRequestCode         = newWithHost("invalid request code", errno.EBADRQC, unix.EBADRQC)
	ErrInvalidSlot                = newWithHost("invalid slot", errno.EBADSLT, unix.EBADSLT)
	ErrBadFontFile                = newWithHost("bad font file format", errno.EBFONT, unix.EBFONT)
	ErrNotStream                  = newWithHost("device not a stream", errno.ENOSTR, unix.ENOSTR)
	ErrNoDataAvailable            = newWithHost("no data available", errno.ENODATA, unix.ENODATA)
	ErrTimerExpired               = newWithHost("timer expired", errno.ETIME, unix.ETIME)
	ErrStreamsResourceDepleted    = newWithHost("out of streams resources", errno.ENOSR, unix.ENOSR)
	ErrMachineNotOnNetwork        = newWithHost("machine is not on the network", errno.ENONET, unix.ENONET)
	ErrPackageNotInstalled        = newWithHost("package not installed", errno.ENOPKG, unix.ENOPKG)
	ErrIsRemote                   = newWithHost("object is remote", errno.EREMOTE, unix.EREMOTE)
	ErrNoLink                     = newWithHost("link has been severed", errno.ENOLINK, unix.ENOLINK)
	ErrAdvertise                  = newWithHost("advertise error", errno.EADV, unix.EADV)
	ErrSRMount                    = newWithHost("srmount error", errno.ESRMNT, unix.ESRMNT)
	ErrSendCommunication          = newWithHost("communication error on send", errno.ECOMM, unix.ECOMM)
	ErrProtocol                   = newWithHost("protocol error", errno.EPROTO, unix.EPROTO)
	ErrMultihopAttempted          = newWithHost("multihop attempted", errno.EMULTIHOP, unix.EMULTIHOP)
	ErrRFS                        = newWithHost("RFS specific error", errno.EDOTDOT, unix.EDOTDOT)
	ErrInvalidDataMessage         = newWithHost("not a data message", errno.EBADMSG, unix.EBADMSG)
	ErrOverflow                   = newWithHost("value too large for defined data type", errno.EOVERFLOW, unix.EOVERFLOW)
	ErrNetworkNameNotUnique       = newWithHost("name not unique on network", errno.ENOTUNIQ, unix.ENOTUNIQ)
	ErrFDInBadState               = newWithHost("file descriptor in bad state", errno.EBADFD, unix.EBADFD)
	ErrRemoteAddressChanged       = newWithHost("remote address changed", errno.EREMCHG, unix.EREMCHG)
	ErrSharedLibraryInaccessible  = newWithHost("can not access a needed shared library", errno.ELIBACC, unix.ELIBACC)
	ErrCorruptedSharedLibrary     = newWithHost("accessing a corrupted shared library", errno.ELIBBAD, unix.ELIBBAD)
	ErrLibSectionCorrupted        = newWithHost(".lib section in a.out corrupted", errno.ELIBSCN, unix.ELIBSCN)
	ErrTooManySharedLibraries     = newWithHost("attempting to link in too many shared libraries", errno.ELIBMAX, unix.ELIBMAX)
	ErrSharedLibraryExeced        = newWithHost("cannot exec a shared library directly", errno.ELIBEXEC, unix.ELIBEXEC)
	ErrIllegalByteSequence        = newWithHost("illegal byte sequence", errno.EILSEQ, unix.EILSEQ)
	ErrShouldRestart              = newWithHost("interrupted system call should be restarted", errno.ERESTART, unix.ERESTART)
	ErrStreamPipe                 = newWithHost("streams pipe error", errno.ESTRPIPE, unix.ESTRPIPE)
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
	ErrNoRoute                    = newWithHost("no route to host", errno.EHOSTUNREACH, unix.EHOSTUNREACH)
	ErrAlreadyInProgress          = newWithHost("operation already in progress", errno.EALREADY, unix.EALREADY)
	ErrInProgress                 = newWithHost("operation now in progress", errno.EINPROGRESS, unix.EINPROGRESS)
	ErrStaleFileHandle            = newWithHost("stale file handle", errno.ESTALE, unix.ESTALE)
	ErrStructureNeedsCleaning     = newWithHost("structure needs cleaning", errno.EUCLEAN, unix.EUCLEAN)
	ErrIsNamedFile                = newWithHost("is a named type file", errno.ENOTNAM, unix.ENOTNAM)
	ErrRemoteIO                   = newWithHost("remote I/O error", errno.EREMOTEIO, unix.EREMOTEIO)
	ErrQuotaExceeded              = newWithHost("quota exceeded", errno.EDQUOT, unix.EDQUOT)
	ErrNoMedium                   = newWithHost("no medium found", errno.ENOMEDIUM, unix.ENOMEDIUM)
	ErrWrongMediumType            = newWithHost("wrong medium type", errno.EMEDIUMTYPE, unix.EMEDIUMTYPE)
	ErrCanceled                   = newWithHost("operation canceled", errno.ECANCELED, unix.ECANCELED)
	ErrNoKey                      = newWithHost("required key not available", errno.ENOKEY, unix.ENOKEY)
	ErrKeyExpired                 = newWithHost("key has expired", errno.EKEYEXPIRED, unix.EKEYEXPIRED)
	ErrKeyRevoked                 = newWithHost("key has been revoked", errno.EKEYREVOKED, unix.EKEYREVOKED)
	ErrKeyRejected                = newWithHost("key was rejected by service", errno.EKEYREJECTED, unix.EKEYREJECTED)
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
	if errno, ok := err.(unix.Errno); ok {
		return FromHost(errno)
	}

	if linuxErr, ok := err.(*errors.Error); ok {
		return FromHost(unix.Errno(linuxErr.Errno()))
	}

	if errno, ok := syserror.TranslateError(err); ok {
		return FromHost(errno)
	}
	panic("unknown error: " + err.Error())
}
