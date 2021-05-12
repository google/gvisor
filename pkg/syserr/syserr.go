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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Error represents an internal error.
type Error struct {
	// message is the human readable form of this Error.
	message string

	// noTranslation indicates that this Error cannot be translated to a
	// linux.Errno.
	noTranslation bool

	// errno is the linux.Errno this Error should be translated to.
	errno linux.Errno
}

// New creates a new Error and adds a translation for it.
//
// New must only be called at init.
func New(message string, linuxTranslation linux.Errno) *Error {
	err := &Error{message: message, errno: linuxTranslation}

	// TODO(b/34162363): Remove this.
	errno := linuxTranslation
	if errno < 0 || int(errno) >= len(linuxBackwardsTranslations) {
		panic(fmt.Sprint("invalid errno: ", errno))
	}

	e := error(unix.Errno(errno))
	// syserror.ErrWouldBlock gets translated to syserror.EWOULDBLOCK and
	// enables proper blocking semantics. This should temporary address the
	// class of blocking bugs that keep popping up with the current state of
	// the error space.
	if e == syserror.EWOULDBLOCK {
		e = syserror.ErrWouldBlock
	}
	linuxBackwardsTranslations[errno] = linuxBackwardsTranslation{err: e, ok: true}

	return err
}

// NewDynamic creates a new error with a dynamic error message and an errno
// translation.
//
// NewDynamic should only be used sparingly and not be used for static error
// messages. Errors with static error messages should be declared with New as
// global variables.
func NewDynamic(message string, linuxTranslation linux.Errno) *Error {
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

func newWithHost(message string, linuxTranslation linux.Errno, hostErrno unix.Errno) *Error {
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
	errno := int(e.errno)
	if errno == linux.NOERRNO {
		return nil
	}
	if errno <= 0 || errno >= len(linuxBackwardsTranslations) || !linuxBackwardsTranslations[errno].ok {
		panic(fmt.Sprintf("unknown error %q (%d)", e.message, errno))
	}
	return linuxBackwardsTranslations[errno].err
}

// ToLinux converts the Error to a Linux ABI error that can be returned to the
// application.
func (e *Error) ToLinux() linux.Errno {
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
	ErrNotPermitted               = newWithHost("operation not permitted", linux.EPERM, unix.EPERM)
	ErrNoFileOrDir                = newWithHost("no such file or directory", linux.ENOENT, unix.ENOENT)
	ErrNoProcess                  = newWithHost("no such process", linux.ESRCH, unix.ESRCH)
	ErrInterrupted                = newWithHost("interrupted system call", linux.EINTR, unix.EINTR)
	ErrIO                         = newWithHost("I/O error", linux.EIO, unix.EIO)
	ErrDeviceOrAddress            = newWithHost("no such device or address", linux.ENXIO, unix.ENXIO)
	ErrTooManyArgs                = newWithHost("argument list too long", linux.E2BIG, unix.E2BIG)
	ErrEcec                       = newWithHost("exec format error", linux.ENOEXEC, unix.ENOEXEC)
	ErrBadFD                      = newWithHost("bad file number", linux.EBADF, unix.EBADF)
	ErrNoChild                    = newWithHost("no child processes", linux.ECHILD, unix.ECHILD)
	ErrTryAgain                   = newWithHost("try again", linux.EAGAIN, unix.EAGAIN)
	ErrNoMemory                   = newWithHost("out of memory", linux.ENOMEM, unix.ENOMEM)
	ErrPermissionDenied           = newWithHost("permission denied", linux.EACCES, unix.EACCES)
	ErrBadAddress                 = newWithHost("bad address", linux.EFAULT, unix.EFAULT)
	ErrNotBlockDevice             = newWithHost("block device required", linux.ENOTBLK, unix.ENOTBLK)
	ErrBusy                       = newWithHost("device or resource busy", linux.EBUSY, unix.EBUSY)
	ErrExists                     = newWithHost("file exists", linux.EEXIST, unix.EEXIST)
	ErrCrossDeviceLink            = newWithHost("cross-device link", linux.EXDEV, unix.EXDEV)
	ErrNoDevice                   = newWithHost("no such device", linux.ENODEV, unix.ENODEV)
	ErrNotDir                     = newWithHost("not a directory", linux.ENOTDIR, unix.ENOTDIR)
	ErrIsDir                      = newWithHost("is a directory", linux.EISDIR, unix.EISDIR)
	ErrInvalidArgument            = newWithHost("invalid argument", linux.EINVAL, unix.EINVAL)
	ErrFileTableOverflow          = newWithHost("file table overflow", linux.ENFILE, unix.ENFILE)
	ErrTooManyOpenFiles           = newWithHost("too many open files", linux.EMFILE, unix.EMFILE)
	ErrNotTTY                     = newWithHost("not a typewriter", linux.ENOTTY, unix.ENOTTY)
	ErrTestFileBusy               = newWithHost("text file busy", linux.ETXTBSY, unix.ETXTBSY)
	ErrFileTooBig                 = newWithHost("file too large", linux.EFBIG, unix.EFBIG)
	ErrNoSpace                    = newWithHost("no space left on device", linux.ENOSPC, unix.ENOSPC)
	ErrIllegalSeek                = newWithHost("illegal seek", linux.ESPIPE, unix.ESPIPE)
	ErrReadOnlyFS                 = newWithHost("read-only file system", linux.EROFS, unix.EROFS)
	ErrTooManyLinks               = newWithHost("too many links", linux.EMLINK, unix.EMLINK)
	ErrBrokenPipe                 = newWithHost("broken pipe", linux.EPIPE, unix.EPIPE)
	ErrDomain                     = newWithHost("math argument out of domain of func", linux.EDOM, unix.EDOM)
	ErrRange                      = newWithHost("math result not representable", linux.ERANGE, unix.ERANGE)
	ErrDeadlock                   = newWithHost("resource deadlock would occur", linux.EDEADLOCK, unix.EDEADLOCK)
	ErrNameTooLong                = newWithHost("file name too long", linux.ENAMETOOLONG, unix.ENAMETOOLONG)
	ErrNoLocksAvailable           = newWithHost("no record locks available", linux.ENOLCK, unix.ENOLCK)
	ErrInvalidSyscall             = newWithHost("invalid system call number", linux.ENOSYS, unix.ENOSYS)
	ErrDirNotEmpty                = newWithHost("directory not empty", linux.ENOTEMPTY, unix.ENOTEMPTY)
	ErrLinkLoop                   = newWithHost("too many symbolic links encountered", linux.ELOOP, unix.ELOOP)
	ErrNoMessage                  = newWithHost("no message of desired type", linux.ENOMSG, unix.ENOMSG)
	ErrIdentifierRemoved          = newWithHost("identifier removed", linux.EIDRM, unix.EIDRM)
	ErrChannelOutOfRange          = newWithHost("channel number out of range", linux.ECHRNG, unix.ECHRNG)
	ErrLevelTwoNotSynced          = newWithHost("level 2 not synchronized", linux.EL2NSYNC, unix.EL2NSYNC)
	ErrLevelThreeHalted           = newWithHost("level 3 halted", linux.EL3HLT, unix.EL3HLT)
	ErrLevelThreeReset            = newWithHost("level 3 reset", linux.EL3RST, unix.EL3RST)
	ErrLinkNumberOutOfRange       = newWithHost("link number out of range", linux.ELNRNG, unix.ELNRNG)
	ErrProtocolDriverNotAttached  = newWithHost("protocol driver not attached", linux.EUNATCH, unix.EUNATCH)
	ErrNoCSIAvailable             = newWithHost("no CSI structure available", linux.ENOCSI, unix.ENOCSI)
	ErrLevelTwoHalted             = newWithHost("level 2 halted", linux.EL2HLT, unix.EL2HLT)
	ErrInvalidExchange            = newWithHost("invalid exchange", linux.EBADE, unix.EBADE)
	ErrInvalidRequestDescriptor   = newWithHost("invalid request descriptor", linux.EBADR, unix.EBADR)
	ErrExchangeFull               = newWithHost("exchange full", linux.EXFULL, unix.EXFULL)
	ErrNoAnode                    = newWithHost("no anode", linux.ENOANO, unix.ENOANO)
	ErrInvalidRequestCode         = newWithHost("invalid request code", linux.EBADRQC, unix.EBADRQC)
	ErrInvalidSlot                = newWithHost("invalid slot", linux.EBADSLT, unix.EBADSLT)
	ErrBadFontFile                = newWithHost("bad font file format", linux.EBFONT, unix.EBFONT)
	ErrNotStream                  = newWithHost("device not a stream", linux.ENOSTR, unix.ENOSTR)
	ErrNoDataAvailable            = newWithHost("no data available", linux.ENODATA, unix.ENODATA)
	ErrTimerExpired               = newWithHost("timer expired", linux.ETIME, unix.ETIME)
	ErrStreamsResourceDepleted    = newWithHost("out of streams resources", linux.ENOSR, unix.ENOSR)
	ErrMachineNotOnNetwork        = newWithHost("machine is not on the network", linux.ENONET, unix.ENONET)
	ErrPackageNotInstalled        = newWithHost("package not installed", linux.ENOPKG, unix.ENOPKG)
	ErrIsRemote                   = newWithHost("object is remote", linux.EREMOTE, unix.EREMOTE)
	ErrNoLink                     = newWithHost("link has been severed", linux.ENOLINK, unix.ENOLINK)
	ErrAdvertise                  = newWithHost("advertise error", linux.EADV, unix.EADV)
	ErrSRMount                    = newWithHost("srmount error", linux.ESRMNT, unix.ESRMNT)
	ErrSendCommunication          = newWithHost("communication error on send", linux.ECOMM, unix.ECOMM)
	ErrProtocol                   = newWithHost("protocol error", linux.EPROTO, unix.EPROTO)
	ErrMultihopAttempted          = newWithHost("multihop attempted", linux.EMULTIHOP, unix.EMULTIHOP)
	ErrRFS                        = newWithHost("RFS specific error", linux.EDOTDOT, unix.EDOTDOT)
	ErrInvalidDataMessage         = newWithHost("not a data message", linux.EBADMSG, unix.EBADMSG)
	ErrOverflow                   = newWithHost("value too large for defined data type", linux.EOVERFLOW, unix.EOVERFLOW)
	ErrNetworkNameNotUnique       = newWithHost("name not unique on network", linux.ENOTUNIQ, unix.ENOTUNIQ)
	ErrFDInBadState               = newWithHost("file descriptor in bad state", linux.EBADFD, unix.EBADFD)
	ErrRemoteAddressChanged       = newWithHost("remote address changed", linux.EREMCHG, unix.EREMCHG)
	ErrSharedLibraryInaccessible  = newWithHost("can not access a needed shared library", linux.ELIBACC, unix.ELIBACC)
	ErrCorruptedSharedLibrary     = newWithHost("accessing a corrupted shared library", linux.ELIBBAD, unix.ELIBBAD)
	ErrLibSectionCorrupted        = newWithHost(".lib section in a.out corrupted", linux.ELIBSCN, unix.ELIBSCN)
	ErrTooManySharedLibraries     = newWithHost("attempting to link in too many shared libraries", linux.ELIBMAX, unix.ELIBMAX)
	ErrSharedLibraryExeced        = newWithHost("cannot exec a shared library directly", linux.ELIBEXEC, unix.ELIBEXEC)
	ErrIllegalByteSequence        = newWithHost("illegal byte sequence", linux.EILSEQ, unix.EILSEQ)
	ErrShouldRestart              = newWithHost("interrupted system call should be restarted", linux.ERESTART, unix.ERESTART)
	ErrStreamPipe                 = newWithHost("streams pipe error", linux.ESTRPIPE, unix.ESTRPIPE)
	ErrTooManyUsers               = newWithHost("too many users", linux.EUSERS, unix.EUSERS)
	ErrNotASocket                 = newWithHost("socket operation on non-socket", linux.ENOTSOCK, unix.ENOTSOCK)
	ErrDestinationAddressRequired = newWithHost("destination address required", linux.EDESTADDRREQ, unix.EDESTADDRREQ)
	ErrMessageTooLong             = newWithHost("message too long", linux.EMSGSIZE, unix.EMSGSIZE)
	ErrWrongProtocolForSocket     = newWithHost("protocol wrong type for socket", linux.EPROTOTYPE, unix.EPROTOTYPE)
	ErrProtocolNotAvailable       = newWithHost("protocol not available", linux.ENOPROTOOPT, unix.ENOPROTOOPT)
	ErrProtocolNotSupported       = newWithHost("protocol not supported", linux.EPROTONOSUPPORT, unix.EPROTONOSUPPORT)
	ErrSocketNotSupported         = newWithHost("socket type not supported", linux.ESOCKTNOSUPPORT, unix.ESOCKTNOSUPPORT)
	ErrEndpointOperation          = newWithHost("operation not supported on transport endpoint", linux.EOPNOTSUPP, unix.EOPNOTSUPP)
	ErrProtocolFamilyNotSupported = newWithHost("protocol family not supported", linux.EPFNOSUPPORT, unix.EPFNOSUPPORT)
	ErrAddressFamilyNotSupported  = newWithHost("address family not supported by protocol", linux.EAFNOSUPPORT, unix.EAFNOSUPPORT)
	ErrAddressInUse               = newWithHost("address already in use", linux.EADDRINUSE, unix.EADDRINUSE)
	ErrAddressNotAvailable        = newWithHost("cannot assign requested address", linux.EADDRNOTAVAIL, unix.EADDRNOTAVAIL)
	ErrNetworkDown                = newWithHost("network is down", linux.ENETDOWN, unix.ENETDOWN)
	ErrNetworkUnreachable         = newWithHost("network is unreachable", linux.ENETUNREACH, unix.ENETUNREACH)
	ErrNetworkReset               = newWithHost("network dropped connection because of reset", linux.ENETRESET, unix.ENETRESET)
	ErrConnectionAborted          = newWithHost("software caused connection abort", linux.ECONNABORTED, unix.ECONNABORTED)
	ErrConnectionReset            = newWithHost("connection reset by peer", linux.ECONNRESET, unix.ECONNRESET)
	ErrNoBufferSpace              = newWithHost("no buffer space available", linux.ENOBUFS, unix.ENOBUFS)
	ErrAlreadyConnected           = newWithHost("transport endpoint is already connected", linux.EISCONN, unix.EISCONN)
	ErrNotConnected               = newWithHost("transport endpoint is not connected", linux.ENOTCONN, unix.ENOTCONN)
	ErrShutdown                   = newWithHost("cannot send after transport endpoint shutdown", linux.ESHUTDOWN, unix.ESHUTDOWN)
	ErrTooManyRefs                = newWithHost("too many references: cannot splice", linux.ETOOMANYREFS, unix.ETOOMANYREFS)
	ErrTimedOut                   = newWithHost("connection timed out", linux.ETIMEDOUT, unix.ETIMEDOUT)
	ErrConnectionRefused          = newWithHost("connection refused", linux.ECONNREFUSED, unix.ECONNREFUSED)
	ErrHostDown                   = newWithHost("host is down", linux.EHOSTDOWN, unix.EHOSTDOWN)
	ErrNoRoute                    = newWithHost("no route to host", linux.EHOSTUNREACH, unix.EHOSTUNREACH)
	ErrAlreadyInProgress          = newWithHost("operation already in progress", linux.EALREADY, unix.EALREADY)
	ErrInProgress                 = newWithHost("operation now in progress", linux.EINPROGRESS, unix.EINPROGRESS)
	ErrStaleFileHandle            = newWithHost("stale file handle", linux.ESTALE, unix.ESTALE)
	ErrStructureNeedsCleaning     = newWithHost("structure needs cleaning", linux.EUCLEAN, unix.EUCLEAN)
	ErrIsNamedFile                = newWithHost("is a named type file", linux.ENOTNAM, unix.ENOTNAM)
	ErrRemoteIO                   = newWithHost("remote I/O error", linux.EREMOTEIO, unix.EREMOTEIO)
	ErrQuotaExceeded              = newWithHost("quota exceeded", linux.EDQUOT, unix.EDQUOT)
	ErrNoMedium                   = newWithHost("no medium found", linux.ENOMEDIUM, unix.ENOMEDIUM)
	ErrWrongMediumType            = newWithHost("wrong medium type", linux.EMEDIUMTYPE, unix.EMEDIUMTYPE)
	ErrCanceled                   = newWithHost("operation canceled", linux.ECANCELED, unix.ECANCELED)
	ErrNoKey                      = newWithHost("required key not available", linux.ENOKEY, unix.ENOKEY)
	ErrKeyExpired                 = newWithHost("key has expired", linux.EKEYEXPIRED, unix.EKEYEXPIRED)
	ErrKeyRevoked                 = newWithHost("key has been revoked", linux.EKEYREVOKED, unix.EKEYREVOKED)
	ErrKeyRejected                = newWithHost("key was rejected by service", linux.EKEYREJECTED, unix.EKEYREJECTED)
	ErrOwnerDied                  = newWithHost("owner died", linux.EOWNERDEAD, unix.EOWNERDEAD)
	ErrNotRecoverable             = newWithHost("state not recoverable", linux.ENOTRECOVERABLE, unix.ENOTRECOVERABLE)

	// ErrWouldBlock translates to EWOULDBLOCK which is the same as EAGAIN
	// on Linux.
	ErrWouldBlock = New("operation would block", linux.EWOULDBLOCK)
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
	if errno, ok := syserror.TranslateError(err); ok {
		return FromHost(errno)
	}
	panic("unknown error: " + err.Error())
}
