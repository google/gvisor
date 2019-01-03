// Copyright 2018 Google LLC
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
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// Error represents an internal error.
type Error struct {
	// message is the human readable form of this Error.
	message string

	// noTranslation indicates that this Error cannot be translated to a
	// linux.Errno.
	noTranslation bool

	// errno is the linux.Errno this Error should be translated to. nil means
	// that this Error should be translated to a nil linux.Errno.
	errno *linux.Errno
}

// New creates a new Error and adds a translation for it.
//
// New must only be called at init.
func New(message string, linuxTranslation *linux.Errno) *Error {
	err := &Error{message: message, errno: linuxTranslation}

	if linuxTranslation == nil {
		return err
	}

	// TODO: Remove this.
	errno := linuxTranslation.Number()
	if errno <= 0 || errno >= len(linuxBackwardsTranslations) {
		panic(fmt.Sprint("invalid errno: ", errno))
	}

	e := error(syscall.Errno(errno))
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
func NewDynamic(message string, linuxTranslation *linux.Errno) *Error {
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

func newWithHost(message string, linuxTranslation *linux.Errno, hostErrno syscall.Errno) *Error {
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

// TODO: Remove this.
var linuxBackwardsTranslations [maxErrno]linuxBackwardsTranslation

// ToError translates an Error to a corresponding error value.
//
// TODO: Remove this.
func (e *Error) ToError() error {
	if e == nil {
		return nil
	}
	if e.noTranslation {
		panic(fmt.Sprintf("error %q does not support translation", e.message))
	}
	if e.errno == nil {
		return nil
	}
	errno := e.errno.Number()
	if errno <= 0 || errno >= len(linuxBackwardsTranslations) || !linuxBackwardsTranslations[errno].ok {
		panic(fmt.Sprintf("unknown error %q (%d)", e.message, errno))
	}
	return linuxBackwardsTranslations[errno].err
}

// ToLinux converts the Error to a Linux ABI error that can be returned to the
// application.
func (e *Error) ToLinux() *linux.Errno {
	if e.noTranslation {
		panic(fmt.Sprintf("No Linux ABI translation available for %q", e.message))
	}
	return e.errno
}

// TODO: Remove or replace most of these errors.
//
// Some of the errors should be replaced with package specific errors and
// others should be removed entirely.
var (
	ErrNotPermitted               = newWithHost("operation not permitted", linux.EPERM, syscall.EPERM)
	ErrNoFileOrDir                = newWithHost("no such file or directory", linux.ENOENT, syscall.ENOENT)
	ErrNoProcess                  = newWithHost("no such process", linux.ESRCH, syscall.ESRCH)
	ErrInterrupted                = newWithHost("interrupted system call", linux.EINTR, syscall.EINTR)
	ErrIO                         = newWithHost("I/O error", linux.EIO, syscall.EIO)
	ErrDeviceOrAddress            = newWithHost("no such device or address", linux.ENXIO, syscall.ENXIO)
	ErrTooManyArgs                = newWithHost("argument list too long", linux.E2BIG, syscall.E2BIG)
	ErrEcec                       = newWithHost("exec format error", linux.ENOEXEC, syscall.ENOEXEC)
	ErrBadFD                      = newWithHost("bad file number", linux.EBADF, syscall.EBADF)
	ErrNoChild                    = newWithHost("no child processes", linux.ECHILD, syscall.ECHILD)
	ErrTryAgain                   = newWithHost("try again", linux.EAGAIN, syscall.EAGAIN)
	ErrNoMemory                   = newWithHost("out of memory", linux.ENOMEM, syscall.ENOMEM)
	ErrPermissionDenied           = newWithHost("permission denied", linux.EACCES, syscall.EACCES)
	ErrBadAddress                 = newWithHost("bad address", linux.EFAULT, syscall.EFAULT)
	ErrNotBlockDevice             = newWithHost("block device required", linux.ENOTBLK, syscall.ENOTBLK)
	ErrBusy                       = newWithHost("device or resource busy", linux.EBUSY, syscall.EBUSY)
	ErrExists                     = newWithHost("file exists", linux.EEXIST, syscall.EEXIST)
	ErrCrossDeviceLink            = newWithHost("cross-device link", linux.EXDEV, syscall.EXDEV)
	ErrNoDevice                   = newWithHost("no such device", linux.ENODEV, syscall.ENODEV)
	ErrNotDir                     = newWithHost("not a directory", linux.ENOTDIR, syscall.ENOTDIR)
	ErrIsDir                      = newWithHost("is a directory", linux.EISDIR, syscall.EISDIR)
	ErrInvalidArgument            = newWithHost("invalid argument", linux.EINVAL, syscall.EINVAL)
	ErrFileTableOverflow          = newWithHost("file table overflow", linux.ENFILE, syscall.ENFILE)
	ErrTooManyOpenFiles           = newWithHost("too many open files", linux.EMFILE, syscall.EMFILE)
	ErrNotTTY                     = newWithHost("not a typewriter", linux.ENOTTY, syscall.ENOTTY)
	ErrTestFileBusy               = newWithHost("text file busy", linux.ETXTBSY, syscall.ETXTBSY)
	ErrFileTooBig                 = newWithHost("file too large", linux.EFBIG, syscall.EFBIG)
	ErrNoSpace                    = newWithHost("no space left on device", linux.ENOSPC, syscall.ENOSPC)
	ErrIllegalSeek                = newWithHost("illegal seek", linux.ESPIPE, syscall.ESPIPE)
	ErrReadOnlyFS                 = newWithHost("read-only file system", linux.EROFS, syscall.EROFS)
	ErrTooManyLinks               = newWithHost("too many links", linux.EMLINK, syscall.EMLINK)
	ErrBrokenPipe                 = newWithHost("broken pipe", linux.EPIPE, syscall.EPIPE)
	ErrDomain                     = newWithHost("math argument out of domain of func", linux.EDOM, syscall.EDOM)
	ErrRange                      = newWithHost("math result not representable", linux.ERANGE, syscall.ERANGE)
	ErrDeadlock                   = newWithHost("resource deadlock would occur", linux.EDEADLOCK, syscall.EDEADLOCK)
	ErrNameTooLong                = newWithHost("file name too long", linux.ENAMETOOLONG, syscall.ENAMETOOLONG)
	ErrNoLocksAvailable           = newWithHost("no record locks available", linux.ENOLCK, syscall.ENOLCK)
	ErrInvalidSyscall             = newWithHost("invalid system call number", linux.ENOSYS, syscall.ENOSYS)
	ErrDirNotEmpty                = newWithHost("directory not empty", linux.ENOTEMPTY, syscall.ENOTEMPTY)
	ErrLinkLoop                   = newWithHost("too many symbolic links encountered", linux.ELOOP, syscall.ELOOP)
	ErrNoMessage                  = newWithHost("no message of desired type", linux.ENOMSG, syscall.ENOMSG)
	ErrIdentifierRemoved          = newWithHost("identifier removed", linux.EIDRM, syscall.EIDRM)
	ErrChannelOutOfRange          = newWithHost("channel number out of range", linux.ECHRNG, syscall.ECHRNG)
	ErrLevelTwoNotSynced          = newWithHost("level 2 not synchronized", linux.EL2NSYNC, syscall.EL2NSYNC)
	ErrLevelThreeHalted           = newWithHost("level 3 halted", linux.EL3HLT, syscall.EL3HLT)
	ErrLevelThreeReset            = newWithHost("level 3 reset", linux.EL3RST, syscall.EL3RST)
	ErrLinkNumberOutOfRange       = newWithHost("link number out of range", linux.ELNRNG, syscall.ELNRNG)
	ErrProtocolDriverNotAttached  = newWithHost("protocol driver not attached", linux.EUNATCH, syscall.EUNATCH)
	ErrNoCSIAvailable             = newWithHost("no CSI structure available", linux.ENOCSI, syscall.ENOCSI)
	ErrLevelTwoHalted             = newWithHost("level 2 halted", linux.EL2HLT, syscall.EL2HLT)
	ErrInvalidExchange            = newWithHost("invalid exchange", linux.EBADE, syscall.EBADE)
	ErrInvalidRequestDescriptor   = newWithHost("invalid request descriptor", linux.EBADR, syscall.EBADR)
	ErrExchangeFull               = newWithHost("exchange full", linux.EXFULL, syscall.EXFULL)
	ErrNoAnode                    = newWithHost("no anode", linux.ENOANO, syscall.ENOANO)
	ErrInvalidRequestCode         = newWithHost("invalid request code", linux.EBADRQC, syscall.EBADRQC)
	ErrInvalidSlot                = newWithHost("invalid slot", linux.EBADSLT, syscall.EBADSLT)
	ErrBadFontFile                = newWithHost("bad font file format", linux.EBFONT, syscall.EBFONT)
	ErrNotStream                  = newWithHost("device not a stream", linux.ENOSTR, syscall.ENOSTR)
	ErrNoDataAvailable            = newWithHost("no data available", linux.ENODATA, syscall.ENODATA)
	ErrTimerExpired               = newWithHost("timer expired", linux.ETIME, syscall.ETIME)
	ErrStreamsResourceDepleted    = newWithHost("out of streams resources", linux.ENOSR, syscall.ENOSR)
	ErrMachineNotOnNetwork        = newWithHost("machine is not on the network", linux.ENONET, syscall.ENONET)
	ErrPackageNotInstalled        = newWithHost("package not installed", linux.ENOPKG, syscall.ENOPKG)
	ErrIsRemote                   = newWithHost("object is remote", linux.EREMOTE, syscall.EREMOTE)
	ErrNoLink                     = newWithHost("link has been severed", linux.ENOLINK, syscall.ENOLINK)
	ErrAdvertise                  = newWithHost("advertise error", linux.EADV, syscall.EADV)
	ErrSRMount                    = newWithHost("srmount error", linux.ESRMNT, syscall.ESRMNT)
	ErrSendCommunication          = newWithHost("communication error on send", linux.ECOMM, syscall.ECOMM)
	ErrProtocol                   = newWithHost("protocol error", linux.EPROTO, syscall.EPROTO)
	ErrMultihopAttempted          = newWithHost("multihop attempted", linux.EMULTIHOP, syscall.EMULTIHOP)
	ErrRFS                        = newWithHost("RFS specific error", linux.EDOTDOT, syscall.EDOTDOT)
	ErrInvalidDataMessage         = newWithHost("not a data message", linux.EBADMSG, syscall.EBADMSG)
	ErrOverflow                   = newWithHost("value too large for defined data type", linux.EOVERFLOW, syscall.EOVERFLOW)
	ErrNetworkNameNotUnique       = newWithHost("name not unique on network", linux.ENOTUNIQ, syscall.ENOTUNIQ)
	ErrFDInBadState               = newWithHost("file descriptor in bad state", linux.EBADFD, syscall.EBADFD)
	ErrRemoteAddressChanged       = newWithHost("remote address changed", linux.EREMCHG, syscall.EREMCHG)
	ErrSharedLibraryInaccessible  = newWithHost("can not access a needed shared library", linux.ELIBACC, syscall.ELIBACC)
	ErrCorruptedSharedLibrary     = newWithHost("accessing a corrupted shared library", linux.ELIBBAD, syscall.ELIBBAD)
	ErrLibSectionCorrupted        = newWithHost(".lib section in a.out corrupted", linux.ELIBSCN, syscall.ELIBSCN)
	ErrTooManySharedLibraries     = newWithHost("attempting to link in too many shared libraries", linux.ELIBMAX, syscall.ELIBMAX)
	ErrSharedLibraryExeced        = newWithHost("cannot exec a shared library directly", linux.ELIBEXEC, syscall.ELIBEXEC)
	ErrIllegalByteSequence        = newWithHost("illegal byte sequence", linux.EILSEQ, syscall.EILSEQ)
	ErrShouldRestart              = newWithHost("interrupted system call should be restarted", linux.ERESTART, syscall.ERESTART)
	ErrStreamPipe                 = newWithHost("streams pipe error", linux.ESTRPIPE, syscall.ESTRPIPE)
	ErrTooManyUsers               = newWithHost("too many users", linux.EUSERS, syscall.EUSERS)
	ErrNotASocket                 = newWithHost("socket operation on non-socket", linux.ENOTSOCK, syscall.ENOTSOCK)
	ErrDestinationAddressRequired = newWithHost("destination address required", linux.EDESTADDRREQ, syscall.EDESTADDRREQ)
	ErrMessageTooLong             = newWithHost("message too long", linux.EMSGSIZE, syscall.EMSGSIZE)
	ErrWrongProtocolForSocket     = newWithHost("protocol wrong type for socket", linux.EPROTOTYPE, syscall.EPROTOTYPE)
	ErrProtocolNotAvailable       = newWithHost("protocol not available", linux.ENOPROTOOPT, syscall.ENOPROTOOPT)
	ErrProtocolNotSupported       = newWithHost("protocol not supported", linux.EPROTONOSUPPORT, syscall.EPROTONOSUPPORT)
	ErrSocketNotSupported         = newWithHost("socket type not supported", linux.ESOCKTNOSUPPORT, syscall.ESOCKTNOSUPPORT)
	ErrEndpointOperation          = newWithHost("operation not supported on transport endpoint", linux.EOPNOTSUPP, syscall.EOPNOTSUPP)
	ErrProtocolFamilyNotSupported = newWithHost("protocol family not supported", linux.EPFNOSUPPORT, syscall.EPFNOSUPPORT)
	ErrAddressFamilyNotSupported  = newWithHost("address family not supported by protocol", linux.EAFNOSUPPORT, syscall.EAFNOSUPPORT)
	ErrAddressInUse               = newWithHost("address already in use", linux.EADDRINUSE, syscall.EADDRINUSE)
	ErrAddressNotAvailable        = newWithHost("cannot assign requested address", linux.EADDRNOTAVAIL, syscall.EADDRNOTAVAIL)
	ErrNetworkDown                = newWithHost("network is down", linux.ENETDOWN, syscall.ENETDOWN)
	ErrNetworkUnreachable         = newWithHost("network is unreachable", linux.ENETUNREACH, syscall.ENETUNREACH)
	ErrNetworkReset               = newWithHost("network dropped connection because of reset", linux.ENETRESET, syscall.ENETRESET)
	ErrConnectionAborted          = newWithHost("software caused connection abort", linux.ECONNABORTED, syscall.ECONNABORTED)
	ErrConnectionReset            = newWithHost("connection reset by peer", linux.ECONNRESET, syscall.ECONNRESET)
	ErrNoBufferSpace              = newWithHost("no buffer space available", linux.ENOBUFS, syscall.ENOBUFS)
	ErrAlreadyConnected           = newWithHost("transport endpoint is already connected", linux.EISCONN, syscall.EISCONN)
	ErrNotConnected               = newWithHost("transport endpoint is not connected", linux.ENOTCONN, syscall.ENOTCONN)
	ErrShutdown                   = newWithHost("cannot send after transport endpoint shutdown", linux.ESHUTDOWN, syscall.ESHUTDOWN)
	ErrTooManyRefs                = newWithHost("too many references: cannot splice", linux.ETOOMANYREFS, syscall.ETOOMANYREFS)
	ErrTimedOut                   = newWithHost("connection timed out", linux.ETIMEDOUT, syscall.ETIMEDOUT)
	ErrConnectionRefused          = newWithHost("connection refused", linux.ECONNREFUSED, syscall.ECONNREFUSED)
	ErrHostDown                   = newWithHost("host is down", linux.EHOSTDOWN, syscall.EHOSTDOWN)
	ErrNoRoute                    = newWithHost("no route to host", linux.EHOSTUNREACH, syscall.EHOSTUNREACH)
	ErrAlreadyInProgress          = newWithHost("operation already in progress", linux.EALREADY, syscall.EALREADY)
	ErrInProgress                 = newWithHost("operation now in progress", linux.EINPROGRESS, syscall.EINPROGRESS)
	ErrStaleFileHandle            = newWithHost("stale file handle", linux.ESTALE, syscall.ESTALE)
	ErrStructureNeedsCleaning     = newWithHost("structure needs cleaning", linux.EUCLEAN, syscall.EUCLEAN)
	ErrIsNamedFile                = newWithHost("is a named type file", linux.ENOTNAM, syscall.ENOTNAM)
	ErrRemoteIO                   = newWithHost("remote I/O error", linux.EREMOTEIO, syscall.EREMOTEIO)
	ErrQuotaExceeded              = newWithHost("quota exceeded", linux.EDQUOT, syscall.EDQUOT)
	ErrNoMedium                   = newWithHost("no medium found", linux.ENOMEDIUM, syscall.ENOMEDIUM)
	ErrWrongMediumType            = newWithHost("wrong medium type", linux.EMEDIUMTYPE, syscall.EMEDIUMTYPE)
	ErrCanceled                   = newWithHost("operation canceled", linux.ECANCELED, syscall.ECANCELED)
	ErrNoKey                      = newWithHost("required key not available", linux.ENOKEY, syscall.ENOKEY)
	ErrKeyExpired                 = newWithHost("key has expired", linux.EKEYEXPIRED, syscall.EKEYEXPIRED)
	ErrKeyRevoked                 = newWithHost("key has been revoked", linux.EKEYREVOKED, syscall.EKEYREVOKED)
	ErrKeyRejected                = newWithHost("key was rejected by service", linux.EKEYREJECTED, syscall.EKEYREJECTED)
	ErrOwnerDied                  = newWithHost("owner died", linux.EOWNERDEAD, syscall.EOWNERDEAD)
	ErrNotRecoverable             = newWithHost("state not recoverable", linux.ENOTRECOVERABLE, syscall.ENOTRECOVERABLE)

	// ErrWouldBlock translates to EWOULDBLOCK which is the same as EAGAIN
	// on Linux.
	ErrWouldBlock = New("operation would block", linux.EWOULDBLOCK)
)

// FromError converts a generic error to an *Error.
//
// TODO: Remove this function.
func FromError(err error) *Error {
	if err == nil {
		return nil
	}
	if errno, ok := err.(syscall.Errno); ok {
		return FromHost(errno)
	}
	if errno, ok := syserror.TranslateError(err); ok {
		return FromHost(errno)
	}
	panic("unknown error: " + err.Error())
}
