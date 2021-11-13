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

//go:build linux
// +build linux

package syserr

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux/errno"
)

const maxErrno = 134

var linuxHostTranslations [maxErrno]*Error

// FromHost translates a unix.Errno to a corresponding Error value.
func FromHost(err unix.Errno) *Error {
	if int(err) >= len(linuxHostTranslations) || linuxHostTranslations[err] == nil {
		panic(fmt.Sprintf("unknown host errno %q (%d)", err.Error(), err))
	}
	return linuxHostTranslations[err]
}

func addHostTranslation(host unix.Errno, trans *Error) {
	if linuxHostTranslations[host] != nil {
		panic(fmt.Sprintf("duplicate translation for host errno %q (%d)", host.Error(), host))
	}
	linuxHostTranslations[host] = trans
}

// TODO(b/34162363): Remove or replace most of these errors.
//
// Some of the errors should be replaced with package specific errors and
// others should be removed entirely.
var (
	ErrAddressFamilyNotSupported  = newWithHost("address family not supported by protocol", errno.EAFNOSUPPORT, unix.EAFNOSUPPORT)
	ErrAddressInUse               = newWithHost("address already in use", errno.EADDRINUSE, unix.EADDRINUSE)
	ErrAddressNotAvailable        = newWithHost("cannot assign requested address", errno.EADDRNOTAVAIL, unix.EADDRNOTAVAIL)
	ErrAdvertise                  = newWithHost("advertise error", errno.EADV, unix.EADV)
	ErrAlreadyConnected           = newWithHost("transport endpoint is already connected", errno.EISCONN, unix.EISCONN)
	ErrAlreadyInProgress          = newWithHost("operation already in progress", errno.EALREADY, unix.EALREADY)
	ErrBadAddress                 = newWithHost("bad address", errno.EFAULT, unix.EFAULT)
	ErrBadFD                      = newWithHost("bad file number", errno.EBADF, unix.EBADF)
	ErrBadFontFile                = newWithHost("bad font file format", errno.EBFONT, unix.EBFONT)
	ErrBrokenPipe                 = newWithHost("broken pipe", errno.EPIPE, unix.EPIPE)
	ErrBusy                       = newWithHost("device or resource busy", errno.EBUSY, unix.EBUSY)
	ErrCanceled                   = newWithHost("operation canceled", errno.ECANCELED, unix.ECANCELED)
	ErrChannelOutOfRange          = newWithHost("channel number out of range", errno.ECHRNG, unix.ECHRNG)
	ErrConnectionAborted          = newWithHost("software caused connection abort", errno.ECONNABORTED, unix.ECONNABORTED)
	ErrConnectionRefused          = newWithHost("connection refused", errno.ECONNREFUSED, unix.ECONNREFUSED)
	ErrConnectionReset            = newWithHost("connection reset by peer", errno.ECONNRESET, unix.ECONNRESET)
	ErrCorruptedSharedLibrary     = newWithHost("accessing a corrupted shared library", errno.ELIBBAD, unix.ELIBBAD)
	ErrCrossDeviceLink            = newWithHost("cross-device link", errno.EXDEV, unix.EXDEV)
	ErrDeadlock                   = newWithHost("resource deadlock would occur", errno.EDEADLOCK, unix.EDEADLOCK)
	ErrDestinationAddressRequired = newWithHost("destination address required", errno.EDESTADDRREQ, unix.EDESTADDRREQ)
	ErrDeviceOrAddress            = newWithHost("no such device or address", errno.ENXIO, unix.ENXIO)
	ErrDirNotEmpty                = newWithHost("directory not empty", errno.ENOTEMPTY, unix.ENOTEMPTY)
	ErrDomain                     = newWithHost("math argument out of domain of func", errno.EDOM, unix.EDOM)
	ErrEcec                       = newWithHost("exec format error", errno.ENOEXEC, unix.ENOEXEC)
	ErrEndpointOperation          = newWithHost("operation not supported on transport endpoint", errno.EOPNOTSUPP, unix.EOPNOTSUPP)
	ErrExchangeFull               = newWithHost("exchange full", errno.EXFULL, unix.EXFULL)
	ErrExists                     = newWithHost("file exists", errno.EEXIST, unix.EEXIST)
	ErrFDInBadState               = newWithHost("file descriptor in bad state", errno.EBADFD, unix.EBADFD)
	ErrFileTableOverflow          = newWithHost("file table overflow", errno.ENFILE, unix.ENFILE)
	ErrFileTooBig                 = newWithHost("file too large", errno.EFBIG, unix.EFBIG)
	ErrHostDown                   = newWithHost("host is down", errno.EHOSTDOWN, unix.EHOSTDOWN)
	ErrIO                         = newWithHost("I/O error", errno.EIO, unix.EIO)
	ErrIdentifierRemoved          = newWithHost("identifier removed", errno.EIDRM, unix.EIDRM)
	ErrIllegalByteSequence        = newWithHost("illegal byte sequence", errno.EILSEQ, unix.EILSEQ)
	ErrIllegalSeek                = newWithHost("illegal seek", errno.ESPIPE, unix.ESPIPE)
	ErrInProgress                 = newWithHost("operation now in progress", errno.EINPROGRESS, unix.EINPROGRESS)
	ErrInterrupted                = newWithHost("interrupted system call", errno.EINTR, unix.EINTR)
	ErrInvalidArgument            = newWithHost("invalid argument", errno.EINVAL, unix.EINVAL)
	ErrInvalidDataMessage         = newWithHost("not a data message", errno.EBADMSG, unix.EBADMSG)
	ErrInvalidExchange            = newWithHost("invalid exchange", errno.EBADE, unix.EBADE)
	ErrInvalidRequestCode         = newWithHost("invalid request code", errno.EBADRQC, unix.EBADRQC)
	ErrInvalidRequestDescriptor   = newWithHost("invalid request descriptor", errno.EBADR, unix.EBADR)
	ErrInvalidSlot                = newWithHost("invalid slot", errno.EBADSLT, unix.EBADSLT)
	ErrInvalidSyscall             = newWithHost("invalid system call number", errno.ENOSYS, unix.ENOSYS)
	ErrIsDir                      = newWithHost("is a directory", errno.EISDIR, unix.EISDIR)
	ErrIsNamedFile                = newWithHost("is a named type file", errno.ENOTNAM, unix.ENOTNAM)
	ErrIsRemote                   = newWithHost("object is remote", errno.EREMOTE, unix.EREMOTE)
	ErrKeyExpired                 = newWithHost("key has expired", errno.EKEYEXPIRED, unix.EKEYEXPIRED)
	ErrKeyRejected                = newWithHost("key was rejected by service", errno.EKEYREJECTED, unix.EKEYREJECTED)
	ErrKeyRevoked                 = newWithHost("key has been revoked", errno.EKEYREVOKED, unix.EKEYREVOKED)
	ErrLevelThreeHalted           = newWithHost("level 3 halted", errno.EL3HLT, unix.EL3HLT)
	ErrLevelThreeReset            = newWithHost("level 3 reset", errno.EL3RST, unix.EL3RST)
	ErrLevelTwoHalted             = newWithHost("level 2 halted", errno.EL2HLT, unix.EL2HLT)
	ErrLevelTwoNotSynced          = newWithHost("level 2 not synchronized", errno.EL2NSYNC, unix.EL2NSYNC)
	ErrLibSectionCorrupted        = newWithHost(".lib section in a.out corrupted", errno.ELIBSCN, unix.ELIBSCN)
	ErrLinkLoop                   = newWithHost("too many symbolic links encountered", errno.ELOOP, unix.ELOOP)
	ErrLinkNumberOutOfRange       = newWithHost("link number out of range", errno.ELNRNG, unix.ELNRNG)
	ErrMachineNotOnNetwork        = newWithHost("machine is not on the network", errno.ENONET, unix.ENONET)
	ErrMessageTooLong             = newWithHost("message too long", errno.EMSGSIZE, unix.EMSGSIZE)
	ErrMultihopAttempted          = newWithHost("multihop attempted", errno.EMULTIHOP, unix.EMULTIHOP)
	ErrNameTooLong                = newWithHost("file name too long", errno.ENAMETOOLONG, unix.ENAMETOOLONG)
	ErrNetworkDown                = newWithHost("network is down", errno.ENETDOWN, unix.ENETDOWN)
	ErrNetworkNameNotUnique       = newWithHost("name not unique on network", errno.ENOTUNIQ, unix.ENOTUNIQ)
	ErrNetworkReset               = newWithHost("network dropped connection because of reset", errno.ENETRESET, unix.ENETRESET)
	ErrNetworkUnreachable         = newWithHost("network is unreachable", errno.ENETUNREACH, unix.ENETUNREACH)
	ErrNoAnode                    = newWithHost("no anode", errno.ENOANO, unix.ENOANO)
	ErrNoBufferSpace              = newWithHost("no buffer space available", errno.ENOBUFS, unix.ENOBUFS)
	ErrNoCSIAvailable             = newWithHost("no CSI structure available", errno.ENOCSI, unix.ENOCSI)
	ErrNoChild                    = newWithHost("no child processes", errno.ECHILD, unix.ECHILD)
	ErrNoDataAvailable            = newWithHost("no data available", errno.ENODATA, unix.ENODATA)
	ErrNoDevice                   = newWithHost("no such device", errno.ENODEV, unix.ENODEV)
	ErrNoFileOrDir                = newWithHost("no such file or directory", errno.ENOENT, unix.ENOENT)
	ErrNoKey                      = newWithHost("required key not available", errno.ENOKEY, unix.ENOKEY)
	ErrNoLink                     = newWithHost("link has been severed", errno.ENOLINK, unix.ENOLINK)
	ErrNoLocksAvailable           = newWithHost("no record locks available", errno.ENOLCK, unix.ENOLCK)
	ErrNoMedium                   = newWithHost("no medium found", errno.ENOMEDIUM, unix.ENOMEDIUM)
	ErrNoMemory                   = newWithHost("out of memory", errno.ENOMEM, unix.ENOMEM)
	ErrNoMessage                  = newWithHost("no message of desired type", errno.ENOMSG, unix.ENOMSG)
	ErrNoProcess                  = newWithHost("no such process", errno.ESRCH, unix.ESRCH)
	ErrNoRoute                    = newWithHost("no route to host", errno.EHOSTUNREACH, unix.EHOSTUNREACH)
	ErrNoSpace                    = newWithHost("no space left on device", errno.ENOSPC, unix.ENOSPC)
	ErrNotASocket                 = newWithHost("socket operation on non-socket", errno.ENOTSOCK, unix.ENOTSOCK)
	ErrNotBlockDevice             = newWithHost("block device required", errno.ENOTBLK, unix.ENOTBLK)
	ErrNotConnected               = newWithHost("transport endpoint is not connected", errno.ENOTCONN, unix.ENOTCONN)
	ErrNotDir                     = newWithHost("not a directory", errno.ENOTDIR, unix.ENOTDIR)
	ErrNotPermitted               = newWithHost("operation not permitted", errno.EPERM, unix.EPERM)
	ErrNotRecoverable             = newWithHost("state not recoverable", errno.ENOTRECOVERABLE, unix.ENOTRECOVERABLE)
	ErrNotTTY                     = newWithHost("not a typewriter", errno.ENOTTY, unix.ENOTTY)
	ErrOverflow                   = newWithHost("value too large for defined data type", errno.EOVERFLOW, unix.EOVERFLOW)
	ErrOwnerDied                  = newWithHost("owner died", errno.EOWNERDEAD, unix.EOWNERDEAD)
	ErrPackageNotInstalled        = newWithHost("package not installed", errno.ENOPKG, unix.ENOPKG)
	ErrPermissionDenied           = newWithHost("permission denied", errno.EACCES, unix.EACCES)
	ErrProtocol                   = newWithHost("protocol error", errno.EPROTO, unix.EPROTO)
	ErrProtocolDriverNotAttached  = newWithHost("protocol driver not attached", errno.EUNATCH, unix.EUNATCH)
	ErrProtocolFamilyNotSupported = newWithHost("protocol family not supported", errno.EPFNOSUPPORT, unix.EPFNOSUPPORT)
	ErrProtocolNotAvailable       = newWithHost("protocol not available", errno.ENOPROTOOPT, unix.ENOPROTOOPT)
	ErrProtocolNotSupported       = newWithHost("protocol not supported", errno.EPROTONOSUPPORT, unix.EPROTONOSUPPORT)
	ErrQuotaExceeded              = newWithHost("quota exceeded", errno.EDQUOT, unix.EDQUOT)
	ErrRFS                        = newWithHost("RFS specific error", errno.EDOTDOT, unix.EDOTDOT)
	ErrRange                      = newWithHost("math result not representable", errno.ERANGE, unix.ERANGE)
	ErrReadOnlyFS                 = newWithHost("read-only file system", errno.EROFS, unix.EROFS)
	ErrRemoteAddressChanged       = newWithHost("remote address changed", errno.EREMCHG, unix.EREMCHG)
	ErrRemoteIO                   = newWithHost("remote I/O error", errno.EREMOTEIO, unix.EREMOTEIO)
	ErrSRMount                    = newWithHost("srmount error", errno.ESRMNT, unix.ESRMNT)
	ErrSendCommunication          = newWithHost("communication error on send", errno.ECOMM, unix.ECOMM)
	ErrSharedLibraryExeced        = newWithHost("cannot exec a shared library directly", errno.ELIBEXEC, unix.ELIBEXEC)
	ErrSharedLibraryInaccessible  = newWithHost("can not access a needed shared library", errno.ELIBACC, unix.ELIBACC)
	ErrShouldRestart              = newWithHost("interrupted system call should be restarted", errno.ERESTART, unix.ERESTART)
	ErrShutdown                   = newWithHost("cannot send after transport endpoint shutdown", errno.ESHUTDOWN, unix.ESHUTDOWN)
	ErrSocketNotSupported         = newWithHost("socket type not supported", errno.ESOCKTNOSUPPORT, unix.ESOCKTNOSUPPORT)
	ErrStaleFileHandle            = newWithHost("stale file handle", errno.ESTALE, unix.ESTALE)
	ErrStreamPipe                 = newWithHost("streams pipe error", errno.ESTRPIPE, unix.ESTRPIPE)
	ErrStreamsResourceDepleted    = newWithHost("out of streams resources", errno.ENOSR, unix.ENOSR)
	ErrStructureNeedsCleaning     = newWithHost("structure needs cleaning", errno.EUCLEAN, unix.EUCLEAN)
	ErrTestFileBusy               = newWithHost("text file busy", errno.ETXTBSY, unix.ETXTBSY)
	ErrTimedOut                   = newWithHost("connection timed out", errno.ETIMEDOUT, unix.ETIMEDOUT)
	ErrTimerExpired               = newWithHost("timer expired", errno.ETIME, unix.ETIME)
	ErrTooManyArgs                = newWithHost("argument list too long", errno.E2BIG, unix.E2BIG)
	ErrTooManyLinks               = newWithHost("too many links", errno.EMLINK, unix.EMLINK)
	ErrTooManyOpenFiles           = newWithHost("too many open files", errno.EMFILE, unix.EMFILE)
	ErrTooManyRefs                = newWithHost("too many references: cannot splice", errno.ETOOMANYREFS, unix.ETOOMANYREFS)
	ErrTooManySharedLibraries     = newWithHost("attempting to link in too many shared libraries", errno.ELIBMAX, unix.ELIBMAX)
	ErrTooManyUsers               = newWithHost("too many users", errno.EUSERS, unix.EUSERS)
	ErrTryAgain                   = newWithHost("try again", errno.EAGAIN, unix.EAGAIN)
	// ErrWouldBlock translates to EWOULDBLOCK which is the same as EAGAIN
	// on Linux.
	ErrWouldBlock             = New("operation would block", errno.EWOULDBLOCK)
	ErrWrongMediumType        = newWithHost("wrong medium type", errno.EMEDIUMTYPE, unix.EMEDIUMTYPE)
	ErrWrongProtocolForSocket = newWithHost("protocol wrong type for socket", errno.EPROTOTYPE, unix.EPROTOTYPE)
)
