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
	ErrDeadlock                  = newWithHost("resource deadlock would occur", errno.EDEADLOCK, unix.EDEADLOCK)
	ErrChannelOutOfRange         = newWithHost("channel number out of range", errno.ECHRNG, unix.ECHRNG)
	ErrLevelTwoNotSynced         = newWithHost("level 2 not synchronized", errno.EL2NSYNC, unix.EL2NSYNC)
	ErrLevelThreeHalted          = newWithHost("level 3 halted", errno.EL3HLT, unix.EL3HLT)
	ErrLevelThreeReset           = newWithHost("level 3 reset", errno.EL3RST, unix.EL3RST)
	ErrLinkNumberOutOfRange      = newWithHost("link number out of range", errno.ELNRNG, unix.ELNRNG)
	ErrProtocolDriverNotAttached = newWithHost("protocol driver not attached", errno.EUNATCH, unix.EUNATCH)
	ErrNoCSIAvailable            = newWithHost("no CSI structure available", errno.ENOCSI, unix.ENOCSI)
	ErrLevelTwoHalted            = newWithHost("level 2 halted", errno.EL2HLT, unix.EL2HLT)
	ErrInvalidExchange           = newWithHost("invalid exchange", errno.EBADE, unix.EBADE)
	ErrInvalidRequestDescriptor  = newWithHost("invalid request descriptor", errno.EBADR, unix.EBADR)
	ErrExchangeFull              = newWithHost("exchange full", errno.EXFULL, unix.EXFULL)
	ErrNoAnode                   = newWithHost("no anode", errno.ENOANO, unix.ENOANO)
	ErrInvalidRequestCode        = newWithHost("invalid request code", errno.EBADRQC, unix.EBADRQC)
	ErrInvalidSlot               = newWithHost("invalid slot", errno.EBADSLT, unix.EBADSLT)
	ErrBadFontFile               = newWithHost("bad font file format", errno.EBFONT, unix.EBFONT)
	ErrMachineNotOnNetwork       = newWithHost("machine is not on the network", errno.ENONET, unix.ENONET)
	ErrPackageNotInstalled       = newWithHost("package not installed", errno.ENOPKG, unix.ENOPKG)
	ErrAdvertise                 = newWithHost("advertise error", errno.EADV, unix.EADV)
	ErrSRMount                   = newWithHost("srmount error", errno.ESRMNT, unix.ESRMNT)
	ErrSendCommunication         = newWithHost("communication error on send", errno.ECOMM, unix.ECOMM)
	ErrRFS                       = newWithHost("RFS specific error", errno.EDOTDOT, unix.EDOTDOT)
	ErrNetworkNameNotUnique      = newWithHost("name not unique on network", errno.ENOTUNIQ, unix.ENOTUNIQ)
	ErrFDInBadState              = newWithHost("file descriptor in bad state", errno.EBADFD, unix.EBADFD)
	ErrRemoteAddressChanged      = newWithHost("remote address changed", errno.EREMCHG, unix.EREMCHG)
	ErrSharedLibraryInaccessible = newWithHost("can not access a needed shared library", errno.ELIBACC, unix.ELIBACC)
	ErrCorruptedSharedLibrary    = newWithHost("accessing a corrupted shared library", errno.ELIBBAD, unix.ELIBBAD)
	ErrLibSectionCorrupted       = newWithHost(".lib section in a.out corrupted", errno.ELIBSCN, unix.ELIBSCN)
	ErrTooManySharedLibraries    = newWithHost("attempting to link in too many shared libraries", errno.ELIBMAX, unix.ELIBMAX)
	ErrSharedLibraryExeced       = newWithHost("cannot exec a shared library directly", errno.ELIBEXEC, unix.ELIBEXEC)
	ErrShouldRestart             = newWithHost("interrupted system call should be restarted", errno.ERESTART, unix.ERESTART)
	ErrStreamPipe                = newWithHost("streams pipe error", errno.ESTRPIPE, unix.ESTRPIPE)
	ErrStructureNeedsCleaning    = newWithHost("structure needs cleaning", errno.EUCLEAN, unix.EUCLEAN)
	ErrIsNamedFile               = newWithHost("is a named type file", errno.ENOTNAM, unix.ENOTNAM)
	ErrRemoteIO                  = newWithHost("remote I/O error", errno.EREMOTEIO, unix.EREMOTEIO)
	ErrNoMedium                  = newWithHost("no medium found", errno.ENOMEDIUM, unix.ENOMEDIUM)
	ErrWrongMediumType           = newWithHost("wrong medium type", errno.EMEDIUMTYPE, unix.EMEDIUMTYPE)
	ErrNoKey                     = newWithHost("required key not available", errno.ENOKEY, unix.ENOKEY)
	ErrKeyExpired                = newWithHost("key has expired", errno.EKEYEXPIRED, unix.EKEYEXPIRED)
	ErrKeyRevoked                = newWithHost("key has been revoked", errno.EKEYREVOKED, unix.EKEYREVOKED)
	ErrKeyRejected               = newWithHost("key was rejected by service", errno.EKEYREJECTED, unix.EKEYREJECTED)
)
