// Copyright 2018 Google Inc.
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
	TCGETS     = 0x00005401
	TCSETS     = 0x00005402
	TCSETSW    = 0x00005403
	TCSETSF    = 0x00005404
	TIOCSCTTY  = 0x0000540e
	TIOCGPGRP  = 0x0000540f
	TIOCSPGRP  = 0x00005410
	TIOCOUTQ   = 0x00005411
	TIOCGWINSZ = 0x00005413
	TIOCSWINSZ = 0x00005414
	TIOCINQ    = 0x0000541b
	FIONREAD   = TIOCINQ
	FIONBIO    = 0x00005421
	TIOCGPTN   = 0x80045430
	TIOCSPTLCK = 0x40045431
	FIONCLEX   = 0x00005450
	FIOCLEX    = 0x00005451
	FIOASYNC   = 0x00005452
	FIOSETOWN  = 0x00008901
	SIOCSPGRP  = 0x00008902
	FIOGETOWN  = 0x00008903
	SIOCGPGRP  = 0x00008904
)

// ioctl(2) requests provided by uapi/linux/android/binder.h
const (
	BinderWriteReadIoctl       = 0xc0306201
	BinderSetIdleTimeoutIoctl  = 0x40086203
	BinderSetMaxThreadsIoctl   = 0x40046205
	BinderSetIdlePriorityIoctl = 0x40046206
	BinderSetContextMgrIoctl   = 0x40046207
	BinderThreadExitIoctl      = 0x40046208
	BinderVersionIoctl         = 0xc0046209
)

// ioctl(2) requests provided by drivers/staging/android/uapi/ashmem.h
const (
	AshmemSetNameIoctl        = 0x41007701
	AshmemGetNameIoctl        = 0x81007702
	AshmemSetSizeIoctl        = 0x40087703
	AshmemGetSizeIoctl        = 0x00007704
	AshmemSetProtMaskIoctl    = 0x40087705
	AshmemGetProtMaskIoctl    = 0x00007706
	AshmemPinIoctl            = 0x40087707
	AshmemUnpinIoctl          = 0x40087708
	AshmemGetPinStatusIoctl   = 0x00007709
	AshmemPurgeAllCachesIoctl = 0x0000770a
)
