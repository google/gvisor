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

// semctl Command Definitions. Source: include/uapi/linux/sem.h
const (
	GETPID  = 11
	GETVAL  = 12
	GETALL  = 13
	GETNCNT = 14
	GETZCNT = 15
	SETVAL  = 16
	SETALL  = 17
)

// ipcs ctl cmds. Source: include/uapi/linux/sem.h
const (
	SEM_STAT     = 18
	SEM_INFO     = 19
	SEM_STAT_ANY = 20
)

// Information about system-wide sempahore limits and parameters.
//
// Source: include/uapi/linux/sem.h
const (
	SEMMNI = 32000
	SEMMSL = 32000
	SEMMNS = SEMMNI * SEMMSL
	SEMOPM = 500
	SEMVMX = 32767
	SEMAEM = SEMVMX

	SEMUME = SEMOPM
	SEMMNU = SEMMNS
	SEMMAP = SEMMNS
	SEMUSZ = 20
)

// Semaphore flags.
const (
	SEM_UNDO = 0x1000
)

// Sembuf is equivalent to struct sembuf.
//
// +marshal slice:SembufSlice
type Sembuf struct {
	SemNum uint16
	SemOp  int16
	SemFlg int16
}

// SemInfo is equivalent to struct seminfo.
//
// Source: include/uapi/linux/sem.h
//
// +marshal
type SemInfo struct {
	SemMap uint32
	SemMni uint32
	SemMns uint32
	SemMnu uint32
	SemMsl uint32
	SemOpm uint32
	SemUme uint32
	SemUsz uint32
	SemVmx uint32
	SemAem uint32
}
