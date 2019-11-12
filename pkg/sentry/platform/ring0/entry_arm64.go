// Copyright 2019 Google Inc.
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

// +build arm64

package ring0

// This is an assembly function.
//
// The sysenter function is invoked in two situations:
//
//  (1) The guest kernel has executed a system call.
//  (2) The guest application has executed a system call.
//
// The interrupt flag is examined to determine whether the system call was
// executed from kernel mode or not and the appropriate stub is called.

func El1_sync_invalid()
func El1_irq_invalid()
func El1_fiq_invalid()
func El1_error_invalid()

func El1_sync()
func El1_irq()
func El1_fiq()
func El1_error()

func El0_sync()
func El0_irq()
func El0_fiq()
func El0_error()

func El0_sync_invalid()
func El0_irq_invalid()
func El0_fiq_invalid()
func El0_error_invalid()

func Vectors()

// Start is the CPU entrypoint.
//
// The CPU state will be set to c.Registers().
func Start()
func kernelExitToEl1()

func kernelExitToEl0()

// Shutdown execution
func Shutdown()
