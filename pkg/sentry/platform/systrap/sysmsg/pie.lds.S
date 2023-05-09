/* Copyright 2020 The gVisor Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

SECTIONS
{
        .crblob 0x0 : {
                *(.head.text)
                *(.text*)
                . = ALIGN(32);
                *(.data*)
                . = ALIGN(32);
                *(COMMON*)
                . = ALIGN(32);
                *(.rodata*)
                . = ALIGN(32);
                *(.bss*)
                . = ALIGN(32);
                *(.got*)
                . = ALIGN(32);
                *(.debug*)
                . = ALIGN(32);
        } =0x00000000,

        /DISCARD/ : {
                *(.interp) *(.gnu.hash) *(.hash) *(.dynamic) *(.dynsym) *(.dynstr) *(.rela.dyn) *(.eh_frame) *(.note.gnu.property)
        }
}
