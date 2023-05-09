// Copyright 2022 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

static int loops = 10000000;

enum syscall_type { get_pid, get_pid_opt };

#ifdef __x86_64__

#define SYSNO_STR1(x) #x
#define SYSNO_STR(x) SYSNO_STR1(x)

void do_getpidopt() {
  __asm__("movl $" SYSNO_STR(SYS_getpid) ", %%eax\n"
    "syscall\n"
    : : : "rax", "rcx", "r11");
}
#endif

static void show_usage(const char *cmd) {
  fprintf(stderr,
          "Usage: %s [options]\n"
          "-l, --loops <num>\t\t Number of syscall loops, default 10000000\n"
          "-s, --syscall <num>\t\tSyscall to run (default getpid)\n"
          "\tOptions:\n"
          "\t%d) getpid\n"
          "\t%d) getpidopt\n",
          cmd, get_pid, get_pid_opt);
}

int main(int argc, char *argv[]) {
  int i, c, sys_val = get_pid;
  struct option long_options[] = {{"loops", required_argument, 0, 'l'},
                                  {"syscall", required_argument, 0, 's'},
                                  {0, 0, 0, 0}};
  int option_index = 0;

  while ((c = getopt_long(argc, argv, "l:s:", long_options, &option_index)) !=
         -1) {
    switch (c) {
      case 'l':
        loops = atoi(optarg);
        if (loops <= 0) {
          show_usage(argv[0]);
          exit(1);
        }
        break;
      case 's':
        sys_val = atoi(optarg);
        if (sys_val < 0) {
          show_usage(argv[0]);
          exit(1);
        }
        break;
      default:
        fprintf(stderr, "unknown option: '%c'\n", c);
        show_usage(argv[0]);
        exit(1);
    }
  }

  switch (sys_val) {
    case (int)get_pid:
      for (i = 0; i < loops; i++) syscall(SYS_getpid);
      break;
    case (int)get_pid_opt:
      for (i = 0; i < loops; i++) do_getpidopt();
      break;
    default:
      fprintf(stderr, "unknown syscall option: %d\n", sys_val);
      show_usage(argv[0]);
      exit(1);
  }

  printf("# Executed %'d calls\n", loops);
  return 0;
}
