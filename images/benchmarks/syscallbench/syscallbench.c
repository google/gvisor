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
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static int loops = 10000000;

enum syscall_type { get_pid, get_pid_opt };
enum seccomp_policy { seccomp_none, seccomp_cacheable, seccomp_uncacheable };

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
          "--seccomp_cacheable\t\tAdd a cacheable ALLOW "
          "seccomp filter for this syscall\n"
          "--seccomp_notcacheable\t\tAdd a non-cacheable ALLOW "
          "seccomp filter for this syscall\n"
          "\tOptions:\n"
          "\t%d) getpid\n"
          "\t%d) getpidopt\n",
          cmd, get_pid, get_pid_opt);
}

static void set_cacheable_filter() {
  // "Prior to [PR_SET_SECCOMP], the task must call prctl(PR_SET_NO_NEW_PRIVS,
  // 1) or run with CAP_SYS_ADMIN privileges in its namespace." -
  // Documentation/prctl/seccomp_filter.txt
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    fprintf(stderr, "prctl(PR_SET_NO_NEW_PRIVS) failed\n");
    exit(1);
  }

  struct sock_filter filter[] = {
      // A = seccomp_data.arch
      BPF_STMT(BPF_LD | BPF_ABS | BPF_W, 4),
      // if (A != AUDIT_ARCH_X86_64) goto kill
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 2),
      // A = seccomp_data.nr
      BPF_STMT(BPF_LD | BPF_ABS | BPF_W, 0),
      // return SECCOMP_RET_ALLOW
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      // kill: return SECCOMP_RET_KILL
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
  };
  struct sock_fprog prog;
  prog.len = 5;
  prog.filter = filter;
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0) {
    fprintf(stderr, "prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) failed\n");
    exit(1);
  }
}

static void set_uncacheable_filter() {
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    fprintf(stderr, "prctl(PR_SET_NO_NEW_PRIVS) failed\n");
    exit(1);
  }

  struct sock_filter filter[] = {
      // A = seccomp_data.arch
      BPF_STMT(BPF_LD | BPF_ABS | BPF_W, 4),
      // if (A != AUDIT_ARCH_X86_64) goto kill
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 3),
      // A = seccomp_data.nr
      BPF_STMT(BPF_LD | BPF_ABS | BPF_W, 0),
      // A = seccomp_data.args[0]
      BPF_STMT(BPF_LD | BPF_ABS | BPF_W, 16),
      // return SECCOMP_RET_ALLOW
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      // kill: return SECCOMP_RET_KILL
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
  };
  struct sock_fprog prog;
  prog.len = 6;
  prog.filter = filter;
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0) {
    fprintf(stderr, "prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) failed\n");
    exit(1);
  }
}

int main(int argc, char *argv[]) {
  int i, c, sys_val = get_pid;
  int seccomp_policy_flag = seccomp_none;
  struct option long_options[] = {{"loops", required_argument, 0, 'l'},
                                  {"syscall", required_argument, 0, 's'},
                                  {"seccomp_cacheable", no_argument,
                                   &seccomp_policy_flag, seccomp_cacheable},
                                  {"seccomp_notcacheable", no_argument,
                                   &seccomp_policy_flag, seccomp_uncacheable},
                                  {0, 0, 0, 0}};
  int option_index = 0;

  while ((c = getopt_long(argc, argv, "l:s:c:", long_options, &option_index)) !=
         -1) {
    switch (c) {
      case 0:
        break;
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
      case 'c':
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

  switch (seccomp_policy_flag) {
    case seccomp_none:
      break;
    case seccomp_cacheable:
      set_cacheable_filter();
      break;
    case seccomp_uncacheable:
      set_uncacheable_filter();
      break;
    default:
      fprintf(stderr, "unknown seccomp option: %d\n", seccomp_policy_flag);
      show_usage(argv[0]);
      exit(1);
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
