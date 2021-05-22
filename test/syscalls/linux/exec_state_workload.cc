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

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/time.h>

#include <iostream>
#include <ostream>
#include <string>

#include "absl/strings/numbers.h"

#ifndef ANDROID  // Conflicts with existing operator<< on Android.

// Pretty-print a sigset_t.
std::ostream& operator<<(std::ostream& out, const sigset_t& s) {
  out << "{ ";

  for (int i = 0; i < NSIG; i++) {
    if (sigismember(&s, i)) {
      out << i << " ";
    }
  }

  out << "}";
  return out;
}

#endif

// Verify that the signo handler is handler.
int CheckSigHandler(uint32_t signo, uintptr_t handler) {
  struct sigaction sa;
  int ret = sigaction(signo, nullptr, &sa);
  if (ret < 0) {
    perror("sigaction");
    return 1;
  }

  if (reinterpret_cast<void (*)(int)>(handler) != sa.sa_handler) {
    std::cerr << "signo " << signo << " handler got: " << sa.sa_handler
              << " expected: " << std::hex << handler;
    return 1;
  }
  return 0;
}

// Verify that the signo is blocked.
int CheckSigBlocked(uint32_t signo) {
  sigset_t s;
  int ret = sigprocmask(SIG_SETMASK, nullptr, &s);
  if (ret < 0) {
    perror("sigprocmask");
    return 1;
  }

  if (!sigismember(&s, signo)) {
    std::cerr << "signal " << signo << " not blocked in signal mask: " << s
              << std::endl;
    return 1;
  }
  return 0;
}

// Verify that the itimer is enabled.
int CheckItimerEnabled(uint32_t timer) {
  struct itimerval itv;
  int ret = getitimer(timer, &itv);
  if (ret < 0) {
    perror("getitimer");
    return 1;
  }

  if (!itv.it_value.tv_sec && !itv.it_value.tv_usec &&
      !itv.it_interval.tv_sec && !itv.it_interval.tv_usec) {
    std::cerr << "timer " << timer
              << " not enabled. value sec: " << itv.it_value.tv_sec
              << " usec: " << itv.it_value.tv_usec
              << " interval sec: " << itv.it_interval.tv_sec
              << " usec: " << itv.it_interval.tv_usec << std::endl;
    return 1;
  }
  return 0;
}

int PrintExecFn() {
  unsigned long execfn = getauxval(AT_EXECFN);
  if (!execfn) {
    std::cerr << "AT_EXECFN missing" << std::endl;
    return 1;
  }

  std::cerr << reinterpret_cast<const char*>(execfn) << std::endl;
  return 0;
}

int PrintExecName() {
  const size_t name_length = 20;
  char name[name_length] = {0};
  if (prctl(PR_GET_NAME, name) < 0) {
    std::cerr << "prctl(PR_GET_NAME) failed" << std::endl;
    return 1;
  }

  std::cerr << name << std::endl;
  return 0;
}

void usage(const std::string& prog) {
  std::cerr << "usage:\n"
            << "\t" << prog << " CheckSigHandler <signo> <handler addr (hex)>\n"
            << "\t" << prog << " CheckSigBlocked <signo>\n"
            << "\t" << prog << " CheckTimerDisabled <timer>\n"
            << "\t" << prog << " PrintExecFn\n"
            << "\t" << prog << " PrintExecName" << std::endl;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    usage(argv[0]);
    return 1;
  }

  std::string func(argv[1]);

  if (func == "CheckSigHandler") {
    if (argc != 4) {
      usage(argv[0]);
      return 1;
    }

    uint32_t signo;
    if (!absl::SimpleAtoi(argv[2], &signo)) {
      std::cerr << "invalid signo: " << argv[2] << std::endl;
      return 1;
    }

    uintptr_t handler;
    if (!absl::numbers_internal::safe_strtoi_base(argv[3], &handler, 16)) {
      std::cerr << "invalid handler: " << std::hex << argv[3] << std::endl;
      return 1;
    }

    return CheckSigHandler(signo, handler);
  }

  if (func == "CheckSigBlocked") {
    if (argc != 3) {
      usage(argv[0]);
      return 1;
    }

    uint32_t signo;
    if (!absl::SimpleAtoi(argv[2], &signo)) {
      std::cerr << "invalid signo: " << argv[2] << std::endl;
      return 1;
    }

    return CheckSigBlocked(signo);
  }

  if (func == "CheckItimerEnabled") {
    if (argc != 3) {
      usage(argv[0]);
      return 1;
    }

    uint32_t timer;
    if (!absl::SimpleAtoi(argv[2], &timer)) {
      std::cerr << "invalid signo: " << argv[2] << std::endl;
      return 1;
    }

    return CheckItimerEnabled(timer);
  }

  if (func == "PrintExecFn") {
    // N.B. This will be called as an interpreter script, with the script passed
    // as the third argument. We don't care about that script.
    return PrintExecFn();
  }

  if (func == "PrintExecName") {
    // N.B. This may be called as an interpreter script like PrintExecFn.
    return PrintExecName();
  }

  std::cerr << "Invalid function: " << func << std::endl;
  return 1;
}
