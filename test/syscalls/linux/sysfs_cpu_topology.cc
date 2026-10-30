// Copyright 2026 The gVisor Authors.
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

#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/ascii.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"
#include "test/util/fs_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

using ::testing::Contains;
using ::testing::IsSupersetOf;

constexpr char kCPUDir[] = "/sys/devices/system/cpu";

// Mask files in cpuN/topology, each paired with a "_list" file. Linux creates
// cluster_cpus on x86 and arm64 and die_cpus on x86 only
// (include/linux/topology.h:TOPOLOGY_{CLUSTER,DIE}_SYSFS).
std::vector<std::string> MaskNames() {
  std::vector<std::string> names = {"core_cpus", "thread_siblings",
                                    "core_siblings", "package_cpus",
                                    "cluster_cpus"};
#ifdef __x86_64__
  names.push_back("die_cpus");
#endif
  return names;
}

bool AllDigits(absl::string_view s) {
  return !s.empty() && std::all_of(s.begin(), s.end(), absl::ascii_isdigit);
}

// Strips the single trailing newline that sysfs attributes end with.
PosixErrorOr<std::string> StripNewline(absl::string_view contents) {
  if (!absl::ConsumeSuffix(&contents, "\n") ||
      absl::StrContains(contents, '\n')) {
    return PosixError(EINVAL, absl::StrCat("not one line: \"", contents, "\""));
  }
  return std::string(contents);
}

// Parses a cpulist as printed by Linux's lib/vsprintf.c:bitmap_list_string():
// ascending, comma-separated maximal ranges, with single CPUs printed as "N"
// rather than "N-N".
PosixErrorOr<std::set<int>> ParseCPUList(absl::string_view contents) {
  ASSIGN_OR_RETURN_ERRNO(std::string line, StripNewline(contents));
  std::set<int> cpus;
  if (line.empty()) {
    return cpus;
  }
  int prev_end = -2;
  for (absl::string_view tok : absl::StrSplit(line, ',')) {
    std::vector<absl::string_view> ends = absl::StrSplit(tok, '-');
    int start, end;
    if (ends.size() > 2 || !AllDigits(ends[0]) || !AllDigits(ends.back()) ||
        !absl::SimpleAtoi(ends[0], &start) ||
        !absl::SimpleAtoi(ends.back(), &end)) {
      return PosixError(EINVAL, absl::StrCat("bad cpulist token: ", tok));
    }
    if (ends.size() == 2 && start >= end) {
      return PosixError(EINVAL, absl::StrCat("non-canonical range: ", tok));
    }
    if (start <= prev_end + 1) {
      return PosixError(EINVAL,
                        absl::StrCat("unsorted or unmerged range: ", tok));
    }
    for (int i = start; i <= end; i++) {
      cpus.insert(i);
    }
    prev_end = end;
  }
  return cpus;
}

// Parses a cpumask as printed by Linux's lib/vsprintf.c:bitmap_string():
// comma-separated 32-bit hex words, most significant first.
PosixErrorOr<std::set<int>> ParseCPUMask(absl::string_view contents) {
  ASSIGN_OR_RETURN_ERRNO(std::string line, StripNewline(contents));
  std::vector<absl::string_view> words = absl::StrSplit(line, ',');
  std::set<int> cpus;
  for (size_t w = 0; w < words.size(); w++) {
    uint32_t word;
    if (words[w].empty() || words[w].size() > 8 ||
        !std::all_of(words[w].begin(), words[w].end(), absl::ascii_isxdigit) ||
        !absl::SimpleHexAtoi(words[w], &word)) {
      return PosixError(EINVAL, absl::StrCat("bad cpumask word: ", words[w]));
    }
    int base = (words.size() - 1 - w) * 32;
    for (int bit = 0; bit < 32; bit++) {
      if (word & (uint32_t{1} << bit)) {
        cpus.insert(base + bit);
      }
    }
  }
  return cpus;
}

PosixErrorOr<int> ParseID(absl::string_view contents) {
  ASSIGN_OR_RETURN_ERRNO(std::string line, StripNewline(contents));
  int id;
  if (!absl::SimpleAtoi(line, &id)) {
    return PosixError(EINVAL, absl::StrCat("bad id: ", line));
  }
  return id;
}

PosixErrorOr<std::set<int>> ReadCPUList(absl::string_view path) {
  ASSIGN_OR_RETURN_ERRNO(std::string contents, GetContents(path));
  return ParseCPUList(contents);
}

std::string TopologyDir(int cpu) {
  return absl::StrCat(kCPUDir, "/cpu", cpu, "/topology");
}

TEST(SysfsCPUTopologyTest, CPUListsAreCanonical) {
  const std::set<int> possible = ASSERT_NO_ERRNO_AND_VALUE(
      ReadCPUList(absl::StrCat(kCPUDir, "/possible")));
  const std::set<int> present =
      ASSERT_NO_ERRNO_AND_VALUE(ReadCPUList(absl::StrCat(kCPUDir, "/present")));
  const std::set<int> online =
      ASSERT_NO_ERRNO_AND_VALUE(ReadCPUList(absl::StrCat(kCPUDir, "/online")));
  ASSERT_FALSE(online.empty());
  EXPECT_THAT(possible, IsSupersetOf(present));
  EXPECT_THAT(present, IsSupersetOf(online));
  EXPECT_EQ(static_cast<long>(online.size()), sysconf(_SC_NPROCESSORS_ONLN));

  // Linux creates cpuN/topology only for online CPUs
  // (drivers/base/topology.c:topology_add_dev() is a CPU hotplug callback).
  std::vector<std::string> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ListDir(kCPUDir, /*skipdots=*/true));
  std::set<int> with_topology;
  for (absl::string_view name : entries) {
    int cpu;
    if (absl::ConsumePrefix(&name, "cpu") && absl::SimpleAtoi(name, &cpu) &&
        ASSERT_NO_ERRNO_AND_VALUE(Exists(TopologyDir(cpu)))) {
      with_topology.insert(cpu);
    }
  }
  EXPECT_EQ(with_topology, online);
}

// ID files and the mask file naming the CPUs that share each ID
// (drivers/base/topology.c:define_id_show_func()).
std::vector<std::pair<std::string, std::string>> IDNames() {
  std::vector<std::pair<std::string, std::string>> ids = {
      {"physical_package_id", "package_cpus"},
      {"core_id", "core_cpus"},
      {"cluster_id", "cluster_cpus"},
  };
#ifdef __x86_64__
  ids.push_back({"die_id", "die_cpus"});
#endif
  return ids;
}

// The parsed contents of one cpuN/topology directory. masks and lists are
// keyed by the mask file name.
struct CPUTopology {
  std::map<std::string, std::set<int>> masks;
  std::map<std::string, std::set<int>> lists;
  std::map<std::string, int> ids;

  bool operator==(const CPUTopology& other) const {
    return masks == other.masks && lists == other.lists && ids == other.ids;
  }
};

PosixErrorOr<CPUTopology> ReadCPUTopology(int cpu) {
  const std::string dir = TopologyDir(cpu);
  CPUTopology topo;
  for (const std::string& name : MaskNames()) {
    ASSIGN_OR_RETURN_ERRNO(std::string mask,
                           GetContents(absl::StrCat(dir, "/", name)));
    ASSIGN_OR_RETURN_ERRNO(topo.masks[name], ParseCPUMask(mask));
    ASSIGN_OR_RETURN_ERRNO(topo.lists[name],
                           ReadCPUList(absl::StrCat(dir, "/", name, "_list")));
  }
  for (const auto& [id_name, mask_name] : IDNames()) {
    ASSIGN_OR_RETURN_ERRNO(std::string id,
                           GetContents(absl::StrCat(dir, "/", id_name)));
    ASSIGN_OR_RETURN_ERRNO(topo.ids[id_name], ParseID(id));
  }
  return topo;
}

// Reads every file in cpuN/topology once for each online CPU.
//
// Saves are disabled: each read is several save points, and with hundreds of
// files the save variants spend minutes restoring unchanged static files.
// StableAcrossSaveRestore covers save/restore with a single explicit save.
PosixErrorOr<std::map<int, CPUTopology>> ReadAllTopology() {
  const DisableSave ds;
  ASSIGN_OR_RETURN_ERRNO(std::set<int> online,
                         ReadCPUList(absl::StrCat(kCPUDir, "/online")));
  std::map<int, CPUTopology> all;
  for (int cpu : online) {
    ASSIGN_OR_RETURN_ERRNO(all[cpu], ReadCPUTopology(cpu));
  }
  return all;
}

TEST(SysfsCPUTopologyTest, ListsMatchMasks) {
  const std::map<int, CPUTopology> all =
      ASSERT_NO_ERRNO_AND_VALUE(ReadAllTopology());
  for (const auto& [cpu, topo] : all) {
    SCOPED_TRACE(absl::StrCat("cpu", cpu));
    for (const auto& [name, mask] : topo.masks) {
      SCOPED_TRACE(name);
      EXPECT_EQ(topo.lists.at(name), mask);
      EXPECT_THAT(mask, Contains(cpu));
    }

    const std::set<int>& package = topo.masks.at("core_siblings");
    EXPECT_THAT(package, IsSupersetOf(topo.masks.at("thread_siblings")));
    EXPECT_THAT(package, IsSupersetOf(topo.masks.at("cluster_cpus")));
#ifdef __x86_64__
    EXPECT_THAT(package, IsSupersetOf(topo.masks.at("die_cpus")));
#endif
    // core_cpus and package_cpus are aliases of thread_siblings and
    // core_siblings (drivers/base/topology.c).
    EXPECT_EQ(topo.masks.at("core_cpus"), topo.masks.at("thread_siblings"));
    EXPECT_EQ(topo.masks.at("package_cpus"), package);
  }
}

TEST(SysfsCPUTopologyTest, IDsAreConsistent) {
  const std::map<int, CPUTopology> all =
      ASSERT_NO_ERRNO_AND_VALUE(ReadAllTopology());
  for (const auto& [cpu, topo] : all) {
    SCOPED_TRACE(absl::StrCat("cpu", cpu));
    for (const auto& [id_name, mask_name] : IDNames()) {
      SCOPED_TRACE(id_name);
      const int id = topo.ids.at(id_name);
      for (int other : topo.lists.at(mask_name)) {
        auto it = all.find(other);
        ASSERT_NE(it, all.end()) << "cpu" << other << " is not online";
        EXPECT_EQ(it->second.ids.at(id_name), id) << "cpu" << other;
      }
    }
  }
}

TEST(SysfsCPUTopologyTest, StableAcrossSaveRestore) {
  const std::map<int, CPUTopology> before =
      ASSERT_NO_ERRNO_AND_VALUE(ReadAllTopology());
  MaybeSave();
  const std::map<int, CPUTopology> after =
      ASSERT_NO_ERRNO_AND_VALUE(ReadAllTopology());
  EXPECT_TRUE(before == after);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
