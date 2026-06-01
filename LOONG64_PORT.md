# gVisor LoongArch64 移植笔记

## 项目背景

- **目标**：在银河麒麟 V11 Swan25 (LoongArch64, Loongson 3A5000, 内核 6.6) 上运行 `runsc` 作为 docker OCI runtime，供 OJ 系统按需启动 4 语言 (C / Python / JS / Java) 学生作业容器。
- **范围**：仅 `ptrace` 平台。**不做** KVM、systrap、ring0 真实实现，**不做** LSX/LASX 上下文保存，**不做** 上游 PR。
- **演示门槛**：与 x86 host 上 `qemu-system-loongarch64 -accel tcg` 跑同样负载相比，性能可观察地高（预期 10×~50×）。

## 设计决策

| 决策 | 选择 | 理由 |
|---|---|---|
| 构建路径 | `docker buildx` + loong64 容器内 Bazel | 跳过 `cc_toolchain_loongarch64` 配置；隐藏 bug 立刻暴露 |
| 页大小 | 仅支持 16K（不分 4k/64k 变体） | Linux 主线 LoongArch 默认；银河麒麟 V11 内核 6.6 默认 |
| FPU 保存 | 仅基础 32×64bit FP + FCC + FCSR | LSX/LASX 在 `cpuid.AllowedHWCap1` 中过滤掉，使 glibc/JVM 不去用 |
| KVM/systrap/ring0 | 全部 panic stub | 这些子系统在 ptrace 平台不会触发；占位让代码树能编译 |
| `atomicbitops` | 直接用 noasm fallback | 包已内置 `!amd64 && !arm64` 兜底实现，零工作量 |
| 上游策略 | fork，不提 PR | 工程压力下保留全部修改主权 |

## 阶段进度

### ✅ P1.A 已完成：Bazel 配置 + 底层 ABI/cpuid/hostarch

**Bazel 配置改动（4 处）**：

- `tools/bazeldefs/BUILD` — 新增 `config_setting(name="loong64", ...)` 约束
- `tools/bazeldefs/defs.bzl` — `select_arch()` 加 `loong64=` 参数；新增 `loong64_config()` transition
- `tools/bazeldefs/tags.bzl` — `archs` 列表加 `"_loong64"`
- `tools/bazeldefs/go.bzl` — `select_goarch()` 加 `loong64="loong64"`

**新增 Go 文件（10 个）**：

- `pkg/abi/linux/epoll_loong64.go` — 16 字节 EpollEvent（与 arm64 同）
- `pkg/abi/linux/file_loong64.go` — fcntl flags + asm-generic stat
- `pkg/abi/linux/mm_loong64.go` — 48-bit TASK_SIZE
- `pkg/abi/linux/ptrace_loong64.go` — `struct user_pt_regs` 映射：32 GPR + ERA + BADV + Reserved[10]，SP=$r3
- `pkg/abi/linux/sem_loong64.go` — asm-generic SemidDS
- `pkg/hostarch/hostarch_loong64.go` — PageShift=14 (16K)、HugePageShift=25 (32MB)、CacheLine=64B、无 TBI
- `pkg/cpuid/hwcap_loong64.go` — HWCAP_LOONGARCH_{CPUCFG,LAM,UAL,FPU,LSX,LASX,CRC32,...}
- `pkg/cpuid/features_loong64.go` — Feature 枚举 + FlagString() 拼 /proc/cpuinfo
- `pkg/cpuid/cpuid_loong64.go` — FeatureSet 主体；**AllowedHWCap1 过滤掉 LSX/LASX**
- `pkg/cpuid/native_loong64.go` — 读 /proc/cpuinfo 拿 Model/Freq

**BUILD srcs 更新（5 处）**：`pkg/abi/linux/BUILD`、`pkg/hostarch/BUILD`、`pkg/cpuid/BUILD` 加入新文件。

**确认无需改动**：`pkg/atomicbitops/atomicbitops_noasm.go` 的 build tag 是 `!amd64 && !arm64`，loong64 自动复用 Go fallback。

### 🚧 P1.B 进行中：核心架构层

详见任务 #7。预计文件：约 15 个，含汇编。最难点是 `safecopy/` 系列（sighandler 与 ucontext 布局）。

### ⏳ P1.C 待办：ptrace 平台 + runsc 适配

详见任务 #8。约 20 个文件。关键文件 `pkg/sentry/platform/ptrace/ptrace_loong64.go` 需要正确使用 `NT_PRSTATUS` regset（不是 `NT_LOONGARCH_*`，那些是补充信息）。

### ⏳ P1.D 待办：批量 panic stub + Dockerfile + 首次编译

详见任务 #9。`ring0/kvm/systrap` 约 35 个文件用最小骨架占位。

## 关键 LoongArch ABI 备忘

| 项 | 值 |
|---|---|
| 通用寄存器 | $r0=zero, $r1=ra, $r2=tp, $r3=sp, $r4..$r11=a0..a7, $r12..$r20=t0..t8, $r22=fp, $r23..$r31=s0..s8 |
| Syscall 号寄存器 | $a7 ($r11) |
| Syscall 返回值 | $a0 ($r4) |
| Syscall 指令 | `syscall 0` (4 字节定长) |
| 页大小 | 16K（CONFIG_PAGE_SIZE_16KB，主线默认） |
| 用户地址空间 | 48 位 |
| 字节序 | 小端 |
| Stack 对齐 | 16 字节 |
| FPU regset note | `NT_PRSTATUS` 通用寄存器 + `NT_PRFPREG` 浮点（gVisor 使用） |
| 补充 note | `NT_LOONGARCH_{CPUCFG,CSR,LSX,LASX,LBT}`（gVisor 不使用） |

## 基础镜像选择

**官方 Docker Hub 的 debian/ubuntu/alpine 都没有 loongarch64 manifest**。必须用社区镜像：

| 用途 | 镜像 | 验证命令 |
|---|---|---|
| 编译机 Dockerfile.builder 的 base | `ghcr.io/loong64/debian:trixie-slim` | `docker run --rm --platform=linux/loong64 ghcr.io/loong64/debian:trixie-slim uname -m` → `loongarch64` |
| OJ 容器 rootfs（C/Python/JS/Java） | 同上 + `apt install` 各运行时 | 4 个语言镜像在 P2 阶段构建 |

## 汇编校对（against Vol1 r1p10 + ELF psABI v2.01）

P1.B 写完后通过两份官方 PDF 校对，结论：

| 项 | 引用页 | 结果 |
|---|---|---|
| 通用寄存器 ABI（regSP=3, regA0=4, regA7=11, regT0=12, RA=R1） | ELF psABI Table 1 | ✓ 全部匹配 |
| `MULV / MULHVU` 助记符（即 MUL.D / MULH.DU） | Vol1 §2.2.1.11 | ✓ |
| `RDTIMED R4, R0` 读 stable counter | Vol1 §2.2.10.4 | ✓ rj=R0 丢弃 ID 合规 |
| `DBAR $0` 全屏障 | Vol1 §2.2.8.1 | ✓ hint=0 是必须实现的完全功能屏障 |
| `SYSCALL` 触发系统调用例外 | Vol1 §2.2.10.1 | ✓ |
| `LL/LLV/SC/SCV` 助记符 | Vol1 §2.2.7.4 | ⚠️ 硬件是 3 操作数 `LL.W rd, rj, si14`；Go 汇编器对 `(R), R` 形式是否自动填 si14=0 需 P1.D 编译验证 |
| 信号 handler ucontext 中 `REG_PC=0xB0` 偏移 | （不在 Vol1 范围） | ⚠️ 基于 glibc `sysdeps/.../loongarch/sys/ucontext.h` 推算，运行时验证 |

附加收获：
- 3A5000 支持 AM\* 原子指令（Vol1 §2.2.10.5: CPUCFG bit22 LAM=1），未来若 LL/SC 性能不够可切到 `AMSWAP_DB.D` 等。
- e_machine = 258 (EM_LOONGARCH) 确认（ELF psABI Table 5），与 `AUDIT_ARCH_LOONGARCH64=0xc0000102` 推算一致。

## 编译指引（占位，待 P1.D 完成后填充）

```bash
# x86 编译机
docker buildx use loong-builder        # 复用已有 instance
docker run --rm --platform=linux/loong64 ghcr.io/loong64/debian:trixie-slim uname -m
./scripts/build-runsc.sh
# 产出 bazel-bin/runsc/runsc_/runsc (linux/loong64)
```

## 部署到银河麒麟（占位）

```bash
scp runsc root@kylin-loong:/usr/local/bin/
# /etc/docker/daemon.json:
# { "runtimes": { "runsc": { "path": "/usr/local/bin/runsc" } } }
systemctl restart docker
docker run --rm --runtime=runsc --network=none oj-c:loong64 \
    sh -c 'echo "int main(){puts(\"ok\");}" > /t.c && cc /t.c -o /t && /t'
```

## ✅ 移植跑通里程碑 (2026-05-30)

`docker run --runtime=runsc ghcr.io/loong64/debian:trixie-slim echo hello` → **hello** (exit 0)，在银河麒麟 V11 LoongArch64 (3A5000, 内核 6.6) 上验证。

### 运行期 bug 修复链 (v3→v12)
| 版本 | 根因 | 修复 |
|---|---|---|
| v3 | LoongArch 内核忽略 mmap hint → stub 地址死循环 | stub mmap 加 `MAP_FIXED_NOREPLACE` (pkg/sentry/platform/ptrace/stub_unsafe.go) |
| v4 | TaskSize 1<<48 超出 LoongArch 用户空间上界 | mm_loong64.go: feasibleTaskSizes = 1<<47 |
| v5/v6 | vDSO Binary 为空 → 解析 EOF | 用 loongarch64-linux-gnu-gcc 编最小 vDSO ELF，独立文件名避开 arch_genrule 冲突 |
| v7 | sentry ELF loader 只认 EM_X86_64/EM_AARCH64 | pkg/sentry/loader/elf.go 加 case 258 (EM_LOONGARCH) → arch.LOONGARCH64 |
| v8 | gofer host seccomp 缺 statx → SIGSYS 杀进程 | fsgofer/filter/config_loong64.go 补 SYS_STATX (LoongArch 无 fstat) |
| v9 | 未注册 LoongArch syscall dispatch table → "no syscall table found" | 新建 syscalls/linux/linux64_loong64.go，复用 ARM64.Table (asm-generic 编号一致) |
| v12 | **syscall arg0 取错**：LoongArch 内核 entry 先存 orig_a0 再设 a0=-ENOSYS；SyscallSaveOrig 误用 a0 覆盖 orig_a0 | SyscallSaveOrig 空实现；SyscallArgs 直接读 c.Regs.OrigA0 (syscalls_loong64.go) |

关键诊断手段：x86 host 上 qemu-user + bazel 交叉编译迭代；龙芯机上 strace gofer + sentry --strace + 在 SyscallArgs 临时 dump 寄存器，定位真实 arg0 在 orig_a0。
