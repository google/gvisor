// cstate_wake_probe: measures cross-thread futex wake latency as a function
// of how long the wakee's CPU has been idle, attributing each series to the
// cpuidle state the wakee actually entered. This is the cost gVisor systrap
// pays on every sentry<->stub handoff when the destination CPU is idle.
//
// Wakee mimics systrap: spins 20us (deepSleepTimeoutNS), then FUTEX_WAITs.
// Waker busy-spins for a controlled gap (so the wakee CPU idles that long),
// then FUTEX_WAKEs and measures time until the wakee runs.
//
// Output (machine-parseable, '|'-separated):
//   CSTATEPROBE_META|kernel=..|model=..|idle_driver=..|states=..|...
//   CSTATEPROBE_RES|gap_us=..|n=..|p50=..|p90=..|p99=..|max=..|dom=..
//   CSTATEPROBE_SUM|shallow_p90=..|deep_p90=..|delta_p90=..|deepest_adv=..
//
// Build: gcc -O2 -static -o cstate_wake_probe cstate_wake_probe.c -lpthread
// Usage: cstate_wake_probe [waker_cpu wakee_cpu]   (default: auto-pick)
//
// Run this on an otherwise idle machine: load keeps CPUs out of deep idle and
// hides the effect entirely.
//
// The summary reports p90, not p50, on purpose. The cpuidle governor may put
// only a minority of idles into the deepest state, in which case the median
// reflects the shallower states and hides the cost completely. Affected CPUs
// measure a deep p90 of 130-230us against a shallow p90 of a few us.
//
// Always check the 'dom' field, which names the idle state the wakee entered
// most often in that series. If the deepest state the CPU offers (see the
// 'states' field of CSTATEPROBE_META) never shows up there, the governor did
// not pick it and these numbers say nothing about its exit cost. To force it,
// disable the shallower states on the wakee CPU and re-run:
//
//	echo 1 | sudo tee /sys/devices/system/cpu/cpu<wakee>/cpuidle/state[12]/disable
//	... run the probe ...
//	echo 0 | sudo tee /sys/devices/system/cpu/cpu<wakee>/cpuidle/state[12]/disable
#define _GNU_SOURCE
#include <dirent.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#define MAX_CPUS 4096
#define MAX_STATES 16
#define MAX_GAPS 8

static atomic_int fword;    // 0=idle, 1=work posted, 2=ack
static atomic_long t_wake;  // waker timestamp, then wakee-computed latency
static long lat[20000];
static int wakee_cpu = -1, waker_cpu = -1;

static long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000L + ts.tv_nsec;
}

static int fwait(atomic_int *a, int v) { return syscall(SYS_futex, a, FUTEX_WAIT_PRIVATE, v, NULL, NULL, 0); }
static int fwake(atomic_int *a) { return syscall(SYS_futex, a, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0); }

static void pin(int cpu) {
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(cpu, &s);
    if (sched_setaffinity(0, sizeof(s), &s) != 0) {
        fprintf(stderr, "pin cpu%d failed\n", cpu);
        exit(1);
    }
}

static void *wakee_fn(void *arg) {
    (void)arg;
    pin(wakee_cpu);
    for (;;) {
        long spin_start = now_ns();
        while (atomic_load(&fword) != 1) {
            if (now_ns() - spin_start > 20000) {  // systrap deepSleepTimeoutNS
                while (atomic_load(&fword) != 1) fwait(&fword, 0);
                break;
            }
        }
        long t = now_ns() - atomic_load(&t_wake);
        atomic_store(&t_wake, t);  // publish latency before the ack
        atomic_store(&fword, 2);
        fwake(&fword);
    }
    return NULL;
}

static int cmpl(const void *a, const void *b) {
    long x = *(const long *)a, y = *(const long *)b;
    return (x > y) - (x < y);
}

// ---- small sysfs helpers ----

static int read_file(const char *path, char *buf, size_t n) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t r = fread(buf, 1, n - 1, f);
    fclose(f);
    while (r > 0 && (buf[r - 1] == '\n' || buf[r - 1] == ' ')) r--;
    buf[r] = 0;
    return 0;
}

static long read_long(const char *fmt, ...) {
    char path[256], buf[64];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(path, sizeof(path), fmt, ap);
    va_end(ap);
    if (read_file(path, buf, sizeof(buf)) != 0) return -1;
    return atol(buf);
}

// cpuidle states of the wakee CPU
static int nstates;
static char state_name[MAX_STATES][32];
static long state_lat[MAX_STATES];

static void load_states(int cpu) {
    nstates = 0;
    for (int i = 0; i < MAX_STATES; i++) {
        char path[256], buf[64];
        snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cpuidle/state%d/name", cpu, i);
        if (read_file(path, buf, sizeof(buf)) != 0) break;
        snprintf(state_name[i], sizeof(state_name[i]), "%s", buf);
        state_lat[i] = read_long("/sys/devices/system/cpu/cpu%d/cpuidle/state%d/latency", cpu, i);
        nstates++;
    }
}

static void snap_usage(int cpu, long *out) {
    for (int i = 0; i < nstates; i++)
        out[i] = read_long("/sys/devices/system/cpu/cpu%d/cpuidle/state%d/usage", cpu, i);
}

// ---- idle-CPU auto-pick ----

static int cpu_node[MAX_CPUS];

static void parse_cpulist(const char *list, int node) {
    // "0-31,64-95" -> cpu_node[..] = node
    const char *p = list;
    while (*p) {
        long a = strtol(p, (char **)&p, 10), b = a;
        if (*p == '-') b = strtol(p + 1, (char **)&p, 10);
        for (long c = a; c <= b && c < MAX_CPUS; c++) cpu_node[c] = node;
        if (*p == ',') p++;
    }
}

static void load_numa(void) {
    memset(cpu_node, 0, sizeof(cpu_node));
    for (int n = 0; n < 64; n++) {
        char path[128], buf[4096];
        snprintf(path, sizeof(path), "/sys/devices/system/node/node%d/cpulist", n);
        if (read_file(path, buf, sizeof(buf)) != 0) continue;
        parse_cpulist(buf, n);
    }
}

static int read_proc_stat(long *idle, long *total, int max) {
    FILE *f = fopen("/proc/stat", "r");
    if (!f) return 0;
    char line[512];
    int maxcpu = -1;
    while (fgets(line, sizeof(line), f)) {
        int cpu;
        long u, n, s, id, io, irq, sirq, st;
        if (sscanf(line, "cpu%d %ld %ld %ld %ld %ld %ld %ld %ld", &cpu, &u, &n, &s, &id, &io, &irq, &sirq, &st) >= 9 &&
            cpu >= 0 && cpu < max) {
            idle[cpu] = id + io;
            total[cpu] = u + n + s + id + io + irq + sirq + st;
            if (cpu > maxcpu) maxcpu = cpu;
        }
    }
    fclose(f);
    return maxcpu + 1;
}

static void pick_cpus(void) {
    static long i0[MAX_CPUS], t0[MAX_CPUS], i1[MAX_CPUS], t1[MAX_CPUS];
    int n = read_proc_stat(i0, t0, MAX_CPUS);
    usleep(300000);
    read_proc_stat(i1, t1, MAX_CPUS);
    if (n < 2) {
        fprintf(stderr, "cannot read /proc/stat\n");
        exit(1);
    }
    double best1 = -1, best2 = -1;
    int c1 = -1, c2 = -1;
    // idlest CPU overall (skip cpu0: timer/housekeeping target)
    for (int c = (n > 2 ? 1 : 0); c < n; c++) {
        long dt = t1[c] - t0[c];
        double f = dt > 0 ? (double)(i1[c] - i0[c]) / dt : 0;
        if (f > best1) { best1 = f; c1 = c; }
    }
    // idlest CPU on the same NUMA node (fall back to any node)
    for (int pass = 0; pass < 2 && c2 < 0; pass++) {
        best2 = -1;
        for (int c = (n > 2 ? 1 : 0); c < n; c++) {
            if (c == c1) continue;
            if (pass == 0 && cpu_node[c] != cpu_node[c1]) continue;
            long dt = t1[c] - t0[c];
            double f = dt > 0 ? (double)(i1[c] - i0[c]) / dt : 0;
            if (f > best2) { best2 = f; c2 = c; }
        }
    }
    wakee_cpu = c1;  // the measured (idling) side gets the idlest CPU
    waker_cpu = c2;
}

int main(int argc, char **argv) {
    load_numa();
    if (argc > 2) {
        waker_cpu = atoi(argv[1]);
        wakee_cpu = atoi(argv[2]);
    } else {
        pick_cpus();
    }
    load_states(wakee_cpu);

    char kernel[128] = "?", model[128] = "?", driver[64] = "none", igov[64] = "?", fgov[64] = "?", arch[32] = "?";
    {
        char buf[256];
        struct utsname un;
        if (uname(&un) == 0) {
            snprintf(kernel, sizeof(kernel), "%s", un.release);
            snprintf(arch, sizeof(arch), "%s", un.machine);
        }
        FILE *f = fopen("/proc/cpuinfo", "r");
        if (f) {
            while (fgets(buf, sizeof(buf), f)) {
                if (!strncmp(buf, "model name", 10)) {
                    char *c = strchr(buf, ':');
                    if (c) {
                        c += 2;
                        c[strcspn(c, "\n")] = 0;
                        snprintf(model, sizeof(model), "%s", c);
                    }
                    break;
                }
            }
            fclose(f);
        }
        read_file("/sys/devices/system/cpu/cpuidle/current_driver", driver, sizeof(driver));
        read_file("/sys/devices/system/cpu/cpuidle/current_governor", igov, sizeof(igov));
        char p[128];
        snprintf(p, sizeof(p), "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_governor", wakee_cpu);
        read_file(p, fgov, sizeof(fgov));
    }
    double load1 = 0;
    {
        FILE *f = fopen("/proc/loadavg", "r");
        if (f) {
            if (fscanf(f, "%lf", &load1) != 1) load1 = -1;
            fclose(f);
        }
    }

    printf("CSTATEPROBE_META|kernel=%s|arch=%s|model=%s|idle_driver=%s|idle_governor=%s|cpufreq_governor=%s|load1=%.2f|waker=%d|wakee=%d|wakee_node=%d|states=",
           kernel, arch, model, driver, igov, fgov, load1, waker_cpu, wakee_cpu, cpu_node[wakee_cpu]);
    for (int i = 0; i < nstates; i++) printf("%s%s:%ld", i ? "," : "", state_name[i], state_lat[i]);
    if (!nstates) printf("(none)");
    printf("\n");

    pin(waker_cpu);
    pthread_t th;
    pthread_create(&th, NULL, wakee_fn, NULL);
    usleep(100000);

    long gaps[MAX_GAPS] = {50, 250, 1000, 6000};
    int counts[MAX_GAPS] = {3000, 2000, 1200, 500};
    double p90s[MAX_GAPS];
    long u_before[MAX_STATES], u_after[MAX_STATES];

    for (int g = 0; g < 4; g++) {
        long gap_ns = gaps[g] * 1000;
        int n = counts[g];
        snap_usage(wakee_cpu, u_before);
        for (int i = 0; i < n; i++) {
            long start = now_ns();
            while (now_ns() - start < gap_ns) ;  // waker stays hot; wakee idles
            atomic_store(&t_wake, now_ns());
            atomic_store(&fword, 1);
            fwake(&fword);
            while (atomic_load(&fword) != 2) ;
            lat[i] = atomic_load(&t_wake);
            atomic_store(&fword, 0);
        }
        snap_usage(wakee_cpu, u_after);
        qsort(lat, n, sizeof(long), cmpl);
        p90s[g] = lat[(int)(n * 0.9)] / 1000.0;
        int dom = -1;
        long dmax = 0;
        for (int i = 0; i < nstates; i++) {
            long d = u_after[i] - u_before[i];
            if (d > dmax) { dmax = d; dom = i; }
        }
        printf("CSTATEPROBE_RES|gap_us=%ld|n=%d|p50=%.1f|p90=%.1f|p99=%.1f|max=%.1f|dom=%s:%ld\n",
               gaps[g], n, lat[n / 2] / 1000.0, p90s[g], lat[(int)(n * 0.99)] / 1000.0,
               lat[n - 1] / 1000.0, dom >= 0 ? state_name[dom] : "?", dmax);
        fflush(stdout);
    }

    long deepest = 0;
    for (int i = 0; i < nstates; i++)
        if (state_lat[i] > deepest) deepest = state_lat[i];
    double deep = p90s[3] > p90s[2] ? p90s[3] : p90s[2];
    printf("CSTATEPROBE_SUM|shallow_p90=%.1f|deep_p90=%.1f|delta_p90=%.1f|deepest_adv=%ld\n",
           p90s[0], deep, deep - p90s[0], deepest);
    return 0;
}
