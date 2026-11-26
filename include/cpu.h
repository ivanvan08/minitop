#ifndef MINITOP_CPU_H
#define MINITOP_CPU_H

#include <stdint.h>

typedef struct CpuSample {
    uint64_t user;
    uint64_t nice;
    uint64_t system;
    uint64_t idle;
    uint64_t iowait;
    uint64_t irq;
    uint64_t softirq;
    uint64_t steal;
    uint64_t idle_all;
    uint64_t busy_all;
    uint64_t total;
} CpuSample;

/**
 * Parses the aggregate "cpu ..." line from /proc/stat text (first 8 fields).
 * @return 0 on success, -1 on parse error.
 */
int parse_proc_stat_cpu(const char *text, CpuSample *out);

/**
 * Reads current CPU counters from /proc/stat.
 * @return 0 on success, -1 on error.
 */
int cpu_read_sample(CpuSample *out);

/**
 * Computes total system CPU usage percentage (0.0 .. 100.0) between two samples.
 * Optionally outputs delta_total_out (total ticks elapsed across all cores) for per-process CPU%.
 */
double cpu_calc_usage_pct(const CpuSample *prev, const CpuSample *curr, uint64_t *delta_total_out);

#endif
