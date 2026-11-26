#include "cpu.h"
#include <stdio.h>
#include <string.h>

static inline uint64_t dlta(uint64_t cur, uint64_t prev) {
    return (cur >= prev) ? (cur - prev) : 0;
}

int parse_proc_stat_cpu(const char *text, CpuSample *out) {
    if (text == NULL || out == NULL) {
        return -1;
    }
    memset(out, 0, sizeof(*out));

    const char *p = text;
    while (*p != '\0') {
        if (strncmp(p, "cpu ", 4) == 0 || strncmp(p, "cpu\t", 4) == 0) {
            unsigned long long u = 0, n = 0, s = 0, id = 0;
            unsigned long long io = 0, irq = 0, sirq = 0, st = 0;

            int matched = sscanf(p + 3, "%llu %llu %llu %llu %llu %llu %llu %llu", &u, &n, &s, &id, &io, &irq, &sirq, &st);
            if (matched < 4) {
                return -1;
            }
            out->user = (uint64_t)u;
            out->nice = (uint64_t)n;
            out->system = (uint64_t)s;
            out->idle = (uint64_t)id;
            out->iowait = (matched >= 5) ? (uint64_t)io : 0;
            out->irq = (matched >= 6) ? (uint64_t)irq : 0;
            out->softirq = (matched >= 7) ? (uint64_t)sirq : 0;
            out->steal = (matched >= 8) ? (uint64_t)st : 0;
            out->idle_all = out->idle + out->iowait;
            out->busy_all = out->user + out->nice + out->system + out->irq + out->softirq + out->steal;
            out->total = out->idle_all + out->busy_all;

            return 0;
        }
        const char *nl = strchr(p, '\n');
        if (nl == NULL) {
            break;
        }
        p = nl + 1;
    }

    return -1;
}

int cpu_read_sample(CpuSample *out) {
    if (out == NULL) {
        return -1;
    }
    FILE *f = fopen("/proc/stat", "r");
    if (f == NULL) {
        return -1;
    }
    char line[512];
    if (fgets(line, sizeof(line), f) == NULL) {
        fclose(f);
        return -1;
    }
    fclose(f);

    return parse_proc_stat_cpu(line, out);
}

double cpu_calc_usage_pct(const CpuSample *prev, const CpuSample *curr, uint64_t *delta_total_out) {
    if (prev == NULL || curr == NULL) {
        if (delta_total_out != NULL) {
            *delta_total_out = 0;
        }
        return 0.0;
    }

    uint64_t d_idle = dlta(curr->idle, prev->idle) + dlta(curr->iowait, prev->iowait);
    uint64_t d_busy = dlta(curr->busy_all, prev->busy_all);
    uint64_t d_tot  = d_idle + d_busy;
    if (delta_total_out != NULL) {
        *delta_total_out = d_tot;
    }
    if (d_tot == 0) {
        return 0.0;
    }
    double pct = ((double)d_busy / (double)d_tot) * 100.0;
    if (pct < 0.0) pct = 0.0;
    if (pct > 100.0) pct = 100.0;

    return pct;
}
