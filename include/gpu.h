#ifndef MINITOP_GPU_H
#define MINITOP_GPU_H

#include <stdint.h>

typedef struct GpuInfo {
    int      present;
    int      util_pct;          /* 0..100, or -1 when the source has no utilization */
    uint64_t mem_used_bytes;
    uint64_t mem_total_bytes;
    unsigned clock_mhz;         /* 0 when unknown */
    char     vendor[16];        /* "NVIDIA", "AMD", "Intel" or "" */
} GpuInfo;

/**
 * Detects a GPU and fills out. Sources are tried in order, first success wins:
 *   1. nvidia-smi (via `timeout 1s` + popen, one shot per call)
 *   2. AMD sysfs (gpu_busy_percent, mem_info_vram_*, pp_dpm_sclk)
 *   3. Intel sysfs (gt_cur_freq_mhz; clock only, util_pct = -1)
 * On failure out is zeroed (present = 0).
 * @return 0 when a GPU was found, -1 otherwise.
 */
int gpu_read(GpuInfo *out);

/**
 * Parses one nvidia-smi CSV line:
 *   "utilization.gpu, memory.used, memory.total, clocks.gr" in MiB and MHz,
 * e.g. "12, 1024, 8192, 2100".
 * Memory is converted to bytes. "[N/A]" / "N/A" is accepted as 0 for memory and
 * clock but not for utilization. util_pct is clamped to 0..100; a negative
 * field or trailing garbage is rejected as malformed. Only the first line is
 * parsed. out is written only on success.
 * @return 0 on success, -1 on malformed input.
 */
int gpu_parse_nvidia_csv(const char *text, GpuInfo *out);

/**
 * Parses amdgpu pp_dpm_sclk text (lines like "0: 2100Mhz *") and returns the
 * MHz value of the line marked with '*'.
 * @return 0 on success, -1 when no marked line or no number is present.
 */
int gpu_parse_amd_sclk(const char *text, unsigned *mhz);

#endif
