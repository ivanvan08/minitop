#ifndef MINITOP_SYSINFO_H
#define MINITOP_SYSINFO_H

#include <stddef.h>
#include <stdint.h>

#define MAX_DISKS 16

typedef struct MemInfo {
    uint64_t mem_total_kib;
    uint64_t mem_free_kib;
    uint64_t mem_avail_kib;
    uint64_t mem_buffers_kib;
    uint64_t mem_cached_kib;
    uint64_t mem_sreclaimable_kib;
    uint64_t mem_used_kib;
    uint64_t swap_total_kib;
    uint64_t swap_free_kib;
    uint64_t swap_used_kib;
} MemInfo;

typedef struct LoadAvg {
    double load1;
    double load5;
    double load15;
    int    running_entities;
    int    total_entities;
} LoadAvg;

typedef struct DiskInfo {
    char     device[64];
    char     mountpoint[64];
    char     fstype[32];
    uint64_t total_bytes;
    uint64_t used_bytes;
    uint64_t avail_bytes;
} DiskInfo;

typedef struct DiskList {
    DiskInfo items[MAX_DISKS];
    size_t   count;
} DiskList;

typedef struct SystemInfo {
    uint64_t uptime_sec;
    LoadAvg  load;
    MemInfo  mem;
    double   cpu_pct;
    double   temp_celsius; /* -1.0 if unavailable (e.g. inside a VM, or just in error case) */
    DiskList disks;
} SystemInfo;

/* pure text parsers */
int parse_meminfo(const char *text, MemInfo *out);
int parse_uptime(const char *text, uint64_t *uptime_sec_out);
int parse_loadavg(const char *text, LoadAvg *out);
int is_physical_mount(const char *dev, const char *mnt, const char *fstype);

/* LIVE readers (/proc, /sys) */
int    sysinfo_read_mem(MemInfo *out);
int    sysinfo_read_uptime(uint64_t *uptime_sec_out);
int    sysinfo_read_loadavg(LoadAvg *out);
double sysinfo_read_temp_celsius(void);
int    sysinfo_read_disks(DiskList *out);

/**
 * Writes the parent (whole-disk) name of a device into dst, without the "/dev/"
 * prefix: "nvme0n1p2" -> "nvme0n1", "sda1" -> "sda", "mmcblk0p1" -> "mmcblk0",
 * "dm-0" -> "dm-0", "mapper/omarchy_root" -> "mapper/omarchy_root".
 * Never yields an empty name for a non-empty device.
 */
void disk_parent_name(const char *device, char *dst, size_t dst_sz);

/**
 * Collapses one row per partition into one row per parent device: used/total/avail
 * are summed over the disk's mounted partitions, device holds the parent name and
 * mountpoint the shortest mountpoint among them. in and out may be the same list.
 * Returns 0 on success, -1 on NULL arguments; out->count never exceeds MAX_DISKS.
 */
int sysinfo_disks_aggregate(const DiskList *in, DiskList *out);

/**
 * Refreshes header metrics. Disk usage is refreshed only when refresh_disks does not equal 0;
 * (e.g. once every 5-10 seconds)
 */
int sysinfo_refresh(SystemInfo *out, int refresh_disks);

#endif
