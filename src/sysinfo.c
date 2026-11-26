#include "sysinfo.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/statvfs.h>

int parse_meminfo(const char *text, MemInfo *out) {
    if (text == NULL || out == NULL) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    /* MemAvailable is optional, MemTotal is required, so both are tracked. */
    int has_total = 0;
    int has_avail = 0;

    const char *p = text;

    while (*p != '\0') {
        char key[64] = {0};
        unsigned long long val = 0;
        if (sscanf(p, "%63[^:\n]: %llu", key, &val) == 2) {
            if (strcmp(key, "MemTotal") == 0) {
                out->mem_total_kib = (uint64_t)val;
                has_total = 1;
            } else if (strcmp(key, "MemFree") == 0) {
                out->mem_free_kib = (uint64_t)val;
            } else if (strcmp(key, "MemAvailable") == 0) {
                out->mem_avail_kib = (uint64_t)val;
                has_avail = 1;
            } else if (strcmp(key, "Buffers") == 0) {
                out->mem_buffers_kib = (uint64_t)val;
            } else if (strcmp(key, "Cached") == 0) {
                out->mem_cached_kib = (uint64_t)val;
            } else if (strcmp(key, "SReclaimable") == 0) {
                out->mem_sreclaimable_kib = (uint64_t)val;
            } else if (strcmp(key, "SwapTotal") == 0) {
                out->swap_total_kib = (uint64_t)val;
            } else if (strcmp(key, "SwapFree") == 0) {
                out->swap_free_kib = (uint64_t)val;
            }
        }
        const char *nl = strchr(p, '\n');
        if (nl == NULL) {
            break;
        }
        p = nl + 1;
    }

    if (!has_total || out->mem_total_kib == 0) {
        return -1;
    }
    if (!has_avail) {
        uint64_t approx_avail = out->mem_free_kib + out->mem_buffers_kib + out->mem_cached_kib + out->mem_sreclaimable_kib;
        out->mem_avail_kib = (approx_avail <= out->mem_total_kib) ? approx_avail : out->mem_total_kib;
    }

    out->mem_used_kib = (out->mem_total_kib >= out->mem_avail_kib) ? (out->mem_total_kib - out->mem_avail_kib) : 0;
    out->swap_used_kib = (out->swap_total_kib >= out->swap_free_kib) ? (out->swap_total_kib - out->swap_free_kib) : 0;

    return 0;
}

int parse_uptime(const char *text, uint64_t *uptime_sec_out) {
    if (text == NULL || uptime_sec_out == NULL) {
        return -1;
    }
    double up = -1.0;
    if (sscanf(text, "%lf", &up) != 1 || up < 0.0) {
        return -1;
    }
    *uptime_sec_out = (uint64_t)up;

    return 0;
}

int parse_loadavg(const char *text, LoadAvg *out) {
    if (text == NULL || out == NULL) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    int running = 0, total = 0;
    int matched = sscanf(text, "%lf %lf %lf %d/%d", &out->load1, &out->load5, &out->load15, &running, &total);
    if (matched < 3 || out->load1 < 0.0 || out->load5 < 0.0 || out->load15 < 0.0) {
        return -1;
    }
    if (matched == 5 && running >= 0 && total >= 0) {
        out->running_entities = running;
        out->total_entities = total;
    }
    return 0;
}

int is_physical_mount(const char *dev, const char *mnt, const char *fstype) {
    if (dev == NULL || mnt == NULL || fstype == NULL) {
        return 0;
    }
    if (strncmp(dev, "/dev/", 5) != 0) {
        return 0;
    }
    if (strncmp(dev, "/dev/loop", 9) == 0 || strncmp(dev, "/dev/ram", 8) == 0 || strncmp(dev, "/dev/zram", 9) == 0) {
        return 0;
    }
    if (strcmp(fstype, "squashfs") == 0 ||
        strcmp(fstype, "tmpfs") == 0 ||
        strcmp(fstype, "devtmpfs") == 0 ||
        strcmp(fstype, "overlay") == 0 ||
        strcmp(fstype, "iso9660") == 0) {
        return 0;
    }
    if (strncmp(mnt, "/run", 4) == 0 ||
        strncmp(mnt, "/sys", 4) == 0 ||
        strncmp(mnt, "/proc", 5) == 0 ||
        strncmp(mnt, "/dev", 4) == 0 ||
        strncmp(mnt, "/snap", 5) == 0) {
        return 0;
    }

    return 1;
}

static int read_file_to_buf(const char *path, char *buf, size_t buf_sz) {
    if (path == NULL || buf == NULL || buf_sz <= 1) {
        return -1;
    }
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }
    size_t n = fread(buf, 1, buf_sz - 1, f);
    fclose(f);
    buf[n] = '\0';
    return (n > 0) ? 0 : -1;
}

int sysinfo_read_mem(MemInfo *out) {
    char buf[4096];
    if (read_file_to_buf("/proc/meminfo", buf, sizeof(buf)) != 0) {
        return -1;
    }
    return parse_meminfo(buf, out);
}

int sysinfo_read_uptime(uint64_t *uptime_sec_out) {
    char buf[128];
    if (read_file_to_buf("/proc/uptime", buf, sizeof(buf)) != 0) {
        return -1;
    }
    return parse_uptime(buf, uptime_sec_out);
}

int sysinfo_read_loadavg(LoadAvg *out) {
    char buf[128];
    if (read_file_to_buf("/proc/loadavg", buf, sizeof(buf)) != 0) {
        return -1;
    }
    return parse_loadavg(buf, out);
}

static int read_millideg(const char *path, long *out) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }
    long value = 0;
    int ok = fscanf(f, "%ld", &value);
    fclose(f);
    if (ok != 1 || value <= 0 || value >= 200000) {
        return -1;
    }
    *out = value;
    return 0;
}

static int zone_temp_by_type(const char *want, long *out) {
    DIR *d = opendir("/sys/class/thermal");
    if (d == NULL) {
        return -1;
    }
    int found = -1;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && found != 0) {
        if (strncmp(ent->d_name, "thermal_zone", 12) != 0) {
            continue;
        }
        char tpath[320], vpath[320];
        snprintf(tpath, sizeof(tpath), "/sys/class/thermal/%s/type", ent->d_name);
        snprintf(vpath, sizeof(vpath), "/sys/class/thermal/%s/temp", ent->d_name);
        char type[64] = {0};
        FILE *tf = fopen(tpath, "r");
        if (tf == NULL) {
            continue;
        }
        if (fgets(type, sizeof(type), tf) == NULL) {
            fclose(tf);
            continue;
        }
        fclose(tf);
        type[strcspn(type, "\n")] = '\0';
        if (strcmp(type, want) == 0 && read_millideg(vpath, out) == 0) {
            found = 0;
        }
    }
    closedir(d);
    return found;
}

static int hwmon_temp_by_name(const char *want, long *out) {
    DIR *d = opendir("/sys/class/hwmon");
    if (d == NULL) {
        return -1;
    }
    int found = -1;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && found != 0) {
        if (strncmp(ent->d_name, "hwmon", 5) != 0) {
            continue;
        }
        char npath[320];
        snprintf(npath, sizeof(npath), "/sys/class/hwmon/%s/name", ent->d_name);
        char name[64] = {0};
        FILE *nf = fopen(npath, "r");
        if (nf == NULL) {
            continue;
        }
        if (fgets(name, sizeof(name), nf) == NULL) {
            fclose(nf);
            continue;
        }
        fclose(nf);
        name[strcspn(name, "\n")] = '\0';
        if (strcmp(name, want) != 0) {
            continue;
        }
        char vpath[320];
        snprintf(vpath, sizeof(vpath), "/sys/class/hwmon/%s/temp1_input", ent->d_name);
        if (read_millideg(vpath, out) == 0) {
            found = 0;
        }
    }
    closedir(d);
    return found;
}

double sysinfo_read_temp_celsius(void) {
    static const char *const hwmon_pref[] = { "coretemp", "k10temp", "zenpower", "asus" };
    static const char *const zone_pref[] = { "x86_pkg_temp", "TCPU", "SEN3" };

    long millideg = 0;
    for (size_t i = 0; i < sizeof(hwmon_pref) / sizeof(hwmon_pref[0]); ++i) {
        if (hwmon_temp_by_name(hwmon_pref[i], &millideg) == 0) {
            return (double)millideg / 1000.0;
        }
    }
    for (size_t i = 0; i < sizeof(zone_pref) / sizeof(zone_pref[0]); ++i) {
        if (zone_temp_by_type(zone_pref[i], &millideg) == 0) {
            return (double)millideg / 1000.0;
        }
    }

    /* last resort: any zone that is not a firmware placeholder */
    DIR *d = opendir("/sys/class/thermal");
    if (d != NULL) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (strncmp(ent->d_name, "thermal_zone", 12) != 0) {
                continue;
            }
            char tpath[320], vpath[320];
            snprintf(tpath, sizeof(tpath), "/sys/class/thermal/%s/type", ent->d_name);
            snprintf(vpath, sizeof(vpath), "/sys/class/thermal/%s/temp", ent->d_name);
            char type[64] = {0};
            FILE *tf = fopen(tpath, "r");
            if (tf == NULL) {
                continue;
            }
            if (fgets(type, sizeof(type), tf) == NULL) {
                fclose(tf);
                continue;
            }
            fclose(tf);
            type[strcspn(type, "\n")] = '\0';
            if (strcmp(type, "acpitz") == 0 || strcmp(type, "INT3400 Thermal") == 0) {
                continue;
            }
            if (read_millideg(vpath, &millideg) == 0) {
                closedir(d);
                return (double)millideg / 1000.0;
            }
        }
        closedir(d);
    }
    return -1.0;
}

static size_t all_digits_len(const char *s, size_t n) {
    size_t i = 0;
    while (i < n && s[i] >= '0' && s[i] <= '9') {
        ++i;
    }
    return i;
}

static size_t disk_parent_len(const char *base, size_t n) {
    if (strncmp(base, "nvme", 4) == 0 || strncmp(base, "mmcblk", 6) == 0) {
        /* nvme0n1p2, mmcblk0p1: the index follows a 'p' separator */
        size_t i = n;
        while (i > 0) {
            --i;
            if (base[i] == 'p' && i > 0 && all_digits_len(base + i + 1, n - i - 1) == n - i - 1) {
                return i;
            }
        }
        return n;
    }
    if (strncmp(base, "sd", 2) == 0 || strncmp(base, "hd", 2) == 0 ||
        strncmp(base, "vd", 2) == 0 || strncmp(base, "xvd", 3) == 0) {
        /* sda1, hdb2, vda3, xvda4: the index is the trailing run of digits */
        size_t i = n;
        while (i > 0 && base[i - 1] >= '0' && base[i - 1] <= '9') {
            --i;
        }
        return (i >= 2 && i < n) ? i : n;
    }
    return n;
}

void disk_parent_name(const char *device, char *dst, size_t dst_sz) {
    if (dst == NULL || dst_sz == 0) {
        return;
    }
    dst[0] = '\0';
    if (device == NULL) {
        return;
    }

    const char *base = device;
    size_t n = strlen(device);
    if (n >= 5 && strncmp(device, "/dev/", 5) == 0) {
        base += 5;
        n -= 5;
    }

    size_t len = (n > 0) ? disk_parent_len(base, n) : 0;
    if (len == 0) {
        /* "/dev/" alone has no base left; keep the device text instead of an empty name */
        len = strlen(device);
        base = device;
    }
    if (len >= dst_sz) {
        len = dst_sz - 1;
    }
    memcpy(dst, base, len);
    dst[len] = '\0';
}

int sysinfo_disks_aggregate(const DiskList *in, DiskList *out) {
    if (in == NULL || out == NULL) {
        return -1;
    }

    DiskList sum;
    memset(&sum, 0, sizeof(sum));

    /* A btrfs subvolume is mounted several times but statvfs reports the whole
     * filesystem every time, so each device is counted once per parent. */
    char seen[MAX_DISKS][sizeof(in->items[0].device)];
    size_t seen_count = 0;

    const size_t n = (in->count > MAX_DISKS) ? MAX_DISKS : in->count;
    for (size_t i = 0; i < n; ++i) {
        const DiskInfo *src = &in->items[i];
        int duplicate = 0;
        for (size_t k = 0; k < seen_count; ++k) {
            if (strcmp(seen[k], src->device) == 0) {
                duplicate = 1;
                break;
            }
        }
        if (duplicate) {
            /* the same filesystem seen through another mount: keep the widest
             * report, never add the numbers twice */
            char parent_dup[sizeof(src->device)];
            disk_parent_name(src->device, parent_dup, sizeof(parent_dup));
            for (size_t j = 0; j < sum.count; ++j) {
                if (strcmp(sum.items[j].device, parent_dup) == 0 &&
                    src->total_bytes > sum.items[j].total_bytes) {
                    sum.items[j].total_bytes = src->total_bytes;
                    sum.items[j].used_bytes = src->used_bytes;
                    sum.items[j].avail_bytes = src->avail_bytes;
                }
            }
            continue;
        }
        if (seen_count < MAX_DISKS) {
            snprintf(seen[seen_count++], sizeof(seen[0]), "%s", src->device);
        }

        char parent[sizeof(src->device)];
        disk_parent_name(src->device, parent, sizeof(parent));
        if (parent[0] == '\0') {
            continue;
        }

        DiskInfo *dst = NULL;
        for (size_t j = 0; j < sum.count; ++j) {
            if (strcmp(sum.items[j].device, parent) == 0) {
                dst = &sum.items[j];
                break;
            }
        }
        if (dst == NULL) {
            if (sum.count >= MAX_DISKS) {
                continue;
            }
            dst = &sum.items[sum.count++];
            snprintf(dst->device, sizeof(dst->device), "%s", parent);
            snprintf(dst->mountpoint, sizeof(dst->mountpoint), "%s", src->mountpoint);
            snprintf(dst->fstype, sizeof(dst->fstype), "%s", src->fstype);
        } else if (strlen(src->mountpoint) < strlen(dst->mountpoint)) {
            snprintf(dst->mountpoint, sizeof(dst->mountpoint), "%s", src->mountpoint);
            snprintf(dst->fstype, sizeof(dst->fstype), "%s", src->fstype);
        }
        dst->total_bytes += src->total_bytes;
        dst->used_bytes += src->used_bytes;
        dst->avail_bytes += src->avail_bytes;
    }

    *out = sum;
    return 0;
}

int sysinfo_read_disks(DiskList *out) {
    if (out == NULL) {
        return -1;
    }
    out->count = 0;

    FILE *f = fopen("/proc/mounts", "r");
    if (f == NULL) {
        return -1;
    }

    char line[512];
    while (fgets(line, sizeof(line), f) != NULL && out->count < MAX_DISKS) {
        char dev[128] = {0}, mnt[128] = {0}, fstype[64] = {0};
        if (sscanf(line, "%127s %127s %63s", dev, mnt, fstype) != 3) {
            continue;
        }
        if (!is_physical_mount(dev, mnt, fstype)) {
            continue;
        }

        /* one row per device: a btrfs/LVM system mounts one filesystem many
         * times, and every mount would report the same numbers */
        int duplicate = 0;
        for (size_t i = 0; i < out->count; ++i) {
            if (strcmp(out->items[i].device, dev) == 0) {
                duplicate = 1;
                if (strlen(mnt) < strlen(out->items[i].mountpoint)) {
                    snprintf(out->items[i].mountpoint, sizeof(out->items[i].mountpoint), "%.63s", mnt);
                }
                break;
            }
        }
        if (duplicate) {
            continue;
        }

        struct statvfs vfs;
        if (statvfs(mnt, &vfs) == 0 && vfs.f_blocks > 0) {
            DiskInfo *dk = &out->items[out->count++];
            snprintf(dk->device, sizeof(dk->device), "%s", dev);
            snprintf(dk->mountpoint, sizeof(dk->mountpoint), "%s", mnt);
            snprintf(dk->fstype, sizeof(dk->fstype), "%s", fstype);

            uint64_t frsize = (vfs.f_frsize > 0) ? (uint64_t)vfs.f_frsize : (uint64_t)vfs.f_bsize;
            dk->total_bytes = (uint64_t)vfs.f_blocks * frsize;
            uint64_t free_b = (uint64_t)vfs.f_bfree * frsize;
            dk->avail_bytes = (uint64_t)vfs.f_bavail * frsize;
            dk->used_bytes = (dk->total_bytes >= free_b) ? (dk->total_bytes - free_b) : 0;
        }
    }

    fclose(f);
    return 0;
}

int sysinfo_refresh(SystemInfo *out, int refresh_disks) {
    if (out == NULL) {
        return -1;
    }
    if (sysinfo_read_uptime(&out->uptime_sec) != 0) {
        return -1;
    }
    if (sysinfo_read_loadavg(&out->load) != 0) {
        return -1;
    }
    if (sysinfo_read_mem(&out->mem) != 0) {
        return -1;
    }
    out->temp_celsius = sysinfo_read_temp_celsius();
    if (refresh_disks) {
        sysinfo_read_disks(&out->disks);
    }
    return 0;
}
