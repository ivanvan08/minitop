#include "gpu.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MIB          (1024ULL * 1024ULL)
#define PATH_MAX_LEN 320 /* "/sys/class/drm/" + NAME_MAX + longest attribute */
#define CLOCK_MAX_MHZ 1000000ULL /* reject nonsense sensor values */

#define NVIDIA_QUERY \
    "timeout 1s nvidia-smi --query-gpu=utilization.gpu,memory.used,memory.total," \
    "clocks.gr --format=csv,noheader,nounits 2>/dev/null"

static const char *skip_ws(const char *p) {
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    return p;
}

/* Parses one non-negative decimal CSV field, advances *cursor past trailing
 * whitespace. allow_na accepts "[N/A]" / "N/A" and yields 0. */
static int parse_field_u64(const char **cursor, uint64_t *out, int allow_na) {
    const char *p = skip_ws(*cursor);
    unsigned long long v;

    if (allow_na && strncmp(p, "[N/A]", 5) == 0) {
        p += 5;
        v = 0;
    } else if (allow_na && strncmp(p, "N/A", 3) == 0) {
        p += 3;
        v = 0;
    } else {
        char *end = NULL;
        if (!isdigit((unsigned char)*p)) {
            return -1;
        }
        errno = 0;
        v = strtoull(p, &end, 10);
        if (end == p || errno != 0) {
            return -1;
        }
        p = end;
    }

    *out = (uint64_t)v;
    *cursor = skip_ws(p);
    return 0;
}

int gpu_parse_nvidia_csv(const char *text, GpuInfo *out) {
    if (text == NULL || out == NULL) {
        return -1;
    }

    const char *p = text;
    uint64_t util = 0, used = 0, total = 0, clock = 0;
    GpuInfo tmp;

    if (parse_field_u64(&p, &util, 0) != 0 || *p != ',') {
        return -1;
    }
    p++;
    if (parse_field_u64(&p, &used, 1) != 0 || *p != ',') {
        return -1;
    }
    p++;
    if (parse_field_u64(&p, &total, 1) != 0 || *p != ',') {
        return -1;
    }
    p++;
    if (parse_field_u64(&p, &clock, 1) != 0) {
        return -1;
    }

    if (*p != '\0' && *p != '\n' && *p != '\r') {
        return -1;
    }
    if (used > UINT64_MAX / MIB || total > UINT64_MAX / MIB) {
        return -1;
    }
    if (clock > CLOCK_MAX_MHZ) {
        return -1;
    }

    memset(&tmp, 0, sizeof(tmp));
    tmp.present = 1;
    tmp.util_pct = (util > 100) ? 100 : (int)util;
    tmp.mem_used_bytes = used * MIB;
    tmp.mem_total_bytes = total * MIB;
    tmp.clock_mhz = (unsigned)clock;
    snprintf(tmp.vendor, sizeof(tmp.vendor), "NVIDIA");

    *out = tmp;
    return 0;
}

int gpu_parse_amd_sclk(const char *text, unsigned *mhz) {
    if (text == NULL || mhz == NULL) {
        return -1;
    }

    const char *p = text;
    while (*p != '\0') {
        const char *nl = strchr(p, '\n');
        size_t len = (nl != NULL) ? (size_t)(nl - p) : strlen(p);

        if (memchr(p, '*', len) != NULL) {
            const char *limit = p + len;
            const char *colon = memchr(p, ':', len);
            const char *q;
            char *end = NULL;
            unsigned long v;

            /* skip the "N:" state index, the number follows the colon */
            q = (colon != NULL) ? colon + 1 : p;
            while (q < limit && !isdigit((unsigned char)*q)) {
                q++;
            }
            if (q == limit) {
                return -1;
            }
            errno = 0;
            v = strtoul(q, &end, 10);
            if (end == q || errno != 0 || v > CLOCK_MAX_MHZ) {
                return -1;
            }
            *mhz = (unsigned)v;
            return 0;
        }

        if (nl == NULL) {
            break;
        }
        p = nl + 1;
    }

    return -1;
}

static int read_first_line(const char *path, char *buf, size_t buf_sz) {
    FILE *f = fopen(path, "r");
    char *r;

    if (f == NULL) {
        return -1;
    }
    r = fgets(buf, (int)buf_sz, f);
    fclose(f);
    return (r != NULL) ? 0 : -1;
}

static int read_u64_file(const char *path, uint64_t *out) {
    char buf[64];
    char *end = NULL;
    unsigned long long v;

    if (read_first_line(path, buf, sizeof(buf)) != 0) {
        return -1;
    }
    errno = 0;
    v = strtoull(buf, &end, 10);
    if (end == buf || errno != 0) {
        return -1;
    }
    *out = (uint64_t)v;
    return 0;
}

static int read_small_file(const char *path, char *buf, size_t buf_sz) {
    FILE *f = fopen(path, "r");
    size_t n;

    if (f == NULL) {
        return -1;
    }
    n = fread(buf, 1, buf_sz - 1, f);
    fclose(f);
    buf[n] = '\0';
    return (n > 0) ? 0 : -1;
}

/* "card" followed by digits only, so connectors like card0-DP-1 are skipped. */
static int is_card_name(const char *name) {
    const char *p = name;

    if (strncmp(p, "card", 4) != 0) {
        return 0;
    }
    p += 4;
    if (*p < '0' || *p > '9') {
        return 0;
    }
    while (*p >= '0' && *p <= '9') {
        p++;
    }
    return *p == '\0';
}

static void fill_amd_extras(const char *card, GpuInfo *out) {
    char path[PATH_MAX_LEN];
    char text[1024];
    uint64_t v = 0;
    unsigned mhz = 0;

    snprintf(path, sizeof(path), "/sys/class/drm/%s/device/mem_info_vram_used", card);
    if (read_u64_file(path, &v) == 0) {
        out->mem_used_bytes = v;
    }
    snprintf(path, sizeof(path), "/sys/class/drm/%s/device/mem_info_vram_total", card);
    if (read_u64_file(path, &v) == 0) {
        out->mem_total_bytes = v;
    }
    snprintf(path, sizeof(path), "/sys/class/drm/%s/device/pp_dpm_sclk", card);
    if (read_small_file(path, text, sizeof(text)) == 0 &&
        gpu_parse_amd_sclk(text, &mhz) == 0) {
        out->clock_mhz = mhz;
    }
}

static int gpu_try_nvidia(GpuInfo *out) {
    FILE *p = popen(NVIDIA_QUERY, "r");
    char line[256];
    int rc = -1;

    if (p == NULL) {
        return -1;
    }
    if (fgets(line, sizeof(line), p) != NULL) {
        rc = gpu_parse_nvidia_csv(line, out);
    }
    pclose(p);
    return rc;
}

static int gpu_try_amd(GpuInfo *out) {
    DIR *d = opendir("/sys/class/drm");
    struct dirent *entry;
    int rc = -1;

    if (d == NULL) {
        return -1;
    }
    while ((entry = readdir(d)) != NULL) {
        char path[PATH_MAX_LEN];
        uint64_t busy = 0;

        if (!is_card_name(entry->d_name)) {
            continue;
        }
        snprintf(path, sizeof(path), "/sys/class/drm/%s/device/gpu_busy_percent", entry->d_name);
        if (read_u64_file(path, &busy) != 0) {
            continue;
        }

        memset(out, 0, sizeof(*out));
        out->present = 1;
        out->util_pct = (busy > 100) ? 100 : (int)busy;
        snprintf(out->vendor, sizeof(out->vendor), "AMD");
        fill_amd_extras(entry->d_name, out);
        rc = 0;
        break;
    }
    closedir(d);
    return rc;
}

static int gpu_try_intel(GpuInfo *out) {
    DIR *d = opendir("/sys/class/drm");
    struct dirent *entry;
    int found = -1;

    if (d == NULL) {
        return -1;
    }
    while ((entry = readdir(d)) != NULL) {
        char path[PATH_MAX_LEN];
        uint64_t mhz = 0;

        if (!is_card_name(entry->d_name)) {
            continue;
        }
        snprintf(path, sizeof(path), "/sys/class/drm/%s/gt_cur_freq_mhz", entry->d_name);
        if (read_u64_file(path, &mhz) != 0) {
            continue;
        }

        memset(out, 0, sizeof(*out));
        out->present = 1;
        out->util_pct = -1; /* i915 exposes no busy percentage here */
        out->clock_mhz = (mhz > CLOCK_MAX_MHZ) ? 0 : (unsigned)mhz;
        snprintf(out->vendor, sizeof(out->vendor), "Intel");
        found = 0;
        break;
    }
    closedir(d);
    return found;
}

int gpu_read(GpuInfo *out) {
    if (out == NULL) {
        return -1;
    }
    memset(out, 0, sizeof(*out));

    if (gpu_try_nvidia(out) == 0) {
        return 0;
    }
    if (gpu_try_amd(out) == 0) {
        return 0;
    }
    if (gpu_try_intel(out) == 0) {
        return 0;
    }

    memset(out, 0, sizeof(*out));
    return -1;
}
