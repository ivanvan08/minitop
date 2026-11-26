#include "procs.h"
#include "flags.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <errno.h>
#include <sys/stat.h>


int proclist_init(ProcList *list, size_t initial_capacity) {
    if (list == NULL) {
        return -1;
    }
    list->count = 0;
    list->capacity = (initial_capacity > 0) ? initial_capacity : 64;
    list->items = (ProcessInfo *)calloc(list->capacity, sizeof(ProcessInfo));
    if (list->items == NULL) {
        list->capacity = 0;
        return -1;
    }
    return 0;
}

void proclist_clear(ProcList *list) {
    if (list != NULL) {
        list->count = 0;
    }
}

int proclist_push(ProcList *list, const ProcessInfo *item) {
    if (list == NULL || item == NULL) {
        return -1;
    }
    if (list->items == NULL) {
        if (proclist_init(list, 64) != 0) {
            return -1;
        }
    }
    if (list->count >= list->capacity) {
        size_t new_cap = list->capacity * 2;
        ProcessInfo *tmp = (ProcessInfo *)realloc(list->items, new_cap * sizeof(ProcessInfo));
        if (tmp == NULL) {
            return -1;
        }
        list->items = tmp;
        list->capacity = new_cap;
    }
    list->items[list->count++] = *item;
    return 0;
}

void proclist_free(ProcList *list) {
    if (list == NULL) {
        return;
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

void format_time_plus(uint64_t utime, uint64_t stime, long hz, char *buf, size_t buf_sz) {
    if (buf == NULL || buf_sz == 0) {
        return;
    }
    if (hz <= 0) {
        hz = 100;
    }
    uint64_t total_centisec = ((utime + stime) * 100ULL) / (uint64_t)hz;
    uint64_t mins = total_centisec / 6000ULL;
    uint64_t secs = (total_centisec / 100ULL) % 60ULL;
    uint64_t cent = total_centisec % 100ULL;

    snprintf(buf, buf_sz, "%llu:%02llu.%02llu",
             (unsigned long long)mins,
             (unsigned long long)secs,
             (unsigned long long)cent);
}

int parse_proc_pid_stat(const char *line, size_t line_len, ProcessInfo *out,
                        long page_size, long hz) {
    if (line == NULL || out == NULL || page_size <= 0) {
        return -1;
    }
    /* /proc reads are length-delimited, so every scan below stops at end: a
     * line cut inside the comm, right after ") ", or inside the numeric fields
     * is rejected without reading a byte past the buffer. */
    const char *end = line + line_len;

    /* "<pid> (<comm>) <state> <fields...>" */
    const char *p = line;
    long long pid_val = 0;
    while (p < end && *p >= '0' && *p <= '9') {
        pid_val = pid_val * 10 + (*p - '0');
        if (pid_val > INT_MAX) {
            return -1;
        }
        ++p;
    }
    if (p == line || pid_val <= 0) {
        return -1;
    }
    if (end - p < 2 || p[0] != ' ' || p[1] != '(') {
        return -1;
    }

    const char *lparen = p + 1;
    const char *rparen = NULL;
    for (const char *q = end; q > lparen + 1; --q) {
        if (q[-1] == ')') {
            rparen = q - 1;
            break;
        }
    }
    if (rparen == NULL) {
        return -1;
    }
    /* The comm closes with ") " and the state character follows it. */
    if (end - rparen < 3 || rparen[1] != ' ') {
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->pid  = (pid_t)pid_val;
    out->risk = -1;
    out->trusted = 0;

    char raw_comm[64];
    size_t comm_len = (size_t)(rparen - (lparen + 1));
    if (comm_len >= sizeof(raw_comm)) {
        comm_len = sizeof(raw_comm) - 1;
    }
    memcpy(raw_comm, lparen + 1, comm_len);
    raw_comm[comm_len] = '\0';
    sanitize_display_str(out->comm, sizeof(out->comm), raw_comm);

    /* Fields after the state character: 1 ppid, 2 pgrp, 3 session, 4 tty_nr, 5 tpgid,
     * 6 flags, 7 minflt, 8 cminflt, 9 majflt, 10 cmajflt, 11 utime, 12 stime, 13 cutime,
     * 14 cstime, 15 priority, 16 nice, 17 num_threads, 18 itrealvalue, 19 starttime,
     * 20 vsize, 21 rss. */
    enum { STAT_FIELDS = 21 };
    long long field[STAT_FIELDS + 1];

    /* rparen[1] is known to be ' ' and rparen[2] to exist; the state byte still
     * needs the space that separates it from the first field. */
    const char *state = rparen + 2;
    if (state + 1 >= end || state[1] != ' ') {
        return -1;
    }
    out->state = *state;
    p = state + 2;

    for (int i = 1; i <= STAT_FIELDS; ++i) {
        while (p < end && *p == ' ') {
            ++p;
        }
        int negative = 0;
        if (p < end && (*p == '-' || *p == '+')) {
            negative = (*p == '-');
            ++p;
        }
        if (p >= end || *p < '0' || *p > '9') {
            return -1;
        }
        long long value = 0;
        while (p < end && *p >= '0' && *p <= '9') {
            if (value < (LLONG_MAX - 9) / 10) {
                value = value * 10 + (*p - '0');
            } else {
                value = LLONG_MAX;
            }
            ++p;
        }
        field[i] = negative ? -value : value;
    }

    if (field[1] < 0) {
        return -1;
    }
    if (field[11] < 0) field[11] = 0;
    if (field[12] < 0) field[12] = 0;
    if (field[19] < 0) field[19] = 0;
    if (field[20] < 0) field[20] = 0;

    out->ppid        = (pid_t)field[1];
    out->utime       = (uint64_t)field[11];
    out->stime       = (uint64_t)field[12];
    out->num_threads = (field[17] > 0) ? (int)field[17] : 1;
    out->starttime   = (uint64_t)field[19];
    out->vsize_bytes = (uint64_t)field[20];
    out->rss_bytes   = (field[21] > 0) ? (uint64_t)field[21] * (uint64_t)page_size : 0;

    memcpy(out->perms, "----------", 11);
    snprintf(out->user, sizeof(out->user), "?");
    format_time_plus(out->utime, out->stime, hz, out->time_plus, sizeof(out->time_plus));
    return 0;
}

int parse_proc_pid_status_uid(const char *status_text, uid_t *uid_out) {
    if (status_text == NULL || uid_out == NULL) {
        return -1;
    }
    const char *p = status_text;
    while (*p != '\0') {
        if (strncmp(p, "Uid:", 4) == 0 && (p[4] == ' ' || p[4] == '\t')) {
            unsigned int u = 0;
            if (sscanf(p + 4, "%u", &u) == 1) {
                *uid_out = (uid_t)u;
                return 0;
            }
        }
        const char *nl = strchr(p, '\n');
        if (nl == NULL) {
            break;
        }
        p = nl + 1;
    }
    return -1;
}

#define UID_CACHE_SIZE 32
typedef struct {
    uid_t uid;
    char  name[32];
    int   valid;
} UidCacheEntry;

static UidCacheEntry g_uid_cache[UID_CACHE_SIZE];

static void resolve_uid_to_user(uid_t uid, char *dst, size_t dst_sz) {
    size_t slot = (size_t)uid % UID_CACHE_SIZE;
    if (g_uid_cache[slot].valid && g_uid_cache[slot].uid == uid) {
        snprintf(dst, dst_sz, "%s", g_uid_cache[slot].name);
        return;
    }

    struct passwd pwd;
    struct passwd *res = NULL;
    char pwbuf[1024];
    char raw_name[32];

    if (getpwuid_r(uid, &pwd, pwbuf, sizeof(pwbuf), &res) == 0 && res != NULL) {
        sanitize_display_str(raw_name, sizeof(raw_name), pwd.pw_name);
    } else {
        snprintf(raw_name, sizeof(raw_name), "%u", (unsigned int)uid);
    }

    g_uid_cache[slot].uid   = uid;
    g_uid_cache[slot].valid = 1;
    snprintf(g_uid_cache[slot].name, sizeof(g_uid_cache[slot].name), "%s", raw_name);
    snprintf(dst, dst_sz, "%s", raw_name);
}

static void apply_ticks_delta(ProcessInfo *c, uint64_t prev_ticks,
                              uint64_t delta_total_cpu, long n_cores) {
    uint64_t cur_ticks = c->utime + c->stime;
    uint64_t d_proc = (cur_ticks >= prev_ticks) ? (cur_ticks - prev_ticks) : 0;

    /* 100% is 1 full core, 200% two etc. */
    c->cpu_pct = ((double)d_proc / (double)delta_total_cpu) * (double)n_cores * 100.0;
}

void procs_compute_cpu_deltas(ProcList *curr, const ProcList *prev,uint64_t delta_total_cpu, long n_cores) {
    if (curr == NULL) {
        return;
    }
    if (n_cores <= 0) {
        n_cores = 1;
    }

    for (size_t i = 0; i < curr->count; ++i) {
        ProcessInfo *c = &curr->items[i];
        c->cpu_pct = 0.0;

        if (prev == NULL || delta_total_cpu == 0) {
            continue;
        }

        for (size_t j = 0; j < prev->count; ++j) {
            const ProcessInfo *p = &prev->items[j];
            if (p->pid == c->pid && p->starttime == c->starttime) {
                apply_ticks_delta(c, p->utime + p->stime, delta_total_cpu, n_cores);
                break;
            }
        }
    }
}

void procticks_capture(ProcTicksList *snap, const ProcList *list) {
    if (snap == NULL || list == NULL) {
        return;
    }
    if (list->count > snap->capacity) {
        size_t cap = snap->capacity > 0 ? snap->capacity : 128;
        while (cap < list->count) {
            cap *= 2;
        }
        ProcTicks *next = realloc(snap->items, cap * sizeof(*next));
        if (next == NULL) {
            /* Drop the history: the next frame shows 0.0% rather than a
             * percentage measured against a sample from two frames ago. */
            snap->count = 0;
            return;
        }
        snap->items = next;
        snap->capacity = cap;
    }
    for (size_t i = 0; i < list->count; ++i) {
        snap->items[i].pid = list->items[i].pid;
        snap->items[i].starttime = list->items[i].starttime;
        snap->items[i].ticks = list->items[i].utime + list->items[i].stime;
    }
    snap->count = list->count;
}

void procticks_free(ProcTicksList *snap) {
    if (snap == NULL) {
        return;
    }
    free(snap->items);
    snap->items = NULL;
    snap->count = 0;
    snap->capacity = 0;
}

void procs_apply_cpu_deltas(ProcList *curr, const ProcTicksList *prev,
                            uint64_t delta_total_cpu) {
    if (curr == NULL) {
        return;
    }
    long n_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (n_cores <= 0) {
        n_cores = 1;
    }

    for (size_t i = 0; i < curr->count; ++i) {
        ProcessInfo *c = &curr->items[i];
        c->cpu_pct = 0.0;

        if (prev == NULL || delta_total_cpu == 0) {
            continue;
        }
        for (size_t j = 0; j < prev->count; ++j) {
            const ProcTicks *p = &prev->items[j];
            if (p->pid == c->pid && p->starttime == c->starttime) {
                apply_ticks_delta(c, p->ticks, delta_total_cpu, n_cores);
                break;
            }
        }
    }
}

static int is_numeric_name(const char *s) {
    if (s == NULL || s[0] == '\0') {
        return 0;
    }
    for (size_t i = 0; s[i] != '\0'; ++i) {
        if (!isdigit((unsigned char)s[i])) {
            return 0;
        }
    }
    return 1;
}

int procs_collect(ProcList *curr, const ProcList *prev,
                  uint64_t delta_total_cpu, ProcSummary *summary_out) {
    if (curr == NULL) {
        return -1;
    }
    proclist_clear(curr);

    if (summary_out != NULL) {
        memset(summary_out, 0, sizeof(*summary_out));
    }

    DIR *dir = opendir("/proc");
    if (dir == NULL) {
        return -1;
    }

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;
    long hz = sysconf(_SC_CLK_TCK);
    if (hz <= 0) hz = 100;
    long n_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (n_cores <= 0) n_cores = 1;

    /* One read of /proc/net/tcp{,6} per pass, then every process compares its
     * socket inodes against the set. The buffer is static: procs_collect owns
     * the only /proc pass in the process and a 64 KB stack frame every second
     * would be wasteful. */
    enum { LISTEN_INODE_CAP = 8192 };
    static uint64_t listen_inodes[LISTEN_INODE_CAP];
    size_t listen_count = procs_collect_listen_inodes(listen_inodes, LISTEN_INODE_CAP);

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (!is_numeric_name(ent->d_name)) {
            continue;
        }

        char path[320];
        char buf[4096];

        /* just skip silently if process exited concurrently */
        snprintf(path, sizeof(path), "/proc/%s/stat", ent->d_name);
        FILE *f = fopen(path, "r");
        if (f == NULL) {
            continue;
        }
        if (fgets(buf, sizeof(buf), f) == NULL) {
            fclose(f);
            continue;
        }
        fclose(f);

        ProcessInfo info;
        if (parse_proc_pid_stat(buf, strlen(buf), &info, page_size, hz) != 0) {
            continue;
        }

        snprintf(path, sizeof(path), "/proc/%s/status", ent->d_name);
        f = fopen(path, "r");
        if (f != NULL) {
            size_t n = fread(buf, 1, sizeof(buf) - 1, f);
            fclose(f);
            buf[n] = '\0';
            if (parse_proc_pid_status_uid(buf, &info.uid) == 0) {
                resolve_uid_to_user(info.uid, info.user, sizeof(info.user));
            }
        }

        snprintf(path, sizeof(path), "/proc/%s/exe", ent->d_name);
        char raw_exe[4096];
        ssize_t len = readlink(path, raw_exe, sizeof(raw_exe) - 1);
        if (len > 0) {
            raw_exe[len] = '\0';
            info.flags = flags_detect_exe(raw_exe);
            sanitize_display_str(info.exe_path, sizeof(info.exe_path), raw_exe);

            struct stat st;
            if (stat(path, &st) == 0) {
                format_mode_rwx(st.st_mode, info.perms);
            } else {
                memcpy(info.perms, "----------", 11);
            }
        } else {
            info.flags = FLAG_NONE;
            info.exe_path[0] = '\0';
            /* Without an exe link there are no exe mode bits to show: kernel
             * threads have no exe at all and another user's process refuses
             * the read. The mode must not be taken from the cmdline fallback
             * below, which is a read-only proc file and never the binary. */
            memcpy(info.perms, "----------", 11);
            /* Non-root minitop cannot read /proc/<pid>/exe of another user, so
             * every root daemon would look like an unknown binary. The first
             * argv entry is world-readable and usually the same path; it is
             * user-controlled, so trust treats it as weaker evidence. */
            snprintf(path, sizeof(path), "/proc/%s/cmdline", ent->d_name);
            FILE *cmd = fopen(path, "r");
            if (cmd != NULL) {
                char cmd0[PATH_MAX];
                size_t got = fread(cmd0, 1, sizeof(cmd0) - 1, cmd);
                fclose(cmd);
                cmd0[got] = '\0';
                if (got > 0 && cmd0[0] == '/') {
                    sanitize_display_str(info.exe_path, sizeof(info.exe_path), cmd0);
                    info.exe_from_argv = 1;
                }
            }
        }

        if (listen_count > 0) {
            info.flags |= procs_has_listen_socket(info.pid, listen_inodes, listen_count);
        }

        snprintf(path, sizeof(path), "/proc/%s/cwd", ent->d_name);
        char raw_cwd[4096];
        len = readlink(path, raw_cwd, sizeof(raw_cwd) - 1);
        if (len > 0) {
            raw_cwd[len] = '\0';
            sanitize_display_str(info.cwd, sizeof(info.cwd), raw_cwd);
        } else {
            info.cwd[0] = '\0';
        }

        if (proclist_push(curr, &info) != 0) {
            closedir(dir);
            return -1;
        }

        if (summary_out != NULL) {
            summary_out->total_procs++;
            summary_out->total_threads += (size_t)info.num_threads;
            if (info.state == 'R') {
                summary_out->running_procs++;
            } else if (info.state == 'S' || info.state == 'D' || info.state == 'I') {
                summary_out->sleeping_procs++;
            }
        }
    }

    closedir(dir);
    procs_compute_cpu_deltas(curr, prev, delta_total_cpu, n_cores);
    return 0;
}

static SortColumn g_sort_col = COL_CPU;
static int g_sort_desc = 1;
/* Modes 2 and 3 show the model's level in the FLAGS cell, so the column has to
 * order by that level instead of by the local rule bits. */
static int g_sort_flags_by_risk;

static int cmp_u64(uint64_t a, uint64_t b) {
    return (a < b) ? -1 : (a > b) ? 1 : 0;
}

static int cmp_double(double a, double b) {
    return (a < b) ? -1 : (a > b) ? 1 : 0;
}

static int process_qsort_cmp(const void *pa, const void *pb) {
    const ProcessInfo *a = (const ProcessInfo *)pa;
    const ProcessInfo *b = (const ProcessInfo *)pb;
    int res = 0;

    switch (g_sort_col) {
        case COL_PID:
            res = (a->pid < b->pid) ? -1 : (a->pid > b->pid) ? 1 : 0;
            break;
        case COL_USER:
            res = strcmp(a->user, b->user);
            break;
        case COL_COMMAND:
            res = strcmp(a->comm, b->comm);
            break;
        case COL_STATE:
            res = (int)(unsigned char)a->state - (int)(unsigned char)b->state;
            break;
        case COL_CPU:
            res = cmp_double(a->cpu_pct, b->cpu_pct);
            break;
        case COL_MEM:
            res = cmp_u64(a->rss_bytes, b->rss_bytes);
            break;
        case COL_TIME:
            res = cmp_u64(a->utime + a->stime, b->utime + b->stime);
            break;
        case COL_FLAGS: {
            if (g_sort_flags_by_risk) {
                /* Trusted rows sort as cleared, unscored rows just below them,
                 * and the level decides the rest: descending puts the most
                 * dangerous process first, which is the question the column
                 * answers in modes 2 and 3. */
                int ra = a->trusted ? -2 : (a->risk > 0 ? a->risk : -1);
                int rb = b->trusted ? -2 : (b->risk > 0 ? b->risk : -1);
                res = ra - rb;
            } else {
                uint8_t mask = FLAG_DEL | FLAG_TMP | FLAG_MEMFD | FLAG_NET;
                uint8_t fa = a->flags & mask;
                uint8_t fb = b->flags & mask;
                res = (int)fa - (int)fb;
            }
            break;
        }
        case COL_PERMS:
            res = strcmp(a->perms, b->perms);
            break;
        default:
            res = 0;
            break;
    }
    if (g_sort_desc) {
        res = -res;
    }
    if (res == 0) {
        res = (a->pid < b->pid) ? -1 : (a->pid > b->pid) ? 1 : 0;
    }

    return res;
}

void proclist_set_flags_sort(int by_risk) {
    g_sort_flags_by_risk = by_risk != 0;
}

void proclist_sort(ProcList *list, SortColumn col, int descending) {
    if (list == NULL || list->count <= 1) {
        return;
    }

    g_sort_col  = col;
    g_sort_desc = descending ? 1 : 0;
    qsort(list->items, list->count, sizeof(ProcessInfo), process_qsort_cmp);
}

ssize_t proclist_find_followed(const ProcList *list, pid_t pid, uint64_t starttime) {
    if (list == NULL || pid <= 0) {
        return -1;
    }

    for (size_t i = 0; i < list->count; ++i) {
        if (list->items[i].pid == pid && list->items[i].starttime == starttime) {
            return (ssize_t)i;
        }
    }

    return -1;
}

int proc_kill(pid_t pid, int force_sigkill) {
    if (pid <= 1) {
        errno = EINVAL;
        return -1;
    }

    int sig = force_sigkill ? SIGKILL : SIGTERM;

    return kill(pid, sig);
}

static int cmp_inode_asc(const void *pa, const void *pb) {
    uint64_t a = *(const uint64_t *)pa;
    uint64_t b = *(const uint64_t *)pb;
    return (a < b) ? -1 : (a > b) ? 1 : 0;
}

static int inode_in_set(uint64_t inode, const uint64_t *inodes, size_t count) {
    size_t lo = 0;
    size_t hi = count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (inodes[mid] == inode) {
            return 1;
        }
        if (inodes[mid] < inode) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return 0;
}

size_t procs_collect_listen_inodes(uint64_t *out, size_t cap) {
    if (out == NULL || cap == 0) {
        return 0;
    }

    static const char *sources[] = {"/proc/net/tcp", "/proc/net/tcp6"};
    size_t count = 0;

    for (size_t s = 0; s < sizeof(sources) / sizeof(sources[0]) && count < cap; ++s) {
        FILE *f = fopen(sources[s], "r");
        if (f == NULL) {
            continue;
        }
        char line[512];
        while (count < cap && fgets(line, sizeof(line), f) != NULL) {
            count += net_listen_inodes(line, out + count, cap - count);
        }
        fclose(f);
    }

    /* Sorted once per pass, so a process with many descriptors does not walk
     * the whole set for each socket it owns. */
    if (count > 1) {
        qsort(out, count, sizeof(uint64_t), cmp_inode_asc);
    }
    return count;
}

uint8_t procs_has_listen_socket(pid_t pid, const uint64_t *inodes, size_t count) {
    if (pid <= 0 || inodes == NULL || count == 0) {
        return FLAG_NONE;
    }

    char dir_path[64];
    snprintf(dir_path, sizeof(dir_path), "/proc/%d/fd", (int)pid);

    DIR *dir = opendir(dir_path);
    if (dir == NULL) {
        return FLAG_NONE;
    }

    uint8_t flags = FLAG_NONE;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') {
            continue;
        }
        char link_path[320];
        snprintf(link_path, sizeof(link_path), "%s/%.200s", dir_path, ent->d_name);

        char target[64];
        ssize_t len = readlink(link_path, target, sizeof(target) - 1);
        if (len <= 0) {
            continue;
        }
        target[len] = '\0';

        uint64_t inode = 0;
        if (net_socket_inode(target, &inode) != 0) {
            continue;
        }
        if (inode_in_set(inode, inodes, count)) {
            flags = FLAG_NET;
            break;
        }
    }

    closedir(dir);
    return flags;
}
