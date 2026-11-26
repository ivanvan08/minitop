#include "model.h"

#include <curl/curl.h>

#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "curlshim.h"
#include "flags.h"

#define MODEL_PENDING_MAX 512
#define MODEL_RESULT_MAX  64
#define MODEL_PORT_TABLE  128
#define MODEL_REPORT_MAX  1024

static char g_model_name[64] = "baseten/bison-1";

static const char *const RISK_INSTRUCTIONS =
    "Score this Linux process as a possible compromise of the host it runs on. "
    "Judge the evidence, never the name: `comm` is chosen by the process and "
    "can be spoofed. `exe_path` is the kernel's executable link; a trailing "
    "\" (deleted)\" means the file was unlinked, and an empty value usually "
    "means the monitor could not read the link, not that no file exists. `cwd` "
    "is the working directory. `user` is the owner. `cpu_pct_irix` is CPU use "
    "where 100 means one core fully busy, so 400 means four cores. "
    "`local_flags` marks DEL (executable deleted), TMP (executable under /tmp, "
    "/var/tmp or /dev/shm) and MEMFD (executed from an anonymous memory file). "
    "`listening_ports` lists TCP ports in LISTEN state only; a process that "
    "only connects out has an empty list, so an empty list is not evidence of "
    "innocence. DEL and a \"(deleted)\" path are the same fact, MEMFD and a "
    "/memfd: path are the same fact, and TMP is implied by such a path; never "
    "count two spellings of one fact as two classes. "
    "Treat these as independent evidence classes. (1) Provenance: the "
    "executable lives outside the distribution-managed directories (/usr, "
    "/bin, /sbin, /lib, /lib64) and the vendor directories (/opt): in a home "
    "directory, a build tree, /tmp, /var/tmp, /dev/shm, /run, or a dot "
    "directory. (2) Volatility: a deleted or anonymous executable, a hidden "
    "dot-named executable, or an executable in tmpfs. (3) Privilege: user root "
    "together with an executable or cwd in a user-writable or temporary "
    "location; root alone is normal for system services. (4) Sustained CPU: "
    "cpu_pct_irix at or near 100 for a non-packaged executable that is not a "
    "compiler or build tool; one saturated core with no visible workload is "
    "the mining and brute-force shape. (5) Network: a listening port the "
    "service does not justify, especially a high or loopback-only port, and "
    "stronger when the executable is volatile or privileged. (6) Interpreter: "
    "a shell or scripting interpreter (sh, bash, dash, zsh, python, perl, "
    "ruby, node, php, lua, busybox) running a script from a user or temporary "
    "directory, especially as root. (7) Masquerade: comm resembles a kernel "
    "thread or a common daemon but exe_path does not match it, or comm and the "
    "executable basename disagree. (8) Working directory: a long-running "
    "process whose cwd is a temporary directory or a deleted directory. "
    "A kernel thread has an empty exe_path and a kernel-thread comm (kworker*, "
    "ksoftirqd*, rcu*, kthreadd, jbd2/*, migration/*, kswapd*, kcompactd*, "
    "kdevtmpfs, kauditd); that is not volatility. A single benign explanation "
    "must cover every signal of a class for the score to stay low. If two or "
    "more independent classes apply and no single benign explanation covers "
    "all of them, the score must be at least 5. If one strong class applies "
    "(deleted or memory-only executable; root running from a user-writable "
    "path; a non-packaged binary saturating a core; a privileged interpreter "
    "working in a user directory), the score must be at least 5 as well. A "
    "non-root application with a home-directory path, a home cwd and a "
    "listening port is an ordinary development server and stays at level 4 at "
    "most unless the executable is volatile or hidden. Likewise a non-root "
    "executable in a temporary directory with no deletion, no listener and no "
    "CPU load has only the TMP signal and stays at level 4. An executable path "
    "and a cwd under the same temporary area are one temporary-location "
    "signal, not two independent classes. Packaged paths are "
    "not proof of innocence, and a familiar name must not lower the score. "
    "Below 5 name the single benign fact that explains the strongest signal; "
    "at 5 and above name the classes that decide it.";

static const char *const RISK_CRITERIA[10] = {
    "level 1: packaged system service or kernel thread, path matches, nothing anomalous",
    "level 2: ordinary packaged or vendor application with no anomaly",
    "level 3: one weak anomaly with a plausible benign explanation, such as a "
    "vendor or home path without privilege or network, a compiler at full CPU, "
    "or an unprivileged interpreter running a user script",
    "level 4: one moderate anomaly, or two weak signals from the same class "
    "with a common benign explanation; manual inspection is warranted but "
    "nothing is clearly hostile",
    "level 5: one strong class (deleted or memory-only executable, root running "
    "from a user-writable path, a non-packaged binary saturating a core, a "
    "privileged interpreter in a user directory), or two independent classes "
    "with no common benign explanation",
    "level 6: a strong class plus one more independent class, for example an "
    "untrusted path with a non-standard listening port, or a masquerade with "
    "volatility",
    "level 7: active threat pattern: a hidden or anonymous executable plus a "
    "network channel, or a masquerading process with an untrusted path and "
    "network activity",
    "level 8: deleted or memory-only executable that also listens or persists",
    "level 9: active compromise with persistence, respawn or a command channel",
    "level 10: certain malice: fileless execution with command-and-control or "
    "persistence",
};

static const char *const PKG_UPGRADE_INSTRUCTIONS =
    "Is the DEL flag most likely caused by a normal package manager upgrade "
    "rather than self-deleting malware? Answer yes only when the executable "
    "path is distribution-managed; a deleted executable from a home or "
    "temporary path is not a package upgrade.";

/* ------------------------------------------------------------------ JSON -- */

typedef struct JsonBuf {
    char  *buf;
    size_t sz;
    size_t len;
    int    failed;
} JsonBuf;

static void jb_append(JsonBuf *b, const char *s, size_t n) {
    if (b->failed) {
        return;
    }
    if (b->len + n + 1 > b->sz) {
        b->failed = 1;
        if (b->sz > 0) {
            b->buf[b->sz - 1] = '\0';
        }
        return;
    }
    memcpy(b->buf + b->len, s, n);
    b->len += n;
    b->buf[b->len] = '\0';
}

static void jb_puts(JsonBuf *b, const char *s) {
    jb_append(b, s, strlen(s));
}

static void jb_printf(JsonBuf *b, const char *fmt, ...) {
    if (b->failed) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(b->buf + b->len, b->sz - b->len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= b->sz - b->len) {
        b->failed = 1;
        if (b->sz > 0) {
            b->buf[b->sz - 1] = '\0';
        }
        return;
    }
    b->len += (size_t)n;
}

static void jb_string(JsonBuf *b, const char *s) {
    static const char hex[] = "0123456789abcdef";

    jb_append(b, "\"", 1);
    if (s != NULL) {
        for (const unsigned char *p = (const unsigned char *)s; *p != '\0'; p++) {
            unsigned char c = *p;
            switch (c) {
            case '"':  jb_append(b, "\\\"", 2); break;
            case '\\': jb_append(b, "\\\\", 2); break;
            case '\b': jb_append(b, "\\b", 2); break;
            case '\f': jb_append(b, "\\f", 2); break;
            case '\n': jb_append(b, "\\n", 2); break;
            case '\r': jb_append(b, "\\r", 2); break;
            case '\t': jb_append(b, "\\t", 2); break;
            default:
                if (c < 0x20 || c == 0x7f) {
                    char esc[6] = { '\\', 'u', '0', '0', hex[c >> 4], hex[c & 0x0f] };
                    jb_append(b, esc, sizeof(esc));
                } else {
                    jb_append(b, (const char *)&c, 1);
                }
                break;
            }
        }
    }
    jb_append(b, "\"", 1);
}

void model_set_name(const char *name) {
    if (name == NULL || name[0] == '\0') {
        return;
    }
    snprintf(g_model_name, sizeof(g_model_name), "%s", name);
}

static void append_local_flags(JsonBuf *b, uint8_t flags) {
    int first = 1;
    jb_append(b, "[", 1);
    if (flags & FLAG_DEL) {
        jb_append(b, "\"DEL\"", 5);
        first = 0;
    }
    if (flags & FLAG_TMP) {
        if (!first) {
            jb_append(b, ",", 1);
        }
        jb_append(b, "\"TMP\"", 5);
        first = 0;
    }
    if (flags & FLAG_MEMFD) {
        if (!first) {
            jb_append(b, ",", 1);
        }
        jb_append(b, "\"MEMFD\"", 7);
    }
    jb_append(b, "]", 1);
}

int model_build_request(const ProcessInfo *p, const TrustInfo *t, char *buf, size_t sz) {
    if (buf == NULL || sz == 0) {
        return -1;
    }
    buf[0] = '\0';
    if (p == NULL) {
        return -1;
    }

    JsonBuf b = { .buf = buf, .sz = sz, .len = 0, .failed = 0 };

    jb_puts(&b, "{\"model\":");
    jb_string(&b, g_model_name);
    jb_puts(&b, ",\"state\":{\"comm\":");
    jb_string(&b, p->comm);
    jb_puts(&b, ",\"exe_path\":");
    jb_string(&b, p->exe_path);
    jb_puts(&b, ",\"cwd\":");
    jb_string(&b, p->cwd);
    jb_puts(&b, ",\"user\":");
    jb_string(&b, p->user);

    double cpu = p->cpu_pct > 0.0 ? p->cpu_pct : 0.0;
    double rss_mib = (double)p->rss_bytes / (1024.0 * 1024.0);
    jb_printf(&b, ",\"cpu_pct_irix\":%.1f,\"rss_mib\":%.1f,\"local_flags\":",
              cpu, rss_mib);
    append_local_flags(&b, p->flags);
    jb_puts(&b, ",\"listening_ports\":[");

    int ports = (t != NULL) ? t->listening_count : 0;
    if (ports > TRUST_MAX_PORTS) {
        ports = TRUST_MAX_PORTS;
    }
    for (int i = 0; i < ports; i++) {
        if (i > 0) {
            jb_append(&b, ",", 1);
        }
        jb_printf(&b, "%u", (unsigned)t->listening_ports[i]);
    }
    jb_puts(&b, "]");

    /* Omitted entirely when the executable is unowned or its desc file could
     * not be read, so the request stays byte-identical for unknown packages. */
    if (t != NULL && t->package_meta && t->package[0] != '\0') {
        jb_puts(&b, ",\"package\":{\"name\":");
        jb_string(&b, t->package);
        jb_puts(&b, ",\"version\":");
        jb_string(&b, t->package_version);
        jb_puts(&b, ",\"desc\":");
        jb_string(&b, t->package_desc);
        jb_puts(&b, ",\"repo\":");
        jb_string(&b, t->repo);
        jb_puts(&b, "}");
    }

    jb_puts(&b, "},\"questions\":{\"risk\":{\"type\":\"score\",\"instructions\":");
    jb_string(&b, RISK_INSTRUCTIONS);
    jb_puts(&b, ",\"criteria\":[");
    for (size_t i = 0; i < sizeof(RISK_CRITERIA) / sizeof(RISK_CRITERIA[0]); i++) {
        if (i > 0) {
            jb_append(&b, ",", 1);
        }
        jb_string(&b, RISK_CRITERIA[i]);
    }
    jb_puts(&b, "]},\"likely_pkg_upgrade\":{\"type\":\"noul\",\"instructions\":");
    jb_string(&b, PKG_UPGRADE_INSTRUCTIONS);
    jb_puts(&b, "}}}");

    if (b.failed) {
        return -1;
    }
    return (int)b.len;
}

/* --------------------------------------------------------------- parsing -- */

static const char *find_json_key(const char *start, const char *end, const char *key) {
    size_t klen = strlen(key);
    if (start == NULL || end == NULL || end < start) {
        return NULL;
    }
    for (const char *p = start; p + klen + 2 <= end; p++) {
        if (p[0] != '"' || memcmp(p + 1, key, klen) != 0 || p[1 + klen] != '"') {
            continue;
        }
        const char *q = p + klen + 2;
        while (q < end && (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n')) {
            q++;
        }
        if (q < end && *q == ':') {
            return q + 1;
        }
    }
    return NULL;
}

int model_parse_level(const char *response, size_t len) {
    if (response == NULL || len == 0) {
        return -1;
    }
    const char *end = response + len;

    const char *scope = response;
    const char *answers = find_json_key(response, end, "answers");
    if (answers != NULL) {
        scope = answers;
    }

    const char *risk = find_json_key(scope, end, "risk");
    if (risk == NULL) {
        return -1;
    }
    while (risk < end && (*risk == ' ' || *risk == '\t' || *risk == '\r' || *risk == '\n')) {
        risk++;
    }
    if (risk >= end || *risk != '{') {
        return -1;
    }
    risk++;
    const char *risk_end = risk + 2048 < end ? risk + 2048 : end;

    const char *score = find_json_key(risk, risk_end, "score");
    if (score != NULL) {
        const char *p = score;
        while (p < risk_end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) {
            p++;
        }
        char *num_end = NULL;
        double value = strtod(p, &num_end);
        if (num_end == p || !(value >= -0.01 && value <= 9.01)) {
            return -1;
        }
        int level = (int)(value + 0.5) + 1;
        if (level < 1) {
            level = 1;
        }
        if (level > 10) {
            level = 10;
        }
        return level;
    }

    const char *level_key = find_json_key(risk, risk_end, "level");
    if (level_key != NULL) {
        const char *p = level_key;
        while (p < risk_end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) {
            p++;
        }
        char *num_end = NULL;
        long value = strtol(p, &num_end, 10);
        if (num_end != p && value >= 1 && value <= 10) {
            return (int)value;
        }
    }
    return -1;
}

int model_format_report(const char *model, const char *time_iso, pid_t pid,
                        const char *comm, int level, char *buf, size_t sz) {
    if (buf == NULL || sz == 0) {
        return -1;
    }
    buf[0] = '\0';
    JsonBuf b = { .buf = buf, .sz = sz, .len = 0, .failed = 0 };

    jb_puts(&b, "{\"time\":");
    jb_string(&b, time_iso);
    jb_printf(&b, ",\"pid\":%d,\"comm\":", (int)pid);
    jb_string(&b, comm);
    jb_printf(&b, ",\"level\":%d,\"model\":", level);
    jb_string(&b, model);
    jb_puts(&b, "}");

    if (b.failed) {
        return -1;
    }
    return (int)b.len;
}

static char *next_token(char **cursor) {
    char *p = *cursor;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
        p++;
    }
    if (*p == '\0') {
        *cursor = p;
        return NULL;
    }
    char *start = p;
    while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') {
        p++;
    }
    if (*p != '\0') {
        *p = '\0';
        p++;
    }
    *cursor = p;
    return start;
}

size_t model_parse_listen_ports(const char *text, uint64_t *inodes,
                                uint16_t *ports, size_t cap) {
    if (text == NULL || inodes == NULL || ports == NULL || cap == 0) {
        return 0;
    }

    size_t count = 0;
    const char *line = text;
    while (*line != '\0' && count < cap) {
        const char *nl = strchr(line, '\n');
        size_t line_len = nl ? (size_t)(nl - line) : strlen(line);
        if (line_len >= 512) {
            line_len = 511;
        }

        char copy[512];
        memcpy(copy, line, line_len);
        copy[line_len] = '\0';

        char *cursor = copy;
        char *tokens[10];
        size_t ntokens = 0;
        while (ntokens < 10) {
            char *tok = next_token(&cursor);
            if (tok == NULL) {
                break;
            }
            tokens[ntokens++] = tok;
        }

        if (ntokens >= 10 && strcmp(tokens[3], "0A") == 0) {
            char *colon = strrchr(tokens[1], ':');
            if (colon != NULL) {
                char *end = NULL;
                unsigned long port = strtoul(colon + 1, &end, 16);
                end = NULL;
                unsigned long long inode = strtoull(tokens[9], &end, 10);
                if (colon[1] != '\0' && port <= 0xffffu &&
                    tokens[9][0] != '\0' && inode != 0) {
                    inodes[count] = (uint64_t)inode;
                    ports[count] = (uint16_t)port;
                    count++;
                }
            }
        }

        if (nl == NULL) {
            break;
        }
        line = nl + 1;
    }
    return count;
}

size_t model_collect_listening_ports(pid_t pid, uint16_t *ports, size_t cap) {
    if (pid <= 0 || ports == NULL || cap == 0) {
        return 0;
    }

    uint64_t inodes[MODEL_PORT_TABLE];
    uint16_t table_ports[MODEL_PORT_TABLE];
    size_t entries = 0;

    static const char *const sources[] = { "/proc/net/tcp", "/proc/net/tcp6" };
    for (size_t s = 0; s < sizeof(sources) / sizeof(sources[0]) && entries < MODEL_PORT_TABLE; s++) {
        FILE *f = fopen(sources[s], "r");
        if (f == NULL) {
            continue;
        }
        char line[512];
        while (entries < MODEL_PORT_TABLE && fgets(line, sizeof(line), f) != NULL) {
            entries += model_parse_listen_ports(line, inodes + entries,
                                                table_ports + entries,
                                                MODEL_PORT_TABLE - entries);
        }
        fclose(f);
    }

    if (entries == 0) {
        return 0;
    }

    char dir_path[64];
    snprintf(dir_path, sizeof(dir_path), "/proc/%d/fd", (int)pid);
    DIR *dir = opendir(dir_path);
    if (dir == NULL) {
        return 0;
    }

    size_t found = 0;
    struct dirent *ent;
    while (found < cap && (ent = readdir(dir)) != NULL) {
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
        for (size_t i = 0; i < entries; i++) {
            if (inodes[i] != inode) {
                continue;
            }
            int duplicate = 0;
            for (size_t k = 0; k < found; k++) {
                if (ports[k] == table_ports[i]) {
                    duplicate = 1;
                    break;
                }
            }
            if (!duplicate) {
                ports[found++] = table_ports[i];
            }
            break;
        }
    }
    closedir(dir);
    return found;
}

/* --------------------------------------------------------------- engine -- */

typedef struct ModelPending {
    pid_t    pid;
    uint64_t starttime;
    char     comm[16];
    char    *request;
} ModelPending;

typedef struct ModelResponse {
    char  *data;
    size_t len;
    size_t cap;
} ModelResponse;

typedef struct ModelActive {
    CURL              *easy;
    struct curl_slist *headers;
    char              *auth;
    char              *request;
    ModelResponse     *response;
    pid_t              pid;
    uint64_t           starttime;
    char               comm[16];
} ModelActive;

typedef struct ModelResult {
    pid_t    pid;
    uint64_t starttime;
    int      level;
    long     status;
    char     comm[16];
} ModelResult;

typedef struct ModelSchedule {
    pid_t    pid;
    uint64_t starttime;
    double   next_allowed;
    int      in_flight;
    int      level; /* last verdict, re-applied to every fresh /proc snapshot */
} ModelSchedule;

struct ModelEngine {
    ModelConfig    cfg;
    char           key[512];
    CURLM         *multi;
    ModelActive    active[MODEL_MAX_ACTIVE];
    int            nactive;
    ModelPending  *pending;
    size_t         pending_count;
    size_t         pending_cap;
    ModelSchedule *sched;
    size_t         sched_count;
    size_t         sched_cap;
    ModelResult    results[MODEL_RESULT_MAX];
    int            res_head;
    int            res_count;
    int            report_failed;
};

static void secure_clear(void *p, size_t n) {
    volatile unsigned char *v = p;
    while (n-- > 0) {
        *v++ = 0;
    }
}

static void set_err(char *err, size_t err_sz, const char *fmt, ...) {
    if (err == NULL || err_sz == 0) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, err_sz, fmt, ap);
    va_end(ap);
}

static int expand_home(const char *path, char *out, size_t sz) {
    if (path == NULL || out == NULL || sz == 0) {
        return -1;
    }
    if (strncmp(path, "~/", 2) != 0) {
        size_t n = strlen(path);
        if (n >= sz) {
            return -1;
        }
        memcpy(out, path, n + 1);
        return 0;
    }
    const char *home = getenv("HOME");
    if (home == NULL || home[0] == '\0') {
        return -1;
    }
    int n = snprintf(out, sz, "%s/%s", home, path + 2);
    return (n >= 0 && (size_t)n < sz) ? 0 : -1;
}

static int read_key(const char *path, char *out, size_t sz, char *err, size_t err_sz) {
    char full[512];
    if (expand_home(path, full, sizeof(full)) != 0) {
        set_err(err, err_sz, "cannot resolve key file \"%s\"", path);
        return -1;
    }

    FILE *f = fopen(full, "r");
    if (f == NULL) {
        if (errno == ENOENT) {
            set_err(err, err_sz, "key file \"%s\" not found", path);
        } else {
            set_err(err, err_sz, "cannot read key file \"%s\": %s", path, strerror(errno));
        }
        return -1;
    }

    size_t n = fread(out, 1, sz - 1, f);
    int extra = (n == sz - 1) ? fgetc(f) : EOF;
    int failed = ferror(f);
    fclose(f);

    if (failed) {
        set_err(err, err_sz, "cannot read key file \"%s\"", path);
        secure_clear(out, sz);
        return -1;
    }
    if (extra != EOF) {
        set_err(err, err_sz, "key file \"%s\" is too long", path);
        secure_clear(out, sz);
        return -1;
    }
    out[n] = '\0';

    char *start = out;
    while (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n') {
        start++;
    }
    size_t len = strlen(start);
    while (len > 0 && (start[len - 1] == ' ' || start[len - 1] == '\t' ||
                       start[len - 1] == '\r' || start[len - 1] == '\n')) {
        start[--len] = '\0';
    }
    if (len == 0) {
        set_err(err, err_sz, "key file \"%s\" is empty", path);
        secure_clear(out, sz);
        return -1;
    }
    if (start != out) {
        memmove(out, start, len + 1);
    }
    return 0;
}

static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static double resample_interval(const ModelEngine *e) {
    double r = (double)rand() / (double)RAND_MAX; /* 0..1 */
    if (r < 0.0) {
        r = 0.0;
    }
    if (r > 1.0) {
        r = 1.0;
    }
    return (double)e->cfg.resample_sec * (0.8 + 0.4 * r);
}

static ModelSchedule *sched_find(ModelEngine *e, pid_t pid, uint64_t starttime, int create) {
    for (size_t i = 0; i < e->sched_count; i++) {
        if (e->sched[i].pid == pid && e->sched[i].starttime == starttime) {
            return &e->sched[i];
        }
    }
    if (!create) {
        return NULL;
    }
    if (e->sched_count == e->sched_cap) {
        size_t cap = e->sched_cap ? e->sched_cap * 2 : 128;
        ModelSchedule *next = realloc(e->sched, cap * sizeof(*next));
        if (next == NULL) {
            return NULL;
        }
        e->sched = next;
        e->sched_cap = cap;
    }
    ModelSchedule *s = &e->sched[e->sched_count++];
    s->pid = pid;
    s->starttime = starttime;
    s->next_allowed = 0.0;
    s->in_flight = 0;
    s->level = -1;
    return s;
}

static int sched_is_live(const ModelSchedule *s, const ProcList *procs) {
    for (size_t i = 0; i < procs->count; i++) {
        if (procs->items[i].pid == s->pid && procs->items[i].starttime == s->starttime) {
            return 1;
        }
    }
    return 0;
}

/* Bounded memory: once the table is large, drop entries whose process is
 * gone. A live process keeps its verdict and its resample deadline. */
static void sched_prune(ModelEngine *e, const ProcList *procs) {
    if (e->sched_count < 2048) {
        return;
    }
    size_t w = 0;
    for (size_t i = 0; i < e->sched_count; i++) {
        if (e->sched[i].in_flight || sched_is_live(&e->sched[i], procs)) {
            e->sched[w++] = e->sched[i];
        }
    }
    e->sched_count = w;
}

static void push_result(ModelEngine *e, const ModelActive *a, int level, long status) {
    if (e->res_count == MODEL_RESULT_MAX) {
        e->res_head = (e->res_head + 1) % MODEL_RESULT_MAX;
        e->res_count--;
    }
    int idx = (e->res_head + e->res_count) % MODEL_RESULT_MAX;
    ModelResult *r = &e->results[idx];
    r->pid = a->pid;
    r->starttime = a->starttime;
    r->level = level;
    r->status = status;
    memcpy(r->comm, a->comm, sizeof(r->comm));
    r->comm[sizeof(r->comm) - 1] = '\0';
    e->res_count++;
}

static int pop_result(ModelEngine *e, ModelResult *out) {
    if (e->res_count == 0) {
        return 0;
    }
    *out = e->results[e->res_head];
    e->res_head = (e->res_head + 1) % MODEL_RESULT_MAX;
    e->res_count--;
    return 1;
}

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
    ModelResponse *r = userdata;
    size_t n = size * nmemb;
    if (n == 0) {
        return 0;
    }
    if (r->len + n + 1 > MODEL_RESPONSE_MAX) {
        return 0;
    }
    if (r->len + n + 1 > r->cap) {
        size_t cap = r->cap ? r->cap : 4096;
        while (cap < r->len + n + 1) {
            cap *= 2;
        }
        if (cap > MODEL_RESPONSE_MAX) {
            cap = MODEL_RESPONSE_MAX;
        }
        char *next = realloc(r->data, cap);
        if (next == NULL) {
            return 0;
        }
        r->data = next;
        r->cap = cap;
    }
    memcpy(r->data + r->len, ptr, n);
    r->len += n;
    r->data[r->len] = '\0';
    return n;
}

static void free_active(ModelActive *a) {
    if (a->easy != NULL) {
        curl_easy_cleanup(a->easy);
    }
    if (a->headers != NULL) {
        curl_slist_free_all(a->headers);
    }
    free(a->auth);
    free(a->request);
    if (a->response != NULL) {
        free(a->response->data);
        free(a->response);
    }
    memset(a, 0, sizeof(*a));
}

static void remove_active(ModelEngine *e, int idx) {
    if (e->multi != NULL && e->active[idx].easy != NULL) {
        curl_multi_remove_handle(e->multi, e->active[idx].easy);
    }
    free_active(&e->active[idx]);
    for (int i = idx + 1; i < e->nactive; i++) {
        e->active[i - 1] = e->active[i];
    }
    e->nactive--;
    memset(&e->active[e->nactive], 0, sizeof(e->active[e->nactive]));
}

static void queue_failure(ModelEngine *e, const ModelPending *p) {
    ModelActive fake;
    memset(&fake, 0, sizeof(fake));
    fake.pid = p->pid;
    fake.starttime = p->starttime;
    memcpy(fake.comm, p->comm, sizeof(fake.comm));
    push_result(e, &fake, -1, 0);
}

static void start_pending(ModelEngine *e) {
    while (e->pending_count > 0 && e->nactive < MODEL_MAX_ACTIVE) {
        ModelPending job = e->pending[0];
        memmove(e->pending, e->pending + 1,
                (e->pending_count - 1) * sizeof(e->pending[0]));
        e->pending_count--;

        CURL *easy = curl_easy_init();
        if (easy == NULL) {
            free(job.request);
            queue_failure(e, &job);
            continue;
        }

        ModelActive *a = &e->active[e->nactive];
        memset(a, 0, sizeof(*a));
        a->easy = easy;
        a->pid = job.pid;
        a->starttime = job.starttime;
        memcpy(a->comm, job.comm, sizeof(a->comm));
        a->request = job.request;

        a->response = calloc(1, sizeof(*a->response));
        size_t auth_sz = strlen(e->key) + 32;
        a->auth = malloc(auth_sz);
        if (a->response == NULL || a->auth == NULL) {
            free_active(a); /* also frees a->request, which is job.request */
            queue_failure(e, &job);
            continue;
        }
        snprintf(a->auth, auth_sz, "Authorization: Bearer %s", e->key);

        a->headers = curl_slist_append(a->headers, "Content-Type: application/json");
        a->headers = curl_slist_append(a->headers, a->auth);

        curl_easy_setopt(easy, CURLOPT_URL, e->cfg.endpoint);
        curl_easy_setopt(easy, CURLOPT_POST, 1L);
        curl_easy_setopt(easy, CURLOPT_POSTFIELDS, a->request);
        curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE, (long)strlen(a->request));
        curl_easy_setopt(easy, CURLOPT_HTTPHEADER, a->headers);
        curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, (long)MODEL_TIMEOUT_MS);
        curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, 4000L);
        curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(easy, CURLOPT_USERAGENT, "minitop/0.4");
        curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 0L);
        curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, write_cb);
        curl_easy_setopt(easy, CURLOPT_WRITEDATA, a->response);

        CURLMcode mc = curl_multi_add_handle(e->multi, easy);
        if (mc != CURLM_OK) {
            free_active(a);
            queue_failure(e, &job);
            continue;
        }
        e->nactive++;
    }
}

static void pump_engine(ModelEngine *e) {
    if (e == NULL || e->multi == NULL || e->nactive == 0) {
        return;
    }

    int numfds = 0;
    curl_multi_poll(e->multi, NULL, 0, 0, &numfds);
    int still = 0;
    CURLMcode mc;
    do {
        mc = curl_multi_perform(e->multi, &still);
    } while (mc == CURLM_CALL_MULTI_PERFORM);

    CURLMsg *msg;
    int left = 0;
    while ((msg = curl_multi_info_read(e->multi, &left)) != NULL) {
        if (msg->msg != CURLMSG_DONE) {
            continue;
        }
        CURL *easy = msg->easy_handle;
        int idx = -1;
        for (int i = 0; i < e->nactive; i++) {
            if (e->active[i].easy == easy) {
                idx = i;
                break;
            }
        }
        if (idx < 0) {
            continue;
        }

        ModelActive *a = &e->active[idx];
        long status = 0;
        curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &status);
        int level = -1;
        if (msg->data.result == CURLE_OK && status >= 200 && status < 300 &&
            a->response != NULL && a->response->data != NULL) {
            level = model_parse_level(a->response->data, a->response->len);
        }
        push_result(e, a, level, status);
        remove_active(e, idx);
    }
}

static void report_verdict(ModelEngine *e, const ModelResult *r) {
    if (e->cfg.report_path[0] == '\0' || strcmp(e->cfg.report_path, "none") == 0) {
        return;
    }

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tmv;
    localtime_r(&ts.tv_sec, &tmv);
    char stamp[48];
    if (strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%S%z", &tmv) == 0) {
        snprintf(stamp, sizeof(stamp), "%lld", (long long)ts.tv_sec);
    }

    char line[MODEL_REPORT_MAX];
    if (model_format_report(e->cfg.name, stamp, r->pid, r->comm, r->level,
                            line, sizeof(line)) < 0) {
        return;
    }

    FILE *f = fopen(e->cfg.report_path, "a");
    if (f == NULL) {
        if (!e->report_failed) {
            fprintf(stderr, "minitop: cannot append model report \"%s\": %s\n",
                    e->cfg.report_path, strerror(errno));
            e->report_failed = 1;
        }
        return;
    }
    fprintf(f, "%s\n", line);
    fclose(f);
}

static void apply_results(ModelEngine *e, ProcList *procs) {
    ModelResult r;
    while (pop_result(e, &r)) {
        for (size_t i = 0; i < procs->count; i++) {
            if (procs->items[i].pid == r.pid &&
                procs->items[i].starttime == r.starttime) {
                procs->items[i].risk = r.level;
                break;
            }
        }
        ModelSchedule *s = sched_find(e, r.pid, r.starttime, 1);
        if (s != NULL) {
            s->in_flight = 0;
            s->level = r.level;
            s->next_allowed = now_seconds() + resample_interval(e);
        }
        /* A transport or HTTP failure is not a verdict: it leaves risk at -1
         * and is not reported. A 2xx answer that cannot be parsed is reported
         * as -1. */
        if (r.status >= 200 && r.status < 300) {
            report_verdict(e, &r);
        }
    }
}

ModelEngine *model_engine_create(const ModelConfig *cfg, char *err, size_t err_sz) {
    if (cfg == NULL) {
        set_err(err, err_sz, "no model configuration");
        return NULL;
    }
    if (!cfg->enabled) {
        set_err(err, err_sz, "model is disabled in the config");
        return NULL;
    }
    if (cfg->endpoint[0] == '\0') {
        set_err(err, err_sz, "model.endpoint is empty");
        return NULL;
    }
    if (cfg->name[0] == '\0') {
        set_err(err, err_sz, "model.name is empty");
        return NULL;
    }

    ModelEngine *e = calloc(1, sizeof(*e));
    if (e == NULL) {
        set_err(err, err_sz, "out of memory");
        return NULL;
    }
    e->cfg = *cfg;
    if (e->cfg.threshold < 1 || e->cfg.threshold > 10) {
        e->cfg.threshold = 5;
    }
    if (e->cfg.resample_sec < 60) {
        e->cfg.resample_sec = 1500;
    }
    if (e->cfg.max_per_pass < 1) {
        e->cfg.max_per_pass = 300;
    }

    if (read_key(e->cfg.key_file, e->key, sizeof(e->key), err, err_sz) != 0) {
        secure_clear(e->key, sizeof(e->key));
        free(e);
        return NULL;
    }

    if (curlshim_acquire(err, err_sz) != 0) {
        secure_clear(e->key, sizeof(e->key));
        free(e);
        return NULL;
    }
    e->multi = curl_multi_init();
    if (e->multi == NULL) {
        set_err(err, err_sz, "libcurl multi handle initialisation failed");
        curlshim_release();
        secure_clear(e->key, sizeof(e->key));
        free(e);
        return NULL;
    }

    model_set_name(e->cfg.name);
    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    return e;
}

void model_engine_destroy(ModelEngine *e) {
    if (e == NULL) {
        return;
    }
    for (int i = 0; i < e->nactive; i++) {
        if (e->multi != NULL && e->active[i].easy != NULL) {
            curl_multi_remove_handle(e->multi, e->active[i].easy);
        }
        free_active(&e->active[i]);
    }
    e->nactive = 0;

    for (size_t i = 0; i < e->pending_count; i++) {
        free(e->pending[i].request);
    }
    free(e->pending);
    free(e->sched);

    if (e->multi != NULL) {
        curl_multi_cleanup(e->multi);
    }
    curlshim_release();

    secure_clear(e->key, sizeof(e->key));
    free(e);
}

int model_score_async(ModelEngine *e, const ProcessInfo *p, const TrustInfo *t) {
    if (e == NULL || p == NULL || e->pending_count >= MODEL_PENDING_MAX) {
        return 0;
    }

    char request[MODEL_REQUEST_MAX];
    int n = model_build_request(p, t, request, sizeof(request));
    if (n < 0) {
        return 0;
    }

    if (e->pending_count == e->pending_cap) {
        size_t cap = e->pending_cap ? e->pending_cap * 2 : 64;
        if (cap > MODEL_PENDING_MAX) {
            cap = MODEL_PENDING_MAX;
        }
        ModelPending *next = realloc(e->pending, cap * sizeof(*next));
        if (next == NULL) {
            return 0;
        }
        e->pending = next;
        e->pending_cap = cap;
    }

    ModelPending *job = &e->pending[e->pending_count];
    memset(job, 0, sizeof(*job));
    job->pid = p->pid;
    job->starttime = p->starttime;
    memcpy(job->comm, p->comm, sizeof(job->comm));
    job->comm[sizeof(job->comm) - 1] = '\0';
    job->request = malloc((size_t)n + 1);
    if (job->request == NULL) {
        return 0;
    }
    memcpy(job->request, request, (size_t)n + 1);
    e->pending_count++;
    return 1;
}

typedef struct OrderEnt {
    pid_t    pid;
    uint64_t starttime;
    size_t   index;
} OrderEnt;

static int cmp_order(const void *a, const void *b) {
    const OrderEnt *x = a;
    const OrderEnt *y = b;
    if (x->pid != y->pid) {
        return x->pid < y->pid ? -1 : 1;
    }
    if (x->starttime != y->starttime) {
        return x->starttime < y->starttime ? -1 : 1;
    }
    return 0;
}

void model_engine_tick(ModelEngine *engine, ProcList *procs, TrustInfo *trust,
                       size_t trust_count) {
    if (engine == NULL) {
        return;
    }
    pump_engine(engine);

    if (procs == NULL || trust == NULL || trust_count != procs->count) {
        start_pending(engine);
        return;
    }

    apply_results(engine, procs);
    /* /proc is re-read every frame, so a verdict has to be copied back into
     * the fresh snapshot or it would vanish after a single frame. */
    for (size_t i = 0; i < procs->count; i++) {
        ModelSchedule *s = sched_find(engine, procs->items[i].pid,
                                      procs->items[i].starttime, 0);
        if (s != NULL) {
            procs->items[i].risk = s->level;
        }
    }
    start_pending(engine);

    if (engine->cfg.max_per_pass <= 0 || procs->count == 0) {
        return;
    }

    OrderEnt *order = malloc(procs->count * sizeof(*order));
    if (order == NULL) {
        return;
    }
    for (size_t i = 0; i < procs->count; i++) {
        order[i].pid = procs->items[i].pid;
        order[i].starttime = procs->items[i].starttime;
        order[i].index = i;
    }
    qsort(order, procs->count, sizeof(*order), cmp_order);

    double now = now_seconds();
    int budget = engine->cfg.max_per_pass;
    for (size_t k = 0; k < procs->count && budget > 0; k++) {
        size_t i = order[k].index;
        if (trust[i].trusted) {
            continue;
        }
        ModelSchedule *s = sched_find(engine, procs->items[i].pid,
                                      procs->items[i].starttime, 1);
        if (s == NULL) {
            break;
        }
        if (s->in_flight || now < s->next_allowed) {
            continue;
        }
        trust[i].listening_count = (int)model_collect_listening_ports(
            procs->items[i].pid, trust[i].listening_ports, TRUST_MAX_PORTS);
        if (!model_score_async(engine, &procs->items[i], &trust[i])) {
            break;
        }
        s->in_flight = 1;
        budget--;
    }
    free(order);

    start_pending(engine);
    sched_prune(engine, procs);
}
