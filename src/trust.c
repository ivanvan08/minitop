#include "trust.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define TRUST_PATH_MAX     256
#define TRUST_BATCH_MAX    512
#define TRUST_CAPTURE_MAX  (4u * 1024u * 1024u)
#define TRUST_CMD_TIMEOUT  5000 /* ms; pacman is local and normally answers in <300 ms */

typedef struct PathEntry {
    char path[TRUST_PATH_MAX];
    char package[64];
    char repo[16];
    int  trusted;
} PathEntry;

typedef struct TrustedPkg {
    char name[64];
    char repo[16];
} TrustedPkg;

static TrustedPkg *g_pkgs;
static size_t     g_pkg_count;
static size_t     g_pkg_cap;
static int        g_pkgs_loaded;
static int        g_pacman_missing;

static PathEntry *g_paths;
static size_t     g_path_count;
static size_t     g_path_cap;

static void copy_str(char *dst, size_t sz, const char *src, size_t len) {
    if (dst == NULL || sz == 0) {
        return;
    }
    if (len >= sz) {
        len = sz - 1;
    }
    if (src != NULL && len > 0) {
        memcpy(dst, src, len);
    }
    dst[len] = '\0';
}

static void skip_space(const char **p) {
    while (**p == ' ' || **p == '\t' || **p == '\r') {
        (*p)++;
    }
}

int trust_pacman_parse(const char *output, char *pkg, size_t sz, char *repo, size_t rsz) {
    if (pkg != NULL && sz > 0) {
        pkg[0] = '\0';
    }
    if (repo != NULL && rsz > 0) {
        repo[0] = '\0';
    }
    if (output == NULL || pkg == NULL || sz == 0) {
        return 0;
    }

    const char *p = output;
    skip_space(&p);
    if (*p == '\0' || *p == '\n' || strncmp(p, "error:", 6) == 0 ||
        strncmp(p, "warning:", 8) == 0) {
        return 0;
    }

    const char *owned = strstr(p, " is owned by ");
    if (owned != NULL) {
        const char *name = owned + 13;
        size_t len = strcspn(name, " \t\r\n");
        if (len == 0 || len >= sz) {
            return 0;
        }
        copy_str(pkg, sz, name, len);
        return 1;
    }

    /* "repo package [version]" as printed by pacman -Sl and pacman -Slq. */
    size_t rlen = strcspn(p, " \t\r\n");
    if (rlen == 0 || rlen >= rsz || p[0] == '/') {
        return 0;
    }
    const char *name = p + rlen;
    skip_space(&name);
    size_t plen = strcspn(name, " \t\r\n");
    if (plen == 0 || plen >= sz) {
        return 0;
    }
    copy_str(repo, rsz, p, rlen);
    copy_str(pkg, sz, name, plen);
    return 1;
}

static int path_is_system(const char *path) {
    return strncmp(path, "/usr/", 5) == 0;
}

static PathEntry *cache_find(const char *path) {
    for (size_t i = 0; i < g_path_count; i++) {
        if (strcmp(g_paths[i].path, path) == 0) {
            return &g_paths[i];
        }
    }
    return NULL;
}

static void cache_put(const char *path, const char *pkg, const char *repo, int trusted) {
    PathEntry *e = cache_find(path);
    if (e == NULL) {
        if (g_path_count == g_path_cap) {
            size_t cap = g_path_cap ? g_path_cap * 2 : 128;
            PathEntry *next = realloc(g_paths, cap * sizeof(*next));
            if (next == NULL) {
                return;
            }
            g_paths = next;
            g_path_cap = cap;
        }
        e = &g_paths[g_path_count++];
        copy_str(e->path, sizeof(e->path), path, strlen(path));
    }
    copy_str(e->package, sizeof(e->package), pkg, pkg ? strlen(pkg) : 0);
    copy_str(e->repo, sizeof(e->repo), repo, repo ? strlen(repo) : 0);
    e->trusted = trusted;
}

static int cmp_pkg(const void *a, const void *b) {
    const TrustedPkg *x = a;
    const TrustedPkg *y = b;
    return strcmp(x->name, y->name);
}

/* bsearch passes the char* key first, the array element second. */
static int cmp_pkg_key(const void *a, const void *b) {
    const char *key = a;
    const TrustedPkg *y = b;
    return strcmp(key, y->name);
}

static void trusted_set_add(const char *pkg, const char *repo) {
    if (g_pkg_count == g_pkg_cap) {
        size_t cap = g_pkg_cap ? g_pkg_cap * 2 : 2048;
        TrustedPkg *next = realloc(g_pkgs, cap * sizeof(*next));
        if (next == NULL) {
            return;
        }
        g_pkgs = next;
        g_pkg_cap = cap;
    }
    TrustedPkg *p = &g_pkgs[g_pkg_count++];
    copy_str(p->name, sizeof(p->name), pkg, strlen(pkg));
    copy_str(p->repo, sizeof(p->repo), repo, repo != NULL ? strlen(repo) : 0);
}

/**
 * Looks a package up in the core/extra set loaded with `pacman -Sl core extra`.
 * @return 1 when the package is distribution-managed, with its repository name
 *         copied to repo when repo != NULL and rsz > 0.
 */
static int trusted_set_repo(const char *pkg, char *repo, size_t rsz) {
    if (pkg == NULL || pkg[0] == '\0' || g_pkg_count == 0) {
        return 0;
    }
    const TrustedPkg *found =
        bsearch(pkg, g_pkgs, g_pkg_count, sizeof(g_pkgs[0]), cmp_pkg_key);
    if (found == NULL) {
        return 0;
    }
    if (repo != NULL && rsz > 0) {
        copy_str(repo, rsz, found->repo, strlen(found->repo));
    }
    return 1;
}

/**
 * Runs argv without a shell and returns its combined stdout+stderr in a
 * malloc'd NUL-terminated buffer. NULL means fork/pipe/read failure.
 * exit_status receives the child's exit status (-1 when it did not exit).
 */
static char *run_capture(char *const argv[], size_t *out_len, int *exit_status) {
    if (out_len != NULL) {
        *out_len = 0;
    }
    if (exit_status != NULL) {
        *exit_status = -1;
    }

    int fds[2];
    if (pipe(fds) != 0) {
        return NULL;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return NULL;
    }
    if (pid == 0) {
        close(fds[0]);
        if (dup2(fds[1], STDOUT_FILENO) < 0 || dup2(fds[1], STDERR_FILENO) < 0) {
            _exit(127);
        }
        close(fds[1]);
        execvp(argv[0], argv);
        _exit(127);
    }

    close(fds[1]);
    size_t cap = 8192;
    size_t len = 0;
    char *buf = malloc(cap);
    if (buf == NULL) {
        kill(pid, SIGKILL);
        close(fds[0]);
        waitpid(pid, NULL, 0);
        return NULL;
    }

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int failed = 0;
    for (;;) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (long)(now.tv_sec - start.tv_sec) * 1000L +
                       (now.tv_nsec - start.tv_nsec) / 1000000L;
        int left = TRUST_CMD_TIMEOUT - (int)elapsed;
        if (left <= 0) {
            kill(pid, SIGKILL);
            failed = 1;
            break;
        }
        struct pollfd pfd = { .fd = fds[0], .events = POLLIN, .revents = 0 };
        int pr = poll(&pfd, 1, left);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            kill(pid, SIGKILL);
            failed = 1;
            break;
        }
        if (pr == 0) {
            kill(pid, SIGKILL);
            failed = 1;
            break;
        }
        ssize_t n = read(fds[0], buf + len, cap - len - 1);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            failed = 1;
            break;
        }
        if (n == 0) {
            break;
        }
        len += (size_t)n;
        if (len + 1 >= cap) {
            if (cap >= TRUST_CAPTURE_MAX) {
                failed = 1;
                break;
            }
            size_t next_cap = cap * 2;
            char *next = realloc(buf, next_cap);
            if (next == NULL) {
                failed = 1;
                break;
            }
            buf = next;
            cap = next_cap;
        }
    }
    close(fds[0]);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    if (exit_status != NULL) {
        *exit_status = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }
    if (failed) {
        free(buf);
        return NULL;
    }
    buf[len] = '\0';
    if (out_len != NULL) {
        *out_len = len;
    }
    return buf;
}

static void trusted_set_load(void) {
    if (g_pkgs_loaded) {
        return;
    }
    g_pkgs_loaded = 1;

    char *argv[] = { "pacman", "-Sl", "core", "extra", NULL };
    size_t len = 0;
    int status = -1;
    char *out = run_capture(argv, &len, &status);
    if (out == NULL || status == 127) {
        g_pacman_missing = 1;
    }
    if (out != NULL) {
        char *line = out;
        while (*line != '\0') {
            char *nl = strchr(line, '\n');
            if (nl != NULL) {
                *nl = '\0';
            }
            char pkg[64];
            char repo[16];
            if (trust_pacman_parse(line, pkg, sizeof(pkg), repo, sizeof(repo)) &&
                (strcmp(repo, "core") == 0 || strcmp(repo, "extra") == 0)) {
                trusted_set_add(pkg, repo);
            }
            if (nl == NULL) {
                break;
            }
            line = nl + 1;
        }
        free(out);
    }
    if (g_pkg_count == 0) {
        g_pacman_missing = 1;
    } else {
        qsort(g_pkgs, g_pkg_count, sizeof(g_pkgs[0]), cmp_pkg);
    }
}

int trust_is_trusted(int kernel_thread, int package_trusted, int systemd_child,
                     int exe_from_argv, uid_t uid) {
    /* The exe link of another user's process is unreadable without root, so on
     * a normal desktop most processes would be scored even when they are
     * packaged daemons. argv[0] is user-controlled, so a path that came from it
     * only earns trust for a system account: anything else that hides its exe
     * (PR_SET_DUMPABLE=0 is enough) is scored. */
    int argv_trust_ok = !exe_from_argv || uid < 1000;

    if (kernel_thread) {
        return 1;
    }
    if (package_trusted && argv_trust_ok) {
        return 1;
    }
    return systemd_child && argv_trust_ok;
}

void trust_classify_process(const ProcessInfo *p, TrustInfo *out) {
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    if (p == NULL) {
        /* Nothing to classify, and no evidence exists to trust: the verdict
         * still comes from the gate so no path hand-writes trusted = 1. */
        out->trusted = trust_is_trusted(0, 0, 0, 0, 0);
        return;
    }

    /* Plan 6.4 rule E, and nothing more: a missing exe link alone is not proof
     * of a kernel thread, because non-root minitop cannot read /proc/<pid>/exe
     * of other users. Only a missing link with ppid == 2 (kthreadd) is E.
     * A comm that merely looks like a kernel thread is not evidence: a process
     * can set its own name with prctl, and a VM run showed a payload under
     * /dev/shm called kswapd0 skipping the model entirely. */
    out->kernel_thread = (p->exe_path[0] == '\0' && p->ppid == 2);
    out->systemd_child = (p->ppid == 1 && path_is_system(p->exe_path));

    PathEntry *entry = cache_find(p->exe_path);
    if (entry != NULL) {
        copy_str(out->package, sizeof(out->package), entry->package, strlen(entry->package));
        copy_str(out->repo, sizeof(out->repo), entry->repo, strlen(entry->repo));
        out->package_trusted = entry->trusted;
    }
    out->trusted = trust_is_trusted(out->kernel_thread, out->package_trusted,
                                    out->systemd_child, p->exe_from_argv, p->uid);
}

static void apply_batch_reply(const char *output, char paths[][TRUST_PATH_MAX],
                              size_t npaths, int pacman_ok) {
    int found[TRUST_BATCH_MAX];

    for (size_t i = 0; i < npaths; i++) {
        found[i] = 0;
    }

    const char *line = output;
    while (line != NULL && *line != '\0') {
        const char *nl = strchr(line, '\n');
        const char *end = nl ? nl : line + strlen(line);
        const char *owned = NULL;
        for (const char *p = line; p + 13 <= end; p++) {
            if (memcmp(p, " is owned by ", 13) == 0) {
                owned = p;
                break;
            }
        }
        if (owned != NULL) {
            size_t path_len = (size_t)(owned - line);
            for (size_t i = 0; i < npaths; i++) {
                if (strlen(paths[i]) == path_len && memcmp(paths[i], line, path_len) == 0) {
                    char pkg[64];
                    char repo[16];
                    if (trust_pacman_parse(line, pkg, sizeof(pkg), repo, sizeof(repo))) {
                        char known_repo[16];
                        int trusted = trusted_set_repo(pkg, known_repo,
                                                       sizeof(known_repo));
                        if (trusted && repo[0] != '\0' &&
                            strcmp(repo, "core") != 0 && strcmp(repo, "extra") != 0) {
                            trusted = 0;
                        }
                        cache_put(paths[i], pkg, trusted ? known_repo : repo, trusted);
                        found[i] = 1;
                    }
                    break;
                }
            }
        }
        if (nl == NULL) {
            break;
        }
        line = nl + 1;
    }

    /* Every queried path that pacman did not own is untrusted. This also
     * caches the negative answer, so the next pass does not ask again. */
    for (size_t i = 0; i < npaths; i++) {
        if (!found[i] || !pacman_ok) {
            cache_put(paths[i], "", "", 0);
        }
    }
}

/* ------------------------------------------- package metadata (pacman db) -- */

#define TRUST_PKG_DB_DEFAULT "/var/lib/pacman/local"
#define TRUST_PKG_READ_MAX   (64u * 1024u)

static const char *g_pkg_db = TRUST_PKG_DB_DEFAULT;
static unsigned long g_desc_reads;

void trust_package_set_db(const char *path) {
    g_pkg_db = (path != NULL && path[0] != '\0') ? path : TRUST_PKG_DB_DEFAULT;
}

unsigned long trust_package_desc_reads(void) {
    return g_desc_reads;
}

void trust_package_desc_reads_reset(void) {
    g_desc_reads = 0;
}

/**
 * Copies the value on the line after an exact "%FIELD%" header. Every value in
 * the pacman desc format is a single line; a missing header is not found.
 */
static int desc_field(const char *text, const char *field, char *out, size_t sz) {
    size_t flen = strlen(field);
    for (const char *p = text; *p != '\0';) {
        const char *nl = strchr(p, '\n');
        size_t len = nl != NULL ? (size_t)(nl - p) : strlen(p);
        if (len == flen && memcmp(p, field, flen) == 0) {
            const char *v = nl != NULL ? nl + 1 : p + len;
            size_t vlen = strcspn(v, "\n");
            while (vlen > 0 && (v[vlen - 1] == '\r' || v[vlen - 1] == ' ' ||
                                v[vlen - 1] == '\t')) {
                vlen--;
            }
            copy_str(out, sz, v, vlen);
            return 1;
        }
        if (nl == NULL) {
            break;
        }
        p = nl + 1;
    }
    return 0;
}

/**
 * Copies at most sz-1 bytes of a database description, cutting on a UTF-8
 * boundary and replacing control bytes with spaces. Trailing spaces left by
 * the sanitiser are trimmed.
 */
static void desc_sanitise(const char *src, char *dst, size_t sz) {
    if (sz == 0) {
        return;
    }
    size_t max = sz - 1;
    size_t n = strlen(src);
    if (n > max) {
        n = max;
        while (n > 0 && ((unsigned char)src[n] & 0xC0) == 0x80) {
            n--;
        }
    }
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)src[i];
        dst[o++] = (c < 0x20 || c == 0x7f) ? ' ' : (char)c;
    }
    while (o > 0 && dst[o - 1] == ' ') {
        o--;
    }
    dst[o] = '\0';
}

typedef struct PkgMeta {
    char version[TRUST_PACKAGE_VERSION_MAX];
    char desc[TRUST_PACKAGE_DESC_MAX];
    int  ok;
} PkgMeta;

typedef struct PkgLookup {
    char     name[64];
    size_t   plen;
    PkgMeta  meta;
} PkgLookup;

/**
 * Reads <db>/<dir>/desc and accepts it only when its %NAME% equals pkg, so a
 * directory that merely shares a prefix (bash and bash-completion) cannot
 * supply the wrong metadata.
 * @return 1 when %NAME% and %VERSION% were found, 0 otherwise.
 */
static int pkg_meta_read(const char *dir, const char *pkg, PkgMeta *m) {
    char path[512];
    int n = snprintf(path, sizeof(path), "%s/%s/desc", g_pkg_db, dir);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        return 0;
    }

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return 0;
    }
    g_desc_reads++;

    char *text = malloc(TRUST_PKG_READ_MAX + 1);
    if (text == NULL) {
        close(fd);
        return 0;
    }
    size_t len = 0;
    for (;;) {
        ssize_t r = read(fd, text + len, TRUST_PKG_READ_MAX - len);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (r == 0) {
            break;
        }
        len += (size_t)r;
        if (len == TRUST_PKG_READ_MAX) {
            break;
        }
    }
    close(fd);
    text[len] = '\0';

    char name[64];
    char raw[1024];
    int ok = desc_field(text, "%NAME%", name, sizeof(name)) &&
             strcmp(name, pkg) == 0 &&
             desc_field(text, "%VERSION%", m->version, sizeof(m->version));
    if (ok) {
        if (desc_field(text, "%DESC%", raw, sizeof(raw))) {
            desc_sanitise(raw, m->desc, sizeof(m->desc));
        } else {
            m->desc[0] = '\0';
        }
        m->ok = 1;
    }
    free(text);
    return ok;
}

void trust_fill_package_meta(const ProcList *list, TrustInfo *out) {
    if (list == NULL || out == NULL || list->count == 0) {
        return;
    }

    size_t need = 0;
    for (size_t i = 0; i < list->count; i++) {
        if (out[i].package[0] != '\0' && !out[i].package_meta) {
            need++;
        }
    }
    if (need == 0) {
        return;
    }

    PkgLookup *lookup = calloc(need, sizeof(*lookup));
    if (lookup == NULL) {
        return;
    }

    size_t n = 0;
    for (size_t i = 0; i < list->count && n < need; i++) {
        if (out[i].package[0] == '\0' || out[i].package_meta) {
            continue;
        }
        size_t k = 0;
        for (; k < n; k++) {
            if (strcmp(lookup[k].name, out[i].package) == 0) {
                break;
            }
        }
        if (k == n) {
            copy_str(lookup[n].name, sizeof(lookup[n].name), out[i].package,
                     strlen(out[i].package));
            lookup[n].plen = strlen(lookup[n].name);
            n++;
        }
    }

    /* One readdir for the whole pass. A package is resolved as soon as a
     * candidate desc names it, so a package that appears in several processes
     * costs one desc read, not one per process. */
    DIR *db = opendir(g_pkg_db);
    if (db != NULL) {
        size_t remaining = n;
        struct dirent *e;
        while (remaining > 0 && (e = readdir(db)) != NULL) {
            if (e->d_name[0] == '.') {
                continue;
            }
            for (size_t k = 0; k < n; k++) {
                if (lookup[k].meta.ok ||
                    e->d_name[0] != lookup[k].name[0] ||
                    strncmp(e->d_name, lookup[k].name, lookup[k].plen) != 0 ||
                    e->d_name[lookup[k].plen] != '-') {
                    continue;
                }
                if (pkg_meta_read(e->d_name, lookup[k].name, &lookup[k].meta)) {
                    remaining--;
                }
            }
        }
        closedir(db);
    }

    for (size_t i = 0; i < list->count; i++) {
        if (out[i].package[0] == '\0' || out[i].package_meta) {
            continue;
        }
        for (size_t k = 0; k < n; k++) {
            if (strcmp(lookup[k].name, out[i].package) != 0) {
                continue;
            }
            if (lookup[k].meta.ok) {
                out[i].package_meta = 1;
                copy_str(out[i].package_version, sizeof(out[i].package_version),
                         lookup[k].meta.version, strlen(lookup[k].meta.version));
                copy_str(out[i].package_desc, sizeof(out[i].package_desc),
                         lookup[k].meta.desc, strlen(lookup[k].meta.desc));
            }
            break;
        }
    }

    free(lookup);
}

void trust_evaluate(const ProcList *list, TrustInfo *out) {
    if (list == NULL || out == NULL) {
        return;
    }

    for (size_t i = 0; i < list->count; i++) {
        trust_classify_process(&list->items[i], &out[i]);
    }

    static char paths[TRUST_BATCH_MAX][TRUST_PATH_MAX];
    size_t npaths = 0;

    for (size_t i = 0; i < list->count && npaths < TRUST_BATCH_MAX; i++) {
        const ProcessInfo *p = &list->items[i];
        if (out[i].kernel_thread || p->exe_path[0] == '\0') {
            continue;
        }
        if (cache_find(p->exe_path) != NULL) {
            continue;
        }
        int duplicate = 0;
        for (size_t k = 0; k < npaths; k++) {
            if (strcmp(paths[k], p->exe_path) == 0) {
                duplicate = 1;
                break;
            }
        }
        if (duplicate) {
            continue;
        }
        copy_str(paths[npaths], TRUST_PATH_MAX, p->exe_path, strlen(p->exe_path));
        npaths++;
    }

    if (npaths > 0) {
        trusted_set_load();
        if (g_pacman_missing) {
            for (size_t i = 0; i < npaths; i++) {
                cache_put(paths[i], "", "", 0);
            }
        } else {
            char *argv[TRUST_BATCH_MAX + 3];
            argv[0] = "pacman";
            argv[1] = "-Qo";
            for (size_t i = 0; i < npaths; i++) {
                argv[i + 2] = paths[i];
            }
            argv[npaths + 2] = NULL;

            size_t len = 0;
            int status = -1;
            char *reply = run_capture(argv, &len, &status);
            if (reply == NULL || status == 127) {
                if (status == 127) {
                    g_pacman_missing = 1;
                }
                for (size_t i = 0; i < npaths; i++) {
                    cache_put(paths[i], "", "", 0);
                }
            } else {
                apply_batch_reply(reply, paths, npaths, 1);
            }
            free(reply);
        }
    }

    for (size_t i = 0; i < list->count; i++) {
        const ProcessInfo *p = &list->items[i];
        PathEntry *entry = cache_find(p->exe_path);
        if (entry != NULL) {
            copy_str(out[i].package, sizeof(out[i].package), entry->package, strlen(entry->package));
            copy_str(out[i].repo, sizeof(out[i].repo), entry->repo, strlen(entry->repo));
            out[i].package_trusted = entry->trusted;
        }
        /* Same gate as trust_classify_process: the package answer only sets
         * package_trusted, and the argv/uid rule decides whether that evidence
         * may skip the model at all. */
        out[i].trusted = trust_is_trusted(out[i].kernel_thread, out[i].package_trusted,
                                          out[i].systemd_child, p->exe_from_argv,
                                          p->uid);
    }

    trust_fill_package_meta(list, out);
}

void trust_cache_reset(void) {
    free(g_pkgs);
    g_pkgs = NULL;
    g_pkg_count = 0;
    g_pkg_cap = 0;
    g_pkgs_loaded = 0;
    g_pacman_missing = 0;

    free(g_paths);
    g_paths = NULL;
    g_path_count = 0;
    g_path_cap = 0;

    g_desc_reads = 0;
}
