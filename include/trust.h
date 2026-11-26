#ifndef MINITOP_TRUST_H
#define MINITOP_TRUST_H

#include <stddef.h>
#include <stdint.h>

#include "procs.h"

/* Ports found in listening sockets; the sampling layer fills them only for a
 * process that is actually about to be sent to the model. */
#define TRUST_MAX_PORTS 8

/* Description is truncated to 120 bytes on a UTF-8 boundary; the extra byte is
 * the NUL. Version is bounded by the longest version in the local database. */
#define TRUST_PACKAGE_VERSION_MAX 48
#define TRUST_PACKAGE_DESC_MAX    121

typedef struct TrustInfo {
    int  kernel_thread;   /* E: no exe and ppid == 2 */
    int  package_trusted; /* C: exe owned by a package from core or extra */
    int  systemd_child;   /* H: ppid == 1 and exe under /usr */
    int  trusted;         /* 1 when trust_is_trusted() accepts the C/E/H evidence
                           * for this process: it must not be scored */
    char package[64];
    char repo[16];

    /* Read from the local pacman database during the process pass. package_meta
     * stays 0 when the executable is unowned or its desc file is missing or
     * does not name the package, so the request can omit the whole object. */
    int  package_meta;
    char package_version[TRUST_PACKAGE_VERSION_MAX];
    char package_desc[TRUST_PACKAGE_DESC_MAX];

    uint16_t listening_ports[TRUST_MAX_PORTS];
    int      listening_count;
} TrustInfo;

/**
 * Parses one line of pacman output into a package name and, when the line
 * carries one, a repository name.
 *
 * Accepted forms:
 *   "core bash 5.2.037-1"                     (pacman -Sl / -Slq)
 *   "extra firefox"                          (pacman -Slq)
 *   "/usr/bin/bash is owned by bash 5.2.037-1" (pacman -Qo; repo is left empty)
 *
 * "error:" and "warning:" lines, empty input and malformed lines return 0.
 * pkg and repo are always NUL-terminated on return; they are set to "" when
 * nothing was parsed. Repo is "core" or "extra" only if pacman printed it.
 * @return 1 when a package name was found, 0 otherwise.
 */
int trust_pacman_parse(const char *output, char *pkg, size_t sz, char *repo, size_t rsz);

/**
 * The single rule that decides whether a process may skip the model.
 *
 * C and H come from the process table; E comes from the package cache. When the
 * executable path came from argv[0] instead of /proc/<pid>/exe - the normal
 * case for another user's process, because the link needs root - the evidence
 * is spoofable, so C and H only count for a system account (uid below 1000).
 * A kernel thread is recognised without the link and is always trusted.
 *
 * @return 1 when the process must not be scored.
 */
int trust_is_trusted(int kernel_thread, int package_trusted, int systemd_child,
                     int exe_from_argv, uid_t uid);

/**
 * Fills out with rules C and H plus the package/repo cached for p->exe_path.
 * Rules C and H are decided from ProcessInfo alone; this function never forks.
 * listening_ports is zeroed. out must not be NULL.
 */
void trust_classify_process(const ProcessInfo *p, TrustInfo *out);

/**
 * Classifies every process in list into out (list->count entries), then
 * resolves all executable paths that are not cached yet with ONE
 * `pacman -Qo <path>...` invocation per call. Packages are trusted only when
 * they come from the core or extra repositories, whose package names are
 * loaded once with `pacman -Sl core extra` and then cached.
 *
 * A missing pacman, a failed exec or an unparsable answer makes the affected
 * paths untrusted; they are then scored. Results are cached by path across
 * passes. out must point to list->count writable entries.
 */
void trust_evaluate(const ProcList *list, TrustInfo *out);

/**
 * Fills package_version, package_desc and package_meta for every process whose
 * executable trust already resolved to a package. The local pacman database is
 * scanned with ONE readdir per call; each candidate <name>-<version>/desc is
 * read at most once (the readdir scan stops for a package as soon as a desc
 * whose %NAME% matches is found), so every process that runs the same
 * executable reuses one lookup. Only %NAME%, %VERSION% and %DESC% are read.
 * The description is truncated to 120 bytes on a UTF-8 boundary and control
 * bytes become spaces. A missing database, a missing desc file or a desc that
 * names another package leaves package_meta at 0. Package metadata is never
 * cached across calls.
 *
 * trust_evaluate() calls this at the end of every pass. out must point to
 * list->count writable entries.
 */
void trust_fill_package_meta(const ProcList *list, TrustInfo *out);

/**
 * Overrides the pacman local database root for tests. NULL or "" restores
 * /var/lib/pacman/local. The path is borrowed, not copied.
 */
void trust_package_set_db(const char *path);

/** Number of desc files opened since the last counter reset (test seam). */
unsigned long trust_package_desc_reads(void);

/** Resets the desc read counter (test seam). */
void trust_package_desc_reads_reset(void);

/** Releases the package and path caches. Safe to call more than once. */
void trust_cache_reset(void);

#endif
