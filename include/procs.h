#ifndef MINITOP_PROCS_H
#define MINITOP_PROCS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum SortColumn {
    COL_PID = 0,
    COL_USER,
    COL_COMMAND,
    COL_STATE,
    COL_CPU,
    COL_MEM,
    COL_TIME,
    COL_FLAGS,
    COL_PERMS,
    COL_COUNT
} SortColumn;

/* 8B -> 4B -> 1B */
typedef struct ProcessInfo {
    uint64_t starttime;
    uint64_t utime;
    uint64_t stime;
    uint64_t vsize_bytes;
    uint64_t rss_bytes;
    double   cpu_pct;

    pid_t    pid;
    pid_t    ppid;
    uid_t    uid;
    int      num_threads;
    int      risk;
    int      llm_verdict;      /* -1 unknown, 0 safe, 1 malicious */
    int      trusted;          /* known-safe by plan 6.4: no model call needed */
    int      exe_from_argv;    /* exe link unreadable; path came from argv[0] */
    char     llm_reason[96];   /* one-line LLM reason, empty when unknown */
    char     llm_detail[512];  /* explanation lines after the verdict */

    uint8_t  flags;
    char     state;
    char     comm[16];
    char     user[32];
    char     time_plus[32];
    char     perms[11];
    char     exe_path[256];
    char     cwd[256];
} ProcessInfo;

typedef struct ProcSummary {
    size_t total_procs;
    size_t total_threads;
    size_t running_procs;
    size_t sleeping_procs;
} ProcSummary;

typedef struct ProcList {
    ProcessInfo *items;
    size_t       count;
    size_t       capacity;
} ProcList;

/* The CPU percentage needs one previous sample per process, but only the pid,
 * starttime and tick counters - not the strings, permissions and flags of a
 * whole ProcessInfo. Keeping this instead of a second ProcList saves about a
 * megabyte on a machine with 800 processes. */
typedef struct ProcTicks {
    pid_t    pid;
    uint64_t starttime;
    uint64_t ticks; /* utime + stime from /proc/<pid>/stat */
} ProcTicks;

typedef struct ProcTicksList {
    ProcTicks *items;
    size_t     count;
    size_t     capacity;
} ProcTicksList;

/* dynamic list */
int  proclist_init(ProcList *list, size_t initial_capacity);
void proclist_clear(ProcList *list);
int  proclist_push(ProcList *list, const ProcessInfo *item);
void proclist_free(ProcList *list);

/* text parsers/calculators */
/**
 * Parses one /proc/<pid>/stat line. `line_len` bounds every read, so a
 * truncated read (which need not be NUL-terminated) is rejected instead of
 * running past the buffer end.
 */
int  parse_proc_pid_stat(const char *line, size_t line_len, ProcessInfo *out,
                         long page_size, long hz);
int  parse_proc_pid_status_uid(const char *status_text, uid_t *uid_out);
void format_time_plus(uint64_t utime, uint64_t stime, long hz, char *buf, size_t buf_sz);
void procs_compute_cpu_deltas(ProcList *curr, const ProcList *prev, uint64_t delta_total_cpu, long n_cores);

/**
 * Replaces snap with pid/starttime/ticks from list. The storage is reused
 * between frames; on allocation failure the history is dropped and the next
 * frame reports zero CPU for every process instead of aborting.
 */
void procticks_capture(ProcTicksList *snap, const ProcList *list);
void procticks_free(ProcTicksList *snap);

/**
 * Same percentages as procs_compute_cpu_deltas, matched against the compact
 * history. The core count is queried here, so the caller passes only the
 * system-wide tick delta.
 */
void procs_apply_cpu_deltas(ProcList *curr, const ProcTicksList *prev,
                           uint64_t delta_total_cpu);

/* /proc scan LIVE */
int procs_collect(ProcList *curr, const ProcList *prev, uint64_t delta_total_cpu, ProcSummary *summary_out);

/* NET flag: procs_collect() reads /proc/net/tcp{,6} once per pass, sorts the
 * LISTEN inodes and marks every process whose /proc/<pid>/fd links to one of
 * them with FLAG_NET. The two functions stay public so a caller can reuse the
 * same set for a single pid without a second parser. */
size_t  procs_collect_listen_inodes(uint64_t *out, size_t cap);
uint8_t procs_has_listen_socket(pid_t pid, const uint64_t *inodes, size_t count);

void    proclist_sort(ProcList *list, SortColumn col, int descending);

/**
 * Selects what the FLAGS column sorts on. Off: the local rule bits (DEL, TMP,
 * MEMFD, NET), which is all the column shows in mode 1. On: the model's risk
 * level, with trusted rows below the cleared ones, matching what modes 2 and 3
 * display.
 */
void    proclist_set_flags_sort(int by_risk);
ssize_t proclist_find_followed(const ProcList *list, pid_t pid, uint64_t starttime);
int     proc_kill(pid_t pid, int force_sigkill);

#endif
