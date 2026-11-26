#include "sysinfo.h"
#include "cpu.h"
#include "flags.h"
#include "procs.h"
#include "display.h"
#include "tui.h"
#include "input.h"
#include "model.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <signal.h>
#include <limits.h>
#include <netinet/in.h>
#include <unistd.h>

static void test_sysinfo_parsers(void) {
    const char *mem_sample =
        "MemTotal:       16000000 kB\n"
        "MemFree:         2000000 kB\n"
        "MemAvailable:   10000000 kB\n"
        "Buffers:          500000 kB\n"
        "Cached:          4000000 kB\n"
        "SReclaimable:     300000 kB\n"
        "SwapTotal:       4000000 kB\n"
        "SwapFree:        3500000 kB\n";

    MemInfo mem;
    assert(parse_meminfo(mem_sample, &mem) == 0);
    assert(mem.mem_total_kib == 16000000ULL);
    assert(mem.mem_avail_kib == 10000000ULL);
    assert(mem.mem_used_kib == 6000000ULL);
    assert(mem.mem_buffers_kib == 500000ULL);
    assert(mem.mem_cached_kib == 4000000ULL);
    assert(mem.swap_total_kib == 4000000ULL);
    assert(mem.swap_used_kib == 500000ULL);

    /* when MemAvailable is absent */
    const char *mem_no_avail =
        "MemTotal:       8000000 kB\n"
        "MemFree:        1000000 kB\n"
        "Buffers:         500000 kB\n"
        "Cached:         1500000 kB\n"
        "SReclaimable:    200000 kB\n";
    assert(parse_meminfo(mem_no_avail, &mem) == 0);
    assert(mem.mem_avail_kib == 3200000ULL);
    assert(mem.mem_used_kib == 4800000ULL);

    uint64_t up = 0;
    assert(parse_uptime("12345.67 54321.00\n", &up) == 0);
    assert(up == 12345ULL);
    assert(parse_uptime("-5.0 0.0\n", &up) == -1);
    assert(parse_uptime(NULL, &up) == -1);

    LoadAvg load;
    assert(parse_loadavg("0.52 1.15 0.98 3/712 9981\n", &load) == 0);
    assert(fabs(load.load1 - 0.52) < 1e-6);
    assert(fabs(load.load5 - 1.15) < 1e-6);
    assert(fabs(load.load15 - 0.98) < 1e-6);
    assert(load.running_entities == 3);
    assert(load.total_entities == 712);

    assert(is_physical_mount("/dev/sda1", "/", "ext4") == 1);
    assert(is_physical_mount("/dev/nvme0n1p2", "/home", "btrfs") == 1);
    assert(is_physical_mount("tmpfs", "/run", "tmpfs") == 0);
    assert(is_physical_mount("/dev/loop0", "/snap/core", "squashfs") == 0);
    assert(is_physical_mount("/dev/sda1", "/boot/efi", "vfat") == 1); /* a real partition */
}

static void test_cpu_parser_and_deltas(void) {
    /* verify guest and guest_nice are'nt double-counted */
    const char *stat1 = "cpu  1000 100 300 8000 600 0 0 0 500 100\ncpu0 500 50 150 4000 300 0 0 0 0 0\n";
    const char *stat2 = "cpu  1200 100 400 8700 550 0 0 0 500 100\n";

    CpuSample s1, s2;
    assert(parse_proc_stat_cpu(stat1, &s1) == 0);
    assert(s1.idle_all == 8600ULL);
    assert(s1.busy_all == 1400ULL);
    assert(s1.total == 10000ULL);

    assert(parse_proc_stat_cpu(stat2, &s2) == 0);
    uint64_t d_tot = 0;
    double pct = cpu_calc_usage_pct(&s1, &s2, &d_tot);
    assert(d_tot == 1000ULL);
    assert(fabs(pct - 30.0) < 1e-6);
}

static void test_flags_and_sanitization(void) {
    assert(flags_detect_exe("/usr/bin/bash") == FLAG_NONE);
    assert(flags_detect_exe("/usr/lib/firefox/firefox (deleted)") == FLAG_DEL);
    assert(flags_detect_exe("/tmp/runner") == FLAG_TMP);
    assert(flags_detect_exe("/var/tmp/agent") == FLAG_TMP);
    assert(flags_detect_exe("/dev/shm/.x11-sync (deleted)") == (FLAG_DEL | FLAG_TMP));
    assert(flags_detect_exe("/memfd:payload (deleted)") == (FLAG_DEL | FLAG_MEMFD));

    /* false-positive guard */
    assert(flags_detect_exe("/tmpfs_custom/app") == FLAG_NONE);
    assert(flags_detect_exe("/home/user/memfd:test/app") == FLAG_NONE);

    /* TUI flag formatting lists every flag the row carries, in one order */
    char fbuf[32];
    flags_format_tui(FLAG_NONE, fbuf, sizeof(fbuf));
    assert(strcmp(fbuf, "-") == 0);
    flags_format_tui(FLAG_MEMFD, fbuf, sizeof(fbuf));
    assert(strcmp(fbuf, "MEMFD") == 0);
    flags_format_tui(FLAG_NET, fbuf, sizeof(fbuf));
    assert(strcmp(fbuf, "NET") == 0);
    flags_format_tui(FLAG_DEL | FLAG_MEMFD, fbuf, sizeof(fbuf));
    assert(strcmp(fbuf, "DEL,MEMFD") == 0);
    flags_format_tui(FLAG_DEL | FLAG_TMP, fbuf, sizeof(fbuf));
    assert(strcmp(fbuf, "DEL,TMP") == 0);
    flags_format_tui(FLAG_NET | FLAG_MEMFD | FLAG_TMP | FLAG_DEL, fbuf, sizeof(fbuf));
    assert(strcmp(fbuf, "DEL,TMP,MEMFD,NET") == 0);

    /* a short buffer cuts the text, never the terminator */
    char tight[8];
    flags_format_tui(FLAG_DEL | FLAG_TMP | FLAG_MEMFD | FLAG_NET, tight, sizeof(tight));
    assert(tight[sizeof(tight) - 1] == '\0');

    char rwx[11];
    format_mode_rwx(S_IFREG | S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH, rwx);
    assert(strcmp(rwx, "-rwxr-xr-x") == 0);

    /* term injection */
    char clean[32];
    sanitize_display_str(clean, sizeof(clean), "evil\x1b[31m\nproc");
    assert(strcmp(clean, "evil?[31m?proc") == 0);

    /* UTF-8 survives, broken sequences do not */
    sanitize_display_str(clean, sizeof(clean), "процес");
    assert(strcmp(clean, "процес") == 0);
    sanitize_display_str(clean, sizeof(clean), "a\xff\xfe" "b");
    assert(strcmp(clean, "a??b") == 0);
    sanitize_display_str(clean, 5, "абвг");
    assert(strcmp(clean, "аб") == 0);

    /* C1 controls (UTF-8 encoded CSI) and overlong encodings are stripped too */
    sanitize_display_str(clean, sizeof(clean), "a\xc2\x9b" "2Jb");
    assert(strcmp(clean, "a?2Jb") == 0);
    sanitize_display_str(clean, sizeof(clean), "\xc0\x9b");
    assert(strcmp(clean, "?") == 0);
    sanitize_display_str(clean, sizeof(clean), "\xe0\x82\xa9");
    assert(strcmp(clean, "?") == 0);

    /* Truncated UTF-8 at end of buffer or before ASCII must not over-read past '\0' or eat ASCII */
    char truncated_end[3] = { 'a', '\xe0', '\0' };
    sanitize_display_str(clean, sizeof(clean), truncated_end);
    assert(strcmp(clean, "a?") == 0);
    sanitize_display_str(clean, sizeof(clean), "a\xe0xy");
    assert(strcmp(clean, "a?xy") == 0);

    /* NET sits next to the path-derived flags, in the same cell */
    flags_format_tui(FLAG_NET, fbuf, sizeof(fbuf));
    assert(strcmp(fbuf, "NET") == 0);
    flags_format_tui(FLAG_DEL | FLAG_NET, fbuf, sizeof(fbuf));
    assert(strcmp(fbuf, "DEL,NET") == 0);
}

static void test_net_parsers(void) {
    const char *net_tcp =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 424242 1\n"
        "   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 515151 1\n"
        "   2: 0100007F:D1F2 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 616161 1\n";

    uint64_t inodes[8];
    size_t n = net_listen_inodes(net_tcp, inodes, 8);
    assert(n == 2);
    assert(inodes[0] == 424242ULL);
    assert(inodes[1] == 515151ULL);

    /* a single line works too, and non-listen states are ignored */
    assert(net_listen_inodes("   2: 0100007F:D1F2 0100007F:1F90 01 0:0 00:00000000 00000000 1000 0 616161 1\n",
                             inodes, 8) == 0);
    assert(net_listen_inodes(NULL, inodes, 8) == 0);

    uint64_t inode = 0;
    assert(net_socket_inode("socket:[98765]", &inode) == 0);
    assert(inode == 98765ULL);
    assert(net_socket_inode("anon_inode:[eventfd]", &inode) == -1);
    assert(net_socket_inode("/tmp/file", &inode) == -1);
    assert(net_socket_inode("socket:[", &inode) == -1);
}

static void test_procs_parser_deltas_and_sort(void) {
    const char *tricky_stat =
        "4242 (my (evil) Z 1) R 1000 4242 1000 0 -1 4194304 "
        "12 0 0 0 6150 205 0 0 20 0 4 0 55555 20971520 1024";

    ProcessInfo p;
    assert(parse_proc_pid_stat(tricky_stat, strlen(tricky_stat), &p, 4096, 100) == 0);
    assert(p.pid == 4242);
    assert(strcmp(p.comm, "my (evil) Z 1") == 0);
    assert(p.state == 'R');
    assert(strcmp(p.user, "?") == 0);
    assert(p.cwd[0] == '\0');
    assert(p.ppid == 1000);
    assert(p.utime == 6150ULL);
    assert(p.stime == 205ULL);
    assert(p.num_threads == 4);
    assert(p.starttime == 55555ULL);
    assert(p.rss_bytes == 1024ULL * 4096ULL);
    assert(strcmp(p.time_plus, "1:03.55") == 0);

    const char *status_sample = "Name:\tbash\nState:\tS (sleeping)\nUid:\t1000\t1000\t1000\t1000\n";
    uid_t uid = 0;
    assert(parse_proc_pid_status_uid(status_sample, &uid) == 0);
    assert(uid == 1000);

    ProcList prev = {0}, curr = {0};
    assert(proclist_init(&prev, 4) == 0);
    assert(proclist_init(&curr, 4) == 0);

    ProcessInfo p1_prev = { .pid = 100, .starttime = 1000, .utime = 100, .stime = 50, .rss_bytes = 8000, .comm = "alpha" };
    ProcessInfo p2_prev = { .pid = 200, .starttime = 2000, .utime = 900, .stime = 100, .rss_bytes = 2000, .comm = "old_proc" };
    assert(proclist_push(&prev, &p1_prev) == 0);
    assert(proclist_push(&prev, &p2_prev) == 0);

    ProcessInfo p1_curr = { .pid = 100, .starttime = 1000, .utime = 140, .stime = 60, .rss_bytes = 8000, .comm = "alpha" };
    ProcessInfo p2_curr = { .pid = 200, .starttime = 3000, .utime = 10,  .stime = 5,  .rss_bytes = 9000, .comm = "new_proc" };
    assert(proclist_push(&curr, &p1_curr) == 0);
    assert(proclist_push(&curr, &p2_curr) == 0);

    procs_compute_cpu_deltas(&curr, &prev, 400, 4);
    assert(fabs(curr.items[0].cpu_pct - 50.0) < 1e-6);
    assert(fabs(curr.items[1].cpu_pct - 0.0) < 1e-6);

    proclist_sort(&curr, COL_MEM, 1);
    assert(curr.items[0].pid == 200);
    assert(proclist_find_followed(&curr, 100, 1000) == 1);

    proclist_sort(&curr, COL_CPU, 1);
    assert(curr.items[0].pid == 100);
    assert(proclist_find_followed(&curr, 100, 1000) == 0);

    assert(proc_kill(1, 0) == -1);
    assert(proc_kill(0, 0) == -1);
    assert(proc_kill(-1, 1) == -1);

    proclist_free(&prev);
    proclist_free(&curr);
}

/* A heap line that is not NUL-terminated, exactly like the buffer a short read
 * of /proc/<pid>/stat hands to the parser. ASan has no slack past the last
 * byte, so any read beyond line[len] shows up as a heap-buffer-overflow. */
static char *heap_line(const char *text, size_t *len_out) {
    size_t n = strlen(text);
    char *line = malloc(n);
    assert(line != NULL);
    memcpy(line, text, n);
    *len_out = n;
    return line;
}

static void test_procs_stat_truncated(void) {
    ProcessInfo p;
    size_t n = 0;

    /* Read stopped right after ") ": the state character never made it into
     * the buffer. */
    char *line = heap_line("123 (comm) ", &n);
    assert(parse_proc_pid_stat(line, n, &p, 4096, 100) == -1);
    free(line);

    /* Read stopped in the middle of comm: no closing parenthesis at all. */
    line = heap_line("77 (half-na", &n);
    assert(parse_proc_pid_stat(line, n, &p, 4096, 100) == -1);
    free(line);

    /* State byte present but the space before the first field is missing. */
    line = heap_line("9 (x) R", &n);
    assert(parse_proc_pid_stat(line, n, &p, 4096, 100) == -1);
    free(line);

    /* Read stopped in the middle of the numeric fields. */
    line = heap_line("9 (x) R 0 1", &n);
    assert(parse_proc_pid_stat(line, n, &p, 4096, 100) == -1);
    free(line);

    /* The empty comm is still a complete line. */
    const char *empty_comm =
        "9 () R 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20";
    assert(parse_proc_pid_stat(empty_comm, strlen(empty_comm), &p, 4096, 100) == 0);
    assert(p.comm[0] == '\0');
    assert(p.state == 'R');

    /* The same truncations carried in a terminated string are rejected too. */
    assert(parse_proc_pid_stat("123 (comm) ", 11, &p, 4096, 100) == -1);
    assert(parse_proc_pid_stat("77 (half-na", 11, &p, 4096, 100) == -1);
}

static const ProcessInfo *find_pid(const ProcList *list, pid_t pid) {
    for (size_t i = 0; i < list->count; ++i) {
        if (list->items[i].pid == pid) {
            return &list->items[i];
        }
    }
    return NULL;
}

/* Child half of the exe-link test: hide /proc/<pid>/exe from the same uid the
 * way another user's process does, then park until the parent kills us. */
static void hidden_exe_child(int ready_fd) {
    if (prctl(PR_SET_DUMPABLE, 0) != 0) {
        _exit(1);
    }
    char ok = 'k';
    if (write(ready_fd, &ok, 1) != 1) {
        _exit(1);
    }
    for (;;) {
        pause();
    }
}

static void test_procs_exe_link_and_perms(void) {
    ProcList live;
    ProcSummary sum;
    assert(proclist_init(&live, 128) == 0);

    /* A normal process shows the mode bits of its binary, not the dashes. */
    char self[PATH_MAX];
    ssize_t self_len = readlink("/proc/self/exe", self, sizeof(self) - 1);
    assert(self_len > 0);
    self[self_len] = '\0';
    struct stat self_st;
    assert(stat(self, &self_st) == 0);
    assert((self_st.st_mode & 0777) != 0);
    char expect[11];
    format_mode_rwx(self_st.st_mode, expect);
    assert(strcmp(expect, "----------") != 0);

    assert(procs_collect(&live, NULL, 0, &sum) == 0);
    const ProcessInfo *me = find_pid(&live, getpid());
    assert(me != NULL);
    assert(strcmp(me->perms, expect) == 0);
    assert(me->exe_from_argv == 0);

    /* A process with no readable exe link: no mode bits, and the executable
     * name still comes from argv[0]. PR_SET_DUMPABLE=0 makes the exe symlink
     * unreadable for the same uid while cmdline stays world-readable, which is
     * exactly the shape of another user's process. */
    int ready[2];
    assert(pipe(ready) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(ready[0]);
        if (dup2(ready[1], 3) != 3) {
            _exit(1);
        }
        close(ready[1]);
        char *args[] = { self, "--hidden-exe-child", NULL };
        execv(self, args);
        _exit(1);
    }
    close(ready[1]);
    char ack = 0;
    assert(read(ready[0], &ack, 1) == 1);
    assert(ack == 'k');

    char proc_link[64];
    snprintf(proc_link, sizeof(proc_link), "/proc/%d/exe", (int)child);
    char probe[PATH_MAX];
    assert(readlink(proc_link, probe, sizeof(probe) - 1) == -1);

    assert(procs_collect(&live, NULL, 0, &sum) == 0);
    const ProcessInfo *hidden = find_pid(&live, child);
    assert(hidden != NULL);
    assert(strcmp(hidden->perms, "----------") == 0);
    assert(hidden->exe_from_argv == 1);
    assert(strcmp(hidden->exe_path, self) == 0);

    assert(kill(child, SIGKILL) == 0);
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    close(ready[0]);
    proclist_free(&live);
}

static void test_sort_flags_by_risk(void) {
    ProcList l = {0};
    assert(proclist_init(&l, 4) == 0);

    ProcessInfo scored_low = { .pid = 10, .risk = 2 };
    ProcessInfo scored_high = { .pid = 11, .risk = 7 };
    ProcessInfo unscored = { .pid = 12, .risk = -1 };
    ProcessInfo trusted = { .pid = 13, .risk = -1, .trusted = 1 };
    assert(proclist_push(&l, &scored_low) == 0);
    assert(proclist_push(&l, &scored_high) == 0);
    assert(proclist_push(&l, &unscored) == 0);
    assert(proclist_push(&l, &trusted) == 0);

    /* Modes 2 and 3 show the level, so the column must order by it: the most
     * dangerous process first, then lower levels, then the unscored, then the
     * rows the trust pass cleared. */
    proclist_set_flags_sort(1);
    proclist_sort(&l, COL_FLAGS, 1);
    assert(l.items[0].pid == 11);
    assert(l.items[1].pid == 10);
    assert(l.items[2].pid == 12);
    assert(l.items[3].pid == 13);

    proclist_sort(&l, COL_FLAGS, 0);
    assert(l.items[0].pid == 13);
    assert(l.items[3].pid == 11);

    /* Mode 1 keeps ordering by the local rule bits, where all four are equal. */
    proclist_set_flags_sort(0);
    proclist_sort(&l, COL_FLAGS, 1);
    assert(l.items[0].pid == 10);
    assert(l.items[3].pid == 13);

    proclist_free(&l);
}

static void test_navigation_can_be_switched_off(void) {
    ProcList list = {0};
    assert(proclist_init(&list, 4) == 0);
    ProcessInfo a = { .pid = 10, .comm = "alpha" };
    ProcessInfo b = { .pid = 11, .comm = "beta" };
    assert(proclist_push(&list, &a) == 0);
    assert(proclist_push(&list, &b) == 0);

    TuiView view;
    tui_view_init(&view);
    Control c;
    control_init(&c);
    c.navigation = 0;
    view.sel_row = 0;

    /* With navigation off the table is a live view: nothing moves, nothing
     * sorts and nothing can be killed behind the user's back. */
    assert(control_key(&c, &view, 'j', &list, 10) == ACT_NONE);
    assert(view.sel_row == 0);
    assert(control_key(&c, &view, 'l', &list, 10) == ACT_NONE);
    assert(view.sel_col == COL_CPU);
    assert(control_key(&c, &view, 's', &list, 10) == ACT_NONE);
    assert(control_key(&c, &view, 'x', &list, 10) == ACT_NONE);
    assert(c.confirming == 0);
    assert(control_key(&c, &view, 'q', &list, 10) == ACT_QUIT);

    /* On by default, so an older config keeps its keys. */
    Control d;
    control_init(&d);
    assert(d.navigation == 1);
    assert(control_key(&d, &view, 'j', &list, 10) == ACT_REDRAW);
    assert(view.sel_row == 1);

    proclist_free(&list);
}

static void test_display_width(void) {
    assert(display_width("") == 0);
    assert(display_width(NULL) == 0);
    assert(display_width("minitop") == 7);
    assert(display_width("процес") == 6);
    assert(display_width("┌─┤ cpu ├─┐") == 11);
    assert(display_width("61°C") == 4);
    assert(display_width("a\xe2\x94") == 3);
    assert(display_width("\xff" "b") == 2);

    char buf[64];
    pad_to_width(buf, sizeof(buf), "ab", 5);
    assert(strcmp(buf, "ab   ") == 0);
    pad_to_width(buf, sizeof(buf), "кіт", 5);
    assert(strcmp(buf, "кіт  ") == 0);
    assert(display_width(buf) == 5);
    pad_to_width(buf, sizeof(buf), "abcdef", 4);
    assert(strcmp(buf, "abc…") == 0);
    pad_to_width(buf, sizeof(buf), "процес", 4);
    assert(strcmp(buf, "про…") == 0);
    assert(display_width(buf) == 4);
    pad_to_width(buf, sizeof(buf), "abcd", 4);
    assert(strcmp(buf, "abcd") == 0);
    pad_to_width(buf, sizeof(buf), NULL, 3);
    assert(strcmp(buf, "   ") == 0);
    pad_to_width(buf, sizeof(buf), "abc", 0);
    assert(strcmp(buf, "") == 0);

    truncate_to_width(buf, sizeof(buf), "─────", 3);
    assert(strcmp(buf, "──…") == 0);
    truncate_to_width(buf, sizeof(buf), "ab", 5);
    assert(strcmp(buf, "ab") == 0);

    truncate_to_width(buf, 6, "абвгд", 10);
    assert(strcmp(buf, "аб") == 0);
    truncate_to_width(buf, 8, "абвгд", 4);
    assert(strcmp(buf, "аб…") == 0);
    truncate_to_width(buf, 3, "abcdef", 4);
    assert(strcmp(buf, "") == 0);
    pad_to_width(buf, 4, "a", 10);
    assert(strcmp(buf, "a  ") == 0);

    char broken[4] = { 'a', '\xd0', '\0', '\0' };
    pad_to_width(buf, sizeof(buf), broken, 3);
    assert(strcmp(buf, "a\xd0 ") == 0);
}

static void fake_system(SystemInfo *sys, ProcSummary *sum, ProcList *list) {
    memset(sys, 0, sizeof(*sys));
    sys->uptime_sec = 3 * 86400 + 3600 + 125;
    sys->cpu_pct = 12.4;
    sys->temp_celsius = 61.0;
    sys->load.load1 = 0.42;
    sys->load.load5 = 1.10;
    sys->load.load15 = 0.98;
    sys->mem.mem_total_kib = 32400000;
    sys->mem.mem_used_kib = 15200000;
    sys->mem.mem_avail_kib = 17100000;
    sys->mem.mem_free_kib = 1930000;
    sys->mem.mem_cached_kib = 16800000;
    sys->mem.mem_buffers_kib = 420000;
    sys->mem.swap_total_kib = 8000000;
    sys->mem.swap_used_kib = 512000;
    sys->disks.count = 2;
    snprintf(sys->disks.items[0].device, 64, "/dev/nvme0n1p2");
    snprintf(sys->disks.items[0].mountpoint, 64, "/");
    sys->disks.items[0].total_bytes = 1021ULL << 30;
    sys->disks.items[0].used_bytes = 582ULL << 30;
    snprintf(sys->disks.items[1].device, 64, "/dev/sda1");
    snprintf(sys->disks.items[1].mountpoint, 64, "/home");
    sys->disks.items[1].total_bytes = 999ULL << 30;
    sys->disks.items[1].used_bytes = 120ULL << 30;

    memset(sum, 0, sizeof(*sum));
    sum->total_procs = 3;
    sum->total_threads = 40;
    sum->running_procs = 1;
    sum->sleeping_procs = 2;

    assert(proclist_init(list, 4) == 0);
    ProcessInfo p;
    memset(&p, 0, sizeof(p));
    p.pid = 1;
    p.state = 'S';
    p.cpu_pct = 0.2;
    p.rss_bytes = 18ULL << 20;
    snprintf(p.comm, sizeof(p.comm), "systemd");
    snprintf(p.user, sizeof(p.user), "root");
    snprintf(p.time_plus, sizeof(p.time_plus), "0:00.00");
    snprintf(p.perms, sizeof(p.perms), "-rwxr-xr-x");
    assert(proclist_push(list, &p) == 0);
    p.pid = 4102;
    snprintf(p.comm, sizeof(p.comm), "процес");
    snprintf(p.user, sizeof(p.user), "користувач-тест");
    assert(proclist_push(list, &p) == 0);
    p.pid = 8891;
    p.state = 'R';
    p.cpu_pct = 96.0;
    p.flags = FLAG_DEL | FLAG_TMP | FLAG_MEMFD;
    snprintf(p.comm, sizeof(p.comm), ".x11-sync");
    assert(proclist_push(list, &p) == 0);
}

static void strip_ansi(const char *src, size_t n, char *dst) {
    size_t di = 0;
    for (size_t i = 0; i < n; ++i) {
        if (src[i] == '\x1b' && i + 1 < n && src[i + 1] == '[') {
            i += 2;
            while (i < n && !(src[i] >= '@' && src[i] <= '~')) {
                i++;
            }
            continue;
        }
        dst[di++] = src[i];
    }
    dst[di] = '\0';
}

static void check_frame(const TuiBuf *buf, int width, int height) {
    const char *body = buf->data;
    assert(strncmp(body, "\x1b[H", 3) == 0);
    assert(strstr(body + 3, "\x1b[H") == NULL);
    assert(strstr(body, "\x1b[2J") == NULL);
    int lines = 0;
    const char *line = body;
    for (;;) {
        const char *nl = strstr(line, "\r\n");
        size_t n = nl ? (size_t)(nl - line) : strlen(line);
        char *plain = malloc(n + 1);
        assert(plain != NULL);
        strip_ansi(line, n, plain);
        assert(display_width(plain) == (size_t)width);
        free(plain);
        lines++;
        if (nl == NULL) {
            break;
        }
        line = nl + 2;
    }
    assert(lines == height);
}

static void test_tui_render(void) {
    SystemInfo sys;
    ProcSummary sum;
    ProcList list;
    fake_system(&sys, &sum, &list);

    TuiView view;
    tui_view_init(&view);
    TuiBuf buf = {0};

    const int sizes[][2] = { {160, 40}, {120, 30}, {100, 24}, {80, 24}, {60, 18}, {64, 16}, {40, 10}, {200, 60} };
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
        assert(tui_render(&buf, sizes[i][0], sizes[i][1], &sys, NULL, &sum, &list, &view) == 0);
        check_frame(&buf, sizes[i][0], sizes[i][1]);
    }

    assert(tui_render(&buf, 120, 30, &sys, NULL, &sum, &list, &view) == 0);
    char *plain = malloc(buf.len + 1);
    assert(plain != NULL);
    strip_ansi(buf.data, buf.len, plain);
    assert(strstr(plain, "DEL,TMP,MEMFD") != NULL);
    assert(strstr(plain, "процес") != NULL);
    assert(strstr(plain, "61\xc2\xb0" "C") != NULL);
    assert(strstr(plain, "CPU%\xe2\x86\x93") != NULL);
    free(plain);

    sys.temp_celsius = -1.0;
    sys.disks.count = 0;
    view.sel_row = 2;
    view.sort_desc = 0;
    view.sel_col = COL_PID;
    view.status = "kill 8891 .x11-sync? y/n";
    assert(tui_render(&buf, 120, 30, &sys, NULL, &sum, &list, &view) == 0);
    check_frame(&buf, 120, 30);

    tui_buf_free(&buf);
    proclist_free(&list);
}

static char *plain_frame(const TuiBuf *buf) {
    char *plain = malloc(buf->len + 1);
    assert(plain != NULL);
    strip_ansi(buf->data, buf->len, plain);
    return plain;
}

static size_t find_at(const char *hay, const char *needle) {
    const char *p = strstr(hay, needle);
    assert(p != NULL);
    return (size_t)(p - hay);
}

static const char *plain_line(const char *plain, int index) {
    const char *p = plain;
    for (int i = 0; i < index; ++i) {
        const char *nl = strstr(p, "\r\n");
        assert(nl != NULL);
        p = nl + 2;
    }
    return p;
}

static void fake_gpu(GpuInfo *gpu, int util_pct, unsigned clock_mhz) {
    memset(gpu, 0, sizeof(*gpu));
    gpu->present = 1;
    gpu->util_pct = util_pct;
    gpu->mem_used_bytes = 3ULL << 30;
    gpu->mem_total_bytes = 8ULL << 30;
    gpu->clock_mhz = clock_mhz;
    snprintf(gpu->vendor, sizeof(gpu->vendor), "NVIDIA");
}

static void test_tui_hidden_column(void) {
    SystemInfo sys;
    ProcSummary sum;
    ProcList list;
    fake_system(&sys, &sum, &list);

    TuiView view;
    tui_view_init(&view);
    TuiBuf buf = {0};

    assert(tui_render(&buf, 120, 30, &sys, NULL, &sum, &list, &view) == 0);
    char *base = plain_frame(&buf);
    size_t state_at = find_at(base, "STATE");
    size_t cpu_at = find_at(base, "CPU%");
    assert(find_at(base, "USER") > 0);

    view.col_visible[COL_USER] = 0;
    assert(tui_render(&buf, 120, 30, &sys, NULL, &sum, &list, &view) == 0);
    check_frame(&buf, 120, 30);
    char *hidden = plain_frame(&buf);
    assert(strstr(hidden, "USER") == NULL);
    /* columns after COMMAND keep their place: it absorbs the freed space */
    assert(find_at(hidden, "STATE") == state_at);
    assert(find_at(hidden, "CPU%") == cpu_at);
    free(base);
    free(hidden);

    /* the flex column itself hidden: no title, no cell, still a full frame */
    tui_view_init(&view);
    view.col_visible[COL_COMMAND] = 0;
    assert(tui_render(&buf, 120, 30, &sys, NULL, &sum, &list, &view) == 0);
    check_frame(&buf, 120, 30);
    char *no_cmd = plain_frame(&buf);
    assert(strstr(no_cmd, "COMMAND") == NULL);
    free(no_cmd);

    /* a hidden sort column and a hidden selection draw no arrow and no crash */
    tui_view_init(&view);
    view.col_visible[COL_USER] = 0;
    view.sort_col = COL_USER;
    view.sel_col = COL_USER;
    assert(tui_render(&buf, 120, 30, &sys, NULL, &sum, &list, &view) == 0);
    check_frame(&buf, 120, 30);
    char *no_arrow = plain_frame(&buf);
    assert(strstr(no_arrow, "\xe2\x86\x91") == NULL);
    assert(strstr(no_arrow, "\xe2\x86\x93") == NULL);
    free(no_arrow);

    /* every column hidden: the table degenerates to blank rows */
    tui_view_init(&view);
    for (int i = 0; i < COL_COUNT; ++i) {
        view.col_visible[i] = 0;
    }
    assert(tui_render(&buf, 120, 30, &sys, NULL, &sum, &list, &view) == 0);
    check_frame(&buf, 120, 30);

    tui_buf_free(&buf);
    proclist_free(&list);
}

static void test_tui_row_highlight_toggle(void) {
    SystemInfo sys;
    ProcSummary sum;
    ProcList list;
    fake_system(&sys, &sum, &list);

    TuiView view;
    tui_view_init(&view);
    view.sel_row = 1;
    view.sel_col = COL_CPU;
    TuiBuf buf = {0};

    assert(tui_render(&buf, 120, 30, &sys, NULL, &sum, &list, &view) == 0);
    assert(strstr(buf.data, "\x1b[48;2;40;56;18m") != NULL);  /* row background */
    assert(strstr(buf.data, "\x1b[48;2;88;126;12m") != NULL); /* selected cell */
    assert(strstr(buf.data, "\x1b[48;2;118;185;0m") != NULL); /* header highlight */

    view.highlight_row = 0;
    assert(tui_render(&buf, 120, 30, &sys, NULL, &sum, &list, &view) == 0);
    check_frame(&buf, 120, 30);
    assert(strstr(buf.data, "\x1b[48;2;40;56;18m") == NULL);
    assert(strstr(buf.data, "\x1b[48;2;88;126;12m") == NULL);
    /* the selected column still owns its header cell */
    assert(strstr(buf.data, "\x1b[48;2;118;185;0m") != NULL);

    tui_buf_free(&buf);
    proclist_free(&list);
}

static void test_tui_gpu_row(void) {
    SystemInfo sys;
    ProcSummary sum;
    ProcList list;
    fake_system(&sys, &sum, &list);

    TuiView view;
    tui_view_init(&view);
    view.show_portrait = 0; /* the widths below assume the three-panel header */
    TuiBuf buf = {0};
    GpuInfo gpu;
    fake_gpu(&gpu, 37, 350);

    assert(tui_render(&buf, 160, 40, &sys, &gpu, &sum, &list, &view) == 0);
    check_frame(&buf, 160, 40);
    char *plain = plain_frame(&buf);
    const char *gpu_line = plain_line(plain, 4); /* third panel row */
    assert(strstr(gpu_line, "gpu") != NULL);
    assert(strstr(gpu_line, "37%") != NULL);
    assert(strstr(gpu_line, "3.0G/8.0G") != NULL);
    assert(strstr(gpu_line, "350MHz") != NULL);
    free(plain);

    /* the clock always carries its unit: 999 stays in MHz, 1000 switches */
    fake_gpu(&gpu, 5, 999);
    assert(tui_render(&buf, 160, 40, &sys, &gpu, &sum, &list, &view) == 0);
    plain = plain_frame(&buf);
    gpu_line = plain_line(plain, 4);
    assert(strstr(gpu_line, "999MHz") != NULL);
    free(plain);
    fake_gpu(&gpu, 5, 1000);
    assert(tui_render(&buf, 160, 40, &sys, &gpu, &sum, &list, &view) == 0);
    check_frame(&buf, 160, 40);
    plain = plain_frame(&buf);
    gpu_line = plain_line(plain, 4);
    assert(strstr(gpu_line, "1.00GHz") != NULL);
    free(plain);

    /* 120x32, 26 inner columns: "gpu 24% 2.7G/8.0G 345MHz" is 24 cells */
    fake_gpu(&gpu, 24, 345);
    gpu.mem_used_bytes = 2899102924ULL; /* 2.7G */
    assert(tui_render(&buf, 120, 32, &sys, &gpu, &sum, &list, &view) == 0);
    check_frame(&buf, 120, 32);
    plain = plain_frame(&buf);
    gpu_line = plain_line(plain, 4);
    assert(strstr(gpu_line, "24%") != NULL);
    assert(strstr(gpu_line, "2.7G/8.0G 345MHz") != NULL);
    free(plain);
    fake_gpu(&gpu, 37, 350);

    /* 30 inner columns: no bar, every value still fits */
    assert(tui_render(&buf, 106, 24, &sys, &gpu, &sum, &list, &view) == 0);
    check_frame(&buf, 106, 24);
    plain = plain_frame(&buf);
    gpu_line = plain_line(plain, 4);
    assert(strstr(gpu_line, "37%") != NULL);
    assert(strstr(gpu_line, "3.0G/8.0G 350MHz") != NULL);
    free(plain);

    /* 28 inner columns: still no room for a 6-cell bar and a 6-cell clock,
     * the row stays text without sacrificing the percent, VRAM or the clock */
    fake_gpu(&gpu, 0, 350);
    assert(tui_render(&buf, 124, 24, &sys, &gpu, &sum, &list, &view) == 0);
    check_frame(&buf, 124, 24);
    plain = plain_frame(&buf);
    gpu_line = plain_line(plain, 4);
    assert(strstr(gpu_line, "0%") != NULL);
    assert(strstr(gpu_line, "3.0G/8.0G 350MHz") != NULL);
    free(plain);
    fake_gpu(&gpu, 37, 350);

    /* 29 inner columns: still the full text, no bar */
    assert(tui_render(&buf, 103, 24, &sys, &gpu, &sum, &list, &view) == 0);
    check_frame(&buf, 103, 24);
    plain = plain_frame(&buf);
    gpu_line = plain_line(plain, 4);
    assert(strstr(gpu_line, "37%") != NULL);
    assert(strstr(gpu_line, "3.0G/8.0G 350MHz") != NULL);
    free(plain);

    /* 23 inner columns: the VRAM total goes first, the clock stays because
     * the owner needs utilisation, VRAM and frequency on screen together */
    assert(tui_render(&buf, 84, 24, &sys, &gpu, &sum, &list, &view) == 0);
    check_frame(&buf, 84, 24);
    plain = plain_frame(&buf);
    gpu_line = plain_line(plain, 4);
    assert(strstr(gpu_line, "37%") != NULL);
    assert(strstr(gpu_line, "3.0G 350MHz") != NULL);
    assert(strstr(gpu_line, "3.0G/8.0G") == NULL);
    free(plain);

    /* 21 inner columns: same, still with the clock */
    assert(tui_render(&buf, 80, 24, &sys, &gpu, &sum, &list, &view) == 0);
    check_frame(&buf, 80, 24);
    plain = plain_frame(&buf);
    gpu_line = plain_line(plain, 4);
    assert(strstr(gpu_line, "37%") != NULL);
    assert(strstr(gpu_line, "3.0G 350MHz") != NULL);
    free(plain);

    /* 16 inner columns: only now does the clock go, never the percent */
    assert(tui_render(&buf, 64, 24, &sys, &gpu, &sum, &list, &view) == 0);
    check_frame(&buf, 64, 24);
    plain = plain_frame(&buf);
    gpu_line = plain_line(plain, 4);
    assert(strstr(gpu_line, "37%") != NULL);
    assert(strstr(gpu_line, "3.0G") != NULL);
    assert(strstr(gpu_line, "3.0G/8.0G") == NULL);
    assert(strstr(gpu_line, "350MHz") == NULL);
    free(plain);

    /* clock-only source: util_pct < 0 */
    fake_gpu(&gpu, -1, 350);
    snprintf(gpu.vendor, sizeof(gpu.vendor), "Intel");
    assert(tui_render(&buf, 160, 40, &sys, &gpu, &sum, &list, &view) == 0);
    check_frame(&buf, 160, 40);
    plain = plain_frame(&buf);
    gpu_line = plain_line(plain, 4);
    assert(strstr(gpu_line, "gpu") != NULL);
    assert(strstr(gpu_line, "\xe2\x80\x94") != NULL);
    assert(strstr(gpu_line, "350MHz") != NULL);
    assert(strstr(gpu_line, "37%") == NULL);
    free(plain);

    tui_buf_free(&buf);
    proclist_free(&list);
}

static void test_tui_layout_and_first_frame(void) {
    SystemInfo sys;
    ProcSummary sum;
    ProcList list;
    fake_system(&sys, &sum, &list);

    TuiView view;
    tui_view_init(&view);
    TuiBuf buf = {0};

    assert(tui_render(&buf, 120, 30, &sys, NULL, &sum, &list, &view) == 0);
    check_frame(&buf, 120, 30);
    char *plain = plain_frame(&buf);

    /* header boxes are separated by a blank column, at the top rule and at
     * the side rules */
    const char *top = plain_line(plain, 0);
    assert(strstr(top, "\xe2\x94\x90 \xe2\x94\x8c") != NULL);
    assert(strstr(top, "\xe2\x94\x90\xe2\x94\x8c") == NULL);
    const char *sides = plain_line(plain, 1);
    assert(strstr(sides, "\xe2\x94\x82 \xe2\x94\x82") != NULL);
    assert(strstr(sides, "\xe2\x94\x82\xe2\x94\x82") == NULL);

    /* and one blank row between the header block and the proc box */
    const char *gap = plain_line(plain, 11);
    for (int i = 0; i < 120; ++i) {
        assert(gap[i] == ' ');
    }
    free(plain);

    /* no CPU delta yet: an em dash replaces the percentage on the first frame */
    sys.cpu_pct = -1.0;
    assert(tui_render(&buf, 120, 30, &sys, NULL, &sum, &list, &view) == 0);
    check_frame(&buf, 120, 30);
    plain = plain_frame(&buf);
    const char *cpu_line = plain_line(plain, 1);
    assert(strstr(cpu_line, "\xe2\x80\x94 \xe2\x94\x82") != NULL);
    assert(strstr(cpu_line, "0.0%") == NULL);
    free(plain);

    tui_buf_free(&buf);
    proclist_free(&list);
}

static void test_tui_gpu_absent(void) {
    SystemInfo sys;
    ProcSummary sum;
    ProcList list;
    fake_system(&sys, &sum, &list);

    TuiView view;
    tui_view_init(&view);
    TuiBuf absent = {0};
    TuiBuf zeroed = {0};

    assert(tui_render(&absent, 160, 40, &sys, NULL, &sum, &list, &view) == 0);
    char *plain = plain_frame(&absent);
    assert(strstr(plain, "gpu") == NULL);
    const char *cpu_procs_line = plain_line(plain, 5); /* fourth panel row */
    assert(strstr(cpu_procs_line, "procs") != NULL);
    assert(strstr(cpu_procs_line, "threads") != NULL);
    free(plain);

    GpuInfo gpu;
    memset(&gpu, 0, sizeof(gpu));
    assert(tui_render(&zeroed, 160, 40, &sys, &gpu, &sum, &list, &view) == 0);
    check_frame(&zeroed, 160, 40);
    /* present == 0 must be pixel-identical to no GPU at all */
    assert(absent.len == zeroed.len);
    assert(memcmp(absent.data, zeroed.data, absent.len) == 0);

    tui_buf_free(&absent);
    tui_buf_free(&zeroed);
    proclist_free(&list);
}

static void add_disk(SystemInfo *sys, const char *dev, const char *mnt,
                     uint64_t total_gib, uint64_t used_gib) {
    assert(sys->disks.count < MAX_DISKS);
    DiskInfo *d = &sys->disks.items[sys->disks.count++];
    memset(d, 0, sizeof(*d));
    snprintf(d->device, sizeof(d->device), "%s", dev);
    snprintf(d->mountpoint, sizeof(d->mountpoint), "%s", mnt);
    snprintf(d->fstype, sizeof(d->fstype), "%s", "btrfs");
    d->total_bytes = total_gib << 30;
    d->used_bytes = used_gib << 30;
    d->avail_bytes = (total_gib - used_gib) << 30;
}

static void test_tui_disk_tree(void) {
    SystemInfo sys;
    ProcSummary sum;
    ProcList list;
    fake_system(&sys, &sum, &list);

    TuiView view;
    tui_view_init(&view);
    TuiBuf buf = {0};

    /* one disk carrying two mounted filesystems, then a second disk:
     * nvme0n1 [/ , /var], sda [/home] - five tree entries in six rows */
    sys.disks.count = 0;
    add_disk(&sys, "/dev/nvme0n1p2", "/", 1021, 582);
    add_disk(&sys, "/dev/sda1", "/home", 999, 120);
    add_disk(&sys, "/dev/nvme0n1p3", "/var", 1021, 300);

    assert(tui_render(&buf, 160, 40, &sys, NULL, &sum, &list, &view) == 0);
    check_frame(&buf, 160, 40);
    char *plain = plain_frame(&buf);
    assert(strstr(plain_line(plain, 0), "2 disks") != NULL);
    const char *l1 = plain_line(plain, 1);
    const char *l2 = plain_line(plain, 2);
    const char *l3 = plain_line(plain, 3);
    const char *l4 = plain_line(plain, 4);
    const char *l5 = plain_line(plain, 5);
    /* the parent carries the aggregated fill: (582+300)/(1021+1021) = 43% */
    assert(strstr(l1, "nvme0n1") != NULL);
    assert(strstr(l1, "43% \xe2\x94\x82") != NULL);
    /* children in list order, each with its own numbers, never with 43% */
    assert(strstr(l2, "\xe2\x94\x82   /") != NULL);
    assert(strstr(l2, "582G/1021G 57% \xe2\x94\x82") != NULL);
    assert(strstr(l2, "43%") == NULL);
    assert(strstr(l3, "\xe2\x94\x82   /var") != NULL);
    assert(strstr(l3, "300G/1021G 29% \xe2\x94\x82") != NULL);
    assert(strstr(l3, "43%") == NULL);
    assert(strstr(l4, "sda") != NULL);
    assert(strstr(l4, "12% \xe2\x94\x82") != NULL);
    assert(strstr(l5, "\xe2\x94\x82   /home") != NULL);
    assert(strstr(l5, "120G/999G 12% \xe2\x94\x82") != NULL);
    /* the parent is emphasised, the children are not */
    assert(strstr(buf.data, "\x1b[38;2;226;229;240m\x1b[1mnvme0n1") != NULL);
    assert(strstr(buf.data, "\x1b[38;2;150;156;178m/") != NULL);
    free(plain);

    /* the same tree at 80x24: 23 inner columns keep indent, name, pair, percent */
    assert(tui_render(&buf, 80, 24, &sys, NULL, &sum, &list, &view) == 0);
    check_frame(&buf, 80, 24);
    plain = plain_frame(&buf);
    assert(strstr(plain, "582G/1021G 57%") != NULL);
    assert(strstr(plain, "\xe2\x80\xa6 +") == NULL);
    free(plain);

    /* one disk with nine mounts is ten entries in nine rows: the last row
     * counts what did not fit instead of drawing past the box */
    sys.disks.count = 0;
    add_disk(&sys, "/dev/nvme0n1p2", "/", 1021, 582);
    add_disk(&sys, "/dev/nvme0n1p3", "/home", 1021, 300);
    add_disk(&sys, "/dev/nvme0n1p4", "/var", 1021, 50);
    add_disk(&sys, "/dev/nvme0n1p5", "/srv", 1021, 20);
    add_disk(&sys, "/dev/nvme0n1p6", "/opt", 1021, 10);
    add_disk(&sys, "/dev/nvme0n1p7", "/mnt", 1021, 5);
    add_disk(&sys, "/dev/nvme0n1p8", "/mnt2", 1021, 4);
    add_disk(&sys, "/dev/nvme0n1p9", "/mnt3", 1021, 3);
    add_disk(&sys, "/dev/nvme0n1p10", "/mnt4", 1021, 2);

    assert(tui_render(&buf, 120, 32, &sys, NULL, &sum, &list, &view) == 0);
    check_frame(&buf, 120, 32);
    plain = plain_frame(&buf);
    assert(strstr(plain_line(plain, 9), "\xe2\x80\xa6 +") != NULL);
    assert(strstr(plain, "/mnt4") == NULL);
    free(plain);

    assert(tui_render(&buf, 80, 24, &sys, NULL, &sum, &list, &view) == 0);
    check_frame(&buf, 80, 24);
    plain = plain_frame(&buf);
    assert(strstr(plain, "\xe2\x80\xa6 +") != NULL);
    free(plain);

    /* an empty disk list still says so */
    sys.disks.count = 0;
    assert(tui_render(&buf, 120, 32, &sys, NULL, &sum, &list, &view) == 0);
    check_frame(&buf, 120, 32);
    plain = plain_frame(&buf);
    assert(strstr(plain, "no mounted disks") != NULL);
    free(plain);

    tui_buf_free(&buf);
    proclist_free(&list);
}

/* ---- ceo portrait: red glasses on a malicious FLAGS row ---- */

#define RIM_ALERT_FG "\x1b[38;2;200;28;32m"
#define RIM_ALERT_BG "\x1b[48;2;200;28;32m"
#define RIM_DARK_FG  "\x1b[38;2;24;24;26m"
#define RIM_DARK_BG  "\x1b[48;2;24;24;26m"
#define RIM_JAW      "\x1b[38;2;70;62;58m"
#define FLAGS_RED_BG "\x1b[48;2;70;18;22m"
#define FLAGS_ATTN   "\x1b[38;2;242;168;58m"

static void assert_calm_portrait(const TuiBuf *buf) {
    assert(strstr(buf->data, RIM_DARK_FG) != NULL);
    assert(strstr(buf->data, RIM_DARK_BG) != NULL);
    assert(strstr(buf->data, RIM_JAW) != NULL);
    assert(strstr(buf->data, RIM_ALERT_FG) == NULL);
    assert(strstr(buf->data, RIM_ALERT_BG) == NULL);
}

/* The red frames keep the same glyphs, so only the rim colours change: the
 * dark frame and the jaw colour have to disappear from the header. */
static void assert_red_glasses(const TuiBuf *buf) {
    assert(strstr(buf->data, RIM_ALERT_FG) != NULL);
    assert(strstr(buf->data, RIM_ALERT_BG) != NULL);
    assert(strstr(buf->data, RIM_DARK_FG) == NULL);
    assert(strstr(buf->data, RIM_DARK_BG) == NULL);
    assert(strstr(buf->data, RIM_JAW) == NULL);
}

/* Renders a 160-column frame whose portrait box is on, with one scored row
 * carrying the given verdict after `fillers` unscored rows. */
static void portrait_frame(TuiBuf *buf, int mode, int running, int risk,
                           int verdict, const char *reason, int fillers,
                           int height, size_t scroll) {
    SystemInfo sys;
    ProcSummary sum;
    ProcList list;
    fake_system(&sys, &sum, &list);
    for (int i = 0; i < fillers; ++i) {
        ProcessInfo f = { .pid = 9100 + i, .state = 'S', .risk = 0 };
        snprintf(f.comm, sizeof(f.comm), "filler%d", i);
        snprintf(f.user, sizeof(f.user), "root");
        snprintf(f.time_plus, sizeof(f.time_plus), "0:00.01");
        snprintf(f.perms, sizeof(f.perms), "-rw-r--r--");
        assert(proclist_push(&list, &f) == 0);
    }
    ProcessInfo p = { .pid = 9001, .state = 'S', .risk = risk, .llm_verdict = verdict };
    if (reason != NULL) {
        snprintf(p.llm_reason, sizeof(p.llm_reason), "%s", reason);
    }
    snprintf(p.comm, sizeof(p.comm), "payload");
    snprintf(p.user, sizeof(p.user), "root");
    snprintf(p.time_plus, sizeof(p.time_plus), "0:00.01");
    snprintf(p.perms, sizeof(p.perms), "-rwxr-xr-x");
    assert(proclist_push(&list, &p) == 0);

    TuiView view;
    tui_view_init(&view);
    view.show_portrait = 1;
    view.scroll = scroll;
    tui_model_set(1, 0, 5, mode);
    tui_llm_set(running);
    assert(tui_render(buf, 160, height, &sys, NULL, &sum, &list, &view) == 0);
    proclist_free(&list);
}

static uint64_t fnv1a64(const char *s, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; ++i) {
        h ^= (unsigned char)s[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* Bytes of the eleven header rows, the box that carries the portrait. */
static size_t header_bytes(const char *plain) {
    size_t n = 0;
    for (int line = 0; line < 11; ++line) {
        const char *nl = strstr(plain + n, "\r\n");
        if (nl == NULL) {
            return n;
        }
        n = (size_t)(nl - plain) + 2;
    }
    return n;
}

static uint64_t header_hash(const TuiBuf *buf) {
    return fnv1a64(buf->data, header_bytes(buf->data));
}

/* Captured from main (4b59b37) with exactly this input: the calm frame and
 * its portrait box must stay byte-identical, so any drift shows up here. */
#define CALM_HEADER_FNV 0x8b22fd271e978ec0ULL

static void test_portrait_calm_frame(void) {
    TuiBuf calm = {0};
    portrait_frame(&calm, 2, 1, 4, -1, NULL, 0, 40, 0);
    assert_calm_portrait(&calm);
    assert(header_hash(&calm) == CALM_HEADER_FNV);
    tui_buf_free(&calm);
}

static void test_portrait_red_glasses_mode2(void) {
    TuiBuf calm = {0};
    TuiBuf red = {0};
    portrait_frame(&calm, 2, 1, 4, -1, NULL, 0, 40, 0);
    portrait_frame(&red, 2, 1, 5, -1, NULL, 0, 40, 0);

    assert_calm_portrait(&calm);
    assert_red_glasses(&red);
    /* the model's threshold turns the row red in the table as well */
    assert(strstr(red.data, FLAGS_RED_BG) != NULL);

    /* same glyphs, same layout: the header, portrait included, is identical
     * once the colour escapes are stripped */
    char *plain_calm = plain_frame(&calm);
    char *plain_red = plain_frame(&red);
    size_t hc = header_bytes(plain_calm);
    assert(hc == header_bytes(plain_red));
    assert(memcmp(plain_calm, plain_red, hc) == 0);
    free(plain_calm);
    free(plain_red);

    tui_buf_free(&calm);
    tui_buf_free(&red);
}

static void test_portrait_waits_for_mode3_verdict(void) {
    TuiBuf pending = {0};
    TuiBuf cleared = {0};
    /* above the threshold but no LLM answer yet: the cell is dim, not red */
    portrait_frame(&pending, 3, 1, 9, -1, NULL, 0, 40, 0);
    assert_calm_portrait(&pending);
    assert(strstr(pending.data, FLAGS_RED_BG) == NULL);
    /* the engine answered "safe": the filter row stays blue */
    portrait_frame(&cleared, 3, 1, 9, 0, "signed system updater", 0, 40, 0);
    assert_calm_portrait(&cleared);
    assert(strstr(cleared.data, FLAGS_RED_BG) == NULL);
    /* the same rows below the fold change nothing either */
    portrait_frame(&pending, 3, 1, 9, -1, NULL, 10, 24, 0);
    assert_calm_portrait(&pending);
    portrait_frame(&cleared, 3, 1, 9, 0, "signed system updater", 10, 24, 0);
    assert_calm_portrait(&cleared);
    tui_buf_free(&pending);
    tui_buf_free(&cleared);
}

static void test_portrait_unreviewed_mode3_stays_calm(void) {
    TuiBuf buf = {0};
    /* at the threshold, LLM engine down: the FLAGS cell is the attention
     * colour, not red, so the glasses stay calm */
    portrait_frame(&buf, 3, 0, 9, -1, NULL, 0, 40, 0);
    assert_calm_portrait(&buf);
    assert(strstr(buf.data, FLAGS_ATTN) != NULL);
    assert(strstr(buf.data, FLAGS_RED_BG) == NULL);
    /* and the unreviewed row below the fold does not alert either */
    portrait_frame(&buf, 3, 0, 9, -1, NULL, 10, 24, 0);
    assert_calm_portrait(&buf);
    assert(strstr(buf.data, FLAGS_RED_BG) == NULL);
    tui_buf_free(&buf);
}

static void test_portrait_red_glasses_mode3_verdict(void) {
    TuiBuf buf = {0};
    /* risk above the threshold and the LLM says malicious, with a reason */
    portrait_frame(&buf, 3, 1, 9, 1, "writes /etc/ld.so.preload", 0, 40, 0);
    assert_red_glasses(&buf);
    assert(strstr(buf.data, FLAGS_RED_BG) != NULL);
    tui_buf_free(&buf);
}

static void test_portrait_never_in_mode1(void) {
    TuiBuf buf = {0};
    portrait_frame(&buf, 1, 1, 9, 1, "writes /etc/ld.so.preload", 0, 40, 0);
    assert_calm_portrait(&buf);
    assert(strstr(buf.data, FLAGS_RED_BG) == NULL);
    tui_buf_free(&buf);
}

static void test_portrait_off_screen_still_alerts(void) {
    TuiBuf buf = {0};
    /* ten unscored rows fill the 24-row table, so the malicious row at the
     * end is below the fold: its cell is never painted, yet the portrait is a
     * system indicator and must turn red anyway */
    portrait_frame(&buf, 2, 1, 9, -1, NULL, 10, 24, 0);
    assert_red_glasses(&buf);
    assert(strstr(buf.data, FLAGS_RED_BG) == NULL);
    tui_buf_free(&buf);
}

static void test_input_and_control(void) {
    int key;
    assert(input_parse("j", 1, &key) == 1 && key == 'j');
    assert(input_parse("\x1b", 1, &key) == 1 && key == KEY_ESC);
    assert(input_parse("\x1b[A", 3, &key) == 3 && key == KEY_UP);
    assert(input_parse("\x1b[B", 3, &key) == 3 && key == KEY_DOWN);
    assert(input_parse("\x1bOA", 3, &key) == 3 && key == KEY_UP);
    assert(input_parse("\x1b[5~", 4, &key) == 4 && key == KEY_PGUP);
    assert(input_parse("\x1b[6~x", 5, &key) == 4 && key == KEY_PGDN);
    assert(input_parse("\x1bq", 2, &key) == 1 && key == KEY_ESC);
    assert(input_parse("\x1b[1;5C", 6, &key) == 6);

    SystemInfo sys;
    ProcSummary sum;
    ProcList list;
    fake_system(&sys, &sum, &list);
    list.items[0].starttime = 10;
    list.items[1].starttime = 20;
    list.items[2].starttime = 30;

    TuiView view;
    tui_view_init(&view);
    Control c;
    control_init(&c);

    assert(view.sel_col == COL_CPU && view.sort_col == COL_CPU && view.sort_desc == 1);
    assert(control_key(&c, &view, 'h', &list, 10) == ACT_REDRAW);
    assert(view.sel_col == COL_STATE);
    for (int i = 0; i < 20; ++i) {
        control_key(&c, &view, 'h', &list, 10);
    }
    assert(view.sel_col == COL_PID);
    for (int i = 0; i < 20; ++i) {
        control_key(&c, &view, 'l', &list, 10);
    }
    assert(view.sel_col == COL_PERMS);

    view.sel_col = COL_PID;
    assert(control_key(&c, &view, 's', &list, 10) == ACT_RESORT);
    assert(view.sort_col == COL_PID && view.sort_desc == 1);
    proclist_sort(&list, view.sort_col, view.sort_desc);
    assert(list.items[0].pid == 8891 && list.items[2].pid == 1);
    assert(control_key(&c, &view, 's', &list, 10) == ACT_RESORT);
    assert(view.sort_desc == 0);
    proclist_sort(&list, view.sort_col, view.sort_desc);
    assert(list.items[0].pid == 1);
    view.sel_col = COL_MEM;
    assert(control_key(&c, &view, 's', &list, 10) == ACT_RESORT);
    assert(view.sort_col == COL_MEM && view.sort_desc == 1);

    /* j/k move the row and must not resort */
    proclist_sort(&list, view.sort_col, view.sort_desc);
    view.sel_row = -1;
    assert(control_key(&c, &view, 'j', &list, 10) == ACT_REDRAW);
    assert(view.sel_row == 0);
    assert(control_key(&c, &view, 'j', &list, 10) == ACT_REDRAW);
    assert(view.sel_row == 1);
    assert(control_key(&c, &view, 'k', &list, 10) == ACT_REDRAW);
    assert(view.sel_row == 0);
    view.sel_row = -1;

    assert(view.sel_row == -1);
    control_key(&c, &view, 'x', &list, 10);
    assert(!c.confirming);
    control_key(&c, &view, KEY_DOWN, &list, 10);
    control_key(&c, &view, KEY_DOWN, &list, 10);
    assert(view.sel_row == 1 && list.items[1].pid == 4102);

    assert(control_key(&c, &view, 'f', &list, 10) == ACT_REDRAW);
    assert(c.follow && view.follow_pid == 4102);
    view.sel_col = COL_PID;
    control_key(&c, &view, 's', &list, 10);
    proclist_sort(&list, view.sort_col, view.sort_desc);
    control_sync(&c, &view, &list, 10);
    assert(list.items[view.sel_row].pid == 4102);

    ProcessInfo extra = list.items[0];
    extra.pid = 9999;
    extra.starttime = 40;
    assert(proclist_push(&list, &extra) == 0);
    proclist_sort(&list, view.sort_col, view.sort_desc);
    control_sync(&c, &view, &list, 10);
    assert(list.items[view.sel_row].pid == 4102);

    assert(control_key(&c, &view, 'x', &list, 10) == ACT_REDRAW);
    assert(c.confirming && !c.kill_force && c.kill_pid == 4102);
    assert(view.status != NULL && strstr(view.status, "SIGTERM") != NULL);
    assert(control_key(&c, &view, KEY_ESC, &list, 10) == ACT_REDRAW);
    assert(!c.confirming);

    control_key(&c, &view, 'x', &list, 10);
    assert(control_key(&c, &view, 'y', &list, 10) == ACT_KILL);
    control_kill_result(&c, &view, 0, 0);
    assert(c.termed_pid == 4102);
    control_key(&c, &view, 'x', &list, 10);
    assert(c.confirming && c.kill_force);
    assert(strstr(view.status, "SIGKILL") != NULL);
    assert(control_key(&c, &view, 'n', &list, 10) == ACT_REDRAW);

    ssize_t idx = proclist_find_followed(&list, 4102, 20);
    assert(idx >= 0);
    list.items[idx] = list.items[list.count - 1];
    list.count--;
    control_sync(&c, &view, &list, 10);
    assert(!c.follow && view.sel_row == -1 && view.follow_pid == 0);

    control_key(&c, &view, KEY_DOWN, &list, 10);
    control_key(&c, &view, 'x', &list, 10);
    pid_t target = c.kill_pid;
    idx = proclist_find_followed(&list, target, c.kill_start);
    list.items[idx].starttime += 1;
    assert(control_key(&c, &view, 'y', &list, 10) == ACT_REDRAW);
    assert(strstr(view.status, "exited") != NULL);

    for (int i = 0; i < 5; ++i) {
        control_tick(&c, &view);
    }
    assert(view.status == NULL);

    /* h/l skip hidden columns, and a hidden selection falls back to its nearest neighbour */
    tui_view_init(&view);
    view.col_visible[COL_USER] = 0;
    view.col_visible[COL_STATE] = 0;
    view.sel_col = COL_PID;
    assert(control_key(&c, &view, 'l', &list, 10) == ACT_REDRAW);
    assert(view.sel_col == COL_COMMAND);
    assert(control_key(&c, &view, 'l', &list, 10) == ACT_REDRAW);
    assert(view.sel_col == COL_CPU);
    assert(control_key(&c, &view, 'h', &list, 10) == ACT_REDRAW);
    assert(view.sel_col == COL_COMMAND);
    assert(control_key(&c, &view, 'h', &list, 10) == ACT_REDRAW);
    assert(view.sel_col == COL_PID);
    assert(control_key(&c, &view, KEY_RIGHT, &list, 10) == ACT_REDRAW);
    assert(view.sel_col == COL_COMMAND);
    assert(control_key(&c, &view, KEY_LEFT, &list, 10) == ACT_REDRAW);
    assert(view.sel_col == COL_PID);
    view.sel_col = COL_USER;
    control_sync(&c, &view, &list, 10);
    assert(view.sel_col == COL_COMMAND);

    assert(control_key(&c, &view, 'q', &list, 10) == ACT_QUIT);
    assert(control_key(&c, &view, 'z', &list, 10) == ACT_NONE);
    proclist_free(&list);
}

static void test_disk_parent_names(void) {
    struct { const char *dev; const char *want; } cases[] = {
        { "/dev/nvme0n1p2", "nvme0n1" },
        { "nvme0n1p2", "nvme0n1" },
        { "/dev/nvme0n1p12", "nvme0n1" },
        { "/dev/nvme0n1", "nvme0n1" },
        { "/dev/sda1", "sda" },
        { "sda1", "sda" },
        { "sda", "sda" },
        { "/dev/sdb12", "sdb" },
        { "/dev/hdb2", "hdb" },
        { "/dev/vda3", "vda" },
        { "/dev/xvda4", "xvda" },
        { "/dev/mmcblk0p1", "mmcblk0" },
        { "mmcblk0p3", "mmcblk0" },
        { "/dev/mmcblk0", "mmcblk0" },
        { "/dev/dm-0", "dm-0" },
        { "dm-0", "dm-0" },
        { "/dev/mapper/omarchy_root", "mapper/omarchy_root" },
        { "/dev/nvme0n1p2p1", "nvme0n1p2" },
    };
    char buf[64];
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        disk_parent_name(cases[i].dev, buf, sizeof(buf));
        assert(strcmp(buf, cases[i].want) == 0);
    }

    /* truncation must not overflow, and a NULL device yields an empty name */
    char tiny[3];
    disk_parent_name("/dev/nvme0n1p2", tiny, sizeof(tiny));
    assert(strlen(tiny) == 2);
    disk_parent_name(NULL, buf, sizeof(buf));
    assert(buf[0] == '\0');
    buf[0] = 'x';
    disk_parent_name("/dev/sda1", NULL, sizeof(buf));
    disk_parent_name("/dev/sda1", buf, 0);
    assert(buf[0] == 'x');
    /* "/dev/" keeps the text rather than producing an empty parent name */
    disk_parent_name("/dev/", buf, sizeof(buf));
    assert(strcmp(buf, "/dev/") == 0);
}

static void test_disk_aggregate(void) {
    DiskList in;
    memset(&in, 0, sizeof(in));
    const char *devs[] = { "/dev/nvme0n1p2", "/dev/nvme0n1p2", "/dev/nvme0n1p2", "/dev/sda1" };
    const char *mnts[] = { "/var/log", "/home", "/", "/data" };
    const char *fss[] = { "btrfs", "btrfs", "btrfs", "ext4" };
    const uint64_t totals[] = { 50ULL << 20, 100ULL << 20, 1021ULL << 30, 999ULL << 30 };
    const uint64_t used[] = { 10ULL << 20, 40ULL << 20, 582ULL << 30, 120ULL << 30 };
    const uint64_t avail[] = { 40ULL << 20, 60ULL << 20, 439ULL << 30, 879ULL << 30 };
    in.count = 4;
    for (size_t i = 0; i < 4; ++i) {
        snprintf(in.items[i].device, sizeof(in.items[i].device), "%s", devs[i]);
        snprintf(in.items[i].mountpoint, sizeof(in.items[i].mountpoint), "%s", mnts[i]);
        snprintf(in.items[i].fstype, sizeof(in.items[i].fstype), "%s", fss[i]);
        in.items[i].total_bytes = totals[i];
        in.items[i].used_bytes = used[i];
        in.items[i].avail_bytes = avail[i];
    }

    DiskList out;
    assert(sysinfo_disks_aggregate(&in, &out) == 0);
    assert(out.count == 2);
    assert(strcmp(out.items[0].device, "nvme0n1") == 0);
    assert(strcmp(out.items[0].mountpoint, "/var/log") == 0); /* first mount of that device */
    assert(strcmp(out.items[0].fstype, "btrfs") == 0);
    assert(out.items[0].total_bytes == (1021ULL << 30));
    assert(out.items[0].used_bytes == (582ULL << 30));
    assert(out.items[0].avail_bytes == (439ULL << 30));
    assert(strcmp(out.items[1].device, "sda") == 0);
    assert(strcmp(out.items[1].mountpoint, "/data") == 0);
    assert(out.items[1].total_bytes == (999ULL << 30));
    assert(out.items[1].used_bytes == (120ULL << 30));
    assert(out.items[1].avail_bytes == (879ULL << 30));

    /* in-place aggregation is allowed */
    DiskList same = in;
    assert(sysinfo_disks_aggregate(&same, &same) == 0);
    assert(same.count == 2);
    assert(strcmp(same.items[0].device, "nvme0n1") == 0);
    assert(same.items[0].total_bytes == out.items[0].total_bytes);

    DiskList empty;
    memset(&empty, 0, sizeof(empty));
    assert(sysinfo_disks_aggregate(&empty, &out) == 0);
    assert(out.count == 0);
    assert(sysinfo_disks_aggregate(NULL, &out) == -1);
    assert(sysinfo_disks_aggregate(&in, NULL) == -1);

    /* one row per parent, capped at MAX_DISKS (the list itself holds MAX_DISKS rows) */
    DiskList many;
    memset(&many, 0, sizeof(many));
    for (size_t i = 0; i < MAX_DISKS; ++i) {
        DiskInfo *dk = &many.items[many.count++];
        snprintf(dk->device, sizeof(dk->device), "/dev/sd%c1", (char)('a' + i));
        snprintf(dk->mountpoint, sizeof(dk->mountpoint), "/mnt/%zu", i);
        snprintf(dk->fstype, sizeof(dk->fstype), "ext4");
        dk->total_bytes = 1000;
        dk->used_bytes = 100;
    }
    assert(sysinfo_disks_aggregate(&many, &out) == 0);
    assert(out.count == MAX_DISKS);
    assert(out.count <= MAX_DISKS);
    assert(strcmp(out.items[0].device, "sda") == 0);
    assert(strcmp(out.items[MAX_DISKS - 1].device, "sdp") == 0);
}

/* ------------------------------------------------- FLAGS column coverage -- */

static void one_process_frame(const ProcessInfo *p, int width, int mode, TuiBuf *buf) {
    SystemInfo sys;
    ProcSummary sum;
    ProcList list;
    memset(&sys, 0, sizeof(sys));
    sys.temp_celsius = -1.0;
    memset(&sum, 0, sizeof(sum));
    assert(proclist_init(&list, 2) == 0);
    assert(proclist_push(&list, p) == 0);

    TuiView view;
    tui_view_init(&view);
    tui_model_set(1, 0, 5, mode);

    memset(buf, 0, sizeof(*buf));
    assert(tui_render(buf, width, 30, &sys, NULL, &sum, &list, &view) == 0);
    proclist_free(&list);
}

static void fill_payload(ProcessInfo *p, uint8_t flags) {
    memset(p, 0, sizeof(*p));
    p->pid = 4242;
    p->state = 'S';
    p->cpu_pct = 1.2;
    p->rss_bytes = 12ULL << 20;
    p->flags = flags;
    p->risk = -1;
    snprintf(p->comm, sizeof(p->comm), "payload");
    snprintf(p->user, sizeof(p->user), "student");
    snprintf(p->time_plus, sizeof(p->time_plus), "0:01.25");
    snprintf(p->perms, sizeof(p->perms), "-rwxr-xr-x");
}

static void test_flags_column_shows_all_four(void) {
    ProcessInfo p;
    fill_payload(&p, FLAG_DEL | FLAG_TMP | FLAG_MEMFD | FLAG_NET);

    /* The tag text is the widest the column gets; it must survive every width
     * the TUI accepts, and the frame must stay exactly as wide as terminal. */
    const int widths[] = { 120, 80, 60 };
    for (size_t i = 0; i < sizeof(widths) / sizeof(widths[0]); ++i) {
        TuiBuf buf;
        one_process_frame(&p, widths[i], 1, &buf);
        check_frame(&buf, widths[i], 30);
        char *plain = plain_frame(&buf);
        assert(strstr(plain, "DEL,TMP,MEMFD,NET") != NULL);
        free(plain);
        tui_buf_free(&buf);
    }

    /* MEMFD and NET are independent bits, each with its own text */
    fill_payload(&p, FLAG_MEMFD);
    TuiBuf memfd;
    one_process_frame(&p, 120, 1, &memfd);
    char *plain = plain_frame(&memfd);
    assert(strstr(plain, "MEMFD") != NULL);
    assert(strstr(plain, "NET") == NULL);
    free(plain);
    tui_buf_free(&memfd);
}

static void test_flags_trusted_still_says_ok(void) {
    ProcessInfo p;
    fill_payload(&p, FLAG_NET);
    p.trusted = 1;
    p.risk = 2;

    /* A packaged daemon that listens is still trusted: NET alone is a fact
     * the model weighs, so mode 2 keeps the "ok" label. */
    TuiBuf buf;
    one_process_frame(&p, 120, 2, &buf);
    char *plain = plain_frame(&buf);
    assert(strstr(plain, "ok") != NULL);
    free(plain);
    tui_buf_free(&buf);

    /* A memfd image is not the packaged binary, so it loses "ok". */
    p.flags = FLAG_NET | FLAG_MEMFD;
    one_process_frame(&p, 120, 2, &buf);
    plain = plain_frame(&buf);
    assert(strstr(plain, "ok") == NULL);
    free(plain);
    tui_buf_free(&buf);

    tui_model_set(1, 0, 5, 1);
}

static void test_flags_net_live_listener(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    assert(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    assert(listen(fd, 1) == 0);

    enum { CAP = 8192 };
    static uint64_t inodes[CAP];
    size_t count = procs_collect_listen_inodes(inodes, CAP);
    assert(count > 0);
    assert(procs_has_listen_socket(getpid(), inodes, count) == FLAG_NET);

    /* the real pass marks this very test process */
    ProcList live;
    ProcSummary sum;
    assert(proclist_init(&live, 64) == 0);
    assert(procs_collect(&live, NULL, 0, &sum) == 0);
    const ProcessInfo *me = NULL;
    for (size_t i = 0; i < live.count; ++i) {
        if (live.items[i].pid == getpid()) {
            me = &live.items[i];
            break;
        }
    }
    assert(me != NULL);
    assert((me->flags & FLAG_NET) != 0);

    char tags[48];
    flags_format_tui(me->flags, tags, sizeof(tags));
    assert(strstr(tags, "NET") != NULL);

    /* and a captured frame carries the tag on that row */
    ProcessInfo row = *me;
    TuiBuf buf;
    one_process_frame(&row, 120, 1, &buf);
    check_frame(&buf, 120, 30);
    char *plain = plain_frame(&buf);
    char pid_text[16];
    snprintf(pid_text, sizeof(pid_text), "%d", (int)getpid());
    assert(strstr(plain, pid_text) != NULL);
    assert(strstr(plain, "NET") != NULL);
    free(plain);
    tui_buf_free(&buf);

    proclist_free(&live);
    close(fd);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--hidden-exe-child") == 0) {
        hidden_exe_child(3);
    }

    test_sysinfo_parsers();
    printf("passed | sysinfo parsers test\n");

    test_cpu_parser_and_deltas();
    printf("passed | cpu parser / deltas test\n");

    test_flags_and_sanitization();
    printf("passed | flags/sanitization test\n");

    test_net_parsers();
    printf("passed | net /proc/net/tcp parser test\n");

    test_procs_parser_deltas_and_sort();
    test_sort_flags_by_risk();
    printf("passed | flags sort by risk test\n");
    printf("passed | procs parser deltas / sort test\n");

    test_procs_stat_truncated();
    printf("passed | procs stat truncation test\n");

    test_procs_exe_link_and_perms();
    printf("passed | procs exe link / perms test\n");

    test_display_width();
    printf("passed | display width test\n");

    test_tui_render();
    printf("passed | tui render test\n");

    test_flags_column_shows_all_four();
    printf("passed | flags column MEMFD/NET at 120/80/60 test\n");

    test_flags_trusted_still_says_ok();
    printf("passed | flags trusted ok test\n");

    test_flags_net_live_listener();
    printf("passed | flags NET live listener test\n");

    test_tui_hidden_column();
    printf("passed | tui hidden column test\n");

    test_tui_row_highlight_toggle();
    printf("passed | tui row highlight toggle test\n");

    test_tui_gpu_row();
    printf("passed | tui gpu row test\n");

    test_tui_layout_and_first_frame();
    printf("passed | tui layout / first frame test\n");

    test_tui_gpu_absent();
    printf("passed | tui gpu absent test\n");

    test_tui_disk_tree();
    printf("passed | tui disk tree test\n");

    test_portrait_calm_frame();
    printf("passed | ceo portrait calm frame test\n");

    test_portrait_red_glasses_mode2();
    printf("passed | ceo portrait mode 2 red glasses test\n");

    test_portrait_waits_for_mode3_verdict();
    printf("passed | ceo portrait mode 3 waits for the verdict test\n");

    test_portrait_unreviewed_mode3_stays_calm();
    printf("passed | ceo portrait mode 3 unreviewed test\n");

    test_portrait_red_glasses_mode3_verdict();
    printf("passed | ceo portrait mode 3 red glasses test\n");

    test_portrait_never_in_mode1();
    printf("passed | ceo portrait mode 1 test\n");

    test_portrait_off_screen_still_alerts();
    printf("passed | ceo portrait off-screen alert test\n");

    test_input_and_control();
    test_navigation_can_be_switched_off();
    printf("passed | input / control test\n");

    test_disk_parent_names();
    printf("passed | disk parent name test\n");

    test_disk_aggregate();
    printf("passed | disk aggregation test\n");

    printf("\nall backend unit tests passed successfully!!!!!!\n");
    return 0;
}
