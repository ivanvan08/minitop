#include "sysinfo.h"
#include "cpu.h"
#include "procs.h"
#include "flags.h"
#include "tui.h"
#include "input.h"
#include "config.h"
#include "gpu.h"
#include "model.h"
#include "llm.h"
#include "trust.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>

#define DEFAULT_REFRESH_MS 1000
#define DEFAULT_DISK_SEC   5

static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_resized = 0;

static void handle_winch(int sig) {
    (void)sig;
    g_resized = 1;
}

static void handle_signal(int sig) {
    (void)sig;
    g_running = 0;
}

static void setup_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* Keep poll() interruptible via EINTR */

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    struct sigaction wa;
    memset(&wa, 0, sizeof(wa));
    wa.sa_handler = handle_winch;
    sigemptyset(&wa.sa_mask);
    sigaction(SIGWINCH, &wa, NULL);
    signal(SIGPIPE, SIG_IGN);
}

static void term_init(void) {
    fputs("\x1b[?1049h\x1b[?25l\x1b[H\x1b[2J", stdout);
    fflush(stdout);
}

static void term_restore(void) {
    term_raw_disable(STDIN_FILENO);
    fputs("\x1b[0m\x1b[?25h\x1b[?1049l", stdout);
    fflush(stdout);
}

static long elapsed_ms_since(const struct timespec *start, const struct timespec *now) {
    long sec  = (long)(now->tv_sec - start->tv_sec);
    long nsec = now->tv_nsec - start->tv_nsec;
    long ms   = sec * 1000L + nsec / 1000000L;
    return (ms > 0) ? ms : 0;
}

static void get_terminal_size(int *cols, int *rows) {
    struct winsize ws;
    *cols = 80;
    *rows = 24;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0 && ws.ws_col > 0) {
        *cols = (int)ws.ws_col;
        *rows = (int)ws.ws_row;
    }
}

static int selected_has_detail(const ProcList *procs, const TuiView *view) {
    if (procs == NULL || view == NULL || view->status != NULL ||
        view->sel_row < 0 || (size_t)view->sel_row >= procs->count) {
        return 0;
    }
    const ProcessInfo *sel = &procs->items[view->sel_row];
    return sel->llm_reason[0] != '\0' && sel->llm_detail[0] != '\0';
}

static size_t render_frame(TuiBuf *frame, const TuiView *view, const SystemInfo *sys,
                           const GpuInfo *gpu, const ProcSummary *sum, const ProcList *procs) {
    int cols;
    int rows;
    get_terminal_size(&cols, &rows);
    if (tui_render(frame, cols, rows, sys, gpu, sum, procs, view) == 0) {
        fwrite(frame->data, 1, frame->len, stdout);
    }
    fflush(stdout);
    return tui_table_rows_detail(rows, selected_has_detail(procs, view));
}

static size_t table_page(const ProcList *procs, const TuiView *view) {
    int cols;
    int rows;
    get_terminal_size(&cols, &rows);
    return tui_table_rows_detail(rows, selected_has_detail(procs, view));
}

static int handle_input(Control *ctl, TuiView *view, ProcList *procs) {
    char buf[64];
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
    if (n <= 0) {
        return 0;
    }
    int dirty = 0;
    size_t off = 0;
    while (off < (size_t)n) {
        int key;
        size_t used = input_parse(buf + off, (size_t)n - off, &key);
        if (used == 0) {
            break;
        }
        off += used;
        size_t page = table_page(procs, view);
        Action act = control_key(ctl, view, key, procs, page);
        if (act == ACT_QUIT) {
            g_running = 0;
            return 0;
        }
        if (act == ACT_RESORT) {
            proclist_sort(procs, view->sort_col, view->sort_desc);
            control_sync(ctl, view, procs, page);
        } else if (act == ACT_KILL) {
            int rc = proc_kill(ctl->kill_pid, ctl->kill_force);
            control_kill_result(ctl, view, rc, rc == 0 ? 0 : errno);
        }
        if (act != ACT_NONE) {
            dirty = 1;
        }
    }
    return dirty;
}

static void usage(const char *argv0) {
    fprintf(stderr, "usage: %s [--config PATH]\n", argv0);
}

/* One shot, no network, no alternate screen: print the request the model would
 * receive for the lowest-pid process that the trust filter does not skip,
 * preferring one whose package metadata is available. */
static int run_model_dry_run(const MiniConfig *cfg) {
    ProcList list = {0};
    if (proclist_init(&list, 128) != 0) {
        fprintf(stderr, "minitop: model dry run: out of memory\n");
        return 1;
    }

    ProcSummary summary;
    memset(&summary, 0, sizeof(summary));
    if (procs_collect(&list, NULL, 0, &summary) != 0) {
        fprintf(stderr, "minitop: model dry run: cannot read /proc\n");
        proclist_free(&list);
        return 1;
    }

    size_t count = list.count > 0 ? list.count : 1;
    TrustInfo *trust = calloc(count, sizeof(*trust));
    if (trust == NULL) {
        fprintf(stderr, "minitop: model dry run: out of memory\n");
        proclist_free(&list);
        return 1;
    }
    trust_evaluate(&list, trust);

    /* Prefer an untrusted process whose package metadata was read, so the
     * printed request shows every state field; fall back to the lowest pid. */
    size_t best = SIZE_MAX;
    for (size_t i = 0; i < list.count; i++) {
        if (trust[i].trusted || !trust[i].package_meta) {
            continue;
        }
        if (best == SIZE_MAX || list.items[i].pid < list.items[best].pid) {
            best = i;
        }
    }
    if (best == SIZE_MAX) {
        for (size_t i = 0; i < list.count; i++) {
            if (!trust[i].trusted &&
                (best == SIZE_MAX || list.items[i].pid < list.items[best].pid)) {
                best = i;
            }
        }
    }

    int rc = 0;
    if (best == SIZE_MAX) {
        fprintf(stderr, "minitop: model dry run: no untrusted process found\n");
        rc = 1;
    } else {
        model_set_name(cfg->model.name);
        char request[MODEL_REQUEST_MAX];
        int n = model_build_request(&list.items[best], &trust[best], request, sizeof(request));
        if (n < 0) {
            fprintf(stderr, "minitop: model dry run: request does not fit in %d bytes\n",
                    MODEL_REQUEST_MAX);
            rc = 1;
        } else {
            fwrite(request, 1, (size_t)n, stdout);
            fputc('\n', stdout);
            fflush(stdout);
        }
    }

    free(trust);
    proclist_free(&list);
    trust_cache_reset();
    return rc;
}

int main(int argc, char **argv) {
    /* Buffer full frame output so each refresh writes cleanly on fflush */
    setvbuf(stdout, NULL, _IOFBF, 1 << 16);
    setup_signals();

    const char *config_path = NULL;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    MiniConfig cfg;
    config_defaults(&cfg);
    char cfg_err[160];

    /* Only the built-in path is created: --config PATH is the user's own
     * choice, and a missing file there keeps meaning "run on the defaults".
     * A failure here is never fatal; the built-in defaults still apply. */
    char default_path[512];
    if (config_path == NULL &&
        config_default_path(default_path, sizeof(default_path)) != NULL) {
        int made = config_create_default(default_path, cfg_err, sizeof(cfg_err));

        if (made > 0) {
            fprintf(stderr, "minitop: created %s\n", default_path);
        } else if (made < 0) {
            fprintf(stderr, "minitop: %s; using the built-in defaults\n", cfg_err);
        }
        config_path = default_path;
    }
    if (config_load(&cfg, config_path, cfg_err, sizeof(cfg_err)) != 0) {
        fprintf(stderr, "minitop: %s (keys above this line stay applied)\n", cfg_err);
    }

    if (cfg.llm.dry_run) {
        return llm_engine_preview(&cfg.llm);
    }
    if (cfg.model.dry_run) {
        return run_model_dry_run(&cfg);
    }

    ModelEngine *model = NULL;
    if (cfg.model.enabled) {
        char model_err[256];
        model = model_engine_create(&cfg.model, model_err, sizeof(model_err));
        if (model == NULL) {
            fprintf(stderr, "minitop: model disabled: %s\n", model_err);
        }
    }

    LlmEngine *llm = NULL;
    if (cfg.llm.enabled) {
        if (model == NULL) {
            fprintf(stderr, "minitop: llm disabled: decision model is not running\n");
        } else {
            char llm_err[256];
            if (cfg.mode == 3) {
                /* Mode 3 treats the model as a filter: everything the model
                 * puts at or above the threshold goes to the LLM, nothing
                 * else does. */
                cfg.llm.min_level = cfg.model.threshold;
                cfg.llm.max_level = 10;
            }
            llm = llm_engine_create(&cfg.llm, llm_err, sizeof(llm_err));
            if (llm == NULL) {
                fprintf(stderr, "minitop: llm disabled: %s\n", llm_err);
            }
        }
    }

    ProcList procs = {0};
    ProcTicksList prev_ticks = {0};
    if (proclist_init(&procs, 128) != 0) {
        fprintf(stderr, "minitop: failed to allocate process buffers\n");
        llm_engine_destroy(llm);
        model_engine_destroy(model);
        trust_cache_reset();
        return 1;
    }

    SystemInfo sys;
    memset(&sys, 0, sizeof(sys));
    sys.temp_celsius = -1.0;

    CpuSample prev_cpu;
    CpuSample curr_cpu;
    memset(&prev_cpu, 0, sizeof(prev_cpu));
    memset(&curr_cpu, 0, sizeof(curr_cpu));

    int has_prev_cpu      = 0;
    int disks_initialized = 0;
    time_t last_disk_sec  = 0;

    TuiView view;
    tui_view_init(&view);
    view.sort_col = cfg.sort_col;
    view.sort_desc = cfg.sort_desc;
    view.show_portrait = cfg.show_portrait;
    view.highlight_row = cfg.highlight_row;
    tui_model_set(model != NULL, cfg.model.enabled && model == NULL,
                  cfg.model.threshold, cfg.mode);
    tui_llm_set(llm != NULL);
    proclist_set_flags_sort(cfg.mode >= 2);
    int visible = 0;
    for (int i = 0; i < COL_COUNT; ++i) {
        view.col_visible[i] = cfg.columns[i];
        visible += cfg.columns[i];
    }
    if (visible == 0) {
        view.col_visible[COL_PID] = 1;
        visible = 1;
    }
    /* The forced PID column counts as visible, so both the sort key and the
     * selection must be revalidated against view.col_visible, never against
     * the requested flags. */
    if (!view.col_visible[view.sort_col]) {
        for (int i = 0; i < COL_COUNT; ++i) {
            if (view.col_visible[i]) {
                view.sort_col = (SortColumn)i;
                break;
            }
        }
    }
    if (!view.col_visible[view.sel_col]) {
        for (int i = 0; i < COL_COUNT; ++i) {
            if (view.col_visible[i]) {
                view.sel_col = (SortColumn)i;
                break;
            }
        }
    }
    Control ctl;
    control_init(&ctl);
    ctl.navigation = cfg.navigation;
    TuiBuf frame = {0};
    ProcSummary summary;
    memset(&summary, 0, sizeof(summary));
    GpuInfo gpu;
    memset(&gpu, 0, sizeof(gpu));

    int frame_ms = cfg.refresh_ms > 0 ? cfg.refresh_ms : DEFAULT_REFRESH_MS;
    int disk_sec = cfg.disk_refresh_sec > 0 ? cfg.disk_refresh_sec : DEFAULT_DISK_SEC;

    int input_on = term_raw_enable(STDIN_FILENO) == 0;
    term_init();

    while (g_running) {
        struct timespec frame_start;
        clock_gettime(CLOCK_MONOTONIC, &frame_start);

        if (cfg.gpu) {
            if (gpu_read(&gpu) != 0) {
                memset(&gpu, 0, sizeof(gpu));
            }
        }
        int refresh_disks = (!disks_initialized ||
                             (frame_start.tv_sec - last_disk_sec) >= disk_sec);
        if (sysinfo_refresh(&sys, refresh_disks) != 0) {
            break;
        }
        if (refresh_disks) {
            disks_initialized = 1;
            last_disk_sec = frame_start.tv_sec;
        }

        if (cpu_read_sample(&curr_cpu) != 0) {
            break;
        }

        uint64_t delta_total = 0;
        if (!has_prev_cpu) {
            prev_cpu     = curr_cpu;
            has_prev_cpu = 1;
            sys.cpu_pct  = -1.0; /* no delta yet: the renderer shows a dash */
        } else {
            sys.cpu_pct = cpu_calc_usage_pct(&prev_cpu, &curr_cpu, &delta_total);
        }

        if (procs_collect(&procs, NULL, 0, &summary) != 0) {
            break;
        }
        /* The previous full snapshot existed only to supply the tick counters,
         * so the history now costs 24 bytes per process instead of a whole
         * ProcessInfo. */
        procs_apply_cpu_deltas(&procs, &prev_ticks, delta_total);
        procticks_capture(&prev_ticks, &procs);
        /* The trust pass and the engines fill risk and trusted, and the FLAGS
         * column sorts on exactly those, so sorting has to wait for them. */
        {
            size_t ntrust = procs.count > 0 ? procs.count : 1;
            TrustInfo *trust = calloc(ntrust, sizeof(*trust));
            if (trust != NULL) {
                /* Evaluated even when both engines are off: the FLAGS cell shows
                 * "ok" for trusted processes, and the package lookups are cached
                 * per executable path after the first pass. */
                trust_evaluate(&procs, trust);
                for (size_t i = 0; i < procs.count; i++) {
                    procs.items[i].trusted = trust[i].trusted ? 1 : 0;
                }
                if (model != NULL) {
                    model_engine_tick(model, &procs, trust, procs.count);
                }
                if (llm != NULL) {
                    llm_engine_tick(llm, &procs, trust, procs.count);
                }
                free(trust);
            }
        }
        /* The selection is a position in the sorted list, not a process: the user
         * stands on row N of a column and stays there when the ranking changes.
         * Keeping the process instead would make `follow` meaningless. */
        proclist_sort(&procs, view.sort_col, view.sort_desc);
        control_tick(&ctl, &view);
        control_sync(&ctl, &view, &procs, table_page(&procs, &view));

        render_frame(&frame, &view, &sys, &gpu, &summary, &procs);

        prev_cpu = curr_cpu;

        while (g_running) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            long elapsed = elapsed_ms_since(&frame_start, &now);
            if (elapsed >= frame_ms) {
                break;
            }
            int remaining_ms = (int)(frame_ms - elapsed);
            struct pollfd pfd = { .fd = STDIN_FILENO, .events = POLLIN, .revents = 0 };
            int rc = poll(&pfd, input_on ? 1 : 0, remaining_ms);
            if (rc < 0 && errno != EINTR) {
                g_running = 0;
                break;
            }
            int dirty = 0;
            if (rc > 0 && (pfd.revents & POLLIN)) {
                dirty = handle_input(&ctl, &view, &procs);
            } else if (rc > 0 && (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))) {
                input_on = 0;
            }
            if (g_resized) {
                g_resized = 0;
                dirty = 1;
            }
            if (dirty && g_running) {
                render_frame(&frame, &view, &sys, &gpu, &summary, &procs);
            }
        }
    }

    term_restore();
    llm_engine_destroy(llm);
    model_engine_destroy(model);
    trust_cache_reset();
    tui_buf_free(&frame);
    proclist_free(&procs);
    procticks_free(&prev_ticks);
    return 0;
}
