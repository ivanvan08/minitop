#ifndef MINITOP_TUI_H
#define MINITOP_TUI_H

#include <stddef.h>
#include <sys/types.h>

#include "gpu.h"
#include "procs.h"
#include "sysinfo.h"

typedef struct TuiBuf {
    char  *data;
    size_t len;
    size_t cap;
    int    failed;
} TuiBuf;

typedef struct TuiView {
    SortColumn  sort_col;
    int         sort_desc;
    SortColumn  sel_col;
    ssize_t     sel_row;
    size_t      scroll;
    int         show_portrait;
    int         highlight_row;
    int         col_visible[COL_COUNT];
    pid_t       follow_pid;
    const char *status;
} TuiView;

void tui_view_init(TuiView *view);
void tui_buf_reset(TuiBuf *buf);
void tui_buf_free(TuiBuf *buf);

size_t tui_table_rows(int height);

/**
 * Rows available for the process table when the footer may carry a second
 * line. detail=1 reserves one extra footer row when height >= MIN_HEIGHT+2;
 * with detail=0 this is exactly tui_table_rows(height).
 */
size_t tui_table_rows_detail(int height, int detail);

int tui_render(TuiBuf *out, int width, int height,
               const SystemInfo *sys, const GpuInfo *gpu, const ProcSummary *sum,
               const ProcList *procs, const TuiView *view);

#endif
