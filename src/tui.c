#include "tui.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "display.h"
#include "flags.h"
#include "model.h"

#define HEADER_INNER   9
#define HEADER_ROWS    (HEADER_INNER + 2)
#define HEADER_GAP     1
#define PANEL_ROWS     9
#define PANEL_TOP      0
#define MIN_WIDTH      60
#define MIN_HEIGHT     18
#define PORTRAIT_W     20
#define PORTRAIT_H     18
#define PORTRAIT_PANEL (PORTRAIT_W + 4)
#define PORTRAIT_MIN_W 100

typedef struct Rgb {
    unsigned char r, g, b;
} Rgb;

#define RGB(r, g, b) ((Rgb){ (r), (g), (b) })

/* Contrast contract, measured against the harness background (14,16,20) and
 * the selected-row background (40,56,18): every text colour clears 4.5:1 on
 * the default background and 3:1 on a highlighted row.  C_TRACK is meter
 * decoration and is never used for text. */
#define C_BORDER  RGB(78, 84, 104)
#define C_ACCENT  RGB(118, 185, 0)
#define C_LABEL   RGB(150, 156, 178)
#define C_VALUE   RGB(226, 229, 240)
#define C_DIM     RGB(126, 128, 138)
#define C_TRACK   RGB(64, 68, 84)
#define C_HEAD_BG RGB(32, 36, 48)
#define C_SEL_BG  RGB(40, 56, 18)
#define C_SEL_HOT RGB(88, 126, 12)
#define C_INK     RGB(14, 16, 20)
#define C_RED     RGB(238, 82, 82)
#define C_ORANGE  RGB(242, 168, 58)
#define C_YELLOW  RGB(232, 206, 72)
#define C_GREEN   RGB(118, 185, 0)
#define C_ROOT    RGB(214, 128, 128)
#define C_USER    RGB(140, 186, 236)

/* FLAGS verdict: risk below the threshold is blue on dark blue, at or above
 * it is red on dark red. Both pairs keep the 4.5:1 text contrast contract. */
#define C_SAFE_BG RGB(16, 34, 66)
#define C_SAFE_FG RGB(150, 196, 255)
#define C_RISK_BG RGB(70, 18, 22)
#define C_RISK_FG RGB(255, 176, 176)
/* Trusted by plan 6.4: muted green, quieter than a model verdict because the
 * label comes from packaging, not from an inspection of the process. */
#define C_TRUST_FG RGB(139, 178, 139)

typedef struct Out {
    TuiBuf *b;
    size_t  col;
    size_t  limit;
} Out;

/* Process-wide FLAGS verdict state, set once by main. The TUI has a single
 * view, and keeping it here avoids widening TuiView for a value that never
 * varies between views. */
static int g_model_enabled;
static int g_model_grey;
static int g_model_threshold = 5;
static int g_mode = 1;
/* Whether anything can actually answer for a flagged process. With the engine
 * down the row must not look like a request that is still in flight. */
static int g_llm_running = 1;

void tui_model_set(int enabled, int grey, int threshold, int mode) {
    g_model_enabled = enabled != 0;
    g_model_grey = grey != 0;
    g_model_threshold = (threshold >= 1 && threshold <= 10) ? threshold : 5;
    g_mode = (mode >= 1 && mode <= 3) ? mode : 1;
}

void tui_llm_set(int running) {
    g_llm_running = running != 0;
}

/* One row's FLAGS verdict. The cell paint and the ceo portrait both read this
 * state, so "the cell is red" and "the glasses are red" are one decision and
 * cannot drift apart. The state is a pure function of the row and the flags
 * configuration above. */
typedef enum FlagCell {
    FLAG_CELL_TAGS,       /* mode 1: the local rule bits, never a verdict */
    FLAG_CELL_NONE,       /* nothing scored yet: a dash */
    FLAG_CELL_MUTED,      /* model client down: a dash, no verdict to paint */
    FLAG_CELL_TRUSTED,    /* known safe by plan 6.4 */
    FLAG_CELL_CLEAR,      /* scored, the verdict is not malicious */
    FLAG_CELL_MALICIOUS,  /* scored, the verdict is malicious: the red cell */
    FLAG_CELL_QUEUED,     /* at or above the threshold, the LLM has not answered */
    FLAG_CELL_UNREVIEWED, /* at or above the threshold, no engine to ask */
} FlagCell;

static FlagCell flag_cell_state(const ProcessInfo *p) {
    if (g_mode < 2) {
        return FLAG_CELL_TAGS;
    }
    if (g_model_grey || p == NULL || p->risk < 1) {
        return g_model_grey ? FLAG_CELL_MUTED : FLAG_CELL_NONE;
    }
    /* A trusted package binary that listens on a socket is still trusted: the
     * NET tag is a fact the model weighs, not a deviation. DEL, TMP and MEMFD
     * mean the running image is not the packaged one, so they do break "ok". */
    if (p->trusted && (p->flags & (FLAG_DEL | FLAG_TMP | FLAG_MEMFD)) == 0) {
        return FLAG_CELL_TRUSTED;
    }
    if (g_mode == 3) {
        /* The model is the filter here: only the LLM's reasoned verdict may
         * paint red. Without one, a flagged row either waits for the engine or,
         * with the engine down, says so in the attention colour. Both are
         * non-red, so both leave the glasses calm. */
        if (p->llm_reason[0] != '\0' && p->llm_verdict >= 0) {
            return p->llm_verdict == 1 ? FLAG_CELL_MALICIOUS : FLAG_CELL_CLEAR;
        }
        int flagged = p->risk >= g_model_threshold;
        if (g_llm_running) {
            return flagged ? FLAG_CELL_QUEUED : FLAG_CELL_CLEAR;
        }
        return flagged ? FLAG_CELL_UNREVIEWED : FLAG_CELL_CLEAR;
    }
    return p->risk >= g_model_threshold ? FLAG_CELL_MALICIOUS : FLAG_CELL_CLEAR;
}

/* A disk panel row is either a physical disk (the parent, carrying the
 * aggregate fill) or one of its mounted filesystems.  Rows follow list order,
 * so every parent is immediately followed by its own children. */
typedef struct DiskRow {
    int    is_parent;
    size_t index;
} DiskRow;

typedef struct DiskTree {
    DiskRow rows[MAX_DISKS * 2]; /* every disk at most once, every mount at most once */
    size_t  count;
    size_t  pair_w; /* widest used/total pair: one field width for every child row */
} DiskTree;

typedef struct Ctx {
    const SystemInfo  *sys;
    const GpuInfo     *gpu;
    const ProcSummary *sum;
    const ProcList    *procs;
    const TuiView     *view;
    const DiskList    *disks;   /* one row per mounted filesystem */
    const DiskList    *parents; /* one row per physical disk */
    const DiskTree    *tree;
    int                alert;   /* a visible row's FLAGS cell is red */
} Ctx;

/* The 18-row portrait of 672f866 vertically resampled 2:3 into the twelve
 * half-block rows the six header cells can show: one row out of every three
 * consecutive ones is dropped and each triple keeps the two that carry the
 * silhouette, the glasses rim, the eyes, the beard and the jacket. */
static const char *const portrait_rows[PORTRAIT_H] = {
    "......wWWWWWWw......",
    "....wWWWWwWWWWWw....",
    "...wWWwWWWWWwWWWw...",
    "..wWWWWWWWWWWWwWWg..",
    "..gWWwSSSSSSSSwWWg..",
    "..gWsSSSSSSSSSSsWg..",
    "..gwsSSSSSSSSSSswg..",
    "..sSGGGGGSSGGGGGSs..",
    ".sSSGLLLGGGGLLLGSSs.",
    ".sSSGLELGSSGLELGSSs.",
    "..sSSHHHSssSHHHSSs..",
    "...SSSSSSssSSSSSS...",
    "...sSsSSSddSSSsSs...",
    "....sSSMTTTTMSSs....",
    ".....sSSMMMMSSs.....",
    ".....JksSSSSskJ.....",
    "...JJJkJttttJkJJJ...",
    ".JJJJjJkJttJkJjJJJJ.",
};
_Static_assert(PORTRAIT_H == HEADER_INNER * 2, "portrait must fill the header");

/* PR 9's red glasses: the frame glyphs of the same pixel map, recoloured to
 * the red that pull request gives them. One map with a palette mode, rather
 * than a second 18-row array, keeps the two states from drifting apart. */
#define C_ALERT_RIM RGB(200, 28, 32)

static int portrait_color(char px, int alert, Rgb *out) {
    switch (px) {
    case '.': *out = RGB(44, 48, 64); return 1;
    case 'W': *out = RGB(240, 240, 242); return 1;
    case 'w': *out = RGB(200, 202, 208); return 1;
    case 'g': *out = RGB(150, 152, 160); return 1;
    case 'S': *out = RGB(240, 196, 158); return 1;
    case 's': *out = RGB(214, 160, 122); return 1;
    case 'd': *out = RGB(182, 128, 96); return 1;
    case 'G': *out = alert ? C_ALERT_RIM : RGB(24, 24, 26); return 1;
    case 'L': *out = RGB(246, 214, 182); return 1;
    case 'E': *out = RGB(60, 40, 30); return 1;
    case 'H': *out = alert ? C_ALERT_RIM : RGB(70, 62, 58); return 1;
    case 'M': *out = RGB(140, 56, 50); return 1;
    case 'T': *out = RGB(250, 250, 250); return 1;
    case 'J': *out = RGB(28, 28, 32); return 1;
    case 'j': *out = RGB(78, 78, 88); return 1;
    case 'k': *out = RGB(130, 130, 140); return 1;
    case 't': *out = RGB(10, 10, 12); return 1;
    default:  return 0;
    }
}

void tui_view_init(TuiView *view) {
    if (view == NULL) {
        return;
    }
    memset(view, 0, sizeof(*view));
    view->sort_col = COL_CPU;
    view->sort_desc = 1;
    view->sel_col = COL_CPU;
    view->sel_row = -1;
    view->show_portrait = 1;
    view->highlight_row = 1;
    tui_model_set(0, 0, 5, 1);
    for (int i = 0; i < COL_COUNT; ++i) {
        view->col_visible[i] = 1;
    }
}

void tui_buf_reset(TuiBuf *buf) {
    if (buf == NULL) {
        return;
    }
    buf->len = 0;
    buf->failed = 0;
    if (buf->data != NULL) {
        buf->data[0] = '\0';
    }
}

void tui_buf_free(TuiBuf *buf) {
    if (buf == NULL) {
        return;
    }
    free(buf->data);
    memset(buf, 0, sizeof(*buf));
}

static int footer_rows_for(int height, int detail) {
    /* one extra footer line costs two rows: the line itself and the table row
     * it displaces; below MIN_HEIGHT+2 the table would get too short */
    return (detail != 0 && height >= MIN_HEIGHT + 2) ? 2 : 1;
}

size_t tui_table_rows_detail(int height, int detail) {
    int rows = height - HEADER_ROWS - HEADER_GAP - footer_rows_for(height, detail) - 3;
    return rows > 0 ? (size_t)rows : 0;
}

size_t tui_table_rows(int height) {
    return tui_table_rows_detail(height, 0);
}

static void buf_put(TuiBuf *b, const char *s, size_t n) {
    if (b->failed) {
        return;
    }
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 8192;
        while (cap < b->len + n + 1) {
            cap *= 2;
        }
        char *p = realloc(b->data, cap);
        if (p == NULL) {
            b->failed = 1;
            return;
        }
        b->data = p;
        b->cap = cap;
    }
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
}

static void buf_puts(TuiBuf *b, const char *s) {
    buf_put(b, s, strlen(s));
}

static void buf_printf(TuiBuf *b, const char *fmt, ...) {
    char tmp[128];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n > 0) {
        buf_put(b, tmp, (size_t)n < sizeof(tmp) ? (size_t)n : sizeof(tmp) - 1);
    }
}

static void fg(Out *o, Rgb c) {
    buf_printf(o->b, "\x1b[38;2;%u;%u;%um", c.r, c.g, c.b);
}

static void bg(Out *o, Rgb c) {
    buf_printf(o->b, "\x1b[48;2;%u;%u;%um", c.r, c.g, c.b);
}

static void bold(Out *o) {
    buf_puts(o->b, "\x1b[1m");
}

static void reset(Out *o) {
    buf_puts(o->b, "\x1b[0m");
}

static void text(Out *o, const char *s) {
    if (o->col >= o->limit) {
        return;
    }
    size_t w = display_width(s);
    if (o->col + w > o->limit) {
        char tmp[512];
        truncate_to_width(tmp, sizeof(tmp), s, o->limit - o->col);
        buf_puts(o->b, tmp);
        o->col += display_width(tmp);
        return;
    }
    buf_puts(o->b, s);
    o->col += w;
}

static size_t room(const Out *o, size_t n) {
    size_t left = o->col < o->limit ? o->limit - o->col : 0;
    return n < left ? n : left;
}

static void spaces(Out *o, size_t n) {
    static const char blank[] = "                                ";
    n = room(o, n);
    o->col += n;
    while (n > 0) {
        size_t k = n < sizeof(blank) - 1 ? n : sizeof(blank) - 1;
        buf_put(o->b, blank, k);
        n -= k;
    }
}

static void repeat(Out *o, const char *glyph, size_t n) {
    size_t len = strlen(glyph);
    n = room(o, n);
    for (size_t i = 0; i < n; ++i) {
        buf_put(o->b, glyph, len);
    }
    o->col += n;
}

static void fill_to(Out *o, size_t col) {
    if (o->col < col) {
        spaces(o, col - o->col);
    }
}

static void cell(Out *o, const char *s, size_t w, int right) {
    char tmp[512];
    if (w == 0) {
        return;
    }
    if (right) {
        truncate_to_width(tmp, sizeof(tmp), s, w);
        spaces(o, w - display_width(tmp));
        text(o, tmp);
    } else {
        pad_to_width(tmp, sizeof(tmp), s, w);
        text(o, tmp);
    }
}

static Rgb mix(Rgb a, Rgb b, double t) {
    Rgb c;
    c.r = (unsigned char)(a.r + (b.r - a.r) * t);
    c.g = (unsigned char)(a.g + (b.g - a.g) * t);
    c.b = (unsigned char)(a.b + (b.b - a.b) * t);
    return c;
}

static Rgb heat(double t) {
    if (t < 0.0) {
        t = 0.0;
    }
    if (t > 1.0) {
        t = 1.0;
    }
    return t < 0.5 ? mix(C_GREEN, C_YELLOW, t * 2.0) : mix(C_YELLOW, C_RED, (t - 0.5) * 2.0);
}

static void bar(Out *o, double pct, size_t w) {
    if (pct < 0.0) {
        pct = 0.0;
    }
    if (pct > 100.0) {
        pct = 100.0;
    }
    size_t filled = (size_t)(pct / 100.0 * (double)w + 0.5);
    for (size_t i = 0; i < w; ++i) {
        if (i < filled) {
            fg(o, heat(((double)i + 0.5) / (double)w));
            repeat(o, "\xe2\x96\x88", 1);
        } else {
            fg(o, C_TRACK);
            repeat(o, "\xc2\xb7", 1);
        }
    }
    reset(o);
}

/* The one size scheme used by the mem panel, the MEM column and the GPU row:
 * a single letter and no space, one decimal below 100 so small values stay
 * precise and 296K stays an integer. */
static void fmt_bytes(uint64_t bytes, char *buf, size_t buf_sz) {
    static const char *const units[] = { "B", "K", "M", "G", "T", "P" };
    double v = (double)bytes;
    size_t u = 0;
    while (v >= 1024.0 && u + 1 < sizeof(units) / sizeof(units[0])) {
        v /= 1024.0;
        u++;
    }
    if (u == 0) {
        snprintf(buf, buf_sz, "%lluB", (unsigned long long)bytes);
    } else if (v < 100.0) {
        snprintf(buf, buf_sz, "%.1f%s", v, units[u]);
    } else {
        snprintf(buf, buf_sz, "%.0f%s", v, units[u]);
    }
}

static void fmt_kib(uint64_t kib, char *buf, size_t buf_sz) {
    fmt_bytes(kib * 1024ULL, buf, buf_sz);
}

static void fmt_uptime(uint64_t up, char *buf, size_t buf_sz) {
    unsigned long long d = up / 86400ULL;
    unsigned long long h = (up % 86400ULL) / 3600ULL;
    unsigned long long m = (up % 3600ULL) / 60ULL;
    if (d > 0) {
        snprintf(buf, buf_sz, "%llud %02llu:%02llu", d, h, m);
    } else {
        snprintf(buf, buf_sz, "%llu:%02llu:%02llu", h, m, (unsigned long long)(up % 60ULL));
    }
}

static double pct_of(uint64_t part, uint64_t whole) {
    return whole > 0 ? (double)part * 100.0 / (double)whole : 0.0;
}

static void kv(Out *o, const char *label, const char *value, size_t w) {
    size_t lw = display_width(label);
    if (lw + 1 > w) {
        fg(o, C_LABEL);
        cell(o, label, w, 0);
        reset(o);
        return;
    }
    size_t vw = w - lw - 1;
    fg(o, C_LABEL);
    cell(o, label, lw + 1, 0);
    fg(o, C_VALUE);
    cell(o, value, vw, 1);
    reset(o);
}

static void kv2(Out *o, const char *l1, const char *v1, const char *l2, const char *v2, size_t w) {
    size_t need1 = display_width(l1) + 1 + display_width(v1);
    size_t need2 = display_width(l2) + 1 + display_width(v2);
    size_t sep = 3;
    if (need1 + need2 + sep > w) {
        sep = 1;
    }
    if (w < 6 || need1 + need2 + sep > w) {
        size_t left = w > 1 ? (w - 1) / 2 : 0;
        kv(o, l1, v1, left);
        spaces(o, w > left ? 1 : 0);
        kv(o, l2, v2, w > left + 1 ? w - left - 1 : 0);
        return;
    }
    size_t left = (w - sep) / 2;
    if (left < need1) {
        left = need1;
    }
    if (w - sep - left < need2) {
        left = w - sep - need2;
    }
    kv(o, l1, v1, left);
    spaces(o, sep);
    kv(o, l2, v2, w - sep - left);
}

static void meter(Out *o, const char *label, double pct, size_t w) {
    char num[16];
    snprintf(num, sizeof(num), "%5.1f%%", pct);
    size_t lw = display_width(label) + 1;
    size_t nw = display_width(num) + 1;
    if (w < lw + nw + 3) {
        kv(o, label, num, w);
        return;
    }
    fg(o, C_LABEL);
    cell(o, label, lw, 0);
    bar(o, pct, w - lw - nw);
    fg(o, C_VALUE);
    bold(o);
    cell(o, num, nw, 1);
    reset(o);
}

/* No sample yet (sys->cpu_pct < 0): an em dash sits exactly where the
 * percentage will appear, so the first frame does not read as idle. */
static void meter_pending(Out *o, const char *label, size_t w) {
    size_t lw = display_width(label) + 1;
    size_t nw = 7; /* room for "100.0%", matching meter() */
    if (w < lw + nw + 1) {
        kv(o, label, "\xe2\x80\x94", w);
        return;
    }
    fg(o, C_LABEL);
    cell(o, label, lw, 0);
    spaces(o, w - lw - nw);
    fg(o, C_VALUE);
    bold(o);
    cell(o, "\xe2\x80\x94", nw, 1);
    reset(o);
}

static void border_line(Out *o, size_t w, const char *lc, const char *rc,
                        const char *title, const char *note) {
    size_t tw = title ? display_width(title) + 2 : 0;
    size_t nw = note ? display_width(note) + 2 : 0;
    fg(o, C_BORDER);
    if (w < 2) {
        repeat(o, "\xe2\x94\x80", w);
        reset(o);
        return;
    }
    size_t start = o->col;
    text(o, lc);
    if (title && w >= tw + 6) {
        text(o, "\xe2\x94\x80\xe2\x94\xa4 ");
        bold(o);
        fg(o, C_ACCENT);
        text(o, title);
        reset(o);
        fg(o, C_BORDER);
        text(o, " \xe2\x94\x9c");
    }
    size_t used = o->col - start;
    size_t tail = (note && w >= used + nw + 6) ? nw + 4 : 1;
    if (tail == 1) {
        note = NULL;
    }
    repeat(o, "\xe2\x94\x80", w - used - tail);
    if (note) {
        text(o, "\xe2\x94\xa4 ");
        fg(o, C_LABEL);
        text(o, note);
        fg(o, C_BORDER);
        text(o, " \xe2\x94\x9c\xe2\x94\x80");
    }
    text(o, rc);
    reset(o);
}

static void side(Out *o) {
    fg(o, C_BORDER);
    text(o, "\xe2\x94\x82");
    reset(o);
}

#define GPU_LABEL_W 4
#define GPU_PCT_W   4
#define GPU_BAR_MIN 6

/* 2745 MHz -> "2.75GHz", 345 MHz -> "345MHz": the unit always rides with the
 * number, so a clock can never be misread as a memory size. */
static void fmt_clock(unsigned mhz, char *buf, size_t buf_sz) {
    if (mhz >= 1000) {
        snprintf(buf, buf_sz, "%.2fGHz", (double)mhz / 1000.0);
    } else {
        snprintf(buf, buf_sz, "%uMHz", mhz);
    }
}

static void fmt_gpu_mem(uint64_t used, uint64_t total, char *buf, size_t buf_sz) {
    char a[24], b[24];
    fmt_bytes(used, a, sizeof(a));
    fmt_bytes(total, b, sizeof(b));
    snprintf(buf, buf_sz, "%s/%s", a, b);
}

static size_t parts_width(const char *const *parts, size_t n) {
    size_t w = 0;
    for (size_t i = 0; i < n; ++i) {
        w += display_width(parts[i]) + (i > 0 ? 1 : 0);
    }
    return w;
}

/* util_pct < 0 is a clock-only source (Intel): "gpu  —  350MHz".
 * The percent, the compact VRAM pair and the clock are content; the bar is
 * decoration.  The bar is drawn only while at least GPU_BAR_MIN cells remain
 * for it, otherwise the row becomes plain text.  When even the text is too
 * wide the clock goes first, then the VRAM total, never the percent. */
static void panel_gpu(Out *o, const GpuInfo *g, size_t w) {
    char pct[8], plain_pct[8], mem[64], used[24], clk[16];
    size_t start = o->col;

    if (g == NULL || !g->present) {
        return;
    }

    if (g->util_pct < 0) {
        fg(o, C_LABEL);
        cell(o, "gpu ", GPU_LABEL_W, 0);
        reset(o);
        spaces(o, 1);
        fg(o, C_VALUE);
        text(o, "\xe2\x80\x94");
        reset(o);
        if (g->clock_mhz > 0) {
            fmt_clock(g->clock_mhz, clk, sizeof(clk));
            if (o->col + 2 + display_width(clk) <= start + w) {
                spaces(o, 2);
                fg(o, C_LABEL);
                text(o, clk);
                reset(o);
            }
        }
        return;
    }

    int util = g->util_pct > 100 ? 100 : g->util_pct;
    snprintf(pct, sizeof(pct), "%3d%%", util);
    snprintf(plain_pct, sizeof(plain_pct), "%d%%", util);

    int has_total = g->mem_total_bytes > 0;
    int has_used = g->mem_used_bytes > 0;
    if (has_used) {
        fmt_bytes(g->mem_used_bytes, used, sizeof(used));
    }
    if (has_total) {
        fmt_gpu_mem(g->mem_used_bytes, g->mem_total_bytes, mem, sizeof(mem));
    }
    int has_clock = g->clock_mhz > 0;
    if (has_clock) {
        fmt_clock(g->clock_mhz, clk, sizeof(clk));
    }

    const char *group[2];
    size_t nparts = 0;
    if (has_total || has_used) {
        group[nparts++] = has_total ? mem : used;
    }
    if (has_clock) {
        group[nparts++] = clk;
    }
    while (nparts > 0 && GPU_LABEL_W + strlen(plain_pct) + 1 + parts_width(group, nparts) > w) {
        if (has_total && has_used) {
            group[0] = used; /* drop the VRAM total, keep the clock */
            has_total = 0;
        } else if (nparts == 2) {
            nparts = 1; /* drop the clock */
        } else {
            nparts = 0;
        }
    }

    size_t group_w = parts_width(group, nparts);
    size_t tail = GPU_PCT_W + (nparts > 0 ? 1 + group_w : 0);
    if (w >= GPU_LABEL_W + GPU_BAR_MIN + 1 + tail) {
        size_t bw = w - GPU_LABEL_W - 1 - tail;
        fg(o, C_LABEL);
        cell(o, "gpu ", GPU_LABEL_W, 0);
        bar(o, (double)util, bw);
        spaces(o, 1);
        fg(o, C_VALUE);
        bold(o);
        cell(o, pct, GPU_PCT_W, 1);
        reset(o);
        if (nparts > 0) {
            fill_to(o, start + w - group_w);
            for (size_t i = 0; i < nparts; ++i) {
                if (i > 0) {
                    spaces(o, 1);
                }
                fg(o, group[i] == clk ? C_LABEL : C_VALUE);
                text(o, group[i]);
                reset(o);
            }
        }
        return;
    }

    fg(o, C_LABEL);
    cell(o, "gpu ", GPU_LABEL_W, 0);
    fg(o, C_VALUE);
    bold(o);
    text(o, plain_pct);
    reset(o);
    for (size_t i = 0; i < nparts; ++i) {
        spaces(o, 1);
        fg(o, group[i] == clk ? C_LABEL : C_VALUE);
        text(o, group[i]);
        reset(o);
    }
}

static void panel_cpu(Out *o, const Ctx *c, int row, size_t w) {
    const SystemInfo *s = c->sys;
    char a[48], b[48];
    switch (row) {
    case 0:
        if (s->cpu_pct < 0.0) {
            meter_pending(o, "cpu", w);
        } else {
            meter(o, "cpu", s->cpu_pct, w);
        }
        break;
    case 1:
        if (s->temp_celsius < 0.0) {
            snprintf(a, sizeof(a), "\xe2\x80\x94");
        } else {
            snprintf(a, sizeof(a), "%.0f\xc2\xb0" "C", s->temp_celsius);
        }
        fmt_uptime(s->uptime_sec, b, sizeof(b));
        kv2(o, "temp", a, "up", b, w);
        break;
    case 2:
        snprintf(a, sizeof(a), "%.2f  %.2f  %.2f", s->load.load1, s->load.load5, s->load.load15);
        kv(o, "load", a, w);
        break;
    case 3:
        panel_gpu(o, c->gpu, w);
        break;
    case 4:
        snprintf(a, sizeof(a), "%zu", c->sum->total_procs);
        snprintf(b, sizeof(b), "%zu", c->sum->total_threads);
        kv2(o, "procs", a, "threads", b, w);
        break;
    case 5:
        snprintf(a, sizeof(a), "%zu", c->sum->running_procs);
        snprintf(b, sizeof(b), "%zu", c->sum->sleeping_procs);
        kv2(o, "running", a, "sleeping", b, w);
        break;
    default:
        break;
    }
}

static void panel_mem(Out *o, const Ctx *c, int row, size_t w) {
    const MemInfo *m = &c->sys->mem;
    char a[32], b[32];
    switch (row) {
    case 0:
        meter(o, "ram ", pct_of(m->mem_used_kib, m->mem_total_kib), w);
        break;
    case 1:
        fmt_kib(m->mem_used_kib, a, sizeof(a));
        fmt_kib(m->mem_total_kib, b, sizeof(b));
        kv2(o, "used", a, "total", b, w);
        break;
    case 2:
        fmt_kib(m->mem_avail_kib, a, sizeof(a));
        fmt_kib(m->mem_free_kib, b, sizeof(b));
        kv2(o, "avail", a, "free", b, w);
        break;
    case 3:
        fmt_kib(m->mem_cached_kib, a, sizeof(a));
        fmt_kib(m->mem_buffers_kib, b, sizeof(b));
        kv2(o, "cached", a, "buffers", b, w);
        break;
    case 4:
        meter(o, "swap", pct_of(m->swap_used_kib, m->swap_total_kib), w);
        break;
    case 5:
        fmt_kib(m->swap_used_kib, a, sizeof(a));
        fmt_kib(m->swap_total_kib, b, sizeof(b));
        kv2(o, "used", a, "total", b, w);
        break;
    default:
        break;
    }
}

static void short_dev(const char *dev, char *dst, size_t dst_sz) {
    const char *p = dev;
    if (strncmp(p, "/dev/", 5) == 0) {
        p += 5;
    }
    if (strncmp(p, "mapper/", 7) == 0) {
        p += 7;
    }
    snprintf(dst, dst_sz, "%s", p);
}

static void disk_tree_build(const DiskList *disks, const DiskList *parents, DiskTree *tree) {
    char name[64], pair[48];
    size_t nd = disks->count < MAX_DISKS ? disks->count : MAX_DISKS;
    size_t np = parents->count < MAX_DISKS ? parents->count : MAX_DISKS;
    tree->count = 0;
    tree->pair_w = 0;
    for (size_t p = 0; p < np; ++p) {
        tree->rows[tree->count].is_parent = 1;
        tree->rows[tree->count].index = p;
        tree->count++;
        for (size_t i = 0; i < nd; ++i) {
            disk_parent_name(disks->items[i].device, name, sizeof(name));
            if (strcmp(name, parents->items[p].device) != 0) {
                continue;
            }
            tree->rows[tree->count].is_parent = 0;
            tree->rows[tree->count].index = i;
            tree->count++;
            fmt_gpu_mem(disks->items[i].used_bytes, disks->items[i].total_bytes,
                        pair, sizeof(pair));
            size_t pw = display_width(pair);
            if (pw > tree->pair_w) {
                tree->pair_w = pw;
            }
        }
    }
}

#define DISK_PCT_W 4 /* "100%": one fixed field keeps the bars of several parents aligned */

static void disk_parent_row(Out *o, const DiskInfo *p, size_t w) {
    char name[64], shown[64], num[16];
    short_dev(p->device, name, sizeof(name));
    double pct = pct_of(p->used_bytes, p->total_bytes);
    snprintf(num, sizeof(num), "%.0f%%", pct);

    size_t nw = display_width(name) + 1;
    size_t name_max = (w > DISK_PCT_W + 7) ? w - DISK_PCT_W - 7 : 4;
    if (nw > name_max) {
        nw = name_max; /* keep at least six bar cells, or a readable name */
    }
    size_t bw = w > nw + DISK_PCT_W + 1 ? w - nw - DISK_PCT_W - 1 : 0;
    int with_bar = bw >= 4;
    size_t width = with_bar ? nw : (w > DISK_PCT_W ? w - DISK_PCT_W : 0);
    /* one blank cell of the name field, so a truncated device name never
     * runs into the bar or the percentage */
    truncate_to_width(shown, sizeof(shown), name, width > 0 ? width - 1 : 0);

    fg(o, C_VALUE);
    bold(o);
    cell(o, shown, width, 0);
    reset(o);
    if (with_bar) {
        bar(o, pct, bw);
        spaces(o, 1);
    }
    fg(o, C_VALUE);
    bold(o);
    cell(o, num, DISK_PCT_W, 1);
    reset(o);
}

/* A child row: two spaces of indent, the mountpoint, its own used/total and
 * its own percentage - never the parent's aggregate.  The pair is dropped
 * before the percentage when the panel is too narrow for both. */
static void disk_child_row(Out *o, const DiskInfo *m, size_t pair_w, size_t w) {
    char name[64], pair[48], num[16];
    double pct = pct_of(m->used_bytes, m->total_bytes);
    snprintf(num, sizeof(num), "%.0f%%", pct);
    fmt_gpu_mem(m->used_bytes, m->total_bytes, pair, sizeof(pair));

    size_t name_w = w > 2 + pair_w + DISK_PCT_W ? w - 2 - pair_w - DISK_PCT_W : 0;
    int show_pair = name_w >= 4;
    if (!show_pair) {
        name_w = w > 2 + DISK_PCT_W ? w - 2 - DISK_PCT_W : 0;
    }
    /* one blank cell of the name field, so a truncated mountpoint never runs
     * into the numbers that follow it */
    truncate_to_width(name, sizeof(name), m->mountpoint, name_w > 0 ? name_w - 1 : 0);

    spaces(o, 2);
    fg(o, C_LABEL);
    cell(o, name, name_w, 0);
    reset(o);
    if (show_pair) {
        fg(o, C_DIM);
        cell(o, pair, pair_w, 1);
        reset(o);
    }
    fg(o, C_LABEL);
    cell(o, num, DISK_PCT_W, 1);
    reset(o);
}

/* Parents first, then their children; when the panel rows run out the last
 * line counts the entries that did not fit. */
static void panel_disks(Out *o, const Ctx *c, int row, size_t w) {
    const DiskTree *t = c->tree;
    if (t->count == 0) {
        if (row == 0) {
            fg(o, C_LABEL);
            cell(o, "no mounted disks", w, 0);
            reset(o);
        }
        return;
    }

    size_t shown = t->count;
    size_t hidden = 0;
    if (t->count > (size_t)PANEL_ROWS) {
        shown = (size_t)PANEL_ROWS - 1;
        hidden = t->count - shown;
    }
    if ((size_t)row == shown && hidden > 0) {
        char more[32];
        snprintf(more, sizeof(more), "\xe2\x80\xa6 +%zu", hidden);
        fg(o, C_DIM);
        cell(o, more, w, 0);
        reset(o);
        return;
    }
    if ((size_t)row >= shown) {
        return;
    }

    const DiskRow *e = &t->rows[row];
    if (e->is_parent) {
        disk_parent_row(o, &c->parents->items[e->index], w);
    } else {
        disk_child_row(o, &c->disks->items[e->index], t->pair_w, w);
    }
}

static void portrait_fill(Out *o, size_t n) {
    Rgb bgc;
    portrait_color('.', 0, &bgc);
    bg(o, bgc);
    spaces(o, n);
    reset(o);
}

static void panel_portrait(Out *o, int row, size_t w, int alert) {
    size_t pad = w > PORTRAIT_W ? (w - PORTRAIT_W) / 2 : 0;
    size_t start = o->col;
    portrait_fill(o, pad);
    const char *top = portrait_rows[row * 2];
    const char *bot = portrait_rows[row * 2 + 1];
    for (size_t x = 0; x < PORTRAIT_W && x < w; ++x) {
        Rgb tc, bc;
        int ht = portrait_color(top[x], alert, &tc);
        int hb = portrait_color(bot[x], alert, &bc);
        if (ht && hb) {
            fg(o, tc);
            bg(o, bc);
            repeat(o, "\xe2\x96\x80", 1);
            reset(o);
        } else if (ht) {
            fg(o, tc);
            repeat(o, "\xe2\x96\x80", 1);
            reset(o);
        } else if (hb) {
            fg(o, bc);
            repeat(o, "\xe2\x96\x84", 1);
            reset(o);
        } else {
            spaces(o, 1);
        }
    }
    if (o->col < start + w) {
        portrait_fill(o, start + w - o->col);
    }
}

typedef struct HeaderLayout {
    size_t cpu_w;
    size_t mem_w;
    size_t disk_w;
    size_t portrait_w;
} HeaderLayout;

/* One blank column between panels: four boxes have three seams with the
 * portrait, three boxes have two seams without it. */
static HeaderLayout header_layout(size_t width, int show_portrait) {
    HeaderLayout l;
    int portrait = show_portrait && width >= PORTRAIT_MIN_W;
    l.portrait_w = portrait ? PORTRAIT_PANEL : 0;
    size_t seams = portrait ? 3 : 2;
    size_t rest = width - l.portrait_w - seams;
    l.cpu_w = rest * 33 / 100;
    l.mem_w = rest * 34 / 100;
    l.disk_w = rest - l.cpu_w - l.mem_w;
    return l;
}

typedef void (*PanelFn)(Out *, const Ctx *, int, size_t);

static void panel_row(Out *o, const Ctx *c, PanelFn fn, int row, size_t w) {
    size_t end = o->col + w;
    size_t outer = o->limit;
    side(o);
    spaces(o, 1);
    size_t inner_end = end - 2;
    o->limit = inner_end;
    if (w > 4) {
        fn(o, c, row, w - 4);
    }
    fill_to(o, inner_end);
    o->limit = outer;
    spaces(o, 1);
    side(o);
    fill_to(o, end);
}

static void render_header(Out *o, const Ctx *c, size_t width, int line) {
    HeaderLayout l = header_layout(width, c->view->show_portrait);
    const PanelFn fns[3] = { panel_cpu, panel_mem, panel_disks };
    const char *titles[3] = { "cpu", "mem", "disks" };
    const size_t ws[3] = { l.cpu_w, l.mem_w, l.disk_w };
    char note[32];
    note[0] = '\0';
    if (c->parents->count > 1) {
        snprintf(note, sizeof(note), "%zu disks", c->parents->count);
    }
    const char *notes[3] = { NULL, NULL, c->parents->count > 1 ? note : NULL };
    int npanels = l.portrait_w ? 4 : 3;
    const int heights[3] = { HEADER_ROWS, HEADER_ROWS, HEADER_ROWS };
    for (int p = 0; p < 3; ++p) {
        if (line >= heights[p]) {
            spaces(o, ws[p]); /* below a short box: the taller neighbours continue */
        } else if (line == 0) {
            border_line(o, ws[p], "\xe2\x94\x8c", "\xe2\x94\x90", titles[p], notes[p]);
        } else if (line == heights[p] - 1) {
            border_line(o, ws[p], "\xe2\x94\x94", "\xe2\x94\x98", NULL, NULL);
        } else {
            panel_row(o, c, fns[p], line - 1 - PANEL_TOP, ws[p]);
        }
        if (p + 1 < npanels) {
            spaces(o, 1);
        }
    }
    if (l.portrait_w) {
        if (line == 0) {
            border_line(o, l.portrait_w, "\xe2\x94\x8c", "\xe2\x94\x90", "ceo", NULL);
        } else if (line == HEADER_ROWS - 1) {
            border_line(o, l.portrait_w, "\xe2\x94\x94", "\xe2\x94\x98", NULL, NULL);
        } else {
            size_t end = o->col + l.portrait_w;
            side(o);
            panel_portrait(o, line - 1, l.portrait_w - 2, c->alert);
            fill_to(o, end - 1);
            side(o);
        }
    }
}

typedef struct Column {
    const char *name;
    size_t      width;
    int         right;
} Column;

#define COMMAND_WANT 18
#define COMMAND_MIN   6
#define GAP_MAX       4

/* A column with width 0 is not drawn at all: it emits neither a cell nor a
 * gap. That is how the fit below hides a column the terminal cannot afford. */
static int col_drawn(const Column *cols, const TuiView *view, int i) {
    return view->col_visible[i] && cols[i].width > 0;
}

/* What the row costs with one-cell gaps and the flex column at zero. */
static size_t table_need(const Column cols[COL_COUNT], const TuiView *view) {
    size_t need = 2;
    int first = 1;
    for (int i = 0; i < COL_COUNT; ++i) {
        if (!col_drawn(cols, view, i)) {
            continue;
        }
        if (!first) {
            need += 1;
        }
        first = 0;
        need += cols[i].width;
    }
    return need;
}

static size_t table_drawn(const Column cols[COL_COUNT], const TuiView *view) {
    size_t n = 0;
    for (int i = 0; i < COL_COUNT; ++i) {
        n += col_drawn(cols, view, i) != 0;
    }
    return n;
}

static size_t table_base(Column cols[COL_COUNT], const Column base[COL_COUNT],
                         const TuiView *view, size_t flags_w) {
    for (int i = 0; i < COL_COUNT; ++i) {
        cols[i] = base[i];
        if (!view->col_visible[i]) {
            cols[i].width = 0;
        }
    }
    cols[COL_COMMAND].width = 0; /* the flex column, filled in at the end */
    if (cols[COL_FLAGS].width < flags_w) {
        cols[COL_FLAGS].width = flags_w;
    }
    return table_need(cols, view);
}

static size_t table_columns(Column cols[COL_COUNT], size_t inner, const TuiView *view,
                            size_t flags_w) {
    static const Column roomy[COL_COUNT] = {
        { "PID", 7, 1 },  { "USER", 10, 0 },  { "COMMAND", 0, 0 },
        { "STATE", 5, 0 }, { "CPU%", 7, 1 },  { "MEM", 9, 1 },
        { "TIME+", 10, 1 }, { "FLAGS", 8, 0 }, { "PERMS", 10, 0 },
    };
    static const Column compact[COL_COUNT] = {
        { "PID", 6, 1 },  { "USER", 8, 0 },   { "COMMAND", 0, 0 },
        { "STATE", 5, 0 }, { "CPU%", 6, 1 },  { "MEM", 8, 1 },
        { "TIME+", 9, 1 }, { "FLAGS", 7, 0 }, { "PERMS", 10, 0 },
    };
    size_t need = table_base(cols, roomy, view, flags_w);
    if (inner < need + 16) {
        need = table_base(cols, compact, view, flags_w);
    }

    /* Narrow terminals drop columns from the right, as config.example says.
     * FLAGS is exempt: it is the column this table is read for, and the whole
     * point of sizing it from its content is that it must not be cut. PID is
     * exempt because the table always needs a row identity. A visible COMMAND
     * asks for a readable minimum, so one more fixed column may give way
     * instead of leaving the flex column at zero. */
    size_t reserve = view->col_visible[COL_COMMAND] ? COMMAND_MIN + 1 : 0;
    while (need + reserve > inner) {
        int drop = -1;
        for (int i = COL_COUNT - 1; i >= 0; --i) {
            if (i == COL_FLAGS || i == COL_PID) {
                continue;
            }
            if (col_drawn(cols, view, i)) {
                drop = i;
                break;
            }
        }
        if (drop < 0) {
            break;
        }
        cols[drop].width = 0;
        need = table_need(cols, view);
    }

    size_t others = table_drawn(cols, view);
    size_t gap = 1;
    if (!view->col_visible[COL_COMMAND]) {
        if (others > 1 && inner > need) {
            size_t extra = (inner - need) / (others - 1);
            gap += extra < GAP_MAX - 1 ? extra : GAP_MAX - 1;
        }
        return gap;
    }

    /* COMMAND takes what is left: first let the gaps breathe while the command
     * still gets the width it wants, then hand it every remaining cell. */
    for (;;) {
        size_t used = need + (gap - 1) * others + gap;
        size_t room = inner > used ? inner - used : 0;
        if (room < COMMAND_MIN) {
            break;
        }
        if (room <= COMMAND_WANT || gap >= GAP_MAX) {
            cols[COL_COMMAND].width = room;
            return gap;
        }
        gap++;
    }

    /* No usable command column after all: spread the slack over the gaps. */
    if (others > 1 && inner > need) {
        size_t extra = (inner - need) / (others - 1);
        gap += extra < GAP_MAX - 1 ? extra : GAP_MAX - 1;
    }
    return gap;
}

/* The FLAGS cell in mode 1 carries text, so the column has to be as wide as
 * the longest tag string any painted row can produce. Modes 2 and 3 put the
 * level or "ok" there instead, which the base widths already cover. */
static size_t flags_column_width(const ProcList *procs) {
    if (g_mode >= 2 || procs == NULL) {
        return 0;
    }
    size_t widest = 0;
    char cell_text[48];
    for (size_t i = 0; i < procs->count; ++i) {
        flags_format_tui(procs->items[i].flags, cell_text, sizeof(cell_text));
        size_t w = display_width(cell_text);
        if (w > widest) {
            widest = w;
        }
    }
    return widest;
}

static Rgb state_color(char st) {
    switch (st) {
    case 'R': return C_GREEN;
    case 'D': return C_ORANGE;
    case 'Z':
    case 'X': return C_RED;
    case 'T':
    case 't': return C_YELLOW;
    default:  return C_LABEL;
    }
}

static void table_head(Out *o, const Ctx *c, const Column *cols, size_t gap, size_t inner) {
    size_t end = o->col + inner;
    size_t outer = o->limit;
    o->limit = end;
    bg(o, C_HEAD_BG);
    spaces(o, 1);
    int first = 1;
    for (int i = 0; i < COL_COUNT; ++i) {
        if (!col_drawn(cols, c->view, i)) {
            continue;
        }
        int sorted = (SortColumn)i == c->view->sort_col;
        char name[24];
        snprintf(name, sizeof(name), "%s", cols[i].name);
        if (!first) {
            spaces(o, gap);
        }
        first = 0;
        bold(o);
        if ((SortColumn)i == c->view->sel_col) {
            bg(o, C_ACCENT);
            fg(o, C_INK);
        } else {
            fg(o, (SortColumn)i == c->view->sort_col ? C_ACCENT : C_VALUE);
        }
        /* the arrow keeps its own cell, so a narrow column truncates the name, not the marker */
        size_t nw = (sorted && cols[i].width > 1) ? cols[i].width - 1 : cols[i].width;
        cell(o, name, nw, cols[i].right);
        if (sorted && cols[i].width > 1) {
            bold(o);
            cell(o, c->view->sort_desc ? "\xe2\x86\x93" : "\xe2\x86\x91", 1, 0);
        }
        reset(o);
        bg(o, C_HEAD_BG);
    }
    fill_to(o, end);
    reset(o);
    o->limit = outer;
}

static void table_row(Out *o, const ProcessInfo *p, const Column *cols, size_t gap, size_t inner, int selected, const TuiView *view) {
    char tmp[64];
    size_t end = o->col + inner;
    size_t outer = o->limit;
    int hot = selected && view->highlight_row;
    o->limit = end;
    if (hot) {
        bg(o, C_SEL_BG);
    }
    spaces(o, 1);
    int first = 1;
    for (int i = 0; i < COL_COUNT; ++i) {
        if (!col_drawn(cols, view, i)) {
            continue;
        }
        if (!first) {
            spaces(o, gap);
        }
        first = 0;
        const char *s = tmp;
        Rgb color = C_VALUE;
        Rgb cell_bg = C_VALUE;
        int has_cell_bg = 0;
        int strong = 0;
        switch ((SortColumn)i) {
        case COL_PID:
            snprintf(tmp, sizeof(tmp), "%d", (int)p->pid);
            color = C_LABEL;
            break;
        case COL_USER:
            s = p->user;
            color = strcmp(p->user, "root") == 0 ? C_ROOT : C_USER;
            break;
        case COL_COMMAND:
            s = p->comm;
            strong = 1;
            break;
        case COL_STATE:
            snprintf(tmp, sizeof(tmp), "%c", p->state);
            color = state_color(p->state);
            strong = p->state == 'R';
            break;
        case COL_CPU:
            snprintf(tmp, sizeof(tmp), "%.1f", p->cpu_pct);
            color = p->cpu_pct < 0.05 ? C_DIM : heat(p->cpu_pct / 100.0);
            break;
        case COL_MEM:
            fmt_bytes(p->rss_bytes, tmp, sizeof(tmp));
            break;
        case COL_TIME:
            s = p->time_plus;
            color = C_LABEL;
            break;
        case COL_FLAGS: {
            /* tmp still holds the previous column's text; the FLAGS cell must
             * never inherit it, so it starts from a neutral dash. */
            FlagCell fc = flag_cell_state(p);
            snprintf(tmp, sizeof(tmp), "%s", "-");
            switch (fc) {
            case FLAG_CELL_TAGS:
                /* Mode 1, vanilla: no model, no rule-derived verdicts. The
                 * column is normally turned off in the config; when it is on
                 * it shows the local rule bits and nothing else. */
                flags_format_tui(p->flags, tmp, sizeof(tmp));
                color = C_DIM;
                break;
            case FLAG_CELL_NONE:
                color = C_DIM; /* no verdict yet */
                break;
            case FLAG_CELL_MUTED:
                color = C_DIM; /* model client failed: no verdict to paint */
                break;
            case FLAG_CELL_TRUSTED:
                /* Known-safe by plan 6.4: a kernel thread, a package-owned
                 * binary from core/extra, or a direct systemd child. The model
                 * skips it on purpose, so say so instead of leaving the cell
                 * indistinguishable from "not scored yet". */
                snprintf(tmp, sizeof(tmp), "%s", "ok");
                color = C_TRUST_FG;
                break;
            case FLAG_CELL_CLEAR:
            case FLAG_CELL_MALICIOUS:
                snprintf(tmp, sizeof(tmp), "%d", p->risk);
                if (fc == FLAG_CELL_MALICIOUS) {
                    color = C_RISK_FG;
                    cell_bg = C_RISK_BG;
                } else {
                    color = C_SAFE_FG;
                    cell_bg = C_SAFE_BG;
                }
                has_cell_bg = 1;
                strong = 1;
                break;
            case FLAG_CELL_QUEUED:
                snprintf(tmp, sizeof(tmp), "%d", p->risk);
                color = C_DIM; /* queued for the LLM, no answer yet */
                break;
            case FLAG_CELL_UNREVIEWED:
                snprintf(tmp, sizeof(tmp), "%d", p->risk);
                color = C_ORANGE;
                strong = 1;
                break;
            }
            break;
        }
        case COL_PERMS:
            s = p->perms[0] ? p->perms : "-";
            color = (p->perms[0] && p->perms[8] == 'w') ? C_ORANGE : C_DIM;
            break;
        default:
            tmp[0] = '\0';
            break;
        }
        if (hot && color.r == C_DIM.r && color.g == C_DIM.g && color.b == C_DIM.b) {
            color = C_LABEL; /* dim is unreadable on the selected-row background */
        }
        if (hot && (SortColumn)i == view->sel_col) {
            bg(o, C_SEL_HOT);
            color = C_INK;
            strong = 1;
            has_cell_bg = 0;
        }
        if (has_cell_bg) {
            bg(o, cell_bg);
        }
        if (strong) {
            bold(o);
        }
        fg(o, color);
        cell(o, s, cols[i].width, cols[i].right);
        reset(o);
        if (hot) {
            bg(o, C_SEL_BG);
        }
    }
    fill_to(o, end);
    reset(o);
    o->limit = outer;
}

static void first_sentence(const char *detail, char *out, size_t sz) {
    if (out == NULL || sz == 0) {
        return;
    }
    out[0] = '\0';
    const char *p = detail;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
        p++;
    }
    size_t n = 0;
    while (*p != '\0' && *p != '\n' && *p != '\r' && n + 1 < sz) {
        out[n++] = *p;
        if (*p == '.' || *p == '!' || *p == '?') {
            char next = p[1];
            if (next == '\0' || next == '\n' || next == '\r' ||
                next == ' ' || next == '\t') {
                p++;
                break;
            }
        }
        p++;
    }
    while (n > 0 && (out[n - 1] == ' ' || out[n - 1] == '\t')) {
        out[--n] = '\0';
    }
    out[n] = '\0';
}

static void render_footer(Out *o, const Ctx *c, size_t width, int line) {
    static const char *const keys[][2] = {
        { "h/l", "column" }, { "j/k", "row" }, { "s", "sort" },
        { "x", "kill" }, { "f", "follow" }, { "esc", "clear" }, { "q", "quit" },
    };
    size_t end = o->col + width;
    const ProcessInfo *sel = NULL;
    if (c->view->sel_row >= 0 &&
        (size_t)c->view->sel_row < c->procs->count) {
        sel = &c->procs->items[c->view->sel_row];
    }
    spaces(o, 1);

    if (line > 0) {
        if (c->view->status == NULL && sel != NULL &&
            sel->llm_reason[0] != '\0' && sel->llm_detail[0] != '\0') {
            char sentence[sizeof(sel->llm_detail)];
            char safe[sizeof(sel->llm_detail)];
            first_sentence(sel->llm_detail, sentence, sizeof(sentence));
            sanitize_display_str(safe, sizeof(safe), sentence);
            if (safe[0] != '\0') {
                fg(o, C_LABEL);
                cell(o, safe, width - 1, 0);
                reset(o);
                return;
            }
        }
        spaces(o, width - 1);
        return;
    }

    if (c->view->status != NULL) {
        fg(o, C_YELLOW);
        bold(o);
        cell(o, c->view->status, width - 1, 0);
        reset(o);
        return;
    }
    if (!c->view->highlight_row && sel != NULL) {
        /* Nothing marks the row, so name it for as long as it stays selected:
         * x kill targets it and the user has to see where that lands. */
        char line_buf[192];
        char safe[192];
        if (sel->llm_reason[0] != '\0') {
            snprintf(line_buf, sizeof(line_buf), "row %d  pid %d  %s: %s",
                     (int)c->view->sel_row, (int)sel->pid, sel->comm, sel->llm_reason);
        } else {
            snprintf(line_buf, sizeof(line_buf), "row %d  pid %d  %s",
                     (int)c->view->sel_row, (int)sel->pid, sel->comm);
        }
        sanitize_display_str(safe, sizeof(safe), line_buf);
        fg(o, sel->llm_verdict == 1 ? C_RISK_FG :
               sel->llm_verdict == 0 ? C_SAFE_FG : C_LABEL);
        bold(o);
        cell(o, safe, width - 1, 0);
        reset(o);
        return;
    }
    if (sel != NULL && sel->llm_reason[0] != '\0') {
        char line_buf[192];
        char safe[192];
        snprintf(line_buf, sizeof(line_buf), "pid %d %s: %s",
                 (int)sel->pid, sel->comm, sel->llm_reason);
        sanitize_display_str(safe, sizeof(safe), line_buf);
        fg(o, sel->llm_verdict == 1 ? C_RISK_FG :
               sel->llm_verdict == 0 ? C_SAFE_FG : C_VALUE);
        bold(o);
        cell(o, safe, width - 1, 0);
        reset(o);
        return;
    }
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        size_t need = display_width(keys[i][0]) + display_width(keys[i][1]) + 4;
        if (o->col + need > end) {
            break;
        }
        bold(o);
        fg(o, C_ACCENT);
        text(o, keys[i][0]);
        reset(o);
        fg(o, C_LABEL);
        text(o, " ");
        text(o, keys[i][1]);
        reset(o);
        spaces(o, 3);
    }
    const char *brand = "minitop";
    size_t bw = display_width(brand) + 1;
    if (o->col + bw <= end) {
        fill_to(o, end - bw);
        fg(o, C_DIM);
        text(o, brand);
        reset(o);
    }
    fill_to(o, end);
}

static void render_small(Out *o, int width, int height) {
    char msg[64];
    snprintf(msg, sizeof(msg), "terminal too small: %dx%d, need %dx%d", width, height, MIN_WIDTH, MIN_HEIGHT);
    for (int y = 0; y < height; ++y) {
        o->col = 0;
        if (y == height / 2) {
            fg(o, C_YELLOW);
            cell(o, msg, (size_t)width, 0);
            reset(o);
        } else {
            spaces(o, (size_t)width);
        }
        if (y + 1 < height) {
            buf_puts(o->b, "\r\n");
        }
    }
}

int tui_render(TuiBuf *out, int width, int height,
               const SystemInfo *sys, const GpuInfo *gpu, const ProcSummary *sum,
               const ProcList *procs, const TuiView *view) {
    if (out == NULL || sys == NULL || sum == NULL || procs == NULL || view == NULL ||
        width <= 0 || height <= 0) {
        return -1;
    }
    tui_buf_reset(out);
    Out o = { out, 0, (size_t)width };
    buf_puts(out, "\x1b[H\x1b[0m");
    if (width < MIN_WIDTH || height < MIN_HEIGHT) {
        render_small(&o, width, height);
        return out->failed ? -1 : 0;
    }

    DiskList parents;
    DiskTree tree;
    if (sysinfo_disks_aggregate(&sys->disks, &parents) != 0) {
        memset(&parents, 0, sizeof(parents));
    }
    disk_tree_build(&sys->disks, &parents, &tree);
    Ctx c = { sys, gpu, sum, procs, view, &sys->disks, &parents, &tree, 0 };
    size_t w = (size_t)width;
    size_t inner = w - 2;
    Column cols[COL_COUNT];
    size_t gap = table_columns(cols, inner, view, flags_column_width(procs));

    int detail = 0;
    if (view->status == NULL && view->sel_row >= 0 &&
        (size_t)view->sel_row < procs->count) {
        const ProcessInfo *sel = &procs->items[view->sel_row];
        detail = sel->llm_reason[0] != '\0' && sel->llm_detail[0] != '\0';
    }
    int footer_rows = footer_rows_for(height, detail);
    size_t rows = tui_table_rows_detail(height, detail);
    size_t first = view->scroll;
    if (view->sel_row >= 0) {
        size_t sel = (size_t)view->sel_row;
        if (sel < first) {
            first = sel;
        } else if (rows > 0 && sel >= first + rows) {
            first = sel - rows + 1;
        }
    }
    if (first > procs->count) {
        first = procs->count;
    }
    size_t shown = procs->count - first < rows ? procs->count - first : rows;

    /* The only portrait trigger: any row in the list carries a malicious FLAGS
     * verdict, even one below the fold. The face is a system indicator rather
     * than a copy of the visible table, and it reads the same state the cell
     * paint uses, so a red cell and red glasses always agree. */
    for (size_t i = 0; i < procs->count && !c.alert; ++i) {
        c.alert = flag_cell_state(&procs->items[i]) == FLAG_CELL_MALICIOUS;
    }

    char top_note[48], bottom_note[80];
    snprintf(top_note, sizeof(top_note), "%zu procs", procs->count);
    char follow_note[24] = "";
    if (view->follow_pid > 0) {
        snprintf(follow_note, sizeof(follow_note), "follow %d \xc2\xb7 ", (int)view->follow_pid);
    }
    if (shown > 0) {
        snprintf(bottom_note, sizeof(bottom_note), "%s%zu-%zu of %zu", follow_note, first + 1, first + shown, procs->count);
    } else {
        snprintf(bottom_note, sizeof(bottom_note), "%s0 of %zu", follow_note, procs->count);
    }

    for (int y = 0; y < height; ++y) {
        o.col = 0;
        if (y < HEADER_ROWS) {
            render_header(&o, &c, w, y);
        } else if (y == HEADER_ROWS) {
            spaces(&o, w); /* blank row: the header boxes must not touch proc */
        } else if (y == HEADER_ROWS + HEADER_GAP) {
            border_line(&o, w, "\xe2\x94\x8c", "\xe2\x94\x90", "proc", top_note);
        } else if (y == height - footer_rows - 1) {
            border_line(&o, w, "\xe2\x94\x94", "\xe2\x94\x98", NULL, bottom_note);
        } else if (y >= height - footer_rows) {
            render_footer(&o, &c, w, y - (height - footer_rows));
        } else {
            side(&o);
            if (y == HEADER_ROWS + HEADER_GAP + 1) {
                table_head(&o, &c, cols, gap, inner);
            } else {
                size_t r = (size_t)(y - (HEADER_ROWS + HEADER_GAP + 2));
                if (r < shown) {
                    size_t idx = first + r;
                    table_row(&o, &procs->items[idx], cols, gap, inner,
                              (ssize_t)idx == view->sel_row, view);
                } else {
                    spaces(&o, inner);
                }
            }
            side(&o);
        }
        reset(&o);
        if (y + 1 < height) {
            buf_puts(out, "\r\n");
        }
    }
    return out->failed ? -1 : 0;
}
