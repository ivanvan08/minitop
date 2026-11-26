#include "config.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CONFIG_LINE_MAX 256
#define CONFIG_FILE_MAX 16384

/* The documented template, byte for byte the content of docs/config.example.
 * It is embedded instead of read at run time so a single binary can create a
 * usable config; test_config compares the two and the parsed defaults, so the
 * three cannot drift apart. mkstemp keeps the ".tmp.XXXXXX" shape of the
 * temporary name out of this text. */
static const char CONFIG_TEMPLATE[] =
    "# minitop configuration\n"
    "# minitop writes this file on first run when it is absent and never touches\n"
    "# it again; edit it and the next start picks the changes up.\n"
    "# Path: $XDG_CONFIG_HOME/minitop/config, else ~/.config/minitop/config.\n"
    "# Override at runtime with: minitop --config PATH\n"
    "# Format: key = value. '#' starts a comment. An unknown key or a bad value\n"
    "# stops parsing at that line with a message on stderr; keys above it stay\n"
    "# applied and the rest of the file is ignored.\n"
    "\n"
    "# --- runtime mode ---\n"
    "# 1 vanilla: no model, no LLM, no network call at all. Set column.flags = false\n"
    "#   to drop the column, since without a model there is no verdict to show.\n"
    "# 2 decision model only: the FLAGS cell carries the level (1..10) and turns red\n"
    "#   at or above model.threshold, blue below it.\n"
    "# 3 model as a filter: every process the model puts at or above the threshold\n"
    "#   is sent to the LLM, and only the LLM's reasoned verdict paints a cell red.\n"
    "#   Rows above the threshold stay dim while their answer is in flight, and a\n"
    "#   level below the threshold is final: it stays blue. A row above the threshold\n"
    "#   whose LLM can never answer, because the stage failed to start (a missing key\n"
    "#   file, for example), is painted in the attention colour (242,168,58): it is\n"
    "#   flagged and unreviewed, which is neither of the two verdict colours.\n"
    "# mode wins over model.enabled and llm.enabled, so the two engine blocks below\n"
    "# cannot contradict it. The built-in default is 1; this file ships that default\n"
    "# so copying it verbatim costs no network call.\n"
    "mode = 1\n"
    "\n"
    "# --- refresh ---\n"
    "# Frame interval in milliseconds (200..60000).\n"
    "refresh_ms = 1000\n"
    "# How often disk usage is re-read, in seconds (1..3600); statvfs is not free.\n"
    "disk_refresh_sec = 5\n"
    "\n"
    "# --- panels ---\n"
    "# Setting this to false hides the right header panel (the \"ceo\" portrait)\n"
    "# entirely, even on terminals wide enough to show it. Below 100 columns the\n"
    "# panel is not drawn at all, so the key changes nothing there.\n"
    "show_portrait = true\n"
    "# Read GPU utilisation, VRAM and clock once per frame; the probe runs an\n"
    "# external command that costs about 20 ms per frame, so turn it off to save it.\n"
    "gpu = true\n"
    "\n"
    "# --- table ---\n"
    "# Column the table is sorted by: pid,user,command,state,cpu,mem,time,flags,perms.\n"
    "# Hiding that column moves the sort to the first visible one, and the arrow\n"
    "# follows, so the table never claims an order it does not use.\n"
    "sort_column = cpu\n"
    "# true sorts largest first, false reverses the order.\n"
    "sort_desc = true\n"
    "# Draw a background on the selected row. With false nothing marks the row, but\n"
    "# x kill still targets it, so the footer names the selected row instead.\n"
    "highlight_row = true\n"
    "# Navigation keys: h/l, j/k, s, x, f and the arrows. Set to false for a table\n"
    "# that only reports: nothing moves, nothing sorts, nothing can be killed, and\n"
    "# q still quits.\n"
    "navigation = true\n"
    "\n"
    "# --- columns: set any key to false to hide that table column ---\n"
    "# With every column false the PID column is shown anyway, and the sort and the\n"
    "# selection fall back to it, so the table never sorts or kills by a column that\n"
    "# is not on screen. Narrow terminals drop columns from the right when the row\n"
    "# does not fit, without a message. FLAGS is never dropped: the column is sized\n"
    "# to the widest tag text in the pass (up to \"DEL,TMP,MEMFD,NET\"), so all four\n"
    "# tags stay readable even at 60 columns.\n"
    "# Show the PID column.\n"
    "column.pid = true\n"
    "# Show the USER column.\n"
    "column.user = true\n"
    "# Show the COMMAND column.\n"
    "column.command = true\n"
    "# Show the STATE column.\n"
    "column.state = true\n"
    "# Show the CPU% column.\n"
    "column.cpu = true\n"
    "# Show the MEM column.\n"
    "column.mem = true\n"
    "# Show the TIME+ column.\n"
    "column.time = true\n"
    "# Show the FLAGS column: DEL/TMP/MEMFD/NET text in mode 1, the model verdict\n"
    "# colour in modes 2 and 3.\n"
    "column.flags = true\n"
    "# Show the PERMS column.\n"
    "column.perms = true\n"
    "\n"
    "# --- decision model (v0.4) ---\n"
    "# Turn the model on; minitop makes no network calls while this is false. Modes 2\n"
    "# and 3 force this on regardless, so the line only decides anything in mode 1.\n"
    "model.enabled = false\n"
    "# Print the request for the first non-trusted process and exit, without a key\n"
    "# or any network call. Works in every mode, whether or not model.enabled is set;\n"
    "# if llm.dry_run is also true, the LLM preview wins.\n"
    "model.dry_run = false\n"
    "# Decisions endpoint that receives the JSON request.\n"
    "model.endpoint = https://openrouter.ai/api/alpha/decisions\n"
    "# Model id sent in the request and written to the report. mammoth wins the\n"
    "# 2026-11-26 run on 32 labelled cases: 31/32 against 30/32 for jev, and it is\n"
    "# the only working model that flags the ELF listener. baseten/bison-1 scores\n"
    "# best on paper but its provider answers HTTP 429 in waves.\n"
    "model.name = baseten/mammoth-1\n"
    "# File that holds the API key; it must be readable by the user running minitop.\n"
    "model.key_file = ~/.config/minitop/openrouter.key\n"
    "# Risk level (1..10) at which FLAGS turns red on dark red; below it is blue on\n"
    "# dark blue. Level 5 is the first concrete evasion level, so ordinary and\n"
    "# merely unusual activity stays blue.\n"
    "model.threshold = 5\n"
    "# Re-score each process after a randomised 0.8..1.2 times this many seconds.\n"
    "model.resample_sec = 1500\n"
    "# Maximum new model requests queued by one refresh pass.\n"
    "model.max_per_pass = 300\n"
    "# Append one JSON line per verdict (pid, comm, level, timestamp, model); no\n"
    "# cmdline is ever written, and \"none\" disables the report.\n"
    "model.report_path = llm_log\n"
    "\n"
    "# --- uncertain-band LLM (v0.4) ---\n"
    "# Send a process to the chat model only when its decision level is inside the\n"
    "# uncertain band; the stage is off by default and makes no network calls.\n"
    "llm.enabled = false\n"
    "# DeepSeek reasoning snapshot ($0.15/M prompt, $0.60/M completion, verified\n"
    "# 2026-11-25). It answers in 1.6 s for 456 tokens on the deleted-binary fixture\n"
    "# against 5.4 s and 295 tokens for deepseek/deepseek-chat, and names the reason\n"
    "# better, so it is the default. Hidden reasoning is billed as completion, and a\n"
    "# slow case can spend the whole budget before it writes the verdict, which is\n"
    "# why llm.max_tokens is 4000 and not a few hundred.\n"
    "llm.name = deepseek/deepseek-v4.1-flash-1017\n"
    "# Endpoint that receives the chat-completions request. It must speak the\n"
    "# OpenAI-compatible chat-completions API: a POST with a Bearer key and a body\n"
    "# of model, messages, temperature, max_tokens and usage; the text is read from\n"
    "# choices[0].message.content and the token counts from usage.\n"
    "llm.endpoint = https://openrouter.ai/api/v1/chat/completions\n"
    "# File that holds the OpenRouter key, read into memory and never logged.\n"
    "llm.key_file = ~/.config/minitop/openrouter.key\n"
    "# Lowest decision level that is sent to the LLM, inclusive (3 leaves clearly safe processes out).\n"
    "# Mode 3 derives this band from model.threshold..10, because there the model is\n"
    "# the filter, so both keys below are ignored whenever the LLM actually runs;\n"
    "# they are read only by llm_engine_create callers other than mode 3.\n"
    "llm.min_level = 3\n"
    "# Highest decision level that is sent to the LLM, inclusive (7 leaves clearly malicious processes out).\n"
    "llm.max_level = 7\n"
    "# Minimum seconds before the same process may be sent to the LLM again.\n"
    "llm.resample_sec = 1800\n"
    "# Maximum new LLM requests queued by one refresh pass.\n"
    "llm.max_per_pass = 10\n"
    "# Maximum completion tokens per answer, including hidden reasoning tokens.\n"
    "# The prompt asks for the VERDICT line first and at most three short reasoning\n"
    "# sentences, so a slow case still has room left after the verdict.\n"
    "llm.max_tokens = 4000\n"
    "# Append one JSON line per LLM verdict (pid, comm, verdict, reason, detail,\n"
    "# truncated flag, model, timestamp, prompt/completion/reasoning tokens and\n"
    "# cost); \"none\" disables it.\n"
    "llm.report_path = llm_verdicts.jsonl\n"
    "# Print the first LLM request and exit without reading the key or using the network, even when llm.enabled is false.\n"
    "llm.dry_run = false\n"
    ;

static const struct SortName {
    const char *name;
    SortColumn  col;
} SORT_NAMES[] = {
    { "pid",     COL_PID },
    { "user",    COL_USER },
    { "command", COL_COMMAND },
    { "state",   COL_STATE },
    { "cpu",     COL_CPU },
    { "mem",     COL_MEM },
    { "time",    COL_TIME },
    { "flags",   COL_FLAGS },
    { "perms",   COL_PERMS },
};

static void set_err(char *err, size_t err_sz, const char *fmt, ...) {
    va_list ap;

    if (err == NULL || err_sz == 0) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(err, err_sz, fmt, ap);
    va_end(ap);
}

static char *trim(char *s) {
    char *end;

    while (*s == ' ' || *s == '\t' || *s == '\r') {
        s++;
    }
    end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r')) {
        end--;
    }
    *end = '\0';
    return s;
}

static int parse_long(const char *s, long *out) {
    char *end = NULL;
    long v;

    if (*s == '\0') {
        return -1;
    }
    /* ERANGE saturates to LONG_MIN/LONG_MAX, which the clamp handles */
    v = strtol(s, &end, 10);
    if (end == s || *end != '\0') {
        return -1;
    }
    *out = v;
    return 0;
}

static int parse_bool(const char *s, int *out) {
    if (strcasecmp(s, "true") == 0 || strcmp(s, "1") == 0 ||
        strcasecmp(s, "yes") == 0) {
        *out = 1;
        return 0;
    }
    if (strcasecmp(s, "false") == 0 || strcmp(s, "0") == 0 ||
        strcasecmp(s, "no") == 0) {
        *out = 0;
        return 0;
    }
    return -1;
}

static int lookup_sort_column(const char *name, SortColumn *out) {
    size_t i;

    for (i = 0; i < sizeof(SORT_NAMES) / sizeof(SORT_NAMES[0]); i++) {
        if (strcmp(name, SORT_NAMES[i].name) == 0) {
            *out = SORT_NAMES[i].col;
            return 0;
        }
    }
    return -1;
}

static long clamp_long(long v, long lo, long hi) {
    if (v < lo) {
        return lo;
    }
    if (v > hi) {
        return hi;
    }
    return v;
}

static int set_string(char *dst, size_t sz, const char *val) {
    size_t n = strlen(val);
    if (n >= sz) {
        return -1;
    }
    memcpy(dst, val, n + 1);
    return 0;
}

static int apply_line(const char *raw, int lineno, MiniConfig *cfg,
                      char *err, size_t err_sz) {
    char line[CONFIG_LINE_MAX];
    size_t len = strcspn(raw, "\n");
    char *key, *val, *hash, *eq;
    long lv;
    int bv;
    SortColumn sc;

    if (len >= sizeof(line)) {
        set_err(err, err_sz, "config: line %d: line too long", lineno);
        return -1;
    }
    memcpy(line, raw, len);
    line[len] = '\0';

    hash = strchr(line, '#');
    if (hash != NULL) {
        *hash = '\0';
    }

    key = trim(line);
    if (*key == '\0') {
        return 0;
    }

    eq = strchr(key, '=');
    if (eq == NULL) {
        set_err(err, err_sz, "config: line %d: expected \"key = value\"", lineno);
        return -1;
    }
    *eq = '\0';
    val = trim(eq + 1);
    key = trim(key);
    if (*key == '\0') {
        set_err(err, err_sz, "config: line %d: missing key before '='", lineno);
        return -1;
    }
    if (*val == '\0') {
        set_err(err, err_sz, "config: line %d: missing value for \"%s\"",
                lineno, key);
        return -1;
    }

    if (strcmp(key, "refresh_ms") == 0) {
        if (parse_long(val, &lv) != 0) {
            goto bad_value;
        }
        cfg->refresh_ms = (int)clamp_long(lv, 200, 60000);
        return 0;
    }
    if (strcmp(key, "disk_refresh_sec") == 0) {
        if (parse_long(val, &lv) != 0) {
            goto bad_value;
        }
        cfg->disk_refresh_sec = (int)clamp_long(lv, 1, 3600);
        return 0;
    }
    if (strcmp(key, "show_portrait") == 0) {
        if (parse_bool(val, &bv) != 0) {
            goto bad_value;
        }
        cfg->show_portrait = bv;
        return 0;
    }
    if (strcmp(key, "gpu") == 0) {
        if (parse_bool(val, &bv) != 0) {
            goto bad_value;
        }
        cfg->gpu = bv;
        return 0;
    }
    if (strcmp(key, "highlight_row") == 0) {
        if (parse_bool(val, &bv) != 0) {
            goto bad_value;
        }
        cfg->highlight_row = bv;
        return 0;
    }
    if (strcmp(key, "navigation") == 0) {
        if (parse_bool(val, &bv) != 0) {
            goto bad_value;
        }
        cfg->navigation = bv;
        return 0;
    }
    if (strcmp(key, "sort_column") == 0) {
        if (lookup_sort_column(val, &sc) != 0) {
            goto bad_value;
        }
        cfg->sort_col = sc;
        return 0;
    }
    if (strcmp(key, "sort_desc") == 0) {
        if (parse_bool(val, &bv) != 0) {
            goto bad_value;
        }
        cfg->sort_desc = bv;
        return 0;
    }
    if (strncmp(key, "column.", 7) == 0) {
        if (lookup_sort_column(key + 7, &sc) != 0) {
            set_err(err, err_sz, "config: line %d: unknown key \"%s\"",
                    lineno, key);
            return -1;
        }
        if (parse_bool(val, &bv) != 0) {
            goto bad_value;
        }
        cfg->columns[sc] = bv;
        return 0;
    }

    if (strcmp(key, "model.enabled") == 0) {
        if (parse_bool(val, &bv) != 0) {
            goto bad_value;
        }
        cfg->model.enabled = bv;
        return 0;
    }
    if (strcmp(key, "model.dry_run") == 0) {
        if (parse_bool(val, &bv) != 0) {
            goto bad_value;
        }
        cfg->model.dry_run = bv;
        return 0;
    }
    if (strcmp(key, "model.endpoint") == 0) {
        if (set_string(cfg->model.endpoint, sizeof(cfg->model.endpoint), val) != 0) {
            goto bad_value;
        }
        return 0;
    }
    if (strcmp(key, "model.name") == 0) {
        if (set_string(cfg->model.name, sizeof(cfg->model.name), val) != 0) {
            goto bad_value;
        }
        return 0;
    }
    if (strcmp(key, "model.key_file") == 0) {
        if (set_string(cfg->model.key_file, sizeof(cfg->model.key_file), val) != 0) {
            goto bad_value;
        }
        return 0;
    }
    if (strcmp(key, "model.threshold") == 0) {
        if (parse_long(val, &lv) != 0) {
            goto bad_value;
        }
        cfg->model.threshold = (int)clamp_long(lv, 1, 10);
        return 0;
    }
    if (strcmp(key, "model.resample_sec") == 0) {
        if (parse_long(val, &lv) != 0) {
            goto bad_value;
        }
        cfg->model.resample_sec = (int)clamp_long(lv, 60, 86400);
        return 0;
    }
    if (strcmp(key, "model.max_per_pass") == 0) {
        if (parse_long(val, &lv) != 0) {
            goto bad_value;
        }
        cfg->model.max_per_pass = (int)clamp_long(lv, 1, 10000);
        return 0;
    }
    if (strcmp(key, "model.report_path") == 0) {
        if (set_string(cfg->model.report_path, sizeof(cfg->model.report_path), val) != 0) {
            goto bad_value;
        }
        return 0;
    }

    if (strcmp(key, "llm.enabled") == 0) {
        if (parse_bool(val, &bv) != 0) {
            goto bad_value;
        }
        cfg->llm.enabled = bv;
        return 0;
    }
    if (strcmp(key, "llm.dry_run") == 0) {
        if (parse_bool(val, &bv) != 0) {
            goto bad_value;
        }
        cfg->llm.dry_run = bv;
        return 0;
    }
    if (strcmp(key, "llm.name") == 0) {
        if (set_string(cfg->llm.name, sizeof(cfg->llm.name), val) != 0) {
            goto bad_value;
        }
        return 0;
    }
    if (strcmp(key, "llm.endpoint") == 0) {
        if (set_string(cfg->llm.endpoint, sizeof(cfg->llm.endpoint), val) != 0) {
            goto bad_value;
        }
        return 0;
    }
    if (strcmp(key, "llm.key_file") == 0) {
        if (set_string(cfg->llm.key_file, sizeof(cfg->llm.key_file), val) != 0) {
            goto bad_value;
        }
        return 0;
    }
    if (strcmp(key, "llm.min_level") == 0) {
        if (parse_long(val, &lv) != 0) {
            goto bad_value;
        }
        cfg->llm.min_level = (int)clamp_long(lv, 1, 10);
        return 0;
    }
    if (strcmp(key, "llm.max_level") == 0) {
        if (parse_long(val, &lv) != 0) {
            goto bad_value;
        }
        cfg->llm.max_level = (int)clamp_long(lv, 1, 10);
        return 0;
    }
    if (strcmp(key, "llm.resample_sec") == 0) {
        if (parse_long(val, &lv) != 0) {
            goto bad_value;
        }
        cfg->llm.resample_sec = (int)clamp_long(lv, 60, 86400);
        return 0;
    }
    if (strcmp(key, "llm.max_per_pass") == 0) {
        if (parse_long(val, &lv) != 0) {
            goto bad_value;
        }
        cfg->llm.max_per_pass = (int)clamp_long(lv, 1, 1000);
        return 0;
    }
    if (strcmp(key, "llm.max_tokens") == 0) {
        if (parse_long(val, &lv) != 0) {
            goto bad_value;
        }
        cfg->llm.max_tokens = (int)clamp_long(lv, 1, 16384);
        return 0;
    }
    if (strcmp(key, "mode") == 0) {
        long mv = 0;
        if (parse_long(val, &mv) != 0 || mv < 1 || mv > 3) {
            goto bad_value;
        }
        cfg->mode = (int)mv;
        return 0;
    }
    if (strcmp(key, "llm.report_path") == 0) {
        if (set_string(cfg->llm.report_path, sizeof(cfg->llm.report_path), val) != 0) {
            goto bad_value;
        }
        return 0;
    }

    set_err(err, err_sz, "config: line %d: unknown key \"%s\"", lineno, key);
    return -1;

bad_value:
    set_err(err, err_sz, "config: line %d: invalid value \"%s\" for \"%s\"",
            lineno, val, key);
    return -1;
}

void config_defaults(MiniConfig *cfg) {
    int i;

    if (cfg == NULL) {
        return;
    }
    memset(cfg, 0, sizeof(*cfg));
    cfg->mode = 1;      /* vanilla: no network at all until a mode says so */
    cfg->refresh_ms = 1000;
    cfg->disk_refresh_sec = 5;
    cfg->show_portrait = 1;
    cfg->gpu = 1; /* the GPU row is part of the cpu panel; set gpu = false to skip the probe */
    cfg->highlight_row = 1;
    cfg->navigation = 1;
    for (i = 0; i < COL_COUNT; i++) {
        cfg->columns[i] = 1;
    }
    cfg->sort_col = COL_CPU;
    cfg->sort_desc = 1;

    cfg->model.enabled = 0; /* network stays off unless asked for */
    cfg->model.dry_run = 0;
    snprintf(cfg->model.endpoint, sizeof(cfg->model.endpoint),
             "%s", "https://openrouter.ai/api/alpha/decisions");
    /* 2026-11-26 on 32 labelled cases: mammoth 31/32, jev 30/32; bison is out
     * while its provider answers HTTP 429 in waves. See docs/model-evaluation.md. */
    snprintf(cfg->model.name, sizeof(cfg->model.name), "%s", "baseten/mammoth-1");
    snprintf(cfg->model.key_file, sizeof(cfg->model.key_file),
             "%s", "~/.config/minitop/openrouter.key");
    /* level 5 is the first level whose criteria describe a concrete evasion
     * indicator (hidden/deleted binary in a temp dir); 1-4 stay blue */
    cfg->model.threshold = 5;
    cfg->model.resample_sec = 1500; /* +/-20% makes the real interval 20..30 min */
    cfg->model.max_per_pass = 300;
    snprintf(cfg->model.report_path, sizeof(cfg->model.report_path), "%s", "llm_log");

    cfg->llm.enabled = 0; /* the LLM stage is an extra network hop: opt-in only */
    cfg->llm.dry_run = 0;
    /* exact OpenRouter id verified with GET /api/v1/models on 2026-11-25;
     * the reasoning snapshot answers in 1.6 s for 456 tokens against 5.4 s and
     * 295 tokens for the chat model on the same fixture, and names the reason
     * better, so the reasoning one is the default with room for its thinking */
    snprintf(cfg->llm.name, sizeof(cfg->llm.name),
             "%s", "deepseek/deepseek-v4.1-flash-1017");
    snprintf(cfg->llm.endpoint, sizeof(cfg->llm.endpoint),
             "%s", "https://openrouter.ai/api/v1/chat/completions");
    snprintf(cfg->llm.key_file, sizeof(cfg->llm.key_file),
             "%s", "~/.config/minitop/openrouter.key");
    cfg->llm.min_level = 3; /* levels 1-2 are clearly safe: no LLM call */
    cfg->llm.max_level = 7; /* levels 8-10 are clearly malicious: no LLM call */
    cfg->llm.resample_sec = 1800;
    cfg->llm.max_per_pass = 10;
    cfg->llm.max_tokens = 4000; /* reasoning tokens are billed against this */
    snprintf(cfg->llm.report_path, sizeof(cfg->llm.report_path),
             "%s", "llm_verdicts.jsonl");
}

/* The three runtime modes of the tool. `mode` is the user-facing switch; the
 * engine booleans it implies are derived here so a config cannot end up in a
 * state the TUI does not expect (an LLM stage without its decision filter, for
 * instance).
 *
 *   1  vanilla: no model, no LLM, no network call
 *   2  decision model only: FLAGS carries the level, red at the threshold
 *   3  decision model as a filter, then the LLM reviews everything at or above
 *      the threshold and only its verdict can paint a cell red */
static void apply_mode(MiniConfig *cfg) {
    switch (cfg->mode) {
    case 1:
        cfg->model.enabled = 0;
        cfg->llm.enabled = 0;
        break;
    case 2:
        cfg->model.enabled = 1;
        cfg->llm.enabled = 0;
        break;
    case 3:
    default:
        cfg->mode = 3;
        cfg->model.enabled = 1;
        cfg->llm.enabled = 1;
        /* The band itself is derived in main.c from model.threshold, so a
         * config that tunes llm.min_level is not silently overwritten here. */
        break;
    }
}

int config_parse_text(const char *text, MiniConfig *cfg, char *err, size_t err_sz) {
    const char *p = text;
    int lineno = 1;

    if (text == NULL || cfg == NULL) {
        set_err(err, err_sz, "config: invalid argument");
        return -1;
    }

    while (*p != '\0') {
        const char *nl;

        if (apply_line(p, lineno, cfg, err, err_sz) != 0) {
            return -1;
        }
        nl = strchr(p, '\n');
        if (nl == NULL) {
            break;
        }
        p = nl + 1;
        lineno++;
    }

    apply_mode(cfg);
    return 0;
}

int config_load(MiniConfig *cfg, const char *path, char *err, size_t err_sz) {
    char defbuf[512];
    char buf[CONFIG_FILE_MAX];
    FILE *f;
    size_t n;
    int extra, failed;

    if (cfg == NULL) {
        set_err(err, err_sz, "config: invalid argument");
        return -1;
    }
    if (path == NULL) {
        if (config_default_path(defbuf, sizeof(defbuf)) == NULL) {
            set_err(err, err_sz, "config: cannot determine default path");
            return -1;
        }
        path = defbuf;
    }

    f = fopen(path, "r");
    if (f == NULL) {
        if (errno == ENOENT) {
            return 0;
        }
        set_err(err, err_sz, "config: cannot open \"%s\": %s", path, strerror(errno));
        return -1;
    }

    n = fread(buf, 1, sizeof(buf) - 1, f);
    extra = (n == sizeof(buf) - 1) ? fgetc(f) : EOF;
    failed = ferror(f);
    fclose(f);

    if (failed) {
        set_err(err, err_sz, "config: read error on \"%s\"", path);
        return -1;
    }
    if (extra != EOF) {
        set_err(err, err_sz, "config: \"%s\" is too large", path);
        return -1;
    }
    buf[n] = '\0';

    return config_parse_text(buf, cfg, err, err_sz);
}

const char *config_default_template(void) {
    return CONFIG_TEMPLATE;
}

/* mkdir -p for the directory part of a config path. Every missing component
 * is created with mode 0700 and then chmod-ed, because a strict umask would
 * otherwise leave a directory the user cannot create the file in. Existing
 * components are left untouched, so a ~/.config the user already owns keeps
 * its mode. */
static int make_dirs(const char *dir, char *err, size_t err_sz) {
    size_t len = strlen(dir);
    char *copy = malloc(len + 1);
    char *p;

    if (copy == NULL) {
        set_err(err, err_sz, "config: out of memory");
        return -1;
    }
    memcpy(copy, dir, len + 1);
    for (p = copy + 1; ; p++) {
        char saved = *p;
        int failed = 0;

        if (saved != '/' && saved != '\0') {
            continue;
        }
        *p = '\0';
        if (mkdir(copy, 0700) == 0) {
            if (chmod(copy, 0700) != 0) {
                /* The directory exists now; a failure here is only about the
                 * mode, and the open below reports the real problem. */
            }
        } else if (errno != EEXIST) {
            set_err(err, err_sz, "config: cannot create directory \"%s\": %s",
                    copy, strerror(errno));
            failed = 1;
        }
        *p = saved;
        if (failed || saved == '\0') {
            free(copy);
            return failed ? -1 : 0;
        }
    }
}

int config_create_default(const char *path, char *err, size_t err_sz) {
    static const char SUFFIX[] = ".tmp.XXXXXX";
    struct stat st;
    char *dir = NULL;
    char *tmp = NULL;
    char *slash;
    size_t path_len, tmpl_len, off;
    int fd = -1;
    int rc = -1;

    if (path == NULL || *path == '\0') {
        set_err(err, err_sz, "config: invalid argument");
        return -1;
    }
    /* An existing path is never opened, truncated or replaced, whether it
     * parses or not; the loader reports a broken file on its own. */
    if (lstat(path, &st) == 0) {
        if (!S_ISREG(st.st_mode)) {
            set_err(err, err_sz, "config: \"%s\" exists and is not a regular file",
                    path);
            return -1;
        }
        return 0;
    }
    if (errno != ENOENT) {
        set_err(err, err_sz, "config: cannot stat \"%s\": %s", path,
                strerror(errno));
        return -1;
    }

    path_len = strlen(path);
    dir = malloc(path_len + 1);
    tmp = malloc(path_len + sizeof(SUFFIX));
    if (dir == NULL || tmp == NULL) {
        set_err(err, err_sz, "config: out of memory");
        goto out;
    }
    memcpy(dir, path, path_len + 1);
    slash = strrchr(dir, '/');
    if (slash == NULL) {
        dir[0] = '.';
        dir[1] = '\0';
    } else if (slash == dir) {
        slash[1] = '\0';
    } else {
        *slash = '\0';
    }
    if (make_dirs(dir, err, err_sz) != 0) {
        goto out;
    }

    snprintf(tmp, path_len + sizeof(SUFFIX), "%s%s", path, SUFFIX);
    fd = mkstemp(tmp);
    if (fd < 0) {
        set_err(err, err_sz, "config: cannot create \"%s\": %s", path,
                strerror(errno));
        goto out;
    }
    /* mkstemp already asks for 0600; setting it again defeats a umask that
     * would leave the file unreadable for its owner. */
    if (fchmod(fd, 0600) != 0) {
        set_err(err, err_sz, "config: cannot set the mode of \"%s\": %s", tmp,
                strerror(errno));
        goto out;
    }
    tmpl_len = strlen(CONFIG_TEMPLATE);
    for (off = 0; off < tmpl_len; ) {
        ssize_t n = write(fd, CONFIG_TEMPLATE + off, tmpl_len - off);

        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            set_err(err, err_sz, "config: write error on \"%s\": %s", path,
                    n < 0 ? strerror(errno) : "short write");
            goto out;
        }
        off += (size_t)n;
    }
    if (fsync(fd) != 0) {
        set_err(err, err_sz, "config: cannot flush \"%s\": %s", path,
                strerror(errno));
        goto out;
    }
    if (close(fd) != 0) {
        fd = -1;
        set_err(err, err_sz, "config: cannot close \"%s\": %s", path,
                strerror(errno));
        goto out;
    }
    fd = -1;

    /* link() publishes the finished file under its final name in one step and
     * fails with EEXIST instead of replacing a config someone else wrote
     * between the lstat above and here. */
    if (link(tmp, path) != 0) {
        if (errno == EEXIST) {
            rc = 0;
        } else {
            set_err(err, err_sz, "config: cannot create \"%s\": %s", path,
                    strerror(errno));
        }
        goto out;
    }
    rc = 1;

out:
    if (fd >= 0) {
        close(fd);
    }
    if (tmp != NULL) {
        unlink(tmp);
    }
    free(tmp);
    free(dir);
    return rc;
}

const char *config_default_path(char *buf, size_t buf_sz) {
    const char *xdg, *home;
    int n;

    if (buf == NULL || buf_sz == 0) {
        return NULL;
    }

    xdg = getenv("XDG_CONFIG_HOME");
    if (xdg != NULL && *xdg != '\0') {
        n = snprintf(buf, buf_sz, "%s/minitop/config", xdg);
    } else {
        home = getenv("HOME");
        if (home == NULL || *home == '\0') {
            return NULL;
        }
        n = snprintf(buf, buf_sz, "%s/.config/minitop/config", home);
    }

    if (n < 0 || (size_t)n >= buf_sz) {
        return NULL;
    }
    return buf;
}
