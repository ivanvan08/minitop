#ifndef MINITOP_CONFIG_H
#define MINITOP_CONFIG_H

#include <stddef.h>

#include "procs.h"

typedef struct ModelConfig {
    int  enabled;
    int  dry_run;
    char endpoint[256];
    char name[64];
    char key_file[256];
    int  threshold;     /* 1..10; risk at or above this level paints FLAGS red */
    int  resample_sec;  /* randomised by +/-20% per process */
    int  max_per_pass;  /* new requests queued in one refresh pass */
    char report_path[256];
} ModelConfig;

typedef struct LlmConfig {
    int  enabled;
    int  dry_run;
    char endpoint[256];
    char name[64];
    char key_file[256];
    int  min_level;    /* uncertain band start, inclusive (1..10) */
    int  max_level;    /* uncertain band end, inclusive (1..10) */
    int  resample_sec; /* one LLM ask per process per this many seconds */
    int  max_per_pass; /* new requests queued in one refresh pass */
    int  max_tokens;   /* completion budget per answer, reasoning included */
    char report_path[256];
} LlmConfig;

typedef struct MiniConfig {
    int        mode;          /* 1 vanilla, 2 decision model, 3 model + LLM */
    int        refresh_ms;
    int        disk_refresh_sec;
    int        show_portrait;
    int        gpu;
    int        highlight_row;
    int        navigation;    /* 0 disables h/l, j/k, s, x, f and the arrows */
    int        columns[COL_COUNT];
    SortColumn sort_col;
    int        sort_desc;
    ModelConfig model;
    LlmConfig   llm;
} MiniConfig;

/**
 * Fills cfg with the built-in defaults: mode 1, refresh_ms 1000,
 * disk_refresh_sec 5, show_portrait 1, gpu 1, highlight_row 1, navigation 1,
 * every column visible, sort_column cpu, sort_desc 1 and the model block
 * disabled with
 * baseten/mammoth-1, threshold 5, resample_sec 1500, max_per_pass 300 and a
 * relative "llm_log" report path. The llm block is disabled with the OpenRouter
 * chat-completions URL, deepseek/deepseek-v4.1-flash-1017, levels 3..7,
 * resample_sec 1800, max_per_pass 10, max_tokens 4000 and the relative path
 * "llm_verdicts.jsonl".
 */
void config_defaults(MiniConfig *cfg);

/**
 * Applies "key = value" lines from text on top of the current cfg contents.
 * Blank lines and '#' comments (whole-line or trailing) are ignored.
 * Unknown keys and unparsable values are errors; already applied keys stay
 * applied. Integer keys are clamped to their documented range:
 * refresh_ms 200..60000, disk_refresh_sec 1..3600.
 * Booleans accept true/false/1/0/yes/no (case-insensitive).
 * sort_column accepts pid,user,command,state,cpu,mem,time,flags,perms.
 * @return 0 on success, -1 on the first error with a message in err.
 */
int config_parse_text(const char *text, MiniConfig *cfg, char *err, size_t err_sz);

/**
 * Loads path (NULL means config_default_path()). A missing file is not an
 * error and leaves cfg untouched; a malformed file yields -1.
 * @return 0 on success or missing file, -1 otherwise.
 */
int config_load(MiniConfig *cfg, const char *path, char *err, size_t err_sz);

/**
 * Writes the default config path into buf:
 * $XDG_CONFIG_HOME/minitop/config, else ~/.config/minitop/config.
 * @return buf on success, NULL when the environment or buffer is insufficient.
 */
const char *config_default_path(char *buf, size_t buf_sz);

/**
 * The documented template that ships inside the binary, byte for byte the
 * content of docs/config.example. It parses to exactly the values of
 * config_defaults(), so a file created from it changes nothing but gives the
 * user something to read and edit.
 */
const char *config_default_template(void);

/**
 * Writes config_default_template() to path when path does not exist yet.
 * Missing parent directories are created with mode 0700; the text goes to a
 * temporary file with mode 0600 in the same directory and is linked into
 * place, so a crash cannot leave a half-written file and an existing file is
 * never opened, truncated or replaced. A read-only directory, a full disk or
 * a missing HOME simply fails here; callers keep running on the defaults.
 * @return 1 when the file was created, 0 when it already existed,
 *         -1 on failure with a message in err.
 */
int config_create_default(const char *path, char *err, size_t err_sz);

#endif
