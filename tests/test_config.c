#include "config.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const struct {
    const char *name;
    SortColumn  col;
} SORT_TABLE[] = {
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

static void test_defaults(void) {
    MiniConfig cfg;
    int i;

    memset(&cfg, 0xff, sizeof(cfg));
    config_defaults(&cfg);
    assert(cfg.refresh_ms == 1000);
    assert(cfg.disk_refresh_sec == 5);
    assert(cfg.show_portrait == 1);
    assert(cfg.gpu == 1);
    assert(cfg.highlight_row == 1);
    for (i = 0; i < COL_COUNT; i++) {
        assert(cfg.columns[i] == 1);
    }
    assert(COL_COUNT == 9);
    assert(cfg.sort_col == COL_CPU);
    assert(cfg.sort_desc == 1);

    config_defaults(NULL); /* must not crash */
}

static void test_all_keys(void) {
    MiniConfig cfg;
    char err[256] = "";

    config_defaults(&cfg);
    const char *text =
        "# minitop config\n"
        "\n"
        "refresh_ms = 250\n"
        "disk_refresh_sec = 12\n"
        "show_portrait = 0\n"
        "gpu = 1\n"
        "highlight_row = no\n"
        "sort_column = mem\n"
        "sort_desc = false\n"
        "column.pid = 0\n"
        "column.user = 0\n"
        "column.command = 1\n"
        "column.state = 0\n"
        "column.cpu = 1\n"
        "column.mem = 1\n"
        "column.time = 0\n"
        "column.flags = 1\n"
        "column.perms = 0\n";

    assert(config_parse_text(text, &cfg, err, sizeof(err)) == 0);
    assert(err[0] == '\0');
    assert(cfg.refresh_ms == 250);
    assert(cfg.disk_refresh_sec == 12);
    assert(cfg.show_portrait == 0);
    assert(cfg.gpu == 1);
    assert(cfg.highlight_row == 0);
    assert(cfg.sort_col == COL_MEM);
    assert(cfg.sort_desc == 0);
    assert(cfg.columns[COL_PID] == 0);
    assert(cfg.columns[COL_USER] == 0);
    assert(cfg.columns[COL_COMMAND] == 1);
    assert(cfg.columns[COL_STATE] == 0);
    assert(cfg.columns[COL_CPU] == 1);
    assert(cfg.columns[COL_MEM] == 1);
    assert(cfg.columns[COL_TIME] == 0);
    assert(cfg.columns[COL_FLAGS] == 1);
    assert(cfg.columns[COL_PERMS] == 0);
}

static void test_sort_column_names(void) {
    MiniConfig cfg;
    char err[256];
    size_t i;

    for (i = 0; i < sizeof(SORT_TABLE) / sizeof(SORT_TABLE[0]); i++) {
        char text[64];

        config_defaults(&cfg);
        snprintf(text, sizeof(text), "sort_column = %s\n", SORT_TABLE[i].name);
        assert(config_parse_text(text, &cfg, err, sizeof(err)) == 0);
        assert(cfg.sort_col == SORT_TABLE[i].col);
    }
}

static void test_comments_and_whitespace(void) {
    MiniConfig cfg;
    char err[256];

    config_defaults(&cfg);
    assert(config_parse_text("   \n\t\n# full line comment\n"
                             "\t refresh_ms = 1500 \t# trailing comment\r\n"
                             "gpu=yes\n",
                             &cfg, err, sizeof(err)) == 0);
    assert(cfg.refresh_ms == 1500);
    assert(cfg.gpu == 1);

    /* trailing comment directly after the value */
    assert(config_parse_text("disk_refresh_sec=7#x\n", &cfg, err, sizeof(err)) == 0);
    assert(cfg.disk_refresh_sec == 7);
}

static void test_errors(void) {
    MiniConfig cfg;
    char err[256];

    config_defaults(&cfg);
    assert(config_parse_text("# comment\nrefresh_ms = 500\nfoo = 1\n",
                             &cfg, err, sizeof(err)) == -1);
    assert(strcmp(err, "config: line 3: unknown key \"foo\"") == 0);
    /* keys before the error stay applied */
    assert(cfg.refresh_ms == 500);

    config_defaults(&cfg);
    assert(config_parse_text("refresh_ms 500\n", &cfg, err, sizeof(err)) == -1);
    assert(strcmp(err, "config: line 1: expected \"key = value\"") == 0);

    config_defaults(&cfg);
    assert(config_parse_text("\n\nno_equals_here\n", &cfg, err, sizeof(err)) == -1);
    assert(strcmp(err, "config: line 3: expected \"key = value\"") == 0);

    config_defaults(&cfg);
    assert(config_parse_text("sort_column = nope\n", &cfg, err, sizeof(err)) == -1);
    assert(strcmp(err, "config: line 1: invalid value \"nope\" for \"sort_column\"") == 0);
    assert(cfg.sort_col == COL_CPU);

    config_defaults(&cfg);
    assert(config_parse_text("refresh_ms = fast\n", &cfg, err, sizeof(err)) == -1);
    assert(strcmp(err, "config: line 1: invalid value \"fast\" for \"refresh_ms\"") == 0);

    config_defaults(&cfg);
    assert(config_parse_text("refresh_ms = 500ms\n", &cfg, err, sizeof(err)) == -1);
    assert(strcmp(err, "config: line 1: invalid value \"500ms\" for \"refresh_ms\"") == 0);

    config_defaults(&cfg);
    assert(config_parse_text("gpu =\n", &cfg, err, sizeof(err)) == -1);
    assert(strcmp(err, "config: line 1: missing value for \"gpu\"") == 0);

    config_defaults(&cfg);
    assert(config_parse_text("column.bogus = 1\n", &cfg, err, sizeof(err)) == -1);
    assert(strcmp(err, "config: line 1: unknown key \"column.bogus\"") == 0);

    config_defaults(&cfg);
    assert(config_parse_text("column.cpu = maybe\n", &cfg, err, sizeof(err)) == -1);
    assert(strcmp(err, "config: line 1: invalid value \"maybe\" for \"column.cpu\"") == 0);

    config_defaults(&cfg);
    assert(config_parse_text("", &cfg, err, sizeof(err)) == 0);
    assert(config_parse_text(NULL, &cfg, err, sizeof(err)) == -1);
    assert(config_parse_text("gpu = 1\n", NULL, err, sizeof(err)) == -1);

    /* truncated error buffer stays NUL-terminated */
    config_defaults(&cfg);
    {
        char small[6];
        memset(small, 'x', sizeof(small));
        assert(config_parse_text("foo = 1\n", &cfg, small, sizeof(small)) == -1);
        assert(small[sizeof(small) - 1] == '\0');
        assert(strncmp(small, "confi", 5) == 0);
    }
    assert(config_parse_text("foo = 1\n", &cfg, NULL, 0) == -1);
    assert(config_parse_text("foo = 1\n", &cfg, err, 0) == -1);
}

static void test_boolean_spellings(void) {
    static const char *const TRUE_WORDS[] = { "true", "TRUE", "1", "yes", "YES" };
    static const char *const FALSE_WORDS[] = { "false", "False", "0", "no", "No" };
    MiniConfig cfg;
    char err[128];
    char text[64];
    size_t i;

    for (i = 0; i < sizeof(TRUE_WORDS) / sizeof(TRUE_WORDS[0]); i++) {
        config_defaults(&cfg);
        snprintf(text, sizeof(text), "gpu = %s\n", TRUE_WORDS[i]);
        assert(config_parse_text(text, &cfg, err, sizeof(err)) == 0);
        assert(cfg.gpu == 1);
        snprintf(text, sizeof(text), "show_portrait = %s\n", TRUE_WORDS[i]);
        assert(config_parse_text(text, &cfg, err, sizeof(err)) == 0);
        assert(cfg.show_portrait == 1);
    }
    for (i = 0; i < sizeof(FALSE_WORDS) / sizeof(FALSE_WORDS[0]); i++) {
        config_defaults(&cfg);
        snprintf(text, sizeof(text), "highlight_row = %s\n", FALSE_WORDS[i]);
        assert(config_parse_text(text, &cfg, err, sizeof(err)) == 0);
        assert(cfg.highlight_row == 0);
        snprintf(text, sizeof(text), "sort_desc = %s\n", FALSE_WORDS[i]);
        assert(config_parse_text(text, &cfg, err, sizeof(err)) == 0);
        assert(cfg.sort_desc == 0);
    }

    config_defaults(&cfg);
    assert(cfg.navigation == 1);
    assert(config_parse_text("navigation = no\n", &cfg, err, sizeof(err)) == 0);
    assert(cfg.navigation == 0);

    /* a number that is not 0/1 is not a boolean */
    config_defaults(&cfg);
    assert(config_parse_text("gpu = 2\n", &cfg, err, sizeof(err)) == -1);
    assert(strcmp(err, "config: line 1: invalid value \"2\" for \"gpu\"") == 0);
}

static void test_clamping(void) {
    MiniConfig cfg;
    char err[128];

    config_defaults(&cfg);
    assert(config_parse_text("refresh_ms = 10\n", &cfg, err, sizeof(err)) == 0);
    assert(cfg.refresh_ms == 200);

    assert(config_parse_text("refresh_ms = 199\n", &cfg, err, sizeof(err)) == 0);
    assert(cfg.refresh_ms == 200);

    assert(config_parse_text("refresh_ms = 200\n", &cfg, err, sizeof(err)) == 0);
    assert(cfg.refresh_ms == 200);

    assert(config_parse_text("refresh_ms = 60000\n", &cfg, err, sizeof(err)) == 0);
    assert(cfg.refresh_ms == 60000);

    assert(config_parse_text("refresh_ms = 60001\n", &cfg, err, sizeof(err)) == 0);
    assert(cfg.refresh_ms == 60000);

    assert(config_parse_text("refresh_ms = 999999999\n", &cfg, err, sizeof(err)) == 0);
    assert(cfg.refresh_ms == 60000);

    assert(config_parse_text("refresh_ms = -5\n", &cfg, err, sizeof(err)) == 0);
    assert(cfg.refresh_ms == 200);

    assert(config_parse_text("disk_refresh_sec = 0\n", &cfg, err, sizeof(err)) == 0);
    assert(cfg.disk_refresh_sec == 1);

    assert(config_parse_text("disk_refresh_sec = 99999\n", &cfg, err, sizeof(err)) == 0);
    assert(cfg.disk_refresh_sec == 3600);

    /* long values out of int range saturate through the clamp, still finite */
    assert(config_parse_text("refresh_ms = 99999999999999999999\n",
                             &cfg, err, sizeof(err)) == 0);
    assert(cfg.refresh_ms == 60000);
}

static const char *make_temp_path(char *buf, size_t sz) {
    snprintf(buf, sz, "/tmp/minitop_test_config_%ld.conf", (long)getpid());
    return buf;
}

static void write_file(const char *path, const char *text) {
    FILE *f = fopen(path, "w");

    assert(f != NULL);
    if (text != NULL) {
        assert(fputs(text, f) >= 0);
    }
    fclose(f);
}

static void test_load(void) {
    char path[128];
    char err[256] = "";
    MiniConfig cfg;

    make_temp_path(path, sizeof(path));
    unlink(path);

    /* missing file: success, defaults untouched */
    config_defaults(&cfg);
    assert(config_load(&cfg, path, err, sizeof(err)) == 0);
    assert(err[0] == '\0');
    assert(cfg.refresh_ms == 1000);
    assert(cfg.sort_col == COL_CPU);
    assert(cfg.sort_desc == 1);

    /* valid file with comments and CRLF */
    write_file(path,
               "# comment\r\n"
               "refresh_ms = 750\r\n"
               "sort_column = state\r\n"
               "sort_desc = 0\r\n"
               "column.pid = 0\r\n");
    assert(config_load(&cfg, path, err, sizeof(err)) == 0);
    assert(cfg.refresh_ms == 750);
    assert(cfg.sort_col == COL_STATE);
    assert(cfg.sort_desc == 0);
    assert(cfg.columns[COL_PID] == 0);
    assert(cfg.columns[COL_MEM] == 1);
    assert(cfg.disk_refresh_sec == 5);

    write_file(path, "refresh_ms = 750\nbogus = 1\n");
    assert(config_load(&cfg, path, err, sizeof(err)) == -1);
    assert(strcmp(err, "config: line 2: unknown key \"bogus\"") == 0);

    /* config_load with the default path when the env points nowhere */
    {
        char old_xdg[256];
        const char *xdg = getenv("XDG_CONFIG_HOME");
        char empty_dir[128];
        char defpath[256];

        if (xdg != NULL) {
            snprintf(old_xdg, sizeof(old_xdg), "%s", xdg);
        }
        snprintf(empty_dir, sizeof(empty_dir), "/tmp/minitop_nocfg_%ld",
                 (long)getpid());
        assert(setenv("XDG_CONFIG_HOME", empty_dir, 1) == 0);
        assert(config_default_path(defpath, sizeof(defpath)) != NULL);
        config_defaults(&cfg);
        assert(config_load(&cfg, NULL, err, sizeof(err)) == 0);
        assert(cfg.refresh_ms == 1000);
        if (xdg != NULL) {
            assert(setenv("XDG_CONFIG_HOME", old_xdg, 1) == 0);
        } else {
            assert(unsetenv("XDG_CONFIG_HOME") == 0);
        }
    }

    unlink(path);
}

static void test_default_path(void) {
    char buf[256];
    char old_xdg[256];
    char old_home[256];
    const char *xdg = getenv("XDG_CONFIG_HOME");
    const char *home = getenv("HOME");

    if (xdg != NULL) {
        snprintf(old_xdg, sizeof(old_xdg), "%s", xdg);
    }
    if (home != NULL) {
        snprintf(old_home, sizeof(old_home), "%s", home);
    }

    assert(setenv("XDG_CONFIG_HOME", "/tmp/xdgconf", 1) == 0);
    assert(config_default_path(buf, sizeof(buf)) == buf);
    assert(strcmp(buf, "/tmp/xdgconf/minitop/config") == 0);

    /* empty XDG_CONFIG_HOME falls back to HOME */
    assert(setenv("XDG_CONFIG_HOME", "", 1) == 0);
    assert(setenv("HOME", "/home/tester", 1) == 0);
    assert(config_default_path(buf, sizeof(buf)) == buf);
    assert(strcmp(buf, "/home/tester/.config/minitop/config") == 0);

    assert(unsetenv("XDG_CONFIG_HOME") == 0);
    assert(config_default_path(buf, sizeof(buf)) == buf);
    assert(strcmp(buf, "/home/tester/.config/minitop/config") == 0);

    /* tiny buffer reports failure */
    assert(config_default_path(buf, 8) == NULL);

    /* no HOME and no XDG */
    assert(unsetenv("HOME") == 0);
    assert(config_default_path(buf, sizeof(buf)) == NULL);

    assert(config_default_path(NULL, sizeof(buf)) == NULL);
    assert(config_default_path(buf, 0) == NULL);

    if (xdg != NULL) {
        assert(setenv("XDG_CONFIG_HOME", old_xdg, 1) == 0);
    } else {
        assert(unsetenv("XDG_CONFIG_HOME") == 0);
    }
    if (home != NULL) {
        assert(setenv("HOME", old_home, 1) == 0);
    }
}

static void assert_same_config(const MiniConfig *want, const MiniConfig *got) {
    int i;

    assert(want->mode == got->mode);
    assert(want->refresh_ms == got->refresh_ms);
    assert(want->disk_refresh_sec == got->disk_refresh_sec);
    assert(want->show_portrait == got->show_portrait);
    assert(want->gpu == got->gpu);
    assert(want->highlight_row == got->highlight_row);
    assert(want->navigation == got->navigation);
    for (i = 0; i < COL_COUNT; i++) {
        assert(want->columns[i] == got->columns[i]);
    }
    assert(want->sort_col == got->sort_col);
    assert(want->sort_desc == got->sort_desc);

    assert(want->model.enabled == got->model.enabled);
    assert(want->model.dry_run == got->model.dry_run);
    assert(strcmp(want->model.endpoint, got->model.endpoint) == 0);
    assert(strcmp(want->model.name, got->model.name) == 0);
    assert(strcmp(want->model.key_file, got->model.key_file) == 0);
    assert(want->model.threshold == got->model.threshold);
    assert(want->model.resample_sec == got->model.resample_sec);
    assert(want->model.max_per_pass == got->model.max_per_pass);
    assert(strcmp(want->model.report_path, got->model.report_path) == 0);

    assert(want->llm.enabled == got->llm.enabled);
    assert(want->llm.dry_run == got->llm.dry_run);
    assert(strcmp(want->llm.endpoint, got->llm.endpoint) == 0);
    assert(strcmp(want->llm.name, got->llm.name) == 0);
    assert(strcmp(want->llm.key_file, got->llm.key_file) == 0);
    assert(want->llm.min_level == got->llm.min_level);
    assert(want->llm.max_level == got->llm.max_level);
    assert(want->llm.resample_sec == got->llm.resample_sec);
    assert(want->llm.max_per_pass == got->llm.max_per_pass);
    assert(want->llm.max_tokens == got->llm.max_tokens);
    assert(strcmp(want->llm.report_path, got->llm.report_path) == 0);
}

/* Reads a whole file; returns 0 when it cannot be opened for reading. */
static size_t slurp(const char *path, char *buf, size_t sz) {
    FILE *f = fopen(path, "r");
    size_t n;

    if (f == NULL) {
        return 0;
    }
    n = fread(buf, 1, sz - 1, f);
    fclose(f);
    buf[n] = '\0';
    return n;
}

/* Number of entries in dir, "." and ".." excluded; -1 when unreadable. */
static int dir_entries(const char *dir) {
    DIR *d = opendir(dir);
    struct dirent *e;
    int n = 0;

    if (d == NULL) {
        return -1;
    }
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0) {
            n++;
        }
    }
    closedir(d);
    return n;
}

static void temp_root(char *buf, size_t sz, const char *tag) {
    snprintf(buf, sz, "/tmp/minitop_cfg_%s_%ld", tag, (long)getpid());
    if (mkdir(buf, 0700) != 0) {
        assert(errno == EEXIST);
    }
    assert(chmod(buf, 0700) == 0);
}

/* The embedded template is the documented file and it parses to exactly the
 * built-in defaults, so a created config cannot change behaviour by itself. */
static void test_template_matches_defaults(void) {
    MiniConfig want;
    MiniConfig got;
    char err[256] = "";
    char file[16392];
    const char *tmpl = config_default_template();
    size_t n;

    assert(tmpl != NULL);
    config_defaults(&want);
    config_defaults(&got);
    assert(config_parse_text(tmpl, &got, err, sizeof(err)) == 0);
    assert(err[0] == '\0');
    assert_same_config(&want, &got);

    /* nothing secret may be embedded: the key is read from its own file */
    assert(strstr(tmpl, "sk-or-") == NULL);
    assert(strstr(tmpl, "Authorization") == NULL);
    assert(strstr(tmpl, "api_key") == NULL);
    assert(strstr(tmpl, "OPENROUTER_API_KEY") == NULL);

    /* make test runs from the repository root; if it does not, say so rather
     * than pretend the documentation was checked */
    n = slurp("docs/config.example", file, sizeof(file));
    if (n == 0) {
        printf("test_config: docs/config.example is not readable from here, "
               "skipping the file comparison\n");
    } else {
        assert(n == strlen(tmpl));
        assert(memcmp(file, tmpl, n) == 0);
    }
}

static void test_create_first_run(void) {
    char root[128];
    char dir[160];
    char path[192];
    char err[256] = "";
    char text[16392];
    struct stat st;
    MiniConfig want;
    MiniConfig got;
    size_t n;

    temp_root(root, sizeof(root), "first");
    snprintf(dir, sizeof(dir), "%s/minitop", root);
    snprintf(path, sizeof(path), "%s/config", dir);

    config_defaults(&want);
    assert(config_create_default(path, err, sizeof(err)) == 1);
    assert(err[0] == '\0');

    assert(stat(dir, &st) == 0);
    assert(S_ISDIR(st.st_mode));
    assert((st.st_mode & 07777) == 0700);
    assert(stat(path, &st) == 0);
    assert(S_ISREG(st.st_mode));
    assert((st.st_mode & 07777) == 0600);

    n = slurp(path, text, sizeof(text));
    assert(n == strlen(config_default_template()));
    assert(memcmp(text, config_default_template(), n) == 0);

    config_defaults(&got);
    assert(config_load(&got, path, err, sizeof(err)) == 0);
    assert(err[0] == '\0');
    assert_same_config(&want, &got);

    /* the temporary file used for write-then-link is gone */
    assert(dir_entries(dir) == 1);
    assert(dir_entries(root) == 1);

    unlink(path);
    rmdir(dir);
    rmdir(root);
}

static void test_second_run_keeps_the_file(void) {
    char root[128];
    char dir[160];
    char path[192];
    char err[256] = "";
    char before[16392];
    char after[16392];
    struct stat s1;
    struct stat s2;
    size_t n1;

    temp_root(root, sizeof(root), "second");
    snprintf(dir, sizeof(dir), "%s/minitop", root);
    snprintf(path, sizeof(path), "%s/config", dir);

    assert(config_create_default(path, err, sizeof(err)) == 1);
    n1 = slurp(path, before, sizeof(before));
    assert(n1 > 0);
    assert(stat(path, &s1) == 0);

    /* a second run leaves the file byte-identical and does not rewrite it */
    err[0] = '\0';
    assert(config_create_default(path, err, sizeof(err)) == 0);
    assert(err[0] == '\0');
    assert(slurp(path, after, sizeof(after)) == n1);
    assert(memcmp(before, after, n1) == 0);
    assert(stat(path, &s2) == 0);
    assert(s1.st_ino == s2.st_ino);
    assert(s1.st_mtim.tv_sec == s2.st_mtim.tv_sec);
    assert(s1.st_mtim.tv_nsec == s2.st_mtim.tv_nsec);

    /* a file that no longer parses is still never replaced */
    write_file(path, "refresh_ms = 750\nbogus = 1\n");
    assert(config_create_default(path, err, sizeof(err)) == 0);
    assert(slurp(path, after, sizeof(after)) == strlen("refresh_ms = 750\nbogus = 1\n"));
    assert(strcmp(after, "refresh_ms = 750\nbogus = 1\n") == 0);

    unlink(path);
    rmdir(dir);
    rmdir(root);
}

/* An explicit --config PATH that does not exist keeps the old behaviour:
 * defaults, no file, no directory. config_load is the only thing main calls
 * for that case, so it is the thing that must not create anything. */
static void test_explicit_missing_path_creates_nothing(void) {
    char root[128];
    char sub[160];
    char path[192];
    char err[256] = "";
    MiniConfig cfg;

    temp_root(root, sizeof(root), "explicit");
    snprintf(sub, sizeof(sub), "%s/sub", root);
    snprintf(path, sizeof(path), "%s/minitop/config", sub);

    config_defaults(&cfg);
    assert(config_load(&cfg, path, err, sizeof(err)) == 0);
    assert(err[0] == '\0');
    assert(cfg.refresh_ms == 1000);
    assert(cfg.sort_col == COL_CPU);

    assert(access(sub, F_OK) != 0);
    assert(access(path, F_OK) != 0);
    assert(dir_entries(root) == 0);

    rmdir(root);
}

/* A read-only home must not stop the program: creation fails with one
 * message, the loader then sees a missing file, and the built-in defaults
 * stay in place. */
static void test_unwritable_dir_reports_and_continues(void) {
    char root[128];
    char path[192];
    char err[256] = "";
    MiniConfig cfg;

    if (geteuid() == 0) {
        printf("test_config: running as root, skipping the read-only "
               "directory check\n");
        return;
    }

    temp_root(root, sizeof(root), "readonly");
    snprintf(path, sizeof(path), "%s/minitop/config", root);
    assert(chmod(root, 0500) == 0);

    assert(config_create_default(path, err, sizeof(err)) == -1);
    assert(err[0] != '\0');
    assert(strncmp(err, "config:", 7) == 0);
    assert(access(path, F_OK) != 0);
    assert(dir_entries(root) == 0);

    config_defaults(&cfg);
    err[0] = '\0';
    assert(config_load(&cfg, path, err, sizeof(err)) == 0);
    assert(err[0] == '\0');
    assert(cfg.refresh_ms == 1000);
    assert(cfg.mode == 1);

    assert(chmod(root, 0700) == 0);
    rmdir(root);
}

int main(void) {
    test_defaults();
    test_all_keys();
    test_sort_column_names();
    test_comments_and_whitespace();
    test_errors();
    test_boolean_spellings();
    test_clamping();
    test_load();
    test_default_path();
    test_template_matches_defaults();
    test_create_first_run();
    test_second_run_keeps_the_file();
    test_explicit_missing_path_creates_nothing();
    test_unwritable_dir_reports_and_continues();
    printf("test_config: all assertions passed\n");
    return 0;
}
