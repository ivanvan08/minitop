#include "config.h"
#include "flags.h"
#include "model.h"
#include "tui.h"
#include "trust.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void test_config_model_defaults(void) {
    MiniConfig cfg;
    config_defaults(&cfg);

    assert(cfg.model.enabled == 0);
    assert(cfg.model.dry_run == 0);
    assert(strcmp(cfg.model.endpoint, "https://openrouter.ai/api/alpha/decisions") == 0);
    assert(strcmp(cfg.model.name, "baseten/mammoth-1") == 0);
    assert(strcmp(cfg.model.key_file, "~/.config/minitop/openrouter.key") == 0);
    assert(cfg.model.threshold == 5);
    assert(cfg.model.resample_sec == 1500);
    assert(cfg.model.max_per_pass == 300);
    assert(strcmp(cfg.model.report_path, "llm_log") == 0);
}

static void test_config_model_parse(void) {
    MiniConfig cfg;
    char err[256] = "";

    config_defaults(&cfg);
    const char *text =
        "mode = 2\n"
        "model.dry_run = yes\n"
        "model.endpoint = https://example.test/decisions\n"
        "model.name = typesafe/jev-1.14\n"
        "model.key_file = /run/keys/model\n"
        "model.threshold = 4\n"
        "model.resample_sec = 1200\n"
        "model.max_per_pass = 40\n"
        "model.report_path = /tmp/model.jsonl\n";
    assert(config_parse_text(text, &cfg, err, sizeof(err)) == 0);
    assert(err[0] == '\0');
    assert(cfg.model.enabled == 1);
    assert(cfg.model.dry_run == 1);
    assert(strcmp(cfg.model.endpoint, "https://example.test/decisions") == 0);
    assert(strcmp(cfg.model.name, "typesafe/jev-1.14") == 0);
    assert(strcmp(cfg.model.key_file, "/run/keys/model") == 0);
    assert(cfg.model.threshold == 4);
    assert(cfg.model.resample_sec == 1200);
    assert(cfg.model.max_per_pass == 40);
    assert(strcmp(cfg.model.report_path, "/tmp/model.jsonl") == 0);

    assert(config_parse_text("model.threshold = 99\n", &cfg, err, sizeof(err)) == 0);
    assert(cfg.model.threshold == 10);
    assert(config_parse_text("model.threshold = 0\n", &cfg, err, sizeof(err)) == 0);
    assert(cfg.model.threshold == 1);
    assert(config_parse_text("model.max_per_pass = 0\n", &cfg, err, sizeof(err)) == 0);
    assert(cfg.model.max_per_pass == 1);

    assert(config_parse_text("model.endpoint =\n", &cfg, err, sizeof(err)) != 0);
    assert(config_parse_text("model.unknown = 1\n", &cfg, err, sizeof(err)) != 0);
}

static void test_trust_pacman_parse(void) {
    char pkg[64];
    char repo[16];

    assert(trust_pacman_parse("core bash 5.2.037-1\n", pkg, sizeof(pkg),
                              repo, sizeof(repo)) == 1);
    assert(strcmp(pkg, "bash") == 0);
    assert(strcmp(repo, "core") == 0);

    assert(trust_pacman_parse("extra firefox\n", pkg, sizeof(pkg),
                              repo, sizeof(repo)) == 1);
    assert(strcmp(pkg, "firefox") == 0);
    assert(strcmp(repo, "extra") == 0);

    assert(trust_pacman_parse("/usr/bin/bash is owned by bash 5.2.037-1\n",
                              pkg, sizeof(pkg), repo, sizeof(repo)) == 1);
    assert(strcmp(pkg, "bash") == 0);
    assert(repo[0] == '\0');

    assert(trust_pacman_parse("error: No package owns /tmp/x\n", pkg, sizeof(pkg),
                              repo, sizeof(repo)) == 0);
    assert(pkg[0] == '\0');
    assert(trust_pacman_parse("   \n", pkg, sizeof(pkg), repo, sizeof(repo)) == 0);
    assert(trust_pacman_parse("", pkg, sizeof(pkg), repo, sizeof(repo)) == 0);
    assert(trust_pacman_parse(NULL, pkg, sizeof(pkg), repo, sizeof(repo)) == 0);

    /* A package name that does not fit is rejected, not truncated into a
     * different (possibly trusted) name. */
    char tiny[4];
    assert(trust_pacman_parse("core bash 5.0\n", tiny, sizeof(tiny),
                              repo, sizeof(repo)) == 0);
}

static void test_trust_argv_gate(void) {
    /* A path taken from argv[0] is spoofable, so it earns no trust for an
     * ordinary user, even when the package really is in core or extra. */
    assert(trust_is_trusted(0, 1, 0, 1, 1000) == 0);
    assert(trust_is_trusted(0, 1, 0, 1, 0) == 1);
    assert(trust_is_trusted(0, 0, 1, 1, 1000) == 0);
    assert(trust_is_trusted(0, 0, 1, 1, 0) == 1);

    /* The real exe link is kernel-true evidence and needs no uid check. */
    assert(trust_is_trusted(0, 1, 0, 0, 1000) == 1);
    assert(trust_is_trusted(0, 0, 1, 0, 4242) == 1);

    /* A kernel thread is recognised without the link. */
    assert(trust_is_trusted(1, 0, 0, 1, 4242) == 1);

    /* Nothing matched: the process is scored. */
    assert(trust_is_trusted(0, 0, 0, 0, 1000) == 0);
}

static void test_trust_classify(void) {
    ProcessInfo p;
    TrustInfo t;

    memset(&p, 0, sizeof(p));
    p.pid = 10;
    snprintf(p.comm, sizeof(p.comm), "systemd");
    p.ppid = 1;
    snprintf(p.exe_path, sizeof(p.exe_path), "/usr/lib/systemd/systemd");
    trust_classify_process(&p, &t);
    assert(t.systemd_child == 1);
    assert(t.kernel_thread == 0);
    assert(t.package_trusted == 0);
    assert(t.trusted == 1);

    /* A kernel-looking comm with a readable executable is not a kernel thread:
     * prctl(PR_SET_NAME) lets any process take the name, and the VM run showed
     * a payload under /dev/shm called kswapd0 that skipped the model this way. */
    memset(&p, 0, sizeof(p));
    p.pid = 11;
    snprintf(p.comm, sizeof(p.comm), "kworker/0:1");
    snprintf(p.exe_path, sizeof(p.exe_path), "/usr/bin/not-real");
    trust_classify_process(&p, &t);
    assert(t.kernel_thread == 0);
    assert(t.trusted == 0);

    memset(&p, 0, sizeof(p));
    p.pid = 12;
    snprintf(p.comm, sizeof(p.comm), "[bracket]");
    trust_classify_process(&p, &t);
    assert(t.kernel_thread == 0);

    memset(&p, 0, sizeof(p));
    p.pid = 17;
    p.ppid = 1;
    snprintf(p.comm, sizeof(p.comm), "kswapd0");
    snprintf(p.exe_path, sizeof(p.exe_path), "/dev/shm/.kworker");
    trust_classify_process(&p, &t);
    assert(t.kernel_thread == 0);
    assert(t.trusted == 0);

    /* no exe link with ppid 2 is a kernel thread ... */
    memset(&p, 0, sizeof(p));
    p.pid = 15;
    p.ppid = 2;
    snprintf(p.comm, sizeof(p.comm), "worker-name");
    trust_classify_process(&p, &t);
    assert(t.kernel_thread == 1);

    /* ... but no exe link with another parent is a process we cannot read,
     * not a kernel thread: it must still be scored (plan 6.4 rule E). */
    memset(&p, 0, sizeof(p));
    p.pid = 16;
    p.ppid = 1;
    snprintf(p.comm, sizeof(p.comm), "NetworkManager");
    trust_classify_process(&p, &t);
    assert(t.kernel_thread == 0);
    assert(t.trusted == 0);

    memset(&p, 0, sizeof(p));
    p.pid = 13;
    p.ppid = 1;
    snprintf(p.comm, sizeof(p.comm), "payload");
    snprintf(p.exe_path, sizeof(p.exe_path), "/home/user/payload");
    trust_classify_process(&p, &t);
    assert(t.kernel_thread == 0);
    assert(t.systemd_child == 0);
    assert(t.package_trusted == 0);
    assert(t.trusted == 0);

    memset(&p, 0, sizeof(p));
    p.pid = 14;
    p.ppid = 777;
    snprintf(p.comm, sizeof(p.comm), "payload");
    snprintf(p.exe_path, sizeof(p.exe_path), "/tmp/payload");
    trust_classify_process(&p, &t);
    assert(t.trusted == 0);
}

/* A fake pacman reports core/bash for every path it is asked about, so the only
 * thing between an unreadable exe link and a free pass to the model is the
 * argv/uid gate: argv[0] is user-controlled, and a payload that claims
 * "/usr/bin/bash" there must still be scored for an ordinary user, because
 * otherwise hiding /proc/<pid>/exe (PR_SET_DUMPABLE=0) buys trust. */
static void test_trust_evaluate_argv_gate(void) {
    char dir[] = "/tmp/minitop-trust-XXXXXX";
    assert(mkdtemp(dir) != NULL);

    char pacman[512];
    snprintf(pacman, sizeof(pacman), "%s/pacman", dir);
    FILE *f = fopen(pacman, "wb");
    assert(f != NULL);
    const char *script =
        "#!/bin/sh\n"
        "if [ \"$1\" = \"-Sl\" ]; then\n"
        "  echo \"core bash\"\n"
        "  exit 0\n"
        "fi\n"
        "shift\n"
        "for p in \"$@\"; do\n"
        "  echo \"$p is owned by bash\"\n"
        "done\n";
    assert(fwrite(script, 1, strlen(script), f) == strlen(script));
    assert(fclose(f) == 0);
    assert(chmod(pacman, 0755) == 0);

    char db[512];
    snprintf(db, sizeof(db), "%s/pacman-local", dir);
    assert(mkdir(db, 0700) == 0);

    char *old_path = getenv("PATH") != NULL ? strdup(getenv("PATH")) : NULL;
    assert(setenv("PATH", dir, 1) == 0);
    trust_package_set_db(db);

    ProcList list;
    ProcessInfo p;
    assert(proclist_init(&list, 1) == 0);
    TrustInfo *t = calloc(1, sizeof(*t));
    assert(t != NULL);

    /* Spoofed argv path: uid 1000, exe link unreadable, argv[0] names a core
     * package. The package answer is real, the trust verdict must not be. */
    memset(&p, 0, sizeof(p));
    p.pid = 4001;
    p.ppid = 500;
    p.uid = 1000;
    p.risk = -1;
    snprintf(p.comm, sizeof(p.comm), "bash");
    snprintf(p.exe_path, sizeof(p.exe_path), "/usr/bin/bash");
    p.exe_from_argv = 1;
    assert(proclist_push(&list, &p) == 0);

    trust_cache_reset();
    trust_evaluate(&list, t);
    assert(t[0].kernel_thread == 0);
    assert(t[0].systemd_child == 0);
    assert(t[0].package_trusted == 1); /* the fake pacman answered core/bash */
    assert(strcmp(t[0].package, "bash") == 0);
    assert(strcmp(t[0].repo, "core") == 0);
    assert(t[0].trusted == 0);

    /* Same evidence at uid 0: a system account, where argv[0] is not a claim
     * an ordinary process can forge, so the package rule counts. */
    list.items[0].pid = 4002;
    list.items[0].uid = 0;
    trust_evaluate(&list, t);
    assert(t[0].package_trusted == 1);
    assert(t[0].trusted == 1);

    /* Genuine kernel thread: no link at all and ppid 2 (kthreadd), with no
     * argv claim behind the empty path. */
    memset(&list.items[0], 0, sizeof(list.items[0]));
    list.items[0].pid = 4003;
    list.items[0].ppid = 2;
    list.items[0].uid = 1000;
    list.items[0].risk = -1;
    snprintf(list.items[0].comm, sizeof(list.items[0].comm), "kworker/0:1");
    trust_evaluate(&list, t);
    assert(t[0].kernel_thread == 1);
    assert(t[0].package_trusted == 0);
    assert(t[0].trusted == 1);

    free(t);
    proclist_free(&list);

    trust_cache_reset();
    trust_package_set_db(NULL);
    assert(setenv("PATH", old_path != NULL ? old_path : "/usr/bin:/bin", 1) == 0);
    free(old_path);
    assert(unlink(pacman) == 0);
    assert(rmdir(db) == 0);
    assert(rmdir(dir) == 0);
}

static void base_process(ProcessInfo *p) {
    memset(p, 0, sizeof(*p));
    p->pid = 4242;
    p->ppid = 55;
    p->starttime = 123456;
    p->cpu_pct = 1.25;
    p->rss_bytes = 12ULL << 20;
    p->flags = FLAG_DEL | FLAG_TMP | FLAG_MEMFD;
    p->risk = -1;
    snprintf(p->comm, sizeof(p->comm), "payload");
    snprintf(p->user, sizeof(p->user), "student");
    snprintf(p->exe_path, sizeof(p->exe_path), "/tmp/.x11-sync (deleted)");
    snprintf(p->cwd, sizeof(p->cwd), "/tmp");
}

static int contains_control_byte(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 && c != '\n') {
            return 1;
        }
    }
    return 0;
}

static void test_request_builder(void) {
    ProcessInfo p;
    TrustInfo t;
    base_process(&p);

    /* hostile comm: quote, backslash, control bytes */
    memset(p.comm, 0, sizeof(p.comm));
    memcpy(p.comm, "a\"b\\c\x01\x1f", 7);

    memset(&t, 0, sizeof(t));
    t.listening_count = 2;
    t.listening_ports[0] = 4444;
    t.listening_ports[1] = 8080;

    /* The pass now sets NET on listeners, but the request keeps carrying ports
     * in their own field: local_flags stays the three path-derived bits. */
    p.flags |= FLAG_NET;

    model_set_name("test/model");
    char buf[MODEL_REQUEST_MAX];
    int n = model_build_request(&p, &t, buf, sizeof(buf));
    assert(n > 0);
    assert((size_t)n == strlen(buf));
    assert(contains_control_byte(buf, (size_t)n) == 0);

    assert(strstr(buf, "\"model\":\"test/model\"") != NULL);
    assert(strstr(buf, "\"comm\":\"a\\\"b\\\\c\\u0001\\u001f\"") != NULL);
    assert(strstr(buf, "\"exe_path\":\"/tmp/.x11-sync (deleted)\"") != NULL);
    assert(strstr(buf, "\"cwd\":\"/tmp\"") != NULL);
    assert(strstr(buf, "\"user\":\"student\"") != NULL);
    assert(strstr(buf, "\"cpu_pct_irix\":1.2") != NULL);
    assert(strstr(buf, "\"rss_mib\":12.0") != NULL);
    assert(strstr(buf, "\"local_flags\":[\"DEL\",\"TMP\",\"MEMFD\"]") != NULL);
    assert(strstr(buf, "\"listening_ports\":[4444,8080]") != NULL);
    assert(strstr(buf, "\"risk\":{\"type\":\"score\"") != NULL);
    assert(strstr(buf, "\"likely_pkg_upgrade\":{\"type\":\"noul\"") != NULL);
    assert(strstr(buf, "independent evidence classes") != NULL);
    assert(strstr(buf, "level 10: certain malice: fileless execution") != NULL);
    assert(strstr(buf, "normal package manager upgrade") != NULL);

    /* truncated output is refused and still NUL-terminated */
    char tiny[40];
    assert(model_build_request(&p, &t, tiny, sizeof(tiny)) == -1);
    assert(strlen(tiny) < sizeof(tiny));
    assert(model_build_request(NULL, &t, tiny, sizeof(tiny)) == -1);

    model_set_name("baseten/bison-1");
}

static void write_text_file(const char *path, const char *text) {
    FILE *f = fopen(path, "wb");
    assert(f != NULL);
    size_t len = strlen(text);
    assert(fwrite(text, 1, len, f) == len);
    assert(fclose(f) == 0);
}

static int valid_utf8(const char *s, size_t n) {
    for (size_t i = 0; i < n;) {
        unsigned char c = (unsigned char)s[i];
        size_t need;
        if (c < 0x80) {
            need = 1;
        } else if ((c & 0xE0) == 0xC0) {
            need = 2;
        } else if ((c & 0xF0) == 0xE0) {
            need = 3;
        } else if ((c & 0xF8) == 0xF0) {
            need = 4;
        } else {
            return 0;
        }
        if (i + need > n) {
            return 0;
        }
        for (size_t k = 1; k < need; k++) {
            if ((s[i + k] & 0xC0) != 0x80) {
                return 0;
            }
        }
        i += need;
    }
    return 1;
}

static void test_package_metadata(void) {
    char root[] = "/tmp/minitop-pkgdb-XXXXXX";
    assert(mkdtemp(root) != NULL);

    char dir[512];
    char path[600];
    char body[1200];

    /* A description with a quote, a backslash, a tab, a control byte and a
     * 200-byte UTF-8 tail; it must be escaped, sanitised and cut at 120 bytes. */
    snprintf(dir, sizeof(dir), "%s/fixture-pkg-1.0-1", root);
    assert(mkdir(dir, 0700) == 0);
    int off = snprintf(body, sizeof(body),
                       "%%NAME%%\nfixture-pkg\n\n%%VERSION%%\n1.0-1\n\n%%DESC%%\n"
                       "quote \" backslash \\ tab\t ctrl\x01 ");
    assert(off > 0);
    for (int i = 0; i < 100; i++) {
        assert((size_t)off + 2 < sizeof(body));
        body[off++] = (char)0xC3;
        body[off++] = (char)0xA9;
    }
    body[off] = '\0';
    strcat(body, "\n\n%URL%\nhttps://example.test\n");
    snprintf(path, sizeof(path), "%s/desc", dir);
    write_text_file(path, body);

    /* A package whose directory exists but whose desc file does not. */
    snprintf(dir, sizeof(dir), "%s/missing-pkg-2.0-1", root);
    assert(mkdir(dir, 0700) == 0);

    ProcList list = {0};
    assert(proclist_init(&list, 4) == 0);
    ProcessInfo p;
    base_process(&p);
    snprintf(p.exe_path, sizeof(p.exe_path), "/opt/fixture/bin/fixture");
    assert(proclist_push(&list, &p) == 0);
    p.pid = 4243;
    assert(proclist_push(&list, &p) == 0);

    TrustInfo out[2];
    memset(out, 0, sizeof(out));
    snprintf(out[0].package, sizeof(out[0].package), "fixture-pkg");
    snprintf(out[1].package, sizeof(out[1].package), "fixture-pkg");
    snprintf(out[0].repo, sizeof(out[0].repo), "extra");

    trust_package_set_db(root);
    trust_package_desc_reads_reset();
    trust_fill_package_meta(&list, out);

    /* Two processes running the same executable cost exactly one desc read. */
    assert(trust_package_desc_reads() == 1);
    assert(out[0].package_meta == 1);
    assert(out[1].package_meta == 1);
    assert(strcmp(out[0].package_version, "1.0-1") == 0);
    assert(strcmp(out[0].package_desc, out[1].package_desc) == 0);

    size_t dlen = strlen(out[0].package_desc);
    assert(dlen >= 110 && dlen <= 120);
    assert(valid_utf8(out[0].package_desc, dlen) == 1);
    for (size_t i = 0; i < dlen; i++) {
        unsigned char c = (unsigned char)out[0].package_desc[i];
        assert(c >= 0x20 && c != 0x7f);
    }

    model_set_name("test/model");
    char buf[MODEL_REQUEST_MAX];
    int n = model_build_request(&p, &out[0], buf, sizeof(buf));
    assert(n > 0);
    assert(strstr(buf, "\"package\":{\"name\":\"fixture-pkg\",\"version\":\"1.0-1\","
                       "\"desc\":\"quote \\\" backslash \\\\ tab") != NULL);
    assert(strstr(buf, ",\"repo\":\"extra\"}") != NULL);
    assert(contains_control_byte(buf, (size_t)n) == 0);

    /* A newline in the description is escaped by the request builder even
     * though the desc format cannot carry one. */
    snprintf(out[0].package_desc, sizeof(out[0].package_desc), "line1\nline2");
    n = model_build_request(&p, &out[0], buf, sizeof(buf));
    assert(n > 0);
    assert(strstr(buf, "\"desc\":\"line1\\nline2\"") != NULL);

    /* A package outside core/extra keeps the repository key with an empty
     * value instead of dropping it. */
    out[0].repo[0] = '\0';
    n = model_build_request(&p, &out[0], buf, sizeof(buf));
    assert(n > 0);
    assert(strstr(buf, ",\"repo\":\"\"}") != NULL);

    /* Missing desc file: no metadata and no package object; the request stays
     * byte-identical to one built with an empty TrustInfo. */
    memset(out, 0, sizeof(out));
    snprintf(out[0].package, sizeof(out[0].package), "missing-pkg");
    trust_package_desc_reads_reset();
    trust_fill_package_meta(&list, out);
    assert(trust_package_desc_reads() == 0);
    assert(out[0].package_meta == 0);

    TrustInfo empty;
    memset(&empty, 0, sizeof(empty));
    char plain[MODEL_REQUEST_MAX];
    int n1 = model_build_request(&p, &out[0], buf, sizeof(buf));
    int n2 = model_build_request(&p, &empty, plain, sizeof(plain));
    assert(n1 > 0 && n1 == n2);
    assert(strcmp(buf, plain) == 0);
    assert(strstr(buf, "\"package\"") == NULL);
    assert(strstr(buf, "\"state\":{\"comm\":\"payload\",\"exe_path\":\"/opt/fixture/bin/fixture\","
                       "\"cwd\":\"/tmp\",\"user\":\"student\",\"cpu_pct_irix\":1.2,"
                       "\"rss_mib\":12.0,\"local_flags\":[\"DEL\",\"TMP\",\"MEMFD\"],"
                       "\"listening_ports\":[]},\"questions\"") != NULL);

    trust_package_set_db(NULL);
    trust_package_desc_reads_reset();
    model_set_name("baseten/bison-1");
    proclist_free(&list);

    snprintf(path, sizeof(path), "%s/fixture-pkg-1.0-1/desc", root);
    assert(unlink(path) == 0);
    snprintf(dir, sizeof(dir), "%s/fixture-pkg-1.0-1", root);
    assert(rmdir(dir) == 0);
    snprintf(dir, sizeof(dir), "%s/missing-pkg-2.0-1", root);
    assert(rmdir(dir) == 0);
    assert(rmdir(root) == 0);
}

static void test_level_parse(void) {
    const char *ok =
        "{\"id\":\"gen\",\"model\":\"m\",\"answers\":{"
        "\"risk\":{\"type\":\"score\",\"score\":8.4,\"confidence\":0.8,\"probabilities\":{}},"
        "\"likely_pkg_upgrade\":{\"type\":\"noul\",\"noul\":0.1}}}";
    assert(model_parse_level(ok, strlen(ok)) == 9);

    const char *low =
        "{\"answers\":{\"risk\":{\"type\":\"score\",\"score\":0}}}";
    assert(model_parse_level(low, strlen(low)) == 1);

    const char *max =
        "{\"answers\":{\"risk\":{\"type\":\"score\",\"score\":9}}}";
    assert(model_parse_level(max, strlen(max)) == 10);

    assert(model_parse_level("{\"answers\":{\"risk\":{\"score\":-0.5}}}", strlen("{\"answers\":{\"risk\":{\"score\":-0.5}}}")) == -1);
    assert(model_parse_level("{\"answers\":{\"risk\":{\"score\":9.5}}}", strlen("{\"answers\":{\"risk\":{\"score\":9.5}}}")) == -1);
    assert(model_parse_level("{\"answers\":{\"risk\":{\"score\":\"x\"}}}", strlen("{\"answers\":{\"risk\":{\"score\":\"x\"}}}")) == -1);
    assert(model_parse_level("{\"risk\":{\"level\":7}}", strlen("{\"risk\":{\"level\":7}}")) == 7);
    assert(model_parse_level("{\"risk\":{\"level\":11}}", strlen("{\"risk\":{\"level\":11}}")) == -1);
    assert(model_parse_level("not json", 8) == -1);
    assert(model_parse_level(NULL, 0) == -1);

    const char *flat = "{\"risk\":{\"type\":\"score\",\"score\":5}}";
    assert(model_parse_level(flat, strlen(flat)) == 6);

    const char *lookalike = "{\"answers\":{\"risk_score\":9}}";
    assert(model_parse_level(lookalike, strlen(lookalike)) == -1);
}

static void test_report_format(void) {
    char buf[512];
    int n = model_format_report("baseten/bison-1", "2026-11-25T23:00:00+0200",
                                4242, "ev\"il\\x", 7, buf, sizeof(buf));
    assert(n > 0);
    assert((size_t)n == strlen(buf));
    assert(strstr(buf, "\"pid\":4242") != NULL);
    assert(strstr(buf, "\"comm\":\"ev\\\"il\\\\x\"") != NULL);
    assert(strstr(buf, "\"level\":7") != NULL);
    assert(strstr(buf, "\"model\":\"baseten/bison-1\"") != NULL);
    assert(strstr(buf, "cmdline") == NULL);
    assert(contains_control_byte(buf, (size_t)n) == 0);

    char tiny[8];
    assert(model_format_report("m", "t", 1, "c", -1, tiny, sizeof(tiny)) == -1);
}

static void test_listen_port_parse(void) {
    const char *text =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1\n"
        "   1: 0100007F:0035 00000000:0000 01 00000000:00000000 00:00000000 00000000  1000        0 999 1\n"
        "   2: 0000000000000000:01BB 0000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 777 1\n";

    uint64_t inodes[8];
    uint16_t ports[8];
    size_t n = model_parse_listen_ports(text, inodes, ports, 8);
    assert(n == 2);
    assert(inodes[0] == 12345);
    assert(ports[0] == 8080);
    assert(inodes[1] == 777);
    assert(ports[1] == 443);

    assert(model_parse_listen_ports(text, inodes, ports, 1) == 1);
    assert(model_parse_listen_ports(text, inodes, ports, 0) == 0);
    assert(model_parse_listen_ports("", inodes, ports, 8) == 0);
    assert(model_parse_listen_ports(NULL, inodes, ports, 8) == 0);
}

/* ------------------------------------------------------------ render test -- */

static void frame_flags_colours(ProcessInfo *p, int model_enabled, int model_grey,
                                int threshold, int mode,
                                int *safe, int *risky, int *legacy_red) {
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
    tui_model_set(model_enabled, model_grey, threshold, mode);

    TuiBuf frame = {0};
    assert(tui_render(&frame, 120, 30, &sys, NULL, &sum, &list, &view) == 0);

    /* The verdict backgrounds are only ever used by the FLAGS cell, so their
     * presence is an unambiguous statement about how that cell was painted. */
    *safe = strstr(frame.data, "\x1b[48;2;16;34;66m") != NULL;
    *risky = strstr(frame.data, "\x1b[48;2;70;18;22m") != NULL;
    *legacy_red = strstr(frame.data, "\x1b[38;2;238;82;82m") != NULL;

    tui_buf_free(&frame);
    proclist_free(&list);
}

static void test_flags_verdict_colours(void) {
    ProcessInfo p;
    int safe = 0;
    int risky = 0;
    int red = 0;

    /* Mode 1 is vanilla: the local flags are shown as text and nothing about
     * them is painted, because no model made a claim. */
    base_process(&p);
    p.flags = FLAG_DEL;
    p.risk = -1;
    frame_flags_colours(&p, 0, 0, 5, 1, &safe, &risky, &red);
    assert(safe == 0);
    assert(risky == 0);
    assert(red == 0);

    /* Mode 2: the level replaces the flag text and is painted by the level. */
    p.risk = 3; /* below threshold */
    frame_flags_colours(&p, 1, 0, 5, 2, &safe, &risky, &red);
    assert(safe == 1);
    assert(risky == 0);

    p.risk = 5; /* at threshold */
    frame_flags_colours(&p, 1, 0, 5, 2, &safe, &risky, &red);
    assert(safe == 0);
    assert(risky == 1);

    p.risk = 10;
    frame_flags_colours(&p, 1, 0, 5, 2, &safe, &risky, &red);
    assert(safe == 0);
    assert(risky == 1);

    /* Mode 3: the model is a filter, so a high level alone paints nothing;
     * the LLM verdict decides, and an unanswered process stays dim. */
    p.risk = 8;
    p.llm_verdict = -1;
    p.llm_reason[0] = '\0';
    frame_flags_colours(&p, 1, 0, 5, 3, &safe, &risky, &red);
    assert(safe == 0);
    assert(risky == 0);

    snprintf(p.llm_reason, sizeof(p.llm_reason), "%s", "packaged daemon, no sockets");
    p.llm_verdict = 0;
    frame_flags_colours(&p, 1, 0, 5, 3, &safe, &risky, &red);
    assert(safe == 1);
    assert(risky == 0);

    p.llm_verdict = 1;
    frame_flags_colours(&p, 1, 0, 5, 3, &safe, &risky, &red);
    assert(safe == 0);
    assert(risky == 1);

    /* Enabled but no key file: the feature reports itself disabled and the
     * cell stays neutral. */
    p.risk = -1;
    p.llm_verdict = -1;
    p.llm_reason[0] = '\0';
    frame_flags_colours(&p, 1, 1, 5, 2, &safe, &risky, &red);
    assert(safe == 0);
    assert(risky == 0);
}

static void test_portrait_toggle_at_120(void) {
    SystemInfo sys;
    ProcSummary sum;
    ProcList list;
    ProcessInfo p;
    memset(&sys, 0, sizeof(sys));
    sys.temp_celsius = -1.0;
    memset(&sum, 0, sizeof(sum));
    base_process(&p);
    assert(proclist_init(&list, 2) == 0);
    assert(proclist_push(&list, &p) == 0);

    TuiView view;
    tui_view_init(&view);
    TuiBuf frame = {0};

    view.show_portrait = 1;
    assert(tui_render(&frame, 120, 30, &sys, NULL, &sum, &list, &view) == 0);
    assert(strstr(frame.data, "ceo") != NULL);

    view.show_portrait = 0;
    assert(tui_render(&frame, 120, 30, &sys, NULL, &sum, &list, &view) == 0);
    assert(strstr(frame.data, "ceo") == NULL);

    tui_buf_free(&frame);
    proclist_free(&list);
}

int main(void) {
    test_config_model_defaults();
    test_config_model_parse();
    test_trust_pacman_parse();
    test_trust_argv_gate();
    test_trust_classify();
    test_trust_evaluate_argv_gate();
    test_request_builder();
    test_package_metadata();
    test_level_parse();
    test_report_format();
    test_listen_port_parse();
    test_flags_verdict_colours();
    test_portrait_toggle_at_120();

    trust_cache_reset();
    puts("test_model: ok");
    return 0;
}
