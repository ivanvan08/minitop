#include "config.h"
#include "flags.h"
#include "llm.h"
#include "model.h"
#include "procs.h"
#include "trust.h"
#include "tui.h"

#include <assert.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* ------------------------------------------------------------- fixtures -- */

static void base_process(ProcessInfo *p) {
    memset(p, 0, sizeof(*p));
    p->pid = 4242;
    p->ppid = 55;
    p->starttime = 123456;
    p->cpu_pct = 1.25;
    p->rss_bytes = 12ULL << 20;
    p->flags = FLAG_DEL | FLAG_TMP;
    p->risk = -1;
    p->llm_verdict = -1;
    snprintf(p->comm, sizeof(p->comm), "payload");
    snprintf(p->user, sizeof(p->user), "student");
    snprintf(p->exe_path, sizeof(p->exe_path), "/tmp/.x11-sync (deleted)");
    snprintf(p->cwd, sizeof(p->cwd), "/tmp");
}

static int contains_control_byte(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20) {
            return 1;
        }
    }
    return 0;
}

/* --------------------------------------------------------------- config -- */

static void test_config_llm_defaults(void) {
    MiniConfig cfg;
    config_defaults(&cfg);

    assert(cfg.llm.enabled == 0);
    assert(cfg.llm.dry_run == 0);
    assert(strcmp(cfg.llm.endpoint, "https://openrouter.ai/api/v1/chat/completions") == 0);
    assert(strcmp(cfg.llm.name, "deepseek/deepseek-v4.1-flash-1017") == 0);
    assert(strcmp(cfg.llm.key_file, "~/.config/minitop/openrouter.key") == 0);
    assert(cfg.llm.min_level == 3);
    assert(cfg.llm.max_level == 7);
    assert(cfg.llm.resample_sec == 1800);
    assert(cfg.llm.max_per_pass == 10);
    assert(cfg.llm.max_tokens == 4000);
    assert(strcmp(cfg.llm.report_path, "llm_verdicts.jsonl") == 0);
}

static void test_config_llm_parse(void) {
    MiniConfig cfg;
    char err[256] = "";

    config_defaults(&cfg);
    const char *text =
        "mode = 3\n"
        "llm.enabled = true\n"
        "llm.dry_run = yes\n"
        "llm.name = deepseek/test-model\n"
        "llm.endpoint = https://example.test/v1/chat/completions\n"
        "llm.key_file = /run/keys/llm\n"
        "llm.min_level = 4\n"
        "llm.max_level = 8\n"
        "llm.resample_sec = 900\n"
        "llm.max_per_pass = 3\n"
        "llm.max_tokens = 1200\n"
        "llm.report_path = /tmp/llm.jsonl\n";
    assert(config_parse_text(text, &cfg, err, sizeof(err)) == 0);
    assert(err[0] == '\0');
    assert(cfg.llm.enabled == 1);
    assert(cfg.llm.dry_run == 1);
    assert(strcmp(cfg.llm.name, "deepseek/test-model") == 0);
    assert(strcmp(cfg.llm.endpoint, "https://example.test/v1/chat/completions") == 0);
    assert(strcmp(cfg.llm.key_file, "/run/keys/llm") == 0);
    assert(cfg.llm.min_level == 4);
    assert(cfg.llm.max_level == 8);
    assert(cfg.llm.resample_sec == 900);
    assert(cfg.llm.max_per_pass == 3);
    assert(cfg.llm.max_tokens == 1200);
    assert(strcmp(cfg.llm.report_path, "/tmp/llm.jsonl") == 0);

    assert(config_parse_text("llm.min_level = 0\n", &cfg, err, sizeof(err)) == 0);
    assert(cfg.llm.min_level == 1);
    assert(config_parse_text("llm.max_level = 99\n", &cfg, err, sizeof(err)) == 0);
    assert(cfg.llm.max_level == 10);
    assert(config_parse_text("llm.resample_sec = 1\n", &cfg, err, sizeof(err)) == 0);
    assert(cfg.llm.resample_sec == 60);
    assert(config_parse_text("llm.max_per_pass = 0\n", &cfg, err, sizeof(err)) == 0);
    assert(cfg.llm.max_per_pass == 1);
    assert(config_parse_text("llm.max_tokens = 0\n", &cfg, err, sizeof(err)) == 0);
    assert(cfg.llm.max_tokens == 1);
    assert(config_parse_text("llm.max_tokens = 99999\n", &cfg, err, sizeof(err)) == 0);
    assert(cfg.llm.max_tokens == 16384);

    assert(config_parse_text("llm.name =\n", &cfg, err, sizeof(err)) != 0);
    assert(config_parse_text("llm.endpoint =\n", &cfg, err, sizeof(err)) != 0);
    assert(config_parse_text("llm.unknown = 1\n", &cfg, err, sizeof(err)) != 0);
}

static void test_band_boundaries(void) {
    assert(llm_level_eligible(2, 3, 7) == 0);
    assert(llm_level_eligible(3, 3, 7) == 1);
    assert(llm_level_eligible(4, 3, 7) == 1);
    assert(llm_level_eligible(7, 3, 7) == 1);
    assert(llm_level_eligible(8, 3, 7) == 0);
    assert(llm_level_eligible(-1, 3, 7) == 0);
    assert(llm_level_eligible(0, 3, 7) == 0);
    assert(llm_level_eligible(11, 3, 7) == 0);

    /* an inverted or nonsensical band never triggers a call */
    assert(llm_level_eligible(4, 8, 3) == 0);
    assert(llm_level_eligible(1, 0, 2) == 1);
    assert(llm_level_eligible(10, 9, 11) == 1);
}

/* --------------------------------------------------------------- prompt -- */

static void test_state_extract_and_request(void) {
    ProcessInfo p;
    TrustInfo t;
    base_process(&p);
    /* hostile comm: quote, backslash and raw control bytes */
    memset(p.comm, 0, sizeof(p.comm));
    memcpy(p.comm, "a\"b\\c\x01\x1f", 7);

    memset(&t, 0, sizeof(t));
    t.listening_count = 2;
    t.listening_ports[0] = 4444;
    t.listening_ports[1] = 8080;

    model_set_name("test/model");
    char decision[MODEL_REQUEST_MAX];
    int dn = model_build_request(&p, &t, decision, sizeof(decision));
    assert(dn > 0);

    char state[LLM_STATE_MAX];
    int sn = llm_extract_state(decision, state, sizeof(state));
    assert(sn > 0);
    assert((size_t)sn == strlen(state));
    assert(state[0] == '{');
    assert(state[strlen(state) - 1] == '}');
    assert(strstr(state, "\"comm\":\"a\\\"b\\\\c\\u0001\\u001f\"") != NULL);
    assert(strstr(state, "\"listening_ports\":[4444,8080]") != NULL);
    assert(strstr(state, "\"state\"") == NULL);
    assert(strstr(state, "\"questions\"") == NULL);

    /* The package object read from the pacman database is part of the state
     * and therefore reaches the LLM prompt unchanged. */
    TrustInfo pkg;
    memset(&pkg, 0, sizeof(pkg));
    pkg.package_meta = 1;
    snprintf(pkg.package, sizeof(pkg.package), "bash");
    snprintf(pkg.package_version, sizeof(pkg.package_version), "5.3.20-1");
    snprintf(pkg.package_desc, sizeof(pkg.package_desc), "The GNU Bourne Again shell");
    snprintf(pkg.repo, sizeof(pkg.repo), "core");
    dn = model_build_request(&p, &pkg, decision, sizeof(decision));
    assert(dn > 0);
    sn = llm_extract_state(decision, state, sizeof(state));
    assert(sn > 0);
    assert(strstr(state, "\"package\":{\"name\":\"bash\",\"version\":\"5.3.20-1\","
                         "\"desc\":\"The GNU Bourne Again shell\",\"repo\":\"core\"}") != NULL);

    char pkg_req[LLM_REQUEST_MAX];
    int pn = llm_build_request("deepseek/test-model", state, 4, 700,
                               pkg_req, sizeof(pkg_req));
    assert(pn > 0);
    assert(strstr(pkg_req, "\\\"package\\\":{\\\"name\\\":\\\"bash\\\"") != NULL);
    assert(strstr(pkg_req, "\\\"repo\\\":\\\"core\\\"") != NULL);

    char tiny[8];
    char scratch[16];
    assert(llm_extract_state(decision, tiny, sizeof(tiny)) == -1);
    assert(llm_extract_state("{\"state\":1}", scratch, sizeof(scratch)) == -1);
    assert(llm_extract_state("", scratch, sizeof(scratch)) == -1);
    assert(llm_extract_state(NULL, scratch, sizeof(scratch)) == -1);

    char req[LLM_REQUEST_MAX];
    int n = llm_build_request("deepseek/test-model", state, 4, 700, req, sizeof(req));
    assert(n > 0);
    assert((size_t)n == strlen(req));
    assert(strstr(req, "\"model\":\"deepseek/test-model\"") != NULL);
    assert(strstr(req, "\"role\":\"system\"") != NULL);
    assert(strstr(req, "\"role\":\"user\"") != NULL);
    assert(strstr(req, "VERDICT <0|1> <reason, at most 60 characters>") != NULL);
    assert(strstr(req, "naming the two or three facts the verdict rests on") != NULL);
    assert(strstr(req, "Judge evidence, never names") != NULL);
    assert(strstr(req, "a loader or dropper is malicious even with no "
                       "listener") != NULL);
    assert(strstr(req, "says nothing about the program") != NULL);
    assert(strstr(req, "Root plus a user-writable path or cwd") != NULL);
    assert(strstr(req, "second independent class") != NULL);
    assert(strstr(req, "path alone establishes it") != NULL);
    assert(strstr(req, "loader or dropper shape") != NULL);
    assert(strstr(req, "monitoring tool itself") != NULL);
    assert(strstr(req, "Write the VERDICT line as the first output") != NULL);
    assert(strstr(req, "Keep the reasoning to at most three short "
                       "sentences") != NULL);
    assert(strstr(req, "Decision model risk level: 4 out of 10.") != NULL);
    assert(strstr(req, "\"temperature\":0") != NULL);
    assert(strstr(req, "\"max_tokens\":700") != NULL);
    assert(strstr(req, "\"usage\":{\"include\":true}") != NULL);

    /* the state JSON is nested inside a JSON string: quotes are escaped and
     * the raw control bytes are gone, while the escape sequences survive */
    assert(contains_control_byte(req, (size_t)n) == 0);
    assert(strstr(req, "\\\"comm\\\":") != NULL);
    assert(strstr(req, "\\\\u0001") != NULL);

    assert(llm_build_request("m", state, 4, 0, req, sizeof(req)) > 0);
    assert(strstr(req, "\"max_tokens\":1") != NULL);
    assert(llm_build_request("m", state, 4, 99999, req, sizeof(req)) > 0);
    assert(strstr(req, "\"max_tokens\":16384") != NULL);

    char small[64];
    assert(llm_build_request("m", state, 4, 700, small, sizeof(small)) == -1);
    assert(llm_build_request(NULL, state, 4, 700, req, sizeof(req)) == -1);
    assert(llm_build_request("m", NULL, 4, 700, req, sizeof(req)) == -1);
    assert(llm_build_request("m", state, 4, 700, NULL, 0) == -1);

    char huge[LLM_STATE_MAX + 2];
    memset(huge, 'x', sizeof(huge) - 1);
    huge[sizeof(huge) - 1] = '\0';
    assert(llm_build_request("m", huge, 4, 700, req, sizeof(req)) == -1);

    /* a "state" key inside the comm string must not confuse the extractor */
    snprintf(p.comm, sizeof(p.comm), "\"state\":{}");
    dn = model_build_request(&p, &t, decision, sizeof(decision));
    assert(dn > 0);
    sn = llm_extract_state(decision, state, sizeof(state));
    assert(sn > 0);
    assert(strstr(state, "\"comm\":\"\\\"state\\\":{}\"") != NULL);
    assert(strstr(state, "\"state\"") == NULL);

    model_set_name("baseten/bison-1");
}

/* -------------------------------------------------------------- parsing -- */

static int parse_body(const char *body, LlmAnswer *a) {
    return llm_parse_response(body, strlen(body), a);
}

static void test_response_valid(void) {
    const char *ok =
        "{\"id\":\"gen-1\",\"choices\":[{\"index\":0,\"message\":{"
        "\"role\":\"assistant\",\"content\":\"VERDICT 1 deleted binary running from /tmp\\n"
        "It listens on a socket.\\n"
        "The executable was deleted.\\n"
        "It runs from a temporary directory.\"},"
        "\"finish_reason\":\"stop\"}],"
        "\"usage\":{\"prompt_tokens\":210,\"completion_tokens\":57,"
        "\"total_tokens\":267,\"cost\":0.000031}}";
    LlmAnswer a;
    assert(parse_body(ok, &a) == 1);
    assert(strcmp(a.reason, "deleted binary running from /tmp") == 0);
    assert(strcmp(a.detail,
                  "It listens on a socket.\n"
                  "The executable was deleted.\n"
                  "It runs from a temporary directory.") == 0);
    assert(a.truncated == 0);
    assert(a.usage.prompt_tokens == 210);
    assert(a.usage.completion_tokens == 57);
    assert(a.usage.total_tokens == 267);
    assert(a.usage.reasoning_tokens == 0);
    assert(a.usage.cost > 0.0000309 && a.usage.cost < 0.0000311);

    const char *safe =
        "{\"choices\":[{\"message\":{\"content\":\"VERDICT 0 package-managed bash\"}}]}";
    assert(parse_body(safe, &a) == 0);
    assert(strcmp(a.reason, "package-managed bash") == 0);
    assert(a.detail[0] == '\0');
    assert(a.truncated == 0);

    /* escaped quote inside the reason */
    const char *quoted =
        "{\"choices\":[{\"message\":{\"content\":\"VERDICT 1 masquerading as \\\"bash\\\"\"}}]}";
    assert(parse_body(quoted, &a) == 1);
    assert(strcmp(a.reason, "masquerading as \"bash\"") == 0);

    /* a normal answer ends with a newline and trailing spaces */
    const char *newline =
        "{\"choices\":[{\"message\":{\"content\":\"VERDICT 0 clean\\n\"}}]}";
    assert(parse_body(newline, &a) == 0);
    assert(strcmp(a.reason, "clean") == 0);
    assert(a.detail[0] == '\0');

    const char *spaces =
        "{\"choices\":[{\"message\":{\"content\":\"VERDICT 1 x   \"}}]}";
    assert(parse_body(spaces, &a) == 1);
    assert(strcmp(a.reason, "x") == 0);

    /* exactly 80 reason bytes is the limit when the answer is complete */
    char line[256];
    char eighty[81];
    memset(eighty, 'a', 80);
    eighty[80] = '\0';
    snprintf(line, sizeof(line),
             "{\"choices\":[{\"message\":{\"content\":\"VERDICT 1 %s\"},"
             "\"finish_reason\":\"stop\"}]}", eighty);
    assert(parse_body(line, &a) == 1);
    assert(strlen(a.reason) == 80);
    assert(a.truncated == 0);

    /* explanation lines are trimmed and two of them fit */
    const char *two =
        "{\"choices\":[{\"message\":{\"content\":\"VERDICT 0 ok\\n  First sentence.  \\n"
        "Second sentence.\\n\"},\"finish_reason\":\"stop\"}]}";
    assert(parse_body(two, &a) == 0);
    assert(strcmp(a.detail, "First sentence.\nSecond sentence.") == 0);
}

static void test_response_length_truncated(void) {
    LlmAnswer a;
    const char *length =
        "{\"choices\":[{\"message\":{\"content\":\"VERDICT 0 benign service\\n"
        "It looks like a packaged daemon.\\n"
        "The second sentence was cut mid\"},"
        "\"finish_reason\":\"length\"}]}";
    assert(parse_body(length, &a) == 0);
    assert(strcmp(a.reason, "benign service [truncated]") == 0);
    assert(strcmp(a.detail,
                  "It looks like a packaged daemon.\n"
                  "The second sentence was cut mid") == 0);
    assert(a.truncated == 1);

    /* a length cut in the reason itself keeps the first 80 bytes */
    char hundred[101];
    memset(hundred, 'a', 100);
    hundred[100] = '\0';
    char body[512];
    snprintf(body, sizeof(body),
             "{\"choices\":[{\"message\":{\"content\":\"VERDICT 1 %s\"},"
             "\"finish_reason\":\"length\"}]}", hundred);
    assert(parse_body(body, &a) == 1);
    assert(strlen(a.reason) == 92); /* 80 bytes + " [truncated]" */
    assert(strncmp(a.reason, hundred, 80) == 0);
    assert(strstr(a.reason, "[truncated]") != NULL);
    assert(a.truncated == 1);

    /* a length answer with no explanation still keeps the verdict */
    const char *bare =
        "{\"choices\":[{\"message\":{\"content\":\"VERDICT 1 x\"},"
        "\"finish_reason\":\"length\"}]}";
    assert(parse_body(bare, &a) == 1);
    assert(strcmp(a.reason, "x [truncated]") == 0);
    assert(a.detail[0] == '\0');
    assert(a.truncated == 1);

    /* more than three explanation lines are kept up to the limit on length */
    const char *four =
        "{\"choices\":[{\"message\":{\"content\":\"VERDICT 0 ok\\n"
        "One.\\nTwo.\\nThree.\\nFour.\"},"
        "\"finish_reason\":\"length\"}]}";
    assert(parse_body(four, &a) == 0);
    assert(strcmp(a.detail, "One.\nTwo.\nThree.") == 0);
    assert(a.truncated == 1);

    /* the same four lines on a complete answer are a contract deviation */
    const char *four_stop =
        "{\"choices\":[{\"message\":{\"content\":\"VERDICT 0 ok\\n"
        "One.\\nTwo.\\nThree.\\nFour.\"},"
        "\"finish_reason\":\"stop\"}]}";
    assert(parse_body(four_stop, &a) == -1);
    assert(a.verdict == -1);
    assert(a.reason[0] == '\0');
    assert(a.detail[0] == '\0');

    /* length alone does not excuse a missing verdict line */
    const char *no_verdict =
        "{\"choices\":[{\"message\":{\"content\":\"I think this is fine.\"},"
        "\"finish_reason\":\"length\"}]}";
    assert(parse_body(no_verdict, &a) == -1);
}

/* The production budget is 4000 tokens and hidden reasoning is billed against
 * it. A reply cut after the verdict line but mid-explanation must keep the
 * verdict and mark the reason, not be rejected. */
static void test_response_cut_at_production_budget(void) {
    char request[LLM_REQUEST_MAX];
    const char *state =
        "{\"comm\":\"bash\",\"exe_path\":\"/usr/bin/bash\",\"cwd\":\"/tmp\","
        "\"user\":\"root\",\"cpu_pct_irix\":0.0,\"rss_mib\":4.0,"
        "\"local_flags\":[],\"listening_ports\":[],"
        "\"package\":{\"name\":\"bash\",\"version\":\"5.2.37-1\","
        "\"desc\":\"The GNU Bourne Again shell\",\"repo\":\"core\"}}";
    assert(llm_build_request("deepseek/test-model", state, 5, 4000,
                             request, sizeof(request)) > 0);
    assert(strstr(request, "\"max_tokens\":4000") != NULL);

    const char *cut =
        "{\"choices\":[{\"message\":{\"content\":\"VERDICT 1 root interpreter "
        "in temporary cwd\\nThe executable /usr/bin/bash is an interpreter, so "
        "its path and package ownership are uninformative.\\nIt runs as root "
        "with cwd /tmp, a temporary user-writable location, and the answer was "
        "cut mid\"},\"finish_reason\":\"length\"}],"
        "\"usage\":{\"prompt_tokens\":1000,\"completion_tokens\":4000,"
        "\"total_tokens\":5000,"
        "\"completion_tokens_details\":{\"reasoning_tokens\":3900},"
        "\"cost\":0.0004}}";
    LlmAnswer a;
    assert(parse_body(cut, &a) == 1);
    assert(a.truncated == 1);
    assert(strcmp(a.reason, "root interpreter in temporary cwd [truncated]") == 0);
    assert(strstr(a.detail,
                  "The executable /usr/bin/bash is an interpreter") != NULL);
    assert(strstr(a.detail, "and the answer was cut mid") != NULL);
    assert(a.usage.completion_tokens == 4000);
    assert(a.usage.reasoning_tokens == 3900);
}

static void test_response_reasoning_only(void) {
    const char *body =
        "{\"id\":\"gen-reason\",\"choices\":[{\"index\":0,"
        "\"finish_reason\":\"length\",\"message\":{\"role\":\"assistant\","
        "\"content\":null,\"reasoning\":\"We need decide. The process is ...\"}}],"
        "\"usage\":{\"prompt_tokens\":300,\"completion_tokens\":700,"
        "\"total_tokens\":1000,"
        "\"completion_tokens_details\":{\"reasoning_tokens\":650},"
        "\"cost\":0.0002}}";
    LlmAnswer a;
    assert(parse_body(body, &a) == -1);
    assert(a.verdict == -1);
    assert(a.reason[0] == '\0');
    assert(a.detail[0] == '\0');
    assert(a.truncated == 0);
    assert(a.usage.prompt_tokens == 300);
    assert(a.usage.completion_tokens == 700);
    assert(a.usage.total_tokens == 1000);
    assert(a.usage.reasoning_tokens == 650);
    assert(a.usage.cost > 0.000199 && a.usage.cost < 0.000201);
}

static void test_response_malformed(void) {
    LlmAnswer a;
    const char *bad[] = {
        "",
        "not json",
        "{}",
        "{\"choices\":[]}",
        "{\"choices\":[{\"message\":{}}]}",
        "{\"choices\":[{\"message\":{\"content\":\"\"}}]}",
        "{\"choices\":[{\"message\":{\"content\":\"VERDICT 1\"}}]}",
        "{\"choices\":[{\"message\":{\"content\":\"VERDICT 0 \"}}]}",
        "{\"choices\":[{\"message\":{\"content\":\"VERDICT\"}}]}",
        "{\"choices\":[{\"message\":{\"content\":\"verdict 1 ok\"}}]}",
        "{\"choices\":[{\"message\":{\"content\":\"VERDICT 2 ok\"}}]}",
        "{\"choices\":[{\"message\":{\"content\":\"VERDICT 01 ok\"}}]}",
        "{\"choices\":[{\"message\":{\"content\":\"VERDICT  1 ok\"}}]}",
        "{\"choices\":[{\"message\":{\"content\":\"VERDICT 1 ok\\rmore\"}}]}",
        "{\"choices\":[{\"message\":{\"content\":\"VERDICT 1 ok\\tmore\"}}]}",
        "{\"choices\":[{\"message\":{\"content\":5}}]}",
        "{\"choices\":[{\"message\":{\"content\":null}}]}",
        NULL,
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        memset(&a, 0x5a, sizeof(a));
        if (bad[i] == NULL) {
            assert(llm_parse_response(NULL, 0, &a) == -1);
        } else {
            assert(parse_body(bad[i], &a) == -1);
        }
        assert(a.verdict == -1);
        assert(a.reason[0] == '\0');
        assert(a.detail[0] == '\0');
    }
    assert(llm_parse_response("{}", 2, NULL) == -1);

    /* a reply that ends on a lone backslash inside a string must be rejected
     * without walking the scanner past the end of the buffer */
    const char *cut_escape =
        "{\"choices\":[{\"message\":{\"content\":\"VERDICT 1 x\\";
    memset(&a, 0x5a, sizeof(a));
    assert(parse_body(cut_escape, &a) == -1);
    assert(a.verdict == -1);
    assert(a.reason[0] == '\0');

    /* 81 reason bytes exceeds the contract on a complete answer */
    char line[256];
    char eightyone[82];
    memset(eightyone, 'a', 81);
    eightyone[81] = '\0';
    snprintf(line, sizeof(line),
             "{\"choices\":[{\"message\":{\"content\":\"VERDICT 1 %s\"},"
             "\"finish_reason\":\"stop\"}]}", eightyone);
    assert(parse_body(line, &a) == -1);
    assert(a.reason[0] == '\0');

    /* usage survives a malformed answer for the report */
    const char *usage_only =
        "{\"choices\":[{\"message\":{\"content\":\"nope\"}}],"
        "\"usage\":{\"total_tokens\":9,\"cost\":0.1}}";
    assert(parse_body(usage_only, &a) == -1);
    assert(a.usage.total_tokens == 9);
    assert(a.usage.cost == 0.1);
}

static void test_report_format(void) {
    LlmUsage u;
    memset(&u, 0, sizeof(u));
    u.prompt_tokens = 210;
    u.completion_tokens = 57;
    u.total_tokens = 267;
    u.reasoning_tokens = 3;
    u.cost = 0.000031;

    char buf[1024];
    int n = llm_format_report("deepseek/deepseek-chat",
                              "2026-11-25T12:00:00+0200", 4242, "ev\"il", 1,
                              "reason \"x\"", "First line.\nSecond line.",
                              &u, 0, buf, sizeof(buf));
    assert(n > 0);
    assert((size_t)n == strlen(buf));
    assert(strstr(buf, "\"time\":\"2026-11-25T12:00:00+0200\"") != NULL);
    assert(strstr(buf, "\"pid\":4242") != NULL);
    assert(strstr(buf, "\"comm\":\"ev\\\"il\"") != NULL);
    assert(strstr(buf, "\"verdict\":1") != NULL);
    assert(strstr(buf, "\"reason\":\"reason \\\"x\\\"\"") != NULL);
    assert(strstr(buf, "\"detail\":\"First line.\\nSecond line.\"") != NULL);
    assert(strstr(buf, "\"truncated\":0") != NULL);
    assert(strstr(buf, "\"model\":\"deepseek/deepseek-chat\"") != NULL);
    assert(strstr(buf, "\"tokens\":267") != NULL);
    assert(strstr(buf, "\"prompt_tokens\":210") != NULL);
    assert(strstr(buf, "\"completion_tokens\":57") != NULL);
    assert(strstr(buf, "\"reasoning_tokens\":3") != NULL);
    assert(strstr(buf, "\"cost\":") != NULL);
    assert(strstr(buf, "cmdline") == NULL);
    assert(strstr(buf, "key") == NULL);
    assert(contains_control_byte(buf, (size_t)n) == 0);

    assert(llm_format_report("m", "t", 1, "c", 1, "r", "d", &u, 1,
                             buf, sizeof(buf)) > 0);
    assert(strstr(buf, "\"truncated\":1") != NULL);

    assert(llm_format_report("m", "t", 1, "c", -1, "", "", NULL, 0,
                             buf, sizeof(buf)) > 0);
    assert(strstr(buf, "\"tokens\":0") != NULL);
    assert(strstr(buf, "\"reasoning_tokens\":0") != NULL);

    char tiny[16];
    assert(llm_format_report("m", "t", 1, "c", -1, "", "", &u, 0,
                             tiny, sizeof(tiny)) == -1);
}

/* --------------------------------------------------------------- engine -- */

static void test_engine_lifecycle_no_network(void) {
    const char *key_path = "/tmp/minitop-test-llm.key";
    FILE *f = fopen(key_path, "w");
    assert(f != NULL);
    fputs("test-key-not-real\n", f);
    fclose(f);

    LlmConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = 1;
    snprintf(cfg.name, sizeof(cfg.name), "%s", "deepseek/test-model");
    snprintf(cfg.endpoint, sizeof(cfg.endpoint), "%s",
             "https://example.test/v1/chat/completions");
    snprintf(cfg.key_file, sizeof(cfg.key_file), "%s", key_path);
    cfg.min_level = 3;
    cfg.max_level = 7;
    cfg.resample_sec = 1800;
    cfg.max_per_pass = 10;
    cfg.max_tokens = 700;
    snprintf(cfg.report_path, sizeof(cfg.report_path), "%s", "none");

    char err[256] = "";
    LlmEngine *e = llm_engine_create(&cfg, err, sizeof(err));
    assert(e != NULL);

    ProcessInfo p;
    base_process(&p);
    p.risk = 2; /* below the band: must not queue a request */
    p.llm_verdict = 0;
    snprintf(p.llm_reason, sizeof(p.llm_reason), "stale value");
    snprintf(p.llm_detail, sizeof(p.llm_detail), "stale detail");
    TrustInfo t;
    memset(&t, 0, sizeof(t));
    ProcList list = {0};
    assert(proclist_init(&list, 2) == 0);
    assert(proclist_push(&list, &p) == 0);

    llm_engine_tick(e, &list, &t, 1);
    assert(list.items[0].llm_verdict == -1);
    assert(list.items[0].llm_reason[0] == '\0');
    assert(list.items[0].llm_detail[0] == '\0');

    llm_engine_destroy(e);
    proclist_free(&list);

    /* an empty endpoint is rejected before any key read */
    cfg.endpoint[0] = '\0';
    err[0] = '\0';
    assert(llm_engine_create(&cfg, err, sizeof(err)) == NULL);
    assert(strstr(err, "llm.endpoint") != NULL);
    snprintf(cfg.endpoint, sizeof(cfg.endpoint), "%s",
             "https://example.test/v1/chat/completions");

    /* inverted band is rejected before any key read */
    cfg.min_level = 8;
    cfg.max_level = 3;
    err[0] = '\0';
    assert(llm_engine_create(&cfg, err, sizeof(err)) == NULL);
    assert(strstr(err, "below") != NULL);

    /* a missing key file is reported, not printed */
    cfg.min_level = 3;
    cfg.max_level = 7;
    remove(key_path);
    err[0] = '\0';
    assert(llm_engine_create(&cfg, err, sizeof(err)) == NULL);
    assert(strstr(err, "not found") != NULL);

    /* the creation path refuses a dry run: preview never needs a key */
    cfg.enabled = 1;
    cfg.dry_run = 1;
    err[0] = '\0';
    assert(llm_engine_create(&cfg, err, sizeof(err)) == NULL);
    assert(strstr(err, "dry run") != NULL);
}

/* The configured endpoint must be the URL libcurl connects to. A forked
 * one-shot listener on 127.0.0.1 accepts the request and writes its first
 * line back; the port exists only in cfg.endpoint, so an accepted connection
 * proves the key reached the HTTP layer. */
static void test_engine_custom_endpoint(void) {
    const char *key_path = "/tmp/minitop-test-llm-endpoint.key";
    FILE *kf = fopen(key_path, "w");
    assert(kf != NULL);
    fputs("test-key-not-real\n", kf);
    fclose(kf);

    /* a proxy would answer instead of the listener and hide the real URL */
    unsetenv("http_proxy");
    unsetenv("HTTP_PROXY");
    unsetenv("all_proxy");
    unsetenv("ALL_PROXY");

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener >= 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    assert(bind(listener, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    assert(listen(listener, 1) == 0);
    socklen_t addr_len = sizeof(addr);
    assert(getsockname(listener, (struct sockaddr *)&addr, &addr_len) == 0);

    int captured[2];
    assert(pipe(captured) == 0);

    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(captured[0]);
        int conn = accept(listener, NULL, NULL);
        if (conn >= 0) {
            char buf[8192];
            size_t used = 0;
            while (used + 1 < sizeof(buf)) {
                ssize_t n = read(conn, buf + used, sizeof(buf) - 1 - used);
                if (n <= 0) {
                    break;
                }
                used += (size_t)n;
                if (memchr(buf, '\n', used) != NULL) {
                    break;
                }
            }
            size_t line = 0;
            while (line < used && buf[line] != '\n' && buf[line] != '\r') {
                line++;
            }
            if (line > 0) {
                ssize_t w = write(captured[1], buf, line);
                (void)w;
            }
            const char *resp = "HTTP/1.1 500 Internal Server Error\r\n"
                               "Content-Length: 0\r\nConnection: close\r\n\r\n";
            ssize_t w = write(conn, resp, strlen(resp));
            (void)w;
            close(conn);
        }
        close(listener);
        close(captured[1]);
        _exit(0);
    }

    close(listener);
    close(captured[1]);
    assert(fcntl(captured[0], F_SETFL, O_NONBLOCK) == 0);

    LlmConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = 1;
    snprintf(cfg.endpoint, sizeof(cfg.endpoint),
             "http://127.0.0.1:%u/v1/chat/completions",
             (unsigned)ntohs(addr.sin_port));
    snprintf(cfg.name, sizeof(cfg.name), "%s", "deepseek/test-model");
    snprintf(cfg.key_file, sizeof(cfg.key_file), "%s", key_path);
    cfg.min_level = 3;
    cfg.max_level = 7;
    cfg.resample_sec = 1800;
    cfg.max_per_pass = 10;
    cfg.max_tokens = 700;
    snprintf(cfg.report_path, sizeof(cfg.report_path), "%s", "none");

    char err[256] = "";
    LlmEngine *e = llm_engine_create(&cfg, err, sizeof(err));
    assert(e != NULL);

    ProcessInfo p;
    base_process(&p);
    p.risk = 5; /* inside the band: the tick queues one request */
    TrustInfo t;
    memset(&t, 0, sizeof(t));
    ProcList list = {0};
    assert(proclist_init(&list, 2) == 0);
    assert(proclist_push(&list, &p) == 0);

    char line[512] = "";
    int got = 0;
    for (int i = 0; i < 10000 && !got; i++) {
        llm_engine_tick(e, &list, &t, 1);
        ssize_t n = read(captured[0], line, sizeof(line) - 1);
        if (n > 0) {
            line[n] = '\0';
            got = 1;
        } else {
            usleep(1000);
        }
    }

    llm_engine_destroy(e);
    proclist_free(&list);
    close(captured[0]);
    if (!got) {
        kill(child, SIGKILL);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    remove(key_path);

    assert(got);
    assert(strncmp(line, "POST ", 5) == 0);
    assert(strstr(line, "/v1/chat/completions") != NULL);
}

/* ----------------------------------------------------------------- TUI -- */

static void render_flags(ProcessInfo *p, int model_enabled, int model_grey,
                         int *safe, int *risky) {
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
    tui_model_set(model_enabled, model_grey, 5, 3);

    TuiBuf frame = {0};
    assert(tui_render(&frame, 120, 30, &sys, NULL, &sum, &list, &view) == 0);

    /* Mode 2 and 3 carry the level as the cell text; the backgrounds are used
     * by no other cell, so their presence answers how FLAGS was painted. */
    *safe = strstr(frame.data, "\x1b[48;2;16;34;66m") != NULL;
    *risky = strstr(frame.data, "\x1b[48;2;70;18;22m") != NULL;

    tui_buf_free(&frame);
    proclist_free(&list);
}

static void test_llm_flags_colour(void) {
    ProcessInfo p;
    base_process(&p);
    p.flags = FLAG_DEL;
    p.risk = 2;
    snprintf(p.llm_reason, sizeof(p.llm_reason), "llm reason");
    int safe = 0;
    int risky = 0;

    p.llm_verdict = 1;
    render_flags(&p, 1, 0, &safe, &risky);
    assert(safe == 0);
    assert(risky == 1);

    p.llm_verdict = 0;
    render_flags(&p, 1, 0, &safe, &risky);
    assert(safe == 1);
    assert(risky == 0);

    /* No verdict yet, and the level is below the filter: the LLM will never
     * see this process, so the filter's clearance is final and the cell is
     * blue, not dim. */
    p.llm_verdict = -1;
    p.llm_reason[0] = '\0';
    render_flags(&p, 1, 0, &safe, &risky);
    assert(safe == 1);
    assert(risky == 0);

    /* A verdict without a reason is ignored: the filter's clearance stands and
     * the cell stays blue. */
    p.llm_verdict = 1;
    render_flags(&p, 1, 0, &safe, &risky);
    assert(safe == 1);
    assert(risky == 0);
    snprintf(p.llm_reason, sizeof(p.llm_reason), "llm reason");

    /* A failed model client keeps the cell neutral even with a cached value. */
    render_flags(&p, 1, 1, &safe, &risky);
    assert(safe == 0);
    assert(risky == 0);

    /* Mode 3: a level above the threshold never paints red by itself; the
     * LLM clearing it keeps the cell blue. */
    p.risk = 9;
    p.llm_verdict = 0;
    render_flags(&p, 1, 0, &safe, &risky);
    assert(safe == 1);
    assert(risky == 0);

    p.risk = 9;
    p.llm_verdict = -1;
    p.llm_reason[0] = '\0';
    render_flags(&p, 1, 0, &safe, &risky);
    assert(safe == 0);
    assert(risky == 0);
}

static void test_footer_names_row_without_highlight(void) {
    ProcessInfo p;
    base_process(&p);
    p.pid = 4242;
    snprintf(p.comm, sizeof(p.comm), "qemu-system-x86");
    p.llm_verdict = -1;

    SystemInfo sys;
    ProcSummary sum;
    ProcList list;
    memset(&sys, 0, sizeof(sys));
    sys.temp_celsius = -1.0;
    memset(&sum, 0, sizeof(sum));
    assert(proclist_init(&list, 2) == 0);
    assert(proclist_push(&list, &p) == 0);

    TuiView view;
    tui_view_init(&view);
    view.highlight_row = 0;
    view.sel_row = 0;
    tui_model_set(1, 0, 5, 1);

    TuiBuf frame = {0};
    assert(tui_render(&frame, 120, 30, &sys, NULL, &sum, &list, &view) == 0);
    /* The name has to survive every frame, not just the one after a keypress. */
    assert(strstr(frame.data, "row 0  pid 4242  qemu-system-x86") != NULL);
    tui_buf_free(&frame);

    /* With the background on, the footer is not the cue. */
    view.highlight_row = 1;
    memset(&frame, 0, sizeof(frame));
    assert(tui_render(&frame, 120, 30, &sys, NULL, &sum, &list, &view) == 0);
    assert(strstr(frame.data, "row 0  pid 4242") == NULL);
    tui_buf_free(&frame);

    proclist_free(&list);
}

static void test_llm_unreviewed_level(void) {
    ProcessInfo p;
    base_process(&p);
    p.flags = FLAG_DEL;
    p.risk = 9;
    p.llm_verdict = -1;
    p.llm_reason[0] = '\0';

    SystemInfo sys;
    ProcSummary sum;
    ProcList list;
    memset(&sys, 0, sizeof(sys));
    sys.temp_celsius = -1.0;
    memset(&sum, 0, sizeof(sum));
    assert(proclist_init(&list, 2) == 0);
    assert(proclist_push(&list, &p) == 0);

    TuiView view;
    tui_view_init(&view);
    tui_model_set(1, 0, 5, 3);
    TuiBuf frame = {0};

    /* Nothing can review a flagged row: the level is painted in the attention
     * colour, and no background claims an answer that will never arrive. */
    tui_llm_set(0);
    assert(tui_render(&frame, 120, 30, &sys, NULL, &sum, &list, &view) == 0);
    assert(strstr(frame.data, "\x1b[38;2;242;168;58m") != NULL);
    assert(strstr(frame.data, "\x1b[48;2;70;18;22m") == NULL);
    assert(strstr(frame.data, "\x1b[48;2;16;34;66m") == NULL);
    tui_buf_free(&frame);

    /* With the stage running the same row is a request in flight, so it dims. */
    tui_llm_set(1);
    memset(&frame, 0, sizeof(frame));
    assert(tui_render(&frame, 120, 30, &sys, NULL, &sum, &list, &view) == 0);
    assert(strstr(frame.data, "\x1b[38;2;242;168;58m") == NULL);
    tui_buf_free(&frame);

    proclist_free(&list);
}

static void render_footer_frame(ProcessInfo *p, ssize_t sel_row, int width,
                                int height, TuiBuf *frame) {
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
    view.sel_row = sel_row;
    tui_model_set(1, 0, 5, 3);

    memset(frame, 0, sizeof(*frame));
    assert(tui_render(frame, width, height, &sys, NULL, &sum, &list, &view) == 0);

    proclist_free(&list);
}

static int count_crlf(const char *frame) {
    int n = 0;
    while (frame[0] != '\0') {
        if (frame[0] == '\r' && frame[1] == '\n') {
            n++;
        }
        frame++;
    }
    return n;
}

static int lines_contain_in_order(const char *frame, const char *first,
                                  const char *second) {
    const char *a = strstr(frame, first);
    const char *b = strstr(frame, second);
    if (a == NULL || b == NULL || b <= a) {
        return 0;
    }
    for (const char *p = a; p + 1 < b; p++) {
        if (p[0] == '\r' && p[1] == '\n') {
            return 1;
        }
    }
    return 0;
}

static void test_footer_reason(void) {
    ProcessInfo p;
    base_process(&p);
    p.risk = 4;
    p.llm_verdict = 1;
    snprintf(p.llm_reason, sizeof(p.llm_reason), "deleted binary in /tmp");

    TuiBuf frame = {0};
    render_footer_frame(&p, 0, 120, 30, &frame);
    assert(strstr(frame.data, "pid 4242 payload: deleted binary in /tmp") != NULL);
    assert(strstr(frame.data, "quit") == NULL);
    assert(count_crlf(frame.data) == 29);
    tui_buf_free(&frame);

    /* no reason: the original key hints and brand are unchanged */
    p.llm_reason[0] = '\0';
    render_footer_frame(&p, 0, 120, 30, &frame);
    assert(strstr(frame.data, "pid 4242 payload:") == NULL);
    assert(strstr(frame.data, "quit") != NULL);
    assert(strstr(frame.data, "minitop") != NULL);
    assert(count_crlf(frame.data) == 29);
    tui_buf_free(&frame);

    /* nothing selected: the footer stays on key hints */
    snprintf(p.llm_reason, sizeof(p.llm_reason), "deleted binary in /tmp");
    render_footer_frame(&p, -1, 120, 30, &frame);
    assert(strstr(frame.data, "pid 4242 payload:") == NULL);
    assert(strstr(frame.data, "quit") != NULL);
    tui_buf_free(&frame);
}

static void test_footer_detail_two_lines(void) {
    ProcessInfo p;
    base_process(&p);
    p.risk = 4;
    p.llm_verdict = 1;
    snprintf(p.llm_reason, sizeof(p.llm_reason), "suspicious binary");
    snprintf(p.llm_detail, sizeof(p.llm_detail),
             "It runs from /tmp. It listens on a socket.");

    TuiBuf frame = {0};
    int widths[] = { 80, 120 };
    for (size_t i = 0; i < sizeof(widths) / sizeof(widths[0]); i++) {
        render_footer_frame(&p, 0, widths[i], 30, &frame);
        assert(strstr(frame.data, "pid 4242 payload: suspicious binary") != NULL);
        assert(strstr(frame.data, "It runs from /tmp.") != NULL);
        assert(strstr(frame.data, "It listens on a socket.") == NULL);
        assert(lines_contain_in_order(frame.data,
                                      "pid 4242 payload: suspicious binary",
                                      "It runs from /tmp."));
        assert(count_crlf(frame.data) == 29);
        tui_buf_free(&frame);
    }

    /* a long first sentence is truncated by display width on both widths */
    char long_detail[300];
    int n = snprintf(long_detail, sizeof(long_detail), "HEAD-MARKER-");
    assert(n > 0);
    for (int i = 0; i < 220; i++) {
        size_t len = strlen(long_detail);
        long_detail[len] = 'x';
        long_detail[len + 1] = '\0';
    }
    strncat(long_detail, "-TAIL-MARKER", sizeof(long_detail) - strlen(long_detail) - 1);
    snprintf(p.llm_detail, sizeof(p.llm_detail), "%s", long_detail);

    for (size_t i = 0; i < sizeof(widths) / sizeof(widths[0]); i++) {
        render_footer_frame(&p, 0, widths[i], 30, &frame);
        assert(strstr(frame.data, "HEAD-MARKER-") != NULL);
        assert(strstr(frame.data, "-TAIL-MARKER") == NULL);
        assert(count_crlf(frame.data) == 29);
        tui_buf_free(&frame);
    }

    /* height 18 leaves no room for the second line; the reason still shows */
    render_footer_frame(&p, 0, 120, 18, &frame);
    assert(strstr(frame.data, "pid 4242 payload: suspicious binary") != NULL);
    assert(strstr(frame.data, "HEAD-MARKER-") == NULL);
    assert(count_crlf(frame.data) == 17);
    tui_buf_free(&frame);

    assert(tui_table_rows_detail(19, 1) == tui_table_rows(19));
    assert(tui_table_rows_detail(20, 1) == tui_table_rows(20) - 1);
    assert(tui_table_rows_detail(30, 1) == tui_table_rows(30) - 1);
    assert(tui_table_rows_detail(30, 0) == tui_table_rows(30));
}

int main(void) {
    test_config_llm_defaults();
    test_config_llm_parse();
    test_band_boundaries();
    test_state_extract_and_request();
    test_response_valid();
    test_response_length_truncated();
    test_response_cut_at_production_budget();
    test_response_reasoning_only();
    test_response_malformed();
    test_report_format();
    test_engine_lifecycle_no_network();
    test_engine_custom_endpoint();
    test_llm_flags_colour();
    test_llm_unreviewed_level();
    test_footer_names_row_without_highlight();
    test_footer_reason();
    test_footer_detail_two_lines();

    trust_cache_reset();
    puts("test_llm: ok");
    return 0;
}
