#ifndef MINITOP_MODEL_H
#define MINITOP_MODEL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "config.h"
#include "procs.h"
#include "trust.h"

#define MODEL_MAX_ACTIVE 4
#define MODEL_TIMEOUT_MS 8000
#define MODEL_REQUEST_MAX 16384
#define MODEL_RESPONSE_MAX (256u * 1024u)

/**
 * Feeds the FLAGS verdict state to the renderer (implemented in src/tui.c).
 * enabled: the client is running, so risk values are painted.
 * grey: model.enabled was set but the client could not start (for example a
 *       missing key file); the FLAGS cell then stays neutral.
 * threshold: 1..10, risk at or above it is red, below it blue.
 */
void tui_model_set(int enabled, int grey, int threshold, int mode);

/**
 * Tells the renderer whether the LLM stage is running. In mode 3 a flagged row
 * waits for a verdict only when something can produce one; without the engine
 * the level is shown in the attention colour instead of staying dim forever.
 */
void tui_llm_set(int running);

/**
 * Sets the model id emitted in the "model" field of every request. The id is
 * required by the Decisions API. Defaults to "baseten/bison-1".
 */
void model_set_name(const char *name);

/**
 * Builds the Decisions API request body for one process:
 *
 *   {"model":"<configured id>",
 *    "state":{"comm":...,"exe_path":...,"cwd":...,"user":...,
 *             "cpu_pct_irix":...,"rss_mib":...,
 *             "local_flags":[...],"listening_ports":[...],
 *             "package":{"name":...,"version":...,"desc":...,"repo":...}},
 *    "questions":{"risk":{"type":"score",...},
 *                 "likely_pkg_upgrade":{"type":"noul",...}}}
 *
 * local_flags contains DEL, TMP, MEMFD (NET is represented by the port list).
 * Strings are JSON-escaped: '"' and '\\' get a backslash, \b \f \n \r \t get
 * their short escapes, every other byte below 0x20 and 0x7f becomes \u00XX.
 * Listening ports come from t->listening_count / t->listening_ports.
 * The package object comes from the local pacman database and is omitted
 * entirely when t->package_meta is 0, so an unknown package leaves the request
 * unchanged. repo is "core" or "extra" when trust resolved it and empty for a
 * package outside those repositories (the AUR, for example).
 * @return bytes written (without the NUL), or -1 on truncation/bad arguments.
 *         buf is always NUL-terminated when buf != NULL and sz > 0.
 */
int model_build_request(const ProcessInfo *p, const TrustInfo *t, char *buf, size_t sz);

/**
 * Extracts the risk level from a Decisions API response.
 *
 * Contract:
 *   1. Find the "answers" key; if present, search only inside its value,
 *      otherwise search the whole response.
 *   2. Find the "risk" key followed by an object.
 *   3. In that object prefer a numeric "score": level = round(score) + 1
 *      (the API score is a zero-based index into the criteria array).
 *      A score outside [-0.01, 9.01] is rejected. Otherwise accept an
 *      integer "level" already in 1..10.
 *   4. Anything else, including a refusal, malformed JSON or no score,
 *      returns -1.
 *
 * @return 1..10, or -1 when the response carries no usable level.
 */
int model_parse_level(const char *response, size_t len);

/**
 * Formats one JSONL report record:
 *   {"time":"...","pid":N,"comm":"...","level":N,"model":"..."}
 * comm is escaped; cmdline is never accepted by this API, so it cannot leak
 * into a report. level may be -1 for an unparsable answer.
 * @return bytes written (without the NUL), or -1 on truncation.
 */
int model_format_report(const char *model, const char *time_iso, pid_t pid,
                        const char *comm, int level, char *buf, size_t sz);

/**
 * Parses /proc/net/tcp{,6} text and stores the inode and local port of every
 * LISTEN (state 0A) socket. Ports are host-order values from the hex field.
 * @return number of entries written, at most cap.
 */
size_t model_parse_listen_ports(const char *text, uint64_t *inodes,
                                uint16_t *ports, size_t cap);

/**
 * Collects the local ports of pid's listening sockets (IPv4 and IPv6).
 * @return number of ports written, at most cap.
 */
size_t model_collect_listening_ports(pid_t pid, uint16_t *ports, size_t cap);

typedef struct ModelEngine ModelEngine;

/**
 * Creates the asynchronous client. Reads the key from cfg->key_file (default
 * "~/.config/minitop/openrouter.key"), initialises the curl multi handle and
 * starts the sampling schedule. The key is kept in memory only; it never
 * reaches argv, stderr or a report.
 *
 * @return engine, or NULL with a one-line reason in err (missing key file,
 *         unreadable file, curl initialisation failure).
 */
ModelEngine *model_engine_create(const ModelConfig *cfg, char *err, size_t err_sz);

/** Frees every request, curl handle, cache and the key buffer. */
void model_engine_destroy(ModelEngine *engine);

/**
 * Queues one request for p. Never blocks and never retries by itself.
 * t must already carry listening ports. The request is built immediately from
 * the state in p and the configured model id.
 * @return 1 when queued, 0 when the engine or queue cannot accept it.
 */
int model_score_async(ModelEngine *engine, const ProcessInfo *p, const TrustInfo *t);

/**
 * Non-blocking sampling step, to be called once per refresh pass:
 *   - drives curl_multi (timeout 0), applies finished verdicts to procs and
 *     appends one JSON line per answer to model.report_path;
 *   - queues at most model.max_per_pass new processes, in pid order, skipping
 *     trusted ones, processes already in flight and processes whose randomised
 *     re-sample interval has not elapsed;
 *   - starts queued requests while fewer than MODEL_MAX_ACTIVE are active.
 * trust must contain procs->count entries from the same pass.
 */
void model_engine_tick(ModelEngine *engine, ProcList *procs, TrustInfo *trust,
                       size_t trust_count);

#endif
