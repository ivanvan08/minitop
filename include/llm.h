#ifndef MINITOP_LLM_H
#define MINITOP_LLM_H

#include <stddef.h>
#include <sys/types.h>

#include "config.h"
#include "procs.h"
#include "trust.h"

#define LLM_MAX_ACTIVE 2
#define LLM_TIMEOUT_MS 10000
#define LLM_REQUEST_MAX 24576
#define LLM_RESPONSE_MAX 262144u
#define LLM_REASON_MAX 96
#define LLM_DETAIL_MAX 512
#define LLM_CONTENT_MAX 65536
#define LLM_STATE_MAX 8192
#define LLM_MAX_TOKENS_MAX 16384

/* Token accounting from one chat-completion answer. reasoning_tokens is the
 * hidden reasoning count when the provider exposes it, otherwise 0. cost is
 * the amount OpenRouter reports in usage.cost; it stays 0 when absent. */
typedef struct LlmUsage {
    long   prompt_tokens;
    long   completion_tokens;
    long   total_tokens;
    long   reasoning_tokens;
    double cost;
} LlmUsage;

/* One parsed answer. reason is the short first line for the footer; detail is
 * the following explanation (up to three lines, newline-separated). */
typedef struct LlmAnswer {
    int      verdict;  /* -1 unknown, 0 safe, 1 malicious */
    int      truncated; /* finish_reason was "length" but a verdict line existed */
    char     reason[LLM_REASON_MAX];
    char     detail[LLM_DETAIL_MAX];
    LlmUsage usage;
} LlmAnswer;

/**
 * True when a decision level belongs to the uncertain band [min, max].
 * Levels outside 1..10 never match; an inverted band never matches.
 */
int llm_level_eligible(int level, int min_level, int max_level);

/**
 * Copies the JSON object that follows the top-level "state" key of a decision
 * request (the exact bytes produced by model_build_request) into buf.
 * @return bytes written without the NUL, or -1 when the key or object is
 *         missing or does not fit.
 */
int llm_extract_state(const char *decision_request, char *buf, size_t sz);

/**
 * Builds the OpenRouter chat-completions request body:
 *
 *   {"model":"<llm.name>",
 *    "messages":[{"role":"system","content":"<output contract>"},
 *                {"role":"user","content":"<level + state JSON>"}],
 *    "temperature":0,"max_tokens":<max_tokens>,
 *    "usage":{"include":true}}
 *
 * The system prompt asks for a first line
 * "VERDICT <0|1> <short reason up to 80 chars>" followed by up to three
 * explanation sentences on the following lines. The state JSON is embedded
 * as an escaped JSON string, so quotes, backslashes and control bytes never
 * break the request. state_json must not exceed LLM_STATE_MAX bytes.
 * max_tokens is clamped to 1..LLM_MAX_TOKENS_MAX.
 * @return bytes written without the NUL, or -1 on truncation/bad arguments.
 */
int llm_build_request(const char *model, const char *state_json,
                      int decision_level, int max_tokens,
                      char *buf, size_t sz);

/**
 * Parses an OpenRouter chat-completions response into out.
 *
 * The content must start with "VERDICT 0|1 <short reason>" on the first line.
 * Up to three non-empty explanation lines may follow; they are copied to
 * detail, newline-separated. A reason longer than 80 bytes, a bad prefix,
 * lowercase, more than three explanation lines (when finish_reason is not
 * "length") or any other deviation sets verdict -1 with empty reason/detail.
 *
 * When finish_reason is "length" and a leading VERDICT line exists, the
 * verdict is kept: the reason gets a " [truncated]" suffix, detail keeps the
 * text that survived, and truncated is set. A reasoning-only answer with
 * content null is rejected because it carries no verdict line.
 *
 * Token usage (prompt, completion, reasoning, total, cost) is filled whenever
 * present, including on a malformed answer.
 * out must not be NULL.
 */
int llm_parse_response(const char *body, size_t len, LlmAnswer *out);

/**
 * Formats one JSONL report record:
 *   {"time":"...","pid":N,"comm":"...","verdict":N,"reason":"...",
 *    "detail":"...","truncated":0|1,"model":"...","tokens":N,
 *    "prompt_tokens":N,"completion_tokens":N,"reasoning_tokens":N,"cost":X}
 * comm, reason and detail are escaped. cmdline and the API key are never
 * accepted by this API, so they cannot leak into a report.
 * @return bytes written without the NUL, or -1 on truncation.
 */
int llm_format_report(const char *model, const char *time_iso, pid_t pid,
                      const char *comm, int verdict, const char *reason,
                      const char *detail, const LlmUsage *usage,
                      int truncated, char *buf, size_t sz);

typedef struct LlmEngine LlmEngine;

/**
 * Creates the asynchronous client. Reads the key from cfg->key_file and keeps
 * it in memory only. Posts to cfg->endpoint, which must speak the
 * OpenAI-compatible chat-completions API; the default is
 * https://openrouter.ai/api/v1/chat/completions.
 *
 * @return engine, or NULL with a one-line reason in err (empty name or
 *         endpoint, missing key file, inverted level band, curl initialisation
 *         failure).
 */
LlmEngine *llm_engine_create(const LlmConfig *cfg, char *err, size_t err_sz);

/** Frees every request, curl handle, cached verdict and the key buffer. */
void llm_engine_destroy(LlmEngine *engine);

/**
 * Non-blocking step, called once per refresh pass after model_engine_tick:
 *   - drives curl_multi (timeout 0) and applies finished verdicts to procs;
 *     every process without a cached verdict is reset to -1;
 *   - queues at most llm.max_per_pass processes whose decision level is in
 *     [llm.min_level, llm.max_level], skipping trusted processes, processes
 *     already in flight and processes asked less than llm.resample_sec ago;
 *   - starts queued requests while fewer than LLM_MAX_ACTIVE are active.
 * trust must contain procs->count entries from the same pass.
 */
void llm_engine_tick(LlmEngine *engine, ProcList *procs,
                     const TrustInfo *trust, size_t trust_count);

/**
 * One-shot dry run: collects /proc, picks the first untrusted process that has
 * package metadata (or the first untrusted one when none does), gives it the
 * middle level of the configured band and prints the chat-completions request
 * to stdout: the request line "POST <llm.endpoint> HTTP/1.1" followed by the
 * JSON body. No key is read and no network call is made.
 * @return 0 on success, 1 on error (message on stderr).
 */
int llm_engine_preview(const LlmConfig *cfg);

#endif
