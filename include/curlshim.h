#ifndef MINITOP_CURLSHIM_H
#define MINITOP_CURLSHIM_H

#include <stddef.h>

#include <curl/curl.h>

/*
 * Every libcurl entry point the two engines use, resolved by name at run time.
 * The executable itself references no libcurl symbol and is linked with
 * --as-needed, so the dynamic loader maps neither libcurl nor its TLS
 * dependencies until a mode 2 or mode 3 engine is created. Mode 1 never calls
 * curlshim_acquire(), therefore it never dlopen()s the library.
 *
 * The fields are declared with __typeof__ so the variadic prototypes
 * (curl_easy_setopt, curl_easy_getinfo) stay exact and calls through the
 * table are indistinguishable from direct calls at the call site.
 */
#define MINITOP_CURL_FUNCTIONS(X) \
    X(global_init)                \
    X(global_cleanup)             \
    X(multi_init)                 \
    X(multi_cleanup)              \
    X(multi_add_handle)           \
    X(multi_remove_handle)        \
    X(multi_poll)                 \
    X(multi_perform)              \
    X(multi_info_read)            \
    X(easy_init)                  \
    X(easy_cleanup)               \
    X(easy_setopt)                \
    X(easy_getinfo)               \
    X(slist_append)               \
    X(slist_free_all)

struct CurlShim {
#define MINITOP_CURL_FIELD(name) __typeof__(curl_##name) *name;
    MINITOP_CURL_FUNCTIONS(MINITOP_CURL_FIELD)
#undef MINITOP_CURL_FIELD
};

extern struct CurlShim curlshim;

/*
 * Resolves the table on the first call and initialises libcurl; every
 * successful acquire must be paired with curlshim_release(). The last release
 * runs curl_global_cleanup(), mirroring the one init/cleanup pair the engines
 * performed before loading became lazy. The library stays mapped until exit,
 * which is harmless: the only code that reaches here is the network modes.
 *
 * @return 0 on success, -1 with a one-line reason in err (libcurl not
 *         installed, a missing symbol, or failed global initialisation).
 */
int curlshim_acquire(char *err, size_t err_sz);

/** Drops one reference; calls curl_global_cleanup() when the last one goes. */
void curlshim_release(void);

/* Call sites keep their curl_* spelling; the preprocessor redirects them
 * through the table, so no direct symbol reference is emitted. curl.h aliases
 * two of these names to its compile-time argument checker, which has no type
 * information for a pointer table; drop those wrappers before replacing them. */
#ifndef MINITOP_CURLSHIM_NO_ALIASES
#undef curl_easy_setopt
#undef curl_easy_getinfo
#define curl_global_init       curlshim.global_init
#define curl_global_cleanup    curlshim.global_cleanup
#define curl_multi_init        curlshim.multi_init
#define curl_multi_cleanup     curlshim.multi_cleanup
#define curl_multi_add_handle  curlshim.multi_add_handle
#define curl_multi_remove_handle curlshim.multi_remove_handle
#define curl_multi_poll        curlshim.multi_poll
#define curl_multi_perform     curlshim.multi_perform
#define curl_multi_info_read   curlshim.multi_info_read
#define curl_easy_init         curlshim.easy_init
#define curl_easy_cleanup      curlshim.easy_cleanup
#define curl_easy_setopt       curlshim.easy_setopt
#define curl_easy_getinfo      curlshim.easy_getinfo
#define curl_slist_append      curlshim.slist_append
#define curl_slist_free_all    curlshim.slist_free_all
#endif

#endif /* MINITOP_CURLSHIM_H */
