#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

/* The aliases would rewrite the curl_* names used inside this file; the table
 * definition itself has to see the real declarations. */
#define MINITOP_CURLSHIM_NO_ALIASES 1
#include "curlshim.h"

/* Candidates in order: the runtime soname first, the development symlink as a
 * fallback for a system without the versioned link. Both live on the default
 * loader path, so no absolute path is baked into the binary. */
static const char *const CURL_LIBRARY_NAMES[] = {
    "libcurl.so.4",
    "libcurl.so",
};

struct CurlShim curlshim;

static void *g_library;
static int g_refs;

static int bind_table(void *lib, char *err, size_t err_sz) {
#define MINITOP_CURL_BIND(name)                                              \
    do {                                                                     \
        void *sym = dlsym(lib, "curl_" #name);                               \
        if (sym == NULL) {                                                   \
            snprintf(err, err_sz, "libcurl is missing curl_" #name);        \
            return -1;                                                       \
        }                                                                    \
        _Static_assert(sizeof(curlshim.name) == sizeof(sym),                 \
                       "a function pointer must fit in void *");             \
        memcpy(&curlshim.name, &sym, sizeof(sym));                           \
    } while (0);

    MINITOP_CURL_FUNCTIONS(MINITOP_CURL_BIND)

#undef MINITOP_CURL_BIND
    return 0;
}

static int open_library(char *err, size_t err_sz) {
    const char *last_error = "dlopen returned no library";

    for (size_t i = 0; i < sizeof(CURL_LIBRARY_NAMES) / sizeof(CURL_LIBRARY_NAMES[0]); i++) {
        void *lib = dlopen(CURL_LIBRARY_NAMES[i], RTLD_NOW | RTLD_LOCAL);
        if (lib != NULL) {
            if (bind_table(lib, err, err_sz) != 0) {
                dlclose(lib);
                return -1;
            }
            g_library = lib;
            return 0;
        }
        last_error = dlerror();
        if (last_error == NULL) {
            last_error = "dlopen failed";
        }
    }

    snprintf(err, err_sz, "libcurl is not available: %s", last_error);
    return -1;
}

int curlshim_acquire(char *err, size_t err_sz) {
    char fallback[1];

    if (err == NULL || err_sz == 0) {
        err = fallback;
        err_sz = sizeof(fallback);
    }
    if (g_library == NULL && open_library(err, err_sz) != 0) {
        return -1;
    }
    if (g_refs == 0 &&
        curlshim.global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        snprintf(err, err_sz, "libcurl initialisation failed");
        return -1;
    }
    g_refs++;
    return 0;
}

void curlshim_release(void) {
    if (g_refs <= 0) {
        return;
    }
    g_refs--;
    if (g_refs == 0) {
        curlshim.global_cleanup();
    }
}
