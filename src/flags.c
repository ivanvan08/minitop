#include "flags.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

uint8_t flags_detect_exe(const char *exe_path) {
    if (exe_path == NULL || exe_path[0] == '\0') {
        return FLAG_NONE;
    }

    uint8_t flags = FLAG_NONE;
    size_t len = strlen(exe_path);

    if (len >= 10 && strcmp(exe_path + len - 10, " (deleted)") == 0) {
        flags |= FLAG_DEL;
    }
    if (strncmp(exe_path, "/memfd:", 7) == 0) {
        flags |= FLAG_MEMFD;
    }
    if (strncmp(exe_path, "/tmp/", 5) == 0 ||
        strncmp(exe_path, "/var/tmp/", 9) == 0 ||
        strncmp(exe_path, "/dev/shm/", 9) == 0) {
        flags |= FLAG_TMP;
    }

    return flags;
}

void flags_format_tui(uint8_t flags, char *buf, size_t buf_sz) {
    if (buf == NULL || buf_sz == 0) {
        return;
    }

    /* One order everywhere: the display, the model's local_flags and the docs
     * all read DEL, TMP, MEMFD, NET, so a row never reorders as bits change. */
    static const struct {
        uint8_t     bit;
        const char *name;
    } tags[] = {
        { FLAG_DEL,   "DEL"   },
        { FLAG_TMP,   "TMP"   },
        { FLAG_MEMFD, "MEMFD" },
        { FLAG_NET,   "NET"   },
    };

    size_t used = 0;
    buf[0] = '\0';
    for (size_t i = 0; i < sizeof(tags) / sizeof(tags[0]); ++i) {
        if ((flags & tags[i].bit) == 0) {
            continue;
        }
        int n = snprintf(buf + used, buf_sz - used, "%s%s",
                         used > 0 ? "," : "", tags[i].name);
        if (n < 0 || (size_t)n >= buf_sz - used) {
            buf[buf_sz - 1] = '\0';
            return;
        }
        used += (size_t)n;
    }
    if (used == 0) {
        snprintf(buf, buf_sz, "-");
    }
}

void format_mode_rwx(mode_t m, char out[11]) {
    if (out == NULL) {
        return;
    }
    out[0] = S_ISDIR(m) ? 'd' : (S_ISLNK(m) ? 'l' : '-');
    out[1] = (m & S_IRUSR) ? 'r' : '-';
    out[2] = (m & S_IWUSR) ? 'w' : '-';
    out[3] = (m & S_IXUSR) ? ((m & S_ISUID) ? 's' : 'x') : ((m & S_ISUID) ? 'S' : '-');
    out[4] = (m & S_IRGRP) ? 'r' : '-';
    out[5] = (m & S_IWGRP) ? 'w' : '-';
    out[6] = (m & S_IXGRP) ? ((m & S_ISGID) ? 's' : 'x') : ((m & S_ISGID) ? 'S' : '-');
    out[7] = (m & S_IROTH) ? 'r' : '-';
    out[8] = (m & S_IWOTH) ? 'w' : '-';
    out[9] = (m & S_IXOTH) ? 'x' : '-';
    out[10] = '\0';
}

/* Terminal-injection guard: control characters and broken UTF-8 become '?'. */
void sanitize_display_str(char *dst, size_t dst_sz, const char *src) {
    if (dst == NULL || dst_sz == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    size_t di = 0;
    size_t si = 0;
    while (src[si] != '\0' && di + 1 < dst_sz) {
        unsigned char c = (unsigned char)src[si];

        if (c < 0x80) {
            int printable = (c >= 0x20 && c != 0x7f);
            dst[di++] = printable ? (char)c : '?';
            si++;
            continue;
        }

        size_t len = 0;
        uint32_t cp = 0;
        if ((c & 0xE0) == 0xC0) {
            len = 2;
            cp = (uint32_t)(c & 0x1Fu);
        } else if ((c & 0xF0) == 0xE0) {
            len = 3;
            cp = (uint32_t)(c & 0x0Fu);
        } else if ((c & 0xF8) == 0xF0) {
            len = 4;
            cp = (uint32_t)(c & 0x07u);
        }

        size_t consumed = 1;
        int valid = (len != 0);
        for (size_t k = 1; valid && k < len; ++k) {
            unsigned char cc = (unsigned char)src[si + k];
            if (cc == '\0' || (cc & 0xC0) != 0x80) {
                valid = 0;
            } else {
                cp = (cp << 6) | (uint32_t)(cc & 0x3Fu);
                consumed++;
            }
        }
        if (valid && (cp < 0xA0u ||
                      (len == 3 && cp < 0x800u) ||
                      (len == 4 && cp < 0x10000u) ||
                      (cp >= 0xD800u && cp <= 0xDFFFu) ||
                      cp > 0x10FFFFu)) {
            valid = 0; /* C1 controls (CSI among them), overlong encodings, surrogates */
        }

        if (!valid) {
            dst[di++] = '?';
            si += consumed;
            continue;
        }
        if (di + len >= dst_sz) {
            break; /* no room for a whole sequence */
        }
        memcpy(dst + di, src + si, len);
        di += len;
        si += len;
    }
    dst[di] = '\0';
}

static size_t split_fields(const char *s, size_t len, const char *tok[], size_t tok_len[], size_t max) {
    size_t n = 0;
    size_t i = 0;
    while (i < len && n < max) {
        while (i < len && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r')) {
            i++;
        }
        if (i >= len) {
            break;
        }
        size_t start = i;
        while (i < len && s[i] != ' ' && s[i] != '\t' && s[i] != '\r') {
            i++;
        }
        tok[n] = s + start;
        tok_len[n] = i - start;
        n++;
    }
    return n;
}

size_t net_listen_inodes(const char *text, uint64_t *out, size_t cap) {
    if (text == NULL || out == NULL || cap == 0) {
        return 0;
    }

    size_t count = 0;
    const char *p = text;
    while (*p != '\0' && count < cap) {
        const char *nl = strchr(p, '\n');
        size_t len = (nl != NULL) ? (size_t)(nl - p) : strlen(p);

        /* columns: sl, local, remote, state, queues, timer, retrnsmt, uid, timeout, inode */
        const char *tok[10];
        size_t tok_len[10];
        if (split_fields(p, len, tok, tok_len, 10) == 10) {
            int listen = (tok_len[3] == 2 && tok[3][0] == '0' && (tok[3][1] == 'A' || tok[3][1] == 'a'));
            if (listen && tok_len[9] < 24) {
                char num[24];
                memcpy(num, tok[9], tok_len[9]);
                num[tok_len[9]] = '\0';
                char *end = NULL;
                unsigned long long inode = strtoull(num, &end, 10);
                if (end != num && *end == '\0') {
                    out[count++] = (uint64_t)inode;
                }
            }
        }

        if (nl == NULL) {
            break;
        }
        p = nl + 1;
    }
    return count;
}

int net_socket_inode(const char *link, uint64_t *out) {
    if (link == NULL || out == NULL) {
        return -1;
    }
    if (strncmp(link, "socket:[", 8) != 0) {
        return -1;
    }
    const char *num = link + 8;
    char *end = NULL;
    unsigned long long inode = strtoull(num, &end, 10);
    if (end == num || *end != ']') {
        return -1;
    }
    *out = (uint64_t)inode;
    return 0;
}
