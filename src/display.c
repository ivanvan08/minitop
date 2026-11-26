#include "display.h"

#include <string.h>

#define ELLIPSIS "\xe2\x80\xa6"
#define ELLIPSIS_LEN 3

size_t utf8_seq_len(const char *s) {
    if (s == NULL || s[0] == '\0') {
        return 0;
    }
    unsigned char c = (unsigned char)s[0];
    size_t len;
    if (c < 0x80) {
        return 1;
    } else if ((c & 0xE0) == 0xC0) {
        len = 2;
    } else if ((c & 0xF0) == 0xE0) {
        len = 3;
    } else if ((c & 0xF8) == 0xF0) {
        len = 4;
    } else {
        return 1;
    }
    for (size_t k = 1; k < len; ++k) {
        if (((unsigned char)s[k] & 0xC0) != 0x80) {
            return 1;
        }
    }
    return len;
}

static size_t char_width(const char *s, size_t len) {
    (void)s;
    (void)len;
    return 1;
}

size_t display_width(const char *s) {
    if (s == NULL) {
        return 0;
    }
    size_t width = 0;
    size_t len;
    while ((len = utf8_seq_len(s)) != 0) {
        width += char_width(s, len);
        s += len;
    }
    return width;
}

static size_t copy_columns(char *dst, size_t dst_sz, const char *src, size_t width, size_t *bytes) {
    size_t di = 0;
    size_t cols = 0;
    size_t len;
    while ((len = utf8_seq_len(src)) != 0) {
        size_t w = char_width(src, len);
        if (cols + w > width || di + len >= dst_sz) {
            break;
        }
        memcpy(dst + di, src, len);
        di += len;
        cols += w;
        src += len;
    }
    dst[di] = '\0';
    *bytes = di;
    return cols;
}

static size_t fit(char *dst, size_t dst_sz, const char *src, size_t width) {
    if (src == NULL) {
        src = "";
    }
    size_t bytes = 0;
    if (display_width(src) <= width) {
        return copy_columns(dst, dst_sz, src, width, &bytes);
    }
    if (width == 0) {
        dst[0] = '\0';
        return 0;
    }
    size_t room = dst_sz > ELLIPSIS_LEN ? dst_sz - ELLIPSIS_LEN : 1;
    size_t cols = copy_columns(dst, room, src, width - 1, &bytes);
    if (bytes + ELLIPSIS_LEN < dst_sz) {
        memcpy(dst + bytes, ELLIPSIS, ELLIPSIS_LEN + 1);
        cols++;
    }
    return cols;
}

void truncate_to_width(char *dst, size_t dst_sz, const char *src, size_t width) {
    if (dst == NULL || dst_sz == 0) {
        return;
    }
    fit(dst, dst_sz, src, width);
}

void pad_to_width(char *dst, size_t dst_sz, const char *src, size_t width) {
    if (dst == NULL || dst_sz == 0) {
        return;
    }
    size_t cols = fit(dst, dst_sz, src, width);
    size_t di = strlen(dst);
    while (cols < width && di + 1 < dst_sz) {
        dst[di++] = ' ';
        cols++;
    }
    dst[di] = '\0';
}
