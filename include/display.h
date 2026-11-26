#ifndef MINITOP_DISPLAY_H
#define MINITOP_DISPLAY_H

#include <stddef.h>

size_t utf8_seq_len(const char *s);

size_t display_width(const char *s);

void truncate_to_width(char *dst, size_t dst_sz, const char *src, size_t width);

void pad_to_width(char *dst, size_t dst_sz, const char *src, size_t width);

#endif
