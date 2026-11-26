#ifndef MINITOP_FLAGS_H
#define MINITOP_FLAGS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define FLAG_NONE  0u
#define FLAG_DEL   (1u << 0) /* " (deleted)" */
#define FLAG_TMP   (1u << 1) /* /tmp/, /var/tmp/, or /dev/shm/ */
#define FLAG_MEMFD (1u << 2) /* /memfd: */
#define FLAG_NET   (1u << 3) /* owns a listening socket; set by the /proc pass */

/**
 * Pure detector of executable path flags (DEL, TMP, MEMFD) from a resolved symlink string.
 * FLAG_NET comes from the socket scan in procs_collect(), not from the path.
 */
uint8_t flags_detect_exe(const char *exe_path);

/**
 * Formats every set flag for the FLAGS column, comma separated in the order
 * DEL, TMP, MEMFD, NET (e.g. "DEL,TMP,MEMFD,NET"), or "-" when none is set.
 */
void flags_format_tui(uint8_t flags, char *buf, size_t buf_sz);

/**
 * Formats st_mode bits into a 10-character permission string (e.g. "-rwxr-xr-x").
 */
void format_mode_rwx(mode_t mode, char out[11]);

/**
 * Replaces control characters and invalid UTF-8 bytes with '?', keeping printable ASCII
 * and well-formed multi-byte UTF-8 sequences intact.
 */
void sanitize_display_str(char *dst, size_t dst_sz, const char *src);

/**
 * Parses /proc/net/tcp or /proc/net/tcp6 text and stores the inodes of sockets in the
 * LISTEN state (0A). Accepts either the whole file or a single line.
 * @return number of inodes written.
 */
size_t net_listen_inodes(const char *text, uint64_t *out, size_t cap);

/**
 * Parses a "socket:[12345]" fd link into its inode.
 * @return 0 on success, -1 on any other link text.
 */
int net_socket_inode(const char *link, uint64_t *out);

#endif
