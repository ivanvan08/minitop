#ifndef MINITOP_INPUT_H
#define MINITOP_INPUT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "procs.h"
#include "tui.h"

enum {
    KEY_NONE = 0,
    KEY_ESC = 0x1b,
    KEY_UP = 0x100,
    KEY_DOWN,
    KEY_LEFT,
    KEY_RIGHT,
    KEY_PGUP,
    KEY_PGDN,
    KEY_HOME,
    KEY_END,
    KEY_UNKNOWN
};

typedef enum Action {
    ACT_NONE = 0,
    ACT_REDRAW,
    ACT_RESORT,
    ACT_KILL,
    ACT_QUIT
} Action;

typedef struct Control {
    /* 0 makes every navigation key inert: the table is a live view, nothing
     * moves and nothing can be killed by a stray keystroke. */
    int      navigation;
    int      follow;
    pid_t    follow_pid;
    uint64_t follow_start;

    int      confirming;
    int      kill_force;
    pid_t    kill_pid;
    uint64_t kill_start;

    pid_t    termed_pid;
    uint64_t termed_start;

    int      status_frames;
    char     status[128];
} Control;

size_t input_parse(const char *buf, size_t len, int *key);

int  term_raw_enable(int fd);
void term_raw_disable(int fd);

void   control_init(Control *c);
Action control_key(Control *c, TuiView *view, int key, const ProcList *list, size_t page);
void   control_sync(Control *c, TuiView *view, const ProcList *list, size_t page);
void   control_tick(Control *c, TuiView *view);
void   control_kill_result(Control *c, TuiView *view, int rc, int err);

#endif
