#include "input.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define STATUS_FRAMES 3

static struct termios g_saved;
static int g_raw_active = 0;

int term_raw_enable(int fd) {
    if (!isatty(fd) || tcgetattr(fd, &g_saved) != 0) {
        return -1;
    }
    struct termios raw = g_saved;
    raw.c_lflag &= (tcflag_t)~(ICANON | ECHO);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(fd, TCSANOW, &raw) != 0) {
        return -1;
    }
    g_raw_active = 1;
    return 0;
}

void term_raw_disable(int fd) {
    if (g_raw_active) {
        tcsetattr(fd, TCSANOW, &g_saved);
        g_raw_active = 0;
    }
}

static int csi_key(char final, int param) {
    switch (final) {
    case 'A': return KEY_UP;
    case 'B': return KEY_DOWN;
    case 'C': return KEY_RIGHT;
    case 'D': return KEY_LEFT;
    case 'H': return KEY_HOME;
    case 'F': return KEY_END;
    case '~':
        switch (param) {
        case 1:
        case 7: return KEY_HOME;
        case 4:
        case 8: return KEY_END;
        case 5: return KEY_PGUP;
        case 6: return KEY_PGDN;
        default: return KEY_UNKNOWN;
        }
    default:
        return KEY_UNKNOWN;
    }
}

size_t input_parse(const char *buf, size_t len, int *key) {
    *key = KEY_NONE;
    if (buf == NULL || len == 0) {
        return 0;
    }
    unsigned char c = (unsigned char)buf[0];
    if (c != 0x1b) {
        *key = c;
        return 1;
    }
    if (len == 1 || (buf[1] != '[' && buf[1] != 'O')) {
        *key = KEY_ESC;
        return 1;
    }
    int param = 0;
    for (size_t i = 2; i < len; ++i) {
        unsigned char b = (unsigned char)buf[i];
        if (b >= '0' && b <= '9') {
            /* Clamp instead of multiplying: a pasted sequence with ten digits
             * would overflow int. A key is only ever compared against small
             * numbers, so any large value means the same thing. */
            if (param < 100000) {
                param = param * 10 + (b - '0');
            }
            continue;
        }
        if (b >= 0x40 && b <= 0x7e) {
            *key = csi_key((char)b, param);
            return i + 1;
        }
        if (b < 0x20 || b > 0x3f) {
            *key = KEY_UNKNOWN;
            return i;
        }
    }
    *key = KEY_UNKNOWN;
    return len;
}

__attribute__((format(printf, 3, 4)))
static void set_status(Control *c, int frames, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(c->status, sizeof(c->status), fmt, ap);
    va_end(ap);
    c->status_frames = frames;
}

static void keep_visible(TuiView *view, size_t page) {
    if (view->sel_row < 0 || page == 0) {
        return;
    }
    size_t sel = (size_t)view->sel_row;
    if (sel < view->scroll) {
        view->scroll = sel;
    } else if (sel >= view->scroll + page) {
        view->scroll = sel - page + 1;
    }
}

static void publish(Control *c, TuiView *view) {
    view->status = c->status[0] != '\0' ? c->status : NULL;
    view->follow_pid = c->follow ? c->follow_pid : 0;
}

void control_init(Control *c) {
    if (c != NULL) {
        memset(c, 0, sizeof(*c));
        c->navigation = 1;
    }
}

static const ProcessInfo *selected(const TuiView *view, const ProcList *list) {
    if (view->sel_row < 0 || list == NULL || (size_t)view->sel_row >= list->count) {
        return NULL;
    }
    return &list->items[view->sel_row];
}

static void move_row(Control *c, TuiView *view, const ProcList *list, long delta) {
    if (list == NULL || list->count == 0) {
        view->sel_row = -1;
        return;
    }
    long row = view->sel_row < 0 ? (delta > 0 ? 0 : (long)list->count - 1) : (long)view->sel_row + delta;
    if (view->sel_row < 0 && (delta > 1 || delta < -1)) {
        row = delta > 0 ? 0 : (long)list->count - 1;
    }
    if (row < 0) {
        row = 0;
    }
    if (row >= (long)list->count) {
        row = (long)list->count - 1;
    }
    view->sel_row = row;
    if (c->follow) {
        c->follow = 0;
        set_status(c, STATUS_FRAMES, "follow off");
    }
}

static const char *const column_names[COL_COUNT] = {
    "pid", "user", "command", "state", "cpu", "mem", "time", "flags", "perms"
};

static Action sort_toggle(TuiView *view) {
    if (view->sort_col != view->sel_col) {
        view->sort_col = view->sel_col;
        view->sort_desc = 1;
    } else {
        view->sort_desc = !view->sort_desc;
    }
    return ACT_RESORT;
}

static Action confirm_key(Control *c, TuiView *view, int key, const ProcList *list) {
    c->confirming = 0;
    if (key != 'y' && key != 'Y') {
        set_status(c, STATUS_FRAMES, "kill cancelled");
        publish(c, view);
        return ACT_REDRAW;
    }
    if (proclist_find_followed(list, c->kill_pid, c->kill_start) < 0) {
        set_status(c, STATUS_FRAMES, "process %d already exited", (int)c->kill_pid);
        publish(c, view);
        return ACT_REDRAW;
    }
    c->status[0] = '\0';
    publish(c, view);
    return ACT_KILL;
}

/* nearest visible column, searching outward; ties go to the right */
static void ensure_sel_visible(TuiView *view) {
    int from = (int)view->sel_col;
    if (from >= 0 && from < COL_COUNT && view->col_visible[from]) {
        return;
    }
    if (from < 0 || from >= COL_COUNT) {
        from = 0;
    }
    for (int d = 1; d < COL_COUNT; ++d) {
        int right = from + d;
        int left = from - d;
        if (right < COL_COUNT && view->col_visible[right]) {
            view->sel_col = (SortColumn)right;
            return;
        }
        if (left >= 0 && view->col_visible[left]) {
            view->sel_col = (SortColumn)left;
            return;
        }
    }
    view->sel_col = COL_PID;
}

static int step_column(const TuiView *view, int dir) {
    int i = (int)view->sel_col;
    while (i + dir >= 0 && i + dir < COL_COUNT) {
        i += dir;
        if (view->col_visible[i]) {
            return i;
        }
    }
    return -1;
}

Action control_key(Control *c, TuiView *view, int key, const ProcList *list, size_t page) {
    if (c == NULL || view == NULL) {
        return ACT_NONE;
    }
    ensure_sel_visible(view);
    if (c->confirming) {
        return confirm_key(c, view, key, list);
    }
    if (!c->navigation) {
        /* Nothing moves and nothing can be killed; the table stays a live view
         * and only q quits. A confirmation already in flight is still answered
         * above, so the switch can never wedge a pending kill question. */
        return key == 'q' || key == 'Q' ? ACT_QUIT : ACT_NONE;
    }
    Action act = ACT_REDRAW;
    const ProcessInfo *p;
    long step = page > 1 ? (long)page - 1 : 1;
    switch (key) {
    case 'q':
    case 'Q':
        return ACT_QUIT;
    case 'h':
    case KEY_LEFT: {
        int prev = step_column(view, -1);
        if (prev >= 0) {
            view->sel_col = (SortColumn)prev;
        }
        break;
    }
    case 'l':
    case KEY_RIGHT: {
        int next = step_column(view, 1);
        if (next >= 0) {
            view->sel_col = (SortColumn)next;
        }
        break;
    }
    case 'j':
        move_row(c, view, list, 1);
        break;
    case 'k':
        move_row(c, view, list, -1);
        break;
    case 's':
    case 'S':
        act = sort_toggle(view);
        set_status(c, STATUS_FRAMES, "sort %s %s",
                   column_names[(int)view->sort_col],
                   view->sort_desc ? "desc" : "asc");
        break;
    case KEY_UP:
        move_row(c, view, list, -1);
        break;
    case KEY_DOWN:
        move_row(c, view, list, 1);
        break;
    case KEY_PGUP:
        move_row(c, view, list, -step);
        break;
    case KEY_PGDN:
        move_row(c, view, list, step);
        break;
    case KEY_HOME:
        move_row(c, view, list, -(long)(list ? list->count : 0));
        break;
    case KEY_END:
        move_row(c, view, list, (long)(list ? list->count : 0));
        break;
    case 'f':
    case 'F':
        p = selected(view, list);
        if (c->follow) {
            c->follow = 0;
            set_status(c, STATUS_FRAMES, "follow off");
        } else if (p == NULL) {
            set_status(c, STATUS_FRAMES, "select a row with j/k first");
        } else {
            c->follow = 1;
            c->follow_pid = p->pid;
            c->follow_start = p->starttime;
            set_status(c, STATUS_FRAMES, "following %d %s", (int)p->pid, p->comm);
        }
        break;
    case 'x':
    case 'X':
        p = selected(view, list);
        if (p == NULL) {
            set_status(c, STATUS_FRAMES, "select a row with j/k first");
            break;
        }
        c->confirming = 1;
        c->kill_pid = p->pid;
        c->kill_start = p->starttime;
        c->kill_force = (c->termed_pid == p->pid && c->termed_start == p->starttime);
        set_status(c, 0, "%s %d %s?  y / n", c->kill_force ? "SIGKILL" : "SIGTERM", (int)p->pid, p->comm);
        break;
    case KEY_ESC:
        c->follow = 0;
        view->sel_row = -1;
        view->scroll = 0;
        c->status[0] = '\0';
        break;
    default:
        return ACT_NONE;
    }
    keep_visible(view, page);
    publish(c, view);
    return act;
}

void control_sync(Control *c, TuiView *view, const ProcList *list, size_t page) {
    if (c == NULL || view == NULL || list == NULL) {
        return;
    }
    ensure_sel_visible(view);
    if (c->follow) {
        ssize_t idx = proclist_find_followed(list, c->follow_pid, c->follow_start);
        if (idx < 0) {
            c->follow = 0;
            view->sel_row = -1;
            set_status(c, STATUS_FRAMES, "process %d exited, follow off", (int)c->follow_pid);
        } else {
            view->sel_row = idx;
        }
    }
    if (view->sel_row >= 0 && (size_t)view->sel_row >= list->count) {
        view->sel_row = list->count > 0 ? (ssize_t)list->count - 1 : -1;
    }
    if (view->scroll > list->count) {
        view->scroll = 0;
    }
    keep_visible(view, page);
    publish(c, view);
}

void control_tick(Control *c, TuiView *view) {
    if (c == NULL || view == NULL) {
        return;
    }
    if (!c->confirming && c->status_frames > 0 && --c->status_frames == 0) {
        c->status[0] = '\0';
    }
    publish(c, view);
}

void control_kill_result(Control *c, TuiView *view, int rc, int err) {
    const char *sig = c->kill_force ? "SIGKILL" : "SIGTERM";
    if (rc == 0) {
        set_status(c, STATUS_FRAMES, "sent %s to %d", sig, (int)c->kill_pid);
        if (!c->kill_force) {
            c->termed_pid = c->kill_pid;
            c->termed_start = c->kill_start;
        }
    } else {
        set_status(c, STATUS_FRAMES, "%s %d failed: %s", sig, (int)c->kill_pid, strerror(err));
    }
    publish(c, view);
}
