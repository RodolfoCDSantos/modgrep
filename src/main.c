/*
 * modgrep - MODBUS TCP ladder diagram viewer (ncurses)
 * Inspired by sngrep: https://github.com/irontec/sngrep
 * Copyright (c) 2026 Rodolfo Santos - MIT License
 */
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <curses.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define MBAP_LEN 7
#define RAW_MAX 48

typedef struct {
    struct timeval ts;
    int is_request;
    uint16_t sport, dport, tid;
    uint8_t unit, fc;
    uint8_t raw[RAW_MAX];
    size_t rawlen;
    char text[160];
} msg_t;

typedef struct {
    char client[INET_ADDRSTRLEN];
    char server[INET_ADDRSTRLEN];
    msg_t *msgs;
    size_t count, cap;
} conv_t;

static conv_t *convs;
static size_t nconvs, capconvs;
static int link_type;
static uint16_t modbus_port = 502;
static pcap_t *live;

static unsigned u16(const uint8_t *p) { return ((unsigned)p[0] << 8) | p[1]; }

static void *xrealloc(void *ptr, size_t size) {
    void *n = realloc(ptr, size);
    if (!n) {
        endwin();
        fputs("out of memory\n", stderr);
        exit(1);
    }
    return n;
}

static const char *fname(uint8_t c) {
    switch (c) {
    case 1: return "Read Coils";
    case 2: return "Read Discrete Inputs";
    case 3: return "Read Holding Registers";
    case 4: return "Read Input Registers";
    case 5: return "Write Single Coil";
    case 6: return "Write Single Register";
    case 15: return "Write Multiple Coils";
    case 16: return "Write Multiple Registers";
    default: return "Unknown Function";
    }
}

static void describe(const uint8_t *f, size_t len, int req, char *out, size_t n) {
    uint8_t fc = f[7], base = fc & 0x7f;
    const uint8_t *d = f + 8;
    size_t r = len - 8;
    int w;
    char *p;
    size_t m;

    if (fc & 0x80) {
        snprintf(out, n, "EXCEPTION %s (0x%02x) code=0x%02x", fname(base), fc, r ? d[0] : 0);
        return;
    }
    w = snprintf(out, n, "%s (0x%02x)", fname(base), fc);
    if (w < 0 || (size_t)w >= n)
        return;
    p = out + w;
    m = n - (size_t)w;
    switch (base) {
    case 1: case 2: case 3: case 4:
        if (req && r >= 4)
            snprintf(p, m, " addr=%u qty=%u", u16(d), u16(d + 2));
        else if (!req && r >= 1)
            snprintf(p, m, " bytes=%u", d[0]);
        break;
    case 5: case 6:
        if (r >= 4)
            snprintf(p, m, " addr=%u value=%u", u16(d), u16(d + 2));
        break;
    case 15: case 16:
        if (req && r >= 5)
            snprintf(p, m, " addr=%u qty=%u bytes=%u", u16(d), u16(d + 2), d[4]);
        else if (!req && r >= 4)
            snprintf(p, m, " addr=%u qty=%u", u16(d), u16(d + 2));
        break;
    default:
        break;
    }
}

static void fmt_time(const struct timeval *ts, char *out, size_t n) {
    struct tm tmv;
    char b[16];
    time_t s = ts->tv_sec;

    localtime_r(&s, &tmv);
    strftime(b, sizeof b, "%H:%M:%S", &tmv);
    snprintf(out, n, "%s.%03ld", b, (long)(ts->tv_usec / 1000));
}

static void add_msg(const char *src, const char *dst, int req, const struct timeval *ts,
                    uint16_t sport, uint16_t dport, const uint8_t *f, size_t flen) {
    const char *client = req ? src : dst;
    const char *server = req ? dst : src;
    conv_t *c = NULL;
    msg_t *m;
    size_t i;

    for (i = 0; i < nconvs; i++)
        if (!strcmp(convs[i].client, client) && !strcmp(convs[i].server, server)) {
            c = &convs[i];
            break;
        }
    if (!c) {
        if (nconvs == capconvs) {
            capconvs = capconvs ? capconvs * 2 : 16;
            convs = xrealloc(convs, capconvs * sizeof(*convs));
        }
        c = &convs[nconvs++];
        memset(c, 0, sizeof(*c));
        snprintf(c->client, sizeof c->client, "%s", client);
        snprintf(c->server, sizeof c->server, "%s", server);
    }
    if (c->count == c->cap) {
        c->cap = c->cap ? c->cap * 2 : 64;
        c->msgs = xrealloc(c->msgs, c->cap * sizeof(*c->msgs));
    }
    m = &c->msgs[c->count++];
    memset(m, 0, sizeof(*m));
    m->ts = *ts;
    m->is_request = req;
    m->sport = sport;
    m->dport = dport;
    m->tid = (uint16_t)u16(f);
    m->unit = f[6];
    m->fc = f[7];
    m->rawlen = flen < RAW_MAX ? flen : RAW_MAX;
    memcpy(m->raw, f, m->rawlen);
    describe(f, flen, req, m->text, sizeof m->text);
}

static void handle_packet(const struct pcap_pkthdr *h, const uint8_t *pkt) {
    size_t cap = h->caplen, off, ihl, t, thl, start, end, o;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    uint16_t sport, dport;
    int req;

    switch (link_type) {
    case DLT_EN10MB: {
        unsigned et;
        if (cap < 14)
            return;
        et = u16(pkt + 12);
        off = 14;
        if (et == 0x8100 && cap >= 18) {
            et = u16(pkt + 16);
            off = 18;
        }
        if (et != 0x0800)
            return;
        break;
    }
    case DLT_LINUX_SLL:
        if (cap < 16 || u16(pkt + 14) != 0x0800)
            return;
        off = 16;
        break;
    case DLT_RAW:
        off = 0;
        break;
    default:
        return;
    }

    if (cap < off + 20 || (pkt[off] >> 4) != 4 || pkt[off + 9] != 6)
        return;
    ihl = (size_t)(pkt[off] & 0x0f) * 4;
    t = off + ihl;
    if (ihl < 20 || cap < t + 20)
        return;
    thl = (size_t)(pkt[t + 12] >> 4) * 4;
    start = t + thl;
    end = off + u16(pkt + off + 2);
    if (end > cap)
        end = cap;
    if (thl < 20 || start >= end)
        return;

    sport = (uint16_t)u16(pkt + t);
    dport = (uint16_t)u16(pkt + t + 2);
    if (dport == modbus_port)
        req = 1;
    else if (sport == modbus_port)
        req = 0;
    else
        return;

    inet_ntop(AF_INET, pkt + off + 12, src, sizeof src);
    inet_ntop(AF_INET, pkt + off + 16, dst, sizeof dst);

    o = start;
    while (end - o >= MBAP_LEN + 1) {
        const uint8_t *f = pkt + o;
        unsigned plen = u16(f + 4);
        size_t flen;

        if (u16(f + 2) != 0 || plen < 2)
            break;
        flen = 6 + (size_t)plen;
        if (o + flen > end)
            break;
        add_msg(src, dst, req, &h->ts, sport, dport, f, flen);
        o += flen;
    }
}

static void pcap_cb(u_char *user, const struct pcap_pkthdr *h, const u_char *p) {
    (void)user;
    handle_packet(h, p);
}

static void poll_live(void) {
    if (live)
        pcap_dispatch(live, -1, pcap_cb, NULL);
}

static void draw_list(size_t sel) {
    int rows = LINES - 5, i;
    size_t top;

    if (rows < 1)
        rows = 1;
    top = sel >= (size_t)rows ? sel - (size_t)rows + 1 : 0;
    erase();
    attron(A_REVERSE);
    mvhline(0, 0, ' ', COLS);
    mvprintw(0, 0, " modgrep - MODBUS TCP conversations%s", live ? " (live)" : "");
    attroff(A_REVERSE);
    mvprintw(2, 0, " %-4s %-17s %-17s %-8s %s", "#", "Client", "Server", "Msgs", "First seen");
    for (i = 0; i < rows && top + (size_t)i < nconvs; i++) {
        conv_t *c = &convs[top + (size_t)i];
        char tb[32];

        fmt_time(&c->msgs[0].ts, tb, sizeof tb);
        if (top + (size_t)i == sel) {
            attron(A_REVERSE);
            mvhline(3 + i, 0, ' ', COLS);
        }
        mvprintw(3 + i, 0, " %-4zu %-17s %-17s %-8zu %s", top + (size_t)i + 1, c->client, c->server, c->count, tb);
        attroff(A_REVERSE);
    }
    if (!nconvs)
        mvprintw(4, 2, "No MODBUS TCP traffic found yet.");
    attron(A_REVERSE);
    mvhline(LINES - 1, 0, ' ', COLS);
    mvprintw(LINES - 1, 0, " Up/Down = select | Enter = ladder diagram | q = quit");
    attroff(A_REVERSE);
    refresh();
}

static void ladder(size_t ci) {
    size_t sel = 0, top = 0;
    int detail = 0;

    for (;;) {
        conv_t *c;
        int lx = 18, rx = COLS - 18, rows, i, k;
        char tb[32], status[300];
        msg_t *cur = NULL;

        poll_live();
        c = &convs[ci];
        if (rx < lx + 30)
            rx = lx + 30;
        rows = (LINES - 7) / 2;
        if (rows < 1)
            rows = 1;
        if (c->count && sel >= c->count)
            sel = c->count - 1;
        if (sel < top)
            top = sel;
        if (sel >= top + (size_t)rows)
            top = sel - (size_t)rows + 1;

        erase();
        attron(A_REVERSE);
        mvhline(0, 0, ' ', COLS);
        mvprintw(0, 0, " modgrep - ladder diagram (%zu messages)%s", c->count, live ? " (live)" : "");
        attroff(A_REVERSE);
        attron(COLOR_PAIR(4) | A_BOLD);
        mvprintw(2, lx - 8, "%-15s", c->client);
        mvprintw(2, rx - 8, "%-15s", c->server);
        attroff(COLOR_PAIR(4) | A_BOLD);
        mvvline(3, lx, ACS_VLINE, LINES - 6);
        mvvline(3, rx, ACS_VLINE, LINES - 6);

        for (i = 0; i < rows && top + (size_t)i < c->count; i++) {
            msg_t *m = &c->msgs[top + (size_t)i];
            int r = 4 + i * 2, pair, w = rx - lx - 3;

            pair = (m->fc & 0x80) ? 3 : (m->is_request ? 1 : 2);
            fmt_time(&m->ts, tb, sizeof tb);
            mvprintw(r + 1, 0, "%s", tb);
            if (top + (size_t)i == sel)
                attron(A_REVERSE);
            mvprintw(r, lx + 2, "%.*s", w, m->text);
            attroff(A_REVERSE);
            attron(COLOR_PAIR(pair) | A_BOLD);
            mvhline(r + 1, lx + 1, ACS_HLINE, rx - lx - 1);
            if (m->is_request)
                mvaddch(r + 1, rx - 1, '>');
            else
                mvaddch(r + 1, lx + 1, '<');
            attroff(COLOR_PAIR(pair) | A_BOLD);
        }

        if (c->count)
            cur = &c->msgs[sel];
        if (cur) {
            long ms = -1;
            size_t j;

            if (!cur->is_request)
                for (j = sel; j-- > 0;)
                    if (c->msgs[j].is_request && c->msgs[j].tid == cur->tid) {
                        ms = (cur->ts.tv_sec - c->msgs[j].ts.tv_sec) * 1000L +
                             (cur->ts.tv_usec - c->msgs[j].ts.tv_usec) / 1000L;
                        break;
                    }
            fmt_time(&cur->ts, tb, sizeof tb);
            snprintf(status, sizeof status, " %s  %s:%u -> %s:%u  tid=%u unit=%u%s", tb,
                     cur->is_request ? c->client : c->server, cur->sport,
                     cur->is_request ? c->server : c->client, cur->dport, cur->tid, cur->unit,
                     ms >= 0 ? "  response time shown below" : "");
            if (ms >= 0) {
                size_t l = strlen(status);
                snprintf(status + l - 26, sizeof status - (l - 26), "  latency=%ld ms", ms);
            }
            if (detail) {
                char hx[3 * RAW_MAX + 8];
                size_t b, p = 0;

                for (b = 0; b < cur->rawlen; b++)
                    p += (size_t)snprintf(hx + p, sizeof hx - p, "%02x ", cur->raw[b]);
                hx[p] = 0;
                mvprintw(LINES - 3, 0, " raw: %.*s", COLS - 7, hx);
            }
        } else {
            snprintf(status, sizeof status, " No messages");
        }
        attron(A_REVERSE);
        mvhline(LINES - 2, 0, ' ', COLS);
        mvprintw(LINES - 2, 0, "%.*s", COLS - 1, status);
        mvhline(LINES - 1, 0, ' ', COLS);
        mvprintw(LINES - 1, 0, " Up/Down = select | PgUp/PgDn = scroll | Enter = raw hex | q = back");
        attroff(A_REVERSE);
        refresh();

        k = getch();
        if (k == ERR)
            continue;
        if (k == 'q' || k == 27)
            return;
        if ((k == KEY_UP || k == 'k') && sel > 0)
            sel--;
        else if ((k == KEY_DOWN || k == 'j') && sel + 1 < c->count)
            sel++;
        else if (k == KEY_PPAGE)
            sel = sel > (size_t)rows ? sel - (size_t)rows : 0;
        else if (k == KEY_NPAGE && c->count)
            sel = (sel + (size_t)rows < c->count) ? sel + (size_t)rows : c->count - 1;
        else if (k == 10 || k == KEY_ENTER)
            detail = !detail;
    }
}

static void run_ui(void) {
    size_t sel = 0;

    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(1, COLOR_GREEN, -1);
        init_pair(2, COLOR_YELLOW, -1);
        init_pair(3, COLOR_RED, -1);
        init_pair(4, COLOR_CYAN, -1);
    }
    timeout(live ? 150 : -1);

    for (;;) {
        int k;

        poll_live();
        if (nconvs && sel >= nconvs)
            sel = nconvs - 1;
        draw_list(sel);
        k = getch();
        if (k == ERR)
            continue;
        if (k == 'q' || k == 27)
            break;
        if ((k == KEY_UP || k == 'k') && sel > 0)
            sel--;
        else if ((k == KEY_DOWN || k == 'j') && sel + 1 < nconvs)
            sel++;
        else if ((k == 10 || k == KEY_ENTER || k == ' ') && nconvs)
            ladder(sel);
    }
    endwin();
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s -r <file.pcap> | -i <interface> [-p port] [-f bpf-filter]\n", prog);
}

int main(int argc, char **argv) {
    const char *iface = NULL, *file = NULL, *filter = NULL;
    char fbuf[64], err[PCAP_ERRBUF_SIZE];
    struct bpf_program prog;
    pcap_t *h;
    int o;

    while ((o = getopt(argc, argv, "i:r:f:p:h")) != -1) {
        switch (o) {
        case 'i': iface = optarg; break;
        case 'r': file = optarg; break;
        case 'f': filter = optarg; break;
        case 'p': modbus_port = (uint16_t)atoi(optarg); break;
        default: usage(argv[0]); return o == 'h' ? 0 : 1;
        }
    }
    if (!iface == !file) {
        usage(argv[0]);
        return 1;
    }
    if (!filter) {
        snprintf(fbuf, sizeof fbuf, "tcp port %u", modbus_port);
        filter = fbuf;
    }

    if (file) {
        h = pcap_open_offline(file, err);
    } else {
        h = pcap_create(iface, err);
        if (h) {
            pcap_set_snaplen(h, 65535);
            pcap_set_promisc(h, 1);
            pcap_set_timeout(h, 100);
            if (pcap_activate(h) < 0) {
                fprintf(stderr, "Cannot activate %s: %s\n", iface, pcap_geterr(h));
                pcap_close(h);
                return 1;
            }
            pcap_setnonblock(h, 1, err);
        }
    }
    if (!h) {
        fprintf(stderr, "pcap error: %s\n", err);
        return 1;
    }
    if (pcap_compile(h, &prog, filter, 1, PCAP_NETMASK_UNKNOWN) < 0 || pcap_setfilter(h, &prog) < 0) {
        fprintf(stderr, "Invalid filter: %s\n", pcap_geterr(h));
        pcap_close(h);
        return 1;
    }
    pcap_freecode(&prog);
    link_type = pcap_datalink(h);

    if (file) {
        struct pcap_pkthdr *hdr;
        const u_char *data;

        while (pcap_next_ex(h, &hdr, &data) == 1)
            handle_packet(hdr, data);
        pcap_close(h);
    } else {
        live = h;
    }

    run_ui();
    if (live)
        pcap_close(live);
    return 0;
}
