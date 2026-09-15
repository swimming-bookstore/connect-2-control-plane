/* Record a PTY session to raw RGB24 frames (stdin of ffmpeg). */
#define _XOPEN_SOURCE 600
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <ft2build.h>
#include FT_FREETYPE_H

#define COLS 106
#define ROWS 30
#define CELL_W 12
#define CELL_H 24
#define PAD_X 4
#define PAD_Y 0
#define W 1280
#define H 720
#define FPS 12

static unsigned char screen_ch[ROWS][COLS];
static unsigned char screen_fg[ROWS][COLS];
static int cur_r, cur_c;
static int fg, bold;
static int master_fd = -1;
static int password_sent;
static unsigned char frame[W * H * 3];
static unsigned char pending[4096];
static int pending_n;

static void reply(const char *s) {
    if (master_fd >= 0) {
        ssize_t _n = write(master_fd, s, strlen(s));
        (void)_n;
    }
}

static void maybe_send_password_from_bytes(const unsigned char *buf, int n) {
    if (n <= 0) return;
    for (int i = 0; i + 3 < n; i++) {
        if (buf[i] == 0x1b && buf[i + 1] == ']' && buf[i + 2] == '1' && buf[i + 3] == '1')
            reply("\033]11;rgb:0b0b/1212/2020\007");
        if (buf[i] == 0x1b && buf[i + 1] == '[' && buf[i + 2] == '6' && buf[i + 3] == 'n')
            reply("\033[1;1R");
    }
    if (password_sent) return;
    for (int i = 0; i + 8 < n; i++) {
        if (buf[i] == 'a' && buf[i + 1] == 's' && buf[i + 2] == 's' &&
            buf[i + 3] == 'w' && buf[i + 4] == 'o' && buf[i + 5] == 'r' &&
            buf[i + 6] == 'd') {
            reply("adminadmin\r");
            password_sent = 1;
            return;
        }
    }
}

static const unsigned char pal[16][3] = {
    {11, 18, 32}, {239, 68, 68}, {52, 211, 153}, {251, 191, 36},
    {56, 189, 248}, {196, 181, 253}, {34, 211, 238}, {230, 237, 243},
    {100, 116, 139}, {248, 113, 113}, {110, 231, 183}, {253, 224, 71},
    {125, 211, 252}, {216, 180, 254}, {103, 232, 249}, {255, 255, 255},
};

static void clear_screen(void) {
    memset(screen_ch, ' ', sizeof(screen_ch));
    memset(screen_fg, 7, sizeof(screen_fg));
    cur_r = cur_c = 0;
}

static void scroll_up(void) {
    memmove(&screen_ch[0][0], &screen_ch[1][0], (ROWS - 1) * COLS);
    memmove(&screen_fg[0][0], &screen_fg[1][0], (ROWS - 1) * COLS);
    memset(screen_ch[ROWS - 1], ' ', COLS);
    memset(screen_fg[ROWS - 1], 7, COLS);
}

static void putc_at(unsigned char ch) {
    if (ch == '\r') {
        cur_c = 0;
        return;
    }
    if (ch == '\n') {
        cur_c = 0;
        cur_r++;
        if (cur_r >= ROWS) {
            cur_r = ROWS - 1;
            scroll_up();
        }
        return;
    }
    if (ch == '\b') {
        if (cur_c > 0) cur_c--;
        return;
    }
    if (ch == '\t') {
        cur_c = (cur_c + 8) & ~7;
        if (cur_c >= COLS) {
            cur_c = 0;
            cur_r++;
            if (cur_r >= ROWS) {
                cur_r = ROWS - 1;
                scroll_up();
            }
        }
        return;
    }
    if (ch < 32) return;
    if (cur_c >= COLS) {
        cur_c = 0;
        cur_r++;
        if (cur_r >= ROWS) {
            cur_r = ROWS - 1;
            scroll_up();
        }
    }
    screen_ch[cur_r][cur_c] = ch;
    screen_fg[cur_r][cur_c] = (unsigned char)((bold ? 8 : 0) | (fg & 7));
    cur_c++;
}

static int parse_csi(const unsigned char *p, int n) {
    int i = 0;
    int args[8] = {0};
    int nargs = 0;
    int priv = 0;
    while (i < n && (isdigit(p[i]) || p[i] == ';' || p[i] == '?' || p[i] == '>')) {
        if (p[i] == '?' || p[i] == '>') {
            priv = 1;
            i++;
            continue;
        }
        if (p[i] == ';') {
            if (nargs < 7) nargs++;
            i++;
            continue;
        }
        args[nargs] = args[nargs] * 10 + (p[i] - '0');
        i++;
    }
    if (i >= n) return 0;
    char cmd = (char)p[i];
    if (isdigit((unsigned char)cmd) || cmd == ';' || cmd == '?' || cmd == '>') return 0;
    if (i > 0 && p[i - 1] != ';' && p[i - 1] != '?' && p[i - 1] != '>' && nargs == 0)
        nargs = 1;
    if (cmd == 'm') {
        if (nargs == 0) {
            fg = 7;
            bold = 0;
        }
        for (int a = 0; a <= nargs; a++) {
            int v = args[a];
            if (v == 0) {
                fg = 7;
                bold = 0;
            } else if (v == 1) bold = 1;
            else if (v == 22) bold = 0;
            else if (v >= 30 && v <= 37) fg = v - 30;
            else if (v >= 90 && v <= 97) {
                fg = v - 90;
                bold = 1;
            } else if (v == 39) fg = 7;
        }
    } else if (cmd == 'H' || cmd == 'f') {
        int r = args[0] ? args[0] - 1 : 0;
        int c = args[1] ? args[1] - 1 : 0;
        if (r < 0) r = 0;
        if (c < 0) c = 0;
        if (r >= ROWS) r = ROWS - 1;
        if (c >= COLS) c = COLS - 1;
        cur_r = r;
        cur_c = c;
    } else if (cmd == 'J') {
        if (args[0] == 2 || args[0] == 3 || nargs == 0) clear_screen();
    } else if (cmd == 'K') {
        for (int c = cur_c; c < COLS; c++) {
            screen_ch[cur_r][c] = ' ';
            screen_fg[cur_r][c] = 7;
        }
    } else if (cmd == 'C') {
        cur_c += args[0] ? args[0] : 1;
        if (cur_c >= COLS) cur_c = COLS - 1;
    } else if (cmd == 'D') {
        cur_c -= args[0] ? args[0] : 1;
        if (cur_c < 0) cur_c = 0;
    } else if (cmd == 'A') {
        cur_r -= args[0] ? args[0] : 1;
        if (cur_r < 0) cur_r = 0;
    } else if (cmd == 'B') {
        cur_r += args[0] ? args[0] : 1;
        if (cur_r >= ROWS) cur_r = ROWS - 1;
    }
    return i + 1;
}

static int parse_osc(const unsigned char *p, int n) {
    int i = 0;
    while (i < n) {
        if (p[i] == 7) {
            return i + 1;
        }
        if (p[i] == 0x1b && i + 1 < n && p[i + 1] == '\\') {
            return i + 2;
        }
        i++;
    }
    return 0;
}

static void feed_bytes(const unsigned char *buf, int n) {
    int i = 0;
    while (i < n) {
        if (buf[i] == 0x1b) {
            if (i + 1 >= n) break;
            if (buf[i + 1] == '[') {
                int used = parse_csi(buf + i + 2, n - i - 2);
                if (used == 0) break;
                i += 2 + used;
                continue;
            }
            if (buf[i + 1] == ']') {
                int used = parse_osc(buf + i + 2, n - i - 2);
                if (used == 0) break;
                i += 2 + used;
                continue;
            }
            i += 2;
            continue;
        }
        putc_at(buf[i]);
        i++;
    }
    if (i < n) {
        int left = n - i;
        if (left > (int)sizeof(pending)) left = sizeof(pending);
        memmove(pending, buf + i, (size_t)left);
        pending_n = left;
    } else {
        pending_n = 0;
    }
}

static void feed(const unsigned char *buf, int n) {
    if (pending_n) {
        int room = (int)sizeof(pending) - pending_n;
        int take = n < room ? n : room;
        memcpy(pending + pending_n, buf, (size_t)take);
        pending_n += take;
        int old = pending_n;
        feed_bytes(pending, pending_n);
        buf += take;
        n -= take;
        if (pending_n == old && n == 0) return;
    }
    if (n > 0) feed_bytes(buf, n);
}

static void fill_bg(void) {
    for (int i = 0; i < W * H; i++) {
        frame[i * 3 + 0] = 11;
        frame[i * 3 + 1] = 18;
        frame[i * 3 + 2] = 32;
    }
}

static void blit_glyph(FT_Bitmap *bmp, int x, int y, const unsigned char *rgb) {
    for (unsigned int row = 0; row < bmp->rows; row++) {
        int py = y + (int)row;
        if (py < 0 || py >= H) continue;
        for (unsigned int col = 0; col < bmp->width; col++) {
            int px = x + (int)col;
            if (px < 0 || px >= W) continue;
            unsigned char a = bmp->buffer[row * bmp->pitch + col];
            if (!a) continue;
            int idx = (py * W + px) * 3;
            frame[idx + 0] = (unsigned char)((a * rgb[0] + (255 - a) * frame[idx + 0]) / 255);
            frame[idx + 1] = (unsigned char)((a * rgb[1] + (255 - a) * frame[idx + 1]) / 255);
            frame[idx + 2] = (unsigned char)((a * rgb[2] + (255 - a) * frame[idx + 2]) / 255);
        }
    }
}

static void render(FT_Face face) {
    fill_bg();
    for (int r = 0; r < ROWS; r++) {
        for (int c = 0; c < COLS; c++) {
            unsigned char ch = screen_ch[r][c];
            if (ch == ' ' || ch == 0) continue;
            if (FT_Load_Char(face, ch, FT_LOAD_RENDER)) continue;
            int x = PAD_X + c * CELL_W + face->glyph->bitmap_left;
            int y = PAD_Y + r * CELL_H + (CELL_H - 6) - face->glyph->bitmap_top;
            blit_glyph(&face->glyph->bitmap, x, y, pal[screen_fg[r][c] & 15]);
        }
    }
    int cx = PAD_X + cur_c * CELL_W;
    int cy = PAD_Y + cur_r * CELL_H + CELL_H - 4;
    const unsigned char *crgb = pal[7];
    for (int x = 0; x < CELL_W - 2; x++) {
        for (int y = 0; y < 2; y++) {
            int px = cx + x, py = cy + y;
            if (px >= 0 && px < W && py >= 0 && py < H) {
                int idx = (py * W + px) * 3;
                frame[idx] = crgb[0];
                frame[idx + 1] = crgb[1];
                frame[idx + 2] = crgb[2];
            }
        }
    }
}

static long now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000L + tv.tv_usec / 1000L;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: pty_record <script>\n");
        return 1;
    }
    FT_Library lib;
    FT_Face face;
    if (FT_Init_FreeType(&lib)) return 2;
    if (FT_New_Face(lib, "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 0, &face)) return 3;
    FT_Set_Pixel_Sizes(face, 0, 18);

    clear_screen();
    fg = 7;
    bold = 0;

    int mfd, sfd;
    struct winsize ws = {.ws_row = ROWS, .ws_col = COLS};
    if (openpty(&mfd, &sfd, NULL, NULL, &ws) != 0) {
        perror("openpty");
        return 4;
    }
    master_fd = mfd;
    pid_t pid = fork();
    if (pid == 0) {
        close(mfd);
        setsid();
        ioctl(sfd, TIOCSCTTY, 0);
        dup2(sfd, 0);
        dup2(sfd, 1);
        dup2(sfd, 2);
        if (sfd > 2) close(sfd);
        setenv("TERM", "xterm-256color", 1);
        execl("/bin/bash", "bash", argv[1], (char *)NULL);
        _exit(127);
    }
    close(sfd);
    fcntl(mfd, F_SETFL, O_NONBLOCK);

    long next = now_ms();
    long deadline = now_ms() + 28000;
    int status = 0;
    int child_done = 0;
    unsigned char buf[4096];
    while ((!child_done || now_ms() < next + 600) && now_ms() < deadline) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(mfd, &rfds);
        struct timeval tv = {.tv_sec = 0, .tv_usec = 20000};
        int sel = select(mfd + 1, &rfds, NULL, NULL, &tv);
        if (sel > 0 && FD_ISSET(mfd, &rfds)) {
            ssize_t n = read(mfd, buf, sizeof buf);
            if (n > 0) {
                maybe_send_password_from_bytes(buf, (int)n);
                feed(buf, (int)n);
            }
            else if (n == 0) child_done = 1;
            else if (errno != EAGAIN && errno != EWOULDBLOCK) child_done = 1;
        }
        if (!child_done && waitpid(pid, &status, WNOHANG) == pid) child_done = 1;
        long t = now_ms();
        if (t >= next) {
            render(face);
            if (fwrite(frame, 1, sizeof frame, stdout) != sizeof frame) break;
            next += 1000 / FPS;
            if (t > next + 200) next = t;
        }
    }
    if (!child_done) {
        kill(pid, SIGTERM);
        waitpid(pid, &status, 0);
    }
    {
        FILE *out = fopen("/tmp/pty_screen.txt", "w");
        if (out) {
            for (int r = 0; r < ROWS; r++) {
                int end = COLS;
                while (end > 0 && screen_ch[r][end - 1] == ' ') end--;
                fwrite(screen_ch[r], 1, (size_t)end, out);
                fputc('\n', out);
            }
            fclose(out);
        }
    }
    close(mfd);
    return 0;
}
