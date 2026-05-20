// sys_zigos.c — ZigOS platform layer for Quake 1.
//
// Replaces sys_linux.c / sys_win.c. Provides Sys_*, VID_*, SNDDMA_*, IN_*
// platform-bridge functions plus the global state Q1's renderer/sound
// expects. Most functions are no-op stubs at this stage — the goal of
// Phase A is to link cleanly; runtime wiring happens in later phases
// where these stubs route to our window framebuffer / hda / event queue.

#include "quakedef.h"

// ============================================================
// VIDEO STATE (referenced by renderer, draw.c, screen.c, ...)
// ============================================================

#define Q_WIDTH  320
#define Q_HEIGHT 200

// `vid`, `vid_menudrawfn`, `vid_menukeyfn` are defined in screen.c / menu.c
// respectively. We only own the palette tables here.
unsigned short d_8to16table[256];
unsigned d_8to24table[256];

// Backing 8bpp buffer (palettized). VID_Update copies+expands to the
// window FB via the Zig wrapper.
static pixel_t vid_buffer[Q_WIDTH * Q_HEIGHT];
static pixel_t vid_colormap[256 * VID_GRADES];

// Zig side will read these to do the present.
unsigned char zq_palette[768];
int zq_dirty = 0;

void VID_Init(unsigned char *palette) {
    vid.width = Q_WIDTH;
    vid.height = Q_HEIGHT;
    vid.rowbytes = Q_WIDTH;
    vid.aspect = ((float)Q_HEIGHT / Q_WIDTH) * (320.0f / 240.0f);
    vid.numpages = 1;
    vid.buffer = vid_buffer;
    vid.colormap = vid_colormap;
    vid.fullbright = 256 - LittleLong(*((int *)vid_colormap + 2048));
    vid.conbuffer = vid_buffer;
    vid.conrowbytes = Q_WIDTH;
    vid.conwidth = Q_WIDTH;
    vid.conheight = Q_HEIGHT;
    vid.direct = 0;
    vid.maxwarpwidth = Q_WIDTH;
    vid.maxwarpheight = Q_HEIGHT;
    VID_SetPalette(palette);
}

void VID_Shutdown(void) {}

// Defined in app/quake1.zig — 8bpp→RGBA blit + 2x scale + present.
extern void zq_present(void);

void VID_Update(vrect_t *rects) {
    (void)rects;
    static int vid_update_count = 0;
    if (vid_update_count < 3) {
        Sys_Printf("ZQ_DBG: VID_Update #%d called\n", vid_update_count);
        vid_update_count++;
    }
    zq_present();
}

void VID_SetPalette(unsigned char *palette) {
    for (int i = 0; i < 768; i++) zq_palette[i] = palette[i];
    for (int i = 0; i < 256; i++) {
        unsigned r = palette[i * 3 + 0];
        unsigned g = palette[i * 3 + 1];
        unsigned b = palette[i * 3 + 2];
        d_8to24table[i] = (0xFFu << 24) | (b << 16) | (g << 8) | r;
    }
    d_8to24table[255] = 0; // transparent
    zq_dirty = 1;
}

void VID_ShiftPalette(unsigned char *palette) { VID_SetPalette(palette); }
int VID_SetMode(int modenum, unsigned char *palette) { (void)modenum; VID_SetPalette(palette); return 1; }
void VID_HandlePause(qboolean pause) { (void)pause; }
// VID_LockBuffer/VID_UnlockBuffer are #define'd as empty macros for
// non-_WIN32 builds in quakedef.h; we don't redefine them here.
void D_BeginDirectRect(int x, int y, byte *pbitmap, int width, int height) {
    (void)x; (void)y; (void)pbitmap; (void)width; (void)height;
}
void D_EndDirectRect(int x, int y, int width, int height) {
    (void)x; (void)y; (void)width; (void)height;
}
void VID_SetDefaultMode(void) {}

// ============================================================
// INPUT (key/mouse delivery into Quake's Key_Event + IN_Move)
// ============================================================

// Input bridge: Zig side scans physical key/mouse state, posts Q1-format
// events into its own ringbuffer, and exposes them through zq_next_key /
// zq_get_mouse. Keeping the loop here (in C) lets us touch Q1's cl.* and
// usercmd_t directly without re-declaring them as Zig extern types.
extern void zq_poll_keys(void);
extern int zq_next_key(int *down_out); // returns Q1 key, 0 if empty
extern void zq_get_mouse_delta(int *dx, int *dy);

extern cvar_t sensitivity;
extern cvar_t m_yaw;
extern cvar_t m_pitch;

void IN_Init(void) {}
void IN_Shutdown(void) {}

void IN_Commands(void) {
    // Per-frame input poll — read physical state, generate press/release
    // events for keys + mouse buttons. Mouse motion is read separately
    // by IN_Move below.
    zq_poll_keys();
}

void Sys_SendKeyEvents(void) {
    int down;
    int key;
    while ((key = zq_next_key(&down)) != 0) {
        Key_Event(key, down);
    }
}

void IN_Move(usercmd_t *cmd) {
    (void)cmd;
    int dx, dy;
    zq_get_mouse_delta(&dx, &dy);
    if (dx == 0 && dy == 0) return;

    // Standard Q1 mouse-look formula. sensitivity / m_yaw / m_pitch are
    // cvars set by Q1's defaults (3.0 / 0.022 / 0.022 respectively at
    // startup). We always operate in mouselook mode; classic Q1 toggled
    // this via in_mlook but always-on matches modern shooter expectations.
    const float fx = (float)dx * sensitivity.value;
    const float fy = (float)dy * sensitivity.value;
    cl.viewangles[YAW]   -= m_yaw.value   * fx;
    cl.viewangles[PITCH] += m_pitch.value * fy;
    if (cl.viewangles[PITCH] >  80.0f) cl.viewangles[PITCH] =  80.0f;
    if (cl.viewangles[PITCH] < -70.0f) cl.viewangles[PITCH] = -70.0f;
}

void IN_ClearStates(void) {}

// ============================================================
// SOUND DMA (snd_dma.c calls into us)
// ============================================================
//
// We don't have a real audio backend wired up yet (task #742). But
// returning false from SNDDMA_Init leaves Q1's `shm` global at NULL,
// and S_Init unconditionally dereferences shm->speed → page fault at
// 0x20. Caught 2026-05-20.
//
// Workaround until task #742 lands: present a software-only DMA
// buffer. Q1's mixer happily writes samples into it; we just never
// read them out, so the game stays silent. The fields below match
// the shape Q1 expects (see dma_t in sound.h).
extern volatile dma_t *shm;

static dma_t fake_dma;
static unsigned char fake_dma_buffer[1 << 16];

qboolean SNDDMA_Init(void) {
    fake_dma.splitbuffer = 0;
    fake_dma.samplebits = 16;
    fake_dma.speed = 22050;
    fake_dma.channels = 2;
    fake_dma.samples = sizeof(fake_dma_buffer) / 2;  // mono samples in buffer
    fake_dma.samplepos = 0;
    fake_dma.soundalive = true;
    fake_dma.gamealive = true;
    fake_dma.submission_chunk = 1;
    fake_dma.buffer = fake_dma_buffer;
    shm = &fake_dma;
    return true;
}
int SNDDMA_GetDMAPos(void) {
    // Q1 advances samplepos via this; without it the mixer doesn't
    // make forward progress and S_Update_ tight-loops. Increment by a
    // chunk per call so the mixer thinks samples are being consumed.
    fake_dma.samplepos = (fake_dma.samplepos + 256) % fake_dma.samples;
    return fake_dma.samplepos;
}
void SNDDMA_Shutdown(void) {}
void SNDDMA_Submit(void) {}

// ============================================================
// SYSTEM (file I/O, time, error, exit)
// ============================================================

// Zig wrapper provides:
//   zq_time_ms() -> u32 (milliseconds since boot)
//   zq_exit(code) -> noreturn
//   zq_print(s)   -> void (write to stdout)
extern unsigned int zq_time_ms(void);
extern void zq_exit(int code) __attribute__((noreturn));
extern void zq_print(const char *s);

// stdio is exposed by libc; we just route through fopen/fread/etc.
// Quake uses int handles, so we map [0..N) to FILE* slots.
#define MAX_QFILES 32
static FILE *qfiles[MAX_QFILES];

static int qfile_alloc(FILE *fp) {
    for (int i = 0; i < MAX_QFILES; i++) {
        if (qfiles[i] == NULL) { qfiles[i] = fp; return i; }
    }
    fclose(fp);
    return -1;
}

int Sys_FileOpenRead(char *path, int *hndl) {
    FILE *fp = fopen(path, "rb");
    if (!fp) { *hndl = -1; return -1; }
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    int h = qfile_alloc(fp);
    if (h < 0) { *hndl = -1; return -1; }
    *hndl = h;
    return (int)sz;
}

int Sys_FileOpenWrite(char *path) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    return qfile_alloc(fp);
}

void Sys_FileClose(int handle) {
    if (handle < 0 || handle >= MAX_QFILES) return;
    if (qfiles[handle]) { fclose(qfiles[handle]); qfiles[handle] = NULL; }
}

void Sys_FileSeek(int handle, int position) {
    if (handle < 0 || handle >= MAX_QFILES || !qfiles[handle]) return;
    fseek(qfiles[handle], position, SEEK_SET);
}

int Sys_FileRead(int handle, void *dest, int count) {
    if (handle < 0 || handle >= MAX_QFILES || !qfiles[handle]) return 0;
    return (int)fread(dest, 1, count, qfiles[handle]);
}

int Sys_FileWrite(int handle, void *data, int count) {
    if (handle < 0 || handle >= MAX_QFILES || !qfiles[handle]) return 0;
    return (int)fwrite(data, 1, count, qfiles[handle]);
}

int Sys_FileTime(char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    fclose(fp);
    return 1;
}

void Sys_mkdir(char *path) { (void)path; }
void Sys_MakeCodeWriteable(unsigned long startaddr, unsigned long length) {
    (void)startaddr; (void)length;
}

void Sys_DebugLog(char *file, char *fmt, ...) { (void)file; (void)fmt; }

void Sys_Error(char *error, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, error);
    vsnprintf(buf, sizeof(buf), error, ap);
    va_end(ap);
    zq_print("Quake Sys_Error: ");
    zq_print(buf);
    zq_print("\n");
    zq_exit(1);
}

void Sys_Printf(char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    zq_print(buf);
}

void Sys_Quit(void) { zq_exit(0); }

double Sys_FloatTime(void) {
    return (double)zq_time_ms() / 1000.0;
}

char *Sys_ConsoleInput(void) { return NULL; }

void Sys_Sleep(void) {}
// Sys_SendKeyEvents moved next to IN_Commands above — needs the same
// zq_next_key/Key_Event glue, so colocated for readability.

// FP-precision controls are x87-only on i386; on x86_64 SSE these are
// no-ops. We use SSE for FP, so leaving these empty is correct.
void Sys_LowFPPrecision(void) {}
void Sys_HighFPPrecision(void) {}
void Sys_SetFPCW(void) {}
void MaskExceptions(void) {}

void Sys_Init(void) {}

// Phase-A setjmp/longjmp stubs. Quake uses these only in Host_Error's
// recovery path; normal startup never longjmps. We make setjmp return
// 0 (caller takes the "no error" branch), and longjmp turns into Quit
// since we can't actually unwind from here.
int setjmp(jmp_buf env) { (void)env; return 0; }
void longjmp(jmp_buf env, int val) { (void)env; (void)val; zq_exit(1); }

// ============================================================
// main() — Quake's entry. _start in app/quake1.zig calls this.
// ============================================================

int quake_main(int argc, char **argv) {
    static quakeparms_t parms;
    static char heap[16 * 1024 * 1024]; // 16 MB hunk

    parms.memsize = sizeof(heap);
    parms.membase = heap;
    // Hardcode basedir — was relying on `-basedir /share/quake` argv but
    // observed path passed to fsize was `quake/id1/pak0.pak` (missing the
    // /share/ prefix), so the arg-parse path is dropping bytes. Bypass it
    // by setting host_parms.basedir directly; this is the value Q1's
    // COM_InitFilesystem falls back to when no -basedir arg is present.
    parms.basedir = "/share/quake";
    parms.cachedir = NULL;

    COM_InitArgv(argc, argv);
    parms.argc = com_argc;
    parms.argv = com_argv;

    Sys_Printf("ZQ_DBG: quake_main argc=%d, argv[0]='%s' argv[1]='%s' argv[2]='%s'\n",
               argc,
               argc >= 1 ? argv[0] : "(none)",
               argc >= 2 ? argv[1] : "(none)",
               argc >= 3 ? argv[2] : "(none)");

    Sys_Init();
    Host_Init(&parms);

    double oldtime = Sys_FloatTime() - 0.1;
    while (1) {
        double newtime = Sys_FloatTime();
        double time = newtime - oldtime;
        Host_Frame(time);
        oldtime = newtime;
    }
    return 0;
}
