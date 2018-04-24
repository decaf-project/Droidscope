#include "monitor/monitor.h"

#include <dirent.h>
#include <stdarg.h>
#include "hw/hw.h"
#include "readline.h"
#include "sysemu/kvm.h"
#include "ui/console.h"
#include "qemu/timer.h"

//Droidscope Stuff

// Moved out so that
// Droidscope plugins can
// access them

#if 0
typedef struct mon_cmd_t {
    const char *name;
    const char *args_type;
    void *handler;
    const char *params;
    const char *help;
} mon_cmd_t;
#endif

/** START DECAF ADDITIONS **/
#include "DECAF_shared/DECAF_main.h"
#include "DECAF_shared/DECAF_main_internal.h"
/** END DECAF ADDITIONS **/


#define MON_CMD_T_INITIALIZER { NULL, NULL, NULL, NULL, NULL }

#define MONITOR_DEF_INITIALIZER  { NULL, 0, NULL, 0 }


static QLIST_HEAD(mon_list, Monitor) mon_list;

#define MD_TLONG 0
#define MD_I32   1

typedef struct MonitorDef {
    const char *name;
    int offset;
    target_long (*get_value)(const struct MonitorDef *md, int val);
    int type;
} MonitorDef;


//Droiscope end

struct Monitor {
    CharDriverState *chr;
    int mux_out;
    int reset_seen;
    int flags;
    int suspend_cnt;
    uint8_t outbuf[1024];
    int outbuf_index;
    ReadLineState *rs;
    CPUState* mon_cpu;
    BlockDriverCompletionFunc *password_completion_cb;
    void *password_opaque;
    QLIST_ENTRY(Monitor) entry;
    int has_quit;
#ifdef CONFIG_ANDROID
    void*            fake_opaque;
    MonitorFakeFunc  fake_func;
    int64_t          fake_count;

#endif
};

// Minimalistic / fake implementation of the QEMU Monitor. (Why? :|)
// DroidScope start

static const mon_cmd_t mon_cmds[] = {
	  MON_CMD_T_INITIALIZER
};

static const mon_cmd_t info_cmds[] = {
	  MON_CMD_T_INITIALIZER
};

// DroidScope end
CPUState *get_cpu_from_mon(Monitor *mon)
{
	return mon->mon_cpu;
}

Monitor *cur_mon = NULL;
/** START DECAF ADDITIONS **/
// default_mon was externed in monitor.h but never really defined
//  so we define it here. See monitor_init() for the assignment
Monitor* default_mon = NULL;
/** END DECAF_ADDITIONS **/


/* Return non-zero iff we have a current monitor, and it is in QMP mode.  */
int monitor_cur_is_qmp(void)
{
    return 0;
}

Monitor*
monitor_fake_new(void* opaque, MonitorFakeFunc cb)
{
    Monitor* mon;

    assert(cb != NULL);
    mon = g_malloc0(sizeof(*mon));
    mon->fake_opaque = opaque;
    mon->fake_func   = cb;
    mon->fake_count  = 0;

    return mon;
}

int
monitor_fake_get_bytes(Monitor* mon)
{
    assert(mon->fake_func != NULL);
    return mon->fake_count;
}

void
monitor_fake_free(Monitor* mon)
{
    assert(mon->fake_func != NULL);
    free(mon);
}

/* This replaces the definition in monitor.c which is in a
 * #ifndef CONFIG_ANDROID .. #endif block.
 */
void monitor_flush(Monitor *mon)
{
    if (!mon)
        return;

    if (mon->fake_func != NULL) {
        mon->fake_func(mon->fake_opaque, (void*)mon->outbuf, mon->outbuf_index);
        mon->outbuf_index = 0;
        mon->fake_count += mon->outbuf_index;
    } else if (!mon->mux_out) {
        qemu_chr_write(mon->chr, mon->outbuf, mon->outbuf_index);
        mon->outbuf_index = 0;
    }
}

/* flush at every end of line or if the buffer is full */
static void monitor_puts(Monitor *mon, const char *str)
{
    char c;

    if (!mon)
        return;

    for(;;) {
        c = *str++;
        if (c == '\0')
            break;
        if (c == '\n')
            mon->outbuf[mon->outbuf_index++] = '\r';
        mon->outbuf[mon->outbuf_index++] = c;
        if (mon->outbuf_index >= (sizeof(mon->outbuf) - 1)
            || c == '\n')
            monitor_flush(mon);
    }
}

void monitor_vprintf(Monitor* mon, const char* fmt, va_list args) {
    char buf[4096];
    vsnprintf(buf, sizeof(buf), fmt, args);
    monitor_puts(mon, buf);
}

void monitor_printf(Monitor *mon, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    monitor_vprintf(mon, fmt, ap);
    va_end(ap);
}

void monitor_print_filename(Monitor *mon, const char *filename)
{
    int i;

    for (i = 0; filename[i]; i++) {
        switch (filename[i]) {
        case ' ':
        case '"':
        case '\\':
            monitor_printf(mon, "\\%c", filename[i]);
            break;
        case '\t':
            monitor_printf(mon, "\\t");
            break;
        case '\r':
            monitor_printf(mon, "\\r");
            break;
        case '\n':
            monitor_printf(mon, "\\n");
            break;
        default:
            monitor_printf(mon, "%c", filename[i]);
            break;
        }
    }
}

void monitor_protocol_event(MonitorEvent event, QObject *data)
{
    /* XXX: TODO */
}

void monitor_set_error(Monitor *mon, QError *qerror)
{
    QDECREF(qerror);
}

/* boot_set handler */
static QEMUBootSetHandler *qemu_boot_set_handler = NULL;
static void *boot_opaque;

void qemu_register_boot_set(QEMUBootSetHandler *func, void *opaque)
{
    qemu_boot_set_handler = func;
    boot_opaque = opaque;
}

//DroidScope Additions to bring back the monitor!

#define MAX_ARGS 16
#define MAX_KEYCODES 16
static uint8_t keycodes[MAX_KEYCODES];
static int nb_pending_keycodes;
static QEMUTimer *key_timer;

static const char *pch;
static jmp_buf expr_env;


typedef struct {
    int keycode;
    const char *name;
} KeyDef;

static const KeyDef key_defs[] = {
    { 0x2a, "shift" },
    { 0x36, "shift_r" },

    { 0x38, "alt" },
    { 0xb8, "alt_r" },
    { 0x64, "altgr" },
    { 0xe4, "altgr_r" },
    { 0x1d, "ctrl" },
    { 0x9d, "ctrl_r" },

    { 0xdd, "menu" },

    { 0x01, "esc" },

    { 0x02, "1" },
    { 0x03, "2" },
    { 0x04, "3" },
    { 0x05, "4" },
    { 0x06, "5" },
    { 0x07, "6" },
    { 0x08, "7" },
    { 0x09, "8" },
    { 0x0a, "9" },
    { 0x0b, "0" },
    { 0x0c, "minus" },
    { 0x0d, "equal" },
    { 0x0e, "backspace" },

    { 0x0f, "tab" },
    { 0x10, "q" },
    { 0x11, "w" },
    { 0x12, "e" },
    { 0x13, "r" },
    { 0x14, "t" },
    { 0x15, "y" },
    { 0x16, "u" },
    { 0x17, "i" },
    { 0x18, "o" },
    { 0x19, "p" },

    { 0x1c, "ret" },

    { 0x1e, "a" },
    { 0x1f, "s" },
    { 0x20, "d" },
    { 0x21, "f" },
    { 0x22, "g" },
    { 0x23, "h" },
    { 0x24, "j" },
    { 0x25, "k" },
    { 0x26, "l" },

    { 0x2c, "z" },
    { 0x2d, "x" },
    { 0x2e, "c" },
    { 0x2f, "v" },
    { 0x30, "b" },
    { 0x31, "n" },
    { 0x32, "m" },
    { 0x33, "comma" },
    { 0x34, "dot" },
    { 0x35, "slash" },

    { 0x37, "asterisk" },

    { 0x39, "spc" },
    { 0x3a, "caps_lock" },
    { 0x3b, "f1" },
    { 0x3c, "f2" },
    { 0x3d, "f3" },
    { 0x3e, "f4" },
    { 0x3f, "f5" },
    { 0x40, "f6" },
    { 0x41, "f7" },
    { 0x42, "f8" },
    { 0x43, "f9" },
    { 0x44, "f10" },
    { 0x45, "num_lock" },
    { 0x46, "scroll_lock" },

    { 0xb5, "kp_divide" },
    { 0x37, "kp_multiply" },
    { 0x4a, "kp_subtract" },
    { 0x4e, "kp_add" },
    { 0x9c, "kp_enter" },
    { 0x53, "kp_decimal" },
    { 0x54, "sysrq" },

    { 0x52, "kp_0" },
    { 0x4f, "kp_1" },
    { 0x50, "kp_2" },
    { 0x51, "kp_3" },
    { 0x4b, "kp_4" },
    { 0x4c, "kp_5" },
    { 0x4d, "kp_6" },
    { 0x47, "kp_7" },
    { 0x48, "kp_8" },
    { 0x49, "kp_9" },

    { 0x56, "<" },

    { 0x57, "f11" },
    { 0x58, "f12" },

    { 0xb7, "print" },

    { 0xc7, "home" },
    { 0xc9, "pgup" },
    { 0xd1, "pgdn" },
    { 0xcf, "end" },

    { 0xcb, "left" },
    { 0xc8, "up" },
    { 0xd0, "down" },
    { 0xcd, "right" },

    { 0xd2, "insert" },
    { 0xd3, "delete" },
    { 0, NULL },
};

static void next(void)
{
    if (pch != '\0') {
        pch++;
        while (qemu_isspace(*pch))
            pch++;
    }
}

/* get the current CPU defined by the user */
static int mon_set_cpu(int cpu_index)
{
    CPUState *env;

    //for(env = first_cpu; env != NULL; env = env->next_cpu) {
	CPU_FOREACH(env) {
		if (env->cpu_index == cpu_index) {
            cur_mon->mon_cpu = env;
            return 0;
        }
    }
    //}
    return -1;
}

static CPUState *mon_get_cpu(void)
{
    if (!cur_mon->mon_cpu) {
        mon_set_cpu(0);
    }
    cpu_synchronize_state(cur_mon->mon_cpu, 0);
    return cur_mon->mon_cpu;
}

void *mon_get_cpu_external(Monitor *mon)
{
	if(!mon)
		mon = cur_mon;

	
	if (!mon->mon_cpu) {
        mon_set_cpu(0);
    }
    cpu_synchronize_state(mon->mon_cpu, 0);
    return (void *)mon->mon_cpu;
}


#if defined(TARGET_I386)
static target_long monitor_get_pc (const struct MonitorDef *md, int val)
{

    //CPUState *env = mon_get_cpu();
	
    //if (!env)
    //   return 0;
	
    return 0; //env->eip + env->segs[R_CS].base;
}
#endif

#if defined(TARGET_PPC)
static target_long monitor_get_ccr (const struct MonitorDef *md, int val)
{
    CPUState *env = mon_get_cpu();
    unsigned int u;
    int i;

    if (!env)
        return 0;

    u = 0;
    for (i = 0; i < 8; i++)
        u |= env->crf[i] << (32 - (4 * i));

    return u;
}

static target_long monitor_get_msr (const struct MonitorDef *md, int val)
{
    CPUState *env = mon_get_cpu();
    if (!env)
        return 0;
    return env->msr;
}

static target_long monitor_get_xer (const struct MonitorDef *md, int val)
{
    CPUState *env = mon_get_cpu();
    if (!env)
        return 0;
    return env->xer;
}

static target_long monitor_get_decr (const struct MonitorDef *md, int val)
{
    CPUState *env = mon_get_cpu();
    if (!env)
        return 0;
    return cpu_ppc_load_decr(env);
}

static target_long monitor_get_tbu (const struct MonitorDef *md, int val)
{
    CPUState *env = mon_get_cpu();
    if (!env)
        return 0;
    return cpu_ppc_load_tbu(env);
}

static target_long monitor_get_tbl (const struct MonitorDef *md, int val)
{
    CPUState *env = mon_get_cpu();
    if (!env)
        return 0;
    return cpu_ppc_load_tbl(env);
}
#endif

#if defined(TARGET_SPARC)
#ifndef TARGET_SPARC64
static target_long monitor_get_psr (const struct MonitorDef *md, int val)
{
    CPUState *env = mon_get_cpu();
    if (!env)
        return 0;
    return GET_PSR(env);
}
#endif

static target_long monitor_get_reg(const struct MonitorDef *md, int val)
{
    CPUState *env = mon_get_cpu();
    if (!env)
        return 0;
    return env->regwptr[val];
}
#endif

static const MonitorDef monitor_defs[] = {
	   MONITOR_DEF_INITIALIZER
};

#if 0
#ifdef TARGET_I386

#define SEG(name, seg) \
    { name, offsetof(CPUState, segs[seg].selector), NULL, MD_I32 },\
    { name ".base", offsetof(CPUState, segs[seg].base) },\
    { name ".limit", offsetof(CPUState, segs[seg].limit), NULL, MD_I32 },

    { "eax", offsetof(CPUState, regs[0]) },
    { "ecx", offsetof(CPUState, regs[1]) },
    { "edx", offsetof(CPUState, regs[2]) },
    { "ebx", offsetof(CPUState, regs[3]) },
    { "esp|sp", offsetof(CPUState, regs[4]) },
    { "ebp|fp", offsetof(CPUState, regs[5]) },
    { "esi", offsetof(CPUState, regs[6]) },
    { "edi", offsetof(CPUState, regs[7]) },
#ifdef TARGET_X86_64
    { "r8", offsetof(CPUState, regs[8]) },
    { "r9", offsetof(CPUState, regs[9]) },
    { "r10", offsetof(CPUState, regs[10]) },
    { "r11", offsetof(CPUState, regs[11]) },
    { "r12", offsetof(CPUState, regs[12]) },
    { "r13", offsetof(CPUState, regs[13]) },
    { "r14", offsetof(CPUState, regs[14]) },
    { "r15", offsetof(CPUState, regs[15]) },
#endif
    { "eflags", offsetof(CPUState, eflags) },
    { "eip", offsetof(CPUState, eip) },
    SEG("cs", R_CS)
    SEG("ds", R_DS)
    SEG("es", R_ES)
    SEG("ss", R_SS)
    SEG("fs", R_FS)
    SEG("gs", R_GS)
    { "pc", 0, monitor_get_pc, },
#elif defined(TARGET_PPC)
    /* General purpose registers */
    { "r0", offsetof(CPUState, gpr[0]) },
    { "r1", offsetof(CPUState, gpr[1]) },
    { "r2", offsetof(CPUState, gpr[2]) },
    { "r3", offsetof(CPUState, gpr[3]) },
    { "r4", offsetof(CPUState, gpr[4]) },
    { "r5", offsetof(CPUState, gpr[5]) },
    { "r6", offsetof(CPUState, gpr[6]) },
    { "r7", offsetof(CPUState, gpr[7]) },
    { "r8", offsetof(CPUState, gpr[8]) },
    { "r9", offsetof(CPUState, gpr[9]) },
    { "r10", offsetof(CPUState, gpr[10]) },
    { "r11", offsetof(CPUState, gpr[11]) },
    { "r12", offsetof(CPUState, gpr[12]) },
    { "r13", offsetof(CPUState, gpr[13]) },
    { "r14", offsetof(CPUState, gpr[14]) },
    { "r15", offsetof(CPUState, gpr[15]) },
    { "r16", offsetof(CPUState, gpr[16]) },
    { "r17", offsetof(CPUState, gpr[17]) },
    { "r18", offsetof(CPUState, gpr[18]) },
    { "r19", offsetof(CPUState, gpr[19]) },
    { "r20", offsetof(CPUState, gpr[20]) },
    { "r21", offsetof(CPUState, gpr[21]) },
    { "r22", offsetof(CPUState, gpr[22]) },
    { "r23", offsetof(CPUState, gpr[23]) },
    { "r24", offsetof(CPUState, gpr[24]) },
    { "r25", offsetof(CPUState, gpr[25]) },
    { "r26", offsetof(CPUState, gpr[26]) },
    { "r27", offsetof(CPUState, gpr[27]) },
    { "r28", offsetof(CPUState, gpr[28]) },
    { "r29", offsetof(CPUState, gpr[29]) },
    { "r30", offsetof(CPUState, gpr[30]) },
    { "r31", offsetof(CPUState, gpr[31]) },
    /* Floating point registers */
    { "f0", offsetof(CPUState, fpr[0]) },
    { "f1", offsetof(CPUState, fpr[1]) },
    { "f2", offsetof(CPUState, fpr[2]) },
    { "f3", offsetof(CPUState, fpr[3]) },
    { "f4", offsetof(CPUState, fpr[4]) },
    { "f5", offsetof(CPUState, fpr[5]) },
    { "f6", offsetof(CPUState, fpr[6]) },
    { "f7", offsetof(CPUState, fpr[7]) },
    { "f8", offsetof(CPUState, fpr[8]) },
    { "f9", offsetof(CPUState, fpr[9]) },
    { "f10", offsetof(CPUState, fpr[10]) },
    { "f11", offsetof(CPUState, fpr[11]) },
    { "f12", offsetof(CPUState, fpr[12]) },
    { "f13", offsetof(CPUState, fpr[13]) },
    { "f14", offsetof(CPUState, fpr[14]) },
    { "f15", offsetof(CPUState, fpr[15]) },
    { "f16", offsetof(CPUState, fpr[16]) },
    { "f17", offsetof(CPUState, fpr[17]) },
    { "f18", offsetof(CPUState, fpr[18]) },
    { "f19", offsetof(CPUState, fpr[19]) },
    { "f20", offsetof(CPUState, fpr[20]) },
    { "f21", offsetof(CPUState, fpr[21]) },
    { "f22", offsetof(CPUState, fpr[22]) },
    { "f23", offsetof(CPUState, fpr[23]) },
    { "f24", offsetof(CPUState, fpr[24]) },
    { "f25", offsetof(CPUState, fpr[25]) },
    { "f26", offsetof(CPUState, fpr[26]) },
    { "f27", offsetof(CPUState, fpr[27]) },
    { "f28", offsetof(CPUState, fpr[28]) },
    { "f29", offsetof(CPUState, fpr[29]) },
    { "f30", offsetof(CPUState, fpr[30]) },
    { "f31", offsetof(CPUState, fpr[31]) },
    { "fpscr", offsetof(CPUState, fpscr) },
    /* Next instruction pointer */
    { "nip|pc", offsetof(CPUState, nip) },
    { "lr", offsetof(CPUState, lr) },
    { "ctr", offsetof(CPUState, ctr) },
    { "decr", 0, &monitor_get_decr, },
    { "ccr", 0, &monitor_get_ccr, },
    /* Machine state register */
    { "msr", 0, &monitor_get_msr, },
    { "xer", 0, &monitor_get_xer, },
    { "tbu", 0, &monitor_get_tbu, },
    { "tbl", 0, &monitor_get_tbl, },
#if defined(TARGET_PPC64)
    /* Address space register */
    { "asr", offsetof(CPUState, asr) },
#endif
    /* Segment registers */
    { "sdr1", offsetof(CPUState, sdr1) },
    { "sr0", offsetof(CPUState, sr[0]) },
    { "sr1", offsetof(CPUState, sr[1]) },
    { "sr2", offsetof(CPUState, sr[2]) },
    { "sr3", offsetof(CPUState, sr[3]) },
    { "sr4", offsetof(CPUState, sr[4]) },
    { "sr5", offsetof(CPUState, sr[5]) },
    { "sr6", offsetof(CPUState, sr[6]) },
    { "sr7", offsetof(CPUState, sr[7]) },
    { "sr8", offsetof(CPUState, sr[8]) },
    { "sr9", offsetof(CPUState, sr[9]) },
    { "sr10", offsetof(CPUState, sr[10]) },
    { "sr11", offsetof(CPUState, sr[11]) },
    { "sr12", offsetof(CPUState, sr[12]) },
    { "sr13", offsetof(CPUState, sr[13]) },
    { "sr14", offsetof(CPUState, sr[14]) },
    { "sr15", offsetof(CPUState, sr[15]) },
    /* Too lazy to put BATs and SPRs ... */
#elif defined(TARGET_SPARC)
    { "g0", offsetof(CPUState, gregs[0]) },
    { "g1", offsetof(CPUState, gregs[1]) },
    { "g2", offsetof(CPUState, gregs[2]) },
    { "g3", offsetof(CPUState, gregs[3]) },
    { "g4", offsetof(CPUState, gregs[4]) },
    { "g5", offsetof(CPUState, gregs[5]) },
    { "g6", offsetof(CPUState, gregs[6]) },
    { "g7", offsetof(CPUState, gregs[7]) },
    { "o0", 0, monitor_get_reg },
    { "o1", 1, monitor_get_reg },
    { "o2", 2, monitor_get_reg },
    { "o3", 3, monitor_get_reg },
    { "o4", 4, monitor_get_reg },
    { "o5", 5, monitor_get_reg },
    { "o6", 6, monitor_get_reg },
    { "o7", 7, monitor_get_reg },
    { "l0", 8, monitor_get_reg },
    { "l1", 9, monitor_get_reg },
    { "l2", 10, monitor_get_reg },
    { "l3", 11, monitor_get_reg },
    { "l4", 12, monitor_get_reg },
    { "l5", 13, monitor_get_reg },
    { "l6", 14, monitor_get_reg },
    { "l7", 15, monitor_get_reg },
    { "i0", 16, monitor_get_reg },
    { "i1", 17, monitor_get_reg },
    { "i2", 18, monitor_get_reg },
    { "i3", 19, monitor_get_reg },
    { "i4", 20, monitor_get_reg },
    { "i5", 21, monitor_get_reg },
    { "i6", 22, monitor_get_reg },
    { "i7", 23, monitor_get_reg },
    { "pc", offsetof(CPUState, pc) },
    { "npc", offsetof(CPUState, npc) },
    { "y", offsetof(CPUState, y) },
#ifndef TARGET_SPARC64
    { "psr", 0, &monitor_get_psr, },
    { "wim", offsetof(CPUState, wim) },
#endif
    { "tbr", offsetof(CPUState, tbr) },
    { "fsr", offsetof(CPUState, fsr) },
    { "f0", offsetof(CPUState, fpr[0]) },
    { "f1", offsetof(CPUState, fpr[1]) },
    { "f2", offsetof(CPUState, fpr[2]) },
    { "f3", offsetof(CPUState, fpr[3]) },
    { "f4", offsetof(CPUState, fpr[4]) },
    { "f5", offsetof(CPUState, fpr[5]) },
    { "f6", offsetof(CPUState, fpr[6]) },
    { "f7", offsetof(CPUState, fpr[7]) },
    { "f8", offsetof(CPUState, fpr[8]) },
    { "f9", offsetof(CPUState, fpr[9]) },
    { "f10", offsetof(CPUState, fpr[10]) },
    { "f11", offsetof(CPUState, fpr[11]) },
    { "f12", offsetof(CPUState, fpr[12]) },
    { "f13", offsetof(CPUState, fpr[13]) },
    { "f14", offsetof(CPUState, fpr[14]) },
    { "f15", offsetof(CPUState, fpr[15]) },
    { "f16", offsetof(CPUState, fpr[16]) },
    { "f17", offsetof(CPUState, fpr[17]) },
    { "f18", offsetof(CPUState, fpr[18]) },
    { "f19", offsetof(CPUState, fpr[19]) },
    { "f20", offsetof(CPUState, fpr[20]) },
    { "f21", offsetof(CPUState, fpr[21]) },
    { "f22", offsetof(CPUState, fpr[22]) },
    { "f23", offsetof(CPUState, fpr[23]) },
    { "f24", offsetof(CPUState, fpr[24]) },
    { "f25", offsetof(CPUState, fpr[25]) },
    { "f26", offsetof(CPUState, fpr[26]) },
    { "f27", offsetof(CPUState, fpr[27]) },
    { "f28", offsetof(CPUState, fpr[28]) },
    { "f29", offsetof(CPUState, fpr[29]) },
    { "f30", offsetof(CPUState, fpr[30]) },
    { "f31", offsetof(CPUState, fpr[31]) },
#ifdef TARGET_SPARC64
    { "f32", offsetof(CPUState, fpr[32]) },
    { "f34", offsetof(CPUState, fpr[34]) },
    { "f36", offsetof(CPUState, fpr[36]) },
    { "f38", offsetof(CPUState, fpr[38]) },
    { "f40", offsetof(CPUState, fpr[40]) },
    { "f42", offsetof(CPUState, fpr[42]) },
    { "f44", offsetof(CPUState, fpr[44]) },
    { "f46", offsetof(CPUState, fpr[46]) },
    { "f48", offsetof(CPUState, fpr[48]) },
    { "f50", offsetof(CPUState, fpr[50]) },
    { "f52", offsetof(CPUState, fpr[52]) },
    { "f54", offsetof(CPUState, fpr[54]) },
    { "f56", offsetof(CPUState, fpr[56]) },
    { "f58", offsetof(CPUState, fpr[58]) },
    { "f60", offsetof(CPUState, fpr[60]) },
    { "f62", offsetof(CPUState, fpr[62]) },
    { "asi", offsetof(CPUState, asi) },
    { "pstate", offsetof(CPUState, pstate) },
    { "cansave", offsetof(CPUState, cansave) },
    { "canrestore", offsetof(CPUState, canrestore) },
    { "otherwin", offsetof(CPUState, otherwin) },
    { "wstate", offsetof(CPUState, wstate) },
    { "cleanwin", offsetof(CPUState, cleanwin) },
    { "fprs", offsetof(CPUState, fprs) },
#endif
#endif
    MONITOR_DEF_INITIALIZER
};
#endif

static int compare_cmd(const char *name, const char *list)
{
    const char *p, *pstart;
    int len;
    len = strlen(name);
    p = list;
    for(;;) {
        pstart = p;
        p = strchr(p, '|');
        if (!p)
            p = pstart + strlen(pstart);
        if ((p - pstart) == len && !memcmp(pstart, name, len))
            return 1;
        if (*p == '\0')
            break;
        p++;
    }
    return 0;
}


static void expr_error(Monitor *mon, const char *msg)
{
    monitor_printf(mon, "%s\n", msg);
    longjmp(expr_env, 1);
}



/* return 0 if OK, -1 if not found, -2 if no CPU defined */
static int get_monitor_def(target_long *pval, const char *name)
{
    const MonitorDef *md;
    void *ptr;

    for(md = monitor_defs; md->name != NULL; md++) {
        if (compare_cmd(name, md->name)) {
            if (md->get_value) {
                *pval = md->get_value(md, md->offset);
            } else {
                CPUState *env = mon_get_cpu();
                if (!env)
                    return -2;
                ptr = (uint8_t *)env + md->offset;
                switch(md->type) {
                case MD_I32:
                    *pval = *(int32_t *)ptr;
                    break;
                case MD_TLONG:
                    *pval = *(target_long *)ptr;
                    break;
                default:
                    *pval = 0;
                    break;
                }
            }
            return 0;
        }
    }
    return -1;
}


static int64_t expr_sum(Monitor *mon);

static int64_t expr_unary(Monitor *mon)
{
    int64_t n;
    char *p;
    int ret;

    switch(*pch) {
    case '+':
        next();
        n = expr_unary(mon);
        break;
    case '-':
        next();
        n = -expr_unary(mon);
        break;
    case '~':
        next();
        n = ~expr_unary(mon);
        break;
    case '(':
        next();
        n = expr_sum(mon);
        if (*pch != ')') {
            expr_error(mon, "')' expected");
        }
        next();
        break;
    case '\'':
        pch++;
        if (*pch == '\0')
            expr_error(mon, "character constant expected");
        n = *pch;
        pch++;
        if (*pch != '\'')
            expr_error(mon, "missing terminating \' character");
        next();
        break;
    case '$':
        {
            char buf[128], *q;
            target_long reg=0;

            pch++;
            q = buf;
            while ((*pch >= 'a' && *pch <= 'z') ||
                   (*pch >= 'A' && *pch <= 'Z') ||
                   (*pch >= '0' && *pch <= '9') ||
                   *pch == '_' || *pch == '.') {
                if ((q - buf) < sizeof(buf) - 1)
                    *q++ = *pch;
                pch++;
            }
            while (qemu_isspace(*pch))
                pch++;
            *q = 0;
            ret = get_monitor_def(&reg, buf);
            if (ret == -1)
                expr_error(mon, "unknown register");
            else if (ret == -2)
                expr_error(mon, "no cpu defined");
            n = reg;
        }
        break;
    case '\0':
        expr_error(mon, "unexpected end of expression");
        n = 0;
        break;
    default:
#if 0 // TARGET_PHYS_ADDR_BITS > 32
        n = strtoull(pch, &p, 0);
#else
        n = strtoul(pch, &p, 0);
#endif
        if (pch == p) {
            expr_error(mon, "invalid char in expression");
        }
        pch = p;
        while (qemu_isspace(*pch))
            pch++;
        break;
    }
    return n;
}


static int64_t expr_prod(Monitor *mon)
{
    int64_t val, val2;
    int op;

    val = expr_unary(mon);
    for(;;) {
        op = *pch;
        if (op != '*' && op != '/' && op != '%')
            break;
        next();
        val2 = expr_unary(mon);
        switch(op) {
        default:
        case '*':
            val *= val2;
            break;
        case '/':
        case '%':
            if (val2 == 0)
                expr_error(mon, "division by zero");
            if (op == '/')
                val /= val2;
            else
                val %= val2;
            break;
        }
    }
    return val;
}


static int64_t expr_logic(Monitor *mon)
{
    int64_t val, val2;
    int op;

    val = expr_prod(mon);
    for(;;) {
        op = *pch;
        if (op != '&' && op != '|' && op != '^')
            break;
        next();
        val2 = expr_prod(mon);
        switch(op) {
        default:
        case '&':
            val &= val2;
            break;
        case '|':
            val |= val2;
            break;
        case '^':
            val ^= val2;
            break;
        }
    }
    return val;
}


static int64_t expr_sum(Monitor *mon)
{
    int64_t val, val2;
    int op;

    val = expr_logic(mon);
    for(;;) {
        op = *pch;
        if (op != '+' && op != '-')
            break;
        next();
        val2 = expr_logic(mon);
        if (op == '+')
            val += val2;
        else
            val -= val2;
    }
    return val;
}


static int get_expr(Monitor *mon, int64_t *pval, const char **pp)
{
    pch = *pp;
    if (setjmp(expr_env)) {
        *pp = pch;
        return -1;
    }
    while (qemu_isspace(*pch))
        pch++;
    *pval = expr_sum(mon);
    *pp = pch;
    return 0;
}


static int get_str(char *buf, int buf_size, const char **pp)
{
    const char *p;
    char *q;
    int c;

    q = buf;
    p = *pp;
    while (qemu_isspace(*p))
        p++;
    if (*p == '\0') {
    fail:
        *q = '\0';
        *pp = p;
        return -1;
    }
    if (*p == '\"') {
        p++;
        while (*p != '\0' && *p != '\"') {
            if (*p == '\\') {
                p++;
                c = *p++;
                switch(c) {
                case 'n':
                    c = '\n';
                    break;
                case 'r':
                    c = '\r';
                    break;
                case '\\':
                case '\'':
                case '\"':
                    break;
                default:
                    qemu_printf("unsupported escape code: '\\%c'\n", c);
                    goto fail;
                }
                if ((q - buf) < buf_size - 1) {
                    *q++ = c;
                }
            } else {
                if ((q - buf) < buf_size - 1) {
                    *q++ = *p;
                }
                p++;
            }
        }
        if (*p != '\"') {
            qemu_printf("unterminated string\n");
            goto fail;
        }
        p++;
    } else {
        while (*p != '\0' && !qemu_isspace(*p)) {
            if ((q - buf) < buf_size - 1) {
                *q++ = *p;
            }
            p++;
        }
    }
    *q = '\0';
    *pp = p;
    return 0;
}

/*
 * Store the command-name in cmdname, and return a pointer to
 * the remaining of the command string.
 */
static const char *get_command_name(const char *cmdline,
                                    char *cmdname, size_t nlen)
{
    size_t len;
    const char *p, *pstart;

    p = cmdline;
    while (qemu_isspace(*p))
        p++;
    if (*p == '\0')
        return NULL;
    pstart = p;
    while (*p != '\0' && *p != '/' && !qemu_isspace(*p))
        p++;
    len = p - pstart;
    if (len > nlen - 1)
        len = nlen - 1;
    memcpy(cmdname, pstart, len);
    cmdname[len] = '\0';
    return p;
}

static int default_fmt_format = 'x';
static int default_fmt_size = 4;


static void file_completion(const char *input)
{
    DIR *ffs;
    struct dirent *d;
    char path[1024];
    char file[1024], file_prefix[1024];
    int input_path_len;
    const char *p;

    p = strrchr(input, '/');
    if (!p) {
        input_path_len = 0;
        pstrcpy(file_prefix, sizeof(file_prefix), input);
        pstrcpy(path, sizeof(path), ".");
    } else {
        input_path_len = p - input + 1;
        memcpy(path, input, input_path_len);
        if (input_path_len > sizeof(path) - 1)
            input_path_len = sizeof(path) - 1;
        path[input_path_len] = '\0';
        pstrcpy(file_prefix, sizeof(file_prefix), p + 1);
    }
#if 0//def DEBUG_COMPLETION
    monitor_printf(cur_mon, "input='%s' path='%s' prefix='%s'\n",
                   input, path, file_prefix);
#endif
    ffs = opendir(path);
    if (!ffs)
        return;
    for(;;) {
        struct stat sb;
        d = readdir(ffs);
        if (!d)
            break;
        if (strstart(d->d_name, file_prefix, NULL)) {
            memcpy(file, input, input_path_len);
            if (input_path_len < sizeof(file))
                pstrcpy(file + input_path_len, sizeof(file) - input_path_len,
                        d->d_name);
            /* stat the file to find out if it's a directory.
             * In that case add a slash to speed up typing long paths
             */
            stat(file, &sb);
            if(S_ISDIR(sb.st_mode))
                pstrcat(file, sizeof(file), "/");
            readline_add_completion(cur_mon->rs, file);
        }
    }
    closedir(ffs);
}

static void monitor_handle_command(Monitor *mon, const char *cmdline)
{
    const char *p, *typestr;
    int c, nb_args, i, has_arg;
    const mon_cmd_t *cmd;
    char cmdname[256];
    char buf[1024];
    void *str_allocated[MAX_ARGS];
    void *args[MAX_ARGS];
    void (*handler_0)(Monitor *mon);
    void (*handler_1)(Monitor *mon, void *arg0);
    void (*handler_2)(Monitor *mon, void *arg0, void *arg1);
    void (*handler_3)(Monitor *mon, void *arg0, void *arg1, void *arg2);
    void (*handler_4)(Monitor *mon, void *arg0, void *arg1, void *arg2,
                      void *arg3);
    void (*handler_5)(Monitor *mon, void *arg0, void *arg1, void *arg2,
                      void *arg3, void *arg4);
    void (*handler_6)(Monitor *mon, void *arg0, void *arg1, void *arg2,
                      void *arg3, void *arg4, void *arg5);
    void (*handler_7)(Monitor *mon, void *arg0, void *arg1, void *arg2,
                      void *arg3, void *arg4, void *arg5, void *arg6);
    void (*handler_8)(Monitor *mon, void *arg0, void *arg1, void *arg2,
                      void *arg3, void *arg4, void *arg5, void *arg6,
                      void *arg7);
    void (*handler_9)(Monitor *mon, void *arg0, void *arg1, void *arg2,
                      void *arg3, void *arg4, void *arg5, void *arg6,
                      void *arg7, void *arg8);
    void (*handler_10)(Monitor *mon, void *arg0, void *arg1, void *arg2,
                       void *arg3, void *arg4, void *arg5, void *arg6,
                       void *arg7, void *arg8, void *arg9);
#ifdef DEBUG
    monitor_printf(mon, "command='%s'\n", cmdline);
#endif

    /* extract the command name */
    p = get_command_name(cmdline, cmdname, sizeof(cmdname));
    if (!p)
        return;

    /* find the command */
    for(cmd = mon_cmds; cmd->name != NULL; cmd++) {
        if (compare_cmd(cmdname, cmd->name))
            break;
    }

	
    /** START DECAF ADDITIONS **/
    // In newer versions of QEMU this for loop is replaced by
    //  a  new function called monitor_find_command.
    //  Furthermore, the whole function structure is different.
    //  In this version of QEMU we have monitor_handle_command()
    //  whereas in newer versions, this function is replaced by
    //  handle_user_command(), which then replaces this whole 
    //  front section with a call to monitor_parse_command().
    //  It is inside monitor_parse_command that the get_command_name
    //  call above is found, and then the call to monitor_find_command()
    //  (the above for loop) is found.
    // At any rate, we need to search our new command arrays here as well
    if (cmd->name == NULL) // if the command has not been found
    {
      if (DECAF_mon_cmds != NULL)
      {
        for (cmd = DECAF_mon_cmds; cmd->name != NULL; cmd++)
        {
          if (compare_cmd(cmdname, cmd->name))
          {
            break;
          }
        }
      }
    }
    //follow with the info commands
    if (cmd->name == NULL) // if the command has not been found
    {
      if (DECAF_info_cmds != NULL)
      {
        for (cmd = DECAF_info_cmds; cmd->name != NULL; cmd++)
        {
          if (compare_cmd(cmdname, cmd->name))
          {
            break;
          }
        }
      }
    }
    // and then plugin commands
    if (cmd->name == NULL) // if the command has not been found
    {
      if (decaf_plugin != NULL)
      {
        if (decaf_plugin->mon_cmds != NULL)
        {
          for (cmd = decaf_plugin->mon_cmds; cmd->name != NULL; cmd++)
          {
            if (compare_cmd(cmdname, cmd->name))
            {
              break;
            }
          }
        }
        if ((cmd->name == NULL) && (decaf_plugin->info_cmds != NULL))
        {
          for (cmd = decaf_plugin->info_cmds; cmd->name != NULL; cmd++)
          {
            if (compare_cmd(cmdname, cmd->name))
            {
              break;
            }
          }
        }
      }
    }
    /** END DECAF ADDITIONS **/

    if (cmd->name == NULL) {
        monitor_printf(mon, "unknown command: '%s'\n", cmdname);
        return;
    }

    for(i = 0; i < MAX_ARGS; i++)
        str_allocated[i] = NULL;

    /* parse the parameters */
    typestr = cmd->args_type;
    nb_args = 0;
    for(;;) {
        c = *typestr;
        if (c == '\0')
            break;
        typestr++;
        switch(c) {
        case 'F':
        case 'B':
        case 's':
            {
                int ret;
                char *str;

                while (qemu_isspace(*p))
                    p++;
                if (*typestr == '?') {
                    typestr++;
                    if (*p == '\0') {
                        /* no optional string: NULL argument */
                        str = NULL;
                        goto add_str;
                    }
                }
                ret = get_str(buf, sizeof(buf), &p);
                if (ret < 0) {
                    switch(c) {
                    case 'F':
                        monitor_printf(mon, "%s: filename expected\n",
                                       cmdname);
                        break;
                    case 'B':
                        monitor_printf(mon, "%s: block device name expected\n",
                                       cmdname);
                        break;
                    default:
                        monitor_printf(mon, "%s: string expected\n", cmdname);
                        break;
                    }
                    goto fail;
                }
                str = g_malloc(strlen(buf) + 1);
                pstrcpy(str, sizeof(buf), buf);
                str_allocated[nb_args] = str;
            add_str:
                if (nb_args >= MAX_ARGS) {
                error_args:
                    monitor_printf(mon, "%s: too many arguments\n", cmdname);
                    goto fail;
                }
                args[nb_args++] = str;
            }
            break;
        case '/':
            {
                int count, format, size;

                while (qemu_isspace(*p))
                    p++;
                if (*p == '/') {
                    /* format found */
                    p++;
                    count = 1;
                    if (qemu_isdigit(*p)) {
                        count = 0;
                        while (qemu_isdigit(*p)) {
                            count = count * 10 + (*p - '0');
                            p++;
                        }
                    }
                    size = -1;
                    format = -1;
                    for(;;) {
                        switch(*p) {
                        case 'o':
                        case 'd':
                        case 'u':
                        case 'x':
                        case 'i':
                        case 'c':
                            format = *p++;
                            break;
                        case 'b':
                            size = 1;
                            p++;
                            break;
                        case 'h':
                            size = 2;
                            p++;
                            break;
                        case 'w':
                            size = 4;
                            p++;
                            break;
                        case 'g':
                        case 'L':
                            size = 8;
                            p++;
                            break;
                        default:
                            goto next;
                        }
                    }
                next:
                    if (*p != '\0' && !qemu_isspace(*p)) {
                        monitor_printf(mon, "invalid char in format: '%c'\n",
                                       *p);
                        goto fail;
                    }
                    if (format < 0)
                        format = default_fmt_format;
                    if (format != 'i') {
                        /* for 'i', not specifying a size gives -1 as size */
                        if (size < 0)
                            size = default_fmt_size;
                        default_fmt_size = size;
                    }
                    default_fmt_format = format;
                } else {
                    count = 1;
                    format = default_fmt_format;
                    if (format != 'i') {
                        size = default_fmt_size;
                    } else {
                        size = -1;
                    }
                }
                if (nb_args + 3 > MAX_ARGS)
                    goto error_args;
                args[nb_args++] = (void*)(long)count;
                args[nb_args++] = (void*)(long)format;
                args[nb_args++] = (void*)(long)size;
            }
            break;
        case 'i':
        case 'l':
            {
                int64_t val;

                while (qemu_isspace(*p))
                    p++;
                if (*typestr == '?' || *typestr == '.') {
                    if (*typestr == '?') {
                        if (*p == '\0')
                            has_arg = 0;
                        else
                            has_arg = 1;
                    } else {
                        if (*p == '.') {
                            p++;
                            while (qemu_isspace(*p))
                                p++;
                            has_arg = 1;
                        } else {
                            has_arg = 0;
                        }
                    }
                    typestr++;
                    if (nb_args >= MAX_ARGS)
                        goto error_args;
                    args[nb_args++] = (void *)(long)has_arg;
                    if (!has_arg) {
                        if (nb_args >= MAX_ARGS)
                            goto error_args;
                        val = -1;
                        goto add_num;
                    }
                }
                if (get_expr(mon, &val, &p))
                    goto fail;
            add_num:
                if (c == 'i') {
                    if (nb_args >= MAX_ARGS)
                        goto error_args;
                    args[nb_args++] = (void *)(long)val;
                } else {
                    if ((nb_args + 1) >= MAX_ARGS)
                        goto error_args;
#if 0 //TARGET_PHYS_ADDR_BITS > 32
                    args[nb_args++] = (void *)(long)((val >> 32) & 0xffffffff);
#else
                    args[nb_args++] = (void *)0;
#endif
                    args[nb_args++] = (void *)(long)(val & 0xffffffff);
                }
            }
            break;
        case '-':
            {
                int has_option;
                /* option */

                c = *typestr++;
                if (c == '\0')
                    goto bad_type;
                while (qemu_isspace(*p))
                    p++;
                has_option = 0;
                if (*p == '-') {
                    p++;
                    if (*p != c) {
                        monitor_printf(mon, "%s: unsupported option -%c\n",
                                       cmdname, *p);
                        goto fail;
                    }
                    p++;
                    has_option = 1;
                }
                if (nb_args >= MAX_ARGS)
                    goto error_args;
                args[nb_args++] = (void *)(long)has_option;
            }
            break;
        default:
        bad_type:
            monitor_printf(mon, "%s: unknown type '%c'\n", cmdname, c);
            goto fail;
        }
    }
    /* check that all arguments were parsed */
    while (qemu_isspace(*p))
        p++;
    if (*p != '\0') {
        monitor_printf(mon, "%s: extraneous characters at the end of line\n",
                       cmdname);
        goto fail;
    }

    switch(nb_args) {
    case 0:
        handler_0 = cmd->handler;
        handler_0(mon);
        break;
    case 1:
        handler_1 = cmd->handler;
        handler_1(mon, args[0]);
        break;
    case 2:
        handler_2 = cmd->handler;
        handler_2(mon, args[0], args[1]);
        break;
    case 3:
        handler_3 = cmd->handler;
        handler_3(mon, args[0], args[1], args[2]);
        break;
    case 4:
        handler_4 = cmd->handler;
        handler_4(mon, args[0], args[1], args[2], args[3]);
        break;
    case 5:
        handler_5 = cmd->handler;
        handler_5(mon, args[0], args[1], args[2], args[3], args[4]);
        break;
    case 6:
        handler_6 = cmd->handler;
        handler_6(mon, args[0], args[1], args[2], args[3], args[4], args[5]);
        break;
    case 7:
        handler_7 = cmd->handler;
        handler_7(mon, args[0], args[1], args[2], args[3], args[4], args[5],
                  args[6]);
        break;
    case 8:
        handler_8 = cmd->handler;
        handler_8(mon, args[0], args[1], args[2], args[3], args[4], args[5],
                  args[6], args[7]);
        break;
    case 9:
        handler_9 = cmd->handler;
        handler_9(mon, args[0], args[1], args[2], args[3], args[4], args[5],
                  args[6], args[7], args[8]);
        break;
    case 10:
        handler_10 = cmd->handler;
        handler_10(mon, args[0], args[1], args[2], args[3], args[4], args[5],
                   args[6], args[7], args[8], args[9]);
        break;
    default:
        monitor_printf(mon, "unsupported number of arguments: %d\n", nb_args);
        goto fail;
    }
 fail:
    for(i = 0; i < MAX_ARGS; i++)
        g_free(str_allocated[i]);
}


static void cmd_completion(const char *name, const char *list)
{
    const char *p, *pstart;
    char cmd[128];
    int len;

    p = list;
    for(;;) {
        pstart = p;
        p = strchr(p, '|');
        if (!p)
            p = pstart + strlen(pstart);
        len = p - pstart;
        if (len > sizeof(cmd) - 2)
            len = sizeof(cmd) - 2;
        memcpy(cmd, pstart, len);
        cmd[len] = '\0';
        if (name[0] == '\0' || !strncmp(name, cmd, strlen(name))) {
            readline_add_completion(cur_mon->rs, cmd);
        }
        if (*p == '\0')
            break;
        p++;
    }
}

static void release_keys(void *opaque)
{
    int keycode;

    while (nb_pending_keycodes > 0) {
        nb_pending_keycodes--;
        keycode = keycodes[nb_pending_keycodes];
        if (keycode & 0x80)
            kbd_put_keycode(0xe0);
        kbd_put_keycode(keycode | 0x80);
    }
}

static void monitor_command_cb(Monitor *mon, const char *cmdline, void *opaque)
{
    monitor_suspend(mon);
    monitor_handle_command(mon, cmdline);
    monitor_resume(mon);
}

int monitor_suspend(Monitor *mon)
{
    if (!mon->rs)
        return -ENOTTY;
    mon->suspend_cnt++;
    return 0;
}

void monitor_resume(Monitor *mon)
{
    if (!mon->rs)
        return;
    if (--mon->suspend_cnt == 0)
        readline_show_prompt(mon->rs);
}


static void monitor_read_command(Monitor *mon, int show_prompt)
{
    readline_start(mon->rs, "(qemu) ", 0, monitor_command_cb, NULL);
    if (show_prompt)
        readline_show_prompt(mon->rs);
}

static int monitor_can_read(void *opaque)
{
    Monitor *mon = opaque;

    return (mon->suspend_cnt == 0) ? 128 : 0;
}

static void monitor_done(Monitor *mon); // forward


static void monitor_read(void *opaque, const uint8_t *buf, int size)
{
    Monitor *old_mon = cur_mon;
    int i;

    cur_mon = opaque;

    if (cur_mon->rs) {
        for (i = 0; i < size; i++)
            readline_handle_byte(cur_mon->rs, buf[i]);
    } else {
        if (size == 0 || buf[size - 1] != 0)
            monitor_printf(cur_mon, "corrupted command\n");
        else
            monitor_handle_command(cur_mon, (char *)buf);
    }

    if (cur_mon->has_quit) {
        monitor_done(cur_mon);
    }
    cur_mon = old_mon;
}

static void monitor_event(void *opaque, int event)
{
    Monitor *mon = opaque;

    switch (event) {
    case CHR_EVENT_MUX_IN:
        mon->mux_out = 0;
        if (mon->reset_seen) {
            readline_restart(mon->rs);
            monitor_resume(mon);
            monitor_flush(mon);
        } else {
            mon->suspend_cnt = 0;
        }
        break;

    case CHR_EVENT_MUX_OUT:
        if (mon->reset_seen) {
            if (mon->suspend_cnt == 0) {
                monitor_printf(mon, "\n");
            }
            monitor_flush(mon);
            monitor_suspend(mon);
        } else {
            mon->suspend_cnt++;
        }
        mon->mux_out = 1;
        break;

    case CHR_EVENT_OPENED:
        monitor_printf(mon, "QEMU %s monitor - type 'help' for more "
                       "information\n", QEMU_VERSION);
        if (!mon->mux_out) {
            readline_show_prompt(mon->rs);
        }
        mon->reset_seen = 1;
        break;
    }
}

/* NOTE: this parser is an approximate form of the real command parser */
static void parse_cmdline(const char *cmdline,
                         int *pnb_args, char **args)
{
    const char *p;
    int nb_args, ret;
    char buf[1024];

    p = cmdline;
    nb_args = 0;
    for(;;) {
        while (qemu_isspace(*p))
            p++;
        if (*p == '\0')
            break;
        if (nb_args >= MAX_ARGS)
            break;
        ret = get_str(buf, sizeof(buf), &p);
        args[nb_args] = g_strdup(buf);
        nb_args++;
        if (ret < 0)
            break;
    }
    *pnb_args = nb_args;
}

static void block_completion_it(void *opaque, BlockDriverState *bs)
{
    const char *name = bdrv_get_device_name(bs);
    const char *input = opaque;

    if (input[0] == '\0' ||
        !strncmp(name, (char *)input, strlen(input))) {
        readline_add_completion(cur_mon->rs, name);
    }
}

static void monitor_find_completion(const char *cmdline)
{
    const char *cmdname;
    char *args[MAX_ARGS];
    int nb_args, i, len;
    const char *ptype, *str;
    const mon_cmd_t *cmd;
    const KeyDef *key;

    parse_cmdline(cmdline, &nb_args, args);
#if 0 //def DEBUG_COMPLETION
    for(i = 0; i < nb_args; i++) {
        monitor_printf(cur_mon, "arg%d = '%s'\n", i, (char *)args[i]);
    }
#endif

    /* if the line ends with a space, it means we want to complete the
       next arg */
    len = strlen(cmdline);
    if (len > 0 && qemu_isspace(cmdline[len - 1])) {
        if (nb_args >= MAX_ARGS)
            return;
        args[nb_args++] = g_strdup("");
    }
    if (nb_args <= 1) {
        /* command completion */
        if (nb_args == 0)
            cmdname = "";
        else
            cmdname = args[0];
        readline_set_completion_index(cur_mon->rs, strlen(cmdname));
        for(cmd = mon_cmds; cmd->name != NULL; cmd++) {
            cmd_completion(cmdname, cmd->name);
        }

		/** START DECAF ADDITIONS **/
        if (DECAF_mon_cmds != NULL)
        {
          for (cmd = DECAF_mon_cmds; cmd->name != NULL; cmd++)
          {
            cmd_completion(cmdname,cmd->name);
          }
        }
        if (decaf_plugin && decaf_plugin->mon_cmds)
        {
          for (cmd = decaf_plugin->mon_cmds; cmd->name != NULL; cmd++)
          {
            cmd_completion(cmdname, cmd->name);
          }
        }
        /** END DECAF ADDITIONS **/
    } else {
        /* find the command */
        for(cmd = mon_cmds; cmd->name != NULL; cmd++) {
            if (compare_cmd(args[0], cmd->name))
                goto found;
        }

        /** START DECAF ADDITIONS **/
        // The logic here is slightly different in new versions 
        //  of QEMU. But the idea is the same - if not found
        //  then continue to look for in the other command sources
        //  until its found or just return

        //If we are here then the cmd is not a QEMU cmd
        if (DECAF_mon_cmds != NULL)
        {
          for (cmd = DECAF_mon_cmds; cmd->name != NULL; cmd++)
          {
            if (compare_cmd(args[0], cmd->name))
            {
              goto found;
            }
          }
        }
        //if we are here then its neither QEMU nor DECAF
        if (decaf_plugin && decaf_plugin->mon_cmds)
        {
          for (cmd = decaf_plugin->mon_cmds; cmd->name != NULL; cmd++)
          {
            if (compare_cmd(args[0], cmd->name))
            {
              goto found;
            }
          }
        }
        //cmd was not found so just exit.
        /** END DECAF ADDITIONS **/
        return;
    found:
        ptype = cmd->args_type;
        for(i = 0; i < nb_args - 2; i++) {
            if (*ptype != '\0') {
                ptype++;
                while (*ptype == '?')
                    ptype++;
            }
        }
        str = args[nb_args - 1];
        switch(*ptype) {
        case 'F':
            /* file completion */
            readline_set_completion_index(cur_mon->rs, strlen(str));
            file_completion(str);
            break;
        case 'B':
            /* block device name completion */
            readline_set_completion_index(cur_mon->rs, strlen(str));
            bdrv_iterate(block_completion_it, (void *)str);
            break;
        case 's':
            /* XXX: more generic ? */
            if (!strcmp(cmd->name, "info")) {
                readline_set_completion_index(cur_mon->rs, strlen(str));
                for(cmd = info_cmds; cmd->name != NULL; cmd++) {
                    cmd_completion(str, cmd->name);
                }

			  /** START DECAF ADDITIONS **/
              // Getting some info?
              if (DECAF_info_cmds != NULL)
              {
                for (cmd = DECAF_info_cmds; cmd->name != NULL; cmd++)
                {
                  cmd_completion(str, cmd->name);
                }
              }
              if (decaf_plugin && decaf_plugin->info_cmds)
              {
                for (cmd = decaf_plugin->info_cmds; cmd->name != NULL; cmd++)
                {
                  cmd_completion(str, cmd->name);
                }
              }
              /** END DECAF ADDITIONS **/

			  
            } else if (!strcmp(cmd->name, "sendkey")) {
                char *sep = strrchr(str, '-');
                if (sep)
                    str = sep + 1;
                readline_set_completion_index(cur_mon->rs, strlen(str));
                for(key = key_defs; key->name != NULL; key++) {
                    cmd_completion(str, key->name);
                }
            }
            break;
        default:
            break;
        }
    }
    for(i = 0; i < nb_args; i++)
        g_free(args[i]);
}

static void monitor_done(Monitor *mon)
{
    if (cur_mon == mon)
        cur_mon = NULL;

    QLIST_REMOVE(mon, entry);

    readline_free(mon->rs);
    qemu_chr_close(mon->chr);

    g_free(mon);
}


void monitor_init(CharDriverState* chr, int flags) {
    static int is_first_init = 1;
    Monitor *mon;

    if (is_first_init) {
		key_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, release_keys, NULL);
		//key_timer = qemu_new_timer_ms(vm_clock, release_keys, NULL);
        is_first_init = 0;
    }

    mon = g_malloc0(sizeof(*mon));

    mon->chr = chr;
    mon->flags = flags;
    if (flags & MONITOR_USE_READLINE) {
        mon->rs = readline_init(mon, monitor_find_completion);
        monitor_read_command(mon, 0);
    }

    qemu_chr_add_handlers(chr, monitor_can_read, monitor_read, monitor_event,
                          mon);

    QLIST_INSERT_HEAD(&mon_list, mon, entry);
    if (!cur_mon || (flags & MONITOR_IS_DEFAULT))
        cur_mon = mon;

    /** START DECAF ADDITIONS **/
    if (!default_mon || (flags & MONITOR_IS_DEFAULT))
    {
      default_mon = mon;
    }
    /** END DECAF ADDITIONS **/
}


