#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/cred.h>
#include <linux/seccomp.h>
#include <linux/uidgid.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DFRoot LKM");

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef void *(*umh_setup_t)(const char *path, char **argv, char **envp, gfp_t gfp,
                             void *init, void *cleanup, void *data);
typedef int (*umh_exec_t)(void *info, int wait);

static struct kprobe defex_enforce_kp;
static struct kprobe defex_umh_kp;
static int defex_enforce_ok;
static int defex_umh_ok;

/* Vivo/OriginOS (and GrapheneOS) kernels carry an extra seccomp policy that
 * kills the process (SECCOMP_RET_KILL_*) when an app issues reboot(2).
 * KernelSU >= 2.0 probes the driver with a magic reboot() "supercall"
 * (ksud ksucalls.rs::init_driver_fd); a kill verdict crashes libksud.so
 * before it can fall back to the daemon socket, so the manager UI freezes
 * (~60s "Shell check timeout") on every resume and after every soft reboot.
 * Downgrade that one verdict to SECCOMP_RET_ALLOW for app uids: the real
 * reboot path still demands CAP_SYS_BOOT, so unprivileged callers get the
 * stock clean -EPERM failure, exactly like devices without the OEM policy.
 * 142 == __NR_reboot (asm-generic, all our targets are arm64).
 *
 * NOTE: this needs CONFIG_KALLSYMS_ALL (the function is static); vivo
 * kernels ship it disabled, in which case this hook silently stays off
 * and the manager-side fix comes from the vivo prctl faker below instead. */
#define DF_NR_REBOOT 142

static struct kprobe seccomp_kp;
static int seccomp_kp_ok;

static int seccomp_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    const struct seccomp_data *sd = (const struct seccomp_data *)regs->regs[0];

    (void)p;
    if (!sd || sd->nr != DF_NR_REBOOT)
        return 0;
    if (__kuid_val(current_uid()) < 10000)
        return 0;
    regs->regs[0] = SECCOMP_RET_ALLOW;
    regs->pc = regs->regs[30]; /* skip body: verdict is allow */
    return 1;
}

/* vivo: ksud late-load injects the official GKI kernelsu.ko, whose init
 * intermittently hard-hangs this kernel (module stuck in "Loading", total
 * freeze, no panic). ksud decides whether to load it via
 * ksuinit::has_kernelsu(), which checks a magic legacy prctl:
 * prctl(0xDEADBEEF, CMD_GET_VERSION=2, &version). Answering with a nonzero
 * version makes late-load take the "already loaded" branch and skip the
 * dangerous module entirely. Gated on the vivo cmdline so Samsung and
 * other devices keep loading the real driver.
 * Disabled for now: bootstrap rmmods dfroot before late-load instead. */
#define KSU_PRCTL_MAGIC 0xDEADBEEF
#define KSU_CMD_GET_VERSION 2

#if 0
static struct kprobe prctl_kp;
static int prctl_kp_ok;

/* NOTE: syscall wrappers take a single `const struct pt_regs *` argument;
 * the real prctl args live one level down. */
static int prctl_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *sysregs = (struct pt_regs *)regs->regs[0];
    u32 one = 1;

    (void)p;
    if (!sysregs)
        return 0;
    if (sysregs->regs[0] != KSU_PRCTL_MAGIC || sysregs->regs[1] != KSU_CMD_GET_VERSION)
        return 0;
    if (!access_ok((void __user *)sysregs->regs[2], sizeof(one)))
        return 0;
    if (copy_to_user((void __user *)sysregs->regs[2], &one, sizeof(one)))
        return 0;
    regs->regs[0] = 0;         /* wrapper returns success */
    regs->pc = regs->regs[30]; /* skip the real syscall */
    return 1;
}
#endif

/* Neutralise SELinux enforcement at the AVC layer. Some vendors ship
 * CONFIG_SECURITY_SELINUX_DEVELOP=n (no runtime enforcing flag at all), and
 * vivo actively flips selinux_state.enforcing back to true, so writing the
 * state below is not enough. A post_handler keeps the real body (callers get
 * a valid av_decision) and only rewrites the return value: every denial
 * becomes an allow, which is exactly what permissive mode does. */
static struct kprobe avc_kp;
static int avc_kp_ok;

static void avc_allow_post_handler(struct kprobe *p, struct pt_regs *regs,
                                   unsigned long flags)
{
    (void)p;
    (void)flags;
    regs->regs[0] = 0;
}

static int null_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    (void)p;
    regs->regs[0] = 0;         /* x0 = DEFEX_ALLOW */
    regs->pc = regs->regs[30]; /* skip body: return to caller */
    return 1;
}

static int __nocfi __init dfroot_init(void)
{
    kallsyms_lookup_name_t get_addr;
    umh_setup_t umh_setup;
    umh_exec_t  umh_exec;
    bool *selinux_state;
    struct kprobe kln_kp;
    void *info;
    int ret;

    // UMH command to run
    static const char sh[] = "/system/bin/sh";
    static char *envp[] = { "PATH=/system/bin", NULL };
    static char *argv[] = { (char *)sh, "-c",
        "touch /dev/dfm0;"
        " rmmod oplus_secure_harden 2>/dev/null;"         //
        " rmmod oplus_security_keventupload 2>/dev/null;" // Oppo/OnePlus
        " rmmod oplus_security_guard 2>/dev/null",        //
        NULL };

    // Symbol finder
    kln_kp = (struct kprobe){ .symbol_name = "kallsyms_lookup_name" };
    if (register_kprobe(&kln_kp) < 0) {
        pr_err("dfroot: kallsyms_lookup_name not found\n");
        return -EINVAL;
    }
    get_addr = (kallsyms_lookup_name_t)kln_kp.addr;
    unregister_kprobe(&kln_kp);

    // NOTE: the page-cache drop for crash_dump64 used to live here, but it
    //   races the exploit: once it drops the spliced pages the crash_dump
    //   bridge is gone and exp.c can no longer restore the vendor file.
    //   exp.c cleanup() now writes the original bytes back instead, which is
    //   deterministic and needs no kernel support.

    // Disable SELinux
    selinux_state = (bool *)get_addr("selinux_state");
    if (!selinux_state) {
        pr_err("dfroot: selinux_state not found, relying on avc hook\n");
    } else {
        WRITE_ONCE(*selinux_state, false);
        pr_info("dfroot: selinux_state permissive\n");
    }

    // Keep it permissive regardless of vendor watchdogs / DEVELOP=n builds
    avc_kp = (struct kprobe){ .symbol_name = "avc_has_perm_noaudit",
                              .post_handler = avc_allow_post_handler };
    avc_kp_ok = register_kprobe(&avc_kp) == 0;
    if (!avc_kp_ok)
        pr_err("dfroot: avc_has_perm_noaudit not in this kernel, skipping\n");
    else
        pr_info("dfroot: avc_has_perm_noaudit hooked\n");

    // Samsung
    defex_enforce_kp = (struct kprobe){ .addr = (kprobe_opcode_t *)get_addr("task_defex_enforce"),
                                .pre_handler = null_pre_handler };
    defex_enforce_ok = register_kprobe(&defex_enforce_kp) == 0;
    if (!defex_enforce_ok)
        pr_err("dfroot: task_defex_enforce not in this kernel, skipping\n");
    else
        pr_info("dfroot: task_defex_enforce hooked\n");
    
    defex_umh_kp = (struct kprobe){ .addr = (kprobe_opcode_t *)get_addr("task_defex_user_exec"),
                              .pre_handler = null_pre_handler };
    defex_umh_ok = register_kprobe(&defex_umh_kp) == 0;
    if (!defex_umh_ok)
        pr_err("dfroot: task_defex_user_exec not in this kernel, skipping\n");
    else
        pr_info("dfroot: task_defex_user_exec hooked\n");

    // Vivo/OriginOS: defuse the seccomp kill on the reboot supercall
    seccomp_kp = (struct kprobe){ .symbol_name = "seccomp_run_filters",
                                  .pre_handler = seccomp_pre_handler };
    seccomp_kp_ok = register_kprobe(&seccomp_kp) == 0;
    if (!seccomp_kp_ok)
        pr_err("dfroot: seccomp_run_filters not in this kernel, skipping\n");
    else
        pr_info("dfroot: seccomp_run_filters hooked\n");

    // Vivo/OriginOS: the official kernelsu.ko from late-load intermittently
    // hard-hangs this kernel while coexisting with our kprobes. Bootstrap
    // now rmmods dfroot before late-load so the driver's init registers its
    // kprobes into a clean kernel; if that still hangs, the prctl faker
    // above can be re-enabled to make late-load skip the driver entirely.
#if 0
    {
        char *cmdline = (char *)get_addr("saved_command_line");

        if (cmdline && strstr(cmdline, "vivo")) {
            prctl_kp = (struct kprobe){ .symbol_name = "__arm64_sys_prctl",
                                        .pre_handler = prctl_pre_handler };
            prctl_kp_ok = register_kprobe(&prctl_kp) == 0;
            if (!prctl_kp_ok)
                pr_err("dfroot: __arm64_sys_prctl not in this kernel, skipping\n");
            else
                pr_info("dfroot: vivo prctl probe faker hooked\n");
        }
    }
#endif

    // Run UMH command
    umh_setup = (umh_setup_t)get_addr("call_usermodehelper_setup");
    umh_exec  = (umh_exec_t)get_addr("call_usermodehelper_exec");
    if (!umh_setup || !umh_exec) {
        pr_err("dfroot: usermodehelper symbols missing (setup=%px exec=%px)\n",
               umh_setup, umh_exec);
        return 0;
    }

    info = umh_setup(sh, argv, envp, GFP_KERNEL, NULL, NULL, NULL);
    if (!info) {
        pr_err("dfroot: usermodehelper_setup: returned NULL\n");
        return 0;
    }
    // bypass CONFIG_STATIC_USERMODEHELPER_PATH="" overriding path to ""
    ((struct subprocess_info *)info)->path = sh;

    ret = umh_exec(info, UMH_WAIT_PROC);
    pr_info("dfroot: usermodehelper_exec returned %d\n", ret);
    
    return 0;
}

static void __exit dfroot_exit(void)
{
    if (defex_enforce_ok) unregister_kprobe(&defex_enforce_kp);
    if (defex_umh_ok)     unregister_kprobe(&defex_umh_kp);
    if (seccomp_kp_ok)    unregister_kprobe(&seccomp_kp);
    if (avc_kp_ok)        unregister_kprobe(&avc_kp);
}

module_init(dfroot_init);
module_exit(dfroot_exit);
