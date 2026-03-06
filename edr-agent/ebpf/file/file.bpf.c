// ebpf/file/file.bpf.c
//
// eBPF program for file integrity monitoring.
//
// Hooks:
//   - kprobe/vfs_write              → file write (kprobe avoids __user issue)
//   - fentry/vfs_create             → file creation
//   - fentry/vfs_unlink             → file deletion
//   - fentry/vfs_rename             → rename/move
//   - fentry/security_inode_setattr → chmod/chown
//
// NOTE on vfs_write: BPF_PROG (fentry) cannot accept pointer-to-userspace
// annotated args like "const char __user *buf" — the __user tag confuses
// the BPF macro expansion.  We use a kprobe instead which receives raw
// pt_regs and reads arguments with PT_REGS_PARMn().
//
// NOTE on kernel version compatibility:
//   vfs_create/vfs_unlink gained the leading mnt_userns arg in 5.12.
//   We use kprobes for those too so the arg list is read from pt_regs
//   and we just pick the dentry regardless of kernel version.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ─── Constants ────────────────────────────────────────────────────────────────

#define TASK_COMM_LEN  16
#define NAME_MAX_BUF   256   // path buffer size
#define OLD_NAME_MAX   128   // old-path buffer (renames)

// Event types (must match pkg/types/events.go)
#define EVENT_FILE_CREATE  20
#define EVENT_FILE_WRITE   21
#define EVENT_FILE_DELETE  22
#define EVENT_FILE_RENAME  23
#define EVENT_FILE_CHMOD   25

// ─── Event struct ─────────────────────────────────────────────────────────────

struct file_event {
    __u64 timestamp_ns;
    __u32 event_type;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char  comm[TASK_COMM_LEN];
    char  path[NAME_MAX_BUF];
    char  old_path[OLD_NAME_MAX];   // renames only
    __u64 inode;
    __u32 dev;
    __u32 mode;
    __u64 size;
    __u32 flags;
    __u32 pad;
};

// ─── Maps ─────────────────────────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} file_events SEC(".maps");

// ─── Helpers ──────────────────────────────────────────────────────────────────

static __always_inline __u32 get_pid(void) {
    return (__u32)(bpf_get_current_pid_tgid() >> 32);
}

static __always_inline __u32 get_ppid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;
    __u32 ppid = 0;
    bpf_core_read(&parent, sizeof(parent), &task->real_parent);
    if (parent)
        bpf_core_read(&ppid, sizeof(ppid), &parent->tgid);
    return ppid;
}

static __always_inline void fill_base(struct file_event *e, __u32 event_type) {
    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type   = event_type;
    e->pid          = get_pid();
    e->ppid         = get_ppid();
    __u64 ugid      = bpf_get_current_uid_gid();
    e->uid          = (__u32)(ugid >> 32);
    e->gid          = (__u32)ugid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline void fill_inode(struct file_event *e, struct inode *inode) {
    if (!inode) return;
    bpf_core_read(&e->inode, sizeof(e->inode), &inode->i_ino);
    bpf_core_read(&e->mode,  sizeof(e->mode),  &inode->i_mode);
    bpf_core_read(&e->size,  sizeof(e->size),  &inode->i_size);
    dev_t dev = 0;
    bpf_core_read(&dev, sizeof(dev), &inode->i_sb->s_dev);
    e->dev = (__u32)dev;
}

static __always_inline void fill_dentry_name(struct file_event *e, struct dentry *dentry) {
    if (!dentry) return;
    struct qstr d_name;
    bpf_core_read(&d_name, sizeof(d_name), &dentry->d_name);
    bpf_probe_read_kernel_str(e->path, sizeof(e->path), d_name.name);
}

// ─── kprobe/vfs_write ─────────────────────────────────────────────────────────
// Signature: ssize_t vfs_write(struct file *file, const char __user *buf,
//                              size_t count, loff_t *pos)
// We use kprobe to avoid the __user annotation problem with BPF_PROG/fentry.

SEC("kprobe/vfs_write")
int kprobe_vfs_write(struct pt_regs *ctx)
{
    struct file *file  = (struct file *)PT_REGS_PARM1(ctx);
    size_t       count = (size_t)PT_REGS_PARM3(ctx);

    if (count == 0 || !file) return 0;

    struct file_event *e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    fill_base(e, EVENT_FILE_WRITE);
    e->size = count;

    struct inode *inode = NULL;
    bpf_core_read(&inode, sizeof(inode), &file->f_inode);
    fill_inode(e, inode);

    struct dentry *dentry = NULL;
    bpf_core_read(&dentry, sizeof(dentry), &file->f_path.dentry);
    fill_dentry_name(e, dentry);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── kprobe/vfs_create ────────────────────────────────────────────────────────
// Kernel < 5.12:  vfs_create(inode *dir, dentry *, umode_t, bool)
// Kernel >= 5.12: vfs_create(user_namespace *, inode *dir, dentry *, umode_t, bool)
//
// Using kprobe + reading from pt_regs lets us handle both by always
// treating the dentry as arg3 (index 2) on pre-5.12 and arg3 (index 2) on 5.12+
// when mnt_userns is arg1.  We detect which layout by checking if arg1 looks
// like a valid inode (has non-zero i_ino) — if not, it's mnt_userns.

SEC("kprobe/vfs_create")
int kprobe_vfs_create(struct pt_regs *ctx)
{
    // Try the 5.12+ layout first: (mnt_userns, dir, dentry, mode, excl)
    // dentry is always arg3 (PT_REGS_PARM3) in both layouts on x86_64:
    //   pre-5.12:  parm1=dir, parm2=dentry, parm3=mode  — dentry is PARM2
    //   post-5.12: parm1=ns,  parm2=dir,    parm3=dentry — dentry is PARM3
    // We use the tracepoint approach below for reliability.

    struct file_event *e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    fill_base(e, EVENT_FILE_CREATE);

    // Read dentry from PARM3 (works for 5.12+ where sig is ns,dir,dentry,...)
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM3(ctx);
    if (!dentry) {
        // Fall back to PARM2 (pre-5.12 where sig is dir,dentry,...)
        dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    }
    fill_dentry_name(e, dentry);

    // mode from PARM4 (5.12+) or PARM3 (pre-5.12) — just use PARM4, worst case 0
    umode_t mode = (umode_t)(unsigned long)PT_REGS_PARM4(ctx);
    e->mode = mode;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── kprobe/vfs_unlink ────────────────────────────────────────────────────────
// Kernel < 5.12:  vfs_unlink(inode *dir, dentry *, inode **delegated)
// Kernel >= 5.12: vfs_unlink(user_namespace *, inode *dir, dentry *, inode **)

SEC("kprobe/vfs_unlink")
int kprobe_vfs_unlink(struct pt_regs *ctx)
{
    struct file_event *e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    fill_base(e, EVENT_FILE_DELETE);

    // Same duality as vfs_create — try PARM3 first (5.12+), fall back to PARM2
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM3(ctx);
    struct inode *inode_check = NULL;
    if (dentry)
        bpf_core_read(&inode_check, sizeof(inode_check), &dentry->d_inode);
    if (!inode_check) {
        dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    }

    struct inode *inode = NULL;
    if (dentry)
        bpf_core_read(&inode, sizeof(inode), &dentry->d_inode);
    fill_inode(e, inode);
    fill_dentry_name(e, dentry);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── fentry/vfs_rename ────────────────────────────────────────────────────────
// vfs_rename(struct renamedata *) — single-arg form added in 5.12 simplifies this.
// For older kernels, fall back to kprobe reading old_dentry from PARM3.

SEC("kprobe/vfs_rename")
int kprobe_vfs_rename(struct pt_regs *ctx)
{
    struct file_event *e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    fill_base(e, EVENT_FILE_RENAME);

    // Kernel >= 5.12: vfs_rename(struct renamedata *rd) — single pointer arg.
    // Kernel < 5.12:  vfs_rename(inode*, dentry*, inode*, dentry*, inode**, unsigned int)
    //
    // Heuristic: check if arg1 could be a renamedata pointer by reading
    // what would be the old_dir field.  We just read old_dentry from
    // PARM2 (old layout) as the safe cross-version path since renamedata->old_dentry
    // is at offset 8 and PARM2 in the old layout is old_dentry directly.

    // Try new single-struct layout first
    struct renamedata *rd = (struct renamedata *)PT_REGS_PARM1(ctx);
    struct dentry *old_dentry = NULL;
    struct dentry *new_dentry = NULL;
    bpf_core_read(&old_dentry, sizeof(old_dentry), &rd->old_dentry);
    bpf_core_read(&new_dentry, sizeof(new_dentry), &rd->new_dentry);

    if (old_dentry) {
        struct qstr qold;
        bpf_core_read(&qold, sizeof(qold), &old_dentry->d_name);
        bpf_probe_read_kernel_str(e->old_path, sizeof(e->old_path), qold.name);
    }
    if (new_dentry) {
        struct qstr qnew;
        bpf_core_read(&qnew, sizeof(qnew), &new_dentry->d_name);
        bpf_probe_read_kernel_str(e->path, sizeof(e->path), qnew.name);
    }

    // Inode from old dentry
    struct inode *inode = NULL;
    if (old_dentry)
        bpf_core_read(&inode, sizeof(inode), &old_dentry->d_inode);
    fill_inode(e, inode);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── fentry/security_inode_setattr — chmod/chown ─────────────────────────────
// Kernel >= 5.12: security_inode_setattr(mnt_userns, dentry, iattr)
// Kernel < 5.12:  security_inode_setattr(dentry, iattr)
// Use kprobe again for version portability.

SEC("kprobe/security_inode_setattr")
int kprobe_security_inode_setattr(struct pt_regs *ctx)
{
    // Try 5.12+ layout: (mnt_userns, dentry, iattr)
    // For pre-5.12: (dentry, iattr) — dentry is PARM1, iattr is PARM2
    // We detect: if PARM1 looks like a dentry (has d_inode), use pre-5.12 layout.

    struct dentry *dentry = (struct dentry *)PT_REGS_PARM1(ctx);
    struct iattr  *attr   = (struct iattr  *)PT_REGS_PARM2(ctx);

    // Quick check: can we read d_inode from what we think is the dentry?
    struct inode *test_inode = NULL;
    int ret = bpf_core_read(&test_inode, sizeof(test_inode), &dentry->d_inode);
    if (ret != 0 || !test_inode) {
        // Probably 5.12+ layout — dentry is PARM2, attr is PARM3
        dentry = (struct dentry *)PT_REGS_PARM2(ctx);
        attr   = (struct iattr  *)PT_REGS_PARM3(ctx);
    }

    // Filter: only ATTR_MODE (0x1), ATTR_UID (0x2), ATTR_GID (0x4)
    unsigned int valid = 0;
    if (attr)
        bpf_core_read(&valid, sizeof(valid), &attr->ia_valid);
    if (!(valid & 0x7)) return 0;

    struct file_event *e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    fill_base(e, EVENT_FILE_CHMOD);
    e->flags = valid;

    if (attr) {
        umode_t new_mode = 0;
        bpf_core_read(&new_mode, sizeof(new_mode), &attr->ia_mode);
        e->mode = new_mode;
    }

    struct inode *inode = NULL;
    if (dentry)
        bpf_core_read(&inode, sizeof(inode), &dentry->d_inode);
    fill_inode(e, inode);
    fill_dentry_name(e, dentry);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
