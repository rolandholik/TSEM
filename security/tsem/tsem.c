// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Enjellic Systems Development, LLC
 * Author: Dr. Greg Wettstein <greg@enjellic.com>
 *
 * TSEM initialization infrastructure.
 */
#define TRAPPED_MSG_LENGTH 128

#define LOCKED true
#define NOLOCK false

#include <linux/magic.h>
#include <linux/mman.h>
#include <linux/binfmts.h>
#include <linux/bpf.h>
#include <linux/ipv6.h>
#include <linux/mount.h>

#include "tsem.h"

static const struct lsm_id tsem_lsmid = {
	.name = "tsem",
	.id = LSM_ID_TSEM
};

struct lsm_blob_sizes tsem_blob_sizes __ro_after_init = {
 	.lbs_task = sizeof(struct tsem_task),
 	.lbs_inode = sizeof(struct tsem_inode),
	.lbs_ipc = sizeof(struct tsem_ipc)
};

enum tsem_action_type tsem_root_actions[TSEM_EVENT_CNT] = {
	TSEM_ACTION_EPERM	/* Undefined. */
};

static atomic64_t task_instance;

static struct tsem_model root_model = {
	.point_lock = __SPIN_LOCK_INITIALIZER(root_model.point_lock),
	.point_list = LIST_HEAD_INIT(root_model.point_list),
	.point_end_mutex = __MUTEX_INITIALIZER(root_model.point_end_mutex),

	.trajectory_lock = __SPIN_LOCK_INITIALIZER(root_model.trajectory_lock),
	.trajectory_list = LIST_HEAD_INIT(root_model.trajectory_list),
	.trajectory_end_mutex = __MUTEX_INITIALIZER(root_model.trajectory_end_mutex),

	.forensics_lock = __SPIN_LOCK_INITIALIZER(root_model.forensics_lock),
	.forensics_list = LIST_HEAD_INIT(root_model.forensics_list),
	.forensics_end_mutex = __MUTEX_INITIALIZER(root_model.forensics_end_mutex),

	.pseudonym_mutex = __MUTEX_INITIALIZER(root_model.pseudonym_mutex),
	.pseudonym_list = LIST_HEAD_INIT(root_model.pseudonym_list)
};

static struct tsem_context root_context;

static int tsem_ready __ro_after_init;
 
static bool tsem_available __ro_after_init;
 
static unsigned int magazine_size __ro_after_init = TSEM_ROOT_MAGAZINE_SIZE;

static enum mode_type {
	FULL_MODELING,
	NO_ROOT_MODELING,
	EXPORT_ONLY
} tsem_mode __ro_after_init;
 
static char *default_hash_function __ro_after_init;

const char * const tsem_names[TSEM_EVENT_CNT] = {
	"undefined",
	"bprm_committing_creds",
	"task_kill",
	"task_setpgid",
	"task_getpgid",
	"task_getsid",
	"task_setnice",
	"task_setioprio",
	"task_getioprio",
	"task_prlimit",
	"task_setrlimit",
	"task_setscheduler",
	"task_getscheduler",
	"task_prctl",
	"file_open",
	"mmap_file",
	"file_ioctl",
	"file_lock",
	"file_fcntl",
	"file_receive",
	"unix_stream_connect",
	"unix_may_send",
	"socket_create",
	"socket_connect",
	"socket_bind",
	"socket_accept",
	"socket_listen",
	"socket_socketpair",
	"socket_sendmsg",
	"socket_recvmsg",
	"socket_getsockname",
	"socket_getpeername",
	"socket_setsockopt",
	"socket_shutdown",
	"ptrace_traceme",
	"kernel_module_request",
	"kernel_load_data",
	"kernel_read_file",
	"sb_mount",
	"sb_umount",
	"sb_remount",
	"sb_pivotroot",
	"sb_statfs",
	"move_mount",
	"shm_associate",
	"shm_shmctl",
	"shm_shmat",
	"sem_associate",
	"sem_semctl",
	"sem_semop",
	"syslog",
	"settime",
	"quotactl",
	"quota_on",
	"msg_queue_associate",
	"msg_queue_msgctl",
	"msg_queue_msgsnd",
	"msg_queue_msgrcv",
	"ipc_permission",
	"key_alloc",
	"key_permission",
	"netlink_send",
	"inode_create",
	"inode_link",
	"inode_unlink",
	"inode_symlink",
	"inode_mkdir",
	"inode_rmdir",
	"inode_mknod",
	"inode_rename",
	"inode_setattr",
	"inode_getattr",
	"inode_setxattr",
	"inode_getxattr",
	"inode_listxattr",
	"inode_removexattr",
	"inode_killpriv",
	"tun_dev_create",
	"tun_dev_attach_queue",
	"tun_dev_attach",
	"tun_dev_open",
	"bpf",
	"bpf_map",
	"bpf_prog"
};

static const unsigned long pseudo_filesystems[] = {
	PROC_SUPER_MAGIC,
	SYSFS_MAGIC,
	DEBUGFS_MAGIC,
	TMPFS_MAGIC,
	DEVPTS_SUPER_MAGIC,
	BINFMTFS_MAGIC,
	SECURITYFS_MAGIC,
	SELINUX_MAGIC,
	SMACK_MAGIC,
	CGROUP_SUPER_MAGIC,
	CGROUP2_SUPER_MAGIC,
	NSFS_MAGIC,
	EFIVARFS_MAGIC
};

static int __init set_magazine_size(char *magazine_value)
{
	if (kstrtouint(magazine_value, 0, &magazine_size))
		pr_warn("tsem: Failed to parse root cache size.\n");

	if (!magazine_size) {
		pr_warn("tsem: Forcing non-zero cache size.\n");
		magazine_size = TSEM_ROOT_MAGAZINE_SIZE;
	}

	pr_info("tsem: Setting default root cache size to %u.\n",
		magazine_size);
	return 1;
}
__setup("tsem_cache=", set_magazine_size);

static int __init set_modeling_mode(char *mode_value)
{
	unsigned long mode = 0;

	if (kstrtoul(mode_value, 0, &mode)) {
		pr_warn("tsem: Failed to parse modeling mode.\n");
		return 1;
	}

	if (mode == 1)
		tsem_mode = NO_ROOT_MODELING;
	else if (mode == 2)
		tsem_mode = EXPORT_ONLY;
	else
		pr_warn("tsem: Unknown mode specified.\n");
	return 1;
}
__setup("tsem_mode=", set_modeling_mode);

static int __init set_default_hash_function(char *hash_function)
{

	default_hash_function = hash_function;
	return 1;
}
__setup("tsem_digest=", set_default_hash_function);

static bool bypass_event(void)
{
	struct tsem_context *ctx = tsem_context(current);

	if (tsem_mode == NO_ROOT_MODELING && !ctx->id)
		return true;
	if (tsem_mode == EXPORT_ONLY && !ctx->id && !ctx->external)
		return true;
	return false;
}

static bool bypass_filesystem(struct inode *inode)
{
	unsigned int lp;

	for (lp = 0; lp < ARRAY_SIZE(pseudo_filesystems); ++lp)
		if (inode->i_sb->s_magic == pseudo_filesystems[lp])
			return true;
	return false;
}

static int event_action(struct tsem_context *ctx, enum tsem_event_type event)
{
	int retn = 0;

	if (tsem_task_trusted(current))
		return retn;

	if (ctx->actions[event] == TSEM_ACTION_EPERM)
		retn = -EPERM;

	return retn;
}

static int trapped_task(enum tsem_event_type event, char *msg, bool locked)
{
	int retn;
	struct tsem_context *ctx = tsem_context(current);

	pr_warn("Untrusted %s: comm=%s, pid=%d, parameters='%s'\n",
		tsem_names[event], current->comm, task_pid_nr(current), msg);

	if (ctx->external) {
		retn = tsem_export_action(event, locked);
		if (retn)
			return retn;
	}

	return event_action(ctx, event);
}

static int trapped_inode(enum tsem_event_type event, struct inode *inode,
			 char *inode_msg, bool locked)
{
	const char *dname;
	char msg[TRAPPED_MSG_LENGTH];
	struct dentry *dird;

	dird = d_find_alias(inode);
	if (dird == NULL)
		dname = "not available";
	else
		dname = dird->d_name.name;
	scnprintf(msg, sizeof(msg), "parent=%s, %s", dname, inode_msg);

	return trapped_task(event, msg, locked);
}

static int dispatch_event(struct tsem_event *ep)
{
	int retn;
	struct tsem_context *ctx = tsem_context(current);

	if (tsem_mode == NO_ROOT_MODELING && !ctx->id)
		return 0;
	if (unlikely(tsem_mode == EXPORT_ONLY && !ctx->id && !ctx->external))
		return 0;

	retn = tsem_event_init(ep);
	if (retn)
		return retn;

	if (!ctx->external)
		retn = tsem_model_event(ep);
	else
		retn = tsem_export_event(ep);

	if (!retn)
		retn = event_action(ctx, ep->event);

	tsem_event_put(ep);
	return retn;
}

static int dispatch_generic_event(enum tsem_event_type event, bool locked)
{
	struct tsem_event *ep;

	if (!tsem_context(current)->id && tsem_mode == NO_ROOT_MODELING)
		return 0;

	ep = tsem_event_allocate(event, locked);
	if (!ep)
		return -ENOMEM;
	ep->no_params = true;

	return dispatch_event(ep);
}

static int tsem_file_open(struct file *file)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct inode *inode = file_inode(file);
	struct tsem_event *ep;

	if (unlikely(!tsem_ready))
		return 0;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "filename=%s, flags=0x%x",
			 file->f_path.dentry->d_name.name, file->f_flags);
		return trapped_task(TSEM_FILE_OPEN, msg, NOLOCK);
	}

	if (!S_ISREG(inode->i_mode))
		return 0;
	if (bypass_filesystem(inode))
		return 0;
	if (tsem_inode(inode)->status == TSEM_INODE_COLLECTING)
		return 0;

	ep = tsem_event_allocate(TSEM_FILE_OPEN, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.file.in.file = file;

	return dispatch_event(ep);
}

static int tsem_mmap_file(struct file *file, unsigned long reqprot,
			  unsigned long prot, unsigned long flags)
{
	const char *p;
	char msg[TRAPPED_MSG_LENGTH];
	struct inode *inode = NULL;
	struct tsem_event *ep;

	if (unlikely(!tsem_ready))
		return 0;

	if (tsem_task_untrusted(current)) {
		p = "anonymous mapping";
		if (file)
			p = file->f_path.dentry->d_name.name;
		scnprintf(msg, sizeof(msg),
			  "filename=%s, rprot=0x%lx, prot=0x%lx, flags=0x%lx",
			  p, reqprot, prot, flags);
		return trapped_task(TSEM_MMAP_FILE, msg, NOLOCK);
	}

	if (!file && !(prot & PROT_EXEC))
		return 0;
	if (file) {
		inode = file_inode(file);
		if (!S_ISREG(inode->i_mode))
			return 0;
		if (bypass_filesystem(inode))
			return 0;
	}

	ep = tsem_event_allocate(TSEM_MMAP_FILE, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.mmap_file.file.in.file = file;
	ep->CELL.mmap_file.anonymous = file == NULL ? 1 : 0;
	ep->CELL.mmap_file.reqprot = reqprot;
	ep->CELL.mmap_file.prot = prot;
	ep->CELL.mmap_file.flags = flags;

	return dispatch_event(ep);
}

static int tsem_file_ioctl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "name=%s, cmd=%u",
			  file->f_path.dentry->d_name.name, cmd);
		return trapped_task(TSEM_FILE_IOCTL, msg, NOLOCK);
	}

	if (bypass_filesystem(file_inode(file)))
		return 0;

	ep = tsem_event_allocate(TSEM_FILE_IOCTL, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.file.cmd = cmd;
	ep->CELL.file.in.file = file;

	return dispatch_event(ep);
}

static int tsem_file_lock(struct file *file, unsigned int cmd)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "name=%s, cmd=%u",
			  file->f_path.dentry->d_name.name, cmd);
		return trapped_task(TSEM_FILE_LOCK, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_FILE_LOCK, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.file.cmd = cmd;
	ep->CELL.file.in.file = file;

	return dispatch_event(ep);
}

static int tsem_file_fcntl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (unlikely(!tsem_ready))
		return 0;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "name=%s, cmd=%u",
			  file->f_path.dentry->d_name.name, cmd);
		return trapped_task(TSEM_FILE_FCNTL, msg, NOLOCK);
	}

	if (bypass_filesystem(file_inode(file)))
		return 0;

	ep = tsem_event_allocate(TSEM_FILE_FCNTL, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.file.cmd = cmd;
	ep->CELL.file.in.file = file;

	return dispatch_event(ep);
}

static int tsem_file_receive(struct file *file)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "name=%s, flags=%u",
			  file->f_path.dentry->d_name.name, file->f_flags);
		return trapped_task(TSEM_FILE_RECEIVE, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_FILE_RECEIVE, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.file.in.file = file;

	return dispatch_event(ep);
}

static int tsem_task_alloc(struct task_struct *new, unsigned long flags)
{
	struct tsem_task *old_task = tsem_task(current);
	struct tsem_task *new_task = tsem_task(new);

	new_task->instance = old_task->instance;
	new_task->p_instance = old_task->instance;

	new_task->trust_status = old_task->trust_status;
	new_task->context = old_task->context;
	memcpy(new_task->task_id, old_task->task_id, HASH_MAX_DIGESTSIZE);
	memcpy(new_task->p_task_id, old_task->task_id, HASH_MAX_DIGESTSIZE);

	if (!new_task->context->id)
		return 0;

	kref_get(&new_task->context->kref);
	memcpy(new_task->task_key, old_task->task_key, HASH_MAX_DIGESTSIZE);
	return 0;
}

static void tsem_task_free(struct task_struct *task)
{
	struct tsem_context *ctx = tsem_context(task);

	if (!ctx->id)
		return;
	tsem_ns_put(ctx);
}

static int tsem_task_kill(struct task_struct *target,
			  struct kernel_siginfo *info, int sig,
			  const struct cred *cred)
{
	bool cross_model;
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;
	struct tsem_context *src_ctx = tsem_context(current);
	struct tsem_context *tgt_ctx = tsem_context(target);

	if (tsem_task_untrusted(current)) {
		snprintf(msg, sizeof(msg),
			 "target=%s, pid=%d, signal=%d", target->comm,
			 task_pid_nr(target), sig);
		return trapped_task(TSEM_TASK_KILL, msg, true);
	}

	cross_model = src_ctx->id != tgt_ctx->id;

	if (info != SEND_SIG_NOINFO && SI_FROMKERNEL(info))
		return 0;
	if (sig == SIGURG)
		return 0;
	if (!capable(TSEM_CONTROL_CAPABILITY) &&
	    has_capability_noaudit(target, TSEM_CONTROL_CAPABILITY))
		return -EPERM;
	if (!capable(TSEM_CONTROL_CAPABILITY) && cross_model)
		return -EPERM;

	ep = tsem_event_allocate(TSEM_TASK_KILL, LOCKED);
	if (!ep)
		return -ENOMEM;

	ep->CELL.task_kill.signal = sig;
	ep->CELL.task_kill.cross_model = cross_model;
	memcpy(ep->CELL.task_kill.target, tsem_task(target)->task_id,
	       tsem_digestsize());

	return dispatch_event(ep);
}

static int tsem_ptrace_traceme(struct task_struct *parent)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "parent=%s", parent->comm);
		return trapped_task(TSEM_PTRACE_TRACEME, msg, LOCKED);
	}

	ep = tsem_event_allocate(TSEM_PTRACE_TRACEME, LOCKED);
	if (!ep)
		return -ENOMEM;

	memcpy(ep->CELL.task_kill.source, tsem_task(parent)->task_id,
	       tsem_digestsize());

	return dispatch_event(ep);
}

static int tsem_task_setpgid(struct task_struct *p, pid_t pgid)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;
	struct task_struct *src;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg),
			  "Untrusted %s: comm=%s, pid=%d, parameters='%s'\n",
			  tsem_names[TSEM_TASK_SETPGID], current->comm,
			  task_pid_nr(current), msg);
		return trapped_task(TSEM_TASK_SETPGID, msg, LOCKED);
	}

	ep = tsem_event_allocate(TSEM_TASK_SETPGID, LOCKED);
	if (!ep)
		return -ENOMEM;

	memcpy(ep->CELL.task_kill.target, tsem_task(p)->task_id,
	       tsem_digestsize());

	if (!pgid)
		memcpy(ep->CELL.task_kill.source, tsem_task(p)->task_id,
		       tsem_digestsize());
	else {
		rcu_read_lock();
		src = find_task_by_vpid(pgid);
		rcu_read_unlock();
		if (src)
			memcpy(ep->CELL.task_kill.source,
			       tsem_task(src)->task_id, tsem_digestsize());
	}

	return dispatch_event(ep);
}

static int tsem_task_getpgid(struct task_struct *p)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "target=%s", p->comm);
		return trapped_task(TSEM_TASK_GETPGID, msg, LOCKED);
	}

	ep = tsem_event_allocate(TSEM_TASK_GETPGID, LOCKED);
	if (!ep)
		return -ENOMEM;

	memcpy(ep->CELL.task_kill.target, tsem_task(p)->task_id,
	       tsem_digestsize());

	return dispatch_event(ep);
}

static int tsem_task_getsid(struct task_struct *p)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "target=%s", p->comm);
		return trapped_task(TSEM_TASK_GETSID, msg, LOCKED);
	}

	ep = tsem_event_allocate(TSEM_TASK_GETSID, LOCKED);
	if (!ep)
		return -ENOMEM;

	memcpy(ep->CELL.task_kill.target, tsem_task(p)->task_id,
	       tsem_digestsize());

	return dispatch_event(ep);
}

static int tsem_task_setnice(struct task_struct *p, int nice)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "target=%s, nice=%d",
			  p->comm, nice);
		return trapped_task(TSEM_TASK_SETNICE, msg, LOCKED);
	}

	ep = tsem_event_allocate(TSEM_TASK_SETNICE, LOCKED);
	if (!ep)
		return -ENOMEM;

	ep->CELL.task_kill.u.value = nice;
	memcpy(ep->CELL.task_kill.target, tsem_task(p)->task_id,
	       tsem_digestsize());

	return dispatch_event(ep);
}

static int tsem_task_setioprio(struct task_struct *p, int ioprio)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "target=%s, ioprio=%d",
			  p->comm, ioprio);
		return trapped_task(TSEM_TASK_SETIOPRIO, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_TASK_SETIOPRIO, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.task_kill.u.value = ioprio;
	memcpy(ep->CELL.task_kill.target, tsem_task(p)->task_id,
	       tsem_digestsize());

	return dispatch_event(ep);
}

static int tsem_task_getioprio(struct task_struct *p)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "target=%s", p->comm);
		return trapped_task(TSEM_TASK_GETIOPRIO, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_TASK_GETIOPRIO, NOLOCK);
	if (!ep)
		return -ENOMEM;

	memcpy(ep->CELL.task_kill.target, tsem_task(p)->task_id,
	       tsem_digestsize());

	return dispatch_event(ep);
}

static int tsem_task_prlimit(const struct cred *cred, const struct cred *tcred,
			     unsigned int flags)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg),
			  "uid=%d, gid=%d, euid=%d, egid=%d, flags=%u",
			  from_kuid(&init_user_ns, tcred->uid),
			  from_kgid(&init_user_ns, tcred->gid),
			  from_kuid(&init_user_ns, tcred->euid),
			  from_kgid(&init_user_ns, tcred->egid), flags);
		return trapped_task(TSEM_TASK_PRLIMIT, msg, LOCKED);
	}

	ep = tsem_event_allocate(TSEM_TASK_PRLIMIT, LOCKED);
	if (!ep)
		return -ENOMEM;

	ep->CELL.task_prlimit.flags = flags;
	ep->CELL.task_prlimit.in.cred = cred;
	ep->CELL.task_prlimit.in.tcred = tcred;

	return dispatch_event(ep);
}

static int tsem_task_setrlimit(struct task_struct *p, unsigned int resource,
			       struct rlimit *new_rlim)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg),
			  "target=%s, res=%u, cur=%lu, max=%lu",
			  p->comm, resource, new_rlim->rlim_cur,
			  new_rlim->rlim_max);
		return trapped_task(TSEM_TASK_SETRLIMIT, msg, LOCKED);
	}

	ep = tsem_event_allocate(TSEM_TASK_SETRLIMIT, LOCKED);
	if (!ep)
		return -ENOMEM;

	ep->CELL.task_kill.u.resource = resource;
	ep->CELL.task_kill.cur = new_rlim->rlim_cur;
	ep->CELL.task_kill.max = new_rlim->rlim_max;
	memcpy(ep->CELL.task_kill.target, tsem_task(p)->task_id,
	       tsem_digestsize());

	return dispatch_event(ep);
}

static int tsem_task_setscheduler(struct task_struct *p)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "target=%s", p->comm);
		return trapped_task(TSEM_TASK_SETSCHEDULER, msg,
					   LOCKED);
	}

	ep = tsem_event_allocate(TSEM_TASK_SETSCHEDULER, LOCKED);
	if (!ep)
		return -ENOMEM;

	memcpy(ep->CELL.task_kill.target, tsem_task(p)->task_id,
	       tsem_digestsize());

	return dispatch_event(ep);
}

static int tsem_task_getscheduler(struct task_struct *p)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "target=%s", p->comm);
		return trapped_task(TSEM_TASK_GETSCHEDULER, msg,
					   LOCKED);
	}

	ep = tsem_event_allocate(TSEM_TASK_GETSCHEDULER, LOCKED);
	if (!ep)
		return -ENOMEM;

	memcpy(ep->CELL.task_kill.target, tsem_task(p)->task_id,
	       tsem_digestsize());

	return dispatch_event(ep);
}

static int tsem_task_prctl(int option, unsigned long arg2, unsigned long arg3,
			   unsigned long arg4, unsigned long arg5)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "option=%d", option);
		return trapped_task(TSEM_TASK_PRCTL, msg, LOCKED);
	}

	ep = tsem_event_allocate(TSEM_TASK_PRCTL, LOCKED);
	if (!ep)
		return -ENOMEM;

	ep->CELL.task_prctl.option = option;
	ep->CELL.task_prctl.arg2 = arg2;
	ep->CELL.task_prctl.arg3 = arg3;
	ep->CELL.task_prctl.arg4 = arg4;
	ep->CELL.task_prctl.arg5 = arg5;

	return dispatch_event(ep);
}

static void tsem_bprm_committing_creds(const struct linux_binprm *bprm)
{
	u8 task_id[HASH_MAX_DIGESTSIZE];

	if (unlikely(!tsem_ready))
		return;

	if (tsem_map_task(bprm->file, task_id))
		memset(task_id, 0xff, sizeof(task_id));

	tsem_task(current)->instance = atomic64_inc_return(&task_instance);
	memcpy(tsem_task(current)->task_id, task_id, tsem_digestsize());
}

static int tsem_inode_alloc_security(struct inode *inode)
{
	struct tsem_inode *tsip = tsem_inode(inode);

	mutex_init(&tsip->mutex);
	INIT_LIST_HEAD(&tsip->digest_list);

	return 0;
}

static void tsem_inode_free_security(struct inode *inode)
{
	struct tsem_inode_digest *digest, *tmp_digest;

	if (bypass_filesystem(inode))
		return;

	list_for_each_entry_safe(digest, tmp_digest,
				 &tsem_inode(inode)->digest_list, list) {
		list_del(&digest->list);
		kfree(digest->name);
		kfree(digest);
	}
}

static int tsem_unix_stream_connect(struct sock *sock, struct sock *other,
				    struct sock *newsk)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "family=%u/%u, ",
			  sock->sk_family, other->sk_family);
		return trapped_task(TSEM_UNIX_STREAM_CONNECT, msg, LOCKED);
	}

	ep = tsem_event_allocate(TSEM_UNIX_STREAM_CONNECT, LOCKED);
	if (!ep)
		return -ENOMEM;

	ep->CELL.socket.in.socka = sock;
	ep->CELL.socket.in.sockb = other;

	return dispatch_event(ep);
}

static int tsem_unix_may_send(struct socket *sock, struct socket *other)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct sock *sk = sock->sk;
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "family=%u, type=%u",
			  sk->sk_family, sock->type);
		return trapped_task(TSEM_UNIX_MAY_SEND, msg, LOCKED);
	}

	ep = tsem_event_allocate(TSEM_UNIX_MAY_SEND, LOCKED);
	if (!ep)
		return -ENOMEM;

	ep->CELL.socket.in.socka = sock->sk;
	ep->CELL.socket.in.sockb = other->sk;

	return dispatch_event(ep);
}

static int tsem_socket_post_create(struct socket *sock, int family, int type,
				   int protocol, int kern)
{
	struct tsem_inode *tsip = tsem_inode(SOCK_INODE(sock));

	if (unlikely(!tsem_ready))
		return 0;

	memcpy(tsip->owner, tsem_task(current)->task_id, tsem_digestsize());
	return 0;
}

static int tsem_socket_create(int family, int type, int protocol, int kern)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (unlikely(!tsem_ready))
		return 0;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg),
			  "family=%d, type=%d, protocol=%d, kern=%d", family,
			  type, protocol, kern);
		return trapped_task(TSEM_SOCKET_CREATE, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_SOCKET_CREATE, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.socket_create.family = family;
	ep->CELL.socket_create.type = type;
	ep->CELL.socket_create.protocol = protocol;
	ep->CELL.socket_create.kern = kern;

	return dispatch_event(ep);
}

static int tsem_socket_connect(struct socket *sock, struct sockaddr *addr,
			     int addr_len)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "family=%u", addr->sa_family);
		return trapped_task(TSEM_SOCKET_CONNECT, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_SOCKET_CONNECT, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.socket_connect.tsip = tsem_inode(SOCK_INODE(sock));
	ep->CELL.socket_connect.addr = addr;
	ep->CELL.socket_connect.addr_len = addr_len;

	return dispatch_event(ep);
}

static int tsem_socket_bind(struct socket *sock, struct sockaddr *addr,
			    int addr_len)

{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "family=%u", addr->sa_family);
		return trapped_task(TSEM_SOCKET_BIND, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_SOCKET_BIND, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.socket_connect.tsip = tsem_inode(SOCK_INODE(sock));
	ep->CELL.socket_connect.addr = addr;
	ep->CELL.socket_connect.addr_len = addr_len;

	return dispatch_event(ep);
}

static int tsem_socket_accept(struct socket *sock, struct socket *newsock)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct sock *sk = sock->sk;
	const struct in6_addr *ipv6;
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "family=%u", sk->sk_family);
		return trapped_task(TSEM_SOCKET_ACCEPT, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_SOCKET_ACCEPT, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.socket_accept.family = sk->sk_family;
	ep->CELL.socket_accept.type = sock->type;
	ep->CELL.socket_accept.port = sk->sk_num;
	ep->CELL.socket_accept.u.ipv4 = sk->sk_rcv_saddr;
	if (sk->sk_family == AF_UNIX)
		ep->CELL.socket_accept.u.af_unix = unix_sk(sk);
	ipv6 = inet6_rcv_saddr(sk);
	if (ipv6)
		ep->CELL.socket_accept.u.ipv6 = *ipv6;

	return dispatch_event(ep);
}

static int tsem_socket_listen(struct socket *sock, int backlog)

{
	char msg[TRAPPED_MSG_LENGTH];
	struct sock *sk = sock->sk;
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "family=%u, type=%u, port=%u",
			  sk->sk_family, sock->type, sk->sk_num);
		return trapped_task(TSEM_SOCKET_LISTEN, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_SOCKET_LISTEN, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.socket.value = backlog;
	ep->CELL.socket.in.socka = sk;

	return dispatch_event(ep);
}

static int tsem_socket_socketpair(struct socket *socka, struct socket *sockb)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct sock *ska = socka->sk, *skb = sockb->sk;
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "family a=%u, family b=%u",
			  ska->sk_family, skb->sk_family);
		return trapped_task(TSEM_SOCKET_SOCKETPAIR, msg,
					   NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_SOCKET_SOCKETPAIR, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.socket.in.socka = ska;
	ep->CELL.socket.in.sockb = skb;

	return dispatch_event(ep);
}

static int tsem_socket_sendmsg(struct socket *sock, struct msghdr *msgmsg,
			       int size)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct sock *sk = sock->sk;
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "family=%u, size=%d",
			  sk->sk_family, size);
		return trapped_task(TSEM_SOCKET_SENDMSG, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_SOCKET_SENDMSG, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.socket.in.socka = sk;
	ep->CELL.socket.in.addr = msgmsg->msg_name;

	return dispatch_event(ep);
}

static int tsem_socket_recvmsg(struct socket *sock, struct msghdr *msgmsg,
			       int size, int flags)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct sock *sk = sock->sk;
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "family=%u, size=%d, flags=%d",
			  sk->sk_family, size, flags);
		return trapped_task(TSEM_SOCKET_RECVMSG, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_SOCKET_RECVMSG, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.socket.in.socka = sk;
	if (msgmsg->msg_name && msgmsg->msg_namelen > 0)
		ep->CELL.socket.in.addr = msgmsg->msg_name;

	return dispatch_event(ep);
}

static int tsem_socket_getsockname(struct socket *sock)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct sock *sk = sock->sk;
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "family=%u", sk->sk_family);
		return trapped_task(TSEM_SOCKET_GETSOCKNAME, msg,
					   NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_SOCKET_GETSOCKNAME, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.socket.in.socka = sk;

	return dispatch_event(ep);
}

static int tsem_socket_getpeername(struct socket *sock)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct sock *sk = sock->sk;
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "family=%u", sk->sk_family);
		return trapped_task(TSEM_SOCKET_GETPEERNAME, msg,
					   NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_SOCKET_GETPEERNAME, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.socket.in.socka = sk;

	return dispatch_event(ep);
}

static int tsem_socket_setsockopt(struct socket *sock, int level, int optname)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct sock *sk = sock->sk;
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "family=%u, level=%d, optname=%d",
			  sk->sk_family, level, optname);
		return trapped_task(TSEM_SOCKET_SETSOCKOPT, msg,
					   NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_SOCKET_SETSOCKOPT, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.socket.value = level;
	ep->CELL.socket.optname = optname;
	ep->CELL.socket.in.socka = sk;

	return dispatch_event(ep);
}

static int tsem_socket_shutdown(struct socket *sock, int how)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct sock *sk = sock->sk;
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "family=%u, how=%d",
			  sk->sk_family, how);
		return trapped_task(TSEM_SOCKET_SHUTDOWN, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_SOCKET_SHUTDOWN, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.socket.value = how;
	ep->CELL.socket.in.socka = sk;

	return dispatch_event(ep);
}

static int tsem_kernel_module_request(char *kmod_name)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (unlikely(!tsem_ready))
		return 0;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "module=%s", kmod_name);
		return trapped_task(TSEM_KERNEL_MODULE_REQUEST, msg,
					   NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_KERNEL_MODULE_REQUEST, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.kernel.in.kmod_name = kmod_name;

	return dispatch_event(ep);
}

static int tsem_kernel_load_data(enum kernel_load_data_id id, bool contents)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "id=%d, contents=%d", id,
			  contents);
		return trapped_task(TSEM_KERNEL_LOAD_DATA, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_KERNEL_LOAD_DATA, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.kernel.id = id;
	ep->CELL.kernel.contents = contents;

	return dispatch_event(ep);
}


static int tsem_kernel_read_file(struct file *file,
				 enum kernel_read_file_id id, bool contents)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg),
			  "filename=%s, flags=0x%x, id=%d, contents=%d",
			  file->f_path.dentry->d_name.name, file->f_flags,
			  id, contents);
		return trapped_task(TSEM_KERNEL_READ_FILE, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_KERNEL_READ_FILE, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.kernel.id = id;
	ep->CELL.kernel.contents = contents;
	ep->CELL.kernel.in.file = file;

	return dispatch_event(ep);
}

static int tsem_sb_mount(const char *dev_name, const struct path *path,
			 const char *type, unsigned long flags, void *data)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (unlikely(!tsem_ready))
		return 0;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "device=%s, type=%s, flags=%lu",
			  dev_name, type, flags);
		return trapped_task(TSEM_SB_MOUNT, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_SB_MOUNT, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.sb.flags = flags;
	ep->CELL.sb.in.dev_name = dev_name;
	ep->CELL.sb.in.path = path;
	ep->CELL.sb.in.type = type;

	return dispatch_event(ep);
}

static	int tsem_sb_umount(struct vfsmount *mnt, int flags)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "root=%s, flags=%d",
			  mnt->mnt_root->d_name.name, flags);
		return trapped_task(TSEM_SB_UMOUNT, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_SB_UMOUNT, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.sb.flags = flags;
	ep->CELL.sb.in.dentry = mnt->mnt_root;

	return dispatch_event(ep);
}

static int tsem_sb_remount(struct super_block *sb, void *mnt_opts)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (unlikely(!tsem_ready))
		return 0;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "fstype=%s, type=%s",
			  sb->s_type->name, sb->s_root->d_name.name);
		return trapped_task(TSEM_SB_REMOUNT, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_SB_REMOUNT, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.sb.in.sb = sb;

	return dispatch_event(ep);
}

static int tsem_sb_pivotroot(const struct path *old_path,
			     const struct path *new_path)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "%s -> %s",
			  old_path->dentry->d_name.name,
			  new_path->dentry->d_name.name);
		return trapped_task(TSEM_SB_PIVOTROOT, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_SB_PIVOTROOT, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.sb.in.path = old_path;
	ep->CELL.sb.in.path2 = new_path;

	return dispatch_event(ep);
}

static int tsem_sb_statfs(struct dentry *dentry)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "name=%s", dentry->d_name.name);
		return trapped_task(TSEM_SB_STATFS, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_SB_STATFS, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.sb.in.dentry = dentry;

	return dispatch_event(ep);
}

static int tsem_move_mount(const struct path *from_path,
			   const struct path *to_path)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "%s -> %s",
			  from_path->dentry->d_name.name,
			  to_path->dentry->d_name.name);
		return trapped_task(TSEM_MOVE_MOUNT, msg, NOLOCK);
	}


	ep = tsem_event_allocate(TSEM_MOVE_MOUNT, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.sb.in.path = from_path;
	ep->CELL.sb.in.path2 = to_path;

	return dispatch_event(ep);
}

static int tsem_shm_associate(struct kern_ipc_perm *perm, int shmflg)
{
	char msg[TRAPPED_MSG_LENGTH];

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "id=%d, mode=%u, flags=%d",
			  perm->id, perm->mode, shmflg);
		return trapped_task(TSEM_SHM_ASSOCIATE, msg, LOCKED);
	}

	return dispatch_generic_event(TSEM_SHM_ASSOCIATE, LOCKED);
}

static int tsem_shm_shmctl(struct kern_ipc_perm *perm, int cmd)
{
	char msg[TRAPPED_MSG_LENGTH];

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "id=%d, mode=%u, cmd=%d",
			  perm->id, perm->mode, cmd);
		return trapped_task(TSEM_SHM_SHMCTL, msg, LOCKED);
	}

	return dispatch_generic_event(TSEM_SHM_SHMCTL, LOCKED);
}

static int tsem_shm_shmat(struct kern_ipc_perm *perm, char __user *shmaddr,
			  int shmflg)
{
	char msg[TRAPPED_MSG_LENGTH];

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "id=%d, mode=%u, flag=%d",
			  perm->id, perm->mode, shmflg);
		return trapped_task(TSEM_SHM_SHMAT, msg, LOCKED);
	}

	return dispatch_generic_event(TSEM_SHM_SHMAT, LOCKED);
}

static int tsem_sem_associate(struct kern_ipc_perm *perm, int semflg)
{
	char msg[TRAPPED_MSG_LENGTH];

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "id=%d, mode=%u, flag=%d",
			  perm->id, perm->mode, semflg);
		return trapped_task(TSEM_SEM_ASSOCIATE, msg, LOCKED);
	}

	return dispatch_generic_event(TSEM_SEM_ASSOCIATE, LOCKED);
}

static int tsem_sem_semctl(struct kern_ipc_perm *perm, int cmd)
{
	char msg[TRAPPED_MSG_LENGTH];

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "id=%d, mode=%u, cmd=%d",
			  perm->id, perm->mode, cmd);
		return trapped_task(TSEM_SEM_SEMCTL, msg, LOCKED);
	}

	return dispatch_generic_event(TSEM_SEM_SEMCTL, LOCKED);
}

static int tsem_sem_semop(struct kern_ipc_perm *perm, struct sembuf *sops,
			  unsigned int nsops, int alter)
{
	char msg[TRAPPED_MSG_LENGTH];

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg),
			  "id=%d, mode=%u, nsops=%u, alter=%d", perm->id,
			  perm->mode, nsops, alter);
		return trapped_task(TSEM_SEM_SEMOP, msg, LOCKED);
	}

	return dispatch_generic_event(TSEM_SEM_SEMOP, LOCKED);
}

static int tsem_syslog(int type)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "type=%d", type);
		return trapped_task(TSEM_SYSLOG, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_SYSLOG, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.value = type;

	return dispatch_event(ep);
}

static int tsem_settime(const struct timespec64 *ts, const struct timezone *tz)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg),
			  "secs=%lld, nsecs=%ld, mwest=%d, dsttime=%d",
			  ts->tv_sec, ts->tv_nsec, tz->tz_minuteswest,
			  tz->tz_dsttime);
		return trapped_task(TSEM_SETTIME, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_SETTIME, NOLOCK);
	if (!ep)
		return -ENOMEM;

	if (ts) {
		ep->CELL.time.seconds = ts->tv_sec;
		ep->CELL.time.nsecs = ts->tv_nsec;
	}
	if (tz) {
		ep->CELL.time.minuteswest = tz->tz_minuteswest;
		ep->CELL.time.dsttime = tz->tz_dsttime;
	}

	return dispatch_event(ep);
}

static int tsem_quotactl(int cmds, int type, int id,
			 const struct super_block *sb)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg),
			  "cmds=%d, type=%d, id=%d, fstype=%s, type=%s", cmds,
			  type, id, sb->s_type->name, sb->s_root->d_name.name);
		return trapped_task(TSEM_QUOTACTL, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_QUOTACTL, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.quota.cmds = cmds;
	ep->CELL.quota.type = type;
	ep->CELL.quota.id = id;
	ep->CELL.quota.in.sb = sb;

	return dispatch_event(ep);
}

static int tsem_quota_on(struct dentry *dentry)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "name=%s", dentry->d_name.name);
		return trapped_task(TSEM_QUOTA_ON, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_QUOTA_ON, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.quota.in.dentry = dentry;

	return dispatch_event(ep);
}

static int tsem_msg_queue_associate(struct kern_ipc_perm *perm, int msqflg)
{
	char msg[TRAPPED_MSG_LENGTH];

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg),
			  "id=%d, mode=%u, msqflg=%d", perm->id, perm->mode,
			  msqflg);
		return trapped_task(TSEM_MSG_QUEUE_ASSOCIATE, msg,
					   LOCKED);
	}

	return dispatch_generic_event(TSEM_MSG_QUEUE_ASSOCIATE, LOCKED);
}

static int tsem_msg_queue_msgsnd(struct kern_ipc_perm *perm,
				 struct msg_msg *msgmsg, int msqflg)

{
	char msg[TRAPPED_MSG_LENGTH];

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg),
			  "id=%d, mode=%u, msqflg=%d", perm->id, perm->mode,
			  msqflg);
		return trapped_task(TSEM_MSG_QUEUE_MSGSND, msg, LOCKED);
	}

	return dispatch_generic_event(TSEM_MSG_QUEUE_MSGSND, LOCKED);
}

static int tsem_msg_queue_msgctl(struct kern_ipc_perm *perm, int cmd)
{
	char msg[TRAPPED_MSG_LENGTH];

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg),
			  "id=%d, mode=%u, cmd=%d", perm->id, perm->mode,
			  cmd);
		return trapped_task(TSEM_MSG_QUEUE_MSGCTL, msg, LOCKED);
	}

	return dispatch_generic_event(TSEM_MSG_QUEUE_MSGCTL, LOCKED);
}

static int tsem_msg_queue_msgrcv(struct kern_ipc_perm *perm,
				 struct msg_msg *msgmsg,
				 struct task_struct *target, long type,
				 int mode)
{
	char msg[TRAPPED_MSG_LENGTH];

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg),
			  "id=%d, mode=%u, target=%s, type=%ld, mode=%d",
			  perm->id, perm->mode, target->comm, type, mode);
		return trapped_task(TSEM_MSG_QUEUE_MSGRCV, msg, LOCKED);
	}

	return dispatch_generic_event(TSEM_MSG_QUEUE_MSGRCV, LOCKED);
}

static int tsem_ipc_alloc(struct kern_ipc_perm *kipc)
{
	struct tsem_ipc *tipc = tsem_ipc(kipc);

	memcpy(tipc->owner, tsem_task(current)->task_id, tsem_digestsize());
	return 0;
}

static int tsem_ipc_permission(struct kern_ipc_perm *ipcp, short flag)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg),
			  "uid=%d, gid=%d, mode=%u, flag=%u",
			  from_kuid(&init_user_ns, ipcp->uid),
			  from_kgid(&init_user_ns, ipcp->gid), ipcp->mode,
			  flag);
		return trapped_task(TSEM_IPC_PERMISSION, msg, LOCKED);
	}

	ep = tsem_event_allocate(TSEM_IPC_PERMISSION, LOCKED);
	if (!ep)
		return -ENOMEM;

	ep->CELL.ipc.perm_flag = flag;
	ep->CELL.ipc.in.perm = ipcp;

	return dispatch_event(ep);
}

#ifdef CONFIG_KEYS
static int tsem_key_alloc(struct key *key, const struct cred *cred,
			  unsigned long flags)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (unlikely(!tsem_ready))
		return 0;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg),
			  "uid=%d, gid=%d, euid=%d, egid=%d, flags=%lu",
			  from_kuid(&init_user_ns, cred->uid),
			  from_kgid(&init_user_ns, cred->gid),
			  from_kuid(&init_user_ns, cred->euid),
			  from_kgid(&init_user_ns, cred->egid), flags);
		return trapped_task(TSEM_KEY_ALLOC, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_KEY_ALLOC, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.key.flags = flags;
	ep->CELL.key.in.cred = cred;

	return dispatch_event(ep);
}

static int tsem_key_permission(key_ref_t key_ref, const struct cred *cred,
			       unsigned int perm)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (unlikely(!tsem_ready))
		return 0;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg),
			  "uid=%d, gid=%d, euid=%d, egid=%d, perm=%u",
			  from_kuid(&init_user_ns, cred->uid),
			  from_kgid(&init_user_ns, cred->gid),
			  from_kuid(&init_user_ns, cred->euid),
			  from_kgid(&init_user_ns, cred->egid), perm);
		return trapped_task(TSEM_KEY_PERMISSION, msg, LOCKED);
	}

	ep = tsem_event_allocate(TSEM_KEY_PERMISSION, LOCKED);
	if (!ep)
		return -ENOMEM;

	ep->CELL.key.flags = perm;
	ep->CELL.key.in.cred = cred;
	ep->CELL.key.in.ref = key_ref;

	return dispatch_event(ep);
}
#endif

static int tsem_netlink_send(struct sock *sk, struct sk_buff *skb)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct scm_creds *cred;
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		cred = NETLINK_CREDS(skb);
		scnprintf(msg, sizeof(msg),
			  "uid=%d, gid=%d",
			  from_kuid(&init_user_ns, cred->uid),
			  from_kgid(&init_user_ns, cred->gid));
		return trapped_task(TSEM_NETLINK_SEND, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_NETLINK_SEND, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.netlink.in.sock = sk;
	ep->CELL.netlink.in.parms = (struct netlink_skb_parms *) skb->cb;

	return dispatch_event(ep);
}

static int tsem_inode_create(struct inode *dir, struct dentry *dentry,
			     umode_t mode)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (unlikely(!tsem_ready))
		return 0;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "name=%s, mode=%u",
			  dentry->d_name.name, mode);
		return trapped_inode(TSEM_INODE_CREATE, dir, msg, NOLOCK);
	}

	if (bypass_filesystem(dir))
		return 0;

	ep = tsem_event_allocate(TSEM_INODE_CREATE, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.inode.in.dir = dir;
	ep->CELL.inode.in.dentry = dentry;
	ep->CELL.inode.mode = mode;

	return dispatch_event(ep);
}

static int tsem_inode_link(struct dentry *old_dentry, struct inode *dir,
			   struct dentry *new_dentry)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (unlikely(!tsem_ready))
		return 0;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "old_name=%s, new_name=%s",
			  old_dentry->d_name.name, new_dentry->d_name.name);
		return trapped_task(TSEM_INODE_LINK, msg, NOLOCK);
	}

	if (bypass_filesystem(dir))
		return 0;

	ep = tsem_event_allocate(TSEM_INODE_LINK, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.inode.in.dir = dir;
	ep->CELL.inode.in.dentry = old_dentry;
	ep->CELL.inode.in.new_dentry = new_dentry;
	ep->CELL.inode.mode = 0;

	return dispatch_event(ep);
}

static int tsem_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "target=%s", dentry->d_name.name);
		return trapped_inode(TSEM_INODE_UNLINK, dir, msg, NOLOCK);
	}

	if (bypass_filesystem(dir))
		return 0;

	ep = tsem_event_allocate(TSEM_INODE_UNLINK, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.inode.in.dir = dir;
	ep->CELL.inode.in.dentry = dentry;
	ep->CELL.inode.mode = 0;

	return dispatch_event(ep);
}

static int tsem_inode_symlink(struct inode *dir, struct dentry *dentry,
			      const char *old_name)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (unlikely(!tsem_ready))
		return 0;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "target=%s", dentry->d_name.name);
		return trapped_task(TSEM_INODE_SYMLINK, msg, NOLOCK);
	}

	if (bypass_filesystem(dir))
		return 0;

	ep = tsem_event_allocate(TSEM_INODE_SYMLINK, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.inode.in.dir = dir;
	ep->CELL.inode.in.dentry = dentry;
	ep->CELL.inode.in.old_name = old_name;

	return dispatch_event(ep);
}

static int tsem_inode_mkdir(struct inode *dir, struct dentry *dentry,
			    umode_t mode)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (unlikely(!tsem_ready))
		return 0;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "target=%s, mode=%u",
			  dentry->d_name.name, mode);
		return trapped_task(TSEM_INODE_MKDIR, msg, NOLOCK);
	}

	if (bypass_filesystem(dir))
		return 0;

	ep = tsem_event_allocate(TSEM_INODE_MKDIR, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.inode.in.dir = dir;
	ep->CELL.inode.in.dentry = dentry;
	ep->CELL.inode.mode = mode;

	return dispatch_event(ep);
}

static int tsem_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "name=%s", dentry->d_name.name);
		return trapped_task(TSEM_INODE_RMDIR, msg, NOLOCK);
	}

	if (bypass_filesystem(dir))
		return 0;

	ep = tsem_event_allocate(TSEM_INODE_RMDIR, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.inode.in.dir = dir;
	ep->CELL.inode.in.dentry = dentry;
	ep->CELL.inode.mode = 0;

	return dispatch_event(ep);
}

static int tsem_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
			     struct inode *new_dir, struct dentry *new_dentry)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "old=%s, new=%s",
			  old_dentry->d_name.name, new_dentry->d_name.name);
		return trapped_task(TSEM_INODE_RENAME, msg, NOLOCK);
	}

	if (bypass_filesystem(old_dir))
		return 0;

	ep = tsem_event_allocate(TSEM_INODE_RENAME, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.inode_rename.in.old_dir = old_dir;
	ep->CELL.inode_rename.in.new_dir = new_dir;
	ep->CELL.inode_rename.in.old_dentry = old_dentry;
	ep->CELL.inode_rename.in.new_dentry = new_dentry;

	return dispatch_event(ep);
}

static int tsem_inode_mknod(struct inode *dir, struct dentry *dentry,
			    umode_t mode, dev_t dev)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (unlikely(!tsem_ready))
		return 0;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "name=%s, mode=%u, dev=%u",
			  dentry->d_name.name, mode, dev);
		return trapped_task(TSEM_INODE_MKNOD, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_INODE_MKNOD, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.inode.in.dir = dir;
	ep->CELL.inode.in.dentry = dentry;
	ep->CELL.inode.mode = mode;
	ep->CELL.inode.dev = dev;

	return dispatch_event(ep);
}

static int tsem_inode_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
			      struct iattr *attr)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (unlikely(!tsem_ready))
		return 0;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg),
			  "name=%s, mode=%u, uid=%d, gid=%d, size=%llu",
			  dentry->d_name.name, attr->ia_mode,
			  from_kuid(&init_user_ns, attr->ia_uid),
			  from_kgid(&init_user_ns, attr->ia_gid),
			  attr->ia_size);
		return trapped_task(TSEM_INODE_SETATTR, msg, NOLOCK);
	}

	if (bypass_filesystem(dentry->d_inode))
		return 0;

	ep = tsem_event_allocate(TSEM_INODE_SETATTR, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.inode_attr.in.dentry = dentry;
	ep->CELL.inode_attr.in.iattr = attr;

	return dispatch_event(ep);
}

static int tsem_inode_getattr(const struct path *path)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (unlikely(!tsem_ready))
		return 0;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "name=%s",
			  path->dentry->d_name.name);
		return trapped_task(TSEM_INODE_GETATTR, msg, NOLOCK);
	}

	if (bypass_filesystem(path->dentry->d_inode))
		return 0;

	ep = tsem_event_allocate(TSEM_INODE_GETATTR, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.inode_attr.in.path = path;

	return dispatch_event(ep);
}

static int tsem_inode_setxattr(struct mnt_idmap *idmap,
			       struct dentry *dentry, const char *name,
			       const void *value, size_t size, int flags)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg),
			  "fname=%s, name=%s, size=%lu, flags=%d",
			  dentry->d_name.name, name, size, flags);
		return trapped_task(TSEM_INODE_SETXATTR, msg, NOLOCK);
	}

	if (bypass_filesystem(dentry->d_inode))
		return 0;

	ep = tsem_event_allocate(TSEM_INODE_SETXATTR, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.inode_xattr.in.dentry = dentry;
	ep->CELL.inode_xattr.in.name = name;
	ep->CELL.inode_xattr.in.value = value;
	ep->CELL.inode_xattr.in.size = size;
	ep->CELL.inode_xattr.in.flags = flags;

	return dispatch_event(ep);
}

static int tsem_inode_getxattr(struct dentry *dentry, const char *name)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep = NULL;

	if (unlikely(!tsem_ready))
		return 0;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg),
			  "fname=%s, name=%s", dentry->d_name.name, name);
		return trapped_task(TSEM_INODE_GETXATTR, msg, NOLOCK);
	}

	if (bypass_filesystem(dentry->d_inode))
		return 0;

	ep = tsem_event_allocate(TSEM_INODE_GETXATTR, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.inode_xattr.in.dentry = dentry;
	ep->CELL.inode_xattr.in.name = name;

	return dispatch_event(ep);
}

static int tsem_inode_listxattr(struct dentry *dentry)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (unlikely(!tsem_ready))
		return 0;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "fname=%s", dentry->d_name.name);
		return trapped_task(TSEM_INODE_LISTXATTR, msg, NOLOCK);
	}

	if (bypass_filesystem(dentry->d_inode))
		return 0;

	ep = tsem_event_allocate(TSEM_INODE_LISTXATTR, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.inode_xattr.in.dentry = dentry;

	return dispatch_event(ep);
}

static int tsem_inode_removexattr(struct mnt_idmap *idmap,
				  struct dentry *dentry, const char *name)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "fname=%s, name=%s",
			  dentry->d_name.name, name);
		return trapped_task(TSEM_INODE_REMOVEXATTR, msg, NOLOCK);
	}

	if (bypass_filesystem(dentry->d_inode))
		return 0;

	ep = tsem_event_allocate(TSEM_INODE_REMOVEXATTR, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.inode_xattr.in.dentry = dentry;
	ep->CELL.inode_xattr.in.name = name;

	return dispatch_event(ep);
}

static int tsem_inode_killpriv(struct mnt_idmap *idmap,
			       struct dentry *dentry)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "fname=%s", dentry->d_name.name);
		return trapped_task(TSEM_INODE_KILLPRIV, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_INODE_KILLPRIV, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.inode.in.dentry = dentry;

	return dispatch_event(ep);
}

static int tsem_tun_dev_create(void)
{
	struct tsem_event *ep;

	if (tsem_task_untrusted(current))
		return trapped_task(TSEM_TUN_DEV_CREATE, "none", NOLOCK);

	if (bypass_event())
		return 0;

	ep = tsem_event_allocate(TSEM_TUN_DEV_CREATE, NOLOCK);
	if (!ep)
		return -ENOMEM;
	ep->no_params = true;

	return dispatch_event(ep);
}

static int tsem_tun_dev_attach_queue(void *security)
{
	struct tsem_event *ep;

	if (tsem_task_untrusted(current))
		return trapped_task(TSEM_TUN_DEV_ATTACH_QUEUE, "none", NOLOCK);

	if (bypass_event())
		return 0;

	ep = tsem_event_allocate(TSEM_TUN_DEV_ATTACH_QUEUE, NOLOCK);
	if (!ep)
		return -ENOMEM;
	ep->no_params = true;

	return dispatch_event(ep);
}

static int tsem_tun_dev_attach(struct sock *sk, void *security)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "family=%u", sk->sk_family);
		return trapped_task(TSEM_TUN_DEV_ATTACH, msg, NOLOCK);
	}

	if (bypass_event())
		return 0;

	ep = tsem_event_allocate(TSEM_TUN_DEV_ATTACH, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.socket.in.socka = sk;

	return dispatch_event(ep);
}

static int tsem_tun_dev_open(void *security)
{
	struct tsem_event *ep;

	if (tsem_task_untrusted(current))
		return trapped_task(TSEM_TUN_DEV_OPEN, "none", NOLOCK);

	if (bypass_event())
		return 0;

	ep = tsem_event_allocate(TSEM_TUN_DEV_OPEN, NOLOCK);
	if (!ep)
		return -ENOMEM;
	ep->no_params = true;

	return dispatch_event(ep);
}

#ifdef CONFIG_BPF_SYSCALL
static int tsem_bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "cmd=%d, size=%u", cmd, size);
		return trapped_task(TSEM_BPF, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_BPF, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.bpf.bpf.cmd = cmd;
	ep->CELL.bpf.bpf.size = size;

	return dispatch_event(ep);
}

static int tsem_bpf_map(struct bpf_map *map, fmode_t fmode)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "type=%d, size=%u", map->map_type,
			  fmode);
		return trapped_task(TSEM_BPF_MAP, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_BPF_MAP, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.bpf.map.fmode = fmode;
	ep->CELL.bpf.map.map_type = map->map_type;

	return dispatch_event(ep);
}

static int tsem_bpf_prog(struct bpf_prog *prog)
{
	char msg[TRAPPED_MSG_LENGTH];
	struct tsem_event *ep;

	if (tsem_task_untrusted(current)) {
		scnprintf(msg, sizeof(msg), "type=%d", prog->type);
		return trapped_task(TSEM_BPF_PROG, msg, NOLOCK);
	}

	ep = tsem_event_allocate(TSEM_BPF_PROG, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.bpf.prog.type = prog->type;
	ep->CELL.bpf.prog.attach_type = prog->expected_attach_type;

	return dispatch_event(ep);
}
#endif

static struct security_hook_list tsem_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(task_alloc, tsem_task_alloc),
	LSM_HOOK_INIT(task_free, tsem_task_free),
	LSM_HOOK_INIT(task_kill, tsem_task_kill),
	LSM_HOOK_INIT(task_setpgid, tsem_task_setpgid),
	LSM_HOOK_INIT(task_getpgid, tsem_task_getpgid),
	LSM_HOOK_INIT(task_getsid, tsem_task_getsid),
	LSM_HOOK_INIT(task_setnice, tsem_task_setnice),
	LSM_HOOK_INIT(task_setioprio, tsem_task_setioprio),
	LSM_HOOK_INIT(task_getioprio, tsem_task_getioprio),
	LSM_HOOK_INIT(task_prlimit, tsem_task_prlimit),
	LSM_HOOK_INIT(task_setrlimit, tsem_task_setrlimit),
	LSM_HOOK_INIT(task_setscheduler, tsem_task_setscheduler),
	LSM_HOOK_INIT(task_getscheduler, tsem_task_getscheduler),
	LSM_HOOK_INIT(task_prctl, tsem_task_prctl),

	LSM_HOOK_INIT(ptrace_traceme, tsem_ptrace_traceme),
	LSM_HOOK_INIT(bprm_committing_creds, tsem_bprm_committing_creds),
	LSM_HOOK_INIT(inode_alloc_security, tsem_inode_alloc_security),
	LSM_HOOK_INIT(inode_free_security, tsem_inode_free_security),

	LSM_HOOK_INIT(file_open, tsem_file_open),
	LSM_HOOK_INIT(mmap_file, tsem_mmap_file),
	LSM_HOOK_INIT(file_ioctl, tsem_file_ioctl),
	LSM_HOOK_INIT(file_lock, tsem_file_lock),
	LSM_HOOK_INIT(file_fcntl, tsem_file_fcntl),
	LSM_HOOK_INIT(file_receive, tsem_file_receive),

	LSM_HOOK_INIT(unix_stream_connect, tsem_unix_stream_connect),
	LSM_HOOK_INIT(unix_may_send, tsem_unix_may_send),

	LSM_HOOK_INIT(socket_post_create, tsem_socket_post_create),
	LSM_HOOK_INIT(socket_create, tsem_socket_create),
	LSM_HOOK_INIT(socket_connect, tsem_socket_connect),
	LSM_HOOK_INIT(socket_bind, tsem_socket_bind),
	LSM_HOOK_INIT(socket_accept, tsem_socket_accept),
	LSM_HOOK_INIT(socket_listen, tsem_socket_listen),
	LSM_HOOK_INIT(socket_socketpair, tsem_socket_socketpair),
	LSM_HOOK_INIT(socket_sendmsg, tsem_socket_sendmsg),
	LSM_HOOK_INIT(socket_recvmsg, tsem_socket_recvmsg),
	LSM_HOOK_INIT(socket_getsockname, tsem_socket_getsockname),
	LSM_HOOK_INIT(socket_getpeername, tsem_socket_getpeername),
	LSM_HOOK_INIT(socket_setsockopt, tsem_socket_setsockopt),
	LSM_HOOK_INIT(socket_shutdown, tsem_socket_shutdown),

	LSM_HOOK_INIT(kernel_module_request, tsem_kernel_module_request),
	LSM_HOOK_INIT(kernel_load_data, tsem_kernel_load_data),
	LSM_HOOK_INIT(kernel_read_file, tsem_kernel_read_file),

	LSM_HOOK_INIT(sb_mount, tsem_sb_mount),
	LSM_HOOK_INIT(sb_umount, tsem_sb_umount),
	LSM_HOOK_INIT(sb_remount, tsem_sb_remount),
	LSM_HOOK_INIT(sb_pivotroot, tsem_sb_pivotroot),
	LSM_HOOK_INIT(sb_statfs, tsem_sb_statfs),
	LSM_HOOK_INIT(move_mount, tsem_move_mount),

	LSM_HOOK_INIT(shm_alloc_security, tsem_ipc_alloc),
	LSM_HOOK_INIT(shm_associate, tsem_shm_associate),
	LSM_HOOK_INIT(shm_shmctl, tsem_shm_shmctl),
	LSM_HOOK_INIT(shm_shmat, tsem_shm_shmat),

	LSM_HOOK_INIT(sem_alloc_security, tsem_ipc_alloc),
	LSM_HOOK_INIT(sem_associate, tsem_sem_associate),
	LSM_HOOK_INIT(sem_semctl, tsem_sem_semctl),
	LSM_HOOK_INIT(sem_semop, tsem_sem_semop),

	LSM_HOOK_INIT(syslog, tsem_syslog),
	LSM_HOOK_INIT(settime, tsem_settime),

	LSM_HOOK_INIT(quotactl, tsem_quotactl),
	LSM_HOOK_INIT(quota_on, tsem_quota_on),

	LSM_HOOK_INIT(msg_queue_alloc_security, tsem_ipc_alloc),
	LSM_HOOK_INIT(msg_queue_associate, tsem_msg_queue_associate),
	LSM_HOOK_INIT(msg_queue_msgctl, tsem_msg_queue_msgctl),
	LSM_HOOK_INIT(msg_queue_msgsnd, tsem_msg_queue_msgsnd),
	LSM_HOOK_INIT(msg_queue_msgrcv, tsem_msg_queue_msgrcv),

	LSM_HOOK_INIT(ipc_permission, tsem_ipc_permission),

#ifdef CONFIG_KEYS
	LSM_HOOK_INIT(key_alloc, tsem_key_alloc),
	LSM_HOOK_INIT(key_permission, tsem_key_permission),
#endif

	LSM_HOOK_INIT(netlink_send, tsem_netlink_send),

	LSM_HOOK_INIT(inode_create, tsem_inode_create),
	LSM_HOOK_INIT(inode_link, tsem_inode_link),
	LSM_HOOK_INIT(inode_unlink, tsem_inode_unlink),
	LSM_HOOK_INIT(inode_symlink, tsem_inode_symlink),
	LSM_HOOK_INIT(inode_mkdir, tsem_inode_mkdir),
	LSM_HOOK_INIT(inode_rmdir, tsem_inode_rmdir),
	LSM_HOOK_INIT(inode_mknod, tsem_inode_mknod),
	LSM_HOOK_INIT(inode_rename, tsem_inode_rename),
	LSM_HOOK_INIT(inode_setattr, tsem_inode_setattr),
	LSM_HOOK_INIT(inode_getattr, tsem_inode_getattr),
	LSM_HOOK_INIT(inode_setxattr, tsem_inode_setxattr),
	LSM_HOOK_INIT(inode_getxattr, tsem_inode_getxattr),
	LSM_HOOK_INIT(inode_listxattr, tsem_inode_listxattr),
	LSM_HOOK_INIT(inode_removexattr, tsem_inode_removexattr),
	LSM_HOOK_INIT(inode_killpriv, tsem_inode_killpriv),

	LSM_HOOK_INIT(tun_dev_create, tsem_tun_dev_create),
	LSM_HOOK_INIT(tun_dev_attach_queue, tsem_tun_dev_attach_queue),
	LSM_HOOK_INIT(tun_dev_attach, tsem_tun_dev_attach),
	LSM_HOOK_INIT(tun_dev_open, tsem_tun_dev_open),

#ifdef CONFIG_BPF_SYSCALL
	LSM_HOOK_INIT(bpf, tsem_bpf),
	LSM_HOOK_INIT(bpf_map, tsem_bpf_map),
	LSM_HOOK_INIT(bpf_prog, tsem_bpf_prog)
#endif
};

static int configure_root_digest(void)
{
	int retn = 0;
	char *digest = NULL;
	u8 zero_digest[HASH_MAX_DIGESTSIZE];
	unsigned int digestsize;
	struct crypto_shash *tfm;
	SHASH_DESC_ON_STACK(shash, tfm);

	if (default_hash_function && crypto_has_shash(default_hash_function,
						      0, 0)) {
		digest = default_hash_function;
		pr_warn("tsem: Using digest %s from command-line.\n", digest);
	}
	if (!digest && default_hash_function)
		pr_warn("tsem: Unknown root digest %s, using sha256.\n",
			default_hash_function);
	if (!digest)
		digest = "sha256";

	tsem_context(current)->digestname = kstrdup(digest, GFP_KERNEL);
	if (!tsem_context(current)->digestname)
		return -ENOMEM;

	tfm = crypto_alloc_shash(digest, 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	shash->tfm = tfm;
	retn = crypto_shash_digest(shash, NULL, 0, zero_digest);
	if (retn)
		goto done;

	tsem_context(current)->tfm = tfm;
	memcpy(root_context.zero_digest, zero_digest, digestsize);

 done:
	if (retn) {
		kfree(tsem_context(current)->digestname);
		crypto_free_shash(tfm);
	}

	return retn;
}

static int __init set_ready(void)
{
	int retn;

	if (!tsem_available)
		return 0;

	retn = configure_root_digest();
	if (retn)
		goto done;

	retn = tsem_model_add_aggregate();
	if (retn)
		goto done;

	retn = tsem_fs_init();
	if (retn)
		goto done;

	if (tsem_mode == EXPORT_ONLY) {
		retn = tsem_ns_export();
		if (retn)
			goto done;
	}

	pr_info("tsem: Now active.\n");
	tsem_ready = 1;

 done:
	return retn;
}

late_initcall(set_ready);

/**
 * tesm_init() - Register Trusted Security Event Modeling LSM.
 *
 * This function is responsible for initializing the TSEM LSM.  It is
 * invoked at the fs_initcall level.  In addition to configuring the
 * LSM hooks this function initializes the Trusted Modeling Agent
 * context including the event actions.  The cache from which
 * the tsem_event description structures is also initialized.
 *
 * Return: If the TSEM LSM is successfully initialized a value of zero
 *	   is returned.  A non-zero error code is returned if
 *	   initialization fails.  Currently the only failure mode can
 *	   come from the initialization of the tsem_event cache.
 */
static int __init tsem_init(void)
{
	int retn;
	char *msg;
	struct tsem_task *tsk = tsem_task(current);
	struct tsem_context *ctx = &root_context;
	struct tsem_model *model = &root_model;

	security_add_hooks(tsem_hooks, ARRAY_SIZE(tsem_hooks), &tsem_lsmid);

	tsk->context = ctx;
	kref_init(&ctx->kref);
	kref_get(&ctx->kref);

	root_context.model = &root_model;

	retn = tsem_event_cache_init();
	if (retn)
		return retn;

	retn = tsem_model_cache_init(model, magazine_size);
	if (retn)
		goto done;

	retn = tsem_export_cache_init();
	if (retn)
		goto done;

	retn = tsem_event_magazine_allocate(ctx, magazine_size);
	if (retn)
		goto done;
	memcpy(ctx->actions, tsem_root_actions, sizeof(tsem_root_actions));

	switch (tsem_mode) {
	case FULL_MODELING:
		msg = "full";
		break;
	case NO_ROOT_MODELING:
		msg = "namespace only";
		break;
	case EXPORT_ONLY:
		msg = "export";
		break;
	}
	pr_info("tsem: Initialized %s modeling.\n", msg);

	tsem_available = true;
	tsk->trust_status = TSEM_TASK_TRUSTED;
	retn = 0;

 done:
	if (retn) {
		tsem_event_magazine_free(ctx);
		tsem_model_magazine_free(model);
	}
	return retn;
}

DEFINE_LSM(tsem) = {
	.name = "tsem",
	.init = tsem_init,
	.blobs = &tsem_blob_sizes,
};
