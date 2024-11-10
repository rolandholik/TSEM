// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2024 Enjellic Systems Development, LLC
 * Author: Dr. Greg Wettstein <greg@enjellic.com>
 *
 * This file is the primary implementation file for the tsem LSM.
 *
 * It implements initialization and setup functions that interpret
 * kernel command-line arguments and prepares TSEM for operation.
 *
 * In addition it contains all of the TSEM specific security event
 * handlers that are responsible for handling the LSM events that TSEM
 * models.
 *
 * Each TSEM event handler calls the tsem_allocate_event() function to
 * allocate a structure that will be used to describe the event.  The
 * CELL union of this structure contains various structures that are
 * used to hold these parameters.
 *
 * Since the event characterization parameters need to be retained for
 * the lifetime of the tsem_event structure that is allocated.  In the
 * case of internally modeled namespaces this lifespan is the lifetime
 * of the security modeling namespace.  In the case of externally
 * modeled namespaces, the lifespan is until the security event
 * description is exported to an external trust orchestrator.
 *
 * In order to support this model, the event description structures
 * are typically composed of a union over 'in' and 'out' structures.
 * The 'in' structures are used to hold arguments to the event handler
 * that may only be relevant for the duration of the call.  These
 * values are translated into members of the 'out' structure that
 * retain the values until the end of the lifetime of the tsem_event
 * structure.
 *
 * Each TSEM event handler is responsible for allocating a tsem_event
 * structure and populating the appropriate CELL structure with the
 * input characteristics of the event.  The dispatch_event() function
 * is called to handle the modeling of the event.  This function
 * returns the permission value that is returned as the result of the
 * LSM event handler.
 *
 * The dispatch_event() calls the tsem_event_init() function that is
 * responsible for translating the input parameters into values that
 * will be retained for the lifetime of the security event
 * description.  The populated event description is then dispatched to
 * either the tsem_model_event() or the tsem_export_event() for
 * modeling by either the internal TMA or by a TMA associated with an
 * external trust orchestrator.
 */

#define LOCK true
#define NOLOCK false

#include <linux/magic.h>
#include <linux/mman.h>
#include <linux/binfmts.h>
#include <linux/bpf.h>
#include <linux/mount.h>
#include <linux/security.h>

#include "tsem.h"
#include "nsmgr.h"

static const struct lsm_id tsem_lsmid = {
	.name = "tsem",
	.id = LSM_ID_TSEM
};

struct lsm_blob_sizes tsem_blob_sizes __ro_after_init = {
	.lbs_task = sizeof(struct tsem_task),
	.lbs_inode = sizeof(struct tsem_inode),
	.lbs_ipc = sizeof(struct tsem_ipc),
	.lbs_xattr_count = 1
};
EXPORT_SYMBOL_GPL(tsem_blob_sizes);

enum tsem_action_type tsem_root_actions[TSEM_EVENT_CNT] = {
	TSEM_ACTION_EPERM	/* Undefined. */
};

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
	.pseudonym_list = LIST_HEAD_INIT(root_model.pseudonym_list),
};

static struct tsem_context root_context;

DEFINE_STATIC_KEY_TRUE(tsem_not_ready);

static bool tsem_available __ro_after_init;

static unsigned int magazine_size __ro_after_init = TSEM_ROOT_MAGAZINE_SIZE;

static enum mode_type {
	FULL_MODELING,
	NO_ROOT_MODELING,
	ROOT_EXPORT_ONLY
} tsem_mode __ro_after_init;

static char *default_hash_function __ro_after_init;

static const struct {
	char *key;
	enum mode_type mode;
} mode_arguments[] __ro_after_init = {
	{"no_root_modeling", NO_ROOT_MODELING},
	{"root_export_only", ROOT_EXPORT_ONLY}
};

/*
 * NOTE:
 * The tsem_event_type enumerations are used to select the
 * member of the tsem_names array that is to be used.  If the members
 * of this array change position, or there are additions or deletions
 * to this array, there needs to be coordinated changes made to the
 * tsem_event_type enumeration in the tsem.h file.
 */
const char * const tsem_names[TSEM_EVENT_CNT] = {
	"undefined",
	"bprm_committed_creds",		/* TSEM_BPRM_COMMITTED_CREDS */
	"task_kill",			/* TSEM_TASK_KILL */
	"task_setpgid",			/* TSEM_TASK_SETPGID */
	"task_getpgid",			/* TSEM_TASK_GETPGID */
	"task_getsid",			/* TSEM_TASK_GETSID */
	"task_setnice",			/* TSEM_TASK_SETNICE */
	"task_setioprio",		/* TSEM_TASK_SETIOPRIO */
	"task_getioprio",		/* TSEM_TASK_GETIOPRIO */
	"task_prlimit",			/* TSEM_TASK_PRLIMIT */
	"task_setrlimit",		/* TSEM_TASK_SETRLIMIT */
	"task_setscheduler",		/* TSEM_TASK_SETSCHEDULER */
	"task_getscheduler",		/* TSEM_TASK_GETSCHEDULER */
	"task_prctl",			/* TSEM_TASK_PRCTL */
	"file_open",			/* TSEM_FILE_OPEN */
	"mmap_file",			/* TSEM_MMAP_FILE */
	"file_ioctl",			/* TSEM_FILE_IOCTL */
	"file_ioctl_compat",		/* TSEM_FILE_IOCTL_COMPAT */
	"file_lock",			/* TSEM_FILE_LOCK */
	"file_fcntl",			/* TSEM_FILE_FCNTL */
	"file_receive",			/* TSEM_FILE_RECEIVE */
	"file_truncate",		/* TSEM_FILE_TRUNCATE */
	"unix_stream_connect",		/* TSEM_UNIX_STREAM_CONNECT */
	"unix_may_send",		/* TSEM_UNIX_MAY_SEND */
	"socket_create",		/* TSEM_SOCKET_CREATE */
	"socket_connect",		/* TSEM_SOCKET_CONNECT */
	"socket_bind",			/* TSEM_SOCKET_BIND */
	"socket_accept",		/* TSEM_SOCKET_ACCEPT */
	"socket_listen",		/* TSEM_SOCKET_LISTEN */
	"socket_socketpair",		/* TSEM_SOCKET_SOCKETPAIR */
	"socket_sendmsg",		/* TSEM_SOCKET_SENDMSG */
	"socket_recvmsg",		/* TSEM_SOCKET_RECVMSG */
	"socket_getsockname",		/* TSEM_SOCKET_GETSOCKNAME */
	"socket_getpeername",		/* TSEM_SOCKET_GETPEERNAME */
	"socket_setsockopt",		/* TSEM_SOCKET_SETSOCKOPT */
	"socket_shutdown",		/* TSEM_SOCKET_SHUTDOWN */
	"ptrace_traceme",		/* TSEM_PTRACE_TRACEME */
	"kernel_module_request",	/* TSEM_KERNEL_MODULE_REQUEST */
	"kernel_load_data",		/* TSEM_KERNEL_LOAD_DATA */
	"kernel_read_file",		/* TSEM_KERNEL_READ_FILE */
	"sb_mount",			/* TSEM_SB_MOUNT */
	"sb_umount",			/* TSEM_SB_UMOUNT */
	"sb_remount",			/* TSEM_SB_REMOUNT */
	"sb_pivotroot",			/* TSEM_SB_PIVOTROOT */
	"sb_statfs",			/* TSEM_SB_STATFS */
	"move_mount",			/* TSEM_MOVE_MOUNT */
	"shm_associate",		/* TSEM_SHM_ASSOCIATE */
	"shm_shmctl",			/* TSEM_SHM_SHMCTL */
	"shm_shmat",			/* TSEM_SHM_SHMAT */
	"sem_associate",		/* TSEM_SEM_ASSOCIATE */
	"sem_semctl",			/* TSEM_SEM_SEMCTL */
	"sem_semop",			/* TSEM_SEM_SEMOP */
	"syslog",			/* TSEM_SYSLOG */
	"settime",			/* TSEM_SETTIME */
	"quotactl",			/* TSEM_QUOTACTL */
	"quota_on",			/* TSEM_QUOTA_ON */
	"msg_queue_associate",		/* TSEM_MSG_QUEUE_ASSOCIATE */
	"msg_queue_msgctl",		/* TSEM_MSG_QUEUE_MSGCTL */
	"msg_queue_msgsnd",		/* TSEM_MSG_QUEUE_MSGSND */
	"msg_queue_msgrcv",		/* TSEM_MSG_QUEUE_MSGRCV */
	"ipc_permission",		/* TSEM_IPC_PERMISSION */
	"key_alloc",			/* TSEM_KEY_ALLOC */
	"key_permission",		/* TSEM_KEY_PERMISSION */
	"netlink_send",			/* TSEM_NETLINK_SEND */
	"inode_create",			/* TSEM_INODE_CREATE */
	"inode_link",			/* TSEM_INODE_LINK */
	"inode_unlink",			/* TSEM_INODE_UNLINK */
	"inode_symlink",		/* TSEM_INODE_SYMLINK */
	"inode_mkdir",			/* TSEM_INODE_MKDIR */
	"inode_rmdir",			/* TSEM_INODE_RMDIR */
	"inode_mknod",			/* TSEM_INODE_MKNOD */
	"inode_rename",			/* TSEM_INODE_RENAME */
	"inode_setattr",		/* TSEM_INODE_SETATTR */
	"inode_getattr",		/* TSEM_INODE_GETATTR */
	"inode_setxattr",		/* TSEM_INODE_SETXATTR */
	"inode_getxattr",		/* TSEM_INODE_GETXATTR */
	"inode_listxattr",		/* TSEM_INODE_LISTXATTR */
	"inode_removexattr",		/* TSEM_INODE_REMOVEXATTR */
	"inode_killpriv",		/* TSEM_INODE_KILLPRIV */
	"tun_dev_create",		/* TSEM_TUN_DEV_CREATE */
	"tun_dev_attach_queue",		/* TSEM_TUN_DEV_ATTACH_QUEUE */
	"tun_dev_attach",		/* TSEM_TUN_DEV_ATTACH */
	"tun_dev_open",			/* TSEM_TUN_DEV_OPEN */
	"bpf",				/* TSEM_BPF */
	"bpf_map",			/* TSEM_BPF_MAP */
	"bpf_prog",			/* TSEM_BPF_PROG */
	"ptrace_access_check",		/* TSEM_PTRACE_ACCESS_CHECK */
	"capable",			/* TSEM_CAPABLE */
	"capget",			/* TSEM_CAPGET */
	"capset",			/* TSEM_CAPSET */
	"task_alloc",			/* TSEM_TASK_ALLOC */
	"bprm_check_security",		/* TSEM_BPRM_CHECK_SECURITY */
	"cred_prepare",			/* TSEM_CRED_PREPARE */
	"path_truncate",		/* TSEM_PATH_TRUNCATE */
	"path_unlink",			/* TSEM_PATH_UNLINK */
	"path_mkdir",			/* TSEM_PATH_MKDIR */
	"path_rmdir",			/* TSEM_PATH_RMDIR */
	"path_symlink"			/* TSEM_PATH_SYMLINK */
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

static int __init set_modeling_mode(char *mode_argument)
{
	unsigned int lp;

	for (lp = 0; lp < ARRAY_SIZE(mode_arguments); ++lp) {
		if (!strcmp(mode_argument, mode_arguments[lp].key)) {
			tsem_mode = mode_arguments[lp].mode;
			return 1;
		}
	}

	pr_warn("tsem: Unknown tsem_mode %s specified, using full modeling.\n",
		mode_argument);
	return 1;
}
__setup("tsem_mode=", set_modeling_mode);

static int __init set_default_hash_function(char *hash_function)
{

	default_hash_function = hash_function;
	return 1;
}
__setup("tsem_digest=", set_default_hash_function);

static int __init set_locked_status(char *str)
{
	tsem_nsmgr_lock(true);
	pr_info("tsem: Model state locked by command-line request.\n");
	return 1;
}
__setup("tsem_locked", set_locked_status);

static bool bypass_event(const enum tsem_event_type event)
{
	if (tsem_context(current)->ops->bypasses[event])
		return true;
	if (tsem_mode == NO_ROOT_MODELING && !tsem_context(current)->id)
		return true;
	return false;
}

static bool pseudo_filesystem(struct inode *inode)
{
	unsigned int lp;

	for (lp = 0; lp < ARRAY_SIZE(pseudo_filesystems); ++lp)
		if (inode->i_sb->s_magic == pseudo_filesystems[lp])
			return true;
	return false;
}

static int untrusted_task(struct tsem_event *ep)
{
	int retn = 0;
	struct tsem_context *ctx = tsem_context(current);

	if (ctx->external) {
		retn = tsem_export_action(ep->event, ep->locked);
		if (retn)
			return retn;
	} else
		pr_warn("Untrusted event %s: model_ns=%lld, comm=%s, pid=%d\n",
			tsem_names[ep->event], ctx->id, current->comm,
			task_pid_nr(current));

	if (ctx->actions[ep->event] == TSEM_ACTION_EPERM)
		retn = -EPERM;
	return retn;
}

static int dispatch_event(struct tsem_event *ep)
{
	int retn;

	if (unlikely(tsem_task_untrusted(current))) {
		retn = untrusted_task(ep);
		goto done;
	}

	if (tsem_context(current)->ops->init)
		retn = tsem_context(current)->ops->init(ep);
	else
		retn = tsem_event_init(ep);
	if (ep->terminate_event)
		goto done;
	if (retn > 0) {
		if (!tsem_context(current)->external)
			retn = tsem_model_event(ep);
		else
			retn = tsem_export_event(ep);
	}

 done:
	tsem_event_put(ep);
	return retn;
}

static int tsem_file_open(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct tsem_event *ep;

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;
	if (bypass_event(TSEM_FILE_OPEN))
		return 0;
	if (unlikely(tsem_inode(inode)->status == TSEM_INODE_CONTROL_PLANE)) {
		if (capable(CAP_MAC_ADMIN))
			return 0;
		else
			return -EPERM;
	}

	if (!S_ISREG(inode->i_mode))
		return 0;
	if (tsem_inode(inode)->status == TSEM_INODE_COLLECTING)
		return 0;

	ep = tsem_event_allocate(TSEM_FILE_OPEN, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.file.in.file = file;
	ep->CELL.file.in.pseudo_file = pseudo_filesystem(inode);

	return dispatch_event(ep);
}

static int tsem_mmap_file(struct file *file, unsigned long prot,
			  unsigned long flags, unsigned long extra)
{
	struct inode *inode = NULL;
	struct tsem_event *ep;

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;
	if (bypass_event(TSEM_MMAP_FILE))
		return 0;

	if (!file && !(prot & PROT_EXEC))
		return 0;
	if (file) {
		inode = file_inode(file);
		if (!S_ISREG(inode->i_mode))
			return 0;
		if (pseudo_filesystem(inode))
			return 0;
	}

	ep = tsem_event_allocate(TSEM_MMAP_FILE, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.mmap_file.anonymous = file == NULL ? 1 : 0;
	ep->CELL.mmap_file.file.in.file = file;
	ep->CELL.mmap_file.prot = prot;
	ep->CELL.mmap_file.flags = flags;

	return dispatch_event(ep);
}

static int tsem_file_ioctl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_FILE_IOCTL))
		return 0;

	ep = tsem_event_allocate(TSEM_FILE_IOCTL, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.file.cmd = cmd;
	ep->CELL.file.in.file = file;
	ep->CELL.file.in.pseudo_file = pseudo_filesystem(file_inode(file));

	return dispatch_event(ep);
}

static int tsem_file_ioctl_compat(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_FILE_IOCTL_COMPAT))
		return 0;

	ep = tsem_event_allocate(TSEM_FILE_IOCTL_COMPAT, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.file.cmd = cmd;
	ep->CELL.file.in.file = file;
	ep->CELL.file.in.pseudo_file = pseudo_filesystem(file_inode(file));

	return dispatch_event(ep);
}

static int tsem_file_lock(struct file *file, unsigned int cmd)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_FILE_LOCK))
		return 0;

	ep = tsem_event_allocate(TSEM_FILE_LOCK, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.file.cmd = cmd;
	ep->CELL.file.in.file = file;
	ep->CELL.file.in.pseudo_file = pseudo_filesystem(file_inode(file));

	return dispatch_event(ep);
}

static int tsem_file_fcntl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	struct tsem_event *ep;

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;
	if (bypass_event(TSEM_FILE_FCNTL))
		return 0;

	ep = tsem_event_allocate(TSEM_FILE_FCNTL, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.file.cmd = cmd;
	ep->CELL.file.in.file = file;
	ep->CELL.file.in.pseudo_file = pseudo_filesystem(file_inode(file));

	return dispatch_event(ep);
}

static int tsem_file_receive(struct file *file)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_FILE_RECEIVE))
		return 0;

	ep = tsem_event_allocate(TSEM_FILE_RECEIVE, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.file.in.file = file;
	ep->CELL.file.in.pseudo_file = pseudo_filesystem(file_inode(file));

	return dispatch_event(ep);
}

static int tsem_file_truncate(struct file *file)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_FILE_TRUNCATE))
		return 0;

	ep = tsem_event_allocate(TSEM_FILE_TRUNCATE, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.file.in.file = file;
	ep->CELL.file.in.pseudo_file = pseudo_filesystem(file_inode(file));

	return dispatch_event(ep);
}

static int tsem_task_alloc(struct task_struct *new, unsigned long flags)
{
	int retn;
	struct tsem_event *ep;

	tsem_task(new)->context = tsem_task(current)->context;

	ep = tsem_event_allocate(TSEM_TASK_ALLOC, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.task_args.task = new;
	ep->CELL.task_args.flags = flags;

	retn = dispatch_event(ep);
	if (!retn)
		kref_get(&tsem_task(new)->context->kref);
	return retn;
}

static void tsem_task_free(struct task_struct *task)
{
	struct tsem_context *ctx = tsem_context(task);

	if (ctx->id)
		tsem_ns_put(ctx);
}

static int tsem_task_kill(struct task_struct *target,
			  struct kernel_siginfo *info, int sig,
			  const struct cred *cred)
{
	bool cross_model;
	struct tsem_event *ep;
	struct tsem_context *src_ctx = tsem_context(current);
	struct tsem_context *tgt_ctx = tsem_context(target);

	if (bypass_event(TSEM_TASK_KILL))
		return 0;

	cross_model = src_ctx->id != tgt_ctx->id;

	if (info != SEND_SIG_NOINFO && SI_FROMKERNEL(info))
		return 0;
	if (sig == SIGURG)
		return 0;
	if (!capable(CAP_MAC_ADMIN) &&
	    has_capability_noaudit(target, CAP_MAC_ADMIN))
		return -EPERM;
	if (!capable(CAP_MAC_ADMIN) && cross_model)
		return -EPERM;

	ep = tsem_event_allocate(TSEM_TASK_KILL, LOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.task_kill.signal = sig;
	ep->CELL.task_kill.cross_model = cross_model;
	memcpy(ep->CELL.task_kill.target, tsem_task(target)->task_id,
	       tsem_digestsize());

	return dispatch_event(ep);
}

static int tsem_ptrace_access_check(struct task_struct *child,
				    unsigned int mode)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_PTRACE_ACCESS_CHECK))
		return 0;

	ep = tsem_event_allocate(TSEM_PTRACE_ACCESS_CHECK, LOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.task_kill.u.resource = mode;
	memcpy(ep->CELL.task_kill.target, tsem_task(child)->task_id,
	       tsem_digestsize());

	return dispatch_event(ep);
}

static int tsem_ptrace_traceme(struct task_struct *parent)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_PTRACE_TRACEME))
		return 0;

	ep = tsem_event_allocate(TSEM_PTRACE_TRACEME, LOCK);
	if (!ep)
		return -ENOMEM;

	memcpy(ep->CELL.task_kill.source, tsem_task(parent)->task_id,
	       tsem_digestsize());

	return dispatch_event(ep);
}

static int tsem_capget(const struct task_struct *target,
		       kernel_cap_t *effective, kernel_cap_t *inheritable,
		       kernel_cap_t *permitted)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_CAPGET))
		return 0;

	ep = tsem_event_allocate(TSEM_CAPGET, LOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.capability.effective = *effective;
	ep->CELL.capability.inheritable = *inheritable;
	ep->CELL.capability.permitted = *permitted;
	memcpy(ep->CELL.capability.target, tsem_task(target)->task_id,
	       tsem_digestsize());

	return dispatch_event(ep);
}

static int tsem_capset(struct cred *new, const struct cred *old,
		       const kernel_cap_t *effective,
		       const kernel_cap_t *inheritable,
		       const kernel_cap_t *permitted)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_CAPSET))
		return 0;

	ep = tsem_event_allocate(TSEM_CAPSET, LOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.capability.effective = *effective;
	ep->CELL.capability.inheritable = *inheritable;
	ep->CELL.capability.permitted = *permitted;

	return dispatch_event(ep);
}

static int tsem_capable(const struct cred *cred, struct user_namespace *ns,
			int cap, unsigned int opts)
{
	struct tsem_event *ep;

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;
	if (bypass_event(TSEM_CAPABLE))
		return 0;

	ep = tsem_event_allocate(TSEM_CAPABLE, LOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.capability.cap = cap;
	ep->CELL.capability.opts = opts;

	return dispatch_event(ep);
}

static int tsem_task_setpgid(struct task_struct *p, pid_t pgid)
{
	struct tsem_event *ep;
	struct task_struct *src;

	if (bypass_event(TSEM_TASK_SETPGID))
		return 0;

	ep = tsem_event_allocate(TSEM_TASK_SETPGID, LOCK);
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
	struct tsem_event *ep;

	if (bypass_event(TSEM_TASK_GETPGID))
		return 0;

	ep = tsem_event_allocate(TSEM_TASK_GETPGID, LOCK);
	if (!ep)
		return -ENOMEM;

	memcpy(ep->CELL.task_kill.target, tsem_task(p)->task_id,
	       tsem_digestsize());

	return dispatch_event(ep);
}

static int tsem_task_getsid(struct task_struct *p)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_TASK_GETSID))
		return 0;

	ep = tsem_event_allocate(TSEM_TASK_GETSID, LOCK);
	if (!ep)
		return -ENOMEM;

	memcpy(ep->CELL.task_kill.target, tsem_task(p)->task_id,
	       tsem_digestsize());

	return dispatch_event(ep);
}

static int tsem_task_setnice(struct task_struct *p, int nice)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_TASK_SETNICE))
		return 0;

	ep = tsem_event_allocate(TSEM_TASK_SETNICE, LOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.task_kill.u.value = nice;
	memcpy(ep->CELL.task_kill.target, tsem_task(p)->task_id,
	       tsem_digestsize());

	return dispatch_event(ep);
}

static int tsem_task_setioprio(struct task_struct *p, int ioprio)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_TASK_SETIOPRIO))
		return 0;

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
	struct tsem_event *ep;

	if (bypass_event(TSEM_TASK_GETIOPRIO))
		return 0;

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
	struct tsem_event *ep;

	if (bypass_event(TSEM_TASK_PRLIMIT))
		return 0;

	ep = tsem_event_allocate(TSEM_TASK_PRLIMIT, LOCK);
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
	struct tsem_event *ep;

	if (bypass_event(TSEM_TASK_SETRLIMIT))
		return 0;

	ep = tsem_event_allocate(TSEM_TASK_SETRLIMIT, LOCK);
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
	struct tsem_event *ep;

	if (bypass_event(TSEM_TASK_SETSCHEDULER))
		return 0;

	ep = tsem_event_allocate(TSEM_TASK_SETSCHEDULER, LOCK);
	if (!ep)
		return -ENOMEM;

	memcpy(ep->CELL.task_kill.target, tsem_task(p)->task_id,
	       tsem_digestsize());

	return dispatch_event(ep);
}

static int tsem_task_getscheduler(struct task_struct *p)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_TASK_GETSCHEDULER))
		return 0;

	ep = tsem_event_allocate(TSEM_TASK_GETSCHEDULER, LOCK);
	if (!ep)
		return -ENOMEM;

	memcpy(ep->CELL.task_kill.target, tsem_task(p)->task_id,
	       tsem_digestsize());

	return dispatch_event(ep);
}

static int tsem_task_prctl(int option, unsigned long arg2, unsigned long arg3,
			   unsigned long arg4, unsigned long arg5)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_TASK_PRCTL))
		return 0;

	ep = tsem_event_allocate(TSEM_TASK_PRCTL, LOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.task_prctl.option = option;
	ep->CELL.task_prctl.arg2 = arg2;
	ep->CELL.task_prctl.arg3 = arg3;
	ep->CELL.task_prctl.arg4 = arg4;
	ep->CELL.task_prctl.arg5 = arg5;

	return dispatch_event(ep);
}

static void tsem_bprm_committed_creds(const struct linux_binprm *bprm)
{
	struct tsem_event *ep;

	if (static_branch_unlikely(&tsem_not_ready))
		return;

	ep = tsem_event_allocate(TSEM_BPRM_COMMITTED_CREDS, NOLOCK);
	if (!ep) {
		pr_warn("tsem: Unable to allocate event for %s\n", __func__); 
		return;
	}

	ep->CELL.file.in.file = bprm->file;
	dispatch_event(ep);
}

static int tsem_bprm_check_security(struct linux_binprm *bprm)
{
	struct tsem_event *ep;

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;
	if (bypass_event(TSEM_BPRM_CHECK_SECURITY))
		return 0;

	ep = tsem_event_allocate(TSEM_BPRM_CHECK_SECURITY, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.bprm = bprm;
	return dispatch_event(ep);
}

static int tsem_cred_prepare(struct cred *new, const struct cred *old,
			      gfp_t gfp)
{
	struct tsem_event *ep;

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;
	if (bypass_event(TSEM_CRED_PREPARE))
		return 0;

	ep = tsem_event_allocate(TSEM_CRED_PREPARE, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.cred_prepare.new = new;
	ep->CELL.cred_prepare.old = old;
	ep->CELL.cred_prepare.gfp = gfp;
	return dispatch_event(ep);
}

static int tsem_inode_alloc_security(struct inode *inode)
{
	struct tsem_inode *tsip = tsem_inode(inode);

	mutex_init(&tsip->digest_mutex);
	INIT_LIST_HEAD(&tsip->digest_list);

	mutex_init(&tsip->create_mutex);
	INIT_LIST_HEAD(&tsip->create_list);

	mutex_init(&tsip->instance_mutex);
	INIT_LIST_HEAD(&tsip->instance_list);

	return 0;
}

static int tsem_inode_init_security(struct inode *inode, struct inode *dir,
				    const struct qstr *qstr,
				    struct xattr *xattrs, int *xattr_count)
{
	u8 *owner = tsem_task(current)->task_id;
	struct tsem_inode *tsip = tsem_inode(inode);
	struct tsem_inode_instance *entry, *retn = NULL;

	mutex_lock(&tsem_inode(dir)->create_mutex);
	list_for_each_entry(entry, &tsem_inode(dir)->create_list, list) {
		if (!memcmp(entry->owner, owner, tsem_digestsize()) &&
		    !strcmp(qstr->name, entry->pathname)) {
			retn = entry;
			break;
		}
	}

	if (retn) {
		tsip->backing = ERR_PTR(-ENOENT);
		tsip->created = true;
		tsip->creator = retn->creator;
		tsip->instance = retn->instance;
		memcpy(tsip->owner, retn->owner, tsem_digestsize());

		list_del(&retn->list);
		__putname(retn->pathname);
		kfree(retn);
	}
	mutex_unlock(&tsem_inode(dir)->create_mutex);

	return -EOPNOTSUPP;
}

static void _release_inode_instances(u64 id, struct tsem_inode *tsip)
{
	struct tsem_inode_instance *owner, *tmp_owner;

	mutex_lock(&tsip->instance_mutex);
	list_for_each_entry_safe(owner, tmp_owner, &tsip->instance_list,
				 list) {
		if (id == owner->creator) {
			list_del(&owner->list);
			kfree(owner);
		}
	}
	mutex_unlock(&tsip->instance_mutex);
}

static void tsem_inode_free_security(struct inode *inode)
{
	struct tsem_inode_instance *owner, *tmp_owner;
	struct tsem_inode_digest *digest, *tmp_digest;
	struct tsem_inode_entry *entry, *tmp_entry;
	struct tsem_context *ctx = tsem_context(current);

	mutex_lock(&ctx->inode_mutex);
	list_for_each_entry_safe(entry, tmp_entry, &ctx->inode_list, list) {
		if (entry->tsip == tsem_inode(inode)) {
			list_del(&entry->list);
			_release_inode_instances(ctx->id, entry->tsip);
			kfree(entry);
		}
	}
	mutex_unlock(&ctx->inode_mutex);

	list_for_each_entry_safe(digest, tmp_digest,
				 &tsem_inode(inode)->digest_list, list) {
		list_del(&digest->list);
		kfree(digest->name);
		kfree(digest);
	}

	list_for_each_entry_safe(owner, tmp_owner,
				 &tsem_inode(inode)->create_list, list) {
		list_del(&owner->list);
		kfree(owner);
	}

	list_for_each_entry_safe(owner, tmp_owner,
				 &tsem_inode(inode)->instance_list, list) {
		list_del(&owner->list);
		kfree(owner);
	}
}

static int tsem_unix_stream_connect(struct sock *sock, struct sock *other,
				    struct sock *newsk)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_UNIX_STREAM_CONNECT))
		return 0;

	ep = tsem_event_allocate(TSEM_UNIX_STREAM_CONNECT, LOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.socket.in.socka = sock;
	ep->CELL.socket.in.sockb = other;

	return dispatch_event(ep);
}

static int tsem_unix_may_send(struct socket *sock, struct socket *other)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_UNIX_MAY_SEND))
		return 0;

	ep = tsem_event_allocate(TSEM_UNIX_MAY_SEND, LOCK);
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

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;

	memcpy(tsip->owner, tsem_task(current)->task_id, tsem_digestsize());
	return 0;
}

static int tsem_socket_create(int family, int type, int protocol, int kern)
{
	struct tsem_event *ep;

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;
	if (bypass_event(TSEM_SOCKET_CREATE))
		return 0;

	ep = tsem_event_allocate(TSEM_SOCKET_CREATE, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.socket.out.socka.family = family;
	ep->CELL.socket.out.socka.type = type;
	ep->CELL.socket.out.socka.protocol = protocol;
	ep->CELL.socket.out.socka.kern = kern;

	return dispatch_event(ep);
}

static int tsem_socket_connect(struct socket *sock, struct sockaddr *addr,
			     int addr_len)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_SOCKET_CONNECT))
		return 0;

	ep = tsem_event_allocate(TSEM_SOCKET_CONNECT, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.socket.in.socka = sock->sk;
	ep->CELL.socket.in.addr = addr;
	ep->CELL.socket.value = addr_len;

	return dispatch_event(ep);
}

static int tsem_socket_bind(struct socket *sock, struct sockaddr *addr,
			    int addr_len)

{
	struct tsem_event *ep;

	if (bypass_event(TSEM_SOCKET_BIND))
		return 0;

	ep = tsem_event_allocate(TSEM_SOCKET_BIND, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.socket.in.socka = sock->sk;
	ep->CELL.socket.in.addr = addr;
	ep->CELL.socket.value = addr_len;

	return dispatch_event(ep);
}

static int tsem_socket_accept(struct socket *sock, struct socket *newsock)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_SOCKET_ACCEPT))
		return 0;

	ep = tsem_event_allocate(TSEM_SOCKET_ACCEPT, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.socket.in.socka = sock->sk;

	return dispatch_event(ep);
}

static int tsem_socket_listen(struct socket *sock, int backlog)

{
	struct sock *sk = sock->sk;
	struct tsem_event *ep;

	if (bypass_event(TSEM_SOCKET_LISTEN))
		return 0;

	ep = tsem_event_allocate(TSEM_SOCKET_LISTEN, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.socket.value = backlog;
	ep->CELL.socket.in.socka = sk;

	return dispatch_event(ep);
}

static int tsem_socket_socketpair(struct socket *socka, struct socket *sockb)
{
	struct sock *ska = socka->sk, *skb = sockb->sk;
	struct tsem_event *ep;

	if (bypass_event(TSEM_SOCKET_SOCKETPAIR))
		return 0;

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
	struct sock *sk = sock->sk;
	struct tsem_event *ep;

	if (bypass_event(TSEM_SOCKET_SENDMSG))
		return 0;

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
	struct sock *sk = sock->sk;
	struct tsem_event *ep;

	if (bypass_event(TSEM_SOCKET_RECVMSG))
		return 0;

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
	struct sock *sk = sock->sk;
	struct tsem_event *ep;

	if (bypass_event(TSEM_SOCKET_GETSOCKNAME))
		return 0;

	ep = tsem_event_allocate(TSEM_SOCKET_GETSOCKNAME, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.socket.in.socka = sk;

	return dispatch_event(ep);
}

static int tsem_socket_getpeername(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct tsem_event *ep;

	if (bypass_event(TSEM_SOCKET_GETPEERNAME))
		return 0;

	ep = tsem_event_allocate(TSEM_SOCKET_GETPEERNAME, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.socket.in.socka = sk;

	return dispatch_event(ep);
}

static int tsem_socket_setsockopt(struct socket *sock, int level, int optname)
{
	struct sock *sk = sock->sk;
	struct tsem_event *ep;

	if (bypass_event(TSEM_SOCKET_SETSOCKOPT))
		return 0;

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
	struct sock *sk = sock->sk;
	struct tsem_event *ep;

	if (bypass_event(TSEM_SOCKET_SHUTDOWN))
		return 0;

	ep = tsem_event_allocate(TSEM_SOCKET_SHUTDOWN, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.socket.value = how;
	ep->CELL.socket.in.socka = sk;

	return dispatch_event(ep);
}

static int tsem_kernel_module_request(char *kmod_name)
{
	struct tsem_event *ep;

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;
	if (bypass_event(TSEM_KERNEL_MODULE_REQUEST))
		return 0;

	ep = tsem_event_allocate(TSEM_KERNEL_MODULE_REQUEST, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.kernel.in.kmod_name = kmod_name;

	return dispatch_event(ep);
}

static int tsem_kernel_load_data(enum kernel_load_data_id id, bool contents)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_KERNEL_LOAD_DATA))
		return 0;

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
	struct tsem_event *ep;

	if (bypass_event(TSEM_KERNEL_READ_FILE))
		return 0;

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
	struct tsem_event *ep;

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;
	if (bypass_event(TSEM_SB_MOUNT))
		return 0;

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
	struct tsem_event *ep;

	if (bypass_event(TSEM_SB_UMOUNT))
		return 0;

	ep = tsem_event_allocate(TSEM_SB_UMOUNT, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.sb.flags = flags;
	ep->CELL.sb.in.dentry = mnt->mnt_root;

	return dispatch_event(ep);
}

static int tsem_sb_remount(struct super_block *sb, void *mnt_opts)
{
	struct tsem_event *ep;

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;
	if (bypass_event(TSEM_SB_REMOUNT))
		return 0;

	ep = tsem_event_allocate(TSEM_SB_REMOUNT, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.sb.in.sb = sb;

	return dispatch_event(ep);
}

static int tsem_sb_pivotroot(const struct path *old_path,
			     const struct path *new_path)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_SB_PIVOTROOT))
		return 0;

	ep = tsem_event_allocate(TSEM_SB_PIVOTROOT, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.sb.in.path = old_path;
	ep->CELL.sb.in.path2 = new_path;

	return dispatch_event(ep);
}

static int tsem_sb_statfs(struct dentry *dentry)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_SB_STATFS))
		return 0;

	ep = tsem_event_allocate(TSEM_SB_STATFS, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.sb.in.dentry = dentry;

	return dispatch_event(ep);
}

static int tsem_move_mount(const struct path *from_path,
			   const struct path *to_path)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_MOVE_MOUNT))
		return 0;

	ep = tsem_event_allocate(TSEM_MOVE_MOUNT, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.sb.in.path = from_path;
	ep->CELL.sb.in.path2 = to_path;

	return dispatch_event(ep);
}

static int tsem_shm_associate(struct kern_ipc_perm *perm, int shmflg)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_SHM_ASSOCIATE))
		return 0;

	ep = tsem_event_allocate(TSEM_SHM_ASSOCIATE, LOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.ipc.in.perm = perm;
	ep->CELL.ipc.value = shmflg;

	return dispatch_event(ep);
}

static int tsem_shm_shmctl(struct kern_ipc_perm *perm, int cmd)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_SHM_SHMCTL))
		return 0;

	ep = tsem_event_allocate(TSEM_SHM_SHMCTL, LOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.ipc.in.perm = perm;
	ep->CELL.ipc.value = cmd;

	return dispatch_event(ep);
}

static int tsem_shm_shmat(struct kern_ipc_perm *perm, char __user *shmaddr,
			  int shmflg)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_SHM_SHMAT))
		return 0;

	ep = tsem_event_allocate(TSEM_SHM_SHMAT, LOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.ipc.in.perm = perm;
	ep->CELL.ipc.value = shmflg;

	return dispatch_event(ep);
}

static int tsem_sem_associate(struct kern_ipc_perm *perm, int semflg)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_SEM_ASSOCIATE))
		return 0;

	ep = tsem_event_allocate(TSEM_SEM_ASSOCIATE, LOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.ipc.in.perm = perm;
	ep->CELL.ipc.value = semflg;

	return dispatch_event(ep);
}

static int tsem_sem_semctl(struct kern_ipc_perm *perm, int cmd)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_SEM_SEMCTL))
		return 0;

	ep = tsem_event_allocate(TSEM_SEM_SEMCTL, LOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.ipc.in.perm = perm;
	ep->CELL.ipc.value = cmd;

	return dispatch_event(ep);
}

static int tsem_sem_semop(struct kern_ipc_perm *perm, struct sembuf *sops,
			  unsigned int nsops, int alter)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_SEM_SEMOP))
		return 0;

	ep = tsem_event_allocate(TSEM_SEM_SEMOP, LOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.ipc.in.perm = perm;
	ep->CELL.ipc.nsops = nsops;
	ep->CELL.ipc.value = alter;

	return dispatch_event(ep);
}

static int tsem_syslog(int type)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_SYSLOG))
		return 0;

	ep = tsem_event_allocate(TSEM_SYSLOG, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.value = type;

	return dispatch_event(ep);
}

static int tsem_settime(const struct timespec64 *ts, const struct timezone *tz)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_SETTIME))
		return 0;

	ep = tsem_event_allocate(TSEM_SETTIME, NOLOCK);
	if (!ep)
		return -ENOMEM;

	if (ts) {
		ep->CELL.time.have_ts = true;
		ep->CELL.time.seconds = ts->tv_sec;
		ep->CELL.time.nsecs = ts->tv_nsec;
	}
	if (tz) {
		ep->CELL.time.have_tz = true;
		ep->CELL.time.minuteswest = tz->tz_minuteswest;
		ep->CELL.time.dsttime = tz->tz_dsttime;
	}

	return dispatch_event(ep);
}

static int tsem_quotactl(int cmds, int type, int id,
			 const struct super_block *sb)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_QUOTACTL))
		return 0;

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
	struct tsem_event *ep;

	if (bypass_event(TSEM_QUOTA_ON))
		return 0;

	ep = tsem_event_allocate(TSEM_QUOTA_ON, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.quota.in.dentry = dentry;

	return dispatch_event(ep);
}

static int tsem_msg_queue_associate(struct kern_ipc_perm *perm, int msqflg)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_MSG_QUEUE_ASSOCIATE))
		return 0;

	ep = tsem_event_allocate(TSEM_MSG_QUEUE_ASSOCIATE, LOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.ipc.in.perm = perm;
	ep->CELL.ipc.value = msqflg;

	return dispatch_event(ep);
}

static int tsem_msg_queue_msgsnd(struct kern_ipc_perm *perm,
				 struct msg_msg *msgmsg, int msqflg)

{
	struct tsem_event *ep;

	if (bypass_event(TSEM_MSG_QUEUE_MSGSND))
		return 0;

	ep = tsem_event_allocate(TSEM_MSG_QUEUE_MSGSND, LOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.ipc.in.perm = perm;
	ep->CELL.ipc.value = msqflg;

	return dispatch_event(ep);
}

static int tsem_msg_queue_msgctl(struct kern_ipc_perm *perm, int cmd)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_MSG_QUEUE_MSGCTL))
		return 0;

	ep = tsem_event_allocate(TSEM_MSG_QUEUE_MSGCTL, LOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.ipc.in.perm = perm;
	ep->CELL.ipc.value = cmd;

	return dispatch_event(ep);
}

static int tsem_msg_queue_msgrcv(struct kern_ipc_perm *perm,
				 struct msg_msg *msgmsg,
				 struct task_struct *target, long type,
				 int mode)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_MSG_QUEUE_MSGRCV))
		return 0;

	ep = tsem_event_allocate(TSEM_MSG_QUEUE_MSGRCV, LOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.ipc.in.perm = perm;
	ep->CELL.ipc.in.target = target;
	ep->CELL.ipc.type = type;
	ep->CELL.ipc.value = mode;

	return dispatch_event(ep);
}

static int tsem_ipc_alloc(struct kern_ipc_perm *kipc)
{
	struct tsem_ipc *tipc = tsem_ipc(kipc);

	memcpy(tipc->owner, tsem_task(current)->task_id, tsem_digestsize());
	return 0;
}

static int tsem_ipc_permission(struct kern_ipc_perm *ipcp, short flag)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_IPC_PERMISSION))
		return 0;

	ep = tsem_event_allocate(TSEM_IPC_PERMISSION, LOCK);
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
	struct tsem_event *ep;

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;
	if (bypass_event(TSEM_KEY_ALLOC))
		return 0;

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
	struct tsem_event *ep;

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;
	if (bypass_event(TSEM_KEY_PERMISSION))
		return 0;

	ep = tsem_event_allocate(TSEM_KEY_PERMISSION, LOCK);
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
	struct tsem_event *ep;

	if (bypass_event(TSEM_NETLINK_SEND))
		return 0;

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
	struct tsem_event *ep;

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;
	if (bypass_event(TSEM_INODE_CREATE))
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
	struct tsem_event *ep;

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;
	if (bypass_event(TSEM_INODE_LINK))
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
	struct tsem_event *ep;

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;
	if (bypass_event(TSEM_INODE_UNLINK))
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
	struct tsem_event *ep;

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;
	if (bypass_event(TSEM_INODE_SYMLINK))
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
	struct tsem_event *ep;

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;
	if (bypass_event(TSEM_INODE_MKDIR))
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
	struct tsem_event *ep;

	if (bypass_event(TSEM_INODE_RMDIR))
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
	struct tsem_event *ep;

	if (bypass_event(TSEM_INODE_RENAME))
		return 0;

	ep = tsem_event_allocate(TSEM_INODE_RENAME, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.inode.in.dir = old_dir;
	ep->CELL.inode.in.new_dir = new_dir;
	ep->CELL.inode.in.dentry = old_dentry;
	ep->CELL.inode.in.new_dentry = new_dentry;

	return dispatch_event(ep);
}

static int tsem_inode_mknod(struct inode *dir, struct dentry *dentry,
			    umode_t mode, dev_t dev)
{
	struct tsem_event *ep;

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;
	if (bypass_event(TSEM_INODE_MKNOD))
		return 0;

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
	struct tsem_event *ep;

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;
	if (bypass_event(TSEM_INODE_SETATTR))
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
	struct tsem_event *ep;

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;
	if (bypass_event(TSEM_INODE_GETATTR))
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
	struct tsem_event *ep;

	if (bypass_event(TSEM_INODE_SETXATTR))
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
	struct tsem_event *ep = NULL;

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;
	if (bypass_event(TSEM_INODE_GETXATTR))
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
	struct tsem_event *ep;

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;
	if (bypass_event(TSEM_INODE_LISTXATTR))
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
	struct tsem_event *ep;

	if (bypass_event(TSEM_INODE_REMOVEXATTR))
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
	struct tsem_event *ep;

	if (bypass_event(TSEM_INODE_KILLPRIV))
		return 0;

	ep = tsem_event_allocate(TSEM_INODE_KILLPRIV, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.inode.in.dentry = dentry;

	return dispatch_event(ep);
}

static int tsem_tun_dev_create(void)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_TUN_DEV_CREATE))
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

	if (bypass_event(TSEM_TUN_DEV_ATTACH_QUEUE))
		return 0;

	ep = tsem_event_allocate(TSEM_TUN_DEV_ATTACH_QUEUE, NOLOCK);
	if (!ep)
		return -ENOMEM;
	ep->no_params = true;

	return dispatch_event(ep);
}

static int tsem_tun_dev_attach(struct sock *sk, void *security)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_TUN_DEV_ATTACH))
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

	if (bypass_event(TSEM_TUN_DEV_OPEN))
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
	struct tsem_event *ep;

	if (bypass_event(TSEM_BPF))
		return 0;

	ep = tsem_event_allocate(TSEM_BPF, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.bpf.bpf.cmd = cmd;
	ep->CELL.bpf.bpf.size = size;

	return dispatch_event(ep);
}

static int tsem_bpf_map(struct bpf_map *map, fmode_t fmode)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_BPF_MAP))
		return 0;

	ep = tsem_event_allocate(TSEM_BPF_MAP, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.bpf.map.fmode = fmode;
	ep->CELL.bpf.map.map_type = map->map_type;

	return dispatch_event(ep);
}

static int tsem_bpf_prog(struct bpf_prog *prog)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_BPF_PROG))
		return 0;

	ep = tsem_event_allocate(TSEM_BPF_PROG, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.bpf.prog.type = prog->type;
	ep->CELL.bpf.prog.attach_type = prog->expected_attach_type;

	return dispatch_event(ep);
}
#endif

#ifdef CONFIG_SECURITY_PATH
static int tsem_path_truncate(const struct path *path)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_PATH_TRUNCATE))
		return 0;

	ep = tsem_event_allocate(TSEM_PATH_TRUNCATE, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.inode.path = path;

	return dispatch_event(ep);
}

static int tsem_path_unlink(const struct path *path, struct dentry *dentry)
{
	struct tsem_event *ep;

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;
	if (bypass_event(TSEM_PATH_UNLINK))
		return 0;

	ep = tsem_event_allocate(TSEM_PATH_UNLINK, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.inode.path = path;
	ep->CELL.inode.in.dentry = dentry;
	ep->CELL.inode.mode = 0;

	return dispatch_event(ep);
}

static int tsem_path_mkdir(const struct path *path, struct dentry *dentry,
	umode_t mode)
{
	struct tsem_event *ep;

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;
	if (bypass_event(TSEM_PATH_MKDIR))
		return 0;

	ep = tsem_event_allocate(TSEM_PATH_MKDIR, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.inode.path = path;
	ep->CELL.inode.in.dentry = dentry;
	ep->CELL.inode.mode = mode;

	return dispatch_event(ep);
}

static int tsem_path_rmdir(const struct path *path, struct dentry *dentry)
{
	struct tsem_event *ep;

	if (bypass_event(TSEM_PATH_RMDIR))
		return 0;

	ep = tsem_event_allocate(TSEM_PATH_RMDIR, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.inode.path = path;
	ep->CELL.inode.in.dentry = dentry;

	return dispatch_event(ep);
}

static int tsem_path_symlink(const struct path *path, struct dentry *dentry,
			     const char *old_name)
{
	struct tsem_event *ep;

	if (static_branch_unlikely(&tsem_not_ready))
		return 0;
	if (bypass_event(TSEM_PATH_SYMLINK))
		return 0;

	ep = tsem_event_allocate(TSEM_PATH_SYMLINK, NOLOCK);
	if (!ep)
		return -ENOMEM;

	ep->CELL.inode.path = path;
	ep->CELL.inode.in.dentry = dentry;
	ep->CELL.inode.in.old_name = old_name;

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

	LSM_HOOK_INIT(ptrace_access_check, tsem_ptrace_access_check),
	LSM_HOOK_INIT(ptrace_traceme, tsem_ptrace_traceme),

	LSM_HOOK_INIT(capget, tsem_capget),
	LSM_HOOK_INIT(capset, tsem_capset),
	LSM_HOOK_INIT(capable, tsem_capable),

	LSM_HOOK_INIT(bprm_committed_creds, tsem_bprm_committed_creds),
	LSM_HOOK_INIT(bprm_check_security, tsem_bprm_check_security),
	LSM_HOOK_INIT(cred_prepare, tsem_cred_prepare),

	LSM_HOOK_INIT(inode_alloc_security, tsem_inode_alloc_security),
	LSM_HOOK_INIT(inode_init_security, tsem_inode_init_security),
	LSM_HOOK_INIT(inode_free_security, tsem_inode_free_security),

	LSM_HOOK_INIT(file_open, tsem_file_open),
	LSM_HOOK_INIT(mmap_file, tsem_mmap_file),
	LSM_HOOK_INIT(file_ioctl, tsem_file_ioctl),
	LSM_HOOK_INIT(file_ioctl_compat, tsem_file_ioctl_compat),
	LSM_HOOK_INIT(file_lock, tsem_file_lock),
	LSM_HOOK_INIT(file_fcntl, tsem_file_fcntl),
	LSM_HOOK_INIT(file_receive, tsem_file_receive),
	LSM_HOOK_INIT(file_truncate, tsem_file_truncate),

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
	LSM_HOOK_INIT(bpf_prog, tsem_bpf_prog),
#endif

#ifdef CONFIG_SECURITY_PATH
	LSM_HOOK_INIT(path_truncate, tsem_path_truncate),
	LSM_HOOK_INIT(path_unlink, tsem_path_unlink),
	LSM_HOOK_INIT(path_mkdir, tsem_path_mkdir),
	LSM_HOOK_INIT(path_rmdir, tsem_path_rmdir),
	LSM_HOOK_INIT(path_symlink, tsem_path_symlink)
#endif
};

static int configure_root_digest(void)
{
	int retn = 0;
	char *digest = NULL;
	u8 zero_digest[HASH_MAX_DIGESTSIZE];
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
	memcpy(root_context.zero_digest, zero_digest,
	       crypto_shash_digestsize(tfm));

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

	retn = tsem_model_init();
	if (retn)
		goto done;

	retn = tsem_fs_init();
	if (retn)
		goto done;

	if (tsem_mode == ROOT_EXPORT_ONLY) {
		retn = tsem_ns_export_root(magazine_size);
		if (retn)
			goto done;
	}

	pr_info("tsem: Now active.\n");
	static_branch_disable(&tsem_not_ready);

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

	mutex_init(&ctx->inode_mutex);
	INIT_LIST_HEAD(&ctx->inode_list);

	mutex_init(&ctx->mount_mutex);
	INIT_LIST_HEAD(&ctx->mount_list);

	root_context.ops = &tsem_model0_ops;
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
		msg = "full modeling";
		break;
	case NO_ROOT_MODELING:
		msg = "namespace only modeling";
		break;
	case ROOT_EXPORT_ONLY:
		msg = "root export only";
		break;
	}
	pr_info("tsem: Initialized %s.\n", msg);

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
