// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2024 Enjellic Systems Development, LLC
 * Author: Dr. Greg Wettstein <greg@enjellic.com>
 *
 * This file implements the export of security relevant events to
 * an external trust orchestrator.  The primary TSEM security
 * documentation describes the types of events that are exported.
 *
 * The structures used to export each event are provided either by the
 * kmem_cache implementation maintained in this file or from a
 * magazine of structures that are maintained for events that are
 * running in atomic context.
 *
 * The events are exported through the following control plane file:
 *
 * /sys/kernel/security/tsem/external_tma/N
 *
 * Where N is a filename consisting of the context identifier of the
 * security modeling namespace that generated the event.
 *
 * A description of the security relevant event being exported is
 * encoded in JSON format.  The TSEM ABI documentation has a
 * description of the encoding that is used.
 *
 * For export events that describe a security event the JSON encoding
 * of the event description is provided by the
 * tsem_fs_show_trajectory() function.  This is the same function that
 * is used to generate the security event descriptions for internally
 * modeled namespaces.
 *
 * Processes that are generating security events in non-atomic context
 * are put to sleep and placed on a wait queue to be scheduled back
 * into execution by the external trust orchestrator after the event
 * is modeled for conformance with the enforced security model.
 *
 * Processes running in atomic context export the event and continue
 * to run.  A trust orchestrator is responsible for determing how to
 * address a workload that generates a model violating event, either
 * by shutting down the workload or generating a security alert via
 * the trust orchestration
 *
 * Security modeling namespaces, including the root namespace, can
 * also be configured for export only mode where the only purpose of
 * the export event is to hand a description of the event to
 * userspace.  This type of export is handled in the same manner as
 * an event being modeled that is running in atomic context.
 */

#include <linux/seq_file.h>

#include "tsem.h"

enum export_type {
	AGGREGATE_EVENT = 1,
	EXPORT_EVENT,
	EXPORT_ASYNC_EVENT,
	LOG_EVENT
};

struct action_description {
	enum export_type type;
	enum tsem_action_type action;
	char comm[TASK_COMM_LEN];
};

struct export_event {
	struct list_head list;
	enum export_type type;
	union {
		u8 *aggregate[HASH_MAX_DIGESTSIZE];
		struct tsem_event *ep;
		struct action_description action;
	} u;
};

static const char * const tsem_actions[TSEM_ACTION_CNT] = {
	"LOG",
	"DENY"
};

static struct kmem_cache *export_cachep;

static void refill_export_magazine(struct work_struct *work)
{
	struct export_event *exp;
	struct tsem_external *ext;
	struct tsem_work *ws;

	ws = container_of(work, struct tsem_work, work);
	ext = ws->u.ext;

	exp = kmem_cache_zalloc(export_cachep, GFP_KERNEL);
	if (!exp) {
		pr_warn("tsem: Cannot refill event magazine.\n");
		return;
	}

	spin_lock(&ws->u.ext->magazine_lock);
	ws->u.ext->magazine[ws->index] = exp;
	clear_bit(ws->index, ws->u.ext->magazine_index);

	/*
	 * The following memory barrier is used to cause the magazine
	 * index to be visible after the refill of the cache slot.
	 */
	smp_mb__after_atomic();
	spin_unlock(&ws->u.ext->magazine_lock);
}

static struct export_event *allocate_export(bool locked)
{
	unsigned int index;
	struct export_event *exp = NULL;
	struct tsem_external *ext = tsem_context(current)->external;

	if (!locked)
		return kmem_cache_zalloc(export_cachep, GFP_KERNEL);

	spin_lock(&ext->magazine_lock);
	index = find_first_zero_bit(ext->magazine_index, ext->magazine_size);
	if (index < ext->magazine_size) {
		exp = ext->magazine[index];
		ext->ws[index].index = index;
		ext->ws[index].u.ext = ext;
		set_bit(index, ext->magazine_index);

		/*
		 * Similar to the issue noted in the refill_event_magazine()
		 * function, this barrier is used to cause the consumption
		 * of the cache entry to become visible.

		 */
		smp_mb__after_atomic();
	}

	spin_unlock(&ext->magazine_lock);

	if (exp) {
		INIT_WORK(&ext->ws[index].work, refill_export_magazine);
		queue_work(system_wq, &ext->ws[index].work);
		return exp;
	}

	pr_warn("tsem: %s in %llu failed export allocation, cache size=%u.\n",
		current->comm, tsem_context(current)->id, ext->magazine_size);
	return NULL;
}

static void trigger_event(struct tsem_context *ctx)
{
	ctx->external->have_event = true;
	wake_up_interruptible(&ctx->external->wq);
}

int tsem_export_show(struct seq_file *sf, void *v)
{
	bool locked = false;
	struct export_event *exp = NULL;
	struct tsem_context *ctx = tsem_context(current);

	if (!ctx->id && !ctx->external)
		return -ENODATA;

	spin_lock(&ctx->external->export_lock);
	if (!list_empty(&ctx->external->export_list)) {
		exp = list_first_entry(&ctx->external->export_list,
				       struct export_event, list);
		list_del(&exp->list);
	}
	spin_unlock(&ctx->external->export_lock);

	if (!exp)
		return -ENODATA;

	seq_putc(sf, '{');
	tsem_fs_show_field(sf, "export");

	switch (exp->type) {
	case AGGREGATE_EVENT:
		tsem_fs_show_key(sf, "type", "}, ", "%s", "aggregate");
		tsem_fs_show_field(sf, "aggregate");
		tsem_fs_show_key(sf, "value", "}", "%*phN", tsem_digestsize(),
				 exp->u.aggregate);
		break;

	case EXPORT_EVENT:
		tsem_fs_show_key(sf, "type", "}, ", "%s", "event");
		tsem_fs_show_trajectory(sf, exp->u.ep);
		locked = exp->u.ep->locked;
		tsem_event_put(exp->u.ep);
		break;

	case EXPORT_ASYNC_EVENT:
		tsem_fs_show_key(sf, "type", "}, ", "%s", "async_event");
		tsem_fs_show_trajectory(sf, exp->u.ep);
		locked = exp->u.ep->locked;
		tsem_event_put(exp->u.ep);
		break;

	case LOG_EVENT:
		tsem_fs_show_key(sf, "type", "}, ", "%s", "log");
		tsem_fs_show_field(sf, "log");
		tsem_fs_show_key(sf, "process", ",", "%s", exp->u.action.comm);
		tsem_fs_show_key(sf, "event", ",", "%s",
				 tsem_names[exp->u.action.type]);
		tsem_fs_show_key(sf, "action", "}", "%s",
				 tsem_actions[exp->u.action.action]);
		break;
	}
	seq_puts(sf, "}\n");

	kmem_cache_free(export_cachep, exp);
	return 0;
}

/**
 * tsem_export_event() - Export a security event description.
 * @event: The TSEM event type number for which the log event is being
 *	   generated.
 *
 * This function queues for export to an external modeling agent a
 * security event description.
 *
 * Return: This function returns 0 if the export was successful or
 *	   an error value if it was not.
 */
int tsem_export_event(struct tsem_event *ep)
{
	int retn = 0;
	struct tsem_task *task = tsem_task(current);
	struct tsem_context *ctx = task->context;
	struct export_event *exp;

	exp = allocate_export(ep->locked);
	if (!exp) {
		pr_warn("tsem: domain %llu failed export allocation.\n",
			ctx->id);
		return -ENOMEM;
	}

	exp->type = ep->locked ? EXPORT_ASYNC_EVENT : EXPORT_EVENT;
	exp->u.ep = ep;
	tsem_event_get(ep);

	spin_lock(&ctx->external->export_lock);
	list_add_tail(&exp->list, &ctx->external->export_list);
	spin_unlock(&ctx->external->export_lock);

	if (ctx->external->export_only || ep->locked) {
		trigger_event(ctx);
		return 0;
	}

	task->trust_status |= TSEM_TASK_TRUST_PENDING;
	trigger_event(ctx);

	while (task->trust_status & TSEM_TASK_TRUST_PENDING) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
		if (signal_pending(current)) {
			if (sigismember(&current->pending.signal, SIGKILL) ||
			    sigismember(&current->signal->shared_pending.signal,
					SIGKILL))
				task->trust_status = TSEM_TASK_UNTRUSTED;
		}
	}

	return retn;
}

/**
 * tsem_export_action() - Exports the action taken to a security violation.
 * @event: The TSEM event type number for which the log event is being
 *	   generated.
 * @locked: A boolean flag indicating whether or not the security hook
 *	    being reported on is called in atomic context.
 *
 * This function queues for export a description of an event that
 * was being disciplined.
 *
 * Return: This function returns 0 if the export was successful or
 *	   an error value if it was not.
 */
int tsem_export_action(enum tsem_event_type event, bool locked)
{
	struct tsem_context *ctx = tsem_context(current);
	struct export_event *exp;

	exp = allocate_export(locked);
	if (!exp) {
		pr_warn("tsem: domain %llu failed export allocation.\n",
			ctx->id);
		return -ENOMEM;
	}

	exp->type = LOG_EVENT;
	exp->u.action.type = event;
	exp->u.action.action = ctx->actions[event];
	strscpy(exp->u.action.comm, current->comm, sizeof(exp->u.action.comm));

	spin_lock(&ctx->external->export_lock);
	list_add_tail(&exp->list, &ctx->external->export_list);
	spin_unlock(&ctx->external->export_lock);

	trigger_event(ctx);

	return 0;
}

/**
 * tsem_export_aggregate() - Exports the hardware aggregate value.
 *
 * This function exports the hardware aggregate measurement for
 * the platform on which the TSEM LSM is being run on.
 *
 * Return: This function returns a value of 0 if the export was
 *	   successful or a non-zero return value if the export was
 *	   not successful.
 */
int tsem_export_aggregate(void)
{
	struct tsem_context *ctx = tsem_context(current);
	struct export_event *exp;

	exp = kmem_cache_zalloc(export_cachep, GFP_KERNEL);
	if (!exp)
		return -ENOMEM;

	exp->type = AGGREGATE_EVENT;
	memcpy(exp->u.aggregate, tsem_trust_aggregate(), tsem_digestsize());

	spin_lock(&ctx->external->export_lock);
	list_add_tail(&exp->list, &ctx->external->export_list);
	spin_unlock(&ctx->external->export_lock);

	trigger_event(ctx);

	return 0;
}

/**
 * tsem export_magazine_allocate() - Allocate a TSEM export magazine.
 * @ctx: A pointer to the external modeling context that the magazine is
 *	 to be allocated for.
 * @size: The number of entries to be created in the magazine.

 * The security event export magazine is an array of export_event
 * structures that are used to service security hooks that are called
 * in atomic context.  Each external modeling domain has a magazine
 * allocated to it and this function allocates and initializes the
 * memory structures needed to manage that magazine.

 * Return: This function returns a value of zero on success and a negative
 *	   error code on failure.
 */
int tsem_export_magazine_allocate(struct tsem_external *ext, size_t size)
{
	unsigned int lp;
	int retn = -ENOMEM;

	ext->magazine_size = size;

	spin_lock_init(&ext->magazine_lock);

	ext->magazine_index = bitmap_zalloc(ext->magazine_size, GFP_KERNEL);
	if (!ext->magazine_index)
		return retn;

	ext->magazine = kcalloc(ext->magazine_size, sizeof(*ext->magazine),
				GFP_KERNEL);
	if (!ext->magazine)
		goto done;

	for (lp = 0; lp < ext->magazine_size; ++lp) {
		ext->magazine[lp] = kmem_cache_zalloc(export_cachep,
						      GFP_KERNEL);
		if (!ext->magazine[lp])
			goto done;
	}

	ext->ws = kcalloc(ext->magazine_size, sizeof(*ext->ws), GFP_KERNEL);
	if (ext->ws)
		retn = 0;

 done:
	if (retn)
		tsem_export_magazine_free(ext);

	return retn;
}

/**
 * tsem export_magazine_free() - Releases a TSEM export magazine
 * @ctx: A pointer to the external modeling context whose magazine is
 *	 to be released.
 *
 * The function is used to free the memory that was allocated by
 * the tsem_export_magazine_allocate() function for an extenral
 * modeling context.
 */
void tsem_export_magazine_free(struct tsem_external *ext)
{
	unsigned int lp;

	for (lp = 0; lp < ext->magazine_size; ++lp)
		kmem_cache_free(export_cachep, ext->magazine[lp]);

	bitmap_free(ext->magazine_index);
	kfree(ext->ws);
	kfree(ext->magazine);
}

/**
 * tsem export_cache_init() - Initialize the TSEM export cache.
 *
 * This function is called by the TSEM initialization function and sets
 * up a cache for export structures that are called by security event
 * descriptions that are generated in atomix context
 *
 * Return: This function returns a value of zero on success and a negative
 *	   error code on failure.
 */
int __init tsem_export_cache_init(void)
{

	export_cachep = kmem_cache_create("tsem_export_cache",
					 sizeof(struct export_event), 0,
					 SLAB_PANIC, 0);
	if (!export_cachep)
		return -ENOMEM;

	return 0;
}
