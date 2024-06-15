// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2024 Enjellic Systems Development, LLC
 * Author: Dr. Greg Wettstein <greg@enjellic.com>
 *
 * This file handles the creation and population of the tsem_event
 * structure that describes each security event that occurs.  The
 * structures that are held in the CELL union of the tsem_event
 * structure are used to deliver the characterizing parameters of a
 * security into the tsem_event_init() function.
 *
 * Most of the structures used to characterize a security event use
 * a strategy where a union is used to enclose an 'in' and 'out'
 * structure.  The parameters that are relevant to the TSEM
 * characterization of an event are placed in the 'in' structure.  The
 * routines in this function are responsible for propagating these
 * characteristics into the 'out' structure for the lifetime of the
 * structure.
 */

#include "tsem.h"

static struct kmem_cache *event_cachep;

static void refill_event_magazine(struct work_struct *work)
{
	unsigned int index;
	struct tsem_event *ep;
	struct tsem_work *ws;

	ws = container_of(work, struct tsem_work, work);

	ep = kmem_cache_zalloc(event_cachep, GFP_KERNEL);
	if (!ep) {
		pr_warn("tsem: Cannot refill event magazine.\n");
		return;
	}

	spin_lock(&ws->u.ctx->magazine_lock);
	ws->u.ctx->magazine[ws->index] = ep;
	clear_bit(ws->index, ws->u.ctx->magazine_index);

	/*
	 * The following memory barrier is used to cause the magazine
	 * index to be visible after the refill of the cache slot.
	 */
	smp_mb__after_atomic();
	spin_unlock(&ws->u.ctx->magazine_lock);

	if (index >= ws->u.ctx->magazine_size) {
		kmem_cache_free(event_cachep, ep);
		WARN_ONCE(true, "Refilling event magazine with no slots.\n");
	}
}

static void get_COE(struct tsem_COE *COE)
{
	struct user_namespace *ns;

	if (tsem_context(current)->use_current_ns)
		ns = current_user_ns();
	else
		ns = &init_user_ns;

	COE->uid = from_kuid(ns, current_uid());
	COE->euid = from_kuid(ns, current_euid());
	COE->suid = from_kuid(ns, current_suid());

	COE->gid = from_kgid(ns, current_gid());
	COE->egid = from_kgid(ns, current_egid());
	COE->sgid = from_kgid(ns, current_sgid());

	COE->fsuid = from_kuid(ns, current_fsuid());
	COE->fsgid = from_kgid(ns, current_fsgid());

	COE->capeff.mask = current_cred()->cap_effective;
}

/**
 * tsem_event_init() - Initialize a security event description structure.
 * @ep: A pointer to the tsem_event structure that describes the
 *	security event.
 *
 * This function is responsible for initializing the tsem_event structure
 * and populating it based on the event type.
 *
 * Return: In the event of an error this function returns an error code
 *	   as a negative return value.  A value of zero indicates that
 *	   the event should be bypassed.  A positive value indicates
 *	   the event should be modeled.
 */
int tsem_event_init(struct tsem_event *ep)
{
	int retn = 1;
	struct tsem_task *task = tsem_task(current);

	ep->pid = task_pid_nr(current);
	ep->instance = task->instance;
	ep->p_instance = task->p_instance;
	ep->timestamp = ktime_get_boottime_ns();
	memcpy(ep->comm, current->comm, sizeof(ep->comm));
	memcpy(ep->task_id, task->task_id, tsem_digestsize());
	memcpy(ep->p_task_id, task->p_task_id, tsem_digestsize());

	get_COE(&ep->COE);

	if (!ep->no_params)
		retn = tsem_context(current)->ops->event_init(ep);

	if (retn <= 0)
		kmem_cache_free(event_cachep, ep);
	else
		kref_init(&ep->kref);
	return retn;
}

/**
 * tsem_free_event() - Free a security event description.
 * @ep: A pointer to the security event description that is to be freed.
 *
 * This function is responsible for freeing the resources that were
 * allocated by the tsem_event_allocate() function.
 */
static void tsem_event_free(struct kref *kref)
{
	struct tsem_event *ep;

	ep = container_of(kref, struct tsem_event, kref);

	if (ep->event_free)
		ep->event_free(ep);
	kmem_cache_free(event_cachep, ep);
}

/**
 * tsem_event_put() - Release a referenceto a TSEM event description.
 *
 * This function is called each time the use of a TSEM event description
 * is dropped.
 */
void tsem_event_put(struct tsem_event *ep)
{
	kref_put(&ep->kref, tsem_event_free);
}

/**
 * tsem_event_get() - Obtain a reference to a TSEM event description.
 *
 * This function is called on each invocation of the tsem_task_free
 * function to release one of the references on the TMA modeling
 * structure.
 */
void tsem_event_get(struct tsem_event *ep)
{
	kref_get(&ep->kref);
}

/**
 * tsem_event_allocate() - Allocate a TSEM event description structure.
 * @locked: A boolean flag used to indicate if the allocation is being
 *	    done in atomic context and must be serviced from the
 *	    pre-allocated event description structures.
 *
 * Return: This function returns a pointer to the allocated structure or
 *	   a NULL pointer in the event of an allocation failure.
 */
struct tsem_event *tsem_event_allocate(enum tsem_event_type event, bool locked)
{
	unsigned int index;
	struct tsem_event *ep = NULL;
	struct tsem_context *ctx = tsem_context(current);

	if (!locked) {
		ep = kmem_cache_zalloc(event_cachep, GFP_KERNEL);
		if (ep)
			ep->event = event;
		return ep;
	}

	spin_lock(&ctx->magazine_lock);
	index = find_first_zero_bit(ctx->magazine_index, ctx->magazine_size);
	if (index < ctx->magazine_size) {
		ep = ctx->magazine[index];
		ctx->ws[index].index = index;
		ctx->ws[index].u.ctx = ctx;
		set_bit(index, ctx->magazine_index);

		/*
		 * Similar to the issue noted in the refill_event_magazine()
		 * function, this barrier is used to cause the consumption
		 * of the cache entry to become visible.

		 */
		smp_mb__after_atomic();
	}

	spin_unlock(&ctx->magazine_lock);

	if (ep) {
		INIT_WORK(&ctx->ws[index].work, refill_event_magazine);
		queue_work(system_highpri_wq, &ctx->ws[index].work);
		ep->event = event;
		ep->locked = true;
		return ep;
	}

	pr_warn("tsem: Fail event allocation comm %s ns %llu cs %u.\n",
		current->comm, tsem_context(current)->id, ctx->magazine_size);
	return NULL;
}

/**
 * tsem event_magazine_allocate() - Allocate a TSEM event magazine.
 * @ctx: A pointer to the modeling context that the magazine is
 *	 to be allocated for.
 * @size: The number of entries to be created in the magazine.

 * The security modeling event magazine is an array of tsem_event
 * structures that are used to service security hooks that are called
 * in atomic context.  Each modeling domain/namespace has a magazine
 * allocated to it and this function allocates and initializes the
 * memory structures needed to manage that magazine.

 * Return: This function returns a value of zero on success and a negative
 *	   error code on failure.
 */
int tsem_event_magazine_allocate(struct tsem_context *ctx, size_t size)
{
	unsigned int lp;
	int retn = -ENOMEM;

	ctx->magazine_size = size;

	spin_lock_init(&ctx->magazine_lock);

	ctx->magazine_index = bitmap_zalloc(ctx->magazine_size, GFP_KERNEL);
	if (!ctx->magazine_index)
		return retn;

	ctx->magazine = kcalloc(ctx->magazine_size, sizeof(*ctx->magazine),
				GFP_KERNEL);
	if (!ctx->magazine)
		goto done;

	for (lp = 0; lp < ctx->magazine_size; ++lp) {
		ctx->magazine[lp] = kmem_cache_zalloc(event_cachep,
						      GFP_KERNEL);
		if (!ctx->magazine[lp])
			goto done;
	}

	ctx->ws = kcalloc(ctx->magazine_size, sizeof(*ctx->ws), GFP_KERNEL);
	if (ctx->ws)
		retn = 0;

 done:
	if (retn)
		tsem_event_magazine_free(ctx);

	return retn;
}

/**
 * tsem event_magazine_free() - Releases a TSEM event magazine.
 * @ctx: A pointer to the modeling context whose magazine is to be
 *	 released.
 *
 * The function is used to free the memory that was allocated by
 * the tsem_event_magazine_allocate() function for a security
 * modeling context.
 */
void tsem_event_magazine_free(struct tsem_context *ctx)
{
	unsigned int lp;

	for (lp = 0; lp < ctx->magazine_size; ++lp)
		kmem_cache_free(event_cachep, ctx->magazine[lp]);

	bitmap_free(ctx->magazine_index);
	kfree(ctx->ws);
	kfree(ctx->magazine);
}

/**
 * tsem event_cache_init() - Initialize the TSEM event cache.
 *
 * This function is called by the TSEM initialization function and sets
 * up the cache that will be used to allocate tsem_event structures.
 *
 * Return: This function returns a value of zero on success and a negative
 *	   error code on failure.
 */
int __init tsem_event_cache_init(void)
{
	event_cachep = kmem_cache_create("tsem_event_cache",
					 sizeof(struct tsem_event), 0,
					 SLAB_PANIC, 0);
	if (!event_cachep)
		return -ENOMEM;

	return 0;
}
