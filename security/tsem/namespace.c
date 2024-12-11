// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2024 Enjellic Systems Development, LLC
 * Author: Dr. Greg Wettstein <greg@enjellic.com>
 *
 * This file is responsible for managing the TSEM namespace
 * implementation that allows security models to be implemented for
 * workloads that are isolated from the root security modeling
 * namespace.  The namespaces that TSEM implements are
 * non-heirarchical and are at only a single depth below the root
 * security modeling namespace.
 *
 * Security modeling namespaces are identified by a 64-bit context
 * identity with context identity 0 being reserved for the root
 * security modeling namespace.
 *
 * The modeling of a namspace can be done by either an internal
 * trusted modeling agent implementation or by a trusted modeling
 * agent implementation associated with an external trust
 * orchestrator.
 *
 * This file is responsible for creating and setting up a tsem_context
 * structure that defines the modeling context being used by a
 * security modeling namespace.  This structure encapsulates
 * functionality that is generic to the namespace, such as the
 * cryptographic digest function that is used for security coefficient
 * mapping.
 *
 * Information for managing externally modeled namespaces are
 * maintained in the tsem_context structure while information for
 * internally modeled namespaces is maintained in the tsem_model
 * structure.  These structures are populated in the tsem_context
 * structure depending on whether or not an internal or externally
 * modeled namespace is being created.
 *
 * A tsem_context structure has a kref structure that is used to track
 * the number of uses of a context.  This reference count is
 * incremented each time a task is allocated in the context of a
 * security modeling namespace and decremented when a task exists.
 *
 * The release of the last reference to a context causes the structure
 * and its embedded structures to be released, thus freeing the
 * resources that have been allocated for modeling the namespace.
 */

#include "tsem.h"

static u64 context_id;

struct context_key {
	struct list_head list;
	u64 context_id;
	u8 key[HASH_MAX_DIGESTSIZE];
};

DEFINE_MUTEX(context_id_mutex);
LIST_HEAD(context_id_list);

static void remove_task_key(u64 context_id)
{
	struct context_key *entry, *tmp_entry;

	list_for_each_entry_safe(entry, tmp_entry, &context_id_list, list) {
		if (context_id == entry->context_id) {
			list_del(&entry->list);
			kfree(entry);
			break;
		}
	}
}

static int generate_task_key(const char *keystr, u64 context_id,
			     struct tsem_task *t_ttask,
			     struct tsem_task *p_ttask)
{
	int retn;
	bool found_key, valid_key = false;
	unsigned int size = tsem_digestsize();
	struct context_key *entry;

	while (!valid_key) {
		get_random_bytes(t_ttask->task_key, size);
		retn = tsem_ns_event_key(t_ttask->task_key, keystr,
					 p_ttask->task_key);
		if (retn)
			goto done;

		if (list_empty(&context_id_list))
			break;

		found_key = false;
		list_for_each_entry(entry, &context_id_list, list) {
			if (!memcmp(entry->key, p_ttask->task_key, size)) {
				found_key = true;
				break;
			}
		}
		if (!found_key)
			valid_key = true;
	}

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		retn = -ENOMEM;
		goto done;
	}

	entry->context_id = context_id;
	memcpy(entry->key, p_ttask->task_key, size);
	list_add_tail(&entry->list, &context_id_list);
	retn = 0;

 done:
	return retn;
}

static struct tsem_external *allocate_external(u64 context_id,
					       const char *keystr)
{
	int retn = -ENOMEM;
	char bufr[20 + 1];
	struct tsem_external *external;
	struct tsem_task *t_ttask = tsem_task(current);
	struct tsem_task *p_ttask = tsem_task(current->real_parent);

	external = kzalloc(sizeof(*external), GFP_KERNEL);
	if (!external)
		goto done;

	retn = generate_task_key(keystr, context_id, t_ttask, p_ttask);
	if (retn)
		goto done;

	spin_lock_init(&external->export_lock);
	INIT_LIST_HEAD(&external->export_list);

	init_waitqueue_head(&external->wq);

	scnprintf(bufr, sizeof(bufr), "%llu", context_id);
	external->dentry = tsem_fs_create_external(bufr);
	if (IS_ERR(external->dentry)) {
		retn = PTR_ERR(external->dentry);
		external->dentry = NULL;
	} else
		retn = 0;

 done:
	if (retn) {
		memset(t_ttask->task_key, '\0', tsem_digestsize());
		memset(p_ttask->task_key, '\0', tsem_digestsize());
		kfree(external);
		remove_task_key(context_id);
		external = ERR_PTR(retn);
	} else
		p_ttask->tma_for_ns = context_id;

	return external;
}

static struct tsem_external *allocate_export(u64 context_id)
{
	int retn = -ENOMEM;
	char bufr[20 + 1];
	struct tsem_external *external;

	external = kzalloc(sizeof(*external), GFP_KERNEL);
	if (!external)
		goto done;

	spin_lock_init(&external->export_lock);
	INIT_LIST_HEAD(&external->export_list);

	init_waitqueue_head(&external->wq);

	scnprintf(bufr, sizeof(bufr), "%llu", context_id);
	external->dentry = tsem_fs_create_external(bufr);
	if (IS_ERR(external->dentry)) {
		retn = PTR_ERR(external->dentry);
		external->dentry = NULL;
	} else
		retn = 0;

 done:
	if (retn) {
		kfree(external);
		external = ERR_PTR(retn);
	}
	return external;
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

static void wq_put(struct work_struct *work)
{
	struct tsem_context *ctx;
	struct tsem_inode_entry *ie, *tmp_ie;

	ctx = container_of(work, struct tsem_context, work);

	mutex_lock(&ctx->inode_mutex);
	list_for_each_entry_safe(ie, tmp_ie, &ctx->inode_list, list) {
		list_del(&ie->list);
		_release_inode_instances(ctx->id, ie->tsip);
		kfree(ie);
	}
	mutex_unlock(&ctx->inode_mutex);

	if (ctx->external) {
		mutex_lock(&context_id_mutex);
		remove_task_key(ctx->id);
		mutex_unlock(&context_id_mutex);

		securityfs_remove(ctx->external->dentry);
		tsem_export_magazine_free(ctx->external);
		kfree(ctx->external);
	} else
		tsem_model_free(ctx);

	crypto_free_shash(ctx->tfm);
	tsem_event_magazine_free(ctx);
	kfree(ctx->digestname);
	kfree(ctx);
}

static void ns_free(struct kref *kref)
{
	struct tsem_context *ctx;

	ctx = container_of(kref, struct tsem_context, kref);

	INIT_WORK(&ctx->work, wq_put);
	if (!queue_work(system_wq, &ctx->work))
		WARN_ON_ONCE(1);
}

/**
 * tsem_ns_put() - Release a reference to a modeling context.
 * @ctx: A pointer to the TMA context for which a reference is
 *	 to be released.
 *
 * This function is called to release a reference to a TMA modeling
 * domain.  The release of the last reference calls the ns_free()
 * function that schedules the actual work to release the resources
 * associated with the namespace to a workqueue.
 */
void tsem_ns_put(struct tsem_context *ctx)
{
	kref_put(&ctx->kref, ns_free);
}

/**
 * tsem_ns_event_key() - Generate TMA authentication key.
 * @task_key: A pointer to the buffer containing the task identification
 *	      key that was randomly generated for the modeling domain.
 * @keystr: A pointer to the buffer containing the TMA authentication key
 *	    in ASCII hexadecimal form.
 *
 * This function generates the authentication key that will be used
 * to validate a call by a TMA to set the trust status of the process.
 *
 * Return: This function returns 0 if the key was properly generated
 *	   or a negative value if a hashing error occurred.
 */
int tsem_ns_event_key(u8 *task_key, const char *keystr, u8 *key)
{
	bool retn;
	u8 tma_key[HASH_MAX_DIGESTSIZE];
	SHASH_DESC_ON_STACK(shash, tfm);

	retn = hex2bin(tma_key, keystr, tsem_digestsize());
	if (retn)
		return -EINVAL;

	shash->tfm = tsem_digest();
	retn = crypto_shash_init(shash);
	if (retn)
		return retn;

	retn = crypto_shash_update(shash, task_key, tsem_digestsize());
	if (retn)
		return retn;

	return crypto_shash_finup(shash, tma_key, tsem_digestsize(), key);
}

static struct crypto_shash *configure_digest(const char *digest,
					     char **digestname,
					     u8 *zero_digest)
{
	int retn;
	struct crypto_shash *tfm;
	SHASH_DESC_ON_STACK(shash, tfm);

	*digestname = kstrdup(digest, GFP_KERNEL);
	if (!*digestname)
		return ERR_PTR(-ENOMEM);

	tfm = crypto_alloc_shash(digest, 0, 0);
	if (IS_ERR(tfm))
		return tfm;

	shash->tfm = tfm;
	retn = crypto_shash_digest(shash, NULL, 0, zero_digest);
	if (retn) {
		crypto_free_shash(tfm);
		tfm = NULL;
	}

	return tfm;
}

/**
 * tsem_ns_create() - Create a TSEM modeling namespace.
 * @type:   The type of namespace being created.
 * @digest: A null terminated character buffer containing the name
 *	    of the hash function that is to be used for the modeling
 *	    domain.
 * @ns:     The enumeration type that specifies whether the security
 *	    event descriptions should reference the initial user
 *	    namespace or the current user namespace.
 * @key:    A pointer to a null-terminated buffer containing the key
 *	    that will be used to authenticate the TMA's ability to set
 *	    the trust status of a process.
 *
 * This function is used to create either an internally or externally
 * modeled TSEM namespace.  The type of the namespace to be created
 * is specified with the tsem_control_type enumeration value.  A
 * request for an internally model namespace causes a new structure to be
 * allocated that will hold the description of the security model.
 * An externally modeled domain will have a control structure allocated
 * that manages the export of security event descriptions to the
 * trust orchestrator that is responsible for running the TMA
 * implementation.
 *
 * Return: This function returns 0 if the namespace was created and
 *	   a negative error value on error.
 */
int tsem_ns_create(const enum tsem_control_type type, const char *digest,
		   const enum tsem_ns_reference ns, const char *key,
		   unsigned int cache_size)
{
	u8 zero_digest[HASH_MAX_DIGESTSIZE];
	char *use_digest;
	int retn = -ENOMEM;
	u64 new_id;
	struct tsem_task *tsk = tsem_task(current);
	struct tsem_context *new_ctx;
	struct tsem_model *model = NULL;
	struct crypto_shash *tfm;

	tfm = configure_digest(digest, &use_digest, zero_digest);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	new_ctx = kzalloc(sizeof(*new_ctx), GFP_KERNEL);
	if (!new_ctx)
		return retn;

	mutex_lock(&context_id_mutex);
	new_id = context_id + 1;

	retn = tsem_event_magazine_allocate(new_ctx, cache_size);
	if (retn)
		goto done;

	if (type == TSEM_CONTROL_INTERNAL) {
		model = tsem_model_allocate(cache_size);
		if (!model)
			goto done;
		new_ctx->model = model;
	}
	if (type == TSEM_CONTROL_EXTERNAL) {
		if (crypto_shash_digestsize(tfm)*2 != strlen(key)) {
			retn = -EINVAL;
			goto done;
		}

		new_ctx->external = allocate_external(new_id, key);
		if (IS_ERR(new_ctx->external)) {
			retn = PTR_ERR(new_ctx->external);
			new_ctx->external = NULL;
			goto done;
		}

		retn = tsem_export_magazine_allocate(new_ctx->external,
						     cache_size);
		if (retn)
			goto done;
	}
	if (type == TSEM_CONTROL_EXPORT) {
		new_ctx->external = allocate_export(new_id);
		if (IS_ERR(new_ctx->external)) {
			retn = PTR_ERR(new_ctx->external);
			new_ctx->external = NULL;
			goto done;
		}

		retn = tsem_export_magazine_allocate(new_ctx->external,
						     cache_size);
		if (retn)
			goto done;

		new_ctx->external->export_only = true;
	}


	kref_init(&new_ctx->kref);

	new_ctx->id = new_id;
	new_ctx->tfm = tfm;
	new_ctx->digestname = use_digest;
	memcpy(new_ctx->zero_digest, zero_digest,
	       crypto_shash_digestsize(tfm));

	mutex_init(&new_ctx->inode_mutex);
	INIT_LIST_HEAD(&new_ctx->inode_list);

	if (ns == TSEM_NS_CURRENT)
		new_ctx->use_current_ns = true;
	memcpy(new_ctx->actions, tsk->context->actions,
	       sizeof(new_ctx->actions));
	retn = 0;

 done:
	if (retn) {
		if (type != TSEM_CONTROL_EXPORT)
			remove_task_key(new_id);
		crypto_free_shash(tfm);
		tsem_event_magazine_free(new_ctx);
		kfree(use_digest);
		if (new_ctx->external)
			tsem_export_magazine_free(new_ctx->external);
		kfree(new_ctx->external);
		kfree(new_ctx);
		kfree(model);
	} else {
		context_id = new_id;
		tsk->context = new_ctx;
		if (type == TSEM_CONTROL_EXTERNAL)
			retn = tsem_export_aggregate();
		if (type == TSEM_CONTROL_INTERNAL)
			retn = tsem_model_add_aggregate();
	}

	mutex_unlock(&context_id_mutex);
	return retn;
}

/**
 * tsem_ns_export_root() - Configure root namespace for export only modeling.
 * @magazine_size:  The number of entries to be implemented in the event
 *		    cache.
 *
 * This function is called to setup the root security modeling namespace
 * for the export of security event descriptions in tsem_mode=2
 * operation.
 *
 * Return: This function returns 0 if the setup of the root namespace
 *	   for export was successul and a negative error value if
 *	   the setup fails.
 */
int tsem_ns_export_root(unsigned int magazine_size)
{
	int retn = -ENOMEM;
	struct tsem_context *new_ctx;
	struct tsem_task *tsk = tsem_task(current);

	new_ctx = kzalloc(sizeof(*new_ctx), GFP_KERNEL);
	if (!new_ctx)
		return retn;
	*new_ctx = *tsem_context(current);

	new_ctx->external = allocate_export(tsem_context(current)->id);
	if (IS_ERR(new_ctx->external)) {
		retn = PTR_ERR(new_ctx->external);
		new_ctx->external = NULL;
		goto done;
	}

	retn = tsem_export_magazine_allocate(new_ctx->external, magazine_size);
	if (retn)
		goto done;

	new_ctx->external->export_only = true;

 done:
	if (retn) {
		tsem_event_magazine_free(new_ctx);
		if (new_ctx->external)
			tsem_export_magazine_free(new_ctx->external);
		kfree(new_ctx);
	} else {
		new_ctx->tfm = tsk->context->tfm;
		new_ctx->digestname = tsk->context->digestname;
		memcpy(new_ctx->zero_digest, tsk->context->zero_digest,
		       crypto_shash_digestsize(tsk->context->tfm));

		mutex_init(&new_ctx->inode_mutex);
		INIT_LIST_HEAD(&new_ctx->inode_list);

		tsk->context = new_ctx;
	}

	return retn;
}
