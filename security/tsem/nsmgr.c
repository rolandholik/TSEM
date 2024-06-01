// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2024 Enjellic Systems Development, LLC
 * Author: Dr. Greg Wettstein <greg@enjellic.com>
 *
 * This file contains infrastructure for managing the security models
 * available for TSEM.
 */

#include "tsem.h"
#include "nsmgr.h"

struct model {
	struct list_head list;
	const struct tsem_context_ops *ops;
	struct module *module;
};

DEFINE_MUTEX(model_list_mutex);
LIST_HEAD(model_list);


static struct model *find_model(const char *name)
{
	struct model *found = NULL, *entry = NULL;

	list_for_each_entry(entry, &model_list, list) {
		if (!strcmp(entry->ops->name, name)) {
			found = entry;
			break;
		}
	}
	return found;
}

/**
 * tsem_nsmgr_put() - Release a reference to a TSEM security model.
 *
 * @ops: A pointer to the tsem_context_ops structure that defines
 *	 this model.
 *
 * This function is the counter part to tsem_nsmgr_get() function.
 * A check is made to determine if a module is supplying this model and
 * if so the reference that was taken to the module when the security
 * namespace is created is released.
 */
void tsem_nsmgr_put(const struct tsem_context_ops *ops)
{
	struct model *model;

	if (!strcmp(tsem_model0_ops.name, ops->name))
		return;

	mutex_lock(&model_list_mutex);
	model = find_model(ops->name);
	if (!model) {
		pr_warn("tsem: Attempt to put an unknown model.\n");
		goto done;
	}
	if (model->module)
		module_put(model->module);

 done:
	mutex_unlock(&model_list_mutex);
}

/**
 * tsem_nsmgr_get() - Obtain a reference to a TSEM security model.
 *
 * @name: A null terminated character buffer containing the name of
 *	  the security model to obtain a reference for.
 *
 * This function is used to determine whether or not TSEM has access
 * to a security model named by the called.  Upon success of locating
 * the named security model a tsem_context_ops structure is returned
 * that implements the model.  In addition a reference is taken to
 * the module in order to prevent its release while a security modeling
 * namespace is using the model.
 *
 * Return: If the named security model is not available a NULL pointer
 *	   is returned.  If the model is available a pointer to the
 *	   tsem_context_ops structure that implements the model is
 *	   returned.
 */
const struct tsem_context_ops *tsem_nsmgr_get(const char *name)
{
	struct model *model;
	const struct tsem_context_ops *retn = NULL;

	mutex_lock(&model_list_mutex);
	model = find_model(name);
	mutex_unlock(&model_list_mutex);

	if (!model) {
		if (request_module("%s", name))
			return NULL;

		mutex_lock(&model_list_mutex);
		model = find_model(name);
		mutex_unlock(&model_list_mutex);
		if (!model)
			return NULL;
	}

	if (model && try_module_get(model->module))
		retn = model->ops;
	return retn;
}

/**
 * tsem_nsmgr_register() - Register a TSEM security namespace model.
 * @ops:    A pointer to a tsem_context_ops structure that describes
 *	    the model that will be implemented.
 * @module: A pointer to the module implementing the security namespace
 *	    model.
 *
 * This function is used by loadable modules to register a security
 * model that is to be available for use by security modeling namespaces.
 *
 * Return: This function returns 0 if the model was successfully registered
 *	   or a negative error value if registration failed.
 */
int tsem_nsmgr_register(const struct tsem_context_ops *ops,
			struct module *module)
{
	int retn = 0;
	struct model *model = NULL;

	if (!capable(CAP_MAC_ADMIN))
		return -EPERM;
	if (!strcmp(tsem_model0_ops.name, ops->name))
		return -EINVAL;

	mutex_lock(&model_list_mutex);
	if (find_model(ops->name)) {
		pr_warn("tsem: Attempt to insert identical model: %s\n",
			ops->name);
		retn = -EEXIST;
		goto done;
	}

	model = kzalloc(sizeof(*model), GFP_KERNEL);
	if (!model) {
		retn = -ENOMEM;
		goto done;
	}

	model->ops = ops;
	model->module = module;
	list_add_tail(&model->list, &model_list);
	pr_info("tsem: Registered model: '%s'\n", ops->name);

 done:
	mutex_unlock(&model_list_mutex);
	return retn;
}
EXPORT_SYMBOL_GPL(tsem_nsmgr_register);

/**
 * tsem_nsmgr_release() - Release a TSEM security namespace model.
 * @name:   A null terminated character buffer containing the name
 *	    of the model being implemented.
 *
 * This function is used to release the use of security modeling
 * namespace model.
 */
void tsem_nsmgr_release(const struct tsem_context_ops *ops)
{
	struct model *model;

	mutex_lock(&model_list_mutex);

	model = find_model(ops->name);
	if (!model) {
		pr_warn("tsem: Model '%s' not found for release.\n",
			ops->name);
		goto done;
	}
	list_del(&model->list);

 done:
	mutex_unlock(&model_list_mutex);
	pr_info("tsem: Released model: '%s'\n", ops->name);
}
EXPORT_SYMBOL_GPL(tsem_nsmgr_release);
