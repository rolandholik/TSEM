/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Copyright (C) 2025 Enjellic Systems Development, LLC
 * Author: Dr. Greg Wettstein <greg@enjellic.com>
 *
 * This header file contains declarations for globally visible
 * functionality surrounding the registration of security models
 * provided in the form of loadable modules.
 *
 * This header file detects whether or not kernel modules are enabled
 * and if not provides a stub function that causes an attempt to
 * specify an alternate security model to fail.
 */

#ifdef CONFIG_MODULES
extern void tsem_nsmgr_put(const struct tsem_context_ops *ops);
extern const struct tsem_context_ops *tsem_nsmgr_get(const char *name);
extern int tsem_nsmgr_lock(const bool);
extern int tsem_nsmgr_register(const struct tsem_context_ops *ops,
			       struct module *module);
extern int tsem_nsmgr_release(const struct tsem_context_ops *ops);
#else
static inline void tsem_nsmgr_put(const struct tsem_context_ops *ops)
{
}

static inline int tsem_nsmgr_lock(const bool by_setup)
{
	return EOPNOTSUPP;
}

static inline const struct tsem_context_ops *tsem_nsmgr_get(const char *name)
{
	return NULL;
}

static inline int tsem_nsmgr_register(const struct tsem_context_ops *ops,
				      struct module *module)
{
	return -EOPNOTSUPP;
}

static inline int tsem_nsmgr_release(const struct tsem_context_ops *ops)
{
	return -EOPNOTSUPP;
}
#endif
