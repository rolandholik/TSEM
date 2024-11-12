// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2024 Enjellic Systems Development, LLC
 * Author: Dr. Greg Wettstein <greg@enjellic.com>
 *
 * This file contains methods and definitions for the 'model0'
 * security model implementation.  This is the default model that
 * TSEM implements.
 */

#include "tsem.h"

static bool event_bypasses[TSEM_EVENT_CNT] = {
	[TSEM_FILE_IOCTL_COMPAT] = true,
	[TSEM_FILE_TRUNCATE] = true,
	[TSEM_BPRM_CHECK_SECURITY] = true,
	[TSEM_CRED_PREPARE] = true,
	[TSEM_PATH_TRUNCATE] = true,
	[TSEM_PATH_UNLINK] = true,
	[TSEM_PATH_MKDIR] = true,
	[TSEM_PATH_RMDIR] = true,
	[TSEM_PATH_SYMLINK] = true,
	[TSEM_PATH_MKNOD] = true,
	[TSEM_PATH_LINK] = true,
	[TSEM_PATH_RENAME] = true
};

const struct tsem_context_ops tsem_model0_ops = {
	.name = "model0",
	.bypasses = event_bypasses,
	.generate = tsem_event_generate,
	.map = tsem_map_event
};
