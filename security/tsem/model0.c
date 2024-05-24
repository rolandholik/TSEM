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

static bool event_bypasses[TSEM_EVENT_CNT];

const struct tsem_context_ops tsem_model0_ops = {
	.name = "model0",
	.bypasses = event_bypasses,
};
