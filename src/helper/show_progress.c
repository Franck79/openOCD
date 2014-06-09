/*
 * show_progress.c - simple progress bar functions
 *
 * Copyright (c) 2010 Sascha Hauer <s.hauer@pengutronix.de>, Pengutronix
 *
 * Copyright (c) 2014 Franck Jullien <franck.jullien@gmail.com>
 *    Made it work with OpenOCD
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <jtag/jtag.h>
#include <target/register.h>
#include <target/target.h>
#include <target/breakpoints.h>
#include <target/target_type.h>
#include <helper/fileio.h>
#include <helper/types.h>

#define HASHES_PER_LINE	65

static int printed;
static int progress_max;
static int now;

void inc_progress(int val)
{
	now += val;

	/* For small transfers show_progress must be call right now */
	if (now <= val)
		target_call_timer_callbacks_now();
	else
		target_call_timer_callbacks();
}

int show_progress(void *dummy)
{
	long long tmp;

	if (progress_max) {
		tmp = (long long)now * HASHES_PER_LINE;
		tmp = tmp / progress_max;

		if (progress_max < now)
			tmp = HASHES_PER_LINE;

		while (printed < tmp) {
			if (!(printed % HASHES_PER_LINE) && printed)
				printf("\n\t");
			printf("#");
			printed++;
		}
	}

	return ERROR_OK;
}

void init_progression_bar(int max)
{
	printed = 0;
	progress_max = max;
	now = 0;

	if (progress_max) {
		printf("\t[%"stringify(HASHES_PER_LINE)"s]\r\t[", "");
		target_register_timer_callback(show_progress, 100, 1, NULL);
	} else {
		printf("\t");
	}
}

void stop_progression_bar(void)
{
	/* If progress val doesn't end exactly where it should, finish the job */
	while (printed < HASHES_PER_LINE) {
		if (!(printed % HASHES_PER_LINE) && printed)
			printf("\n\t");
		printf("#");
		printed++;
	}

	printf("\n");
	target_unregister_timer_callback(&show_progress, NULL);
}
