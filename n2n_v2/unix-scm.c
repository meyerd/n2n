/*
 * unix-scm.c - unix stubs for service control manager functions
 *
 * Copyright (c) 2010 Hamish Coleman <hamish@zot.org>
 *               2003 Benjamin Schweizer <gopher at h07 dot org>
 *               1998 Stephen Early <Stephen.Early@cl.cam.ac.uk>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <stdlib.h>

#include "scm.h"

int SCM_Start(struct SCM_def *sd, int argc, char **argv) {
	sd->mode=SVC_CONSOLE;

	int err;

	if (sd->init) {
		err = sd->init(argc,argv);
		if (err!=0) {
			return SVC_FAIL;
		}
	}

	sd->main(argc,argv);
	return SVC_OK;
}

char *SCM_Install(struct SCM_def *sd,char *args) {
	return NULL;
}

int SCM_Remove(struct SCM_def *sd) {
	return SVC_FAIL;
}

