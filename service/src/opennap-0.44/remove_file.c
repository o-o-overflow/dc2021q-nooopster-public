/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id: remove_file.c,v 1.36 2001/09/22 05:52:06 drscholl Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include "opennap.h"
#include "debug.h"

#ifndef ROUTING_ONLY

/* 102 <filename> */
HANDLER (remove_file)
{
    USER   *user;
    DATUM  *info;
    unsigned int fsize;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("remove_file");
    user = con->user;
    if (!user->shared)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "Not sharing any files");
	return;
    }

    ASSERT (pkt != 0);
    if (!*pkt)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "remove file failed: missing argument");
	return;
    }

    /* find the file in the user's list */
    info = hash_lookup (con->uopt->files, pkt);
    if (!info)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "Not sharing that file");
	return;
    }

    /* adjust the global state information */
    fsize = info->size / 1024;	/* kB */

    if (fsize > user->libsize)
    {
	log_message ("remove_file: bad lib size for %s, fsize=%u user->libsize=%u",
	     user->nick, fsize, user->libsize);
	user->libsize = fsize;	/* prevent negative count */
    }
    user->libsize -= fsize;

    if (fsize > Num_Gigs)
    {
	log_message ("remove_file: bad lib size for %s, fsize=%u Num_Gigs=%f",
	     user->nick, fsize, Num_Gigs);
	Num_Gigs = fsize;	/* prevent negative count */
    }
    Num_Gigs -= fsize;

    ASSERT (Num_Files > 0);
    Num_Files--;

    ASSERT (Local_Files > 0);
    Local_Files--;

    user->shared--;
    user->unsharing = 1;	/* note that we are unsharing */

    /* this invokes free_datum() indirectly */
    hash_remove (con->uopt->files, info->filename);
}
#endif /* ! ROUTING_ONLY */
