/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id: resume.c,v 1.26 2001/03/06 06:49:53 drscholl Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

/* packet contains: <checksum> <filesize> */
HANDLER (resume)
{
#if RESUME
    char   *av[2];
    FLIST  *flist;
    LIST   *ptr;
    DATUM  *d;
    int     fsize;
#endif /* RESUME */

    (void) tag;
    (void) len;
    (void) pkt;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("resume");
#if RESUME
    if (split_line (av, sizeof (av) / sizeof (char *), pkt) != 2)
    {
	unparsable (con);
	return;
    }

    fsize = atoi (av[1]);
    if (fsize < 1)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "invalid file size");
	return;
    }

    /* search the database for a list of all files which match this hash */
    flist = hash_lookup (MD5, av[0]);
    if (flist)
    {
	for (ptr = flist->list; ptr; ptr = ptr->next)
	{
	    d = (DATUM *) ptr->data;
	    if (d->size == (size_t) fsize)
	    {
		ASSERT (validate_user (d->user));
		send_cmd (con, MSG_SERVER_RESUME_MATCH,
			  "%s %u %hu \"%s\" %s %u %hu",
			  d->user->nick, d->user->ip, d->user->port,
			  d->filename, d->hash, d->size, d->user->speed);
	    }
	}
    }
#endif /* RESUME */

    send_cmd (con, MSG_SERVER_RESUME_MATCH_END, "");
}
