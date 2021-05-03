/* Copyright (C) 2001 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id: napigator.c,v 1.8 2001/09/22 05:52:06 drscholl Exp $ */

/*** support for Napigator ***/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef ROUTING_ONLY

#include <stdlib.h>
#include <string.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#include "opennap.h"
#include "debug.h"
#include "md5.h"

static char *stat_server_salt = 0;

void
stat_server_read (void)
{
    int     n;
    char   *p;
    int     do_close = 0;
    char   *salt;

    n = READ (global.stat_server_fd, Buf, sizeof (Buf));
    if (n <= 0)
    {
	if (n == -1)
	    logerr ("stat_server_read", "read");
	log_message ("stat_server_read: got hangup");
	do_close = 1;
    }
    else
    {
	/* find end of line */
	p = strpbrk (Buf, "\r\n");
	if (*p)
	    *p = 0;
	p = Buf;

	n = atoi (Buf);
	if (n == 220)
	{
	    /* got connect

	     * first, save the salt */
	    next_arg (&p);
	    salt = next_arg (&p);
	    if (!salt)
	    {
		log_message ("stat_server_read:unable to get salt string");
		strcpy (Buf, "QUIT\r\n");
		WRITE (global.stat_server_fd, Buf, strlen (Buf));
	    }
	    else
	    {
		if (stat_server_salt)
		    FREE (stat_server_salt);
		stat_server_salt = STRDUP (salt);

		snprintf (Buf, sizeof (Buf), "USER %s\r\n", global.stat_user);

		WRITE (global.stat_server_fd, Buf, strlen (Buf));
	    }
	}
	else if (n == 221)
	{
	    /* server hangup */
	    do_close = 1;
	}
	else if (n == 300)
	{
	    struct md5_ctx md;
	    char    hash[33];

	    md5_init_ctx (&md);
	    md5_process_bytes (stat_server_salt, strlen (stat_server_salt),
			       &md);
	    md5_process_bytes (global.stat_pass, strlen (global.stat_pass),

			       &md);
	    md5_finish_ctx (&md, hash);
	    expand_hex (hash, 16);
	    hash[32] = 0;
	    snprintf (Buf, sizeof (Buf), "PASS %s\r\n", hash);
	    WRITE (global.stat_server_fd, Buf, strlen (Buf));
	}
	else if (n == 201)
	{
	    /* auth complete */
	    log_message ("stat_server_read: logged in");

	    /* send updated ip:port in case we are a dynamic server */
	    snprintf (Buf, sizeof (Buf), "IPPORT %s %s %d\r\n",
		    global.report_name,
		    global.report_ip,
		    global.report_port);
	    WRITE (global.stat_server_fd, Buf, strlen (Buf));

	    /* force immediate update */
	    stat_server_push ();
	}
	else if (n / 100 >= 4)
	{
	    /* something failed */
	    log_message ("stat_server_read:%s", Buf);
	    strcpy (Buf, "QUIT\r\n");
	    WRITE (global.stat_server_fd, Buf, strlen (Buf));
	}
	else if (n == 200)
	{
	    /* stats updated successfully */
	}
	else
	{
	    log_message ("stat_server_read: unhandled:%s", Buf);
	}
    }

    if (do_close)
    {
	log_message ("stat_server_read: closing connection");
	CLOSE (global.stat_server_fd);
#if HAVE_POLL
	remove_fd (global.stat_server_fd);
#else
	FD_CLR (global.stat_server_fd, &global.read_fds);
	FD_CLR (global.stat_server_fd, &global.write_fds);
#endif
	global.stat_server_fd = -1;
    }
}

void
stat_server_push (void)
{
    unsigned int ip;

    if (global.stat_server_fd == -1)
    {
	/* attempt to make new connection to stats server */
	if (!*global.stat_user || !*global.stat_pass || !*global.stat_server)
	{
	    return;		/* nothing defined */
	}

	global.stat_server_fd = make_tcp_connection (global.stat_server,
				       global.stat_server_port, &ip);
	if (global.stat_server_fd != -1)
	{
	    /* do a nonblocking connect */
	    add_fd (global.stat_server_fd);
	    set_write (global.stat_server_fd);
	}
	return;
    }

    snprintf (Buf, sizeof (Buf), "STATS %s %u %u 0 %.0f 0\r\n",
	      global.report_name, Users->dbsize, Num_Files, Num_Gigs * 1024);

    if (WRITE (global.stat_server_fd, Buf, strlen (Buf)) == -1)
    {
	log_message ("stat_server_push: write: %s (%d)", strerror (N_ERRNO), N_ERRNO);
	CLOSE (global.stat_server_fd);
#if HAVE_POLL
	remove_fd (global.stat_server_fd);
#else
	FD_CLR (global.stat_server_fd, &global.read_fds);
	FD_CLR (global.stat_server_fd, &global.write_fds);
#endif
	global.stat_server_fd = -1;
    }
}

#endif /* !ROUTING_ONLY */
