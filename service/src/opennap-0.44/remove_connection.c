/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id: remove_connection.c,v 1.60 2001/09/22 05:52:06 drscholl Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <stdlib.h>
#include "opennap.h"
#include "hashlist.h"
#include "debug.h"

static void
server_split (USER * user, CONNECTION * con)
{
    ASSERT (validate_user (user));
    ASSERT (validate_connection (con));
    ASSERT (con->class == CLASS_SERVER);

    /* check to see if this user was behind the server that just split */
    if (user->con == con)
    {
	/* on split, we have to notify our peer servers that this user
	   is no longer online */
	pass_message_args (con, MSG_CLIENT_QUIT, "%s", user->nick);
	/* remove the user from the hash table */
	hash_remove (Users, user->nick);
    }
}

/* free resources associated with CLASS_USER connection. this is broken out
   here so that login() can call this directly to remove a "ghost" user and
   allow the new connection to complete. */
void
remove_user (CONNECTION * con)
{
    LIST   *u;

    ASSERT (ISUSER (con));

    if (con->user->level >= LEVEL_MODERATOR)
	Mods = list_delete (Mods, con);

    /* remove user from global list, calls free_user() indirectly */
    ASSERT (validate_user (con->user));
    hash_remove (Users, con->user->nick);

    /* if this user had hotlist entries, remove them from the lists */
    for (u = con->uopt->hotlist; u; u = u->next)
    {
	ASSERT (hashlist_validate (u->data));
	hashlist_remove (Hotlist, ((hashlist_t *) u->data)->key, con);
    }

    list_free (con->uopt->hotlist, 0);
    list_free (con->uopt->ignore, free_pointer);

    if (con->uopt->files)
    {
	/* indirectly calls free_datum() */
	free_hash (con->uopt->files);
    }

    /* sanity check */
    if (con->uopt->searches < 0)
	log_message("remove_user: ERROR, con->uopt->searches < 0!!!");

    FREE (con->uopt);
}

static void
free_server_name (const char *s)
{
    LIST  **list = &Server_Names;
    LIST   *tmp;

    for (; *list; list = &(*list)->next)
    {
	if (s == (*list)->data)
	{
	    tmp = *list;
	    *list = (*list)->next;
	    FREE (tmp->data);
	    FREE (tmp);
	    break;
	}
    }
}

void
remove_connection (CONNECTION * con)
{
    ASSERT (validate_connection (con));

    /* should have been properly shut down */
    if (con->fd != -1)
	log_message ("remove_connection: ERROR, con->fd != -1");

    /* if this connection had any pending searches, cancel them */
    cancel_search (con);

    if (ISUSER (con))
    {
	remove_user (con);
    }
    else if (ISSERVER (con))
    {
	/* if we detect that a server has quit, we need to remove all users
	   that were behind this server.  we do this by searching the User
	   hash table for entries where the .serv member is this connection.
	   we also need to send QUIT messages for each user to any other
	   servers we have */

	/* first off, lets remove this server from the Servers list so
	   that pass_message() doesnt try to send message back through this
	   server (although we could just pass this connection to it and it
	   would avoid sending it) */

	log_message ("remove_connection: server split detected (%s)", con->host);
	if (!con->quit)
	{
	    notify_mods (SERVERLOG_MODE, "Server %s has quit: EOF",
			 con->host);
	    /* notify our peers this server has quit */
	    pass_message_args (con, MSG_CLIENT_DISCONNECT,
			       ":%s %s \"EOF\"", Server_Name, con->host);

	    /* if this server was linked to other servers, remove the
	     * information we have on those links */
	    remove_links (con->host);
	}

	Servers = list_delete (Servers, con);

	/* remove all users that were behind this server from the hash table.
	   this should be an infrequent enough occurance than iterating the
	   entire hash table does not need to be optimized the way we split
	   out the server connections. */
	hash_foreach (Users, (hash_callback_t) server_split, con);

	finalize_compress (con->sopt);
	buffer_free (con->sopt->outbuf);
	FREE (con->sopt);

	/* free the server name cache entry */
	free_server_name (con->host);
    }
    else
    {
	ASSERT (con->class == CLASS_UNKNOWN);
	if (con->server_login)
	{
	    if (con->opt.auth)
	    {
		if (con->opt.auth->nonce)
		    FREE (con->opt.auth->nonce);
		if (con->opt.auth->sendernonce)
		    FREE (con->opt.auth->sendernonce);
		FREE (con->opt.auth);
	    }
	}
    }

    /* common data */
    if (con->host)
	FREE (con->host);
    buffer_free (con->sendbuf);
    buffer_free (con->recvbuf);

    /* temp fix to catch bad contexts */
    memset (con, 0xff, sizeof (CONNECTION));

    FREE (con);
}
