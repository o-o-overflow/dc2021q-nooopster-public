/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id: free_user.c,v 1.49 2001/09/22 05:52:06 drscholl Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include "opennap.h"
#include "hashlist.h"
#include "debug.h"

void
free_user (USER * user)
{
    LIST   *list;
    USERDB *db;
    whowas_t *who;
    ip_info_t *info;

    ASSERT (validate_user (user));

    if (ISUSER (user->con) && Servers && !user->con->killed)
    {
	/* local user, notify peers of this user's departure */
	pass_message_args (user->con, MSG_CLIENT_QUIT, "%s", user->nick);
    }

    /* remove this user from any channels they were on */
    if (user->channels)
    {
	for (list = user->channels; list; list = list->next)
	{
	    /* notify locally connected clients in the same channel that
	       this user has parted */
	    part_channel (list->data, user);
	}
	list_free (user->channels, 0);
    }

    /* check the global hotlist for this user to see if anyone wants notice
       of this user's departure */
    for (list = hashlist_lookup (Hotlist, user->nick); list;
	 list = list->next)
    {
	ASSERT (validate_connection (list->data));
	send_cmd (list->data, MSG_SERVER_USER_SIGNOFF, "%s", user->nick);
    }

    ASSERT (Num_Files >= user->shared);
    Num_Files -= user->shared;
    ASSERT (Num_Gigs >= user->libsize);

    if (Num_Gigs < user->libsize)
    {
	log_message ("free_user: bad total lib size: Num_Gigs=%f user->libsize=%u",
	     Num_Gigs, user->libsize);
	Num_Gigs = user->libsize;	/* prevent negative value */
    }
    Num_Gigs -= user->libsize;	/* this is in kB */

#ifndef ROUTING_ONLY
    if (ISUSER (user->con))
    {
	if (user->shared > Local_Files)
	{
	    log_message
		("free_user: local file count error, %s is sharing %d, more than %d",
		 user->nick, user->shared, Local_Files);
	    Local_Files = 0;
	}
	else
	    Local_Files -= user->shared;
    }
#endif /* !ROUTING_ONLY */

    /* record the log off time */
    if ((db = hash_lookup (User_Db, user->nick)))
	db->lastSeen = global.current_time;

    /* save info in the who-was table */
    who = hash_lookup (Who_Was, user->nick);
    if (!who)
    {
	who = CALLOC (1, sizeof (whowas_t));
	if (!who)
	{
	    OUTOFMEMORY ("free_user");
	    FREE (user->nick);
	}
	else
	{
	    who->nick = user->nick;
	    hash_add (Who_Was, who->nick, who);
	}
    }
    else
	FREE (user->nick);
    if (who)
    {
	who->ip = user->ip;
	who->when = global.current_time;
	who->server = user->server;
	who->clientinfo = user->clientinfo;
    }

    memset (user->pass, 0, strlen (user->pass));
    FREE (user->pass);

    /* decrement the clone count */
    info = hash_lookup (Clones, (void *) user->ip);
    if (info->users <= 0)
    {
	log_message ("free_user: ERROR, info->users <= 0");
	info->users = 0;
    }
    else
	info->users--;

    /* NOTE: user->server is just a ref, not a malloc'd pointer */
    memset (user, 0xff, sizeof (USER));	/* catch refs to bad memory */
    FREE (user);
}
